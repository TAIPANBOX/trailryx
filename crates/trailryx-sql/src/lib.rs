//! The SQL facade: DataFusion over our projections.
//!
//! # The only crate here with third-party dependencies
//!
//! Two hundred and forty-three of them, transitively, against zero in every other
//! crate in this workspace. That number is published rather than buried: it is the
//! cost of the decision, and `docs/planning/trailryx-architecture.md` §3.1 argues
//! the trade in one sentence, from the lesson that made VictoriaMetrics: **it is
//! compatibility that wins, not speed.** Speaking the Postgres wire protocol means
//! Grafana, Metabase, Superset, DBeaver, psql, pandas and every ORM in every
//! language work on the day of release, with no integration work on our side. The
//! architecture also rejects the alternative explicitly, in the section that turns
//! down Zig: the risk of our own SQL engine exceeds the gain.
//!
//! What did **not** change, and what the gate now enforces in two separate checks:
//!
//! - **Every other crate still has zero third-party dependencies.** In particular
//!   `trailryx-verify`, the offline verifier, which is the answer to "who checked
//!   your code". That property was never about the workspace, it was about the
//!   thing an auditor reads.
//! - **The core builds and passes its tests with this crate absent.**
//!   §3.2a requires that test by name: if the core cannot stand up without the
//!   facade, the facade has got into the foundation.
//!
//! # Why the isolation matters more now, not less
//!
//! The core is a deterministic state machine per shard, and that determinism is what
//! makes deterministic simulation testing possible, which is the method the whole
//! correctness argument rests on (§1a, called the most important section of the
//! architecture). DataFusion brings tokio, with its own thread pool and its own
//! scheduling. Mixing them in one task space would cost the core its determinism and
//! with it the way bugs get found here.
//!
//! So §3.2a's boundary is a correctness boundary and not a tidiness one: the facade
//! runs in its own threads, reads **only projections and sealed segments**, never the
//! live journal, and speaks to the core over channels.
//!
//! # How SQL does not become a hole in the proof model
//!
//! [`pushdown`] is that answer and it is deliberately engine-agnostic. A predicate
//! on one of the five provable dimensions becomes the sorted dimension of an
//! authenticated index range, and the answer carries a completeness proof. Anything
//! else is applied but **named**, and the answer says `partial` with the list.
//!
//! Writing is not offered at all. `INSERT` through SQL is forbidden by the plan and
//! there is nothing here that could perform one: records arrive through a `Source`
//! and nowhere else.

pub mod dialect;
pub mod gate;
pub mod pushdown;
pub mod server;
pub mod table;
pub mod wire;

use std::sync::Arc;

use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::SessionContext;
use trailryx_index::segment::Segment;

pub use gate::Refusal;
pub use table::{Provability, RecordTable};

/// A read-only session over sealed segments.
///
/// # Why this exists rather than a bare `SessionContext`
///
/// So the statement gate cannot be forgotten. A bare `SessionContext` accepts
/// `CREATE EXTERNAL TABLE ... LOCATION '/etc/passwd'` and returns the file, which
/// makes any server that forwards SQL to one an arbitrary local file read on the
/// store's host. That is measured, not supposed: `gate`'s first test is the statement
/// that did it.
///
/// A server author who reached for `SessionContext::sql` directly would reintroduce
/// that with no warning, so there is one entry point here and it gates first. The
/// context is deliberately **not** exposed.
///
/// # One session is one reader, and that is now literal
///
/// A session owns its proof slot, so [`Self::last_proof`] and `trailryx_proof()`
/// answer about the queries **this** session asked. The Postgres facade builds one
/// per connection through [`Self::for_connection`]; before 5 August 2026 it built one
/// for the whole process and every connection shared it, which meant a reader could
/// be told that an answer was proved because a stranger's query had been.
pub struct Session {
    context: SessionContext,
    table: Arc<RecordTable>,
    /// The sealed segments this session reads, shared with every session forked from
    /// it. Sealed is immutable, so there is nothing to isolate here and copying them
    /// per connection would price the isolation at the size of the trail.
    segments: Arc<Vec<Segment>>,
    /// Whether the `journal` function is registered, carried so a forked session is
    /// the same session and not a quietly weaker one. See [`Self::with_raw_access`]
    /// for what this flag is and, more to the point, what it is not.
    raw: bool,
}

impl std::fmt::Debug for Session {
    /// Hand-written because `SessionContext` has no `Debug`, and the workspace lint
    /// warns on a type without one. Prints what a reader would want anyway: the last
    /// answer's provability, not the engine's internals.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("last_proof", &self.table.last_proof())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Register the sealed segments as `records` and nothing else.
    ///
    /// One table, no catalog of the operator's choosing, no external locations. The
    /// tables a session can see are the ones the store registered.
    /// A session that may query the projections and nothing more.
    pub fn new(segments: Vec<Segment>) -> Self {
        Self::with_raw_access(segments, false)
    }

    /// A session that may also read the journal past the projections.
    ///
    /// `raw` registers the `journal` function; false leaves it out of the catalog, so
    /// a session without it does not have the function rather than being refused when
    /// it reaches for one. That much is `pg_walinspect`'s shape and it is the right
    /// one: the catalog a session can see is what it may use.
    ///
    /// **It is a construction flag and not a permission.** Whoever builds the session
    /// decides, once, for every client that will ever connect to the server built on
    /// it. Nothing consults the deployment's `AuthProvider` about it: the only
    /// authorisation this facade performs is one `Action::Query` at connect time, in
    /// [`server::ReadGate`]. The architecture asks for `Action::ReadMetadata` to be a
    /// separate grant per principal, and that is not built. Until it is, raw journal
    /// access is a property of the **server**, so a deployment that wants it for one
    /// auditor and not for everybody else runs a second server for that auditor.
    pub fn with_raw_access(segments: Vec<Segment>, raw: bool) -> Self {
        Self::over(Arc::new(segments), raw)
    }

    /// A session of this session's segments, with a proof slot of its own.
    ///
    /// What the Postgres facade calls once per accepted connection. A Postgres
    /// session is a connection, `trailryx_proof()` reports "the last answer on this
    /// session", and those two only agree if each connection has a session.
    ///
    /// Sealed segments are shared, not copied, so this costs one `SessionContext`, a
    /// table, four registrations and a pointer, rather than a copy of the trail.
    pub fn for_connection(&self) -> Self {
        Self::over(Arc::clone(&self.segments), self.raw)
    }

    /// Every session is built here, so a forked one cannot drift from an original.
    fn over(segments: Arc<Vec<Segment>>, raw: bool) -> Self {
        let slot = table::ProofSlot::default();
        let table = Arc::new(RecordTable::over(Arc::clone(&segments)).sharing(Arc::clone(&slot)));
        let context = SessionContext::new();
        context
            .register_table("records", Arc::clone(&table) as Arc<_>)
            .expect("a fresh context has no `records` table to collide with");

        // The dialect extensions, as table functions, because the engine's own parser
        // accepts those and does not accept `AS OF TIMESTAMP` or a trailing
        // `WITH PROOF`. See `dialect` for the deviation and why a second parser was
        // refused rather than written.
        //
        // Every one of them takes THIS session's slot. A function handed the slot of
        // some longer-lived thing would put the leak back one module over from where
        // it was fixed.
        context.register_udtf(
            "records_as_of",
            Arc::new(dialect::RecordsAsOf::new(
                Arc::clone(&segments),
                Arc::clone(&slot),
            )),
        );
        context.register_udtf(
            "causal_closure",
            Arc::new(dialect::CausalClosure::new(
                Arc::clone(&segments),
                Arc::clone(&slot),
            )),
        );
        context.register_udtf(
            "trailryx_proof",
            Arc::new(dialect::ProofOfLastAnswer::new(Arc::clone(&table))),
        );
        if raw {
            context.register_udtf(
                "journal",
                Arc::new(dialect::Journal::new(
                    Arc::clone(&segments),
                    Arc::clone(&slot),
                )),
            );
        }

        Self {
            context,
            table,
            segments,
            raw,
        }
    }

    /// Run one statement, if it is one this facade serves.
    ///
    /// The gate runs **before** the engine sees the text, and its refusal is returned
    /// rather than turned into a generic error, because a caller who tried `COPY`
    /// should learn it was refused deliberately.
    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>, QueryError> {
        gate::allow(sql).map_err(QueryError::Refused)?;
        let frame = self
            .context
            .sql(sql)
            .await
            .map_err(|e| QueryError::Engine(e.to_string()))?;
        frame
            .collect()
            .await
            .map_err(|e| QueryError::Engine(e.to_string()))
    }

    /// How provable the last answer **on this session** was.
    ///
    /// A stopgap until the dialect carries `WITH PROOF`; see [`table`] for what that
    /// costs and why it is not a lie in the meantime.
    pub fn last_proof(&self) -> Option<Provability> {
        self.table.last_proof()
    }

    /// The Postgres-facing service, with the statement gate already installed.
    ///
    /// Built here rather than by the server so the gate cannot be left out. The
    /// `SessionContext` is still not exposed: a caller gets a service that has the
    /// hook, or it gets nothing, and there is no third option to reach for under time
    /// pressure.
    ///
    /// One service per session, and **not** one service per connection over one
    /// session: `SessionContext` is `Clone` over an `Arc<RwLock<SessionState>>`, so
    /// every service built from one session resolves the same registered tables and
    /// therefore the same proof slot. Isolating connections has to happen at the
    /// session, which is what [`Self::for_connection`] is for.
    pub fn pg_service(&self) -> Arc<datafusion_postgres::DfSessionService> {
        Arc::new(datafusion_postgres::DfSessionService::new_with_hooks(
            Arc::new(self.context.clone()),
            wire::hooks(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// The gate refused it, with the reason.
    Refused(Refusal),
    /// It got past the gate and the engine could not run it.
    Engine(String),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "refused: {r}"),
            Self::Engine(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for QueryError {}
