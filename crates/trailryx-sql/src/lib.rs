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

pub mod pushdown;
