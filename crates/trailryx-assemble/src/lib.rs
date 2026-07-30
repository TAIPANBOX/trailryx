//! Turning what a source handed over into records the journal will take.
//!
//! The two sides of this seam were built and tested before the middle was. A
//! source produces [`trailryx_contracts::ingest::Ingest`]; the journal takes a
//! [`trailryx_record::Record`]. Nothing joined them, so for one commit the join
//! lived in the demo binary, which was the wrong place for the missing half of a
//! write path. This is that half, and moving it here closed three defects that a
//! demo could tolerate and a store cannot:
//!
//! - **Identity.** It minted ids from a counter, so the first record after a
//!   restart claimed an identity a record already had, the journal reported a
//!   duplicate, and the record was dropped. Now it mints a ULID, whose high bits
//!   are the clock. See [`ids`].
//! - **Memory.** It remembered every source name it had ever seen. A demo exits;
//!   a receiver runs for months. Now the window is bounded. See [`correlation`].
//! - **Order.** The caller had to ask what the next id would be, seal a payload
//!   against it, and pass the reference back in. Two steps that had to agree, in
//!   two places. Now the id is minted first and the sealing happens here.
//!
//! # What this decides, and what it refuses to
//!
//! It decides three things and nothing else:
//!
//! - the record's identity, which is ours to mint and never a source's. A source
//!   that could choose an id could overwrite a record by claiming its identity,
//!   because the journal's deduplication is keyed on exactly that field;
//! - the `caused_by` edges, by matching the source's own names against each other
//!   and then forgetting them;
//! - `recorded_at`, which is the store's clock, and the skew between it and
//!   whatever the emitter claimed.
//!
//! Everything else the journal stamps on append: the sequence number, the
//! previous chain head, the segment and the shard. So this does not guess at any
//! of them, and the fields are left at values that are obviously nothing rather
//! than at plausible ones.

pub mod correlation;
pub mod ids;

use std::collections::BTreeMap;

use correlation::Correlation;
use ids::Ids;
use trailryx_contracts::contracts::{KeyProvider, ObjectStore};
use trailryx_contracts::ingest::{Ingest, MetaDraft, PayloadPart};
use trailryx_erasure::aead::{Aead, KeySource};
use trailryx_erasure::subject::SubjectHandle;
use trailryx_erasure::vault::{Vault, VaultError};
use trailryx_record::{
    Algorithms, ErrorCode, EventType, Hash, Outcome, PayloadClass, PayloadRef, Record, RecordId,
    RunId, SegmentId, Severity, ShardIx, Timestamp, Untrusted, Verdict, assess_skew,
};
use trailryx_sim::rng::Rng;

/// How many source names to keep.
///
/// A parent and its child are milliseconds apart in a trace, so this covers the
/// real distance by orders of magnitude. It does not cover arrival *order*, which
/// is a separate problem with a separate fix: see [`Assembler::adopt_batch`].
pub const DEFAULT_CORRELATION_WINDOW: usize = 65_536;

/// A record, and the payload parts that still have to go behind a key.
///
/// Two pieces rather than one because sealing needs a vault and the caller owns
/// that. Handing back a record whose payload reference was already filled in
/// would mean this crate deciding whose data it is, and it does not know.
#[derive(Debug)]
pub struct Assembled {
    pub record: Record,
    pub payload: Vec<PayloadPart>,
}

impl Assembled {
    /// Put the payload behind a key and commit the record to the reference.
    ///
    /// One function rather than two steps in the caller, because the id has to be
    /// minted before the payload is sealed against it and there is no reason to
    /// make anybody else remember that.
    pub fn seal<O, K, A, S>(
        mut self,
        vault: &mut Vault<O, K, A, S>,
        subject: Option<&SubjectHandle>,
    ) -> Result<Record, VaultError>
    where
        O: ObjectStore,
        K: KeyProvider,
        A: Aead,
        S: KeySource,
    {
        if self.payload.is_empty() {
            return Ok(self.record);
        }
        let reference = vault.seal(self.record.id, &self.payload, subject)?;
        self.record.payload = Some(reference);
        Ok(self.record)
    }

    /// Whether anything is waiting to be sealed.
    pub fn has_payload(&self) -> bool {
        !self.payload.is_empty()
    }
}

/// One shard's minter of identities and resolver of edges.
///
/// One per shard, and only one: two assemblers on one shard would be two minters
/// of a single identity space, which this type cannot prevent and its caller must
/// not do.
#[derive(Debug)]
pub struct Assembler<R> {
    shard: ShardIx,
    ids: Ids<R>,
    correlation: Correlation,
    unresolved_parents: u64,
    /// Which runs lost an edge, and how many, until somebody writes it down.
    ///
    /// A count on its own could never reach a reconstruction. `reconstruct` can only
    /// downgrade a proof for an edge that is *present* and unresolvable: an edge that
    /// was never created produces no hop, so the closure stayed `Full` and
    /// `is_complete()` returned true, indistinguishable from a run that genuinely had
    /// no parent. That was the second debt the README carried.
    ///
    /// Keyed by run, because that is what makes the fix possible without touching the
    /// frozen record schema. A `StoreEvent` carrying the affected run's own id is
    /// found by the very query a reconstruction of that run already runs, since
    /// `run_id` is one of the five provable dimensions. So the downgrade ends up
    /// backed by a chained, committed record rather than by a number in memory, which
    /// is strictly better than the field I was going to add.
    ///
    /// Bounded by the correlation window, for the same reason that is: a receiver
    /// runs for months and a map of every run it ever saw is a leak whose symptom is
    /// a store that gets slower and then stops.
    lost_edges: BTreeMap<RunId, u32>,
}

impl<R: Rng> Assembler<R> {
    pub fn new(shard: ShardIx, rng: R) -> Self {
        Self::with_window(shard, rng, DEFAULT_CORRELATION_WINDOW)
    }

    pub fn with_window(shard: ShardIx, rng: R, window: usize) -> Self {
        Self {
            shard,
            ids: Ids::new(rng),
            correlation: Correlation::new(window),
            unresolved_parents: 0,
            lost_edges: BTreeMap::new(),
        }
    }

    pub fn shard(&self) -> ShardIx {
        self.shard
    }

    pub fn correlation(&self) -> &Correlation {
        &self.correlation
    }

    /// How many events named a parent that could not be resolved into an edge.
    ///
    /// Counted because it was not. An unresolvable parent produced no edge, no
    /// counter and no marker, so the missing edge was indistinguishable from an
    /// event that genuinely had no parent, and a reconstruction over such records
    /// reported itself complete. Downgrading the *proof* for it needs a field on
    /// the record and the record schema is frozen, so this is the honest half that
    /// can be had now: an operator can see that edges were lost, and how many.
    pub fn unresolved_parents(&self) -> u64 {
        self.unresolved_parents
    }

    /// One record per run that lost an edge, so a reconstruction of that run finds out.
    ///
    /// This is the whole fix for the second debt, and the shape is the interesting
    /// part. `reconstruct` can only downgrade a proof for an edge that is *present*
    /// and unresolvable; an edge that was never created produces no hop, so the
    /// closure stayed `Full` and said it was complete. A counter here could never
    /// change that, because a counter is not in the store.
    ///
    /// A record is. Each one carries the affected run's **own** `run_id`, which is one
    /// of the five provable dimensions, so the query a reconstruction of that run
    /// already runs finds it without a new index, a new field or a format version.
    /// The record schema is frozen and stays frozen.
    ///
    /// `EventType::StoreEvent` is the store speaking about itself, which its own doc
    /// comment lists as "a gap, a re-sign, a recovery", and a lost edge is a gap.
    /// `Verdict::Failed` is what a reconstruction looks for: it does not need to know
    /// which kind of loss this was, only that something about this run was lost, so
    /// nothing here has to be invented to be recognised.
    ///
    /// Drains what it reports. Calling it twice does not double the record, and a run
    /// that loses another edge later earns another one.
    pub fn lost_edge_events(
        &mut self,
        recorded_at: Timestamp,
        draft: &MetaDraft,
    ) -> Vec<Assembled> {
        let lost = std::mem::take(&mut self.lost_edges);
        lost.into_iter()
            .map(|(run_id, edges)| {
                let mut meta = draft.clone();
                // The run that lost the edge, not the store's own synthetic one. That
                // substitution is the entire mechanism: the record lands in the same
                // run_id index bucket as the records it is about.
                meta.run_id = run_id;
                meta.mapper = trailryx_record::MapperVersion::UNMAPPED;
                meta.event_type = EventType::StoreEvent;
                meta.severity = Severity::Warning;
                meta.verdict = Some(Verdict::Failed);
                meta.error = Some(ErrorCode::Internal);
                meta.occurred_at = Untrusted::new(recorded_at);
                meta.decided_at = None;
                meta.latency_micros = None;
                meta.tokens_in = Some(edges);
                meta.tokens_out = None;
                meta.cost_micros = None;
                let id = self.ids.mint(recorded_at);
                Assembled {
                    record: assemble(id, self.shard, meta, recorded_at, Vec::new()),
                    // The count is metadata and survives erasure; the detail is
                    // payload, because a source's own name for a parent is the
                    // source's text and belongs on the encrypted side.
                    payload: vec![PayloadPart::new(
                        PayloadClass::Diagnostic,
                        format!("caused_by_unresolved\t{edges}\n").into_bytes(),
                    )],
                }
            })
            .collect()
    }

    /// Whether any run is waiting for one of those records.
    pub fn has_lost_edges(&self) -> bool {
        !self.lost_edges.is_empty()
    }

    /// A record from the store's own envelope, where the caller knows the edges.
    pub fn record(
        &mut self,
        draft: MetaDraft,
        recorded_at: Timestamp,
        caused_by: Vec<RecordId>,
        payload: Vec<PayloadPart>,
    ) -> Assembled {
        let id = self.ids.mint(recorded_at);
        Assembled {
            record: assemble(id, self.shard, draft, recorded_at, caused_by),
            payload,
        }
    }

    /// A whole batch from a source, resolved after every unit in it has a name.
    ///
    /// **This is the method an adapter should call.** Resolving in arrival order
    /// cannot work for OpenTelemetry, and OpenTelemetry is the only source in the
    /// tree: a span is exported when it *ends*, and a child ends inside its
    /// parent, so a batch arrives children first. [`Self::adopt`] resolves a
    /// parent before remembering the current event, so a parent that arrives after
    /// its child could never be found, whatever the window size. Measured through
    /// the real wire path: two spans, one parent and one child, one batch, in the
    /// order an SDK produces them, and both records came out with no edges at all.
    /// The causal graph, which the contracts crate calls half of what the store is
    /// for, was empty for every OTLP-sourced trace.
    ///
    /// So: mint every id and remember every name first, then resolve. An edge
    /// within a batch is found regardless of the order the batch is in, and the
    /// window still carries parents from earlier batches.
    pub fn adopt_batch(&mut self, batch: Vec<Ingest>, recorded_at: Timestamp) -> Vec<Assembled> {
        let minted: Vec<(Ingest, RecordId)> = batch
            .into_iter()
            .map(|ingest| {
                let id = self.ids.mint(recorded_at);
                if let Some(correlation) = ingest.correlation {
                    self.correlation.remember(correlation.id, id);
                }
                (ingest, id)
            })
            .collect();

        minted
            .into_iter()
            .map(|(ingest, id)| self.finish(ingest, id, recorded_at))
            .collect()
    }

    /// One event, where nothing later in the same batch can be its parent.
    ///
    /// Correct for a source that emits parents before children and for a caller
    /// handing over a single event. For a batch use [`Self::adopt_batch`], which
    /// is the only thing that works when the batch is ordered children first.
    pub fn adopt(&mut self, ingest: Ingest, recorded_at: Timestamp) -> Assembled {
        let id = self.ids.mint(recorded_at);
        if let Some(correlation) = ingest.correlation {
            self.correlation.remember(correlation.id, id);
        }
        self.finish(ingest, id, recorded_at)
    }

    /// Resolve the edge and build the record. The id is already minted and this
    /// event's own name is already remembered.
    fn finish(&mut self, ingest: Ingest, id: RecordId, recorded_at: Timestamp) -> Assembled {
        let mut caused_by = Vec::new();
        let mut lost = false;
        if let Some(parent) = ingest.correlation.and_then(|c| c.parent) {
            match self.correlation.resolve(&parent) {
                // A span naming itself as its own parent. Not a guess to make:
                // an edge from a record to itself is a cycle of length one, and
                // remembering this event's name before resolving is what makes it
                // reachable at all.
                Some(found) if found == id => lost = true,
                Some(found) => caused_by.push(found),
                // Out of the window, or in another shard's assembler. No edge,
                // and counted rather than dropped in silence.
                None => lost = true,
            }
        }
        if lost {
            self.unresolved_parents += 1;
            // Against the run that lost it, so a reconstruction of that run can find
            // out. Bounded like the correlation window it shares a lifetime with: at
            // the cap the count is dropped rather than the map grown, and dropping a
            // count is not dropping the fact, because the total above never resets.
            if self.lost_edges.len() < self.correlation.capacity() {
                let entry = self
                    .lost_edges
                    .entry(ingest.meta.run_id.clone())
                    .or_insert(0);
                *entry = entry.saturating_add(1);
            } else if let Some(entry) = self.lost_edges.get_mut(&ingest.meta.run_id) {
                *entry = entry.saturating_add(1);
            }
        }

        Assembled {
            record: assemble(id, self.shard, ingest.meta, recorded_at, caused_by),
            payload: ingest.payload,
        }
    }
}

fn assemble(
    id: RecordId,
    shard: ShardIx,
    draft: MetaDraft,
    recorded_at: Timestamp,
    caused_by: Vec<RecordId>,
) -> Record {
    Record {
        id,
        tenant: draft.tenant,
        shard,
        agent_id: draft.agent_id,
        run_id: draft.run_id,
        parent_run_id: draft.parent_run_id,
        on_behalf_of: draft.on_behalf_of,
        // The emitter's clock, and it stays wrapped so nothing downstream can
        // quietly treat it as ours.
        occurred_at: draft.occurred_at,
        decided_at: draft.decided_at,
        // Ours, always. This is the one the index sorts on.
        recorded_at,
        knowledge_as_of: None,
        // Recorded rather than judged. A record from a machine an hour out of
        // step is still evidence; a record that hid the disagreement would not
        // be.
        clock_skew_nanos: Some(assess_skew(draft.occurred_at, recorded_at).skew_nanos()),
        event_type: draft.event_type,
        severity: draft.severity,
        basis: draft.basis,
        caused_by,
        outcome: Outcome {
            verdict: draft.verdict,
            error: draft.error,
            latency_micros: draft.latency_micros,
            tokens_in: draft.tokens_in,
            tokens_out: draft.tokens_out,
            cost_micros: draft.cost_micros,
        },
        // Filled in by `Assembled::seal`, if there is anything to seal.
        payload: None,
        // Stamped by the journal on append. Left at values that are obviously
        // nothing, so a reader is not misled into thinking they mean something
        // yet: a plausible sequence number here would be a lie that survives.
        seq: 0,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(0),
        algorithms: Algorithms::default(),
        // The source's, not ours. A literal 1 here made every record in the store
        // claim to have come from the first version of the GenAI mapper, including
        // the ones the store wrote about itself and the ones a later mapper had
        // produced. See `MetaDraft::mapper`.
        mapper: draft.mapper,
    }
}

/// A payload reference for a record assembled elsewhere.
///
/// Exists for the erasure manifest, which is a payload the store writes about
/// itself rather than one a source handed over.
pub fn attach(record: &mut Record, reference: PayloadRef) {
    record.payload = Some(reference);
}
