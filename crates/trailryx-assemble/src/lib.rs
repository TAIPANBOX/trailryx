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

use correlation::Correlation;
use ids::Ids;
use trailryx_contracts::contracts::{KeyProvider, ObjectStore};
use trailryx_contracts::ingest::{Ingest, MetaDraft, PayloadPart};
use trailryx_erasure::aead::{Aead, KeySource};
use trailryx_erasure::subject::SubjectHandle;
use trailryx_erasure::vault::{Vault, VaultError};
use trailryx_record::{
    Algorithms, Hash, MapperVersion, Outcome, PayloadRef, Record, RecordId, SegmentId, ShardIx,
    Timestamp, assess_skew,
};
use trailryx_sim::rng::Rng;

/// How many source names to keep. A parent arrives before its child within
/// milliseconds, so this is generous by orders of magnitude.
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
        }
    }

    pub fn shard(&self) -> ShardIx {
        self.shard
    }

    pub fn correlation(&self) -> &Correlation {
        &self.correlation
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

    /// A record from what a source handed over.
    ///
    /// The source's name for this event is remembered so a later child can point
    /// at it, and its name for the parent is resolved into an edge. A parent that
    /// has fallen out of the window yields no edge, which is not a guess and is
    /// not silence either: a reconstruction missing an edge reports itself
    /// incomplete.
    pub fn adopt(&mut self, ingest: Ingest, recorded_at: Timestamp) -> Assembled {
        let id = self.ids.mint(recorded_at);

        let caused_by = ingest
            .correlation
            .and_then(|c| c.parent)
            .and_then(|parent| self.correlation.resolve(&parent))
            .map(|parent| vec![parent])
            .unwrap_or_default();
        if let Some(correlation) = ingest.correlation {
            self.correlation.remember(correlation.id, id);
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
        mapper: MapperVersion(1),
    }
}

/// A payload reference for a record assembled elsewhere.
///
/// Exists for the erasure manifest, which is a payload the store writes about
/// itself rather than one a source handed over.
pub fn attach(record: &mut Record, reference: PayloadRef) {
    record.payload = Some(reference);
}
