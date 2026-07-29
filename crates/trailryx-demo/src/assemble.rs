//! Turning what a source handed over into records the journal will take.
//!
//! # This belongs in a crate of its own
//!
//! Said here because burying it in a demo would misrepresent the state of the
//! architecture. The pieces on either side exist and are tested: a source
//! produces [`trailryx_contracts::ingest::Ingest`], and the journal takes a
//! [`Record`]. Nothing in the repository joins them, so this does, and it is the
//! next thing to lift out.
//!
//! What the join actually involves, and why it is not a one-line conversion:
//!
//! - **Identity.** A record id is ours to mint, never the source's. A source
//!   that could choose an id could overwrite a record by claiming its identity,
//!   and the journal's deduplication is keyed on exactly that field.
//! - **Causality.** A source names events in its own terms: a span id, a message
//!   id. Those correlation keys are matched against each other here, turned into
//!   `caused_by` edges over our record ids, and then dropped. They never reach a
//!   record, which is why [`trailryx_contracts::ingest::MetaDraft`] has no field
//!   for one.
//! - **Payload.** The classified parts go to the vault and come back as a
//!   reference. The record commits to the reference; the bytes live behind a key.
//!
//! Everything else the journal stamps itself: sequence number, previous chain
//! head, segment and shard. So this does not, and must not, guess at any of them.

use std::collections::BTreeMap;
use trailryx_contracts::ingest::{Ingest, MetaDraft, SourceKey};
use trailryx_erasure::subject::SubjectHandle;
use trailryx_erasure::vault::{Vault, VaultError};
use trailryx_record::{
    Algorithms, MapperVersion, Outcome, PayloadRef, Record, RecordId, SegmentId, ShardIx, Timestamp,
};

/// Mints record ids and remembers what a source called things.
#[derive(Debug)]
pub struct Assembler {
    shard: ShardIx,
    /// A monotonic counter standing in for a ULID.
    ///
    /// A real store mints a ULID, which sorts by time and carries no meaning. A
    /// counter sorts by time too, which is the only property anything here
    /// depends on, and it makes a demo run reproducible.
    next: u128,
    /// The source's own names for events, live only while a batch is being
    /// assembled. Dropped with the assembler, so nothing here outlives the
    /// records it helped build.
    correlation: BTreeMap<SourceKey, RecordId>,
}

impl Assembler {
    pub fn new(shard: ShardIx) -> Self {
        Self {
            shard,
            next: 1,
            correlation: BTreeMap::new(),
        }
    }

    /// The id the next record will get, so a payload can be sealed against the
    /// record that is about to carry it.
    pub fn peek(&self) -> u128 {
        self.next
    }

    fn mint(&mut self) -> RecordId {
        let id = RecordId(self.next);
        self.next += 1;
        id
    }

    /// A record written with the store's own envelope: full basis, our clock.
    #[allow(clippy::too_many_arguments)]
    pub fn own(
        &mut self,
        draft: MetaDraft,
        recorded_at: Timestamp,
        caused_by: Vec<RecordId>,
        payload: Option<PayloadRef>,
    ) -> Record {
        let id = self.mint();
        assemble(id, self.shard, draft, recorded_at, caused_by, payload)
    }

    /// A record from something a source handed over.
    ///
    /// The correlation key is used once, to resolve the parent into an edge, and
    /// then it is gone.
    pub fn adopt<O, K, A, S>(
        &mut self,
        ingest: Ingest,
        recorded_at: Timestamp,
        vault: &mut Vault<O, K, A, S>,
        subject: Option<&SubjectHandle>,
    ) -> Result<Record, VaultError>
    where
        O: trailryx_contracts::contracts::ObjectStore,
        K: trailryx_contracts::contracts::KeyProvider,
        A: trailryx_erasure::aead::Aead,
        S: trailryx_erasure::aead::KeySource,
    {
        let id = self.mint();

        let caused_by = ingest
            .correlation
            .and_then(|c| c.parent)
            .and_then(|parent| self.correlation.get(&parent).copied())
            .map(|parent| vec![parent])
            .unwrap_or_default();
        if let Some(correlation) = ingest.correlation {
            self.correlation.insert(correlation.id, id);
        }

        let payload = if ingest.payload.is_empty() {
            None
        } else {
            Some(vault.seal(id, &ingest.payload, subject)?)
        };

        Ok(assemble(
            id,
            self.shard,
            ingest.meta,
            recorded_at,
            caused_by,
            payload,
        ))
    }
}

fn assemble(
    id: RecordId,
    shard: ShardIx,
    draft: MetaDraft,
    recorded_at: Timestamp,
    caused_by: Vec<RecordId>,
    payload: Option<PayloadRef>,
) -> Record {
    Record {
        id,
        tenant: draft.tenant,
        shard,
        agent_id: draft.agent_id,
        run_id: draft.run_id,
        parent_run_id: draft.parent_run_id,
        on_behalf_of: draft.on_behalf_of,
        occurred_at: draft.occurred_at,
        decided_at: draft.decided_at,
        // Ours, always. The draft's `occurred_at` is the emitter's and stays
        // wrapped as untrusted; this is the one the index sorts on.
        recorded_at,
        knowledge_as_of: None,
        clock_skew_nanos: Some(
            trailryx_record::assess_skew(draft.occurred_at, recorded_at).skew_nanos(),
        ),
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
        payload,
        // Stamped by the journal on append. Set to nothing here so a reader of
        // this function is not misled into thinking they mean anything yet.
        seq: 0,
        prev_hash: trailryx_record::Hash::ZERO,
        segment_id: SegmentId(0),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}
