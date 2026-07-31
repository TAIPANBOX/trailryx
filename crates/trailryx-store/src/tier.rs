//! Hot and cold, and the read that crosses between them.
//!
//! # What the tier is for
//!
//! §6.1 of the architecture puts the journal and the freshest segments on local
//! disk and the rest in object storage. Until this module existed the cold half was
//! a pair of functions nobody called: [`crate::cold`] could publish a segment and
//! read one back, and nothing decided when to do either.
//!
//! A [`Tier`] holds the recent segments locally, publishes every sealed segment to
//! the object store, and drops the oldest from memory once there are more than the
//! policy keeps. A query for a segment that is no longer local fetches it back.
//!
//! # The question that makes this worth writing carefully
//!
//! **A segment fetched from cold storage has to be as trustworthy as one that never
//! left.** Object storage is somebody else's disk, the bytes came back over a
//! network, and the whole product is a claim about bytes not having changed.
//!
//! So warming a segment does not decode it and hand it over. It **re-seals** it:
//! the records are decoded, their chain links are recomputed from the manifest's
//! own `chain_before`, and the whole segment is built again from those bytes. The
//! manifest that falls out is compared with the manifest that was published.
//!
//! That comparison is the check, and it is a strong one. The manifest commits to
//! the history root, to all five index roots and to both chain ends, so a single
//! byte altered anywhere in the body produces a different manifest and the fetch is
//! refused. It costs the work of sealing, which is the honest price of not trusting
//! a bucket.
//!
//! It is also not the same as marking one's own homework. The published manifest is
//! what a signature and an anchor commit to, so agreeing with it is agreeing with
//! something an outside party attested to, rather than with this process's memory.

use std::collections::BTreeMap;

use trailryx_contracts::ObjectStore;
use trailryx_crypto::chain_step;
use trailryx_index::segment::Segment;
use trailryx_index::{SealError, SegmentManifest};
use trailryx_journal::wire::decode_record;
use trailryx_record::{Hash, Record, SegmentId, ShardIx};

use crate::cold::{self, ColdError};
use crate::query::{Answer, Query, query_segment};
use crate::seal::SealedSegment;

/// How much stays on local disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// How many of the newest segments per shard stay hot.
    ///
    /// Not a byte budget: a segment is the unit everything else here is counted
    /// in, and a policy in bytes would evict half of one.
    pub keep_hot: usize,
}

impl Default for Policy {
    fn default() -> Self {
        // Enough that an ordinary query about recent activity never touches the
        // object store, and small enough that the cold path is exercised in any
        // run long enough to seal a few segments.
        Self { keep_hot: 4 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TierError {
    Cold(ColdError),
    /// The object store has no such segment. Distinct from a failure: a segment
    /// nobody published is absent, and a caller may have asked about a future one.
    NotPublished,
    /// A record in the fetched body is not a record.
    Undecodable,
    /// The body decoded and the segment it produces is not the segment that was
    /// published. Every byte of the body is under the manifest, so this is what
    /// tampering in the bucket looks like from here.
    ManifestMismatch {
        published: Box<SegmentManifest>,
        recomputed: Box<SegmentManifest>,
    },
    /// The records cannot be sealed into a segment at all.
    Seal(SealError),
}

impl std::fmt::Display for TierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cold(e) => write!(f, "{e}"),
            Self::NotPublished => f.write_str("no such segment has been published"),
            Self::Undecodable => {
                f.write_str("the fetched body holds something that is not a record")
            }
            Self::ManifestMismatch { published, .. } => write!(
                f,
                "the body fetched for segment {} does not rebuild the manifest that was \
                 published for it, so those bytes are not the ones that were sealed",
                published.segment.0
            ),
            Self::Seal(e) => write!(f, "the fetched records do not form a segment: {e:?}"),
        }
    }
}

impl std::error::Error for TierError {}

/// Local segments in front of an object store.
pub struct Tier<O: ObjectStore> {
    cold: O,
    hot: BTreeMap<(ShardIx, SegmentId), Segment>,
    policy: Policy,
    /// Counted rather than logged, because the useful question about a tier is how
    /// often it had to go to the store, and a counter answers it in a test too.
    warmed: u64,
}

impl<O: ObjectStore> std::fmt::Debug for Tier<O> {
    /// Written rather than derived: the object store underneath is somebody's
    /// deployment and its `Debug` is not this type's to print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tier")
            .field("hot", &self.hot.len())
            .field("policy", &self.policy)
            .field("warmed", &self.warmed)
            .finish_non_exhaustive()
    }
}

impl<O: ObjectStore> Tier<O> {
    pub fn new(cold: O, policy: Policy) -> Self {
        Self {
            cold,
            hot: BTreeMap::new(),
            policy,
            warmed: 0,
        }
    }

    /// How many times a query had to fetch a segment back from the object store.
    pub fn warmed(&self) -> u64 {
        self.warmed
    }

    pub fn hot_count(&self) -> usize {
        self.hot.len()
    }

    /// Publish a sealed segment and keep it hot, evicting whatever the policy no
    /// longer keeps.
    ///
    /// Published first, evicted second, and never the other way round: dropping a
    /// segment from memory before the store has it is how a segment stops existing.
    pub fn publish(&mut self, sealed: &SealedSegment, attempts: u32) -> Result<(), TierError> {
        let manifest = sealed.manifest().clone();
        let bodies: Vec<Vec<u8>> = sealed
            .segment
            .records()
            .iter()
            .map(trailryx_journal::wire::encode_record)
            .collect();
        cold::publish_segment(&mut self.cold, &manifest, &bodies, attempts)
            .map_err(TierError::Cold)?;

        self.hot
            .insert((manifest.shard, manifest.segment), sealed.segment.clone());
        self.evict();
        Ok(())
    }

    /// Drop the oldest segments of each shard beyond what the policy keeps.
    fn evict(&mut self) {
        let mut per_shard: BTreeMap<ShardIx, Vec<SegmentId>> = BTreeMap::new();
        for (shard, segment) in self.hot.keys() {
            per_shard.entry(*shard).or_default().push(*segment);
        }
        for (shard, mut segments) in per_shard {
            if segments.len() <= self.policy.keep_hot {
                continue;
            }
            // The map is ordered, so this is oldest first already; sorted anyway
            // rather than relying on it from a distance.
            segments.sort();
            let drop = segments.len() - self.policy.keep_hot;
            for segment in segments.into_iter().take(drop) {
                self.hot.remove(&(shard, segment));
            }
        }
    }

    /// A query, answered from memory or from the object store, with the same answer
    /// and the same proof either way.
    pub fn query(
        &mut self,
        shard: ShardIx,
        segment: SegmentId,
        q: &Query,
    ) -> Result<Answer, TierError> {
        if let Some(held) = self.hot.get(&(shard, segment)) {
            return Ok(query_segment(held, q));
        }
        let warmed = self.warm(shard, segment)?;
        let answer = query_segment(&warmed, q);
        // Kept, because a cold segment somebody asked about is a segment somebody
        // is likely to ask about again, and the policy will evict it in turn.
        self.hot.insert((shard, segment), warmed);
        self.evict();
        Ok(answer)
    }

    /// Fetch a segment out of cold storage and rebuild it, refusing bytes that do
    /// not rebuild what was published.
    pub fn warm(&mut self, shard: ShardIx, segment: SegmentId) -> Result<Segment, TierError> {
        let fetched = cold::fetch_segment(&mut self.cold, shard, segment)
            .map_err(TierError::Cold)?
            .ok_or(TierError::NotPublished)?;
        self.warmed += 1;

        let mut records: Vec<(Record, Hash)> = Vec::with_capacity(fetched.records.len());
        let mut link = fetched.manifest.chain_before;
        for bytes in &fetched.records {
            let record = decode_record(bytes).map_err(|_| TierError::Undecodable)?;
            // Recomputed rather than stored: a link that travelled with the record
            // would be a claim by whoever wrote the object, and this is the one
            // number that must not be taken on trust.
            link = chain_step(link, record.seq, bytes);
            records.push((record, link));
        }

        let rebuilt = Segment::seal(segment, shard, fetched.manifest.chain_before, &records)
            .map_err(TierError::Seal)?;
        if *rebuilt.manifest() != fetched.manifest {
            return Err(TierError::ManifestMismatch {
                published: Box::new(fetched.manifest),
                recomputed: Box::new(rebuilt.manifest().clone()),
            });
        }
        Ok(rebuilt)
    }

    /// The object store underneath, for an operator that has to look.
    pub fn cold_store(&mut self) -> &mut O {
        &mut self.cold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_contracts::fakes::{MemoryObjectStore, VersioningObjectStore};
    use trailryx_index::completeness::Dimension;
    use trailryx_journal::wire::encode_record;
    use trailryx_record::{Hash as RecordHash, Record};

    use crate::cold::encode_body;

    /// One record, built the way the store's own query tests build them.
    fn record(seq: u64, prev: Hash) -> Record {
        use trailryx_record::{
            AgentId, Algorithms, Basis, EventType, MapperVersion, Outcome, RecordId, RunId,
            Severity, TenantId, Timestamp, Untrusted,
        };
        Record {
            id: RecordId(u128::from(seq)),
            tenant: TenantId::parse("acme").expect("a tenant"),
            shard: ShardIx(0),
            agent_id: AgentId::parse("agent://acme.example/support").expect("an agent"),
            run_id: RunId::parse("run-1").expect("a run"),
            parent_run_id: None,
            on_behalf_of: Vec::new(),
            occurred_at: Untrusted::new(Timestamp(1_000 + seq)),
            decided_at: None,
            recorded_at: Timestamp(1_000 + seq),
            knowledge_as_of: None,
            clock_skew_nanos: None,
            event_type: EventType::ModelCall,
            severity: Severity::Info,
            basis: Basis::default(),
            caused_by: Vec::new(),
            outcome: Outcome::default(),
            payload: None,
            seq,
            prev_hash: prev,
            segment_id: SegmentId(1),
            algorithms: Algorithms::default(),
            mapper: MapperVersion(1),
        }
    }

    /// A segment sealed with real chain links, because the tier recomputes them
    /// and a stand-in link would make the round trip prove nothing.
    fn sealed(shard: u16, segment: u64, count: u64, from: Hash) -> SealedSegment {
        let mut records = Vec::new();
        let mut link = from;
        for n in 0..count {
            let r = record(n + segment * 100, link);
            let bytes = encode_record(&r);
            link = chain_step(link, r.seq, &bytes);
            records.push((r, link));
        }
        let segment_value = Segment::seal(SegmentId(segment), ShardIx(shard), from, &records)
            .expect("records seal into a segment");
        SealedSegment {
            segment: segment_value,
            records: count,
            chain_after: link,
        }
    }

    fn any_query() -> Query {
        Query::range(Dimension::RecordedAt, Vec::new(), vec![0xff; 8])
    }

    /// `Answer` holds proofs that do not compare, so equality is stated as what a
    /// caller would notice: the same records, the same proof status, the same
    /// count before filters.
    fn same(a: &Answer, b: &Answer) -> bool {
        a.proof == b.proof
            && a.matched_before_filters == b.matched_before_filters
            && a.records
                .iter()
                .map(|r| r.id)
                .eq(b.records.iter().map(|r| r.id))
            && a.segment_proofs.len() == b.segment_proofs.len()
    }

    #[test]
    fn a_query_is_answered_the_same_whether_the_segment_is_hot_or_cold() {
        let mut tier = Tier::new(MemoryObjectStore::default(), Policy { keep_hot: 1 });
        let first = sealed(0, 1, 3, RecordHash::ZERO);
        let second = sealed(0, 2, 3, first.chain_after);

        tier.publish(&first, 1).expect("published");
        let hot = tier
            .query(ShardIx(0), SegmentId(1), &any_query())
            .expect("a hot answer");
        assert_eq!(tier.warmed(), 0, "the first answer came from memory");

        // The second publication evicts the first, so the same query has to cross
        // into the object store.
        tier.publish(&second, 1).expect("published");
        assert_eq!(tier.hot_count(), 1, "the policy keeps one");

        let cold = tier
            .query(ShardIx(0), SegmentId(1), &any_query())
            .expect("a cold answer");
        assert_eq!(tier.warmed(), 1, "and it did come from the store");
        assert!(
            same(&cold, &hot),
            "a segment that went to cold storage must answer exactly as it did when it was \
             hot, proof included"
        );
        assert!(
            !cold.records.is_empty(),
            "a comparison of two empty answers would prove nothing"
        );
    }

    #[test]
    fn a_segment_nobody_published_is_named_rather_than_answered_emptily() {
        let mut tier = Tier::new(MemoryObjectStore::default(), Policy::default());
        assert!(matches!(
            tier.query(ShardIx(0), SegmentId(99), &any_query()),
            Err(TierError::NotPublished)
        ));
    }

    /// The defence the whole module exists for. Somebody with write access replaces
    /// the body in the bucket with records that are internally consistent: they
    /// chain, they seal, they produce a perfectly good segment. It is just not the
    /// segment that was published, and the manifest says so.
    #[test]
    fn a_body_replaced_with_a_different_valid_segment_is_still_refused() {
        let mut tier = Tier::new(VersioningObjectStore::default(), Policy { keep_hot: 0 });
        let real = sealed(0, 1, 3, RecordHash::ZERO);
        tier.publish(&real, 1).expect("published");

        // A different segment, sealed correctly, written under the same body key.
        let forged = sealed(0, 1, 5, RecordHash::ZERO);
        let bodies: Vec<Vec<u8>> = forged.segment.records().iter().map(encode_record).collect();
        let real_bodies: Vec<Vec<u8>> = real.segment.records().iter().map(encode_record).collect();
        let body_key = trailryx_publish::Publication {
            shard: ShardIx(0),
            segment: SegmentId(1),
            manifest: Vec::new(),
            body: encode_body(&real_bodies),
        }
        .body_key();
        tier.cold_store()
            .overwrite(&body_key, &encode_body(&bodies));

        match tier.query(ShardIx(0), SegmentId(1), &any_query()) {
            // The digest check in `cold` catches it first, which is the cheaper
            // check doing its job. Either refusal is correct; being answered is not.
            Err(TierError::Cold(ColdError::BodyAltered)) => {}
            Err(TierError::ManifestMismatch { .. }) => {}
            other => panic!("forged bytes must not be answered from: {other:?}"),
        }
    }

    /// The attack the previous test cannot reach, and the reason this one exists.
    ///
    /// An operator who can write to the bucket replaces the body AND rewrites the
    /// envelope so its digest matches the new body. The cheap check now passes: the
    /// bytes are exactly what the envelope says they are. What they are not is the
    /// segment whose manifest was signed and anchored, and only rebuilding catches
    /// that.
    ///
    /// Written after a mutation showed the manifest comparison was never exercised:
    /// the digest check caught everything first, so the deep check was a comment.
    #[test]
    fn a_body_and_its_envelope_replaced_together_are_caught_by_rebuilding() {
        let mut tier = Tier::new(VersioningObjectStore::default(), Policy { keep_hot: 0 });
        let real = sealed(0, 1, 3, RecordHash::ZERO);
        tier.publish(&real, 1).expect("published");

        // The same count as the real segment, so the cheaper checks in `cold` have
        // nothing to say: only the contents differ, which is the case that has to
        // reach the rebuild.
        let forged = sealed(0, 1, 3, RecordHash([9u8; 48]));
        let forged_body = encode_body(
            &forged
                .segment
                .records()
                .iter()
                .map(encode_record)
                .collect::<Vec<_>>(),
        );
        let real_body = encode_body(
            &real
                .segment
                .records()
                .iter()
                .map(encode_record)
                .collect::<Vec<_>>(),
        );

        // The forged body goes at the key its own digest names, which is where the
        // rewritten envelope will point. Keys here are content-addressed, so an
        // attacker does not overwrite the old body, they add theirs beside it.
        let _ = real_body;
        let key = trailryx_publish::Publication {
            shard: ShardIx(0),
            segment: SegmentId(1),
            manifest: Vec::new(),
            body: forged_body.clone(),
        }
        .body_key();
        tier.cold_store().overwrite(&key, &forged_body);

        // And the envelope rewritten so its digest matches, keeping the published
        // manifest, which is the part the attacker cannot forge a signature over.
        let envelope = crate::cold::encode_envelope(
            &trailryx_publish::body_digest(&forged_body),
            real.manifest(),
        );
        let manifest_key = trailryx_publish::Publication {
            shard: ShardIx(0),
            segment: SegmentId(1),
            manifest: Vec::new(),
            body: Vec::new(),
        }
        .manifest_key();
        tier.cold_store().overwrite(&manifest_key, &envelope);

        match tier.query(ShardIx(0), SegmentId(1), &any_query()) {
            Err(TierError::ManifestMismatch {
                published,
                recomputed,
            }) => {
                assert_ne!(published.history_root, recomputed.history_root);
            }
            other => panic!("rebuilding must refuse this: {other:?}"),
        }
    }

    #[test]
    fn the_policy_keeps_what_it_says_and_publication_always_precedes_eviction() {
        let mut tier = Tier::new(MemoryObjectStore::default(), Policy { keep_hot: 2 });
        let mut link = RecordHash::ZERO;
        for n in 1..=5u64 {
            let s = sealed(0, n, 2, link);
            link = s.chain_after;
            tier.publish(&s, 1).expect("published");
        }
        assert_eq!(tier.hot_count(), 2, "only the newest two stay local");

        // Every one of the five is still answerable, which is the point of having
        // evicted rather than deleted.
        for n in 1..=5u64 {
            assert!(
                tier.query(ShardIx(0), SegmentId(n), &any_query()).is_ok(),
                "segment {n} must still be answerable"
            );
        }
        assert_eq!(
            tier.warmed(),
            3,
            "three of the five came back from the store"
        );
    }
}
