//! Composing proofs across segments and shards.
//!
//! The honest case is short. The rest is the failure this construction exists
//! to catch: an answer that looks complete because a shard, a segment, a
//! boundary or an entire count quietly went missing.
//!
//! Four of these tests exist because the first version of this file passed
//! while the code was broken. Each one now pins a claim the answer used to be
//! allowed to make about itself.

use trailryx_crypto::Sha384;
use trailryx_index::completeness::Dimension;
use trailryx_index::segment::{
    CompositeFailure, CompositeProof, SealError, Segment, SegmentContribution, ShardContribution,
    ShardTree, StoreTree,
};
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, SigAlg, TenantId, Timestamp, Untrusted, Verdict,
};

fn record(seq: u64, shard: u16, at: u64) -> Record {
    Record {
        id: RecordId(u128::from(seq) | (u128::from(shard) << 64)),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(shard),
        agent_id: AgentId::parse("agent://acme.example/support").unwrap(),
        run_id: RunId::parse(format!("run-{shard}-{seq}")).unwrap(),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(at)),
        decided_at: None,
        recorded_at: Timestamp(at),
        knowledge_as_of: None,
        clock_skew_nanos: None,
        event_type: EventType::ModelCall,
        severity: Severity::Info,
        basis: Basis::default(),
        caused_by: Vec::new(),
        outcome: Outcome::default(),
        payload: None,
        seq,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(0),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}

/// A stand-in for the journal's chain link, which is what a real sealer passes.
fn link(shard: u16, seq: u64) -> Hash {
    Sha384::digest(format!("chain-{shard}-{seq}").as_bytes())
}

struct Store {
    shards: Vec<ShardTree>,
    segments: Vec<Vec<Segment>>,
    tree: StoreTree,
}

fn build_store() -> Store {
    let mut shards = Vec::new();
    let mut segments = Vec::new();

    for s in 0..2u16 {
        let mut shard = ShardTree::new(ShardIx(s));
        let mut segs = Vec::new();
        let mut chain = Hash::ZERO;
        for seg in 0..2u64 {
            let base = 1_000 + u64::from(s) * 100 + seg * 40;
            let pairs: Vec<(Record, Hash)> = (0..6u64)
                .map(|i| {
                    let seq = seg * 6 + i + 1;
                    (record(seq, s, base + i * 5), link(s, seq))
                })
                .collect();
            let sealed = Segment::seal(SegmentId(seg), ShardIx(s), chain, &pairs).expect("seals");
            chain = sealed.manifest().chain_after;
            shard.push(sealed.manifest().clone());
            segs.push(sealed);
        }
        shards.push(shard);
        segments.push(segs);
    }

    let tree = StoreTree::from_shards(&shards);
    Store {
        shards,
        segments,
        tree,
    }
}

/// Answer a time range across the store, skipping segments that provably lie
/// outside it.
fn answer(store: &Store, lo: u64, hi: u64) -> CompositeProof {
    let lo_k = Dimension::time_key(lo);
    let hi_k = Dimension::time_key(hi);

    let shards = store
        .shards
        .iter()
        .enumerate()
        .map(|(si, shard)| {
            let segments = store.segments[si]
                .iter()
                .enumerate()
                .map(|(gi, seg)| {
                    let m = seg.manifest().clone();
                    let mp = shard.inclusion(gi).expect("segment in shard");
                    let span = seg.time_span();
                    let outside = span.as_ref().is_none_or(|s| {
                        s.max.key.as_slice() < lo_k.as_slice()
                            || s.min.key.as_slice() > hi_k.as_slice()
                    });
                    if outside {
                        SegmentContribution::ExcludedByTime {
                            manifest: m,
                            manifest_proof: mp,
                            span,
                        }
                    } else {
                        SegmentContribution::Answered {
                            proof: Box::new(
                                seg.range(Dimension::RecordedAt, &lo_k, &hi_k)
                                    .expect("dimension exists"),
                            ),
                            manifest: m,
                            manifest_proof: mp,
                        }
                    }
                })
                .collect();
            ShardContribution {
                shard: shard.shard(),
                shard_root: shard.root(),
                segments_in_shard: shard.len(),
                shard_proof: store.tree.inclusion(si).expect("shard in store"),
                segments,
            }
        })
        .collect();

    CompositeProof {
        dimension: Dimension::RecordedAt,
        shards,
    }
}

fn verify(store: &Store, proof: &CompositeProof, lo: u64, hi: u64) -> Result<(), CompositeFailure> {
    proof.verify(
        Dimension::RecordedAt,
        &Dimension::time_key(lo),
        &Dimension::time_key(hi),
        store.tree.root(),
        store.tree.shards(),
    )
}

// ---------------------------------------------------------------------------
// Honest answers
// ---------------------------------------------------------------------------

#[test]
fn a_store_wide_answer_verifies() {
    let store = build_store();
    let p = answer(&store, 0, u64::MAX);
    assert_eq!(p.matched(), 24, "every record in both shards");
    assert_eq!(verify(&store, &p, 0, u64::MAX), Ok(()));
}

#[test]
fn a_range_straddling_segments_verifies() {
    let store = build_store();
    let p = answer(&store, 1_015, 1_045);
    assert_eq!(verify(&store, &p, 1_015, 1_045), Ok(()));
    assert!(p.matched() > 0);
}

#[test]
fn a_provably_out_of_range_segment_may_be_skipped() {
    let store = build_store();
    let p = answer(&store, 1_000, 1_020);
    let excluded = p
        .shards
        .iter()
        .flat_map(|s| &s.segments)
        .filter(|c| matches!(c, SegmentContribution::ExcludedByTime { .. }))
        .count();
    assert!(excluded > 0, "some segment should have been skipped");
    assert_eq!(verify(&store, &p, 1_000, 1_020), Ok(()));
}

// ---------------------------------------------------------------------------
// Counts must come from committed data
// ---------------------------------------------------------------------------

#[test]
fn forgetting_a_shard_breaks_the_answer() {
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    p.shards.pop();

    assert_eq!(
        verify(&store, &p, 0, u64::MAX),
        Err(CompositeFailure::ShardMissing {
            expected: 2,
            got: 1
        })
    );
}

#[test]
fn forgetting_one_segment_breaks_the_answer() {
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    p.shards[0].segments.pop();

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::SegmentsMissing { .. }),
        "got {err:?}"
    );
}

#[test]
fn forgetting_every_segment_of_a_shard_breaks_the_answer() {
    // This one passed before. The per-segment loop simply never ran, and
    // nothing else looked at how many segments there should have been, so an
    // entire shard's records disappeared from a verifying answer.
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    p.shards[1].segments.clear();

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(
            err,
            CompositeFailure::SegmentsMissing {
                expected: 2,
                got: 0,
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn understating_the_segment_count_breaks_the_answer() {
    // Adjusting the declared count to match a truncated list does not help:
    // the count is in the store leaf, so the shard's own inclusion proof fails.
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    p.shards[1].segments.clear();
    p.shards[1].segments_in_shard = 0;

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::ShardNotInStore { .. }),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Exclusion must be proven, not declared
// ---------------------------------------------------------------------------

#[test]
fn skipping_a_segment_that_does_overlap_is_refused() {
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    if let SegmentContribution::Answered {
        manifest,
        manifest_proof,
        ..
    } = p.shards[0].segments[0].clone()
    {
        let span = store.segments[0][0].time_span();
        p.shards[0].segments[0] = SegmentContribution::ExcludedByTime {
            manifest,
            manifest_proof,
            span,
        };
    }

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::ExclusionNotJustified { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_skip_without_a_span_proof_is_refused() {
    // Before, the skip was justified by the manifest's own declared bounds,
    // written by the party being audited. A sealer could write first=1 last=2
    // over records at t=5000 and then legitimately exclude the segment from
    // every query that mattered.
    let store = build_store();
    let mut p = answer(&store, 1_000, 1_020);
    for sc in &mut p.shards {
        for c in &mut sc.segments {
            if let SegmentContribution::ExcludedByTime { span, .. } = c {
                *span = None;
            }
        }
    }

    let err = verify(&store, &p, 1_000, 1_020).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::ExclusionUnproven { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_segment_cannot_be_skipped_on_a_dimension_with_no_bounds() {
    let store = build_store();
    let mut p = answer(&store, 0, 1_010);
    p.dimension = Dimension::AgentId;

    let err = p
        .verify(
            Dimension::AgentId,
            b"a",
            b"z",
            store.tree.root(),
            store.tree.shards(),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            CompositeFailure::ExclusionNotCheckable {
                dimension: Dimension::AgentId
            }
        ),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Forgery
// ---------------------------------------------------------------------------

#[test]
fn a_forged_shard_root_is_refused() {
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    p.shards[1].shard_root = Hash::ZERO;

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::ShardNotInStore { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_tampered_manifest_is_refused() {
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    if let SegmentContribution::Answered { manifest, .. } = &mut p.shards[0].segments[0] {
        manifest.records += 1;
    }

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::SegmentNotInShard { .. }),
        "got {err:?}"
    );
}

#[test]
fn hiding_a_record_inside_one_segment_still_breaks_the_whole_answer() {
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    if let SegmentContribution::Answered { proof, .. } = &mut p.shards[1].segments[1] {
        proof.entries.remove(1);
        proof.entry_proofs.remove(1);
    }

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::SegmentProof { .. }),
        "got {err:?}"
    );
}

#[test]
fn an_empty_answer_from_a_full_segment_is_refused() {
    // The struct-literal attack, composed. A proof declaring size 0 used to
    // verify against any root, so a store-wide answer of zero records verified
    // for any query at all.
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    if let SegmentContribution::Answered { proof, .. } = &mut p.shards[0].segments[0] {
        proof.size = 0;
        proof.first_index = 0;
        proof.entries.clear();
        proof.entry_proofs.clear();
        proof.left_boundary = None;
        proof.right_boundary = None;
    }

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::SegmentProof { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_manifest_from_another_shard_is_refused() {
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    if let SegmentContribution::Answered { manifest, .. } = &mut p.shards[0].segments[0] {
        manifest.shard = ShardIx(1);
    }

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::ManifestShardMismatch { .. }),
        "got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

#[test]
fn the_segment_root_depends_on_record_content() {
    // Before, the history leaf was a hash of the sequence number, so a segment
    // could be resealed with different verdicts, costs and tenants under an
    // identical root, and a completeness proof said nothing about the records
    // a query would return beside it.
    let pairs: Vec<(Record, Hash)> = (1..=6u64)
        .map(|i| (record(i, 0, 1_000 + i), link(0, i)))
        .collect();
    let honest = Segment::seal(SegmentId(1), ShardIx(0), Hash::ZERO, &pairs).unwrap();

    let mut rewritten = pairs.clone();
    rewritten[2].0.outcome.verdict = Some(Verdict::Allowed);
    rewritten[2].0.tenant = TenantId::parse("someone-else").unwrap();
    // A rewritten record produces a different chain link, which is the point:
    // the link is what the history leaf commits to.
    rewritten[2].1 = Sha384::digest(b"a different chain link");
    let tampered = Segment::seal(SegmentId(1), ShardIx(0), Hash::ZERO, &rewritten).unwrap();

    assert_ne!(honest.root(), tampered.root());
    assert_ne!(
        honest.manifest().history_root,
        tampered.manifest().history_root
    );
}

#[test]
fn sealing_the_same_records_twice_gives_the_same_root() {
    let pairs: Vec<(Record, Hash)> = (1..=7u64)
        .map(|i| (record(i, 0, 1_000 + i), link(0, i)))
        .collect();
    let a = Segment::seal(SegmentId(3), ShardIx(0), Hash::ZERO, &pairs).unwrap();
    let b = Segment::seal(SegmentId(3), ShardIx(0), Hash::ZERO, &pairs).unwrap();
    assert_eq!(a.root(), b.root());

    let elsewhere = Segment::seal(SegmentId(4), ShardIx(0), Hash::ZERO, &pairs).unwrap();
    assert_ne!(a.root(), elsewhere.root(), "segment id is committed");

    let later = Segment::seal(SegmentId(3), ShardIx(0), link(0, 99), &pairs).unwrap();
    assert_ne!(
        a.root(),
        later.root(),
        "the incoming chain head is committed"
    );
}

#[test]
fn a_segment_chains_to_the_one_before_it() {
    let first: Vec<(Record, Hash)> = (1..=4u64)
        .map(|i| (record(i, 0, 1_000 + i), link(0, i)))
        .collect();
    let a = Segment::seal(SegmentId(0), ShardIx(0), Hash::ZERO, &first).unwrap();
    assert_eq!(a.manifest().chain_after, link(0, 4));

    let second: Vec<(Record, Hash)> = (5..=8u64)
        .map(|i| (record(i, 0, 1_000 + i), link(0, i)))
        .collect();
    let b = Segment::seal(SegmentId(1), ShardIx(0), a.manifest().chain_after, &second).unwrap();
    assert_eq!(b.manifest().chain_before, a.manifest().chain_after);
}

#[test]
fn duplicate_positions_are_refused_at_seal() {
    // Two entries at the same (key, seq) would make every range covering both
    // permanently unverifiable: a data condition becoming a denial of service.
    let pairs = vec![
        (record(1, 0, 1_000), link(0, 1)),
        (record(1, 0, 1_000), link(0, 2)),
    ];
    assert!(matches!(
        Segment::seal(SegmentId(0), ShardIx(0), Hash::ZERO, &pairs),
        Err(SealError::DuplicateKey { .. })
    ));
}

#[test]
fn mixed_algorithms_are_refused_at_seal() {
    // One manifest cannot honestly say which algorithms produced a segment
    // sealed across a migration, and enumerating what to re-sign is the whole
    // reason the field exists.
    let mut pairs: Vec<(Record, Hash)> = (1..=3u64)
        .map(|i| (record(i, 0, 1_000 + i), link(0, i)))
        .collect();
    pairs[1].0.algorithms.signature = SigAlg::MlDsa65;
    assert!(matches!(
        Segment::seal(SegmentId(0), ShardIx(0), Hash::ZERO, &pairs),
        Err(SealError::MixedAlgorithms)
    ));
}

#[test]
fn an_empty_segment_still_has_a_root() {
    let s = Segment::seal(SegmentId(9), ShardIx(0), Hash::ZERO, &[]).unwrap();
    assert_eq!(s.manifest().records, 0);
    assert!(!s.root().is_zero());
    assert!(s.time_span().is_none());
}
