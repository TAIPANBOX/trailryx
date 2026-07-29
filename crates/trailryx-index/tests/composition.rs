//! Composing proofs across segments and shards.
//!
//! The honest case is short. The rest is the failure this whole construction
//! exists to catch: an answer that looks complete because a shard, a segment or
//! a boundary quietly went missing.

use trailryx_index::completeness::Dimension;
use trailryx_index::segment::{
    CompositeFailure, CompositeProof, Segment, SegmentContribution, ShardContribution, ShardTree,
    StoreTree,
};
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};

fn record(seq: u64, shard: u16, at: u64) -> Record {
    Record {
        id: RecordId(u128::from(seq) | (u128::from(shard) << 64)),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(shard),
        agent_id: AgentId::parse("agent://acme.example/support").unwrap(),
        run_id: RunId::parse(format!("run-{seq}")).unwrap(),
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

/// Two shards, two segments each, times laid out so a range can straddle them.
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
        for seg in 0..2u64 {
            let base = 1_000 + u64::from(s) * 100 + seg * 40;
            let records: Vec<Record> = (0..6u64)
                .map(|i| record(seg * 6 + i + 1, s, base + i * 5))
                .collect();
            let sealed = Segment::seal(SegmentId(seg), ShardIx(s), &records);
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

/// Answer a time range across the whole store, excluding segments whose
/// committed bounds put them outside it.
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
                    let outside =
                        hi < m.first_recorded_at.as_nanos() || lo > m.last_recorded_at.as_nanos();
                    if outside {
                        SegmentContribution::ExcludedByTime {
                            manifest: m,
                            manifest_proof: mp,
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
fn excluding_a_segment_by_its_committed_bounds_is_allowed() {
    let store = build_store();
    // Shard 1 starts at 1100, so a range entirely inside shard 0 excludes it.
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
// Omission
// ---------------------------------------------------------------------------

#[test]
fn forgetting_a_shard_breaks_the_answer() {
    // The failure the composition exists for. An answer missing an entire node
    // still looks like a list of records.
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
fn forgetting_a_segment_breaks_the_answer() {
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    p.shards[0].segments.pop();

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::SegmentNotInShard { .. }),
        "got {err:?}"
    );
}

#[test]
fn skipping_a_segment_that_does_overlap_is_refused() {
    // The tempting shortcut: call a segment irrelevant and skip it. Only the
    // manifest's committed bounds can justify that, and here they do not.
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    if let SegmentContribution::Answered {
        manifest,
        manifest_proof,
        ..
    } = p.shards[0].segments[0].clone()
    {
        p.shards[0].segments[0] = SegmentContribution::ExcludedByTime {
            manifest,
            manifest_proof,
        };
    }

    let err = verify(&store, &p, 0, u64::MAX).unwrap_err();
    assert!(
        matches!(err, CompositeFailure::ExclusionNotJustified { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_segment_cannot_be_skipped_on_a_dimension_with_no_bounds() {
    // Time is the only dimension whose bounds the manifest commits to. On any
    // other, "this segment could not have matched" is an unverifiable claim.
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
    // Changing a record count, or a time bound, or an index root: all of them
    // move the manifest root, and the shard tree no longer accepts it.
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
    // Composition must not dilute the per-segment guarantee.
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
fn the_shard_count_comes_from_the_store_not_from_the_proof() {
    // A proof that could state how many shards exist could also understate it.
    let store = build_store();
    let mut p = answer(&store, 0, u64::MAX);
    p.shards.pop();

    // Believing the proof's own count would accept this.
    assert!(
        p.verify(
            Dimension::RecordedAt,
            &Dimension::time_key(0),
            &Dimension::time_key(u64::MAX),
            store.tree.root(),
            p.shards.len(),
        )
        .is_err(),
        "the remaining shard's inclusion proof must not fit a smaller store"
    );
}

#[test]
fn sealing_the_same_records_twice_gives_the_same_root() {
    // Two honest sealers must agree byte for byte, or nothing above them can be
    // compared.
    let records: Vec<Record> = (1..=7u64).map(|i| record(i, 0, 1_000 + i)).collect();
    let a = Segment::seal(SegmentId(3), ShardIx(0), &records);
    let b = Segment::seal(SegmentId(3), ShardIx(0), &records);
    assert_eq!(a.root(), b.root());

    let different = Segment::seal(SegmentId(4), ShardIx(0), &records);
    assert_ne!(a.root(), different.root(), "segment id is committed");
}

#[test]
fn an_empty_segment_still_has_a_root() {
    let s = Segment::seal(SegmentId(9), ShardIx(0), &[]);
    assert_eq!(s.manifest().records, 0);
    assert!(!s.root().is_zero());
}
