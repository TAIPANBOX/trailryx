//! The read surface, and the one thing it must never do.
//!
//! Returning wrong records would be a bug. Returning right records while
//! implying they are all of them, when a filter has quietly narrowed the set,
//! would be the product failing at the only thing it claims. So most of these
//! tests are about the proof status rather than about the rows.

use trailryx_index::completeness::Dimension;
use trailryx_index::segment::Segment;
use trailryx_record::{
    AgentId, Algorithms, Basis, ErrorCode, EventType, Hash, MapperVersion, Outcome, Record,
    RecordId, RunId, SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted, Verdict,
};
use trailryx_store::query::{Filter, ProofStatus, Query, query_segment};

fn rec(seq: u64, at: u64, sev: Severity, verdict: Option<Verdict>) -> (Record, Hash) {
    let r = Record {
        id: RecordId(u128::from(seq)),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse(if seq % 2 == 0 {
            "agent://acme.example/support"
        } else {
            "agent://acme.example/billing"
        })
        .unwrap(),
        run_id: RunId::parse(format!("run-{}", seq.div_ceil(3))).unwrap(),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(at)),
        decided_at: None,
        recorded_at: Timestamp(at),
        knowledge_as_of: None,
        clock_skew_nanos: None,
        event_type: EventType::ModelCall,
        severity: sev,
        basis: Basis::default(),
        caused_by: Vec::new(),
        outcome: Outcome {
            verdict,
            error: verdict.and(Some(ErrorCode::None)),
            ..Outcome::default()
        },
        payload: None,
        seq,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(1),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    };
    // Stand-in for the journal's link; the seam test covers the real one.
    let link = trailryx_crypto::Sha384::digest(format!("link-{seq}").as_bytes());
    (r, link)
}

fn segment() -> Segment {
    let pairs: Vec<(Record, Hash)> = (1..=12u64)
        .map(|i| {
            let sev = if i % 4 == 0 {
                Severity::Critical
            } else {
                Severity::Info
            };
            let verdict = if i % 3 == 0 {
                Some(Verdict::Denied)
            } else {
                Some(Verdict::Allowed)
            };
            rec(i, 1_000 + i * 10, sev, verdict)
        })
        .collect();
    Segment::seal(SegmentId(1), ShardIx(0), Hash::ZERO, &pairs).expect("seals")
}

#[test]
fn a_range_on_a_sorted_dimension_is_fully_proved() {
    let seg = segment();
    let a = query_segment(
        &seg,
        &Query::time_between(Timestamp(1_030), Timestamp(1_080)),
    );
    assert_eq!(a.len(), 6);
    assert_eq!(a.proof, ProofStatus::Full);
    assert_eq!(a.matched_before_filters, 6);
}

#[test]
fn a_point_query_is_fully_proved() {
    let seg = segment();
    let a = query_segment(
        &seg,
        &Query::point(Dimension::AgentId, b"agent://acme.example/billing".to_vec()),
    );
    assert_eq!(a.len(), 6, "the odd-numbered records");
    assert_eq!(a.proof, ProofStatus::Full);
}

#[test]
fn the_records_returned_are_the_ones_the_proof_points_at() {
    let seg = segment();
    let a = query_segment(
        &seg,
        &Query::time_between(Timestamp(1_030), Timestamp(1_050)),
    );
    let times: Vec<u64> = a.records.iter().map(|r| r.recorded_at.as_nanos()).collect();
    assert_eq!(times, vec![1_030, 1_040, 1_050]);
    // Every returned record corresponds to an entry the proof committed to.
    assert_eq!(a.records.len(), a.segment_proofs[0].entries.len());
}

// ---------------------------------------------------------------------------
// What a filter costs
// ---------------------------------------------------------------------------

#[test]
fn a_filter_downgrades_the_proof_and_names_itself() {
    let seg = segment();
    let a = query_segment(
        &seg,
        &Query::time_between(Timestamp(1_000), Timestamp(1_120))
            .with(Filter::Severity(Severity::Critical)),
    );
    assert_eq!(a.len(), 3, "records 4, 8 and 12");
    assert_eq!(
        a.proof,
        ProofStatus::Partial {
            unproved: vec!["severity"]
        }
    );
    assert_eq!(
        a.matched_before_filters, 12,
        "the gap between this and the answer is what the filter removed"
    );
}

#[test]
fn a_filter_that_removed_nothing_still_costs_the_proof() {
    // Whether a particular run happened to drop rows is not what makes the
    // difference: the proof covers the range, not the filtered result.
    let seg = segment();
    let a = query_segment(
        &seg,
        &Query::time_between(Timestamp(1_000), Timestamp(1_120))
            .with(Filter::Tenant(TenantId::parse("acme").unwrap())),
    );
    assert_eq!(a.len(), 12, "nothing was removed");
    assert!(!a.proof.is_full(), "and yet it is not a full proof");
}

#[test]
fn several_filters_are_all_named_once_each() {
    let seg = segment();
    let a = query_segment(
        &seg,
        &Query::time_between(Timestamp(1_000), Timestamp(1_120))
            .with(Filter::MinSeverity(Severity::Warning))
            .with(Filter::Verdict(Verdict::Denied))
            .with(Filter::Severity(Severity::Critical)),
    );
    match a.proof {
        ProofStatus::Partial { unproved } => {
            assert_eq!(unproved, vec!["severity", "outcome.verdict"]);
        }
        other => panic!("expected a partial proof, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// as_of
// ---------------------------------------------------------------------------

#[test]
fn as_of_on_the_time_dimension_keeps_the_proof() {
    // Transaction time on the sorted dimension is just a tighter bound.
    let seg = segment();
    let a = query_segment(
        &seg,
        &Query::time_between(Timestamp(1_000), Timestamp(1_120)).as_of(Timestamp(1_050)),
    );
    assert_eq!(a.len(), 5, "up to and including 1050");
    assert_eq!(a.proof, ProofStatus::Full);
}

#[test]
fn as_of_on_another_dimension_costs_the_proof() {
    // One index is sorted by one thing. A second predicate on a different field
    // cannot be covered by it, and saying otherwise would be the exact
    // dishonesty the status exists to prevent.
    let seg = segment();
    let a = query_segment(
        &seg,
        &Query::point(Dimension::AgentId, b"agent://acme.example/billing".to_vec())
            .as_of(Timestamp(1_050)),
    );
    assert_eq!(a.len(), 3, "records 1, 3 and 5");
    assert_eq!(
        a.proof,
        ProofStatus::Partial {
            unproved: vec!["as_of"]
        }
    );
}

#[test]
fn as_of_before_everything_returns_nothing_and_still_proves_it() {
    let seg = segment();
    let a = query_segment(
        &seg,
        &Query::time_between(Timestamp(0), Timestamp(u64::MAX)).as_of(Timestamp(1)),
    );
    assert!(a.is_empty());
    assert_eq!(
        a.proof,
        ProofStatus::Full,
        "an empty answer is still an answer"
    );
}

#[test]
fn a_wider_as_of_than_the_range_does_not_widen_the_range() {
    let seg = segment();
    let a = query_segment(
        &seg,
        &Query::time_between(Timestamp(1_000), Timestamp(1_050)).as_of(Timestamp(u64::MAX)),
    );
    assert_eq!(a.len(), 5);
    assert_eq!(a.proof, ProofStatus::Full);
}

// ---------------------------------------------------------------------------
// The proof travels with the answer
// ---------------------------------------------------------------------------

#[test]
fn the_answers_proof_verifies_against_the_segment() {
    let seg = segment();
    let q = Query::time_between(Timestamp(1_030), Timestamp(1_080));
    let a = query_segment(&seg, &q);

    let idx = seg.index(Dimension::RecordedAt).unwrap();
    assert_eq!(
        a.segment_proofs[0].verify(Dimension::RecordedAt, &q.lo, &q.hi, idx.root(), idx.len()),
        Ok(())
    );
}

#[test]
fn an_answer_always_carries_a_status() {
    // No path returns records without saying how well they are backed.
    let seg = segment();
    for q in [
        Query::time_between(Timestamp(0), Timestamp(u64::MAX)),
        Query::point(Dimension::RunId, b"run-2".to_vec()),
        Query::time_between(Timestamp(0), Timestamp(u64::MAX)).with(Filter::HasPayload(false)),
        Query::point(
            Dimension::EventType,
            Dimension::event_key(EventType::ModelCall),
        )
        .as_of(Timestamp(1_050)),
    ] {
        let a = query_segment(&seg, &q);
        match a.proof {
            ProofStatus::Full => assert!(!a.segment_proofs.is_empty()),
            ProofStatus::Partial { ref unproved } => assert!(!unproved.is_empty()),
            ProofStatus::None { why } => assert!(!why.is_empty()),
        }
    }
}
