//! Causal reconstruction: what led to a decision, and how much of it is proved.

use trailryx_crypto::Sha384;
use trailryx_index::segment::Segment;
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted, Verdict,
};
use trailryx_store::causal::{Bounds, Hop, Stopped, reconstruct};
use trailryx_store::query::ProofStatus;

struct B {
    id: u128,
    run: &'static str,
    agent: &'static str,
    at: u64,
    parent_run: Option<&'static str>,
    caused_by: Vec<u128>,
}

fn build(b: B) -> (Record, Hash) {
    let r = Record {
        id: RecordId(b.id),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse(b.agent).unwrap(),
        run_id: RunId::parse(b.run).unwrap(),
        parent_run_id: b.parent_run.map(|p| RunId::parse(p).unwrap()),
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(b.at)),
        decided_at: None,
        recorded_at: Timestamp(b.at),
        knowledge_as_of: None,
        clock_skew_nanos: None,
        event_type: EventType::ModelCall,
        severity: Severity::Info,
        basis: Basis::default(),
        caused_by: b.caused_by.into_iter().map(RecordId).collect(),
        outcome: Outcome::default(),
        payload: None,
        seq: b.id as u64,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(1),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    };
    let link = Sha384::digest(format!("link-{}", b.id).as_bytes());
    (r, link)
}

/// Two shards. A support agent's run delegates to a billing agent's run, and
/// individual records point at their causes across the boundary.
fn two_shards() -> (Segment, Segment) {
    let support = vec![
        build(B {
            id: 1,
            run: "run-support",
            agent: "agent://acme.example/support",
            at: 1_000,
            parent_run: None,
            caused_by: vec![],
        }),
        build(B {
            id: 2,
            run: "run-support",
            agent: "agent://acme.example/support",
            at: 1_010,
            parent_run: None,
            caused_by: vec![1],
        }),
        // The record that reaches into the other shard.
        build(B {
            id: 3,
            run: "run-support",
            agent: "agent://acme.example/support",
            at: 1_020,
            parent_run: None,
            caused_by: vec![2, 11],
        }),
    ];
    let billing = vec![
        build(B {
            id: 11,
            run: "run-billing",
            agent: "agent://acme.example/billing",
            at: 990,
            parent_run: Some("run-origin"),
            caused_by: vec![],
        }),
        build(B {
            id: 12,
            run: "run-origin",
            agent: "agent://acme.example/billing",
            at: 980,
            parent_run: None,
            caused_by: vec![],
        }),
    ];
    (
        Segment::seal(SegmentId(1), ShardIx(0), Hash::ZERO, &support).unwrap(),
        Segment::seal(SegmentId(1), ShardIx(1), Hash::ZERO, &billing).unwrap(),
    )
}

#[test]
fn a_run_reconstructs_across_shards_and_stays_proved() {
    // The property worth having: causality crosses shards, because a
    // delegation chain connects different agents and agents are what the store
    // is sharded by. Every hop is a point query on a sorted dimension, so each
    // carries its own proof.
    let (support, billing) = two_shards();
    let r = reconstruct(
        &[&support, &billing],
        &RunId::parse("run-support").unwrap(),
        Bounds::default(),
    );

    let ids: Vec<u128> = r.records.iter().map(|x| x.id.0).collect();
    assert_eq!(ids, vec![12, 11, 1, 2, 3], "sorted by time, then id");
    assert_eq!(r.proof, ProofStatus::Full);
    assert_eq!(r.stopped, Stopped::Exhausted);
    assert!(r.is_complete());
}

#[test]
fn every_hop_records_the_record_that_justified_it() {
    // A hop nobody can account for is a walk somebody took and asked us to
    // believe. Each one names the already-proved record whose committed edge
    // caused it.
    let (support, billing) = two_shards();
    let r = reconstruct(
        &[&support, &billing],
        &RunId::parse("run-support").unwrap(),
        Bounds::default(),
    );

    assert!(matches!(r.hops.first(), Some(Hop::Root { .. })));
    assert!(
        r.hops.iter().any(|h| matches!(
            h,
            Hop::Cause {
                record: RecordId(11),
                from: RecordId(3)
            }
        )),
        "{:?}",
        r.hops
    );
    assert!(
        r.hops.iter().any(|h| matches!(
            h,
            Hop::ParentRun {
                from: RecordId(11),
                ..
            }
        )),
        "{:?}",
        r.hops
    );
}

#[test]
fn an_edge_pointing_nowhere_costs_the_proof() {
    // A closure that is ninety percent proved is not a proved closure.
    let (support, _billing) = two_shards();
    let r = reconstruct(
        &[&support],
        &RunId::parse("run-support").unwrap(),
        Bounds::default(),
    );

    assert!(!r.proof.is_full(), "record 11 is not in this segment");
    assert!(!r.is_complete());
    match r.proof {
        ProofStatus::Partial { unproved } => {
            assert!(
                unproved.iter().any(|u| u.contains("caused_by")),
                "{unproved:?}"
            );
        }
        other => panic!("expected partial, got {other:?}"),
    }
}

#[test]
fn a_hop_limit_is_reported_rather_than_hidden() {
    // A truncated closure reported as complete is the same lie in a different
    // coat.
    let (support, billing) = two_shards();
    let r = reconstruct(
        &[&support, &billing],
        &RunId::parse("run-support").unwrap(),
        Bounds {
            max_hops: 1,
            ..Bounds::default()
        },
    );
    assert_eq!(r.stopped, Stopped::HopLimit);
    assert!(
        !r.is_complete(),
        "every hop taken was proved, and it is still incomplete"
    );
}

#[test]
fn a_record_limit_is_reported_rather_than_hidden() {
    let (support, billing) = two_shards();
    let r = reconstruct(
        &[&support, &billing],
        &RunId::parse("run-support").unwrap(),
        Bounds {
            max_records: 2,
            ..Bounds::default()
        },
    );
    assert_eq!(r.stopped, Stopped::RecordLimit);
    assert!(!r.is_complete());
}

#[test]
fn a_cycle_does_not_loop_forever() {
    // Nothing stops a malformed or hostile graph from pointing back at itself.
    let pairs = vec![
        build(B {
            id: 1,
            run: "run-loop",
            agent: "agent://acme.example/support",
            at: 1_000,
            parent_run: None,
            caused_by: vec![2],
        }),
        build(B {
            id: 2,
            run: "run-loop",
            agent: "agent://acme.example/support",
            at: 1_010,
            parent_run: None,
            caused_by: vec![1],
        }),
    ];
    let seg = Segment::seal(SegmentId(1), ShardIx(0), Hash::ZERO, &pairs).unwrap();

    let r = reconstruct(
        &[&seg],
        &RunId::parse("run-loop").unwrap(),
        Bounds::default(),
    );
    assert_eq!(r.len(), 2);
    assert_eq!(r.stopped, Stopped::Exhausted);
}

#[test]
fn an_unknown_run_returns_nothing_and_proves_it() {
    let (support, billing) = two_shards();
    let r = reconstruct(
        &[&support, &billing],
        &RunId::parse("run-that-never-existed").unwrap(),
        Bounds::default(),
    );
    assert!(r.is_empty());
    assert_eq!(
        r.proof,
        ProofStatus::Full,
        "an empty answer is still an answer"
    );
    assert!(r.is_complete());
}

#[test]
fn the_same_closure_reconstructs_the_same_way_twice() {
    // Two honest reconstructions must be the same answer, not merely
    // equivalent ones, or nothing above this can be compared.
    let (support, billing) = two_shards();
    let a = reconstruct(
        &[&support, &billing],
        &RunId::parse("run-support").unwrap(),
        Bounds::default(),
    );
    let b = reconstruct(
        &[&support, &billing],
        &RunId::parse("run-support").unwrap(),
        Bounds::default(),
    );
    assert_eq!(a.records, b.records);
    assert_eq!(a.hops, b.hops);
    assert_eq!(a.stopped, b.stopped);
}

#[test]
fn a_loss_the_store_recorded_stops_the_closure_claiming_to_be_complete() {
    // The second debt the README carried, from the other end. `reconstruct` could only
    // downgrade for an edge that was PRESENT and unresolvable, so an edge the assembler
    // never managed to create produced no hop at all: the proof stayed `Full` and
    // `is_complete()` returned true for a run whose causal graph had a hole in it, and
    // that is indistinguishable from a run which genuinely had no parent.
    //
    // What closes it needs no new field. The assembler writes a `StoreEvent` carrying
    // the affected run's own id, so it lands in the same `run_id` bucket as the records
    // it is about and the query a reconstruction already runs finds it.
    let clean = vec![
        build(B {
            id: 1,
            run: "run-a",
            agent: "agent://acme.example/support",
            at: 1_000,
            parent_run: None,
            caused_by: vec![],
        }),
        build(B {
            id: 2,
            run: "run-a",
            agent: "agent://acme.example/support",
            at: 1_010,
            parent_run: None,
            caused_by: vec![1],
        }),
    ];
    let segment = Segment::seal(SegmentId(1), ShardIx(0), Sha384::digest(b"g"), &clean).unwrap();
    let whole = reconstruct(
        &[&segment],
        &RunId::parse("run-a").unwrap(),
        Bounds::default(),
    );
    assert!(
        whole.is_complete(),
        "the control: nothing is missing, so nothing is claimed to be"
    );

    // The same run, plus the record the store writes when it loses an edge.
    let mut with_loss = clean.clone();
    let (mut note, link) = build(B {
        id: 3,
        run: "run-a",
        agent: "agent://acme.example/trailryx.assemble",
        at: 1_020,
        parent_run: None,
        caused_by: vec![],
    });
    note.event_type = EventType::StoreEvent;
    note.severity = Severity::Warning;
    note.outcome.verdict = Some(Verdict::Failed);
    note.outcome.tokens_in = Some(1);
    with_loss.push((note, link));

    let short = Segment::seal(SegmentId(1), ShardIx(0), Sha384::digest(b"g"), &with_loss).unwrap();
    let r = reconstruct(
        &[&short],
        &RunId::parse("run-a").unwrap(),
        Bounds::default(),
    );
    assert!(
        !r.is_complete(),
        "a run the store recorded a loss against must not report itself complete"
    );
    let why = format!("{:?}", r.proof);
    assert!(
        why.contains("recorded a loss against this run"),
        "and it has to say why: {why}"
    );

    // Still every record, because a downgrade is about the claim and not the data.
    assert_eq!(r.records.len(), 3);
}
