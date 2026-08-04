//! Verified replication, against a run built the way a real sender builds one.
//!
//! The runs here are chained with the same `chain_step` the journal uses, so a
//! passing test means the receiver reproduced arithmetic somebody else did,
//! rather than agreeing with a fixture written to match it.
//!
//! Each refusal gets a test that reaches it, which is not decoration: the
//! checks are ordered, and an earlier one that is too eager hides every later
//! one. That failure has bitten this repository before, in the cold tier, where
//! a cheap digest check made an expensive manifest comparison unreachable and
//! therefore untested for a week.

use trailryx_crypto::{Hash, chain_step};
use trailryx_federation::replication::{Refusal, accept_from, accept_unanchored};
use trailryx_journal::wire::encode_record;
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};

const SHARD: ShardIx = ShardIx(0);

fn record(seq: u64, prev: Hash, shard: ShardIx) -> Record {
    Record {
        id: RecordId(u128::from(seq)),
        tenant: TenantId::parse("acme").expect("a tenant"),
        shard,
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

/// A run chained honestly, starting from `from`, seq `first..first+n`.
/// Returns the records and the head the chain reaches.
fn run(from: Hash, first: u64, n: u64) -> (Vec<Record>, Hash) {
    let mut link = from;
    let mut out = Vec::new();
    for i in 0..n {
        let r = record(first + i, link, SHARD);
        link = chain_step(link, r.seq, &encode_record(&r));
        out.push(r);
    }
    (out, link)
}

#[test]
fn an_honest_run_that_continues_the_head_is_accepted() {
    let (records, head_after) = run(Hash::ZERO, 1, 5);
    let accepted = accept_from(Hash::ZERO, SHARD, &records).expect("an honest run verifies");
    assert_eq!(accepted.records, 5);
    assert_eq!(accepted.last_seq, 5);
    assert_eq!(
        accepted.head, head_after,
        "the receiver must arrive at the same head the sender did"
    );
    assert!(accepted.anchored);
}

/// A second run picking up where the first left off, which is what replication
/// actually looks like over time.
#[test]
fn the_next_run_continues_from_the_head_the_last_one_returned() {
    let (first, head) = run(Hash::ZERO, 1, 3);
    let accepted = accept_from(Hash::ZERO, SHARD, &first).expect("the first run verifies");
    let (second, _) = run(accepted.head, 4, 3);
    let next = accept_from(accepted.head, SHARD, &second).expect("the second run continues it");
    assert_eq!(next.last_seq, 6);
    assert_eq!(head, accepted.head);
}

#[test]
fn a_run_that_does_not_continue_our_head_is_refused_before_anything_else() {
    let (records, _) = run(Hash::ZERO, 1, 3);
    let ours = chain_step(Hash::ZERO, 99, b"a history of our own");
    match accept_from(ours, SHARD, &records) {
        Err(Refusal::NotAContinuation { expected, claimed }) => {
            assert_eq!(expected, ours);
            assert_eq!(claimed, Hash::ZERO);
        }
        other => panic!("expected NotAContinuation, got {other:?}"),
    }
}

/// The check the whole module exists for: bytes that are not the bytes that
/// produced the chain.
#[test]
fn an_altered_record_breaks_the_link_at_its_own_position() {
    let (mut records, _) = run(Hash::ZERO, 1, 5);
    // Change something the chain covers, leaving every hash the sender sent in
    // place. This is exactly the edit a peer would make to rewrite history.
    records[2].severity = Severity::Critical;
    match accept_from(Hash::ZERO, SHARD, &records) {
        // Position 3 still LOOKS right (its own prev_hash is untouched); the
        // arithmetic diverges at the record after it.
        Err(Refusal::LinkBroken { at_seq }) => assert_eq!(at_seq, 4),
        other => panic!("expected LinkBroken, got {other:?}"),
    }
}

#[test]
fn a_removed_record_is_refused_rather_than_shortening_the_history() {
    let (mut records, _) = run(Hash::ZERO, 1, 5);
    records.remove(2);
    match accept_from(Hash::ZERO, SHARD, &records) {
        Err(Refusal::NotContiguous { at_seq, expected }) => {
            assert_eq!(at_seq, 4);
            assert_eq!(expected, 3);
        }
        other => panic!("expected NotContiguous, got {other:?}"),
    }
}

#[test]
fn a_duplicated_record_is_refused() {
    let (mut records, _) = run(Hash::ZERO, 1, 4);
    let repeat = records[1].clone();
    records.insert(2, repeat);
    match accept_from(Hash::ZERO, SHARD, &records) {
        Err(Refusal::NotContiguous { at_seq, expected }) => {
            assert_eq!(at_seq, 2);
            assert_eq!(expected, 3);
        }
        other => panic!("expected NotContiguous, got {other:?}"),
    }
}

/// Two records swapped keep every seq present and every count right. Only the
/// chain notices, which is the point of binding the position into the link.
#[test]
fn two_records_swapped_are_refused_although_nothing_is_missing() {
    let (mut records, _) = run(Hash::ZERO, 1, 5);
    records.swap(1, 2);
    assert_eq!(records.len(), 5, "nothing was removed, only reordered");
    assert!(matches!(
        accept_from(Hash::ZERO, SHARD, &records),
        Err(Refusal::NotContiguous { .. } | Refusal::LinkBroken { .. })
    ));
}

#[test]
fn a_run_that_changes_shard_part_way_is_refused() {
    let (mut records, _) = run(Hash::ZERO, 1, 4);
    records[2].shard = ShardIx(1);
    match accept_from(Hash::ZERO, SHARD, &records) {
        Err(Refusal::ShardChanged { at_seq, expected }) => {
            assert_eq!(at_seq, 3);
            assert_eq!(expected, SHARD);
        }
        other => panic!("expected ShardChanged, got {other:?}"),
    }
}

#[test]
fn an_empty_run_is_refused_rather_than_quietly_accepted() {
    assert_eq!(accept_from(Hash::ZERO, SHARD, &[]), Err(Refusal::Empty));
    assert_eq!(accept_unanchored(SHARD, &[]), Err(Refusal::Empty));
}

/// The honest limit, asserted rather than only described in prose. A peer that
/// invents a starting point passes the unanchored check, because a fabricated
/// chain is internally consistent by construction. If this test ever starts
/// failing, somebody has made `accept_unanchored` claim more than it can, and
/// the claim is the dangerous part.
#[test]
fn a_fabricated_history_passes_unanchored_and_fails_anchored() {
    let invented = chain_step(Hash::ZERO, 1, b"a head this peer made up");
    let (records, _) = run(invented, 1, 4);

    let loose = accept_unanchored(SHARD, &records).expect("internally consistent");
    assert!(
        !loose.anchored,
        "an unanchored acceptance must not describe itself as anchored"
    );

    assert!(
        matches!(
            accept_from(Hash::ZERO, SHARD, &records),
            Err(Refusal::NotAContinuation { .. })
        ),
        "against a head we hold, the same run is refused"
    );
}

/// Ordering: the shard check runs before the chain arithmetic, so a run that is
/// wrong in two ways reports the structural fault rather than a hash mismatch
/// that would send somebody looking for tampering.
#[test]
fn a_run_wrong_in_two_ways_reports_the_structural_fault_first() {
    let (mut records, _) = run(Hash::ZERO, 1, 4);
    records[1].shard = ShardIx(7);
    records[1].severity = Severity::Critical;
    assert!(matches!(
        accept_from(Hash::ZERO, SHARD, &records),
        Err(Refusal::ShardChanged { at_seq: 2, .. })
    ));
}
