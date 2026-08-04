//! The assumption verified replication rests on, checked across the layer that
//! could break it.
//!
//! `trailryx-federation::replication` hashes bytes it produces itself, by
//! re-encoding the record it decoded. Over the wire that record has been
//! through protobuf, so the chain only reproduces if
//! `from_wire(to_wire(r)) == r` for every field the record encoder writes.
//!
//! That is not a property anybody can hold in their head, and the failure it
//! would cause is the worst kind: a lossy or normalising conversion does not
//! report "the codec dropped a field", it reports **a broken chain**, and
//! somebody goes looking for a peer that tampered with history. So it is a
//! test, at the seam, rather than a sentence in a doc comment.

use trailryx_crypto::{Hash, Sha384, chain_step};
use trailryx_federation::replication::{Refusal, accept_from};
use trailryx_federation_grpc::{from_wire, to_wire};
use trailryx_journal::wire::encode_record;
use trailryx_record::{
    AgentId, Algorithms, Basis, ErrorCode, EventType, MapperVersion, ModelId, Outcome,
    PayloadClass, PayloadRef, PolicyVersion, PrincipalId, Record, RecordId, RunId, SegmentId,
    Severity, ShardIx, TenantId, Timestamp, ToolName, Untrusted, Verdict,
};

const SHARD: ShardIx = ShardIx(0);

/// Every optional field populated, mirroring `maximal` in the journal's own
/// codec tests. Deliberately not a minimal record: a codec loses optional
/// fields first, and a run of empty records would round-trip perfectly while
/// hiding exactly the defect this file exists to catch.
fn record(seq: u64, prev: Hash) -> Record {
    Record {
        id: RecordId(u128::from(seq)),
        tenant: TenantId::parse("acme").expect("a tenant"),
        shard: SHARD,
        agent_id: AgentId::parse("agent://acme.example/support/tier1").expect("an agent"),
        run_id: RunId::parse(format!("run-{seq}")).expect("a run"),
        parent_run_id: Some(RunId::parse("run-parent").expect("a parent run")),
        on_behalf_of: vec![
            PrincipalId::parse("user://analyst-7").expect("a principal"),
            PrincipalId::parse("agent://acme.example/planner").expect("a principal"),
        ],
        occurred_at: Untrusted::new(Timestamp(1_800_000_000_000_000_000 + seq)),
        decided_at: Some(Untrusted::new(Timestamp(1_800_000_000_000_000_002))),
        recorded_at: Timestamp(1_800_000_000_000_000_001 + seq),
        knowledge_as_of: Some(Timestamp(1_799_000_000_000_000_000)),
        clock_skew_nanos: Some(7_500_000_000),
        event_type: EventType::PolicyDecision,
        severity: Severity::Critical,
        basis: Basis {
            policy_version: Some(PolicyVersion::parse("v2.4.1").expect("a policy version")),
            budget_remaining_micros: Some(-4_250_000),
            memory_ref: Some(Sha384::digest(b"memory snapshot")),
            model: Some(ModelId::parse("anthropic/claude-opus-5").expect("a model")),
            temperature_milli: Some(700),
            max_tokens: Some(4096),
            prompt_hash: Some(Sha384::digest(b"the prompt")),
            tool_manifest: vec![
                ToolName::parse("search").expect("a tool"),
                ToolName::parse("send-mail").expect("a tool"),
            ],
            identity_chain: vec![PrincipalId::parse("user://analyst-7").expect("a principal")],
        },
        caused_by: vec![RecordId(11), RecordId(12), RecordId(13)],
        outcome: Outcome {
            verdict: Some(Verdict::Denied),
            error: Some(ErrorCode::BudgetExceeded),
            latency_micros: Some(123_456),
            tokens_in: Some(1_024),
            tokens_out: Some(0),
            cost_micros: Some(9_999),
        },
        payload: Some(PayloadRef {
            hash: Sha384::digest(b"payload bytes"),
            size_bytes: 4_096,
            class: PayloadClass::Prompt,
            key_id: Sha384::digest(b"subject key"),
        }),
        seq,
        prev_hash: prev,
        segment_id: SegmentId(3),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}

fn run(from: Hash, n: u64) -> (Vec<Record>, Hash) {
    let mut link = from;
    let mut out = Vec::new();
    for seq in 1..=n {
        let r = record(seq, link);
        link = chain_step(link, r.seq, &encode_record(&r));
        out.push(r);
    }
    (out, link)
}

#[test]
fn a_chain_still_verifies_after_a_round_trip_through_protobuf() {
    let (sent, head_after) = run(Hash::ZERO, 6);

    let received: Vec<Record> = sent
        .iter()
        .map(|r| from_wire(to_wire(r)).expect("what we encoded decodes"))
        .collect();

    let accepted =
        accept_from(Hash::ZERO, SHARD, &received).expect("the wire must not break the chain");
    assert_eq!(accepted.records, 6);
    assert!(accepted.anchored);
    assert_eq!(
        accepted.head, head_after,
        "the receiver arrives at the head the sender computed, or the codec moved a byte"
    );
}

/// The stronger statement, and the one that makes the test above meaningful:
/// not merely that the chain still verifies, but that the bytes the chain is
/// computed over are identical. A codec could in principle normalise a field
/// consistently on both sides and still chain, which would pass the test above
/// while quietly changing what the record means.
#[test]
fn the_bytes_the_chain_covers_survive_the_wire_unchanged() {
    let (sent, _) = run(Hash::ZERO, 3);
    for original in &sent {
        let back = from_wire(to_wire(original)).expect("decodes");
        assert_eq!(
            encode_record(original),
            encode_record(&back),
            "the canonical bytes changed crossing the wire, at seq {}",
            original.seq
        );
        assert_eq!(&back, original, "and the record itself changed");
    }
}

/// Tampering after the wire is still caught. The point of putting this here as
/// well as in the federation crate's own tests is that it is the composition of
/// the two layers somebody deploys, and a check that only holds before
/// serialisation protects nothing.
#[test]
fn a_record_altered_after_the_wire_is_still_refused() {
    let (sent, _) = run(Hash::ZERO, 5);
    let mut received: Vec<Record> = sent
        .iter()
        .map(|r| from_wire(to_wire(r)).expect("decodes"))
        .collect();

    received[2].outcome.verdict = Some(Verdict::Allowed);

    match accept_from(Hash::ZERO, SHARD, &received) {
        Err(Refusal::LinkBroken { at_seq }) => assert_eq!(at_seq, 4),
        other => panic!("expected LinkBroken after the wire, got {other:?}"),
    }
}
