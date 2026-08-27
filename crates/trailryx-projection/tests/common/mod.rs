//! A small sealed store to project.

#![allow(dead_code)]

use trailryx_crypto::chain_step;
use trailryx_index::segment::Segment;
use trailryx_journal::wire::encode_record;
use trailryx_record::{
    AgentId, Algorithms, Basis, ErrorCode, EventType, Hash, MapperVersion, ModelId, Outcome,
    PayloadClass, PayloadRef, PolicyVersion, PrincipalId, Record, RecordId, RunId, SegmentId,
    Severity, ShardIx, TenantId, Timestamp, ToolName, Untrusted, Verdict,
};

pub fn record(id: u128, seq: u64, rich: bool) -> Record {
    Record {
        id: RecordId(id),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse("agent://acme.example/billing").unwrap(),
        run_id: RunId::parse("run-a").unwrap(),
        parent_run_id: rich.then(|| RunId::parse("run-root").unwrap()),
        on_behalf_of: if rich {
            vec![PrincipalId::parse("user://acme.example/u-1").unwrap()]
        } else {
            Vec::new()
        },
        occurred_at: Untrusted::new(Timestamp(1_000 + seq)),
        decided_at: rich.then(|| Untrusted::new(Timestamp(1_005 + seq))),
        recorded_at: Timestamp(1_100 + seq),
        knowledge_as_of: rich.then_some(Timestamp(900)),
        clock_skew_nanos: rich.then_some(42),
        event_type: EventType::ModelCall,
        severity: Severity::Info,
        basis: Basis {
            policy_version: rich.then(|| PolicyVersion::parse("v-7").unwrap()),
            budget_remaining_micros: rich.then_some(-1_500),
            memory_ref: rich.then_some(Hash([3u8; 48])),
            model: rich.then(|| ModelId::parse("gpt-4o-mini").unwrap()),
            temperature_milli: rich.then_some(700),
            max_tokens: rich.then_some(512),
            prompt_hash: rich.then_some(Hash([4u8; 48])),
            tool_manifest: if rich {
                vec![
                    ToolName::parse("lookup_balance").unwrap(),
                    ToolName::parse("send_email").unwrap(),
                ]
            } else {
                Vec::new()
            },
            identity_chain: Vec::new(),
            delegation_proof: None,
        },
        caused_by: if rich { vec![RecordId(1)] } else { Vec::new() },
        outcome: Outcome {
            verdict: rich.then_some(Verdict::Allowed),
            error: rich.then_some(ErrorCode::None),
            latency_micros: rich.then_some(250_000),
            tokens_in: rich.then_some(1_204),
            tokens_out: rich.then_some(87),
            cost_micros: rich.then_some(-7),
        },
        payload: rich.then_some(PayloadRef {
            hash: Hash([5u8; 48]),
            size_bytes: 1_234,
            class: PayloadClass::Prompt,
            key_id: Hash([6u8; 48]),
        }),
        seq,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(1),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}

/// Three records, one of them with every optional field empty, so both sides of
/// every nullable column are exercised.
pub fn segment() -> Segment {
    let records = [record(1, 1, true), record(2, 2, false), record(3, 3, true)];
    let mut link = Hash::ZERO;
    let leaves: Vec<(Record, Hash)> = records
        .iter()
        .map(|r| {
            link = chain_step(link, r.seq, &encode_record(r));
            (r.clone(), link)
        })
        .collect();
    Segment::seal(SegmentId(1), ShardIx(0), Hash::ZERO, &leaves).unwrap()
}
