//! The estate's own event stream, all the way to a sealed segment.
//!
//! The mapper has its own suite next door, over lines. This is the other half of
//! the claim, and it is the half the audit of 5 August 2026 was about: a mapper
//! that nothing calls is a library, so this drives a real file through the real
//! plane and reads the records back out of the directory afterwards.

use std::path::PathBuf;

use trailryx_agentevent::EnvelopeConfig;
use trailryx_index::completeness::Dimension;
use trailryx_node::{Plane, SealPolicy, ingest_file, reader};
use trailryx_record::{ShardIx, TenantId, Timestamp};
use trailryx_store::query::{ProofStatus, Query, query_segment};

const TRUST_DOMAIN: &str = "acme.example";
const T0: u64 = 1_785_000_000_000_000_000;

/// A scratch directory this process alone can name: invariant 29. The pre-clean
/// is for a recycled process id, and the test wipes it again at the end.
fn scratch(what: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trailryx-node-{what}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn tenant() -> TenantId {
    TenantId::parse("acme").expect("a constant tenant parses")
}

/// Two events that map, one whose type this reading does not, and one from
/// another trust domain. The last two are the point: they are counted rather than
/// dropped in silence, and the file still lands.
const EVENTS: &str = concat!(
    r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:44.100Z","source":"tokenfuse","type":"budget_exhausted","severity":"critical","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","on_behalf_of":["user://acme.example/j.doe"],"data":{"budget_usd":2.0,"spent_usd":2.0}}"#,
    "\n",
    r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:45.000Z","source":"wardryx","type":"policy_deny","severity":"high","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","data":{"policy":"prod-deploy"}}"#,
    "\n",
    r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:46.000Z","source":"qryx","type":"crypto_finding","severity":"info","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842"}"#,
    "\n",
    r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:47.000Z","source":"tokenfuse","type":"run_killed","severity":"high","agent_id":"agent://other.example/support/tier1-bot","run_id":"run-8842"}"#,
    "\n",
);

#[test]
fn a_file_of_agent_events_becomes_records_a_reader_gets_back() {
    let dir = scratch("events");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("events.ndjson");
    std::fs::write(&path, EVENTS).expect("the fixture is written");

    let policy = SealPolicy {
        seal_after_records: 2,
        seal_after_nanos: u64::MAX,
        sync_every: 1,
    };
    let (mut plane, _) = Plane::open(&dir, ShardIx(0), tenant(), TRUST_DOMAIN, policy, 0x616765)
        .expect("a data directory opens");
    let cfg = EnvelopeConfig::new(tenant(), TRUST_DOMAIN).expect("a usable trust domain");

    let ingested = ingest_file(&mut plane, &cfg, &path, Timestamp(T0)).expect("the file is read");
    assert_eq!(ingested.report.mapped, 2, "two of the four map");
    assert_eq!(
        ingested.report.unknown_type, 1,
        "a type this reading does not map is counted rather than guessed at"
    );
    assert_eq!(
        ingested.report.foreign_trust_domain, 1,
        "and so is an agent this receiver does not serve"
    );
    assert_eq!(ingested.accepted.written, 2);
    assert!(
        ingested.accepted.declined_payload_parts >= 2,
        "each event carried members no typed field holds"
    );

    plane
        .seal(Timestamp(T0))
        .expect("a seal on request")
        .expect("a sealed segment");
    drop(plane);

    let held = reader::read_sealed(&dir, ShardIx(0)).expect("the directory reads back");
    let answer = query_segment(
        held.segments.first().expect("one segment"),
        &Query::point(Dimension::RunId, b"run-8842".to_vec()),
    );
    assert_eq!(
        answer.proof,
        ProofStatus::Full,
        "the run is a provable dimension, so the answer carries its proof"
    );
    assert!(
        answer.records.len() >= 2,
        "both mapped events came back: {}",
        answer.records.len()
    );
    assert!(
        answer
            .records
            .iter()
            .any(|r| r.event_type == trailryx_record::EventType::PolicyDecision),
        "the policy refusal is one of them"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
