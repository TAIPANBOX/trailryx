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

/// A heraldyx dispatch journal, in the shape `internal/record/record.go` writes:
/// one chained agent-event per message sent, `alert_sent`, the recipients in
/// `data.to`.
///
/// Three lines, and the third is deliberate. heraldyx records a dispatch about an
/// event that carried no run with no run of its own rather than inventing one, so
/// the record plane refuses it by name. That refusal is the correct outcome on
/// both sides and it is pinned here so that nobody makes the number go to zero by
/// synthesising a run in the other repository.
const DISPATCHES: &str = concat!(
    r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-08-06T03:14:00Z","source":"heraldyx","type":"alert_sent","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","severity":"info","data":{"kind":"alert","about":"budget_exhausted:agent://acme.example/support/tier1-bot","to":["ops@acme.example"],"transport":"smtp","outcome":"accepted"}}"#,
    "\n",
    r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-08-06T03:14:02Z","source":"heraldyx","type":"alert_sent","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","severity":"info","data":{"kind":"digest","about":"digest:2026-08-06","to":["ops@acme.example","oncall@acme.example"],"transport":"smtp","outcome":"accepted"}}"#,
    "\n",
    r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-08-06T03:14:04Z","source":"heraldyx","type":"alert_sent","agent_id":"agent://acme.example/eng/ci-fixer","severity":"info","data":{"kind":"alert","about":"policy_deny:agent://acme.example/eng/ci-fixer","to":["ops@acme.example"],"transport":"smtp","outcome":"accepted"}}"#,
    "\n",
);

/// The seam heraldyx's invariant 14 names, from its file to a sealed segment and
/// back out through somebody else's verifier.
///
/// Four things at once, because they only mean anything together: the lines map,
/// a query on the new event type is answered with a completeness proof rather
/// than as a filter, no operator address is anywhere in the metadata plane, and
/// the pack the reader hands over is accepted by the offline verifier, which
/// shares no code with the store and has never heard of this event type by name.
#[test]
fn a_heraldyx_dispatch_journal_becomes_records_and_the_recipients_stay_out_of_metadata() {
    let dir = scratch("dispatches");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("sent.ndjson");
    std::fs::write(&path, DISPATCHES).expect("the fixture is written");

    let policy = SealPolicy {
        seal_after_records: 64,
        seal_after_nanos: u64::MAX,
        sync_every: 1,
    };
    let (mut plane, _) = Plane::open(&dir, ShardIx(0), tenant(), TRUST_DOMAIN, policy, 0x616c65)
        .expect("a data directory opens");
    let cfg = EnvelopeConfig::new(tenant(), TRUST_DOMAIN).expect("a usable trust domain");

    let ingested = ingest_file(&mut plane, &cfg, &path, Timestamp(T0)).expect("the file is read");
    assert_eq!(
        ingested.report.mapped, 2,
        "the two dispatches with a run map"
    );
    assert_eq!(
        ingested.report.no_run_id, 1,
        "and the one heraldyx refused to invent a run for is refused by name here"
    );
    assert_eq!(ingested.accepted.written, 2);
    assert!(
        ingested.accepted.declined_payload_parts >= 2,
        "`data` went to a payload plane this process has no key for, and was counted"
    );

    plane
        .seal(Timestamp(T0))
        .expect("a seal on request")
        .expect("a sealed segment");
    drop(plane);

    let held = reader::read_sealed(&dir, ShardIx(0)).expect("the directory reads back");
    let key = Dimension::EventType
        .key_from_text("notification_dispatched")
        .expect("a dispatched notification is a value on a provable dimension");
    let answer = query_segment(
        held.segments.first().expect("one segment"),
        &Query::point(Dimension::EventType, key),
    );
    assert_eq!(
        answer.proof,
        ProofStatus::Full,
        "the event type is a provable dimension, so this answer carries its proof"
    );
    assert_eq!(answer.records.len(), 2);
    for record in &answer.records {
        assert_eq!(record.event_type.as_str(), "notification_dispatched");
    }

    // Nothing out of `data` is in the plane that survives erasure, and that
    // includes the addresses of the people who were written to.
    let metadata = format!("{:?}", held.segments[0].records());
    for from_data in ["ops@acme.example", "oncall@acme.example", "smtp"] {
        assert!(
            !metadata.contains(from_data),
            "{from_data} reached the metadata plane"
        );
    }

    // And the pack is graded by code that shares none of ours. The verifier reads
    // the event type as the byte it is and never by name, which is why a type it
    // has never been told about does not stop it verifying.
    let pack = reader::pack(&held, &tenant(), Timestamp(T0));
    let report = trailryx_verify::verify(&pack).expect("the pack parses");
    assert!(
        report.verified(),
        "the offline verifier must accept a pack carrying the new event type: {:?}",
        report.findings
    );
    assert_eq!(
        report.records_checked, 3,
        "two dispatches and the store's note"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

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
