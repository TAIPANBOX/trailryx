//! The record plane, run as a process would run it.
//!
//! Every test here crosses the boundary the audit of 5 August 2026 said nothing
//! crossed: records go in through the same seam a source uses, the journal takes
//! them, a segment seals on a schedule, the process ends, and something else
//! reads them back out of the directory it left behind.
//!
//! Nothing here mocks storage. The journal is a real file, the manifest is a real
//! file, and the reader is given nothing but the path.

use std::path::PathBuf;

use trailryx_contracts::ingest::{Correlation, Cursor, Ingest, MetaDraft, PayloadPart, SourceKey};
use trailryx_index::completeness::Dimension;
use trailryx_node::{Plane, SealPolicy, reader};
use trailryx_record::{
    AgentId, Basis, EventType, MapperVersion, PayloadClass, RunId, Severity, ShardIx, TenantId,
    Timestamp, Untrusted,
};
use trailryx_store::query::{ProofStatus, Query, query_segment};

const TENANT: &str = "acme";
const TRUST_DOMAIN: &str = "acme.example";
const AGENT: &str = "agent://acme.example/billing";
const RUN: &str = "run-4471";
/// A moment far enough from the epoch that a record's ULID is well formed.
const T0: u64 = 1_785_000_000_000_000_000;

/// A scratch directory this process alone can name.
///
/// The process id is invariant 29: `$TMPDIR` belongs to the user, not to the run,
/// so a fixture named after itself is one a second copy of this binary names
/// identically. The pre-clean is for a recycled process id; every test wipes its
/// own directory at the end.
fn scratch(what: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trailryx-node-{what}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn tenant() -> TenantId {
    TenantId::parse(TENANT).expect("a constant tenant parses")
}

fn draft(run: &str) -> MetaDraft {
    MetaDraft {
        mapper: MapperVersion(2),
        tenant: tenant(),
        agent_id: AgentId::parse_strict(AGENT).expect("a constant agent parses"),
        run_id: RunId::parse(run).expect("a constant run parses"),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(T0)),
        decided_at: None,
        event_type: EventType::ModelCall,
        severity: Severity::Info,
        basis: Basis::default(),
        verdict: None,
        error: None,
        latency_micros: None,
        tokens_in: None,
        tokens_out: None,
        cost_micros: None,
    }
}

/// One unit as a source hands it over, with an optional payload part.
fn unit(n: u64, payload: bool) -> Ingest {
    Ingest {
        meta: draft(RUN),
        payload: if payload {
            vec![PayloadPart::new(PayloadClass::Prompt, b"a prompt".to_vec())]
        } else {
            Vec::new()
        },
        correlation: Some(Correlation {
            id: SourceKey::new(&n.to_be_bytes()).expect("eight bytes is a key"),
            parent: None,
        }),
        cursor: Cursor(n),
    }
}

fn units(count: u64) -> Vec<Ingest> {
    (0..count).map(|n| unit(n, false)).collect()
}

fn policy(records: u64) -> SealPolicy {
    SealPolicy {
        seal_after_records: records,
        // Out of reach, so a test about the record count is not also a test about
        // the clock.
        seal_after_nanos: u64::MAX,
        sync_every: 1,
    }
}

fn open(dir: &std::path::Path, policy: SealPolicy) -> (Plane, trailryx_node::Opened) {
    Plane::open(dir, ShardIx(0), tenant(), TRUST_DOMAIN, policy, 0x7461696c)
        .expect("a data directory opens")
}

/// Every sealed record of one shard, by agent, with whatever proof it carries.
fn read_back(dir: &std::path::Path) -> (usize, ProofStatus) {
    let held = reader::read_sealed(dir, ShardIx(0)).expect("the directory reads back");
    let key = AGENT.as_bytes().to_vec();
    let mut rows = 0;
    let mut proof = ProofStatus::Full;
    for segment in &held.segments {
        let answer = query_segment(segment, &Query::point(Dimension::AgentId, key.clone()));
        rows += answer.records.len();
        if answer.proof != ProofStatus::Full {
            proof = answer.proof;
        }
    }
    (rows, proof)
}

/// The whole point of the crate: what went in comes back out of a directory, in
/// a process that was not the one that wrote it.
#[test]
fn records_are_sealed_and_another_process_reads_them_back() {
    let dir = scratch("round-trip");
    let (mut plane, opened) = open(&dir, policy(5));
    assert_eq!(
        opened.recovered.records, 0,
        "a fresh directory holds nothing"
    );

    let accepted = plane
        .accept(units(5), Timestamp(T0))
        .expect("five units are taken");
    assert_eq!(accepted.written, 5, "five records reached the journal");

    let sealed = plane
        .tick(Timestamp(T0))
        .expect("the schedule runs")
        .expect("five records is the policy's segment");
    assert_eq!(sealed.records, 5);
    // The process ends here. Everything below has only the directory.
    drop(plane);

    let (rows, proof) = read_back(&dir);
    assert_eq!(rows, 5, "every sealed record comes back");
    assert_eq!(
        proof,
        ProofStatus::Full,
        "and the answer carries its completeness proof"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A shard is one chain across as many files as it takes, and a restart is where
/// that stops being free: the second process has to learn where the first left
/// off from the directory rather than from memory.
#[test]
fn a_second_segment_continues_the_first_across_a_restart() {
    let dir = scratch("chain");
    let (mut plane, _) = open(&dir, policy(2));
    plane
        .accept(units(2), Timestamp(T0))
        .expect("two units are taken");
    let first = plane
        .tick(Timestamp(T0))
        .expect("the schedule runs")
        .expect("a first segment");
    drop(plane);

    let (mut plane, opened) = open(&dir, policy(2));
    assert_eq!(
        opened.segment.0, 2,
        "a restart continues at the segment after the last sealed one"
    );
    plane
        .accept(units(2), Timestamp(T0 + 1_000_000))
        .expect("two more units are taken");
    let second = plane
        .tick(Timestamp(T0 + 1_000_000))
        .expect("the schedule runs")
        .expect("a second segment");
    assert_eq!(second.segment.0, 2);
    drop(plane);

    let held = reader::read_sealed(&dir, ShardIx(0)).expect("the directory reads back");
    assert_eq!(held.segments.len(), 2, "both segments are sealed");
    assert_eq!(
        held.segments[1].manifest().chain_before,
        first.chain_after,
        "segment 2 begins where segment 1 ended, so a whole file cannot be dropped \
         without breaking the pair"
    );
    let (rows, _) = read_back(&dir);
    assert_eq!(rows, 4);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sealing is the store's own job on its own schedule. A store whose segments
/// only seal when a caller remembers to ask is a library.
#[test]
fn sealing_happens_on_a_schedule_rather_than_when_a_caller_asks() {
    let dir = scratch("schedule");
    let (mut plane, _) = open(&dir, policy(3));

    plane
        .accept(units(2), Timestamp(T0))
        .expect("two units are taken");
    assert!(
        plane
            .tick(Timestamp(T0))
            .expect("the schedule runs")
            .is_none(),
        "two records is under the policy, so nothing seals"
    );

    plane
        .accept(units(1), Timestamp(T0 + 1))
        .expect("a third unit is taken");
    let sealed = plane
        .tick(Timestamp(T0 + 1))
        .expect("the schedule runs")
        .expect("the third record reaches the policy");
    assert_eq!(sealed.records, 3);
    drop(plane);

    // And the other half of the schedule: a shard too quiet to reach the record
    // count still seals, because an audit trail nobody can read until it is busy
    // is not an audit trail.
    let dir2 = scratch("schedule-time");
    let slow = SealPolicy {
        seal_after_records: u64::MAX,
        seal_after_nanos: 1_000_000_000,
        sync_every: 1,
    };
    let (mut plane, _) = open(&dir2, slow);
    plane
        .accept(units(1), Timestamp(T0))
        .expect("one unit is taken");
    assert!(
        plane
            .tick(Timestamp(T0))
            .expect("the schedule runs")
            .is_none(),
        "no time has passed"
    );
    let sealed = plane
        .tick(Timestamp(T0 + 2_000_000_000))
        .expect("the schedule runs")
        .expect("two seconds is past the policy");
    assert_eq!(sealed.records, 1);
    drop(plane);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

/// An idle shard is a normal thing to find, and sealing an empty segment would
/// put a slot in the shard that anything could later be attached to.
#[test]
fn an_idle_shard_seals_nothing() {
    let dir = scratch("idle");
    let (mut plane, _) = open(&dir, policy(1));
    assert!(
        plane
            .tick(Timestamp(T0 + 10_000_000_000))
            .expect("the schedule runs")
            .is_none(),
        "there is nothing durable to seal"
    );
    drop(plane);
    let held = reader::read_sealed(&dir, ShardIx(0)).expect("the directory reads back");
    assert!(held.segments.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The reader rebuilds a segment from the journal's own bytes and compares what
/// falls out with the manifest that was published for it. A byte changed in the
/// bucket, or on the disk, is the case this exists for.
#[test]
fn a_journal_altered_after_sealing_is_refused_rather_than_answered() {
    let dir = scratch("tamper");
    let (mut plane, _) = open(&dir, policy(3));
    plane
        .accept(units(3), Timestamp(T0))
        .expect("three units are taken");
    plane
        .tick(Timestamp(T0))
        .expect("the schedule runs")
        .expect("a sealed segment");
    drop(plane);

    // It reads back before anything is touched, so the refusal below is about the
    // change and not about the file.
    let (rows, _) = read_back(&dir);
    assert_eq!(rows, 3);

    let path = dir.join(trailryx_node::plane::journal_name(
        ShardIx(0),
        trailryx_record::SegmentId(1),
    ));
    let mut bytes = std::fs::read(&path).expect("the journal is on disk");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&path, &bytes).expect("the journal is writable");

    let refused = reader::read_sealed(&dir, ShardIx(0))
        .expect_err("a segment that does not rebuild must not be answered from");
    assert!(
        format!("{refused}").contains("seg-"),
        "the refusal names the segment: {refused}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The durability contract, across the boundary it is about. Records that were
/// acked and not yet sealed are not lost by a restart: the next process recovers
/// them and the next seal covers them.
#[test]
fn records_acked_but_not_sealed_survive_a_restart() {
    let dir = scratch("unsealed");
    let (mut plane, _) = open(&dir, policy(u64::MAX));
    plane
        .accept(units(4), Timestamp(T0))
        .expect("four units are taken");
    plane.sync().expect("the journal is synced");
    assert_eq!(plane.acked(), 4);
    drop(plane);

    let (mut plane, opened) = open(&dir, policy(1));
    assert_eq!(
        opened.recovered.records, 4,
        "the four acked records came back"
    );
    assert_eq!(
        opened.segment.0, 1,
        "and they are still the open segment, because nothing sealed them"
    );
    plane
        .tick(Timestamp(T0 + 1))
        .expect("the schedule runs")
        .expect("the recovered records are sealed");
    drop(plane);

    let (rows, proof) = read_back(&dir);
    assert_eq!(rows, 4);
    assert_eq!(proof, ProofStatus::Full);
    let _ = std::fs::remove_dir_all(&dir);
}

/// This process has no key custodian, so it keeps no payloads. What it must not
/// do is drop them quietly: the count is a record, in the run it belongs to,
/// where a reconstruction of that run finds it.
#[test]
fn a_payload_this_process_cannot_seal_is_written_down_rather_than_dropped() {
    let dir = scratch("payload");
    let (mut plane, _) = open(&dir, policy(u64::MAX));
    let accepted = plane
        .accept(vec![unit(1, true)], Timestamp(T0))
        .expect("the unit is taken");
    assert_eq!(
        accepted.declined_payload_parts, 1,
        "the payload part was declined"
    );
    assert_eq!(
        accepted.written, 1,
        "one record; the note about what was not kept is written when the segment closes"
    );
    plane
        .seal(Timestamp(T0))
        .expect("a seal on request")
        .expect("a sealed segment");
    drop(plane);

    let held = reader::read_sealed(&dir, ShardIx(0)).expect("the directory reads back");
    let records: Vec<_> = held.segments.iter().flat_map(|s| s.records()).collect();
    assert_eq!(
        records.len(),
        2,
        "the record, and the store's own note about what it would not keep, in the \
         same segment"
    );
    let source_record = records
        .iter()
        .find(|r| r.event_type == EventType::ModelCall)
        .expect("the source's record");
    assert!(
        source_record.payload.is_none(),
        "a record must not point at a payload nothing sealed"
    );
    let note = records
        .iter()
        .find(|r| r.event_type == EventType::StoreEvent)
        .expect("the store's own note");
    assert_eq!(
        note.run_id.as_str(),
        RUN,
        "the note lands in the run it is about, which is a provable dimension"
    );
    assert_eq!(
        note.outcome.tokens_in,
        Some(1),
        "and it carries how many parts were declined"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The reader's answer, checked by the one implementation that shares no code
/// with the store. A round trip graded by the code that wrote it proves that the
/// code agrees with itself.
#[test]
fn what_a_reader_hands_over_is_what_the_offline_verifier_checks() {
    use trailryx_index::segment::{ShardTree, StoreTree};

    let dir = scratch("pack");
    let (mut plane, _) = open(&dir, policy(3));
    plane
        .accept(units(3), Timestamp(T0))
        .expect("three units are taken");
    plane
        .tick(Timestamp(T0))
        .expect("the schedule runs")
        .expect("a sealed segment");
    drop(plane);

    let held = reader::read_sealed(&dir, ShardIx(0)).expect("the directory reads back");
    let pack = reader::pack(&held, &tenant(), Timestamp(T0));
    let report = trailryx_verify::verify(&pack).expect("the pack parses");
    assert!(
        report.verified(),
        "the offline verifier must accept what the reader produced: {:?}",
        report.findings
    );
    assert_eq!(report.records_checked, 3);

    // And the shape the pack was built from is the shape the store publishes.
    let mut shard = ShardTree::new(ShardIx(0));
    for segment in &held.segments {
        shard.push(segment.manifest().clone());
    }
    assert_eq!(StoreTree::from_shards(&[shard]).shards(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
