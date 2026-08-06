//! Running `trailryx-node events --file` again, on purpose.
//!
//! heraldyx ships its dispatch journal into this plane on a schedule, which means
//! the same file is handed over again and again, having grown a little each time.
//! Every test here is one sentence about what that must do, and the first of them
//! is the defect: three imports of an unchanged file used to produce three copies
//! of every record, with `0 duplicate(s)` reported each time.

use std::path::{Path, PathBuf};

use trailryx_index::completeness::Dimension;
use trailryx_node::cursor::{self, Whole};
use trailryx_node::{Resume, SealPolicy, Ship, reader, ship};
use trailryx_record::{ShardIx, TenantId, Timestamp};
use trailryx_store::query::{Query, query_segment};

const TRUST_DOMAIN: &str = "acme.example";

/// A scratch directory this process alone can name: invariant 29. The pre-clean
/// is for a recycled process id, and every test wipes it again at the end.
fn scratch(what: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trailryx-cursor-{what}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn tenant() -> TenantId {
    TenantId::parse("acme").expect("a constant tenant parses")
}

/// One heraldyx dispatch, in the shape `internal/record/record.go` writes.
fn dispatch(second: u32) -> String {
    format!(
        r#"{{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-08-06T03:14:{second:02}Z","source":"heraldyx","type":"alert_sent","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","severity":"info","data":{{"kind":"alert","about":"budget_exhausted","to":["ops@acme.example"],"transport":"smtp","outcome":"accepted"}}}}
"#
    )
}

fn journal(lines: u32) -> String {
    (0..lines).map(dispatch).collect()
}

fn policy() -> SealPolicy {
    SealPolicy {
        seal_after_records: 4_096,
        seal_after_nanos: u64::MAX,
        sync_every: 64,
    }
}

fn run(dir: &Path, file: &Path) -> trailryx_node::Shipped {
    ship(&Ship {
        dir,
        shard: ShardIx(0),
        tenant: tenant(),
        trust_domain: TRUST_DOMAIN,
        policy: policy(),
        seed: 0x63757273,
        file,
    })
    .expect("the file is shipped")
}

/// Every dispatched notification in the directory, by the instant it happened at.
///
/// The event's own timestamp rather than the record's identity, because identity
/// is exactly what a re-import changes: two records minted from one line differ in
/// every field this plane stamps and agree on the one the producer wrote.
fn occurred(dir: &Path) -> Vec<u64> {
    let held = reader::read_sealed(dir, ShardIx(0)).expect("the directory reads back");
    let key = Dimension::EventType
        .key_from_text("notification_dispatched")
        .expect("a dispatched notification is a value on a provable dimension");
    let mut out = Vec::new();
    for segment in &held.segments {
        let answer = query_segment(segment, &Query::point(Dimension::EventType, key.clone()));
        out.extend(
            answer
                .records
                .iter()
                .map(|r| r.occurred_at.as_untrusted().as_nanos()),
        );
    }
    out.sort_unstable();
    out
}

/// Everything in a directory, by name and by size, so "wrote nothing" is checkable.
fn contents(dir: &Path) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = std::fs::read_dir(dir)
        .expect("the directory lists")
        .map(|entry| {
            let entry = entry.expect("an entry");
            (
                entry.file_name().to_string_lossy().into_owned(),
                entry.metadata().map(|m| m.len()).unwrap_or(0),
            )
        })
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------

#[test]
fn importing_an_unchanged_file_again_writes_nothing_and_says_so() {
    // The defect. Measured before this branch: three imports of a two-line file
    // produced nine records across three segments and reported no duplicates.
    let dir = scratch("unchanged");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, journal(2)).expect("the fixture is written");

    let first = run(&dir, &file);
    assert_eq!(first.ingested.accepted.written, 2, "both lines land");
    let after_first = contents(&dir);

    for again in 2..=3 {
        let repeat = run(&dir, &file);
        assert!(
            repeat.nothing_new(),
            "run {again} found something new in a file that has not changed: \
             {} .. {}",
            repeat.from,
            repeat.to
        );
        assert_eq!(
            repeat.ingested.accepted.written, 0,
            "run {again} wrote records for lines that were already stored"
        );
        assert!(
            repeat.opened.is_none(),
            "run {again} opened the plane, which is a write to the directory for a \
             run that had nothing to do"
        );
        assert_eq!(
            contents(&dir),
            after_first,
            "run {again} changed the data directory"
        );
    }

    assert_eq!(
        occurred(&dir).len(),
        2,
        "three imports of a two-line file left more than two records"
    );
    assert!(first.cursor_written, "the position is written down");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_file_that_has_grown_gives_up_only_its_new_lines() {
    let dir = scratch("grown");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, journal(2)).expect("the fixture is written");
    let first = run(&dir, &file);
    assert_eq!(first.ingested.accepted.written, 2);

    // heraldyx appends. The prefix is untouched and two more dispatches follow.
    std::fs::write(&file, journal(5)).expect("the fixture grows");
    let second = run(&dir, &file);
    assert!(
        matches!(second.resume, Resume::After(_)),
        "an appended file is resumed, not restarted: {:?}",
        second.resume
    );
    assert_eq!(
        second.ingested.report.mapped, 3,
        "only the three new lines were mapped"
    );
    assert_eq!(second.ingested.accepted.written, 3);
    assert_eq!(second.from, first.to, "it carried on from where it stopped");

    let instants = occurred(&dir);
    assert_eq!(instants.len(), 5, "five lines, five records");
    let mut unique = instants.clone();
    unique.dedup();
    assert_eq!(unique, instants, "a line was recorded twice");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_different_file_under_the_same_name_is_read_whole_rather_than_resumed() {
    // Rotation. The name survives and the bytes do not, and resuming into the new
    // file would skip however many bytes the old one had.
    let dir = scratch("rotated");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, journal(4)).expect("the fixture is written");
    run(&dir, &file);

    // A fresh journal under the same name, longer than the old one so that the
    // length alone cannot be what gives it away.
    let replacement: String = (10..16).map(dispatch).collect();
    std::fs::write(&file, &replacement).expect("the fixture is replaced");
    let after = run(&dir, &file);
    assert!(
        matches!(after.resume, Resume::Whole(Whole::PrefixDiffers { .. })),
        "a replaced file was resumed as though it were the old one: {:?}",
        after.resume
    );
    assert_eq!(after.from, 0, "it was read from the beginning");
    assert_eq!(after.ingested.accepted.written, 6);

    assert_eq!(
        occurred(&dir).len(),
        10,
        "four from the file that was rotated away and six from the one that replaced it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_file_that_shrank_is_read_whole_rather_than_resumed() {
    let dir = scratch("shrank");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, journal(4)).expect("the fixture is written");
    run(&dir, &file);

    std::fs::write(&file, journal(1)).expect("the fixture is truncated");
    let after = run(&dir, &file);
    assert!(
        matches!(after.resume, Resume::Whole(Whole::FileShorter { .. })),
        "a truncated file was resumed past its own end: {:?}",
        after.resume
    );
    assert_eq!(after.ingested.accepted.written, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_line_whose_terminator_has_not_arrived_is_held_back_rather_than_recorded_half_written() {
    // A collector that flushes on a timer leaves its last line unterminated most
    // of the time. Recording half of one would put a truncated event in an audit
    // trail, and the next flush would complete a line nothing was waiting for.
    let dir = scratch("partial");
    let file = dir.join("sent.ndjson");
    let mut half = journal(2);
    half.push_str(&dispatch(9)[..40]);
    std::fs::write(&file, &half).expect("the fixture is written");

    let first = run(&dir, &file);
    assert_eq!(first.ingested.accepted.written, 2, "only complete lines");
    assert_eq!(first.held_back, 40, "and the rest is left where it is");
    assert_eq!(occurred(&dir).len(), 2);

    // The producer finishes the line. It lands, once.
    std::fs::write(&file, journal(3)).expect("the fixture is completed");
    let second = run(&dir, &file);
    assert_eq!(second.held_back, 0);
    assert_eq!(second.ingested.accepted.written, 1);
    assert_eq!(occurred(&dir).len(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_cursor_that_did_not_survive_its_write_is_read_as_absent_rather_than_as_a_position() {
    // Every failure in the cursor module points this way on purpose. A damaged
    // position read as a position skips lines that were never stored, which is
    // silent; read as absent it re-imports lines that already are, which the run
    // reports.
    let dir = scratch("torn");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, journal(3)).expect("the fixture is written");
    let first = run(&dir, &file);

    let text = std::fs::read_to_string(&first.cursor_path).expect("the cursor is there");
    std::fs::write(&first.cursor_path, &text[..text.len() - 20]).expect("the cursor is cut short");

    let after = run(&dir, &file);
    assert!(
        matches!(after.resume, Resume::Whole(Whole::CursorUnreadable(_))),
        "a torn cursor was believed: {:?}",
        after.resume
    );
    assert_eq!(after.ingested.accepted.written, 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_cursor_lost_after_its_records_were_sealed_re_imports_rather_than_losing_the_lines() {
    // The direction the write order buys, stated as a test. The cursor is written
    // AFTER the seal, so a crash can only leave it behind the evidence, and behind
    // means a line is stored twice. Ahead would mean a line is never stored at
    // all, and nothing would say so: the test below is the other half of this one.
    let dir = scratch("lost");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, journal(3)).expect("the fixture is written");
    let first = run(&dir, &file);
    std::fs::remove_file(&first.cursor_path).expect("the cursor is lost");

    let after = run(&dir, &file);
    assert_eq!(
        after.ingested.accepted.written, 3,
        "the lines were read again"
    );
    assert_eq!(
        occurred(&dir).len(),
        6,
        "and are in the store twice, which is the cost of a cursor that is behind"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_cursor_ahead_of_the_evidence_would_lose_lines_which_is_why_it_is_written_last() {
    // The failure the ordering exists to make impossible, produced by hand so that
    // the reason the cursor is written after the seal is measured rather than
    // asserted. Nothing in this crate can write a cursor like this one.
    let dir = scratch("ahead");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, journal(4)).expect("the fixture is written");
    let bytes = std::fs::read(&file).expect("the fixture reads back");

    let ahead = cursor::Cursor {
        path: cursor::source_name(&file),
        bytes: bytes.len() as u64,
        lines: 4,
        records: 4,
        prefix: cursor::digest(&bytes),
        at: Timestamp(0),
    };
    cursor::save(&dir, ShardIx(0), &file, &ahead).expect("a cursor is written by hand");

    let after = run(&dir, &file);
    assert!(after.nothing_new(), "the whole file was skipped");
    assert_eq!(
        reader::read_sealed(&dir, ShardIx(0))
            .map(|held| held.records())
            .unwrap_or(0),
        0,
        "four dispatches were never stored and nothing said so"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_cursor_under_the_same_name_but_about_another_file_says_nothing_about_this_one() {
    // Sixty-four bits of a path digest name the cursor file, so two paths can land
    // on one name. The path inside is what turns that from a silent resume into a
    // file read whole.
    let dir = scratch("collision");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, journal(2)).expect("the fixture is written");
    let bytes = std::fs::read(&file).expect("the fixture reads back");

    let stranger = cursor::Cursor {
        path: "/somewhere/else/sent.ndjson".to_owned(),
        bytes: bytes.len() as u64,
        lines: 2,
        records: 2,
        prefix: cursor::digest(&bytes),
        at: Timestamp(0),
    };
    cursor::save(&dir, ShardIx(0), &file, &stranger).expect("a cursor is written by hand");

    let after = run(&dir, &file);
    assert!(
        matches!(after.resume, Resume::Whole(Whole::AnotherPath { .. })),
        "a cursor about another file was taken as this file's: {:?}",
        after.resume
    );
    assert_eq!(after.ingested.accepted.written, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_cursor_counts_the_whole_file_rather_than_the_fragment_one_run_read() {
    let dir = scratch("counts");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, journal(2)).expect("the fixture is written");
    let first = run(&dir, &file);
    assert_eq!(first.cursor.lines, 2);
    assert_eq!(first.cursor.records, 2);

    std::fs::write(&file, journal(5)).expect("the fixture grows");
    let second = run(&dir, &file);
    assert_eq!(
        second.cursor.lines, 5,
        "five lines of this file have been read"
    );
    assert_eq!(second.cursor.records, 5);
    assert_eq!(
        second.cursor.bytes,
        std::fs::metadata(&file)
            .expect("the fixture is there")
            .len()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
