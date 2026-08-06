//! Running `trailryx-node events --file` again, on purpose.
//!
//! heraldyx ships its dispatch journal into this plane on a schedule, which means
//! the same file is handed over again and again, having grown a little each time.
//! Every test here is one sentence about what that must do, and the first of them
//! is the defect: three imports of an unchanged file used to produce three copies
//! of every record, with `0 duplicate(s)` reported each time.

use std::path::{Path, PathBuf};

use trailryx_index::completeness::Dimension;
use trailryx_node::cursor::{self, Remembered, Whole};
use trailryx_node::{PlaneError, Resume, SealPolicy, Ship, Shipped, reader, ship};
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

fn run(dir: &Path, file: &Path) -> Shipped {
    attempt(policy(), dir, file, 0x63757273).expect("the file is shipped")
}

/// One run, with the policy and the seed named, and its failure handed back.
///
/// Separate from [`run`] because the tests below are about runs that do not
/// finish, and about a policy that seals inside one. The seed differs per run for
/// the reason `plane::seed_from_process` gives: two runs minting from one seed in
/// one millisecond would mint one identity twice, and the journal would absorb the
/// second record as a duplicate, which is exactly the thing these tests count.
fn attempt(policy: SealPolicy, dir: &Path, file: &Path, seed: u64) -> Result<Shipped, PlaneError> {
    ship(&Ship {
        dir,
        shard: ShardIx(0),
        tenant: tenant(),
        trust_domain: TRUST_DOMAIN,
        policy,
        seed,
        file,
    })
}

/// A policy that seals inside a run rather than only at the end of one.
fn sealing_every(records: u64) -> SealPolicy {
    SealPolicy {
        seal_after_records: records,
        seal_after_nanos: u64::MAX,
        sync_every: 64,
    }
}

/// A dispatch at an instant of its own, every line exactly as wide as every other.
///
/// The width is the point. With a constant line length the end of line *n* is at
/// byte *n* times that length, so a test can name the byte a cursor must stand on
/// rather than measuring the file and asserting it equals itself.
fn dispatch_at(n: u32) -> String {
    let (minute, second) = (n / 60, n % 60);
    format!(
        r#"{{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-08-06T03:{minute:02}:{second:02}Z","source":"heraldyx","type":"alert_sent","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","severity":"info","data":{{"kind":"alert","about":"budget_exhausted","to":["ops@acme.example"],"transport":"smtp","outcome":"accepted"}}}}
"#
    )
}

/// A line no reading of the registry maps, so it produces no record at all.
fn unmappable(n: u32) -> String {
    let (minute, second) = (n / 60, n % 60);
    format!(
        r#"{{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-08-06T03:{minute:02}:{second:02}Z","source":"heraldyx","type":"heartbeat","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","severity":"info"}}
"#
    )
}

/// A journal long enough to cross a seal boundary, and the width of one line.
fn long_journal(lines: u32) -> String {
    (0..lines).map(dispatch_at).collect()
}

fn line_width() -> u64 {
    dispatch_at(0).len() as u64
}

/// How many segments in this directory are sealed, which is how many manifests
/// there are: the manifest write is the commit point and nothing else says it.
fn manifests(dir: &Path) -> usize {
    contents(dir)
        .into_iter()
        .filter(|(name, _)| name.ends_with(".mf"))
        .count()
}

/// Stop the seal of one segment, the way a crash stops it: at the commit point.
///
/// `write_committing` writes `<manifest>.part` and renames it, so a directory
/// sitting on that name makes the create fail and the manifest never lands. The
/// journal keeps every record that was appended, unsealed, which is precisely the
/// state a `SIGKILL` between two seals leaves behind. `sealed_manifests` does not
/// look at a name ending in `.part`, so nothing else in the run notices it.
fn block_the_seal_of(dir: &Path, segment: u64) -> PathBuf {
    let at = dir.join(format!("s0-{segment:06}.mf.part"));
    std::fs::create_dir_all(&at).expect("the seal is blocked");
    at
}

fn remembered(dir: &Path, file: &Path) -> cursor::Cursor {
    match cursor::load(dir, ShardIx(0), file) {
        Remembered::Cursor(cursor) => cursor,
        other => panic!("no position was written down at all: {other:?}"),
    }
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

// ---------------------------------------------------------------------------
// How wide the window is, and what closes it
// ---------------------------------------------------------------------------

#[test]
fn an_import_longer_than_one_segment_seals_as_often_as_the_policy_says() {
    // `--seal-records` was a flag on this command that nothing read: `ship` sealed
    // once, at the end, whatever the number said. A run that seals once has a
    // duplication window as wide as itself.
    let dir = scratch("many-seals");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, long_journal(500)).expect("the fixture is written");

    let shipped =
        attempt(sealing_every(100), &dir, &file, 0x736f6d65).expect("the file is shipped");
    assert_eq!(shipped.ingested.accepted.written, 500, "every line landed");
    assert_eq!(
        manifests(&dir),
        5,
        "five hundred records at a hundred to a segment is five sealed segments, and \
         a command that seals once at the end of its run publishes one"
    );
    assert_eq!(shipped.sealed.len(), 5, "and the run says so");
    assert_eq!(
        shipped.cursor.bytes,
        500 * line_width(),
        "the position still ends at the end of the file"
    );
    assert_eq!(
        shipped.cursor_commits, 5,
        "one commit per sealed segment, and the one at the end of the run asked for \
         the position the fifth seal had already written"
    );
    assert_eq!(occurred(&dir).len(), 500, "and no line was stored twice");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_run_that_stops_between_seals_resumes_from_the_last_one_and_not_from_the_start() {
    // The whole point, measured. A crash costs a re-import of the records that were
    // written and never sealed, and of nothing before them. Before this branch it
    // cost a re-import of the entire run, because the position moved once, at the
    // end, and a run that did not reach its end moved it not at all.
    let dir = scratch("stopped");
    let file = dir.join("sent.ndjson");
    std::fs::write(&file, long_journal(500)).expect("the fixture is written");
    let blocked = block_the_seal_of(&dir, 3);

    let stopped = attempt(sealing_every(100), &dir, &file, 0x73746f70);
    assert!(
        stopped.is_err(),
        "the run reached the end of a five-segment file without ever trying to seal a \
         third segment, so it seals once per run rather than once per segment: {:?}",
        stopped.map(|s| (s.cursor.bytes, s.cursor.lines))
    );

    // Two segments are sealed and the position stands on the second of them: behind
    // the records that were written into the third and never committed, never ahead.
    assert_eq!(manifests(&dir), 2, "the third seal never landed");
    let at = remembered(&dir, &file);
    assert_eq!(at.bytes, 200 * line_width(), "two segments' worth of bytes");
    assert_eq!(at.lines, 200);
    assert_eq!(at.records, 200);
    assert_eq!(
        occurred(&dir).len() as u64,
        at.records,
        "the position claims exactly the records a reader can find sealed"
    );

    // What resuming then costs. The next run reads from line 200, so the hundred
    // records the dead run had put in the unsealed segment are the only ones stored
    // twice, and nothing is missing.
    std::fs::remove_dir(&blocked).expect("the seal is unblocked");
    let after = attempt(sealing_every(100), &dir, &file, 0x61667465).expect("the rest is shipped");
    assert_eq!(
        after.from,
        200 * line_width(),
        "it carried on from the last seal"
    );
    assert_eq!(after.ingested.report.mapped, 300);

    let instants = occurred(&dir);
    let mut distinct = instants.clone();
    distinct.dedup();
    assert_eq!(distinct.len(), 500, "every line is in the store");
    assert_eq!(
        instants.len() - distinct.len(),
        100,
        "and exactly one unsealed segment's worth is in it twice, rather than the \
         whole of the run that died"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_line_that_produced_no_record_does_not_carry_the_position_past_itself() {
    // A refused line advances the file offset and stores nothing, so a position
    // committed past one rests on no evidence at all. Committing it at a seal would
    // mean that a build which later learns to map that type never sees the line
    // again, and nothing would say so. So a seal moves the position to the last line
    // whose record is in the segment being sealed, and not one byte further.
    let dir = scratch("refused");
    let file = dir.join("sent.ndjson");
    let mut text = long_journal(100);
    for n in 100..103 {
        text.push_str(&unmappable(n));
    }
    for n in 103..200 {
        text.push_str(&dispatch_at(n));
    }
    std::fs::write(&file, &text).expect("the fixture is written");
    let blocked = block_the_seal_of(&dir, 2);

    let stopped = attempt(sealing_every(100), &dir, &file, 0x72656675);
    assert!(
        stopped.is_err(),
        "the run finished without a second seal, so nothing was committed inside it: \
         {:?}",
        stopped.map(|s| (s.cursor.bytes, s.cursor.lines))
    );

    let at = remembered(&dir, &file);
    assert_eq!(
        at.bytes,
        100 * line_width(),
        "the position stands on the last line the sealed segment holds a record for, \
         and not past the three that produced none"
    );
    assert_eq!(
        at.lines, 100,
        "three refused lines are not accounted for yet"
    );
    assert_eq!(at.records, 100);

    // They are read again, refused again, and cost a parse rather than a record.
    std::fs::remove_dir(&blocked).expect("the seal is unblocked");
    let after = attempt(sealing_every(100), &dir, &file, 0x61676169).expect("the rest is shipped");
    assert_eq!(
        after.ingested.report.unknown_type, 3,
        "the lines that produced nothing were read again"
    );
    assert_eq!(after.ingested.report.mapped, 97);
    assert_eq!(
        after.cursor.lines, 200,
        "and the end of the run accounts for all of them, refused ones included, \
         exactly as it did before"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_run_that_seals_nothing_writes_its_position_down_as_it_always_did() {
    // The no-regression half. A file this reading maps nothing in produces no
    // record, no segment and no manifest, and the position still moves to the end of
    // it, or every run afterwards would read the same unmappable lines for ever.
    let dir = scratch("nothing-sealed");
    let file = dir.join("sent.ndjson");
    let text: String = (0..40).map(unmappable).collect();
    std::fs::write(&file, &text).expect("the fixture is written");

    let shipped = attempt(sealing_every(10), &dir, &file, 0x6e6f7468).expect("the file is shipped");
    assert_eq!(shipped.ingested.accepted.written, 0);
    assert_eq!(manifests(&dir), 0, "there was nothing durable to seal");
    assert!(shipped.cursor_written, "and the position still moved");
    assert_eq!(shipped.cursor.bytes, text.len() as u64);
    assert_eq!(shipped.cursor.records, 0);

    let again = attempt(sealing_every(10), &dir, &file, 0x6e6f7469).expect("the file is shipped");
    assert!(
        again.nothing_new(),
        "a file of lines nothing maps must not be read again for ever"
    );
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
