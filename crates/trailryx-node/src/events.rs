//! A file of the estate's agent events, read into the plane, once each.
//!
//! The other products in this estate already emit NDJSON in the shared
//! `taipanbox.dev/agent-event` envelope. `trailryx-agentevent` maps one line into
//! one ingest unit; this is what makes that mapper reachable, because a mapper
//! nothing calls is exactly the shape the audit of 5 August 2026 found everywhere
//! else in this repository.
//!
//! Framing is `trailryx_json::Framer`, the same framer the OTLP/JSON file source
//! uses, and it is a dependency rather than a second loop for the reason that
//! crate gives: a partial last line is not corruption, an oversize line is a
//! bound rather than a syntax error, and a byte-order mark makes the whole stream
//! unreadable at any read size. Every one of those was a defect once.
//!
//! # Running it again
//!
//! [`ship`] is the whole command, and it is the part that makes a schedule safe.
//! It asks [`crate::cursor`] where the last run stopped in this file, reads only
//! what follows, seals it, and writes the new position down **after** the seal.
//! Everything about that ordering is in the cursor module's header; what belongs
//! here is why the command is a function rather than a block inside `main`. Three
//! of the four things it has to get right are about what it does **not** do: it
//! must not open the plane when there is nothing new, it must not write a cursor
//! when the seal failed, and it must not consume a line whose terminator has not
//! arrived. None of those is observable from outside a process, so none of them
//! could be tested while they lived in a binary.

use std::path::{Path, PathBuf};

use trailryx_agentevent::{EnvelopeConfig, Rejection, Report, map_line};
use trailryx_contracts::ingest::{Cursor as SourceCursor, Ingest};
use trailryx_json::{Framer, Limits};
use trailryx_record::{ShardIx, TenantId, Timestamp};
use trailryx_sim::clock::{Clock, SystemClock};

use crate::cursor::{self, Cursor, Resume};
use crate::plane::{Accepted, Opened, Plane, PlaneError, SealPolicy, Sealed};

/// How many units are handed to the plane at once.
///
/// A batch rather than a line, because the assembler resolves causal edges within
/// one batch and a batch of one can never find a parent.
const BATCH: usize = 1_024;

/// What a file cost, in records and in lines that produced none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ingested {
    pub accepted: Accepted,
    pub report: Report,
    /// Complete lines this run read, blank ones included.
    pub lines: u64,
}

/// One run of `trailryx-node events --file`.
#[derive(Debug, Clone)]
pub struct Ship<'a> {
    pub dir: &'a Path,
    pub shard: ShardIx,
    pub tenant: TenantId,
    pub trust_domain: &'a str,
    pub policy: SealPolicy,
    pub seed: u64,
    pub file: &'a Path,
}

/// What one run did, in enough detail that a reader can tell the cases apart.
#[derive(Debug)]
pub struct Shipped {
    /// What was decided about this file before anything was opened.
    pub resume: Resume,
    /// The first byte of the file this run read.
    pub from: u64,
    /// One past the last byte this run read. Equal to `from` when nothing was new.
    pub to: u64,
    /// Bytes of an unterminated final line, left where they are.
    pub held_back: u64,
    pub ingested: Ingested,
    /// Absent when nothing was new, because then the plane is never opened.
    pub opened: Option<Opened>,
    pub sealed: Option<Sealed>,
    /// Where the reader stands in this file now.
    pub cursor: Cursor,
    /// Whether that position was written down this run.
    pub cursor_written: bool,
    pub cursor_path: PathBuf,
}

impl Shipped {
    /// Whether this run found anything to read.
    ///
    /// The distinction the command's output rests on: a reader has to be able to
    /// tell "nothing new" from "nothing happened", and those look identical in a
    /// report that only prints what it wrote.
    pub fn nothing_new(&self) -> bool {
        self.from == self.to
    }
}

/// Read whatever this file has that the last run did not, and seal it.
pub fn ship(ship: &Ship<'_>) -> Result<Shipped, PlaneError> {
    let cfg = EnvelopeConfig::new(ship.tenant.clone(), ship.trust_domain).map_err(|e| {
        PlaneError::Refused(format!(
            "trust domain {} is not usable: {e:?}",
            ship.trust_domain
        ))
    })?;
    let bytes = std::fs::read(ship.file)
        .map_err(|e| PlaneError::Io(format!("{}: {e}", ship.file.display())))?;

    let source = cursor::source_name(ship.file);
    let remembered = cursor::load(ship.dir, ship.shard, ship.file);
    let resume = cursor::decide(remembered, &bytes, &source);

    let from = resume.from();
    // A line is not consumed until its terminator has landed, so the region this
    // run may read ends at the last one. `max(from)` is for the case where the
    // last terminator in the file is the one the cursor already passed: then the
    // region is empty and the tail is held back, rather than a length that runs
    // backwards.
    let to = cursor::complete_prefix(&bytes).max(from);
    let held_back = bytes.len() as u64 - to;

    let mut out = Shipped {
        from,
        to,
        held_back,
        ingested: Ingested::default(),
        opened: None,
        sealed: None,
        cursor: Cursor {
            path: source.clone(),
            bytes: to,
            lines: resume.lines_before(),
            records: resume.records_before(),
            prefix: cursor::digest(&bytes[..usize::try_from(to).unwrap_or(usize::MAX)]),
            at: Timestamp(SystemClock::new().wall_nanos()),
        },
        cursor_written: false,
        cursor_path: cursor::path_of(ship.dir, ship.shard, ship.file),
        resume,
    };

    if out.nothing_new() {
        // Not one byte of the plane is touched. Opening it would create the next
        // segment's journal and its watermark, which is a change to a directory
        // for a run that had nothing to do, and this command is meant to be safe
        // to run on a timer against a file nobody is writing to.
        //
        // The position is still written down when it is not the position that was
        // remembered, which is how a file that was rotated away to nothing stops
        // being reported as rotated on every run afterwards.
        out.cursor_written = out.wrote_a_new_position(ship)?;
        return Ok(out);
    }

    let (mut plane, opened) = Plane::open(
        ship.dir,
        ship.shard,
        ship.tenant.clone(),
        ship.trust_domain,
        ship.policy,
        ship.seed,
    )?;
    out.opened = Some(opened);
    let now = plane.now();
    let region = &bytes
        [usize::try_from(from).unwrap_or(usize::MAX)..usize::try_from(to).unwrap_or(usize::MAX)];
    out.ingested = ingest_bytes(&mut plane, &cfg, region, now, out.resume.lines_before())?;

    // Sealed here rather than left for a schedule, because this command ends: a
    // record that is written and never sealed is a record no proof covers.
    //
    // THE ORDER BELOW IS THE WHOLE DURABILITY ARGUMENT. The manifest write inside
    // `seal` is the commit point, and the cursor moves only after it, so a crash
    // can leave the cursor behind the evidence and never ahead of it. Behind means
    // this run's lines are read again and stored twice, which the next run
    // reports; ahead would mean lines that were never stored are skipped, and
    // nothing at all would say so. The `?` is part of it: a seal that failed never
    // reaches the line below.
    out.sealed = plane.seal(plane.now())?;
    out.cursor.lines = out.resume.lines_before() + out.ingested.lines;
    out.cursor.records = out.resume.records_before() + out.ingested.accepted.written;
    out.cursor_written = out.wrote_a_new_position(ship)?;
    Ok(out)
}

impl Shipped {
    /// Commit the position, unless it is the position that was already there.
    ///
    /// The exception is what makes "an unchanged file is not written to" literal
    /// rather than nearly true: a re-run over a file nobody has touched must leave
    /// the data directory byte for byte as it found it, cursor included.
    fn wrote_a_new_position(&self, ship: &Ship<'_>) -> Result<bool, PlaneError> {
        if let Resume::After(before) = &self.resume
            && before.bytes == self.cursor.bytes
            && before.lines == self.cursor.lines
            && before.records == self.cursor.records
        {
            return Ok(false);
        }
        cursor::save(ship.dir, ship.shard, ship.file, &self.cursor)
            .map_err(|e| PlaneError::Io(format!("{}: {e}", self.cursor_path.display())))?;
        Ok(true)
    }
}

/// Read a file of agent events into the plane.
///
/// Fail-open per line and never silent, which is the rule every source in this
/// tree follows: a line that cannot become a record is counted by its reason and
/// the rest of the file still lands. What the caller does with the counts is its
/// own business, and the binary writes them out.
pub fn ingest_file(
    plane: &mut Plane,
    cfg: &EnvelopeConfig,
    path: &Path,
    now: Timestamp,
) -> Result<Ingested, PlaneError> {
    let bytes =
        std::fs::read(path).map_err(|e| PlaneError::Io(format!("{}: {e}", path.display())))?;
    ingest_bytes(plane, cfg, &bytes, now, 0)
}

/// The same, over bytes a caller already holds.
///
/// `lines_before` is how many lines of this file earlier runs already read, so
/// the cursor a source is told about is its position in the whole file rather
/// than in the fragment this run happened to be given.
pub fn ingest_bytes(
    plane: &mut Plane,
    cfg: &EnvelopeConfig,
    bytes: &[u8],
    now: Timestamp,
    lines_before: u64,
) -> Result<Ingested, PlaneError> {
    let mut out = Ingested::default();
    let mut framer = Framer::new(Limits::default());
    let mut batch: Vec<Ingest> = Vec::new();

    let mut take = |line: trailryx_json::Line<'_>| -> trailryx_json::JsonResult<()> {
        let at = lines_before.saturating_add(line.number);
        match map_line(cfg, line.bytes, SourceCursor(at)) {
            Ok(unit) => {
                out.report.mapped = out.report.mapped.saturating_add(1);
                batch.push(unit);
            }
            Err(rejection) => out.report.note(rejection),
        }
        Ok(())
    };

    // A stream this framer refuses is refused whole rather than half read: a
    // UTF-16 mark means nothing in the file is what it says it is.
    if framer.push(bytes, &mut take).is_err() || framer.finish(&mut take).is_err() {
        return Err(PlaneError::Refused(
            "this file is not UTF-8 JSON Lines, so none of it was read".to_owned(),
        ));
    }
    out.lines = framer.line_no();

    for chunk in batch.chunks(BATCH) {
        let accepted = plane.accept(chunk.to_vec(), now)?;
        out.accepted.written += accepted.written;
        out.accepted.duplicates += accepted.duplicates;
        out.accepted.declined_payload_parts += accepted.declined_payload_parts;
    }
    Ok(out)
}

/// Whether a rejection means a producer has to change something.
///
/// Split out because the two kinds want different answers from an operator: a
/// line this reading of the registry does not map is a decision written down in
/// `trailryx-agentevent`, while a line with no run identifier is a producer that
/// can add one.
pub fn is_producer_fixable(rejection: Rejection) -> bool {
    matches!(
        rejection,
        Rejection::NoRunId | Rejection::NoAgent | Rejection::ForeignTrustDomain
    )
}
