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
//!
//! # A seal boundary is not a place in the file
//!
//! The position moves once per sealed segment, so this file's job is to know which
//! byte of the source each seal covers, and the two do not line up on their own.
//! One import's lines can straddle two segments; a segment can hold records
//! recovered from a run that died; and a line that produced no record advances the
//! file and commits nothing. So "how far this run has read" is the wrong number to
//! write at a seal: it reaches over lines whose records are in the next, still open
//! segment.
//!
//! [`Batch`] is the answer, and it is small on purpose. Units are cut into batches
//! that never span a seal, and each batch carries the offset one past the last line
//! that put a unit **in that batch**. Accepting a batch puts every one of its
//! records on the journal, so when the seal that follows lands, that offset is
//! covered by a manifest and nothing past it is. Nothing is kept per line, no side
//! index of the file is built, and no second file records any of it: the number
//! rides with the units it is about and dies with them.

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

/// Units to hand over at once, and the source position they account for.
///
/// The two numbers are the whole of the per-segment cursor. `through` is one past
/// the terminator of the last line that put a unit in here, **absolute in the
/// file**, and `lines` is that same line's number. Lines after it are not in this
/// batch, whether because they produced no record or because they belong to the
/// next one, and neither kind may carry a position over on this batch's evidence.
struct Batch {
    units: Vec<Ingest>,
    through: u64,
    lines: u64,
}

/// Everything framing one region produced.
struct Framed {
    batches: Vec<Batch>,
    report: Report,
    /// Complete lines in the region, blank and refused ones included.
    lines: u64,
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
    /// Every segment this run sealed, in order.
    ///
    /// A list rather than the one seal a run used to end with: the schedule decides
    /// how many there are, and each of them is a commit point that moved the
    /// position. Empty is a real answer and means nothing durable was produced.
    pub sealed: Vec<Sealed>,
    /// Where the reader stands in this file now.
    pub cursor: Cursor,
    /// Whether that position was written down this run.
    pub cursor_written: bool,
    /// Whether the position was HELD BACK because the run stored nothing and
    /// every refusal was the trust domain it was handed.
    ///
    /// A separate answer from `!cursor_written`, which is also what a run over
    /// an unchanged file reports, and the two want opposite reactions from an
    /// operator: one is the quiet correct case and this one means the argument
    /// they passed matches nothing on their bus.
    pub held_for_trust_domain: bool,
    /// How many times it was written. One per sealed segment, plus the one at the
    /// end of the run, minus any that would have rewritten a position unchanged.
    pub cursor_commits: u64,
    pub cursor_path: PathBuf,
    /// The position that is on disk, as far as this run knows.
    ///
    /// Private, and it is the guard behind "an unchanged file is not written to":
    /// with one commit per run that could be read off `resume`, and with several it
    /// cannot, because the second commit has to be compared against the first
    /// rather than against what the run started from.
    committed: Option<(u64, u64, u64)>,
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

    // The hash of the prefix a position claims. Carried across the run's commits,
    // because there are now several of them and taking each from byte zero would
    // make an import cost its own length times the number of seals.
    let mut prefix = cursor::Prefix::default();

    let mut out = Shipped {
        from,
        to,
        held_back,
        ingested: Ingested::default(),
        opened: None,
        sealed: Vec::new(),
        cursor: Cursor {
            path: source.clone(),
            bytes: from,
            lines: resume.lines_before(),
            records: resume.records_before(),
            prefix: prefix.through(&bytes, from),
            at: Timestamp(SystemClock::new().wall_nanos()),
        },
        cursor_written: false,
        held_for_trust_domain: false,
        cursor_commits: 0,
        cursor_path: cursor::path_of(ship.dir, ship.shard, ship.file),
        committed: match &resume {
            Resume::After(before) => Some((before.bytes, before.lines, before.records)),
            Resume::Whole(_) => None,
        },
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
        let (lines, records) = (out.cursor.lines, out.cursor.records);
        out.commit(ship, &bytes, &mut prefix, to, lines, records)?;
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

    // A batch may not span a seal, because the schedule is only asked between two
    // of them. With the default policy this is the batch size and the run behaves
    // as it always did; with a segment smaller than a batch it is the segment, or
    // `--seal-records 100` would seal every thousand records and quietly mean
    // something other than what it says.
    let cut = BATCH
        .min(usize::try_from(ship.policy.seal_after_records).unwrap_or(BATCH))
        .max(1);
    let framed = frame(&cfg, region, from, out.resume.lines_before(), cut)?;
    out.ingested.report = framed.report;
    out.ingested.lines = framed.lines;

    for batch in framed.batches {
        let (through, lines) = (batch.through, batch.lines);
        absorb(&mut out.ingested.accepted, plane.accept(batch.units, now)?);
        if !plane.seal_due(now) {
            continue;
        }
        // THE ORDER HERE IS THE WHOLE DURABILITY ARGUMENT, and it is the same one
        // the end of this function makes. The manifest write inside `seal` is the
        // commit point; the position moves only after it returns a sealed segment,
        // and only as far as the last line whose record is in that segment. So a
        // crash can leave the position behind the evidence and never ahead of it.
        // Behind means those lines are read again and stored twice, which the next
        // run reports; ahead would mean lines nobody stored are skipped, and
        // nothing at all would say so.
        //
        // `seal_due` is asked with the run's own `now`, the same instant the
        // records carry, so where a run seals is a function of what it read and not
        // of how long the machine took to read it.
        let Some(sealed) = plane.seal(now)? else {
            continue;
        };
        out.sealed.push(sealed);
        let records = out.resume.records_before() + out.ingested.accepted.written;
        out.commit(ship, &bytes, &mut prefix, through, lines, records)?;
    }

    // Sealed here rather than left for a schedule, because this command ends: a
    // record that is written and never sealed is a record no proof covers.
    //
    // The last commit is the only one that may reach past a line that produced no
    // record, and it is why a file of lines this build cannot map is not read for
    // ever: the run has finished with them, nothing was stored for them, and
    // nothing can be lost by not reading them again. A commit inside the run may
    // not do that, because a crash would then have skipped lines a later build,
    // taught to map them, would never see. The `?` is part of the order: a seal
    // that failed never reaches the line below it.
    if let Some(sealed) = plane.seal(plane.now())? {
        out.sealed.push(sealed);
    }

    // ONE REFUSAL CLASS IS NOT THE RUN'S TO FINISH WITH.
    //
    // The paragraph above is right about every rejection but one. A type this
    // reading does not map is this build's registry being CORRECT, and a line
    // with no run identifier is missing something no later run will add to
    // these bytes. Neither can be lost by not reading them again.
    //
    // The trust domain is different in kind: it is an ARGUMENT to this run, not
    // a property of the line or of the build. The same bytes under a different
    // `--trust-domain` map. So a run that stored nothing and refused only
    // because of the domain it was handed has not finished with those lines,
    // and a position committed past them is the silent loss this module's own
    // opening paragraph says it will not take: correcting the domain then
    // answers "nothing new. The cursor is at byte N of N (0 record(s) so far)",
    // and the only way back is deleting a cursor file by hand.
    //
    // Measured on stack-up's bus, 2026-08-27: 52 lines, 0 records, a position
    // past every one, exit 0. Seven sealed segments held 35 records and all 35
    // were that launcher's synthetic demo fleet, while four real planes had
    // been writing into the same directory for weeks.
    //
    // NARROW ON PURPOSE, and both halves matter. It applies only when the run
    // wrote NOTHING: a partial refusal is the designed state for a box whose
    // planes mint under more than one domain, and holding the position there
    // would re-read and duplicate every line that did map, on every run, for
    // ever. And it applies only to this class: `is_producer_fixable` groups
    // this one with two whose bytes will never map, which is the right split
    // for an operator's attention and the wrong one for a cursor.
    let stored_nothing_but_saw_a_foreign_domain =
        out.ingested.accepted.written == 0 && out.ingested.report.foreign_trust_domain > 0;
    if stored_nothing_but_saw_a_foreign_domain {
        out.held_for_trust_domain = true;
        return Ok(out);
    }

    let lines = out.resume.lines_before() + out.ingested.lines;
    let records = out.resume.records_before() + out.ingested.accepted.written;
    out.commit(ship, &bytes, &mut prefix, to, lines, records)?;
    Ok(out)
}

impl Shipped {
    /// Commit a position, unless it is the position that is already there.
    ///
    /// **Every caller of this is after a seal or after a run that sealed nothing,
    /// and there is no third case.** The argument for that is at both call sites;
    /// what belongs here is the exception, which makes "an unchanged file is not
    /// written to" literal rather than nearly true: a re-run over a file nobody has
    /// touched must leave the data directory byte for byte as it found it, cursor
    /// included. It also absorbs the ordinary end of an import, where the final
    /// commit asks for the position the last seal already committed.
    fn commit(
        &mut self,
        ship: &Ship<'_>,
        bytes: &[u8],
        prefix: &mut cursor::Prefix,
        at: u64,
        lines: u64,
        records: u64,
    ) -> Result<(), PlaneError> {
        // The path is the one thing that does not move, so the position is edited
        // rather than rebuilt around it.
        self.cursor.bytes = at;
        self.cursor.lines = lines;
        self.cursor.records = records;
        self.cursor.prefix = prefix.through(bytes, at);
        self.cursor.at = Timestamp(SystemClock::new().wall_nanos());
        if self.committed == Some((at, lines, records)) {
            return Ok(());
        }
        cursor::save(ship.dir, ship.shard, ship.file, &self.cursor)
            .map_err(|e| PlaneError::Io(format!("{}: {e}", self.cursor_path.display())))?;
        self.committed = Some((at, lines, records));
        self.cursor_written = true;
        self.cursor_commits += 1;
        Ok(())
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
    let framed = frame(cfg, bytes, 0, lines_before, BATCH)?;
    let mut out = Ingested {
        accepted: Accepted::default(),
        report: framed.report,
        lines: framed.lines,
    };
    // No seal here, and that is the division of labour rather than an omission:
    // this reads bytes into a plane, and only [`ship`] owns a position, so only
    // [`ship`] may decide when a segment closes. A caller with its own schedule
    // keeps it.
    for batch in framed.batches {
        absorb(&mut out.accepted, plane.accept(batch.units, now)?);
    }
    Ok(out)
}

/// Frame a region into batches, mapping every line it can.
///
/// `base` is where `bytes[0]` sits in the file, so a batch's `through` is a
/// position in the file rather than in whichever fragment this run was given.
/// `cut` is how many units one batch may hold, and the caller chooses it: the seal
/// is only asked about between batches, so a batch that spanned one would seal late
/// and commit a position over records that are not in the segment.
fn frame(
    cfg: &EnvelopeConfig,
    bytes: &[u8],
    base: u64,
    lines_before: u64,
    cut: usize,
) -> Result<Framed, PlaneError> {
    let cut = cut.max(1);
    let mut out = Framed {
        batches: Vec::new(),
        report: Report::default(),
        lines: 0,
    };
    let mut framer = Framer::new(Limits::default());

    let mut take = |line: trailryx_json::Line<'_>| -> trailryx_json::JsonResult<()> {
        let at = lines_before.saturating_add(line.number);
        match map_line(cfg, line.bytes, SourceCursor(at)) {
            Ok(unit) => {
                out.report.mapped = out.report.mapped.saturating_add(1);
                let open = match out.batches.last_mut() {
                    Some(batch) if batch.units.len() < cut => batch,
                    _ => {
                        out.batches.push(Batch {
                            units: Vec::new(),
                            through: base,
                            lines: lines_before,
                        });
                        out.batches.last_mut().expect("a batch was just pushed")
                    }
                };
                open.units.push(unit);
                // The batch reaches as far as the line that just put a unit in it,
                // and no further. A line after this one either produced no record
                // or will land in the next batch, and neither is evidence for a
                // position past this point.
                open.through = base.saturating_add(line.end);
                open.lines = at;
            }
            // Counted, and it moves nothing. The offset a refused line occupies is
            // accounted for at the end of the run and never at a seal: see `ship`.
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
    Ok(out)
}

/// One batch's counts into a run's.
fn absorb(total: &mut Accepted, one: Accepted) {
    total.written += one.written;
    total.duplicates += one.duplicates;
    total.declined_payload_parts += one.declined_payload_parts;
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
