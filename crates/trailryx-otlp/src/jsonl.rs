//! A file of OTLP/JSON lines as a [`Source`].
//!
//! The sibling of [`crate::source`] for the transport that writes to a disk
//! instead of to a socket: one `{"resourceSpans":[...]}` per line, which is what
//! the collector's file exporter and otel-java's `OtlpJsonLoggingSpanExporter`
//! produce. The decoder is [`crate::otlpjson`] and the mapper is
//! [`crate::semconv`], both unchanged, so a record made from a file and a record
//! made from a socket are the same record. Only the framing and the counters that
//! are about framing live here.
//!
//! # Fail-open, but never silent
//!
//! A malformed line does not stop the reader and does not fail the producer. An
//! agent whose telemetry library has a bug must not be turned into an agent that
//! cannot work, and a file is worse than a socket in this respect: one bad line
//! in the middle of yesterday's archive would otherwise cost every line after it.
//! So every refusal costs one line, is counted by name, and the counts become a
//! record of their own through [`JsonlSource::anomaly_event`].
//!
//! The *fact* of loss is metadata, where erasure cannot reach it; the *breakdown*
//! is payload, because it counts things that were about somebody.
//!
//! # An archive and a live file are not the same file
//!
//! [`JsonlSource::replay`] and [`JsonlSource::tail`] differ in exactly one
//! judgement, and it is the one that cannot be made from the bytes: whether the
//! producer's clock is supposed to agree with ours. Replaying last week's archive
//! through a reader that assesses skew marks every record excessively skewed and
//! then writes an anomaly record saying the fleet's clocks have drifted, which is
//! true of the reader and false of the fleet. So skew is assessed only in
//! [`Mode::Tail`], and in [`Mode::Replay`] the absence is counted rather than
//! hidden: see [`LineReport::skew_not_assessed`].
//!
//! # No clock of its own, and no file name either
//!
//! `recorded_at` is supplied by the caller, because it must come from the store's
//! clock. A reader that stamped its own time would be one process away from a
//! source that stamps its own time, and the difference between those two is the
//! entire trust model.
//!
//! Nor does any record here name a file. A path is operator infrastructure and
//! frequently a person's home directory, so it belongs in whatever launched the
//! reader and nowhere in the metadata plane. Which line something came from
//! reaches an operator through the counters, and that is deliberate:
//! [`trailryx_json::JsonError`] carries a line number and
//! [`trailryx_contracts::contracts::AdapterError`] cannot.

use crate::otlp::{Dropped, Limits as OtlpLimits};
use crate::otlpjson::{ShapeReport, decode_traces_data};
use crate::semconv::{MAPPER_VERSION, MapperConfig, Report, map_span};
use std::collections::VecDeque;
use std::fmt;
use trailryx_contracts::contracts::{
    AdapterResult, Delivery, Ordering, Source, SourceDescriptor, Trust,
};
use trailryx_contracts::ingest::{Cursor, Ingest, MetaDraft, PayloadPart};
use trailryx_json::frame::FrameReport;
use trailryx_json::{Bound, Encoding, Framer, JsonError, Kind, Limits as JsonLimits, Line, Syntax};
use trailryx_record::{
    AgentId, Basis, EventType, MapperVersion, PayloadClass, RunId, Severity, Timestamp, Untrusted,
    Verdict, assess_skew,
};

/// Records that may wait to be drained before the reader stops reading.
///
/// 65_536, which is `trailryx_ingest::Config::max_pending` and the same number
/// for the same reason. The queue is the only unbounded thing a reader can grow,
/// and a reader that keeps reading into one nobody drains is a slow OOM: the
/// bytes it has not read yet are still on the disk, and the records it has
/// already made are not.
pub const DEFAULT_MAX_PENDING: usize = 65_536;

/// Whether the file is an archive or one a producer is still writing.
///
/// Not a flag on a single reader but a choice made when it is constructed,
/// because the two answers are not interchangeable at runtime: see the module
/// doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// An archive. The producer's clock is not compared with ours, because the
    /// two are not supposed to agree.
    Replay,
    /// A live file. Both clocks refer to now, so a disagreement is worth
    /// noticing.
    Tail,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::Tail => "tail",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a counter names something that is missing, or something that merely
/// describes what arrived.
///
/// Every counter in the reader is one or the other, and saying which is what
/// makes [`Counters::anomaly_total`] a sum rather than a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// A record that does not exist, or a field of one that does not. Reaches
    /// [`Counters::anomaly_total`] and therefore becomes a record.
    Loss,
    /// True of the traffic and not a loss. Reported, never alarmed on: a counter
    /// that fires an anomaly for the ordinary state of a live file would make
    /// every tail read look like an incident.
    Diagnostic,
}

/// One counter, named and classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counter {
    pub name: &'static str,
    pub value: u64,
    pub class: Class,
}

/// What the framing saw that was not a line, and what a line cost.
///
/// [`Self::malformed_lines`] is the total of every line refused for any reason.
/// Everything below it that is a subclass **explains that total without adding to
/// it**, so the two are never summed: a refused line counted once as itself and
/// once as its subclass would report twice the loss there was.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LineReport {
    /// Lines that produced nothing because they could not be read. The total.
    pub malformed_lines: u64,

    /// Over [`trailryx_json::Limits::max_line_bytes`]. Counted by the framer,
    /// which refuses the line on bytes read rather than assembling it first.
    pub oversize_lines: u64,
    /// Nesting past [`trailryx_json::Limits::max_depth`]. Cheap to send and,
    /// without the bound, a way to abort the process from outside.
    pub too_deep: u64,
    /// The same member name twice in one object. Fatal in this tree because
    /// which duplicate wins is an implementation detail, and CVE-2017-12635 is
    /// that detail becoming a privilege escalation.
    pub duplicate_members: u64,
    /// An unpaired surrogate, escaped or raw. Fatal because every lenient
    /// reading of one is lossy, and truncation is a published escalation
    /// primitive.
    pub lone_surrogates: u64,
    /// Not UTF-8, or a byte-order mark that says UTF-16 or UTF-32. A whole
    /// stream refused for a mark is charged here and to the total, because it
    /// produced no records and something has to be visible.
    pub bad_encoding: u64,
    /// Two JSON values on one line. otel-java's `OtlpStdout*` exporters wrote
    /// exactly this before roughly 1.44, so it is a producer's signature rather
    /// than random corruption and is worth telling apart from one.
    pub concatenated_values: u64,
    /// A line that ended in the middle of a value, with more lines after it.
    /// The signature of a pretty-printed file: somebody ran a formatter over
    /// JSON Lines and every record became several lines of one.
    pub incomplete_interior_lines: u64,
    /// The stream, as read so far, stops in the middle of a line.
    ///
    /// Never charged to [`Self::malformed_lines`], and this is the counter that
    /// difference exists for: a collector that flushes on a timer leaves a
    /// partial line most of the time, so calling it corruption would make every
    /// tail read look like an incident. Counted once per partial line rather
    /// than once per read, for the same reason.
    pub unterminated_final_line: u64,
    /// Empty, or only spaces and tabs. Skipped, and the line number still
    /// advances so a position still matches what an operator sees in an editor.
    pub blank_lines: u64,
    /// A UTF-8 byte-order mark was present at offset zero and skipped. One,
    /// there, and nowhere else: anywhere else it is bytes inside a line.
    pub leading_bom: bool,
    /// Chunks refused because the queue was full.
    ///
    /// Not yet a loss, and the last moment at which an operator can act before
    /// it becomes one: the bytes were not read, so they are still the caller's,
    /// but a live file that rotates while the reader is stalled takes them with
    /// it. Charged as a loss for that reason.
    pub queue_full_stops: u64,
    /// Lines whose records went in without their clock being compared with ours,
    /// because the file is an archive.
    ///
    /// A diagnostic and never a loss. Assessing skew against an archive is what
    /// produces an anomaly record that is true of the reader and false of the
    /// fleet; counting the omission is what stops the omission from being
    /// invisible.
    pub skew_not_assessed: u64,
}

/// Every counter the reader keeps, in one place.
///
/// One struct because [`Self::list`] has to be exhaustive over all four reports
/// at once, and it can only be exhaustive if there is a single place that owns
/// them.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Counters {
    /// What the mapper made of the spans.
    pub mapping: Report,
    /// What the framing and the grammar made of the lines.
    pub lines: LineReport,
    /// What a decode had to leave out.
    pub dropped: Dropped,
    /// What the lines' shape was, as opposed to what they said.
    pub shape: ShapeReport,
}

impl Counters {
    /// How many counters there are. Six from the mapper, thirteen from the
    /// framing, five from the bounds, thirteen from the shape.
    pub const COUNT: usize = 6 + 13 + 5 + 13;

    /// Every counter, named and classified.
    ///
    /// The four destructurings are exhaustive on purpose and `..` must never
    /// creep into any of them: a counter added to one of these structs and
    /// forgotten here is a counter that never reaches an operator and never
    /// reaches [`Self::anomaly_total`], so it has to be a compile error until
    /// somebody says whether it is a loss or a diagnostic.
    ///
    /// That is not hypothetical. [`crate::source::OtlpSource::anomaly_total`] is
    /// a hand-written sum of seven terms which omits `dropped.invalid_utf8`, so a
    /// batch whose only fault is invalid UTF-8 produces no anomaly record at all
    /// and the loss is visible only to somebody who already suspected it.
    ///
    /// An array and not a `Vec`, for two reasons: the length is a second compile
    /// error for the same omission, and [`Self::anomaly_total`] is asked once per
    /// batch by a caller deciding whether to write a record, which is not a
    /// question that should allocate.
    pub fn list(&self) -> [Counter; Self::COUNT] {
        let Report {
            mapped,
            not_genai,
            unknown_operation,
            no_run_id,
            no_agent,
            excessive_skew,
        } = self.mapping;
        let LineReport {
            malformed_lines,
            oversize_lines,
            too_deep,
            duplicate_members,
            lone_surrogates,
            bad_encoding,
            concatenated_values,
            incomplete_interior_lines,
            unterminated_final_line,
            blank_lines,
            leading_bom,
            queue_full_stops,
            skew_not_assessed,
        } = self.lines;
        let Dropped {
            spans,
            attributes,
            events,
            oversize_values,
            invalid_utf8,
        } = self.dropped;
        let ShapeReport {
            unknown_members,
            snake_case_keys,
            not_traces_data,
            wrong_signal,
            bare_resource_spans,
            empty_batches,
            bad_ids,
            bad_types,
            bad_numbers,
            double_overflow,
            nonfinite_doubles,
            bad_base64,
            multi_valued_anyvalue,
        } = self.shape;

        use Class::{Diagnostic, Loss};
        [
            // What the mapper made of the spans. `mapped` is the successes and
            // `not_genai` is traffic that was never ours: a database span in the
            // same file is not a loss.
            counter("mapped", mapped, Diagnostic),
            counter("not_genai", not_genai, Diagnostic),
            counter("unknown_operation", unknown_operation, Loss),
            counter("no_run_id", no_run_id, Loss),
            counter("no_agent", no_agent, Loss),
            // Not a lost record: the record is written with both times. It is
            // still a loss of the one thing an audit trail is ordered by.
            counter("excessive_clock_skew", excessive_skew, Loss),
            // The total, and then the subclasses that explain it. Only the total
            // is a loss, or every refused line would be counted twice.
            counter("malformed_lines", malformed_lines, Loss),
            counter("oversize_lines", oversize_lines, Diagnostic),
            counter("too_deep", too_deep, Diagnostic),
            counter("duplicate_members", duplicate_members, Diagnostic),
            counter("lone_surrogates", lone_surrogates, Diagnostic),
            counter("bad_encoding", bad_encoding, Diagnostic),
            counter("concatenated_values", concatenated_values, Diagnostic),
            counter(
                "incomplete_interior_lines",
                incomplete_interior_lines,
                Diagnostic,
            ),
            counter(
                "unterminated_final_line",
                unterminated_final_line,
                Diagnostic,
            ),
            counter("blank_lines", blank_lines, Diagnostic),
            counter("leading_bom", u64::from(leading_bom), Diagnostic),
            counter("queue_full_stops", queue_full_stops, Loss),
            counter("skew_not_assessed", skew_not_assessed, Diagnostic),
            // Everything a bound cost. Each one is a span, an attribute or a
            // value that a record does not have.
            counter("dropped_spans", spans, Loss),
            counter("dropped_attributes", attributes, Loss),
            counter("dropped_events", events, Loss),
            counter("oversize_values", oversize_values, Loss),
            // The one `OtlpSource` forgets. This transport cannot charge it at
            // all, because the reader refuses a bad byte before a decoder sees
            // it, and it is listed anyway so the two paths report the same
            // fields and a reader comparing them is not left wondering.
            counter("invalid_utf8", invalid_utf8, Loss),
            // What the lines' shape was. Expected to be non-zero against a newer
            // producer, which is why the first two are diagnostics.
            counter("unknown_members", unknown_members, Diagnostic),
            counter("snake_case_keys", snake_case_keys, Diagnostic),
            // A line that was JSON and not traces data produced no records, and
            // `otel-cli server json` produces a whole file of them. A metrics
            // envelope is the same shape of fault one configuration step
            // earlier: a file of them that reported nothing would read as a file
            // with nothing in it.
            counter("not_traces_data", not_traces_data, Loss),
            counter("wrong_signal", wrong_signal, Loss),
            // Accepted dialects. Counted so nobody mistakes one for the
            // envelope, and an empty batch is a heartbeat rather than a fault.
            counter("bare_resource_spans", bare_resource_spans, Diagnostic),
            counter("empty_batches", empty_batches, Diagnostic),
            // Each of these costs a span or a field of one.
            counter("bad_ids", bad_ids, Loss),
            counter("bad_types", bad_types, Loss),
            counter("bad_numbers", bad_numbers, Loss),
            counter("double_overflow", double_overflow, Loss),
            // `"NaN"` and the infinities are the only way this encoding has to
            // say what they say, so accepting them is not a fault.
            counter("nonfinite_doubles", nonfinite_doubles, Diagnostic),
            counter("bad_base64", bad_base64, Loss),
            // One member of the oneof overwrote another, so a value that was
            // sent is not in the record.
            counter("multi_valued_anyvalue", multi_valued_anyvalue, Loss),
        ]
    }

    /// Everything that has gone wrong, as one number.
    ///
    /// A sum over [`Self::list`] rather than over a hand-written expression, so
    /// the set of terms cannot drift from the set of counters.
    pub fn anomaly_total(&self) -> u64 {
        self.list()
            .iter()
            .filter(|c| c.class == Class::Loss)
            .fold(0u64, |total, c| total.saturating_add(c.value))
    }
}

fn counter(name: &'static str, value: impl Into<u64>, class: Class) -> Counter {
    Counter {
        name,
        value: value.into(),
        class,
    }
}

/// `[profile.test]` turns on overflow checks, so a file with four billion of
/// anything saturates rather than panicking. `accept_chunk` promises not to
/// panic, and a counter is the one thing in here an attacker can drive.
fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// The same, for the counters the decoder and the mapper keep as `u32`.
fn bump_small(counter: &mut u32) {
    *counter = counter.saturating_add(1);
}

#[derive(Debug)]
pub struct JsonlSource {
    cfg: MapperConfig,
    otlp_limits: OtlpLimits,
    json_limits: JsonLimits,
    mode: Mode,
    framer: Framer,
    /// The framer's own cumulative report as of the last time it was read, so
    /// what it counted since can be added rather than assigned. Assignment would
    /// silently stop working the day a second thing writes one of those fields.
    framed: FrameReport,
    pending: VecDeque<Ingest>,
    max_pending: usize,
    next_cursor: u64,
    acked: Cursor,
    counters: Counters,
    anomalies_reported: u64,
    /// Whether the partial line currently held has already been counted.
    tail_noted: bool,
    /// A byte-order mark said this stream is not UTF-8, so nothing more is read.
    stream_refused: bool,
}

impl JsonlSource {
    /// An archive: skew is not assessed.
    pub fn replay(cfg: MapperConfig) -> Self {
        Self::with_limits(
            cfg,
            OtlpLimits::default(),
            JsonLimits::default(),
            Mode::Replay,
        )
    }

    /// A live file: skew is assessed.
    pub fn tail(cfg: MapperConfig) -> Self {
        Self::with_limits(
            cfg,
            OtlpLimits::default(),
            JsonLimits::default(),
            Mode::Tail,
        )
    }

    /// Both sets of bounds: `otlp` bounds what OTLP says, `json` bounds how it is
    /// spelled.
    pub fn with_limits(cfg: MapperConfig, otlp: OtlpLimits, json: JsonLimits, mode: Mode) -> Self {
        Self {
            cfg,
            otlp_limits: otlp,
            json_limits: json,
            mode,
            framer: Framer::new(json),
            framed: FrameReport::default(),
            pending: VecDeque::new(),
            max_pending: DEFAULT_MAX_PENDING,
            next_cursor: 1,
            acked: Cursor(0),
            counters: Counters::default(),
            anomalies_reported: 0,
            tail_noted: false,
            stream_refused: false,
        }
    }

    /// Change the queue bound. Exists so a test can fill the queue with three
    /// records instead of sixty-five thousand.
    ///
    /// Floored at one: a bound of zero would refuse every chunk forever, which is
    /// a stall wearing a configuration's clothes.
    pub fn with_max_pending(mut self, records: usize) -> Self {
        self.max_pending = records.max(1);
        self
    }

    /// Take the next bytes of the file, at any chunk boundary.
    ///
    /// Returns how many records they produced. Never returns an error and never
    /// panics: a producer is told nothing, because there is nobody to tell, and
    /// what became of its bytes is in the counters.
    pub fn accept_chunk(&mut self, chunk: &[u8], recorded_at: Timestamp) -> usize {
        // A stream the framer has refused for its byte-order mark is not readable,
        // so later chunks produce nothing rather than whatever ASCII happens to
        // follow the mark. Both layers latch it, and this one exists because the
        // framer's refusal used to be per chunk: an adversarial review measured
        // the same file behind a UTF-16 mark admitting 0 records at a 64 KiB read
        // and 199 at a two-byte read, while the report said one or two lost lines
        // either way. What reaches an audit store cannot depend on the read size.
        if self.stream_refused {
            return 0;
        }
        // Full queue: the chunk is not read at all, so its bytes are still the
        // caller's and the same chunk can be handed over again after a drain.
        // Reading it anyway is the slow OOM this counter exists to prevent. The
        // bound is on the queue and not on the chunk, so a single chunk's own
        // records can carry the queue over it; peak is `max_pending` plus one
        // chunk's worth, which is why a caller reads in fixed-size pieces.
        if self.pending.len() >= self.max_pending {
            bump(&mut self.counters.lines.queue_full_stops);
            return 0;
        }

        let mut produced = 0usize;
        // The framer travels out and back because `push` borrows it while the
        // callback needs the rest of `self`. A fresh `Framer` allocates nothing,
        // and nothing can observe the one left behind.
        let limits = self.json_limits;
        let mut framer = std::mem::replace(&mut self.framer, Framer::new(limits));
        let outcome = framer.push(chunk, |line| {
            produced += self.take_line(&line, false, recorded_at);
            Ok(())
        });
        self.framer = framer;

        // The callback above never refuses a line, so the only error `push` can
        // return is an encoding it says the stream cannot be. That is about the
        // whole stream rather than one line, and it is charged to the total as
        // well as to its subclass because it produced no records and something
        // has to be visible.
        if let Err(e) = outcome {
            // Charged once for the stream, not once per chunk, because the latch
            // stops the caller ever getting here again.
            self.stream_refused = matches!(e.kind, Kind::Encoding(_));
            self.note_refusal(e, false);
        }
        self.absorb_framing();
        self.note_tail();
        produced
    }

    /// End of stream: the file ends here.
    ///
    /// An inherent method and not part of [`Source`], which is frozen and has no
    /// `close`. Adding one would be a breaking change for every adapter in the
    /// tree, and the reason there is a trait at all is that adapters can be added
    /// without touching it.
    ///
    /// A held partial line is a complete line with no terminator, so it is read
    /// here. If it ends mid-value it is the producer's flush and not corruption,
    /// and [`LineReport::malformed_lines`] is not charged.
    pub fn finish(&mut self, recorded_at: Timestamp) -> usize {
        // A refusal already charged is not charged again. Both layers latch the
        // mark, so `Framer::finish` reports the same refusal a chunk already
        // reported, and counting it twice would make the one number an operator
        // reads about a whole stream say two.
        if self.stream_refused {
            return 0;
        }
        let mut produced = 0usize;
        let limits = self.json_limits;
        let mut framer = std::mem::replace(&mut self.framer, Framer::new(limits));
        let outcome = framer.finish(|line| {
            produced += self.take_line(&line, true, recorded_at);
            Ok(())
        });
        self.framer = framer;

        match outcome {
            // The stream stopped in the middle of a line, and nothing has said so
            // yet: an oversize line discarded to a newline that never came leaves
            // no partial line for `note_tail` to have seen.
            Ok(true) if !self.tail_noted => {
                bump(&mut self.counters.lines.unterminated_final_line);
            }
            Ok(_) => {}
            Err(e) => {
                self.stream_refused = matches!(e.kind, Kind::Encoding(_));
                self.note_refusal(e, false);
            }
        }
        // The framer cleared its carry whatever happened, so the next partial
        // line is a new one and gets its own count.
        self.tail_noted = false;
        self.absorb_framing();
        produced
    }

    /// One line: decode it, map its spans, and count whatever it cost.
    ///
    /// `final_line` is true only for the line [`Framer::finish`] hands over,
    /// which is the one that may legitimately end mid-value.
    fn take_line(&mut self, line: &Line<'_>, final_line: bool, recorded_at: Timestamp) -> usize {
        let decoded =
            match decode_traces_data(line.bytes, self.otlp_limits, self.json_limits, line.number) {
                Ok(decoded) => decoded,
                Err(e) => {
                    self.note_refusal(e, final_line);
                    return 0;
                }
            };
        self.merge_shape(decoded.shape);
        self.merge_dropped(decoded.request.dropped);
        if self.mode == Mode::Replay {
            // One per line read, so the number an operator sees is the number of
            // lines that went in with nobody checking their clock. In `Tail` the
            // comparison happens below instead.
            bump(&mut self.counters.lines.skew_not_assessed);
        }

        let mut produced = 0usize;
        for resource_spans in &decoded.request.resource_spans {
            for scope in &resource_spans.scopes {
                for span in &scope.spans {
                    // Minted, not consumed: the cursor advances only if a record
                    // came of it, so the sequence stays dense from 1 and a
                    // refused span leaves no hole for a resume to skip over.
                    let cursor = Cursor(self.next_cursor);
                    match map_span(
                        &self.cfg,
                        &resource_spans.resource,
                        &scope.scope_name,
                        span,
                        cursor,
                    ) {
                        Ok(ingest) => {
                            self.next_cursor = self.next_cursor.saturating_add(1);
                            bump_small(&mut self.counters.mapping.mapped);
                            // Both clocks are known here and nowhere else, so
                            // this is where a disagreement can be noticed at all.
                            // The record is kept either way: an event with a bad
                            // clock is still evidence, as long as nobody is told
                            // the clock was fine.
                            if self.mode == Mode::Tail
                                && assess_skew(ingest.meta.occurred_at, recorded_at).is_excessive()
                            {
                                bump_small(&mut self.counters.mapping.excessive_skew);
                            }
                            self.pending.push_back(ingest);
                            produced += 1;
                        }
                        Err(rejection) => self.counters.mapping.note(rejection),
                    }
                }
            }
        }
        produced
    }

    /// Charge a refusal to the total and, where it has one, to the subclass that
    /// names the producer to fix.
    fn note_refusal(&mut self, error: JsonError, final_line: bool) {
        let lines = &mut self.counters.lines;
        let mid_write = matches!(
            error.kind,
            Kind::Syntax(Syntax::UnexpectedEof) | Kind::Encoding(Encoding::IncompleteUtf8)
        );
        if final_line && mid_write {
            // The normal state of a file a collector flushes on a timer. Already
            // counted as an unterminated tail, and deliberately not counted as
            // malformed: a tail read that reported corruption every second would
            // train an operator to ignore the counter that means it.
            //
            // `IncompleteUtf8` belongs here for the same reason and was missing.
            // A flush can land inside a multi-byte character as easily as between
            // two members, and an adversarial review measured 19 of 299 truncation
            // points of one Ukrainian-language line each producing a warning record
            // claiming a lost line. Nothing was lost either time; only the byte the
            // producer stopped on differs. On a line that is NOT last, a truncated
            // character before a terminator is real corruption and still counts.
            return;
        }
        match error.kind {
            Kind::Syntax(Syntax::UnexpectedEof) => bump(&mut lines.incomplete_interior_lines),
            Kind::Syntax(Syntax::TrailingContent) => bump(&mut lines.concatenated_values),
            Kind::Syntax(Syntax::DuplicateName) => bump(&mut lines.duplicate_members),
            Kind::Syntax(Syntax::LoneSurrogate) => bump(&mut lines.lone_surrogates),
            Kind::Encoding(_) => bump(&mut lines.bad_encoding),
            Kind::Limit(Bound::Depth) => bump(&mut lines.too_deep),
            // The framer refuses an oversize line on bytes read and hands it to
            // nobody, so it is counted through `absorb_framing` and cannot arrive
            // here. Named rather than left to the wildcard, so the day a reader
            // does return it, this arm is where somebody looks.
            Kind::Limit(Bound::LineTooLong) => {}
            // A number too long and an object with too many members have no
            // subclass of their own. They are bounds rather than producer
            // signatures, and a counter per constant would be a counter nobody
            // reads.
            Kind::Limit(_) | Kind::Syntax(_) => {}
        }
        bump(&mut lines.malformed_lines);
    }

    /// Take over what the framer counted since it was last asked.
    fn absorb_framing(&mut self) {
        let now = self.framer.report();
        let FrameReport {
            blank_lines,
            oversize_lines,
            leading_bom,
        } = now;
        let lines = &mut self.counters.lines;
        let refused = oversize_lines.saturating_sub(self.framed.oversize_lines);
        lines.oversize_lines = lines.oversize_lines.saturating_add(refused);
        // An oversize line is a line that produced nothing, so it is a loss and
        // has to reach the total. The subclass above only says which loss it was.
        lines.malformed_lines = lines.malformed_lines.saturating_add(refused);
        lines.blank_lines = lines
            .blank_lines
            .saturating_add(blank_lines.saturating_sub(self.framed.blank_lines));
        lines.leading_bom = leading_bom;
        self.framed = now;
    }

    /// Notice that the stream, as read so far, stops in the middle of a line.
    ///
    /// Once per partial line and not once per read. A collector that flushes on a
    /// timer leaves a partial line most of the time, so a counter that grew with
    /// every poll would report thousands of faults for a file that is merely
    /// being appended to.
    fn note_tail(&mut self) {
        if self.framer.carried() == 0 {
            self.tail_noted = false;
        } else if !self.tail_noted {
            self.tail_noted = true;
            bump(&mut self.counters.lines.unterminated_final_line);
        }
    }

    /// Destructured so a field added to [`ShapeReport`] is a compile error here
    /// rather than a counter that silently stays at zero.
    fn merge_shape(&mut self, other: ShapeReport) {
        let ShapeReport {
            unknown_members,
            snake_case_keys,
            not_traces_data,
            wrong_signal,
            bare_resource_spans,
            empty_batches,
            bad_ids,
            bad_types,
            bad_numbers,
            double_overflow,
            nonfinite_doubles,
            bad_base64,
            multi_valued_anyvalue,
        } = other;
        let into = &mut self.counters.shape;
        into.unknown_members = into.unknown_members.saturating_add(unknown_members);
        into.snake_case_keys = into.snake_case_keys.saturating_add(snake_case_keys);
        into.not_traces_data = into.not_traces_data.saturating_add(not_traces_data);
        into.wrong_signal = into.wrong_signal.saturating_add(wrong_signal);
        into.bare_resource_spans = into.bare_resource_spans.saturating_add(bare_resource_spans);
        into.empty_batches = into.empty_batches.saturating_add(empty_batches);
        into.bad_ids = into.bad_ids.saturating_add(bad_ids);
        into.bad_types = into.bad_types.saturating_add(bad_types);
        into.bad_numbers = into.bad_numbers.saturating_add(bad_numbers);
        into.double_overflow = into.double_overflow.saturating_add(double_overflow);
        into.nonfinite_doubles = into.nonfinite_doubles.saturating_add(nonfinite_doubles);
        into.bad_base64 = into.bad_base64.saturating_add(bad_base64);
        into.multi_valued_anyvalue = into
            .multi_valued_anyvalue
            .saturating_add(multi_valued_anyvalue);
    }

    /// See [`Self::merge_shape`].
    fn merge_dropped(&mut self, other: Dropped) {
        let Dropped {
            spans,
            attributes,
            events,
            oversize_values,
            invalid_utf8,
        } = other;
        let into = &mut self.counters.dropped;
        into.spans = into.spans.saturating_add(spans);
        into.attributes = into.attributes.saturating_add(attributes);
        into.events = into.events.saturating_add(events);
        into.oversize_values = into.oversize_values.saturating_add(oversize_values);
        into.invalid_utf8 = into.invalid_utf8.saturating_add(invalid_utf8);
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn report(&self) -> &Report {
        &self.counters.mapping
    }

    pub fn line_report(&self) -> &LineReport {
        &self.counters.lines
    }

    pub fn dropped(&self) -> Dropped {
        self.counters.dropped
    }

    pub fn shape(&self) -> &ShapeReport {
        &self.counters.shape
    }

    /// Every counter, named and classified. What the anomaly record is made of.
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Whether anything went wrong that has not yet been written down.
    pub fn has_unreported_anomaly(&self) -> bool {
        self.counters.anomaly_total() > self.anomalies_reported
    }

    /// Turn everything that went wrong so far into a record.
    ///
    /// An audit trail with a hole in it and no note about the hole is worse than
    /// one that admits it, because the first looks complete. The event type and
    /// the severity are the part that survives erasure; the breakdown is payload,
    /// because it counts things that were about somebody.
    ///
    /// Returns `None` when nothing has gone wrong since the last call.
    ///
    /// # Four deliberate differences from `OtlpSource::anomaly_event`
    ///
    /// Three of them are defects that file carries. Each is marked where it
    /// happens below, and they are: the total is a sum over
    /// [`Counters::list`] rather than a hand-written expression that has already
    /// lost a term; both identifiers are built before the watermark moves; the
    /// record's `mapper` is [`MapperVersion::UNMAPPED`]; and the cursor is
    /// `Cursor(0)`.
    pub fn anomaly_event(&mut self, recorded_at: Timestamp) -> Option<Ingest> {
        if !self.has_unreported_anomaly() {
            return None;
        }
        // Difference 1: the total and the breakdown come from the same
        // exhaustively destructured list, so neither can lose a term without a
        // compile error. `OtlpSource::anomaly_total` adds seven fields by hand out
        // of the eight it has, and the one it leaves out is `dropped.invalid_utf8`:
        // a batch whose only fault is bytes that are not UTF-8 produces no anomaly
        // record there at all.
        let counters = self.counters.list();
        let total = self.counters.anomaly_total();
        let since = total.saturating_sub(self.anomalies_reported);

        // Difference 2: both identifiers first, and only then the watermark.
        // `OtlpSource` assigns the watermark and then `?`s on construction, so a
        // trust domain that is too long once the anomaly agent's longer path is
        // appended discards the whole report and reports it as nothing to report.
        let run_id = RunId::parse(format!("jsonl-anomalies-{total}")).ok()?;
        // The trust domain comes from configuration and never from the wire, so
        // this identifier cannot be influenced by a line.
        let agent_id = AgentId::parse_strict(format!(
            "agent://{}/trailryx.jsonl",
            self.cfg.trust_domain()
        ))
        .ok()?;
        self.anomalies_reported = total;

        let mut detail = format!("anomalies_since_last\t{since}\n");
        for c in &counters {
            detail.push_str(c.name);
            detail.push('\t');
            detail.push_str(&c.value.to_string());
            detail.push('\n');
        }
        // Which file this was, in the only sense that is not a path: whether the
        // clocks were compared at all.
        detail.push_str(&format!("mode\t{}\n", self.mode.as_str()));
        // The version the *records* were mapped under, which is not the version
        // of this record. See the `mapper` field below.
        detail.push_str(&format!("mapper_version\t{}\n", MAPPER_VERSION.0));

        Some(Ingest {
            meta: MetaDraft {
                // Difference 3: no mapper touched this record. `MetaDraft::mapper`
                // says a record made by the store about itself is `UNMAPPED`, and
                // `source.rs` stamps `MAPPER_VERSION` on one anyway, which claims
                // a reading of the GenAI conventions was applied to a row of
                // counters.
                mapper: MapperVersion::UNMAPPED,
                tenant: self.cfg.tenant().clone(),
                agent_id,
                run_id,
                parent_run_id: None,
                on_behalf_of: Vec::new(),
                // The store speaking about itself, so for once the clock is ours
                // and the "untrusted" wrapper is a formality the type system
                // still insists on. Better a wrapper we do not need than a field
                // that can be filled from the wire.
                occurred_at: Untrusted::new(recorded_at),
                decided_at: None,
                event_type: EventType::StoreEvent,
                severity: Severity::Warning,
                basis: Basis::default(),
                verdict: Some(Verdict::Failed),
                error: None,
                latency_micros: None,
                tokens_in: None,
                tokens_out: None,
                cost_micros: None,
            },
            payload: vec![PayloadPart::new(
                PayloadClass::Diagnostic,
                detail.into_bytes(),
            )],
            correlation: None,
            // Difference 4: an anomaly is not a position in the file. `OtlpSource`
            // mints a cursor above every pending record, so acknowledging the
            // anomaly would acknowledge records that have not been drained yet
            // and a resume would start after them.
            cursor: Cursor(0),
        })
    }
}

impl Source for JsonlSource {
    fn descriptor(&self) -> SourceDescriptor {
        SourceDescriptor {
            name: "otlp/traces+jsonl",
            // The times are the producer's, written into a file the producer
            // owns. Nothing here proves either of them, and the conformance
            // suite requires the honest answer unconditionally.
            clock_trust: Trust::Untrusted,
            // The agent comes from `service.name`, an attribute the producer
            // chose. The trust domain around it is ours; nothing inside it is.
            identity_trust: Trust::Untrusted,
            // A file can be read twice, a rotated file can be read again under
            // its new name, and nothing in the format identifies a line.
            delivery: Delivery::AtLeastOnce,
            // The JSON Lines specification disclaims ordering outright, and OTLP
            // exports a span when it ends, so a child is written before its
            // parent as a matter of course.
            ordering: Ordering::Unordered,
        }
    }

    fn poll(&mut self, budget: usize) -> AdapterResult<Vec<Ingest>> {
        let take = budget.min(self.pending.len());
        Ok(self.pending.drain(..take).collect())
    }

    fn ack(&mut self, cursor: Cursor) -> AdapterResult<()> {
        // Idempotent, and never a rewind: an older cursor is a repeat of
        // something already settled, not an instruction to reopen it.
        if cursor > self.acked {
            self.acked = cursor;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counter_list_names_every_field_and_the_names_are_distinct() {
        let counters = Counters::default();
        let list = counters.list();
        let mut names: Vec<&str> = list.iter().map(|c| c.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), list.len(), "two counters share a name");
        assert!(list.iter().all(|c| c.value == 0));
        assert_eq!(counters.anomaly_total(), 0);
    }

    #[test]
    fn the_counter_list_covers_all_four_reports() {
        // The names, grouped by the report they came from, so a whole report that
        // stopped being visited fails here rather than shrinking the total in
        // silence. Written out because a count would pass just as happily if two
        // of the four groups traded a field.
        let list = Counters::default().list();
        for group in [
            ["mapped", "not_genai", "unknown_operation"].as_slice(),
            ["malformed_lines", "blank_lines", "skew_not_assessed"].as_slice(),
            ["dropped_spans", "invalid_utf8"].as_slice(),
            ["unknown_members", "bad_ids", "multi_valued_anyvalue"].as_slice(),
        ] {
            for name in group {
                assert!(
                    list.iter().any(|c| c.name == *name),
                    "{name} is not in the list"
                );
            }
        }
        assert_eq!(list.len(), Counters::COUNT);
    }
}
