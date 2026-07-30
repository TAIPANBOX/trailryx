//! OTLP/JSON traces, decoded into exactly what the protobuf reader produces.
//!
//! The twin of [`crate::otlp`], function for function, and meant to be read
//! beside it. Same message names, same field order, same bounds charged to the
//! same counters, same output type. Where the two files differ, the difference
//! is the encoding and nothing else, and a reviewer should be able to point at
//! each one.
//!
//! # What OTLP/JSON is, and what it is not
//!
//! It is proto3's JSON mapping with one override. The rules that bite are the
//! ones the wire reader never has to think about:
//!
//! - **Member names are lowerCamelCase.** `traceId`, never `trace_id`. A name
//!   spelled the way the `.proto` file spells it is not a valid key, and it is
//!   counted apart from other unknown members because the producer that writes
//!   `trace_id` also writes base64 ids: it is not a newer OTLP, it is a
//!   different encoding wearing the same shape.
//! - **A trace or span id is hex, not base64.** This is the override. Exactly 32
//!   and 16 characters, either case. Everything else typed `bytes`,
//!   `bytesValue` included, stays base64.
//! - **A 64-bit integer is a decimal string or a JSON number.** Both are legal
//!   and real emitters send both, so a decoder that reads one of them loses
//!   whole fields from half the collectors in the world.
//! - **`NaN` and the infinities are quoted words**, because JSON has no literal
//!   for them and this crate's reader refuses the bare ones.
//! - **An enum is an integer.** Proto3 JSON also permits the name; that spelling
//!   is refused here, and the reason is written down at `enum_member` below.
//!
//! # Nothing an emitter can write refuses a line
//!
//! Only the grammar refuses. An unknown member, a member of the wrong JSON type,
//! an id that is not hex, a number that does not fit, base64 that is not base64:
//! each of those loses one field or at worst one span, is counted, and the rest
//! of the batch still becomes records. The store is fail-open towards an
//! emitter's traffic for the same reason the wire reader is, and a loss becomes a
//! number an operator can see rather than a silence.
//!
//! The one exception is an id, and it goes the other way. A span whose
//! `parentSpanId` cannot be read is **dropped**, not stored with the field
//! defaulted, because a defaulted parent is a *claim*: `Span::has_parent` would
//! then say the span is a root and `semconv` would map a Delegation as a
//! RequestReceived. That is the defect `MAPPER_VERSION` 2 was cut for and it must
//! not come back through a second transport.
//!
//! # The three dialects this meets in the wild
//!
//! - the canonical envelope, `{"resourceSpans":[...]}`, from any collector
//!   configured for `application/json`;
//! - a **bare** `ResourceSpans`, with `resource` and `scopeSpans` at the top
//!   level, which otel-java's `OtlpJsonLoggingSpanExporter` writes deliberately,
//!   one per line. Accepted, and counted so that nobody mistakes it for the
//!   envelope;
//! - `otel-cli server json`, which writes snake_case names and base64 ids.
//!   Accepted as a line and understood as nothing: every member is skipped and
//!   the counters say why. Half-reading it would produce records with no trace
//!   id, which is worse than producing none.
//!
//! A metrics or logs envelope is reported as the wrong signal rather than as a
//! fault, because an exporter pointed at the traces endpoint is a configuration
//! problem and an operator needs to be told which problem they have.

use crate::otlp::{
    Attr, Dropped, Event, Limits, ResourceSpans, ScopeSpans, Span, SpanKind, StatusCode,
    TraceRequest, Value, lossy_string, push_attr,
};
use trailryx_json::{Event as JsonEvent, JsonError, JsonResult, Reader};

/// The bounds on the JSON grammar itself: depth, number length, members in one
/// object, bytes in one line. Separate from [`Limits`], which bounds what OTLP
/// says rather than how it is spelled.
pub use trailryx_json::Limits as JsonLimits;

/// A `traceId` is 16 bytes and OTLP fixes its JSON spelling at 32 hex
/// characters. Not "at most": an id of some other length is not a short id, it is
/// a different encoding, and the one that turns up is base64.
const TRACE_ID_CHARS: usize = 32;

/// A `spanId` and a `parentSpanId` are 8 bytes, so 16 characters.
const SPAN_ID_CHARS: usize = 16;

/// What the line's shape was, as opposed to what it said.
///
/// Every counter here is something an operator can act on: fix a producer, raise
/// a bound, or point an exporter at the right endpoint. None of them is an error,
/// and a line that scores on any of them is still a line that was read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShapeReport {
    /// Members skipped because this version does not act on them. Expected to be
    /// non-zero against a newer producer, and worth watching all the same: it is
    /// the measure of how much of each line we understood.
    pub unknown_members: u32,
    /// Members named the way the `.proto` file names them. Counted apart from the
    /// rest because it identifies the producer rather than a version skew.
    pub snake_case_keys: u32,
    /// Lines that were valid JSON and not a traces envelope at all.
    pub not_traces_data: u32,
    /// Lines that were a metrics or logs envelope.
    pub wrong_signal: u32,
    /// Lines that were a bare `ResourceSpans` rather than the envelope.
    pub bare_resource_spans: u32,
    /// Traces envelopes that carried no spans. A heartbeat, not a fault.
    pub empty_batches: u32,
    /// Ids present and not hex of the length OTLP fixes. Each one costs a span.
    pub bad_ids: u32,
    /// Known members whose JSON type is not their field's. The member is
    /// abandoned and the field keeps proto3's default.
    pub bad_types: u32,
    /// 64-bit fields out of range, not integral, or neither a string nor a
    /// number.
    pub bad_numbers: u32,
    /// Finite `doubleValue` literals too large for the type. Refused rather than
    /// stored as infinity, because storing infinity for a number the emitter
    /// wrote out in full would be a repair.
    pub double_overflow: u32,
    /// `doubleValue` written as `"NaN"`, `"Infinity"` or `"-Infinity"`. Accepted,
    /// because those words are the only way this encoding has to say it.
    pub nonfinite_doubles: u32,
    /// `bytesValue` strings that were not base64 in either alphabet.
    pub bad_base64: u32,
    /// `AnyValue` objects with more than one of the oneof's members set.
    pub multi_valued_anyvalue: u32,
}

impl ShapeReport {
    /// Every counter, named, for a report or an assertion.
    ///
    /// The destructuring is exhaustive on purpose and `..` is not allowed to
    /// creep into it: a counter added to the struct and forgotten here is a
    /// counter that never reaches an operator, so it has to be a compile error
    /// until somebody says what it is called.
    pub fn counters(&self) -> [(&'static str, u32); 13] {
        let Self {
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
        } = *self;
        [
            ("unknown_members", unknown_members),
            ("snake_case_keys", snake_case_keys),
            ("not_traces_data", not_traces_data),
            ("wrong_signal", wrong_signal),
            ("bare_resource_spans", bare_resource_spans),
            ("empty_batches", empty_batches),
            ("bad_ids", bad_ids),
            ("bad_types", bad_types),
            ("bad_numbers", bad_numbers),
            ("double_overflow", double_overflow),
            ("nonfinite_doubles", nonfinite_doubles),
            ("bad_base64", bad_base64),
            ("multi_valued_anyvalue", multi_valued_anyvalue),
        ]
    }
}

/// One decoded OTLP/JSON line, and what its shape was.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    /// The same type the wire reader returns. Nothing downstream of here can
    /// tell which transport the batch arrived on, which is the whole point.
    pub request: TraceRequest,
    pub shape: ShapeReport,
}

/// The three things every function below needs and neither the reader nor the
/// output type carries: the bounds, what they cost, and what the shape was.
///
/// The wire reader passes `limits`, `dropped` and `spans_so_far` one at a time.
/// Here there is a fourth, so they travel together and the twin signatures stay
/// short enough to compare.
#[derive(Debug)]
struct Ctx {
    limits: Limits,
    dropped: Dropped,
    shape: ShapeReport,
    spans_so_far: usize,
    /// How many OTLP messages deep we are, counted exactly as the wire reader
    /// counts them, and bounded by exactly the same number.
    ///
    /// This is where the parity between the two transports lives, and it lives
    /// here because it cannot live in the JSON reader's container bound. The wire
    /// charges 2 containers-worth per `arrayValue` level and 3 per `kvlistValue`
    /// level; the JSON spelling charges 3 and 4. Two different ratios, so a single
    /// container bound cannot match a message bound for every mix of the two, and
    /// an adversarial review measured the old derivation failing in both
    /// directions at once: a resource attribute nested two array and three map
    /// levels was refused on the wire and accepted here, and a span attribute
    /// nested four array and one map level was accepted on the wire and refused
    /// here. Two transports that disagree about which lines become records are
    /// two stores.
    msg_depth: usize,
    /// The line, for an error a caller can locate.
    line_no: u64,
}

impl Ctx {
    /// Read one nested OTLP message, charging it against [`protobuf::MAX_DEPTH`].
    ///
    /// One call per message the wire reader would open with `Reader::nested`:
    /// `ResourceSpans`, `Resource`, `ScopeSpans`, `InstrumentationScope`, `Span`,
    /// `Event`, `Status`, `KeyValue`, `AnyValue`, `ArrayValue`, `KeyValueList`.
    /// Miss one and the two transports drift apart again, silently, in whichever
    /// direction the missed message points.
    ///
    /// The depth is not restored on the error path, and that is deliberate rather
    /// than sloppy: a refusal abandons the whole line, so there is nothing left to
    /// be at the wrong depth for.
    fn message<T>(
        &mut self,
        at: usize,
        f: impl FnOnce(&mut Ctx) -> JsonResult<T>,
    ) -> JsonResult<T> {
        self.msg_depth += 1;
        if self.msg_depth > crate::protobuf::MAX_DEPTH {
            return Err(JsonError::limit(
                trailryx_json::Bound::Depth,
                self.line_no,
                at as u64,
            ));
        }
        let out = f(self)?;
        self.msg_depth -= 1;
        Ok(out)
    }
}

/// Every counter is a `u32` and `[profile.test]` turns on overflow checks, so a
/// line with four billion of anything saturates rather than panicking.
fn bump(counter: &mut u32) {
    *counter = counter.saturating_add(1);
}

/// Decode one line of OTLP/JSON `TracesData`.
///
/// `limits` bounds what OTLP says and is the same value the wire path uses.
/// `json` bounds how it is spelled. `line_no` is carried into any error, because
/// a refusal an operator cannot locate is a refusal they cannot fix.
///
/// An `Err` means the bytes were not JSON, or were JSON past a bound. Every other
/// disagreement with the encoding is in the [`ShapeReport`].
pub fn decode_traces_data(
    line: &[u8],
    limits: Limits,
    json: JsonLimits,
    line_no: u64,
) -> Result<Decoded, JsonError> {
    let mut cx = Ctx {
        limits,
        dropped: Dropped::default(),
        shape: ShapeReport::default(),
        spans_so_far: 0,
        msg_depth: 0,
        line_no,
    };
    let mut r = Reader::new(line, json, line_no);
    let mut resource_spans = Vec::new();
    // Where the bare dialect's members go. Built whether or not it turns out to
    // be that dialect, because the members arrive before the answer does.
    let mut bare = ResourceSpans {
        resource: Vec::new(),
        scopes: Vec::new(),
    };
    let mut saw_envelope = false;
    let mut saw_bare = false;
    let mut saw_other_signal = false;
    let mut members: u32 = 0;

    let top = r.value()?;
    let is_object = matches!(top, JsonEvent::ObjectStart);
    if is_object {
        while let Some(name) = r.next_name()? {
            members = members.saturating_add(1);
            match name.as_ref() {
                "resourceSpans" => {
                    saw_envelope = true;
                    if opens_array(&mut r, &mut cx)? {
                        while r.next_element()? {
                            if opens_object(&mut r, &mut cx)? {
                                resource_spans.push(decode_resource_spans(&mut r, &mut cx)?);
                            }
                        }
                    }
                }
                // Recognised so that a misconfigured exporter is a sentence and
                // not a shrug. Never read: a metric is not a span and there is
                // nothing here that could hold one.
                "resourceMetrics" | "resourceLogs" => {
                    saw_other_signal = true;
                    unrecognised(&name, &mut r, &mut cx)?;
                }
                other => {
                    if resource_spans_member(other, &mut r, &mut cx, &mut bare)? {
                        saw_bare = true;
                    } else {
                        unrecognised(other, &mut r, &mut cx)?;
                    }
                }
            }
        }
    } else {
        r.skip_rest(&top)?;
    }
    let stats = r.finish()?;

    // A line that carried both dialects at once is nobody's output and is still
    // not a reason to lose spans, so the bare part is appended rather than
    // discarded and the counter says it was there.
    if saw_bare {
        bump(&mut cx.shape.bare_resource_spans);
        resource_spans.push(bare);
    }
    // `unrecognised` has been counting as it went, per element for an array so that
    // the figure matches the wire's tag-per-element. The reader's own tally counts
    // members instead, which is the right answer to a different question, so it is
    // deliberately not used here. It is still worth having: a gap between the two is
    // exactly how many repeated unknown fields a producer sent.
    let _ = stats;
    let request = TraceRequest {
        resource_spans,
        dropped: cx.dropped,
        // JSON has no varints to pad. Zero and not absent, so a caller
        // aggregating both transports adds up the same fields either way.
        padded_varints: 0,
        unknown_fields: cx.shape.unknown_members,
    };

    // The classification, in one place and only once the whole line has been
    // seen. Member order is not a shape: JSON fixes no order, so deciding from
    // the first member would give two documents with the same members two
    // different answers depending on which one the producer wrote first.
    if !is_object {
        bump(&mut cx.shape.not_traces_data);
    } else if saw_envelope || saw_bare {
        if request.span_count() == 0 {
            bump(&mut cx.shape.empty_batches);
        }
    } else if members == 0 {
        // `{}` is a batch with nothing in it, which a collector with an empty
        // queue does send. Not traces data would be the wrong answer: it is
        // traces data and it is empty.
        bump(&mut cx.shape.empty_batches);
    } else if saw_other_signal {
        bump(&mut cx.shape.wrong_signal);
    } else {
        bump(&mut cx.shape.not_traces_data);
    }

    Ok(Decoded {
        request,
        shape: cx.shape,
    })
}

/// One member of a `ResourceSpans`, wherever that object appears.
///
/// Returns whether the name was one of them. The bare dialect puts these two
/// members at the top level, so the same two arms serve both places: two copies
/// of them would be two things a reviewer has to check still agree.
fn resource_spans_member(
    name: &str,
    r: &mut Reader<'_>,
    cx: &mut Ctx,
    into: &mut ResourceSpans,
) -> JsonResult<bool> {
    match name {
        "resource" => {
            if opens_object(r, cx)? {
                into.resource = decode_resource(r, cx)?;
            }
        }
        "scopeSpans" => {
            if opens_array(r, cx)? {
                while r.next_element()? {
                    if opens_object(r, cx)? {
                        into.scopes.push(decode_scope_spans(r, cx)?);
                    }
                }
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// The object is already open; this drives it to its closing brace.
///
/// Every `decode_*` below takes the same contract, which is the JSON shape of the
/// wire reader's "here is a submessage, read it to the end".
fn decode_resource_spans(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<ResourceSpans> {
    // One OTLP message: ResourceSpans. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut out = ResourceSpans {
            resource: Vec::new(),
            scopes: Vec::new(),
        };
        while let Some(name) = r.next_name()? {
            // `schemaUrl` lands here: a version marker for the attribute names, not
            // data about the run, and stage 6 work we do not do yet.
            if !resource_spans_member(&name, r, cx, &mut out)? {
                unrecognised(&name, r, cx)?;
            }
        }
        Ok(out)
    })
}

fn decode_resource(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Vec<Attr>> {
    // One OTLP message: Resource. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut attrs = Vec::new();
        while let Some(name) = r.next_name()? {
            match name.as_ref() {
                "attributes" => key_values(r, cx, &mut attrs)?,
                _ => unrecognised(&name, r, cx)?,
            }
        }
        Ok(attrs)
    })
}

fn decode_scope_spans(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<ScopeSpans> {
    // One OTLP message: ScopeSpans. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut scope_name = String::new();
        let mut scope_version = String::new();
        let mut spans = Vec::new();
        while let Some(name) = r.next_name()? {
            match name.as_ref() {
                "scope" => {
                    if opens_object(r, cx)? {
                        let (name, version) = decode_scope(r, cx)?;
                        scope_name = name;
                        scope_version = version;
                    }
                }
                "spans" => {
                    if !opens_array(r, cx)? {
                        continue;
                    }
                    while r.next_element()? {
                        // The bound is charged before the span is read and against
                        // the whole batch, not this scope, exactly as on the wire.
                        if cx.spans_so_far >= cx.limits.max_spans {
                            bump(&mut cx.dropped.spans);
                            discard(r)?;
                            continue;
                        }
                        if !opens_object(r, cx)? {
                            continue;
                        }
                        if let Some(span) = decode_span(r, cx)? {
                            spans.push(span);
                            cx.spans_so_far += 1;
                        }
                    }
                }
                _ => unrecognised(&name, r, cx)?,
            }
        }
        Ok(ScopeSpans {
            scope_name,
            scope_version,
            spans,
        })
    })
}

fn decode_scope(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<(String, String)> {
    // One OTLP message: InstrumentationScope. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut name = String::new();
        let mut version = String::new();
        while let Some(member) = r.next_name()? {
            match member.as_ref() {
                "name" => {
                    if let Some(text) = string_member(r, cx)? {
                        name = text;
                    }
                }
                "version" => {
                    if let Some(text) = string_member(r, cx)? {
                        version = text;
                    }
                }
                _ => unrecognised(&member, r, cx)?,
            }
        }
        Ok((name, version))
    })
}

/// `None` when the span must not be stored at all.
///
/// The one divergence from the wire twin's signature, and it is the reason this
/// file exists: on the wire an id is bytes and there is nothing to misread, while
/// in JSON an id is text that can be *almost* right. A span whose id text could
/// not be read is dropped rather than stored with the field defaulted, because
/// `has_parent` reads a defaulted parent as "this is a root" and the mapper turns
/// that into a different event type.
fn decode_span(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Option<Span>> {
    // One OTLP message: Span. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut span = Span {
            trace_id: Vec::new(),
            span_id: Vec::new(),
            parent_span_id: Vec::new(),
            name: String::new(),
            kind: SpanKind::Unspecified,
            start_time_unix_nano: 0,
            end_time_unix_nano: 0,
            attributes: Vec::new(),
            events: Vec::new(),
            status_code: StatusCode::Unset,
            status_message: String::new(),
        };
        let mut unreadable_id = false;

        while let Some(name) = r.next_name()? {
            match name.as_ref() {
                "traceId" => match id_member(r, cx, TRACE_ID_CHARS)? {
                    Some(bytes) => span.trace_id = bytes,
                    None => unreadable_id = true,
                },
                "spanId" => match id_member(r, cx, SPAN_ID_CHARS)? {
                    Some(bytes) => span.span_id = bytes,
                    None => unreadable_id = true,
                },
                // `traceState` lands in the default arm: W3C vendor data, free text
                // by construction, so it has no home in the metadata plane.
                "parentSpanId" => match id_member(r, cx, SPAN_ID_CHARS)? {
                    Some(bytes) => span.parent_span_id = bytes,
                    None => unreadable_id = true,
                },
                "name" => {
                    if let Some(text) = string_member(r, cx)? {
                        span.name = text;
                    }
                }
                "kind" => {
                    if let Some(code) = enum_member(r, cx)? {
                        span.kind = SpanKind::from_wire(code);
                    }
                }
                "startTimeUnixNano" => {
                    if let Some(at) = u64_member(r, cx)? {
                        span.start_time_unix_nano = at;
                    }
                }
                "endTimeUnixNano" => {
                    if let Some(at) = u64_member(r, cx)? {
                        span.end_time_unix_nano = at;
                    }
                }
                "attributes" => key_values(r, cx, &mut span.attributes)?,
                "events" => {
                    if !opens_array(r, cx)? {
                        continue;
                    }
                    while r.next_element()? {
                        if span.events.len() >= cx.limits.max_events {
                            bump(&mut cx.dropped.events);
                            discard(r)?;
                            continue;
                        }
                        if opens_object(r, cx)? {
                            span.events.push(decode_event(r, cx)?);
                        }
                    }
                }
                "status" => {
                    if opens_object(r, cx)? {
                        let (code, message) = decode_status(r, cx)?;
                        span.status_code = code;
                        span.status_message = message;
                    }
                }
                _ => unrecognised(&name, r, cx)?,
            }
        }

        if unreadable_id {
            bump(&mut cx.dropped.spans);
            return Ok(None);
        }
        Ok(Some(span))
    })
}

fn decode_event(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Event> {
    // One OTLP message: Event. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut event = Event {
            time_unix_nano: 0,
            name: String::new(),
            attributes: Vec::new(),
        };
        while let Some(name) = r.next_name()? {
            match name.as_ref() {
                "timeUnixNano" => {
                    if let Some(at) = u64_member(r, cx)? {
                        event.time_unix_nano = at;
                    }
                }
                "name" => {
                    if let Some(text) = string_member(r, cx)? {
                        event.name = text;
                    }
                }
                "attributes" => key_values(r, cx, &mut event.attributes)?,
                _ => unrecognised(&name, r, cx)?,
            }
        }
        Ok(event)
    })
}

fn decode_status(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<(StatusCode, String)> {
    // One OTLP message: Status. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut code = StatusCode::Unset;
        let mut message = String::new();
        while let Some(name) = r.next_name()? {
            match name.as_ref() {
                "message" => {
                    if let Some(text) = string_member(r, cx)? {
                        message = text;
                    }
                }
                "code" => {
                    if let Some(wire) = enum_member(r, cx)? {
                        code = StatusCode::from_wire(wire);
                    }
                }
                _ => unrecognised(&name, r, cx)?,
            }
        }
        Ok((code, message))
    })
}

fn decode_attr(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Attr> {
    // One OTLP message: KeyValue. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut key = String::new();
        let mut value = Value::Empty;
        while let Some(name) = r.next_name()? {
            match name.as_ref() {
                "key" => {
                    if let Some(text) = string_member(r, cx)? {
                        // Cut by bytes at the same boundary as the wire path and
                        // through the same function, so a key that straddles the cut
                        // gets the same U+FFFD in both stores. Two spellings of one
                        // attribute key would mean two columns in a projection.
                        let cut = text.len().min(cx.limits.max_key_bytes);
                        key = lossy_string(&text.as_bytes()[..cut]);
                    }
                }
                "value" => {
                    if opens_object(r, cx)? {
                        value = decode_value(r, cx)?;
                    }
                }
                _ => unrecognised(&name, r, cx)?,
            }
        }
        Ok(Attr { key, value })
    })
}

/// An `AnyValue`.
///
/// `{}` is a value that is present and empty, which is [`Value::Empty`] and is
/// not the same as the attribute being absent: an SDK given a key and no value
/// writes exactly this, and folding the two together loses the difference between
/// a cleared field and one nobody wrote.
fn decode_value(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Value> {
    // One OTLP message: AnyValue. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut value = Value::Empty;
        let mut assigned = false;
        while let Some(name) = r.next_name()? {
            let member = match name.as_ref() {
                "stringValue" => string_member(r, cx)?.map(|text| string_value(text, cx)),
                "boolValue" => bool_member(r, cx)?.map(Value::Bool),
                "intValue" => i64_member(r, cx)?.map(Value::Int),
                "doubleValue" => double_member(r, cx)?.map(Value::Double),
                "bytesValue" => bytes_member(r, cx)?.map(Value::Bytes),
                "arrayValue" => {
                    if opens_object(r, cx)? {
                        Some(Value::Array(decode_array(r, cx)?))
                    } else {
                        None
                    }
                }
                "kvlistValue" => {
                    if opens_object(r, cx)? {
                        Some(Value::Map(decode_kvlist(r, cx)?))
                    } else {
                        None
                    }
                }
                _ => {
                    unrecognised(&name, r, cx)?;
                    None
                }
            };
            if let Some(next) = member {
                // A oneof with two members set. Last wins, matching the wire reader
                // whose match arms overwrite, so the two transports cannot disagree
                // about a message neither of them should have been sent. Counted
                // because no ordinary encoder can produce one.
                if assigned {
                    bump(&mut cx.shape.multi_valued_anyvalue);
                }
                assigned = true;
                value = next;
            }
        }
        Ok(value)
    })
}

fn decode_array(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Vec<Value>> {
    // One OTLP message: ArrayValue. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut items = Vec::new();
        while let Some(name) = r.next_name()? {
            match name.as_ref() {
                "values" => {
                    if !opens_array(r, cx)? {
                        continue;
                    }
                    while r.next_element()? {
                        // Charged to `attributes`, as it is on the wire: one counter
                        // for "an attribute lost part of itself".
                        if items.len() >= cx.limits.max_array_items {
                            bump(&mut cx.dropped.attributes);
                            discard(r)?;
                            continue;
                        }
                        if opens_object(r, cx)? {
                            items.push(decode_value(r, cx)?);
                        }
                    }
                }
                _ => unrecognised(&name, r, cx)?,
            }
        }
        Ok(items)
    })
}

fn decode_kvlist(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Vec<Attr>> {
    // One OTLP message: KeyValueList. See `Ctx::message`.
    let at = r.offset();
    cx.message(at, |cx| {
        let mut attrs = Vec::new();
        while let Some(name) = r.next_name()? {
            match name.as_ref() {
                "values" => key_values(r, cx, &mut attrs)?,
                _ => unrecognised(&name, r, cx)?,
            }
        }
        Ok(attrs)
    })
}

// ---------------------------------------------------------------------------
// One member at a time, and every way one can disagree with the encoding
// ---------------------------------------------------------------------------

/// A repeated `KeyValue`: `attributes` on a resource, a span or an event, and
/// `values` inside a `kvlistValue`.
///
/// One helper because the array is JSON's own: on the wire each element is its
/// own tag and there is nothing to wrap. The bound goes through [`push_attr`]
/// rather than being re-derived here, so both transports drop the same attribute
/// and charge the same counter.
fn key_values(r: &mut Reader<'_>, cx: &mut Ctx, into: &mut Vec<Attr>) -> JsonResult<()> {
    if !opens_array(r, cx)? {
        return Ok(());
    }
    while r.next_element()? {
        if opens_object(r, cx)? {
            let attr = decode_attr(r, cx)?;
            push_attr(into, attr, cx.limits, &mut cx.dropped);
        }
    }
    Ok(())
}

/// Read a value that has to be an object. `false` means it was not one, the type
/// fault is counted, and the value has been walked past.
fn opens_object(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<bool> {
    match r.value()? {
        JsonEvent::ObjectStart => Ok(true),
        other => {
            wrong_type(r, &other, cx)?;
            Ok(false)
        }
    }
}

/// Read a value that has to be an array. See [`opens_object`].
fn opens_array(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<bool> {
    match r.value()? {
        JsonEvent::ArrayStart => Ok(true),
        other => {
            wrong_type(r, &other, cx)?;
            Ok(false)
        }
    }
}

/// A member this version knows, holding a JSON type its field does not have:
/// `"kind":"SPAN_KIND_SERVER"`, `"attributes":{}`.
///
/// The member is abandoned and the field keeps proto3's default. Refusing the
/// line would lose every other span in the batch over one emitter's misspelling,
/// and guessing would put a value in a record nobody sent.
fn wrong_type<'a>(r: &mut Reader<'a>, opened: &JsonEvent<'a>, cx: &mut Ctx) -> JsonResult<()> {
    bump(&mut cx.shape.bad_types);
    r.skip_rest(opened)
}

/// Skip a member this version does not act on, and say what kind of name it had.
///
/// # Why this counts elements and not members
///
/// An underscore is the whole test for snake_case, and it is enough because
/// OTLP/JSON has no member name containing one: an attribute *key* like
/// `gen_ai.request.model` is a string value, not a member name, and never reaches
/// this.
///
/// The count is the interesting part. `unknown_fields` is documented as the measure
/// of how much of a message we understood, and on the wire a repeated field is one
/// tag per element, so two unknown `links` cost two. In JSON they are one member
/// whose value is an array of two, so counting members made the same message read as
/// 2 on the wire and 1 here, which is a hole in the whole claim that the two
/// decoders mean the same thing: the differential test would fail on a legal message
/// nobody had thought to write.
///
/// So an unknown member whose value is an array is charged per element, which maps
/// exactly onto the wire's tag-per-element rather than approximately: an array of
/// arrays costs one per outer element on both sides, because the wire also sees one
/// tag per outer element. Anything that is not an array costs one.
///
/// `Reader::skip_value` would count the member itself, so this drives the value by
/// hand and counts as it goes. `trailryx-json` deliberately keeps counting members,
/// because that is the truthful statement about JSON, and knowing that a repeated
/// field's elements are what the wire counts is OTLP's business and not the
/// grammar's.
fn unrecognised(name: &str, r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<()> {
    if name.contains('_') {
        bump(&mut cx.shape.snake_case_keys);
    }
    let opened = r.value()?;
    if opened == JsonEvent::ArrayStart {
        let mut elements = 0u32;
        while r.next_element()? {
            let element = r.value()?;
            r.skip_rest(&element)?;
            elements = elements.saturating_add(1);
        }
        // Exactly the element count, with no floor. A floor of one was the first
        // answer and it was wrong the other way: proto3 JSON omits an empty
        // repeated field, so `"links":[]` and no `links` at all are the same
        // message, the wire charges nothing for it, and the differential test said
        // so within the minute.
        bump_by(&mut cx.shape.unknown_members, elements);
        return Ok(());
    }
    bump(&mut cx.shape.unknown_members);
    r.skip_rest(&opened)
}

/// Add a measured count, saturating, because `[profile.test]` checks overflow.
fn bump_by(counter: &mut u32, by: u32) {
    *counter = counter.saturating_add(by);
}

/// Walk past a value without calling it unknown.
///
/// [`Reader::skip_value`] counts what it skipped, which is right for a member
/// this version does not know and wrong for one it knows and is declining to
/// store: a batch past `max_spans` would otherwise report a hundred thousand
/// fields we did not understand when we understood every one of them.
fn discard(r: &mut Reader<'_>) -> JsonResult<()> {
    let opened = r.value()?;
    r.skip_rest(&opened)
}

/// A member that has to be a JSON string.
fn string_member(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Option<String>> {
    match r.value()? {
        JsonEvent::Str(text) => Ok(Some(text.into_owned())),
        other => {
            wrong_type(r, &other, cx)?;
            Ok(None)
        }
    }
}

/// A `stringValue`, under the same bound the wire path puts on one.
///
/// [`Dropped::invalid_utf8`] cannot be charged from this transport at all: the
/// reader refuses a bad byte before a decoder sees it, and refuses a lone
/// surrogate too. That is a real difference between the two readers rather than
/// something missing here, and it is why the JSON path can hand back a `String`
/// where the wire path has to decide what to do with bytes that are not text.
fn string_value(text: String, cx: &mut Ctx) -> Value {
    if text.len() > cx.limits.max_value_bytes {
        bump(&mut cx.dropped.oversize_values);
        return Value::Empty;
    }
    Value::Str(text)
}

fn bool_member(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Option<bool>> {
    match r.value()? {
        JsonEvent::Bool(b) => Ok(Some(b)),
        other => {
            wrong_type(r, &other, cx)?;
            Ok(None)
        }
    }
}

/// A `bytesValue`: base64, in either alphabet, padded or not.
fn bytes_member(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Option<Vec<u8>>> {
    let Some(text) = string_member(r, cx)? else {
        return Ok(None);
    };
    let Some(bytes) = base64_bytes(text.as_bytes()) else {
        bump(&mut cx.shape.bad_base64);
        return Ok(None);
    };
    if bytes.len() > cx.limits.max_value_bytes {
        bump(&mut cx.dropped.oversize_values);
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// An enum: `kind`, `status.code`.
///
/// Integers only. Proto3 JSON also permits the name, and accepting
/// `"SPAN_KIND_SERVER"` would mean a second table of names to keep in step with
/// the numbers; the day the two disagree, a Server span becomes an Internal one
/// and nothing says so. The integer goes through the same `from_wire` the wire
/// reader uses, so there is one table for both transports and a value neither of
/// them knows lands on the same default.
fn enum_member(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Option<u64>> {
    match r.value()? {
        JsonEvent::Number(n) => match n.as_u64() {
            Some(code) => Ok(Some(code)),
            None => {
                bump(&mut cx.shape.bad_numbers);
                Ok(None)
            }
        },
        other => {
            wrong_type(r, &other, cx)?;
            Ok(None)
        }
    }
}

/// A 64-bit unsigned field: `startTimeUnixNano`, `endTimeUnixNano`,
/// `timeUnixNano`.
///
/// Either spelling. `None` means the field keeps its default and one
/// `bad_numbers` was charged, whichever of the three ways it failed: out of
/// range, not a whole number, or neither a string nor a number.
fn u64_member(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Option<u64>> {
    let read = match r.value()? {
        JsonEvent::Number(n) => n.as_u64(),
        JsonEvent::Str(text) => decimal_u64(text.as_bytes()),
        other => {
            r.skip_rest(&other)?;
            None
        }
    };
    if read.is_none() {
        bump(&mut cx.shape.bad_numbers);
    }
    Ok(read)
}

/// A 64-bit signed field: `intValue`. See [`u64_member`].
fn i64_member(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Option<i64>> {
    let read = match r.value()? {
        JsonEvent::Number(n) => n.as_i64(),
        JsonEvent::Str(text) => decimal_i64(text.as_bytes()),
        other => {
            r.skip_rest(&other)?;
            None
        }
    };
    if read.is_none() {
        bump(&mut cx.shape.bad_numbers);
    }
    Ok(read)
}

/// A `doubleValue`.
///
/// A JSON number, or one of the three words. The asymmetry between them is
/// deliberate: `"Infinity"` is accepted because an emitter that means infinity
/// has that way to say so, and a finite literal that overflows to infinity
/// (`1e999`) is refused because storing infinity for a number the emitter wrote
/// out in full would be a repair, and this tree does not repair. The value then
/// stays [`Value::Empty`], which is visibly not a measurement.
fn double_member(r: &mut Reader<'_>, cx: &mut Ctx) -> JsonResult<Option<f64>> {
    match r.value()? {
        JsonEvent::Number(n) => match n.as_f64_finite() {
            Some(d) => Ok(Some(d)),
            None => {
                bump(&mut cx.shape.double_overflow);
                Ok(None)
            }
        },
        JsonEvent::Str(text) => {
            let word = match text.as_ref() {
                "NaN" => f64::NAN,
                "Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                // Those three and nothing else. `"1.5"` is a number written as a
                // string, which this encoding allows for 64-bit integers and not
                // for doubles, and reading it anyway would be us inventing a
                // dialect for one producer.
                _ => {
                    bump(&mut cx.shape.bad_types);
                    return Ok(None);
                }
            };
            bump(&mut cx.shape.nonfinite_doubles);
            Ok(Some(word))
        }
        other => {
            wrong_type(r, &other, cx)?;
            Ok(None)
        }
    }
}

/// A `traceId`, `spanId` or `parentSpanId`.
///
/// `None` means the span must go, and the counter that was charged says which
/// fault it was: `bad_types` for a member that is not a string at all,
/// `bad_ids` for text that is not hex of the fixed length. Both drop the span,
/// because the consequence of reading an unreadable id as absent does not depend
/// on how it was unreadable.
fn id_member(r: &mut Reader<'_>, cx: &mut Ctx, chars: usize) -> JsonResult<Option<Vec<u8>>> {
    match r.value()? {
        JsonEvent::Str(text) => {
            // Proto3's "always print fields" mode writes an absent `bytes` field
            // as the empty string, and refusing that would drop every root span
            // an emitter in that mode sends. Empty, absent and all-zero all mean
            // the same thing, and `Span::has_parent` is the single place that
            // decides so: this returns the bytes and does not re-derive it.
            if text.is_empty() {
                return Ok(Some(Vec::new()));
            }
            match hex_bytes(text.as_bytes(), chars) {
                Some(bytes) => Ok(Some(bytes)),
                None => {
                    bump(&mut cx.shape.bad_ids);
                    Ok(None)
                }
            }
        }
        other => {
            wrong_type(r, &other, cx)?;
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Text to bytes, and text to numbers
// ---------------------------------------------------------------------------

/// Hex of exactly `chars` characters, either case, to bytes.
///
/// The length is exact because OTLP fixes it, and that is what tells an id from
/// the other encoding of the same bytes: `otel-cli server json` writes a span id
/// as 12 characters of base64 and a trace id as 24, and a decoder that decoded
/// them anyway would point every span in the batch at a trace nobody can find.
fn hex_bytes(text: &[u8], chars: usize) -> Option<Vec<u8>> {
    if text.len() != chars {
        return None;
    }
    let mut out = Vec::with_capacity(chars / 2);
    for pair in text.chunks(2) {
        let high = nibble(pair[0])?;
        let low = nibble(*pair.get(1)?)?;
        out.push((high << 4) | low);
    }
    Some(out)
}

/// One hex digit. Classified by byte range, never by `char::is_alphanumeric`,
/// which would make U+FF11 FULLWIDTH DIGIT ONE a digit.
fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Base64 to bytes, both alphabets, padding optional.
///
/// Written here for the same reason the protobuf reader is: this runs on bytes a
/// stranger chose. Both alphabets, because proto3 says `bytes` are base64 and
/// does not say which of the two, so refusing `-` and `_` would refuse a
/// conforming emitter. Padding accepted and not required, because a producer that
/// strips it is still unambiguous: the number of characters left over says how
/// many bytes the last group holds.
///
/// Refused: a length that leaves one character over, since no group encodes fewer
/// than six bits; any byte outside the alphabet, whitespace and newlines
/// included; and leftover bits that are not zero. That last one matters here more
/// than it would elsewhere: `/w==` and `/x==` are the same byte to a lenient
/// decoder, and a store that publishes a Merkle root over what it decoded must
/// not accept two spellings of one value.
fn base64_bytes(text: &[u8]) -> Option<Vec<u8>> {
    let mut body = text;
    let mut pad = 0usize;
    while pad < 2 && body.last() == Some(&b'=') {
        body = &body[..body.len() - 1];
        pad += 1;
    }
    if body.last() == Some(&b'=') {
        return None;
    }
    if pad > 0 && (body.len() + pad) % 4 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in body {
        acc = ((acc << 6) | u32::from(sextet(b)?)) & 0xffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 6 {
        return None;
    }
    if bits > 0 && acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// One base64 character. 62 and 63 are the two positions where the standard and
/// URL-safe alphabets differ.
fn sextet(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// A 64-bit unsigned integer written as a decimal string.
///
/// The grammar is the one the *number* form already gets from the reader: no
/// sign, no leading zero, at least one digit. That symmetry is the point. It is
/// also why `str::parse` is not used: verified locally, `"+1"` and `"01"` both
/// parse `Ok` as `u64`, so a decoder built on `parse` would accept as a string
/// exactly what it refuses as a number, and an emitter could pick whichever
/// spelling got past us.
fn decimal_u64(text: &[u8]) -> Option<u64> {
    match text {
        [] => return None,
        [b'0'] => return Some(0),
        [b'0', ..] => return None,
        _ => {}
    }
    let mut value: u64 = 0;
    for &b in text {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(value)
}

/// The signed twin. Accumulated as a magnitude and negated with checked
/// arithmetic, never through an `f64`: `1e19 as i64` is `i64::MAX` and
/// `9223372036854775808u64 as i64` is `i64::MIN`, and both of those are a refusal
/// wearing a plausible value's clothes.
fn decimal_i64(text: &[u8]) -> Option<i64> {
    let Some((b'-', digits)) = text.split_first() else {
        return i64::try_from(decimal_u64(text)?).ok();
    };
    let magnitude = decimal_u64(digits)?;
    // `i64::MIN` has no positive counterpart, so `try_from` and then negate would
    // refuse the one value that is legal.
    if magnitude == i64::MIN.unsigned_abs() {
        return Some(i64::MIN);
    }
    i64::try_from(magnitude).ok()?.checked_neg()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_reads_both_alphabets_padded_or_not() {
        // The fixture's fingerprint, whose standard spelling uses `+`, `/` and a
        // pad character, and whose URL-safe spelling uses `-` and `_`.
        let want = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f, 0xff];
        for text in ["3q2+7wB//w==", "3q2-7wB__w==", "3q2+7wB//w", "3q2-7wB__w"] {
            assert_eq!(base64_bytes(text.as_bytes()), Some(want.clone()), "{text}");
        }
        assert_eq!(base64_bytes(b""), Some(Vec::new()));
        assert_eq!(base64_bytes(b"/w=="), Some(vec![0xff]));
        assert_eq!(base64_bytes(b"/+8="), Some(vec![0xff, 0xef]));
    }

    #[test]
    fn base64_refuses_a_second_spelling_of_the_same_bytes() {
        // `/x==` decodes to the same byte as `/w==` in a lenient decoder, because
        // the four bits below the byte are ignored. Accepting both would give one
        // value two hashes.
        assert_eq!(base64_bytes(b"/x=="), None);
        assert_eq!(base64_bytes(b"/+9="), None);
        // One character over, which no group can be.
        assert_eq!(base64_bytes(b"A"), None);
        assert_eq!(base64_bytes(b"AAAAA"), None);
        // Padding that does not complete a group, and too much of it.
        assert_eq!(base64_bytes(b"A==="), None);
        assert_eq!(base64_bytes(b"AAA=="), None);
        // Anything outside the alphabet, whitespace included.
        for text in ["A A=", "AA\n=", "AA*=", "AA=A", "3q2+7wB//w=x"] {
            assert_eq!(base64_bytes(text.as_bytes()), None, "{text}");
        }
    }

    #[test]
    fn a_hex_id_is_case_insensitive_and_exactly_as_long_as_otlp_says() {
        let want = vec![0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7];
        assert_eq!(
            hex_bytes(b"00f067aa0ba902b7", SPAN_ID_CHARS),
            Some(want.clone())
        );
        assert_eq!(hex_bytes(b"00F067AA0BA902B7", SPAN_ID_CHARS), Some(want));
        // One character short, one over, and the base64 spelling of eight bytes.
        assert_eq!(hex_bytes(b"00f067aa0ba902b", SPAN_ID_CHARS), None);
        assert_eq!(hex_bytes(b"00f067aa0ba902b70", SPAN_ID_CHARS), None);
        assert_eq!(hex_bytes(b"APBnqgupArc=", SPAN_ID_CHARS), None);
        // A non-hex byte at every position, and a fullwidth digit.
        assert_eq!(hex_bytes(b"00f067aa0ba902bg", SPAN_ID_CHARS), None);
        assert_eq!(
            hex_bytes("00f067aa0ba902b\u{ff11}".as_bytes(), SPAN_ID_CHARS),
            None
        );
    }

    #[test]
    fn a_decimal_string_gets_the_grammar_the_number_form_gets() {
        assert_eq!(decimal_u64(b"0"), Some(0));
        assert_eq!(
            decimal_u64(b"1700000000123456789"),
            Some(1_700_000_000_123_456_789)
        );
        assert_eq!(decimal_u64(b"18446744073709551615"), Some(u64::MAX));
        // Each of these `str::parse` would accept, or would accept as something
        // else. None of them is a JSON number.
        for text in [
            "",
            "+1",
            "01",
            "00",
            " 1",
            "1 ",
            "-1",
            "1.0",
            "1e3",
            "0x1f",
            "1_0",
            "NaN",
            "18446744073709551616",
            "١٢٣",
        ] {
            assert_eq!(decimal_u64(text.as_bytes()), None, "{text}");
        }
    }

    #[test]
    fn a_signed_decimal_string_keeps_the_value_with_no_positive_counterpart() {
        assert_eq!(decimal_i64(b"-9223372036854775808"), Some(i64::MIN));
        assert_eq!(decimal_i64(b"9223372036854775807"), Some(i64::MAX));
        assert_eq!(decimal_i64(b"-0"), Some(0));
        assert_eq!(decimal_i64(b"-1024"), Some(-1024));
        assert_eq!(decimal_i64(b"9223372036854775808"), None);
        assert_eq!(decimal_i64(b"-9223372036854775809"), None);
        assert_eq!(decimal_i64(b"-01"), None);
        assert_eq!(decimal_i64(b"--1"), None);
        assert_eq!(decimal_i64(b"-"), None);
    }

    #[test]
    fn the_counter_list_names_every_field_and_the_names_are_distinct() {
        let report = ShapeReport::default();
        let counters = report.counters();
        let mut names: Vec<&str> = counters.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), counters.len(), "two counters share a name");
        assert!(counters.iter().all(|(_, n)| *n == 0));
    }
}
