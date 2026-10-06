//! One fixture, described once, written by two encoders that share no code.
//!
//! The value of a differential test is entirely in the independence of the two
//! sides. So what lives here is data: field names, values, ids, the shape of a
//! nested message. [`encode_protobuf`] walks it with the helpers in
//! `common/mod.rs` and [`encode_json`] walks it with the writer in
//! `common/jsonenc.rs`, and neither walk calls the other. If the two decoders
//! then produce the same [`trailryx_otlp::TraceRequest`], that is a fact about
//! the decoders. If the encoders shared a rendering step, it would be a fact
//! about nothing.
//!
//! # Why this particular content
//!
//! Every entry is here because it is a place a decoder has been seen to go
//! wrong, or a place where the two encodings say the same thing differently:
//!
//! - an `AnyValue` of `{}`, which is present and empty and not the same as
//!   absent;
//! - a child span naming its parent, and a third span whose `parentSpanId` is
//!   all zeros. OTLP defines the all-zero id as invalid and emitters write it out
//!   rather than omitting the field, and reading those eight bytes as a name
//!   manufactured causal edges until `MAPPER_VERSION` 2;
//! - one 64-bit integer written as a decimal string and another as a JSON
//!   number, because both are legal and a decoder that reads one of them loses
//!   whole fields;
//! - nanosecond clocks that are not exactly representable as an IEEE double, on
//!   the span whose times use the number form. A decoder that parses an integer
//!   token through `f64` returns a timestamp nobody sent, and the protobuf side
//!   is what proves the value it should have been;
//! - a string carrying a tab, a newline, DEL, U+2028, an astral character and a
//!   non-character, none of which a decoder may repair;
//! - the same text spelled once as raw UTF-8 and once as `\uXXXX` escapes with a
//!   surrogate pair, which must decode to one string;
//! - a `bytesValue`, base64 on one side and a length-delimited field on the
//!   other;
//! - a double that is not finite, quoted on the JSON side because JSON has no
//!   literal for it;
//! - an attribute key that appears twice. `trace.proto` says attribute keys
//!   MUST be unique and that the behaviour of software receiving duplicates "can
//!   be unpredictable", which is a specification declining to decide. Emitters
//!   send them anyway, both encodings can carry them, and this store has to be
//!   predictable about them: the same span must decode the same way from either;
//! - a status with a code and a message, and an event with attributes of three
//!   different types.

#![allow(dead_code)]

use super::*;

/// How the JSON side spells a 64-bit integer for one entry.
///
/// A property of the fixture rather than of either encoder: on the wire an
/// integer is a varint and there is nothing to choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntText {
    /// `"1024"`, the form the reference collector emits.
    Quoted,
    /// `1024`, also legal.
    Bare,
}

/// An OTLP `AnyValue`, as fixture data.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    /// No field set at all. Present and empty.
    Empty,
    Str(&'static str),
    /// The same as [`Val::Str`] to protobuf. The JSON side writes every
    /// non-ASCII scalar as a `\uXXXX` escape, so that both spellings decoding to
    /// one string is something a test can assert rather than assume.
    Escaped(&'static str),
    Bool(bool),
    Int(i64, IntText),
    Double(f64),
    Bytes(&'static [u8]),
    Array(Vec<Val>),
    Map(Vec<Attribute>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    pub key: &'static str,
    pub value: Val,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FixtureEvent {
    pub at: u64,
    pub name: &'static str,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FixtureSpan {
    pub name: &'static str,
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    /// `None` names no parent at all. `Some([0; 8])` is a different case and the
    /// fixture carries both, because they arrive from real emitters and mean the
    /// same thing while looking nothing alike.
    pub parent_span_id: Option<[u8; 8]>,
    pub start: u64,
    pub end: u64,
    /// How the JSON side spells this span's clocks and its events'.
    pub times: IntText,
    pub attributes: Vec<Attribute>,
    pub events: Vec<FixtureEvent>,
    pub status: Option<(u64, &'static str)>,
    pub dropped_attributes: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Fixture {
    pub resource: Vec<Attribute>,
    pub scope: Scope,
    pub spans: Vec<FixtureSpan>,
}

// ---------------------------------------------------------------------------
// The data
// ---------------------------------------------------------------------------

/// The trace and span ids from the W3C trace-context examples, so a reader who
/// has seen them elsewhere recognises them, and so nothing in the fixture is a
/// run of identical bytes that a length or offset bug could survive.
pub const TRACE_ID: [u8; 16] = [
    0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36,
];
pub const ROOT_SPAN_ID: [u8; 8] = [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7];
pub const CHILD_SPAN_ID: [u8; 8] = [0xb7, 0xad, 0x6b, 0x71, 0x69, 0x20, 0x33, 0x31];
pub const ORPHAN_SPAN_ID: [u8; 8] = [0x9a, 0x4c, 0x1d, 0x87, 0x2f, 0x60, 0x05, 0xe3];

/// The all-zero span id, which OTLP defines as invalid and emitters send anyway.
pub const INVALID_PARENT: [u8; 8] = [0; 8];

/// Everything a decoder must carry through a string without repairing it: a tab,
/// a newline, DEL, U+2028 (valid JSON and a line terminator to a JavaScript
/// reader), an astral character, and U+FFFE, which is a non-character and still a
/// perfectly good scalar value.
pub const CONTROL_ZOO: &str =
    "tab\there\nnewline \u{7f} sep \u{2028} clef \u{1d11e} noncharacter \u{fffe} end";

/// Bytes that are not UTF-8, and whose base64 uses `+`, `/` and one pad
/// character, so a hand-rolled encoder cannot pass by getting the easy alphabet
/// right.
pub const FINGERPRINT: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f, 0xff];

fn attr(key: &'static str, value: Val) -> Attribute {
    Attribute { key, value }
}

/// The resource, including one attribute whose value is the empty `AnyValue`.
pub fn resource() -> Vec<Attribute> {
    vec![
        attr("service.name", Val::Str("payments-agent")),
        attr("telemetry.sdk.language", Val::Str("python")),
        // An SDK that was configured with the key and given no value. The
        // attribute exists, its value does not, and a decoder that turns this
        // into an absent attribute has lost the difference.
        attr("deployment.environment", Val::Empty),
    ]
}

pub fn scope() -> Scope {
    Scope {
        name: "opentelemetry.instrumentation.openai",
        version: "0.42.1",
    }
}

/// The GenAI messages shape, nested three levels below the attribute: an array of
/// messages, each a map, whose `parts` is an array of maps. The text is escaped
/// on the JSON side and carries an accented character and an astral one.
fn input_messages() -> Val {
    Val::Array(vec![Val::Map(vec![
        attr("role", Val::Str("user")),
        attr(
            "parts",
            Val::Array(vec![Val::Map(vec![
                attr("type", Val::Str("text")),
                attr("content", Val::Escaped("Résume la partition \u{1d11e}")),
            ])]),
        ),
    ])])
}

pub fn spans() -> Vec<FixtureSpan> {
    vec![
        // A root: an agent invoked from nothing, which the mapper reads as a
        // request arriving rather than a delegation.
        FixtureSpan {
            name: "invoke_agent triage",
            trace_id: TRACE_ID,
            span_id: ROOT_SPAN_ID,
            parent_span_id: None,
            start: 1_700_000_000_000_000_000,
            end: 1_700_000_000_900_000_000,
            times: IntText::Quoted,
            attributes: vec![
                attr("gen_ai.operation.name", Val::Str("invoke_agent")),
                attr("gen_ai.agent.name", Val::Str("triage")),
                attr("app.dry_run", Val::Bool(false)),
            ],
            events: Vec::new(),
            status: None,
            dropped_attributes: 0,
        },
        // The inference call underneath it, and everything awkward in one span.
        FixtureSpan {
            name: "chat gpt-4o-mini",
            trace_id: TRACE_ID,
            span_id: CHILD_SPAN_ID,
            parent_span_id: Some(ROOT_SPAN_ID),
            start: 1_700_000_000_100_000_000,
            end: 1_700_000_000_850_000_000,
            times: IntText::Quoted,
            attributes: vec![
                attr("gen_ai.operation.name", Val::Str("chat")),
                attr("gen_ai.provider.name", Val::Str("openai")),
                attr("gen_ai.request.model", Val::Str("gpt-4o-mini")),
                attr("gen_ai.request.temperature", Val::Double(0.2)),
                // The one the brief asks for by name: a string in JSON, a varint
                // on the wire, one number to both decoders.
                attr("gen_ai.request.max_tokens", Val::Int(1024, IntText::Quoted)),
                attr("gen_ai.usage.input_tokens", Val::Int(1_204, IntText::Bare)),
                attr("gen_ai.usage.output_tokens", Val::Int(87, IntText::Quoted)),
                attr("gen_ai.input.messages", input_messages()),
                attr("error.type", Val::Str("RateLimitError")),
                attr("app.note", Val::Str(CONTROL_ZOO)),
                attr("app.request.fingerprint", Val::Bytes(FINGERPRINT)),
                // Not finite. Positive infinity rather than NaN on purpose: NaN
                // is not equal to itself, so a fixture built around it cannot be
                // compared by equality, and the quoting is the same code path.
                attr("app.score", Val::Double(f64::INFINITY)),
                // The same key twice: a violation of `trace.proto`, which says
                // keys MUST be unique, and one every SDK with a retry loop
                // eventually commits. Note that this is a repeated element of
                // the `attributes` *array* and not two members of one JSON
                // object, which would be a different defect. A reader that
                // takes the first must keep taking the first.
                attr("app.retry", Val::Int(1, IntText::Bare)),
                attr("app.retry", Val::Str("after the second attempt")),
            ],
            events: vec![FixtureEvent {
                at: 1_700_000_000_500_000_000,
                name: "exception",
                attributes: vec![
                    attr("exception.type", Val::Str("RateLimitError")),
                    attr("exception.escaped", Val::Bool(true)),
                    attr("retry.after_ms", Val::Int(3_000, IntText::Bare)),
                ],
            }],
            // Code 2 is ERROR, written as the integer and never as its name.
            // The message quotes an upstream error, which is why it carries
            // control characters: they arrive from the provider, not from us.
            status: Some((2, "429 Too Many Requests\n\tupstream said: slow down")),
            dropped_attributes: 3,
        },
        // The third span: a root that says so by writing eight zero bytes.
        // Its clocks use the number form, and neither of them is exactly
        // representable as an IEEE double.
        FixtureSpan {
            name: "invoke_agent summarize",
            trace_id: TRACE_ID,
            span_id: ORPHAN_SPAN_ID,
            parent_span_id: Some(INVALID_PARENT),
            start: 1_700_000_000_123_456_789,
            end: 1_700_000_000_987_654_321,
            times: IntText::Bare,
            attributes: vec![
                attr("gen_ai.operation.name", Val::Str("invoke_agent")),
                attr("app.detached", Val::Bool(true)),
            ],
            events: Vec::new(),
            status: None,
            dropped_attributes: 0,
        },
    ]
}

pub fn fixture() -> Fixture {
    Fixture {
        resource: resource(),
        scope: scope(),
        spans: spans(),
    }
}

// ---------------------------------------------------------------------------
// The protobuf encoder
// ---------------------------------------------------------------------------

/// The fixture as an OTLP protobuf `ExportTraceServiceRequest`.
///
/// The envelope is spelled out here rather than through `common::request`
/// because the fixture names a scope version and that helper writes the scope
/// name only. The existing tests are written against that helper, so it stays as
/// it is.
pub fn encode_protobuf(f: &Fixture) -> Vec<u8> {
    let mut resource_body = Vec::new();
    for a in &f.resource {
        resource_body.extend_from_slice(&len_delim(1, &kv(a.key, pb_value(&a.value))));
    }

    // InstrumentationScope: name is field 1, version is field 2.
    let mut scope_body = string_field(1, f.scope.name);
    scope_body.extend_from_slice(&string_field(2, f.scope.version));

    let mut scope_spans = len_delim(1, &scope_body);
    for span in &f.spans {
        scope_spans.extend_from_slice(&len_delim(2, &pb_span(span)));
    }

    let mut resource_spans = len_delim(1, &resource_body);
    resource_spans.extend_from_slice(&len_delim(2, &scope_spans));

    len_delim(1, &resource_spans)
}

fn pb_span(span: &FixtureSpan) -> Vec<u8> {
    let mut builder = SpanBuilder::new(span.name)
        .trace_id(span.trace_id.to_vec())
        .span_id(span.span_id.to_vec())
        .times(span.start, span.end);
    if let Some(parent) = span.parent_span_id {
        builder = builder.parent(parent.to_vec());
    }
    for a in &span.attributes {
        builder = builder.attr(a.key, pb_value(&a.value));
    }
    for event in &span.events {
        let attrs: Vec<(&str, Vec<u8>)> = event
            .attributes
            .iter()
            .map(|a| (a.key, pb_value(&a.value)))
            .collect();
        builder = builder.event(event.at, event.name, &attrs);
    }
    if let Some((code, message)) = span.status {
        builder = builder.status(code, message);
    }

    let mut bytes = builder.encode();
    if span.dropped_attributes > 0 {
        // `dropped_attributes_count` is field 10, appended after the status
        // field 15 that `SpanBuilder` wrote. Protobuf fixes no order between
        // fields and a decoder that loops over tags cannot tell; writing it
        // here keeps `common/mod.rs` untouched.
        bytes.extend_from_slice(&varint_field(10, u64::from(span.dropped_attributes)));
    }
    bytes
}

fn pb_value(value: &Val) -> Vec<u8> {
    match value {
        // An `AnyValue` submessage with nothing in it. `common::kv` writes the
        // `value` field either way, so this is the present-but-empty case.
        Val::Empty => Vec::new(),
        // Escaping is a JSON spelling of the same text. Protobuf has one way to
        // say it, which is what makes the two sides comparable.
        Val::Str(s) | Val::Escaped(s) => any_string(s),
        Val::Bool(b) => any_bool(*b),
        Val::Int(i, _) => any_int(*i),
        Val::Double(d) => any_double(*d),
        // Field 7, written out rather than through `common::any_bytes`, which
        // writes field 1: a *string* whose bytes are not UTF-8, which is a
        // different message and a different decode path.
        Val::Bytes(b) => len_delim(7, b),
        Val::Array(items) => {
            let encoded: Vec<Vec<u8>> = items.iter().map(pb_value).collect();
            any_array(&encoded)
        }
        Val::Map(fields) => {
            let encoded: Vec<(&str, Vec<u8>)> =
                fields.iter().map(|a| (a.key, pb_value(&a.value))).collect();
            any_map(&encoded)
        }
    }
}

// ---------------------------------------------------------------------------
// The JSON encoder
// ---------------------------------------------------------------------------

/// The fixture as canonical OTLP/JSON, on one line.
pub fn encode_json(f: &Fixture) -> String {
    let resource: Vec<(&str, String)> = f
        .resource
        .iter()
        .map(|a| (a.key, json_value(&a.value)))
        .collect();
    let spans: Vec<jsonenc::SpanBuilder> = f.spans.iter().map(json_span).collect();
    jsonenc::request(&resource, f.scope.name, f.scope.version, &spans)
}

fn json_span(span: &FixtureSpan) -> jsonenc::SpanBuilder {
    let mut builder = jsonenc::SpanBuilder::new(span.name)
        .trace_id(span.trace_id.to_vec())
        .span_id(span.span_id.to_vec())
        .times(span.start, span.end)
        .time_form(int_form(span.times))
        .dropped_attributes(span.dropped_attributes);
    if let Some(parent) = span.parent_span_id {
        builder = builder.parent(parent.to_vec());
    }
    for a in &span.attributes {
        builder = builder.attr(a.key, json_value(&a.value));
    }
    for event in &span.events {
        let attrs: Vec<(&str, String)> = event
            .attributes
            .iter()
            .map(|a| (a.key, json_value(&a.value)))
            .collect();
        builder = builder.event(event.at, event.name, &attrs);
    }
    if let Some((code, message)) = span.status {
        builder = builder.status(code, message);
    }
    builder
}

fn json_value(value: &Val) -> String {
    match value {
        Val::Empty => jsonenc::any_empty(),
        Val::Str(s) => jsonenc::any_string(s),
        Val::Escaped(s) => jsonenc::any_string_escaped(s),
        Val::Bool(b) => jsonenc::any_bool(*b),
        Val::Int(i, text) => jsonenc::any_int(*i, int_form(*text)),
        Val::Double(d) => jsonenc::any_double(*d),
        Val::Bytes(b) => jsonenc::any_bytes(b),
        Val::Array(items) => {
            let encoded: Vec<String> = items.iter().map(json_value).collect();
            jsonenc::any_array(&encoded)
        }
        Val::Map(fields) => {
            let encoded: Vec<(&str, String)> = fields
                .iter()
                .map(|a| (a.key, json_value(&a.value)))
                .collect();
            jsonenc::any_map(&encoded)
        }
    }
}

fn int_form(text: IntText) -> jsonenc::IntForm {
    match text {
        IntText::Quoted => jsonenc::IntForm::DecimalString,
        IntText::Bare => jsonenc::IntForm::Number,
    }
}
