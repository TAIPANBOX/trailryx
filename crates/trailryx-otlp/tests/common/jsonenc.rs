//! An OTLP/JSON writer, the JSON twin of the protobuf encoder next door.
//!
//! Same reason as `common/mod.rs`: handing a decoder a struct we built ourselves
//! proves nothing about the decoder. This writes the bytes a collector
//! configured for `application/json` puts on the wire, member by member, so a
//! test starts where a real batch starts.
//!
//! It is a second implementation on purpose, not a serialiser pointed at the
//! protobuf helpers. The pair exists to be able to disagree: a differential test
//! is worth running only if the two encoders can be wrong independently, and one
//! shared code path would make them agree by construction rather than by being
//! right.
//!
//! # What canonical means here
//!
//! OTLP/JSON is proto3's JSON mapping, and the rules that bite are the ones the
//! protobuf side never has to think about:
//!
//! - member names are lowerCamelCase (`traceId`, never `trace_id`). A decoder
//!   written against the `.proto` field names ignores every field a real
//!   collector sends, and it does so silently, which is the whole reason
//!   `tests/jsonenc_is_otlp_json.rs` checks each name against a list.
//! - trace and span ids are lowercase hex, **not** base64. This is the one place
//!   OTLP overrides proto3's own mapping for `bytes`, and it is exactly 32 and 16
//!   characters. Everything else typed `bytes`, `bytesValue` included, stays
//!   base64.
//! - a 64-bit integer may be a JSON number or a decimal string, and both are
//!   legal, which is why [`IntForm`] is a parameter here instead of a decision
//!   this file makes on a decoder's behalf.
//! - enums are integers here. Proto3 JSON also permits the name
//!   (`"SPAN_KIND_CLIENT"`); that is a separate fixture and not this one.
//! - `NaN` and the infinities are quoted words, because JSON has no literal for
//!   them.

#![allow(dead_code)]

/// How a 64-bit integer is spelled.
///
/// Both spellings are legal and real emitters send both, so a fixture names the
/// one it wants rather than letting the writer pick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntForm {
    /// `"1024"`. What the specification recommends and what the reference
    /// collector emits: a reader that treats a JSON number as an IEEE double
    /// loses precision above 2^53, and a nanosecond timestamp has been past
    /// that since 2001.
    DecimalString,
    /// `1024`. Also legal, and what hand-rolled emitters produce.
    Number,
}

// --- primitives -------------------------------------------------------------

/// A quoted JSON string, with everything JSON forbids raw escaped.
///
/// The bytes below 0x20 are the ones that matter: RFC 8259 forbids them
/// unescaped, so a fixture that emitted a raw newline inside a string would be
/// testing a decoder against a document conforming parsers reject. Everything at
/// or above 0x20 travels as UTF-8, which is what a collector sends: an astral
/// character is its own four bytes and not a surrogate pair.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for ch in s.chars() {
        push_escaped(&mut out, ch, false);
    }
    out.push('"');
    out
}

/// The same text with every non-ASCII scalar written as `\uXXXX`.
///
/// Legal JSON for the identical string, and the spelling a decoder is most
/// likely to get wrong: anything above the BMP arrives as a surrogate pair
/// (U+1D11E as the two units d834 and dd1e), and a decoder that combines them
/// wrongly reads a different string out of the same document. The fixture writes
/// its astral character both ways so that difference cannot hide.
pub fn string_escaped(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for ch in s.chars() {
        push_escaped(&mut out, ch, true);
    }
    out.push('"');
    out
}

fn push_escaped(out: &mut String, ch: char, ascii_only: bool) {
    match ch {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        // The short forms, because they are what a reader of the fixture file
        // expects to see. The six-character u-escape of the same character would
        // be just as correct and much harder to recognise as a tab.
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\u{08}' => out.push_str("\\b"),
        '\u{0c}' => out.push_str("\\f"),
        c if (c as u32) < 0x20 => push_u_escape(out, c as u32 as u16),
        c if ascii_only && !c.is_ascii() => {
            let code = c as u32;
            if code >= 0x1_0000 {
                let above = code - 0x1_0000;
                push_u_escape(out, 0xd800 | (above >> 10) as u16);
                push_u_escape(out, 0xdc00 | (above & 0x3ff) as u16);
            } else {
                push_u_escape(out, code as u16);
            }
        }
        c => out.push(c),
    }
}

fn push_u_escape(out: &mut String, unit: u16) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    for shift in [12u32, 8, 4, 0] {
        out.push(DIGITS[usize::from((unit >> shift) & 0xf)] as char);
    }
}

/// Lowercase hex, no prefix. What OTLP/JSON uses for a trace or span id.
///
/// Lowercase because that is what collectors emit, and the fixture has to look
/// like traffic. The specification calls the encoding case-insensitive and its
/// own example is uppercase, so a decoder that only accepts what this writer
/// produces is a decoder that will refuse a real batch.
///
/// No padding and no truncation: a fixture that wants an id of the wrong length
/// is testing whether a decoder refuses it, and a helper that quietly corrected
/// the length would delete that test.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Standard base64, with padding, per RFC 4648 section 4.
///
/// Standard and not the URL-safe alphabet: proto3's JSON mapping says `bytes`
/// are base64, and a decoder that only accepted `-` and `_` would refuse the
/// `+` and `/` a real collector emits.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let word = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(word >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(word >> 12) as usize & 0x3f] as char);
        // The pad characters carry the length: two bytes of input end in one
        // `=`, one byte in two. A decoder that ignores them reads trailing zero
        // bytes that were never sent.
        if chunk.len() > 1 {
            out.push(ALPHABET[(word >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[word as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// A signed 64-bit integer, in whichever of the two legal spellings was asked
/// for. A decimal never contains a character JSON escapes, so the quoted form is
/// the digits between quotes and nothing else.
pub fn int64(value: i64, form: IntForm) -> String {
    match form {
        IntForm::DecimalString => format!("\"{value}\""),
        IntForm::Number => value.to_string(),
    }
}

/// The unsigned twin, for the nanosecond clocks.
pub fn uint64(value: u64, form: IntForm) -> String {
    match form {
        IntForm::DecimalString => format!("\"{value}\""),
        IntForm::Number => value.to_string(),
    }
}

/// A 32-bit count. Always a JSON number: the string form exists because 64 bits
/// do not survive a double, and 32 bits do.
pub fn uint32(value: u32) -> String {
    value.to_string()
}

/// A `double`.
///
/// The non-finite values are quoted words, which is proto3's mapping and not an
/// invention: JSON has no literal for infinity, and a bare `Infinity` would be a
/// document half the parsers in the world refuse.
pub fn double(value: f64) -> String {
    if value.is_nan() {
        return "\"NaN\"".to_owned();
    }
    if value == f64::INFINITY {
        return "\"Infinity\"".to_owned();
    }
    if value == f64::NEG_INFINITY {
        return "\"-Infinity\"".to_owned();
    }
    // The shortest form that reads back to the same bits, so the fixture says
    // the same thing on every platform.
    format!("{value:?}")
}

pub fn boolean(value: bool) -> String {
    if value { "true" } else { "false" }.to_owned()
}

/// An object, in the member order given. JSON fixes no order, and this writer
/// keeps the order of the `.proto` field numbers so the two encoders can be read
/// side by side.
pub fn object(members: &[(&str, String)]) -> String {
    let mut out = String::from("{");
    for (i, (name, value)) in members.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&string(name));
        out.push(':');
        out.push_str(value);
    }
    out.push('}');
    out
}

pub fn array(items: &[String]) -> String {
    let mut out = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(item);
    }
    out.push(']');
    out
}

// --- AnyValue ---------------------------------------------------------------

/// An `AnyValue` with no field set.
///
/// `{}` is a value that is present and empty, which OTLP uses and which is not
/// the same as the attribute being absent. A decoder that folds the two together
/// cannot tell a cleared field from one nobody ever wrote.
pub fn any_empty() -> String {
    "{}".to_owned()
}

pub fn any_string(s: &str) -> String {
    object(&[("stringValue", string(s))])
}

/// The same value with the non-ASCII scalars escaped. See [`string_escaped`].
pub fn any_string_escaped(s: &str) -> String {
    object(&[("stringValue", string_escaped(s))])
}

pub fn any_bytes(b: &[u8]) -> String {
    object(&[("bytesValue", string(&base64(b)))])
}

pub fn any_bool(b: bool) -> String {
    object(&[("boolValue", boolean(b))])
}

pub fn any_int(i: i64, form: IntForm) -> String {
    object(&[("intValue", int64(i, form))])
}

pub fn any_double(d: f64) -> String {
    object(&[("doubleValue", double(d))])
}

/// `{"arrayValue":{"values":[...]}}`. The extra `values` wrapper is easy to
/// forget and is not optional: `ArrayValue` is a message with one field.
pub fn any_array(items: &[String]) -> String {
    object(&[("arrayValue", object(&[("values", array(items))]))])
}

/// `{"kvlistValue":{"values":[...]}}`, whose values are `KeyValue` objects
/// rather than bare members. A map is not spelled as a JSON object here.
pub fn any_map(pairs: &[(&str, String)]) -> String {
    let values: Vec<String> = pairs
        .iter()
        .map(|(key, value)| kv(key, value.clone()))
        .collect();
    object(&[("kvlistValue", object(&[("values", array(&values))]))])
}

/// One `KeyValue`.
pub fn kv(key: &str, value: String) -> String {
    object(&[("key", string(key)), ("value", value)])
}

// --- Span -------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SpanBuilder {
    trace_id: Vec<u8>,
    span_id: Vec<u8>,
    parent_span_id: Vec<u8>,
    name: String,
    kind: u64,
    start: u64,
    end: u64,
    time_form: IntForm,
    dropped_attributes: u32,
    attributes: Vec<String>,
    events: Vec<String>,
    status: Option<(u64, String)>,
}

impl SpanBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            trace_id: vec![0xab; 16],
            span_id: vec![0x11; 8],
            parent_span_id: Vec::new(),
            name: name.to_owned(),
            kind: 3, // CLIENT, what an inference span usually is
            start: 1_700_000_000_000_000_000,
            end: 1_700_000_000_250_000_000,
            // The spelling the reference collector uses, so an unadorned fixture
            // looks like real traffic.
            time_form: IntForm::DecimalString,
            dropped_attributes: 0,
            attributes: Vec::new(),
            events: Vec::new(),
            status: None,
        }
    }

    pub fn trace_id(mut self, id: Vec<u8>) -> Self {
        self.trace_id = id;
        self
    }

    pub fn span_id(mut self, id: Vec<u8>) -> Self {
        self.span_id = id;
        self
    }

    pub fn parent(mut self, id: Vec<u8>) -> Self {
        self.parent_span_id = id;
        self
    }

    pub fn kind(mut self, kind: u64) -> Self {
        self.kind = kind;
        self
    }

    pub fn times(mut self, start: u64, end: u64) -> Self {
        self.start = start;
        self.end = end;
        self
    }

    /// Which spelling the nanosecond clocks get. Worth varying between fixtures:
    /// the number form is where a decoder that routes integers through a double
    /// starts returning a timestamp nobody sent.
    pub fn time_form(mut self, form: IntForm) -> Self {
        self.time_form = form;
        self
    }

    pub fn attr(mut self, key: &str, value: String) -> Self {
        self.attributes.push(kv(key, value));
        self
    }

    pub fn str_attr(self, key: &str, value: &str) -> Self {
        self.attr(key, any_string(value))
    }

    pub fn int_attr(self, key: &str, value: i64) -> Self {
        self.attr(key, any_int(value, IntForm::DecimalString))
    }

    /// A count of attributes the emitter itself threw away. Nothing in this
    /// crate reads it; it is here because a decoder has to walk past it, and a
    /// member never present in a fixture is a member never walked past.
    pub fn dropped_attributes(mut self, count: u32) -> Self {
        self.dropped_attributes = count;
        self
    }

    pub fn event(mut self, at: u64, name: &str, attrs: &[(&str, String)]) -> Self {
        let values: Vec<String> = attrs
            .iter()
            .map(|(key, value)| kv(key, value.clone()))
            .collect();
        let mut members = vec![
            ("timeUnixNano", uint64(at, self.time_form)),
            ("name", string(name)),
        ];
        if !values.is_empty() {
            members.push(("attributes", array(&values)));
        }
        self.events.push(object(&members));
        self
    }

    pub fn status(mut self, code: u64, message: &str) -> Self {
        self.status = Some((code, message.to_owned()));
        self
    }

    pub fn encode(&self) -> String {
        let mut members = vec![
            ("traceId", string(&hex(&self.trace_id))),
            ("spanId", string(&hex(&self.span_id))),
        ];
        // Omitted when empty, the way proto3 omits a default: an emitter with no
        // parent to name sends no member, and a decoder that required one would
        // refuse every root span.
        if !self.parent_span_id.is_empty() {
            members.push(("parentSpanId", string(&hex(&self.parent_span_id))));
        }
        members.push(("name", string(&self.name)));
        members.push(("kind", self.kind.to_string()));
        members.push(("startTimeUnixNano", uint64(self.start, self.time_form)));
        members.push(("endTimeUnixNano", uint64(self.end, self.time_form)));
        if !self.attributes.is_empty() {
            members.push(("attributes", array(&self.attributes)));
        }
        if self.dropped_attributes > 0 {
            members.push(("droppedAttributesCount", uint32(self.dropped_attributes)));
        }
        if !self.events.is_empty() {
            members.push(("events", array(&self.events)));
        }
        if let Some((code, message)) = &self.status {
            members.push((
                "status",
                object(&[("message", string(message)), ("code", code.to_string())]),
            ));
        }
        object(&members)
    }
}

/// A whole `ExportTraceServiceRequest`.
///
/// Takes the scope version as well as its name, which the protobuf twin does
/// not: `common::request` predates the fixture and the tests written against it
/// pass one string.
pub fn request(
    resource: &[(&str, String)],
    scope: &str,
    version: &str,
    spans: &[SpanBuilder],
) -> String {
    let attributes: Vec<String> = resource
        .iter()
        .map(|(key, value)| kv(key, value.clone()))
        .collect();
    let encoded: Vec<String> = spans.iter().map(SpanBuilder::encode).collect();

    let scope_obj = if version.is_empty() {
        object(&[("name", string(scope))])
    } else {
        object(&[("name", string(scope)), ("version", string(version))])
    };
    let scope_spans = object(&[("scope", scope_obj), ("spans", array(&encoded))]);
    let resource_spans = object(&[
        ("resource", object(&[("attributes", array(&attributes))])),
        ("scopeSpans", array(&[scope_spans])),
    ]);

    object(&[("resourceSpans", array(&[resource_spans]))])
}

/// The resource a stock SDK attaches.
pub fn service(name: &str) -> Vec<(&str, String)> {
    vec![
        ("service.name", any_string(name)),
        ("telemetry.sdk.language", any_string("python")),
    ]
}

/// Re-indent one line of JSON, for the fixture file a human reads.
///
/// Not part of the encoding: the tests compare compact bytes, and this exists so
/// a reviewer can see a fixture's shape without reaching for a formatter. It is
/// careful about exactly one thing, which is that it must not touch what is
/// inside a string, because the fixture strings carry braces, brackets, commas
/// and escaped quotes on purpose.
pub fn pretty(line: &str) -> String {
    let mut out = String::with_capacity(line.len().saturating_mul(2));
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    // Where to cut back to if a container turns out to be empty, so `{}` stays
    // two characters instead of becoming three lines.
    let mut just_opened: Option<usize> = None;

    for ch in line.chars() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => {
                just_opened = None;
                in_string = true;
                out.push(ch);
            }
            '{' | '[' => {
                out.push(ch);
                let mark = out.len();
                depth = depth.saturating_add(1);
                out.push('\n');
                indent(&mut out, depth);
                just_opened = Some(mark);
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                match just_opened.take() {
                    Some(mark) => out.truncate(mark),
                    None => {
                        out.push('\n');
                        indent(&mut out, depth);
                    }
                }
                out.push(ch);
            }
            ',' => {
                just_opened = None;
                out.push(ch);
                out.push('\n');
                indent(&mut out, depth);
            }
            ':' => {
                just_opened = None;
                out.push_str(": ");
            }
            other => {
                just_opened = None;
                out.push(other);
            }
        }
    }
    out
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}
