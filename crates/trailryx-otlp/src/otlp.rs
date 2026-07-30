//! OTLP trace messages, decoded into something we can reason about.
//!
//! Field numbers come from `opentelemetry/proto/trace/v1/trace.proto` and
//! `opentelemetry/proto/common/v1/common.proto`, which are part of OTLP 1.0 and
//! therefore stable: the protocol promises these numbers will not be reused or
//! renumbered. That promise is what makes it reasonable to write the field
//! numbers down by hand instead of generating them, and it is the same promise
//! every generated decoder relies on.
//!
//! Unknown fields are skipped, not refused. A newer collector will send fields
//! this version has never heard of, and refusing them would mean the store
//! stops working the day OTLP grows. They are counted instead, and the count
//! travels with the batch, because a record mapped from a message we only
//! partly understood is a partial view of what was said.
//!
//! # Limits
//!
//! Every repeated field here is attacker-controlled, so every one is bounded.
//! Exceeding a bound drops the item and increments a counter; it does not fail
//! the batch. The store is fail-open towards an emitter's traffic, and a loss
//! becomes a record rather than a silence.

use crate::protobuf::{Reader, Stats, WireError, WireType};

/// Bounds on a single decode. Attacker-controlled input needs all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_spans: usize,
    pub max_attributes: usize,
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
    pub max_events: usize,
    pub max_array_items: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_spans: 65_536,
            max_attributes: 512,
            max_key_bytes: 256,
            max_value_bytes: 256 * 1024,
            max_events: 256,
            max_array_items: 1024,
        }
    }
}

/// What a decode had to leave out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dropped {
    pub spans: u32,
    pub attributes: u32,
    pub events: u32,
    pub oversize_values: u32,
    /// Strings whose bytes were not valid UTF-8. The bytes are kept as bytes
    /// rather than lost or repaired: repairing would change what the emitter
    /// said, and losing would hide it.
    pub invalid_utf8: u32,
}

impl Dropped {
    pub fn any(self) -> bool {
        self.spans + self.attributes + self.events + self.oversize_values + self.invalid_utf8 > 0
    }
}

/// An OTLP `AnyValue`.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// The field was present but empty, which OTLP uses and which is not the
    /// same as absent.
    Empty,
    Str(String),
    Bool(bool),
    Int(i64),
    Double(f64),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<Attr>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            // Some SDKs emit token counts as doubles. Accept a double that is
            // exactly an integer; refuse one that is not, rather than round
            // somebody's numbers on their behalf.
            Self::Double(d) if d.fract() == 0.0 && d.is_finite() => Some(*d as i64),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Double(d) => Some(*d),
            Self::Int(i) => Some(*i as f64),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attr {
    pub key: String,
    pub value: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    Unspecified,
    Internal,
    Server,
    Client,
    Producer,
    Consumer,
}

impl SpanKind {
    pub(crate) fn from_wire(v: u64) -> Self {
        match v {
            1 => Self::Internal,
            2 => Self::Server,
            3 => Self::Client,
            4 => Self::Producer,
            5 => Self::Consumer,
            _ => Self::Unspecified,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    Unset,
    Ok,
    Error,
}

impl StatusCode {
    pub(crate) fn from_wire(v: u64) -> Self {
        match v {
            1 => Self::Ok,
            2 => Self::Error,
            _ => Self::Unset,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub time_unix_nano: u64,
    pub name: String,
    pub attributes: Vec<Attr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Span {
    pub trace_id: Vec<u8>,
    pub span_id: Vec<u8>,
    pub parent_span_id: Vec<u8>,
    pub name: String,
    pub kind: SpanKind,
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
    pub attributes: Vec<Attr>,
    pub events: Vec<Event>,
    pub status_code: StatusCode,
    pub status_message: String,
}

impl Span {
    pub fn attr(&self, key: &str) -> Option<&Value> {
        self.attributes
            .iter()
            .find(|a| a.key == key)
            .map(|a| &a.value)
    }

    /// Whether this span names a parent.
    ///
    /// All-zero counts as absent, exactly as it does for a trace id. The OTLP
    /// specification defines an all-zero span id as invalid, and emitters do
    /// write the field out as zeros rather than omitting it. Treating those eight
    /// bytes as a real name manufactured causal edges: two unrelated roots, each
    /// naming the invalid parent, became children of whichever span had claimed
    /// the all-zero id, and `event_type` flipped from a request arriving to one
    /// agent delegating to another, which is the edge an auditor follows.
    pub fn has_parent(&self) -> bool {
        !is_absent(&self.parent_span_id)
    }

    /// This span's own name, or nothing if it did not give a valid one.
    pub fn own_id(&self) -> Option<&[u8]> {
        (!is_absent(&self.span_id)).then_some(self.span_id.as_slice())
    }
}

/// Empty, or all zeros, which OTLP defines as an invalid trace or span id.
fn is_absent(id: &[u8]) -> bool {
    id.is_empty() || id.iter().all(|b| *b == 0)
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScopeSpans {
    pub scope_name: String,
    pub scope_version: String,
    pub spans: Vec<Span>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResourceSpans {
    pub resource: Vec<Attr>,
    pub scopes: Vec<ScopeSpans>,
}

impl ResourceSpans {
    pub fn attr(&self, key: &str) -> Option<&Value> {
        self.resource
            .iter()
            .find(|a| a.key == key)
            .map(|a| &a.value)
    }
}

/// One decoded `ExportTraceServiceRequest`, with what it cost to decode.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceRequest {
    pub resource_spans: Vec<ResourceSpans>,
    pub dropped: Dropped,
    pub padded_varints: u32,
    pub unknown_fields: u32,
}

impl TraceRequest {
    pub fn span_count(&self) -> usize {
        self.resource_spans
            .iter()
            .flat_map(|r| r.scopes.iter())
            .map(|s| s.spans.len())
            .sum()
    }
}

/// Decode an `ExportTraceServiceRequest`.
pub fn decode_trace_request(buf: &[u8], limits: Limits) -> Result<TraceRequest, WireError> {
    let stats = Stats::default();
    let mut dropped = Dropped::default();
    let mut reader = Reader::new(buf, &stats);
    let mut resource_spans = Vec::new();
    let mut spans_so_far = 0usize;

    while !reader.is_empty() {
        let (field, wire) = reader.tag()?;
        match (field, wire) {
            (1, WireType::Bytes) => {
                let mut sub = reader.nested()?;
                resource_spans.push(decode_resource_spans(
                    &mut sub,
                    limits,
                    &mut dropped,
                    &mut spans_so_far,
                )?);
            }
            _ => reader.skip(wire)?,
        }
    }

    Ok(TraceRequest {
        resource_spans,
        dropped,
        padded_varints: stats.padded_varints(),
        unknown_fields: stats.unknown_fields(),
    })
}

fn decode_resource_spans(
    r: &mut Reader<'_>,
    limits: Limits,
    dropped: &mut Dropped,
    spans_so_far: &mut usize,
) -> Result<ResourceSpans, WireError> {
    let mut resource = Vec::new();
    let mut scopes = Vec::new();
    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (1, WireType::Bytes) => {
                let mut sub = r.nested()?;
                resource = decode_resource(&mut sub, limits, dropped)?;
            }
            (2, WireType::Bytes) => {
                let mut sub = r.nested()?;
                scopes.push(decode_scope_spans(&mut sub, limits, dropped, spans_so_far)?);
            }
            // 3 is schema_url: a version marker for the attribute names, not
            // data about the run. It changes how a mapper should read the
            // attributes, which is stage 6 work we do not do yet, so it is
            // skipped like any field we cannot act on.
            _ => r.skip(wire)?,
        }
    }
    Ok(ResourceSpans { resource, scopes })
}

fn decode_resource(
    r: &mut Reader<'_>,
    limits: Limits,
    dropped: &mut Dropped,
) -> Result<Vec<Attr>, WireError> {
    let mut attrs = Vec::new();
    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (1, WireType::Bytes) => {
                let mut sub = r.nested()?;
                push_attr(
                    &mut attrs,
                    decode_attr(&mut sub, limits, dropped)?,
                    limits,
                    dropped,
                );
            }
            _ => r.skip(wire)?,
        }
    }
    Ok(attrs)
}

fn decode_scope_spans(
    r: &mut Reader<'_>,
    limits: Limits,
    dropped: &mut Dropped,
    spans_so_far: &mut usize,
) -> Result<ScopeSpans, WireError> {
    let mut scope_name = String::new();
    let mut scope_version = String::new();
    let mut spans = Vec::new();
    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (1, WireType::Bytes) => {
                let mut sub = r.nested()?;
                let (name, version) = decode_scope(&mut sub)?;
                scope_name = name;
                scope_version = version;
            }
            (2, WireType::Bytes) => {
                if *spans_so_far >= limits.max_spans {
                    dropped.spans = dropped.spans.saturating_add(1);
                    r.bytes()?;
                    continue;
                }
                let mut sub = r.nested()?;
                if let Some(span) = decode_span(&mut sub, limits, dropped)? {
                    spans.push(span);
                }
                // Counted against the cap whether or not it survived, exactly as a
                // span dropped for the cap itself is: the work of reading it was
                // done, and a batch of a million malformed spans must not get a free
                // pass past `max_spans`.
                *spans_so_far += 1;
            }
            _ => r.skip(wire)?,
        }
    }
    Ok(ScopeSpans {
        scope_name,
        scope_version,
        spans,
    })
}

fn decode_scope(r: &mut Reader<'_>) -> Result<(String, String), WireError> {
    let mut name = String::new();
    let mut version = String::new();
    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (1, WireType::Bytes) => name = lossy_string(r.bytes()?),
            (2, WireType::Bytes) => version = lossy_string(r.bytes()?),
            _ => r.skip(wire)?,
        }
    }
    Ok((name, version))
}

/// One span, or none.
///
/// `None` for a span whose trace or span id is present at a length OTLP does not
/// define. The JSON twin has always dropped that span and this one kept it, so the
/// two transports disagreed about which spans became records: measured, a four-byte
/// trace id gave one record on the wire and none in JSON. That is the same class as
/// the depth bound that diverged in both directions, and the same answer, which is
/// that the parity has to be a property of the code rather than of which reader you
/// happened to use.
///
/// Dropping is the safe side of the disagreement and not merely the JSON side.
/// Keeping a wrong-length id means deriving a run identifier from four bytes of
/// something, and an unreadable `parent_span_id` treated as absent turns a
/// delegation into a request arriving, which is exactly the defect `MAPPER_VERSION`
/// 2 was cut for. A conforming emitter never sends another length: absent and
/// all-zero are handled separately, as absent.
fn decode_span(
    r: &mut Reader<'_>,
    limits: Limits,
    dropped: &mut Dropped,
) -> Result<Option<Span>, WireError> {
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

    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (1, WireType::Bytes) => span.trace_id = r.bytes()?.to_vec(),
            (2, WireType::Bytes) => span.span_id = r.bytes()?.to_vec(),
            // 3 is trace_state: W3C vendor data, free text by construction, so
            // it has no home in the metadata plane and nothing reads it here.
            (4, WireType::Bytes) => span.parent_span_id = r.bytes()?.to_vec(),
            (5, WireType::Bytes) => span.name = lossy_string(r.bytes()?),
            (6, WireType::Varint) => span.kind = SpanKind::from_wire(r.varint()?),
            (7, WireType::Fixed64) => span.start_time_unix_nano = r.fixed64()?,
            (8, WireType::Fixed64) => span.end_time_unix_nano = r.fixed64()?,
            (9, WireType::Bytes) => {
                let mut sub = r.nested()?;
                let attr = decode_attr(&mut sub, limits, dropped)?;
                push_attr(&mut span.attributes, attr, limits, dropped);
            }
            (11, WireType::Bytes) => {
                if span.events.len() >= limits.max_events {
                    dropped.events = dropped.events.saturating_add(1);
                    r.bytes()?;
                    continue;
                }
                let mut sub = r.nested()?;
                span.events.push(decode_event(&mut sub, limits, dropped)?);
            }
            (15, WireType::Bytes) => {
                let mut sub = r.nested()?;
                let (code, message) = decode_status(&mut sub)?;
                span.status_code = code;
                span.status_message = message;
            }
            _ => r.skip(wire)?,
        }
    }
    if !well_formed_id(&span.trace_id, TRACE_ID_BYTES)
        || !well_formed_id(&span.span_id, SPAN_ID_BYTES)
    {
        dropped.spans = dropped.spans.saturating_add(1);
        return Ok(None);
    }
    // A parent named at the wrong length is the reclassification hazard, so it costs
    // the span too rather than being quietly read as no parent.
    if !well_formed_id(&span.parent_span_id, SPAN_ID_BYTES) {
        dropped.spans = dropped.spans.saturating_add(1);
        return Ok(None);
    }
    Ok(Some(span))
}

/// Sixteen bytes for a trace, eight for a span, by the OTLP specification.
const TRACE_ID_BYTES: usize = 16;
const SPAN_ID_BYTES: usize = 8;

/// Whether an id is absent or exactly the length OTLP defines.
///
/// Absent counts as well formed: an emitter omitting a parent, or writing it as all
/// zeros, is saying there is no parent, and `is_absent` already reads both that way.
fn well_formed_id(id: &[u8], expected: usize) -> bool {
    is_absent(id) || id.len() == expected
}

fn decode_event(
    r: &mut Reader<'_>,
    limits: Limits,
    dropped: &mut Dropped,
) -> Result<Event, WireError> {
    let mut event = Event {
        time_unix_nano: 0,
        name: String::new(),
        attributes: Vec::new(),
    };
    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (1, WireType::Fixed64) => event.time_unix_nano = r.fixed64()?,
            (2, WireType::Bytes) => event.name = lossy_string(r.bytes()?),
            (3, WireType::Bytes) => {
                let mut sub = r.nested()?;
                let attr = decode_attr(&mut sub, limits, dropped)?;
                push_attr(&mut event.attributes, attr, limits, dropped);
            }
            _ => r.skip(wire)?,
        }
    }
    Ok(event)
}

fn decode_status(r: &mut Reader<'_>) -> Result<(StatusCode, String), WireError> {
    let mut code = StatusCode::Unset;
    let mut message = String::new();
    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (2, WireType::Bytes) => message = lossy_string(r.bytes()?),
            (3, WireType::Varint) => code = StatusCode::from_wire(r.varint()?),
            _ => r.skip(wire)?,
        }
    }
    Ok((code, message))
}

fn decode_attr(
    r: &mut Reader<'_>,
    limits: Limits,
    dropped: &mut Dropped,
) -> Result<Attr, WireError> {
    let mut key = String::new();
    let mut value = Value::Empty;
    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (1, WireType::Bytes) => {
                let raw = r.bytes()?;
                key = lossy_string(&raw[..raw.len().min(limits.max_key_bytes)]);
            }
            (2, WireType::Bytes) => {
                let mut sub = r.nested()?;
                value = decode_value(&mut sub, limits, dropped)?;
            }
            _ => r.skip(wire)?,
        }
    }
    Ok(Attr { key, value })
}

fn decode_value(
    r: &mut Reader<'_>,
    limits: Limits,
    dropped: &mut Dropped,
) -> Result<Value, WireError> {
    let mut value = Value::Empty;
    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (1, WireType::Bytes) => {
                let raw = r.bytes()?;
                if raw.len() > limits.max_value_bytes {
                    dropped.oversize_values = dropped.oversize_values.saturating_add(1);
                    value = Value::Empty;
                } else {
                    value = match std::str::from_utf8(raw) {
                        Ok(s) => Value::Str(s.to_owned()),
                        Err(_) => {
                            // Not repaired and not discarded. A replacement
                            // character would change what the emitter said,
                            // and this is a record store.
                            dropped.invalid_utf8 = dropped.invalid_utf8.saturating_add(1);
                            Value::Bytes(raw.to_vec())
                        }
                    };
                }
            }
            (2, WireType::Varint) => value = Value::Bool(r.varint()? != 0),
            (3, WireType::Varint) => value = Value::Int(r.varint()? as i64),
            (4, WireType::Fixed64) => value = Value::Double(f64::from_bits(r.fixed64()?)),
            (5, WireType::Bytes) => {
                let mut sub = r.nested()?;
                value = Value::Array(decode_array(&mut sub, limits, dropped)?);
            }
            (6, WireType::Bytes) => {
                let mut sub = r.nested()?;
                value = Value::Map(decode_kvlist(&mut sub, limits, dropped)?);
            }
            (7, WireType::Bytes) => {
                let raw = r.bytes()?;
                if raw.len() > limits.max_value_bytes {
                    dropped.oversize_values = dropped.oversize_values.saturating_add(1);
                } else {
                    value = Value::Bytes(raw.to_vec());
                }
            }
            _ => r.skip(wire)?,
        }
    }
    Ok(value)
}

fn decode_array(
    r: &mut Reader<'_>,
    limits: Limits,
    dropped: &mut Dropped,
) -> Result<Vec<Value>, WireError> {
    let mut items = Vec::new();
    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (1, WireType::Bytes) => {
                if items.len() >= limits.max_array_items {
                    dropped.attributes = dropped.attributes.saturating_add(1);
                    r.bytes()?;
                    continue;
                }
                let mut sub = r.nested()?;
                items.push(decode_value(&mut sub, limits, dropped)?);
            }
            _ => r.skip(wire)?,
        }
    }
    Ok(items)
}

fn decode_kvlist(
    r: &mut Reader<'_>,
    limits: Limits,
    dropped: &mut Dropped,
) -> Result<Vec<Attr>, WireError> {
    let mut attrs = Vec::new();
    while !r.is_empty() {
        let (field, wire) = r.tag()?;
        match (field, wire) {
            (1, WireType::Bytes) => {
                let mut sub = r.nested()?;
                let attr = decode_attr(&mut sub, limits, dropped)?;
                push_attr(&mut attrs, attr, limits, dropped);
            }
            _ => r.skip(wire)?,
        }
    }
    Ok(attrs)
}

pub(crate) fn push_attr(into: &mut Vec<Attr>, attr: Attr, limits: Limits, dropped: &mut Dropped) {
    if into.len() >= limits.max_attributes {
        dropped.attributes = dropped.attributes.saturating_add(1);
        return;
    }
    into.push(attr);
}

/// A protobuf `string` field whose bytes were not valid UTF-8.
///
/// Only used for fields that are structural rather than content: a span name, a
/// scope name, a status message. Those go to the payload plane anyway, and
/// losing the whole span over one bad byte in a name would fail an emitter for
/// something nobody reads.
pub(crate) fn lossy_string(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}
