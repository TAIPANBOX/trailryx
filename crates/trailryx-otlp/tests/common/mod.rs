//! An OTLP encoder, so the tests exercise real bytes rather than structs.
//!
//! Decoding a struct we built ourselves proves nothing about a decoder. These
//! helpers write the wire format the way a collector writes it, field number by
//! field number, so every test below starts where a real batch starts.

#![allow(dead_code)]

pub fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn tag(field: u32, wire: u8) -> Vec<u8> {
    varint((u64::from(field) << 3) | u64::from(wire))
}

pub fn len_delim(field: u32, body: &[u8]) -> Vec<u8> {
    let mut out = tag(field, 2);
    out.extend_from_slice(&varint(body.len() as u64));
    out.extend_from_slice(body);
    out
}

pub fn string_field(field: u32, s: &str) -> Vec<u8> {
    len_delim(field, s.as_bytes())
}

pub fn varint_field(field: u32, value: u64) -> Vec<u8> {
    let mut out = tag(field, 0);
    out.extend_from_slice(&varint(value));
    out
}

pub fn fixed64_field(field: u32, value: u64) -> Vec<u8> {
    let mut out = tag(field, 1);
    out.extend_from_slice(&value.to_le_bytes());
    out
}

// --- AnyValue ---------------------------------------------------------------

pub fn any_string(s: &str) -> Vec<u8> {
    string_field(1, s)
}

pub fn any_bytes(b: &[u8]) -> Vec<u8> {
    len_delim(1, b)
}

pub fn any_bool(b: bool) -> Vec<u8> {
    varint_field(2, u64::from(b))
}

pub fn any_int(i: i64) -> Vec<u8> {
    varint_field(3, i as u64)
}

pub fn any_double(d: f64) -> Vec<u8> {
    fixed64_field(4, d.to_bits())
}

pub fn any_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        body.extend_from_slice(&len_delim(1, item));
    }
    len_delim(5, &body)
}

pub fn any_map(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (key, value) in pairs {
        body.extend_from_slice(&len_delim(1, &kv(key, value.clone())));
    }
    len_delim(6, &body)
}

/// One `KeyValue`.
pub fn kv(key: &str, value: Vec<u8>) -> Vec<u8> {
    let mut out = string_field(1, key);
    out.extend_from_slice(&len_delim(2, &value));
    out
}

// --- Span -------------------------------------------------------------------

pub struct SpanBuilder {
    trace_id: Vec<u8>,
    span_id: Vec<u8>,
    parent_span_id: Vec<u8>,
    name: String,
    kind: u64,
    start: u64,
    end: u64,
    attributes: Vec<Vec<u8>>,
    events: Vec<Vec<u8>>,
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

    pub fn times(mut self, start: u64, end: u64) -> Self {
        self.start = start;
        self.end = end;
        self
    }

    pub fn attr(mut self, key: &str, value: Vec<u8>) -> Self {
        self.attributes.push(kv(key, value));
        self
    }

    pub fn str_attr(self, key: &str, value: &str) -> Self {
        self.attr(key, any_string(value))
    }

    pub fn int_attr(self, key: &str, value: i64) -> Self {
        self.attr(key, any_int(value))
    }

    pub fn event(mut self, at: u64, name: &str, attrs: &[(&str, Vec<u8>)]) -> Self {
        let mut body = fixed64_field(1, at);
        body.extend_from_slice(&string_field(2, name));
        for (key, value) in attrs {
            body.extend_from_slice(&len_delim(3, &kv(key, value.clone())));
        }
        self.events.push(body);
        self
    }

    pub fn status(mut self, code: u64, message: &str) -> Self {
        self.status = Some((code, message.to_owned()));
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = len_delim(1, &self.trace_id);
        out.extend_from_slice(&len_delim(2, &self.span_id));
        if !self.parent_span_id.is_empty() {
            out.extend_from_slice(&len_delim(4, &self.parent_span_id));
        }
        out.extend_from_slice(&string_field(5, &self.name));
        out.extend_from_slice(&varint_field(6, self.kind));
        out.extend_from_slice(&fixed64_field(7, self.start));
        out.extend_from_slice(&fixed64_field(8, self.end));
        for attr in &self.attributes {
            out.extend_from_slice(&len_delim(9, attr));
        }
        for event in &self.events {
            out.extend_from_slice(&len_delim(11, event));
        }
        if let Some((code, message)) = &self.status {
            let mut status = string_field(2, message);
            status.extend_from_slice(&varint_field(3, *code));
            out.extend_from_slice(&len_delim(15, &status));
        }
        out
    }
}

/// A whole `ExportTraceServiceRequest`.
pub fn request(resource: &[(&str, Vec<u8>)], scope: &str, spans: &[SpanBuilder]) -> Vec<u8> {
    let mut resource_body = Vec::new();
    for (key, value) in resource {
        resource_body.extend_from_slice(&len_delim(1, &kv(key, value.clone())));
    }

    let mut scope_spans = len_delim(1, &string_field(1, scope));
    for span in spans {
        scope_spans.extend_from_slice(&len_delim(2, &span.encode()));
    }

    let mut resource_spans = len_delim(1, &resource_body);
    resource_spans.extend_from_slice(&len_delim(2, &scope_spans));

    len_delim(1, &resource_spans)
}

/// The resource a stock SDK attaches.
pub fn service(name: &str) -> Vec<(&str, Vec<u8>)> {
    vec![
        ("service.name", any_string(name)),
        ("telemetry.sdk.language", any_string("python")),
    ]
}
