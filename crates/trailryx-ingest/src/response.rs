//! Writing responses, through one door.
//!
//! # Why there is a single serializer
//!
//! Response splitting is the oldest injection there is: put a CRLF in a header
//! value and the rest of your message becomes headers of its own. RFC 9112
//! names the mitigation directly, which is to restrict header output to an API
//! that filters CR and LF, and that is what this module is. No call site
//! anywhere builds a header line by concatenation, so a future call site cannot
//! reintroduce the hole.
//!
//! Nothing from a request is ever echoed into a response either: not the path,
//! not `Host`, not `User-Agent`, not `Content-Type`. There is no legitimate
//! reason to and every reason not to.
//!
//! # Why every response has a body length
//!
//! On a kept-alive connection a response of unknown length makes the client
//! either block forever or read our next response as the tail of this one.
//! Every response here carries an accurate `Content-Length`, zero where there
//! is no body, and nothing is ever compressed on the way out: `Accept-Encoding`
//! is ignored entirely, which is legal and removes the need for a compressor.

use std::io::{self, Write};

/// The statuses this server actually produces, and nothing else.
///
/// An enum rather than a number, so a call site cannot invent a status with no
/// reason phrase or pick one the OTLP retry table says nothing about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Continue,
    BadRequest,
    NotFound,
    MethodNotAllowed,
    RequestTimeout,
    LengthRequired,
    PayloadTooLarge,
    UnsupportedMediaType,
    ExpectationFailed,
    RequestHeaderFieldsTooLarge,
    NotImplemented,
    ServiceUnavailable,
    HttpVersionNotSupported,
}

impl Status {
    pub fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::Continue => 100,
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::RequestTimeout => 408,
            Self::LengthRequired => 411,
            Self::PayloadTooLarge => 413,
            Self::UnsupportedMediaType => 415,
            Self::ExpectationFailed => 417,
            Self::RequestHeaderFieldsTooLarge => 431,
            Self::NotImplemented => 501,
            Self::ServiceUnavailable => 503,
            Self::HttpVersionNotSupported => 505,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Continue => "Continue",
            Self::BadRequest => "Bad Request",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::RequestTimeout => "Request Timeout",
            Self::LengthRequired => "Length Required",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::UnsupportedMediaType => "Unsupported Media Type",
            Self::ExpectationFailed => "Expectation Failed",
            Self::RequestHeaderFieldsTooLarge => "Request Header Fields Too Large",
            Self::NotImplemented => "Not Implemented",
            Self::ServiceUnavailable => "Service Unavailable",
            Self::HttpVersionNotSupported => "HTTP Version Not Supported",
        }
    }

    /// Whether an OTLP client will try this batch again.
    ///
    /// The distinction is the difference between a five-second blip and
    /// permanent fleet-wide data loss, so it is written down next to the codes
    /// rather than left in a comment somewhere else.
    pub fn is_retryable(self) -> bool {
        matches!(self.code(), 429 | 502 | 503 | 504)
    }

    /// The `google.rpc.Code` an OTLP client expects in the `Status` body.
    fn rpc_code(self) -> i32 {
        match self {
            Self::BadRequest => 3,          // INVALID_ARGUMENT
            Self::NotFound => 5,            // NOT_FOUND
            Self::RequestTimeout => 4,      // DEADLINE_EXCEEDED
            Self::PayloadTooLarge => 8,     // RESOURCE_EXHAUSTED
            Self::ServiceUnavailable => 14, // UNAVAILABLE
            Self::NotImplemented => 12,     // UNIMPLEMENTED
            Self::MethodNotAllowed
            | Self::LengthRequired
            | Self::UnsupportedMediaType
            | Self::ExpectationFailed
            | Self::RequestHeaderFieldsTooLarge
            | Self::HttpVersionNotSupported => 3,
            Self::Ok | Self::Continue => 0,
        }
    }
}

/// The media types this server emits.
///
/// An enum rather than a string, so `body` cannot be handed a value that needs
/// validating. The single-door property of this module then holds by
/// construction rather than by a check somebody could bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Protobuf,
}

impl ContentType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Protobuf => "application/x-protobuf",
        }
    }
}

/// The longest a diagnostic message may be.
///
/// An OTLP client caps the response it will read, and a response over that cap
/// becomes a parse failure rather than a diagnosis. A kilobyte is far under any
/// client's limit and far more than a sentence needs.
const MAX_MESSAGE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// A name outside the token character set.
    BadName,
    /// A value carrying CR, LF or NUL. Rejected rather than stripped: a value
    /// that needed stripping came from somewhere it should not have.
    BadValue,
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// One response, assembled in memory and written in one go.
#[derive(Debug, Clone)]
pub struct Response {
    status: Status,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Whether the connection must close after this. Set for every rejection,
    /// because after one the byte boundary is no longer certain.
    close: bool,
}

impl Response {
    pub fn new(status: Status) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            close: false,
        }
    }

    pub fn status(&self) -> Status {
        self.status
    }

    pub fn will_close(&self) -> bool {
        self.close
    }

    pub fn closing(mut self) -> Self {
        self.close = true;
        self
    }

    /// Add a header, refusing anything that could split the message.
    pub fn header(mut self, name: &str, value: &str) -> Result<Self, HeaderError> {
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(HeaderError::BadName);
        }
        if value
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b == 0 || b < 0x20)
        {
            return Err(HeaderError::BadValue);
        }
        self.headers.push((name.to_owned(), value.to_owned()));
        Ok(self)
    }

    /// Tell a client when to come back.
    ///
    /// Seconds, built from a number, so there is nothing to validate and
    /// nothing that can fail. A date would be worse than useless: some
    /// exporters clamp a negative delta to zero, which turns throttling into a
    /// retry storm the moment two clocks disagree.
    pub fn retry_after(mut self, seconds: u32) -> Self {
        self.headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("retry-after"));
        self.headers
            .push(("Retry-After".to_owned(), seconds.to_string()));
        self
    }

    /// Say which methods a known path takes. A crate constant, never a value
    /// derived from the request.
    pub fn allow(mut self, methods: &'static str) -> Self {
        self.headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("allow"));
        self.headers.push(("Allow".to_owned(), methods.to_owned()));
        self
    }

    pub fn body(mut self, content_type: ContentType, bytes: Vec<u8>) -> Self {
        self.body = bytes;
        self.headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("content-type"));
        // Both halves are crate constants, so there is nothing here a caller
        // could have chosen and nothing to validate.
        self.headers
            .push(("Content-Type".to_owned(), content_type.as_str().to_owned()));
        self
    }

    /// An error response with the protobuf `Status` body the spec requires.
    ///
    /// A plain-text or HTML error body breaks the contract and hides the reason
    /// from whoever has to fix it.
    pub fn error(status: Status, message: &str) -> Self {
        let mut trimmed: String = message.chars().take(MAX_MESSAGE).collect();
        // Control bytes cannot reach a header from here, and they have no
        // business in a message either.
        trimmed.retain(|c| !c.is_control());
        Response::new(status)
            .body(
                ContentType::Protobuf,
                encode_rpc_status(status.rpc_code(), &trimmed),
            )
            .closing()
    }

    /// Serialise and write. One buffered write, so a response cannot be seen
    /// half-finished by a client that is about to be told to go away.
    pub fn write_to<W: Write>(&self, out: &mut W) -> io::Result<()> {
        let mut buf = Vec::with_capacity(128 + self.body.len());
        buf.extend_from_slice(
            format!(
                "HTTP/1.1 {} {}\r\n",
                self.status.code(),
                self.status.reason()
            )
            .as_bytes(),
        );
        for (name, value) in &self.headers {
            // Validated at insertion. Checked again here, because this is the
            // function that would otherwise be the hole.
            debug_assert!(name.bytes().all(is_tchar));
            debug_assert!(!value.bytes().any(|b| b == b'\r' || b == b'\n'));
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        if self.close {
            buf.extend_from_slice(b"Connection: close\r\n");
        }
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.body);
        out.write_all(&buf)?;
        out.flush()
    }

    /// `100 Continue` is an interim response: no headers, no body, no
    /// `Content-Length`, and the real response follows on the same connection.
    pub fn write_continue<W: Write>(out: &mut W) -> io::Result<()> {
        out.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        out.flush()
    }
}

// ---------------------------------------------------------------------------
// Just enough protobuf to answer
// ---------------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn put_tag(out: &mut Vec<u8>, field: u32, wire: u8) {
    put_varint(out, (u64::from(field) << 3) | u64::from(wire));
}

fn put_len_delimited(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    put_tag(out, field, 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// `google.rpc.Status { int32 code = 1; string message = 2; }`
pub fn encode_rpc_status(code: i32, message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + message.len());
    if code != 0 {
        put_tag(&mut out, 1, 0);
        // A negative code cannot occur here; the cast is the protobuf
        // encoding for a non-negative int32 either way.
        put_varint(&mut out, code as u64);
    }
    if !message.is_empty() {
        put_len_delimited(&mut out, 2, message.as_bytes());
    }
    out
}

/// `ExportTraceServiceResponse { ExportTracePartialSuccess partial_success = 1; }`
/// with `ExportTracePartialSuccess { int64 rejected_spans = 1; string error_message = 2; }`
///
/// An all-zero `partial_success` that is *present* makes some client versions
/// log an error for every export, so a full success returns no bytes at all: a
/// zero-length body is a valid encoding of the empty message.
pub fn encode_export_response(rejected_spans: u64, error_message: &str) -> Vec<u8> {
    if rejected_spans == 0 && error_message.is_empty() {
        return Vec::new();
    }
    let mut inner = Vec::with_capacity(16 + error_message.len());
    if rejected_spans != 0 {
        put_tag(&mut inner, 1, 0);
        put_varint(&mut inner, rejected_spans);
    }
    if !error_message.is_empty() {
        let clipped: String = error_message.chars().take(MAX_MESSAGE).collect();
        put_len_delimited(&mut inner, 2, clipped.as_bytes());
    }
    let mut out = Vec::with_capacity(inner.len() + 8);
    put_len_delimited(&mut out, 1, &inner);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(response: &Response) -> String {
        let mut out = Vec::new();
        response.write_to(&mut out).unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn a_value_carrying_a_newline_is_refused_not_stripped() {
        // The whole reason this module exists. A stripped value would still be
        // a value somebody chose; a refusal is a bug report.
        let r = Response::new(Status::Ok);
        for bad in ["one\r\nX-Injected: 1", "one\ntwo", "one\0two", "one\rtwo"] {
            assert_eq!(
                r.clone().header("X-A", bad).err(),
                Some(HeaderError::BadValue),
                "{bad:?} was accepted"
            );
        }
        assert!(r.header("X-A", "one two").is_ok());
    }

    #[test]
    fn a_name_outside_the_token_set_is_refused() {
        let r = Response::new(Status::Ok);
        for bad in ["X A", "", "X:A", "X\r\nA"] {
            assert_eq!(
                r.clone().header(bad, "1").err(),
                Some(HeaderError::BadName),
                "{bad:?} was accepted"
            );
        }
        assert!(r.header("X-A_b.c", "1").is_ok());
    }

    #[test]
    fn every_response_states_its_own_length() {
        // Without this a kept-alive client either blocks or reads our next
        // response as this one's tail.
        let empty = rendered(&Response::new(Status::Ok));
        assert!(empty.contains("Content-Length: 0\r\n"), "{empty}");

        let with_body =
            rendered(&Response::new(Status::Ok).body(ContentType::Protobuf, vec![1, 2, 3]));
        assert!(with_body.contains("Content-Length: 3\r\n"), "{with_body}");
        assert!(
            with_body.contains("Content-Type: application/x-protobuf\r\n"),
            "{with_body}"
        );
    }

    #[test]
    fn a_rejection_always_closes_and_carries_a_protobuf_status() {
        let r = Response::error(Status::PayloadTooLarge, "the body exceeds 16 MiB");
        assert!(r.will_close());
        let text = rendered(&r);
        assert!(
            text.starts_with("HTTP/1.1 413 Payload Too Large\r\n"),
            "{text}"
        );
        assert!(text.contains("Connection: close\r\n"), "{text}");
        assert!(
            text.contains("Content-Type: application/x-protobuf\r\n"),
            "{text}"
        );
        assert!(text.contains("the body exceeds 16 MiB"), "{text}");
    }

    #[test]
    fn a_message_cannot_smuggle_control_bytes_into_the_body() {
        let r = Response::error(Status::BadRequest, "a\r\nb\0c");
        let text = rendered(&r);
        // Exactly one blank line, the one separating headers from body.
        assert_eq!(text.matches("\r\n\r\n").count(), 1, "{text}");
    }

    #[test]
    fn the_retry_table_is_the_specifications_and_not_a_guess() {
        // The one that matters: backpressure must be retryable, or a blip
        // becomes permanent loss across a fleet.
        assert!(Status::ServiceUnavailable.is_retryable());
        assert!(!Status::BadRequest.is_retryable());
        assert!(!Status::UnsupportedMediaType.is_retryable());
        assert!(!Status::PayloadTooLarge.is_retryable());
        assert!(!Status::NotFound.is_retryable());
    }

    #[test]
    fn a_full_success_says_nothing_at_all() {
        // A present-but-empty partial_success makes some clients log an error
        // per export, for data that arrived intact.
        assert!(encode_export_response(0, "").is_empty());
    }

    #[test]
    fn a_partial_success_encodes_where_a_client_looks_for_it() {
        let bytes = encode_export_response(2, "two spans had no trace id");
        // field 1, wire type 2: the partial_success submessage.
        assert_eq!(bytes[0], 0x0a);
        let len = usize::from(bytes[1]);
        assert_eq!(bytes.len(), 2 + len);
        let inner = &bytes[2..];
        // field 1 varint = rejected_spans = 2
        assert_eq!(&inner[..2], &[0x08, 0x02]);
        // field 2 length-delimited = error_message
        assert_eq!(inner[2], 0x12);
        assert!(
            String::from_utf8_lossy(inner).contains("two spans had no trace id"),
            "{inner:?}"
        );
    }

    #[test]
    fn an_rpc_status_carries_the_code_a_client_switches_on() {
        // INVALID_ARGUMENT for a malformed batch, RESOURCE_EXHAUSTED for a cap,
        // UNAVAILABLE for backpressure.
        assert_eq!(encode_rpc_status(3, "")[..2], [0x08, 0x03]);
        assert_eq!(Status::BadRequest.rpc_code(), 3);
        assert_eq!(Status::PayloadTooLarge.rpc_code(), 8);
        assert_eq!(Status::ServiceUnavailable.rpc_code(), 14);
        assert_eq!(Status::NotImplemented.rpc_code(), 12);
    }

    #[test]
    fn an_interim_continue_has_no_length_and_no_headers() {
        let mut out = Vec::new();
        Response::write_continue(&mut out).unwrap();
        assert_eq!(out, b"HTTP/1.1 100 Continue\r\n\r\n");
    }
}
