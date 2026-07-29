//! Reading a request, strictly.
//!
//! # Strict on purpose, and it is not pedantry
//!
//! Every rule here that looks fussy is a rule whose absence is a named
//! vulnerability class. The one that matters most: this server will sit behind
//! a reverse proxy, because it has no TLS, and the moment there are two parsers
//! in a row any disagreement between them about where a message ends becomes
//! request smuggling. The defence is not to be clever about ambiguity, it is to
//! refuse to have an opinion: anything the specification permits a recipient to
//! interpret two ways is a 400 and a closed connection.
//!
//! So, concretely:
//!
//! - CRLF only. A bare LF is not a line ending here even though RFC 9112 lets a
//!   recipient recognise one, because the proxy in front might not.
//! - `Transfer-Encoding` in any form is 501. There is no chunk parser, no chunk
//!   extensions and no trailer section, which deletes that whole family.
//! - `Content-Length` is validated digit by digit before it is parsed, and a
//!   second one is a rejection rather than a choice between them.
//! - No autocorrection anywhere. Nothing is trimmed, re-encoded, lowercased or
//!   repaired before the decision about validity is taken.
//!
//! # Bytes, never strings
//!
//! Parsing happens on `&[u8]` throughout. `from_utf8_lossy` would replace a
//! hostile byte with a valid one, `trim` would strip more than the grammar
//! allows, and `to_lowercase` on a non-ASCII byte would change its length. None
//! of the three appears on this path.
//!
//! # Nothing is sized from a client's number
//!
//! No buffer here is allocated from `Content-Length` or from any other length
//! the client chose. The declared length is compared against the cap first and
//! the buffer grows in bounded steps as bytes actually arrive.

use crate::config::Config;
use crate::response::Status;
use std::io::{self, Read};
use std::time::{Duration, Instant};

/// Why a request was refused, with the status to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reject {
    pub status: Status,
    pub why: &'static str,
}

impl Reject {
    fn new(status: Status, why: &'static str) -> Self {
        Self { status, why }
    }
}

/// The method, narrowed to what routing needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Post,
    /// Anything else that is a syntactically valid token. Kept as one variant
    /// because the only thing routing does with it is answer 405.
    Other,
}

/// A parsed head. The body is read separately, after the caller has decided
/// whether it wants one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub method: Method,
    /// Percent-decoded once, after grammar validation.
    pub path: String,
    /// `None` when the request carried no `Content-Length` at all.
    ///
    /// Deliberately not collapsed into zero. "I am sending nothing" and "I
    /// meant to send something and did not say how much" are different
    /// messages that need different answers, and folding them together made an
    /// SDK posting a legitimate empty export get told its length was missing.
    pub declared_length: Option<u64>,
    pub content_type: Option<Vec<u8>>,
    pub content_encoding: Option<Vec<u8>>,
    pub expect_continue: bool,
    pub close_requested: bool,
}

impl Head {
    /// How many body bytes to read. Absent framing means none.
    pub fn body_length(&self) -> u64 {
        self.declared_length.unwrap_or(0)
    }
}

/// What reading a head produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    Head(Head),
    Refused(Reject),
    /// The peer closed cleanly between requests. Not an error.
    Eof,
}

/// Why a body read ended badly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    /// A rejection to report to the client.
    Refused(Reject),
    /// The peer vanished mid-body. Nothing may be handed onward: `accept` cannot
    /// tell a truncated batch from a small one, so this is the only place a
    /// half-written record can be prevented.
    Truncated,
}

/// A connection's read side, with its buffer and its budgets.
#[derive(Debug)]
pub struct Wire<S> {
    stream: S,
    buf: Vec<u8>,
    /// Bytes in `buf` that have been read from the socket.
    filled: usize,
    /// Bytes in `buf` already consumed by a previous message.
    at: usize,
    read_timeout: Duration,
}

/// How much room the buffer has for a head. Sized once, from configuration,
/// never from a client.
const READ_CHUNK: usize = 16 * 1024;

/// How long a body gets before the rate floor starts asking questions.
///
/// Long enough that a legitimate client whose first packet is small and whose
/// second is delayed by an ordinary retransmit is not punished for it.
const RATE_GRACE: Duration = Duration::from_secs(2);

impl<S: Read> Wire<S> {
    pub fn new(stream: S, config: &Config) -> Self {
        Self {
            stream,
            // One allocation, big enough for the largest head the config
            // allows plus a read chunk of body that arrives with it.
            buf: vec![0u8; config.max_header_section + READ_CHUNK],
            filled: 0,
            at: 0,
            read_timeout: config.read_timeout,
        }
    }

    /// Bytes already read but not yet consumed.
    ///
    /// Asked after a response is written: anything left is either a broken
    /// client or the attacker's next request, and either way the connection
    /// closes rather than being reused.
    pub fn buffered(&self) -> usize {
        self.filled - self.at
    }

    /// Drop consumed bytes so the buffer does not creep across requests.
    fn compact(&mut self) {
        if self.at > 0 {
            self.buf.copy_within(self.at..self.filled, 0);
            self.filled -= self.at;
            self.at = 0;
        }
    }

    /// One read, classified.
    ///
    /// `WouldBlock` and `TimedOut` are both a socket timeout on different
    /// platforms, and treating only one of them as such is the bug that makes a
    /// slowloris defence not work on half the machines it runs on.
    fn fill(&mut self, deadline: Instant) -> Result<usize, Reject> {
        if Instant::now() >= deadline {
            return Err(Reject::new(Status::RequestTimeout, "the deadline passed"));
        }
        if self.filled == self.buf.len() {
            return Err(Reject::new(
                Status::RequestHeaderFieldsTooLarge,
                "the head does not fit the buffer",
            ));
        }
        loop {
            match self.stream.read(&mut self.buf[self.filled..]) {
                Ok(0) => return Ok(0),
                Ok(n) => {
                    self.filled += n;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(Reject::new(Status::RequestTimeout, "the peer went quiet"));
                }
                Err(_) => return Err(Reject::new(Status::BadRequest, "the connection failed")),
            }
        }
    }

    /// Read and parse one head.
    pub fn read_head(&mut self, config: &Config, deadline: Instant) -> Incoming {
        self.compact();
        let end = match self.find_head_end(config, deadline) {
            Ok(Some(end)) => end,
            Ok(None) => return Incoming::Eof,
            Err(reject) => return Incoming::Refused(reject),
        };
        let head = self.buf[..end].to_vec();
        self.at = end;
        match parse_head(&head, config) {
            Ok(head) => Incoming::Head(head),
            Err(reject) => Incoming::Refused(reject),
        }
    }

    /// Walk lines until the empty one, refusing anything that is not CRLF.
    ///
    /// `Ok(None)` means the peer closed before sending anything, which on a
    /// kept-alive connection is how a client says goodbye.
    fn find_head_end(
        &mut self,
        config: &Config,
        deadline: Instant,
    ) -> Result<Option<usize>, Reject> {
        let mut scan = 0usize;
        let mut line_start = 0usize;
        loop {
            while scan < self.filled {
                if scan >= config.max_header_section {
                    return Err(Reject::new(
                        Status::RequestHeaderFieldsTooLarge,
                        "the header section exceeds its cap",
                    ));
                }
                match self.buf[scan] {
                    // Reached only when the LF was not preceded by CR: a CRLF
                    // pair is always consumed together below.
                    b'\n' => {
                        return Err(Reject::new(
                            Status::BadRequest,
                            "a bare LF is not a line ending",
                        ));
                    }
                    b'\r' => {
                        if scan + 1 >= self.filled {
                            break; // need the next byte to know
                        }
                        if self.buf[scan + 1] != b'\n' {
                            return Err(Reject::new(
                                Status::BadRequest,
                                "a CR that is not part of CRLF",
                            ));
                        }
                        if scan == line_start {
                            return Ok(Some(scan + 2));
                        }
                        scan += 2;
                        line_start = scan;
                    }
                    0 => {
                        return Err(Reject::new(
                            Status::BadRequest,
                            "a NUL in the header section",
                        ));
                    }
                    _ => scan += 1,
                }
            }
            if self.fill(deadline)? == 0 {
                // EOF. Clean only if nothing at all had arrived.
                return if self.filled == 0 {
                    Ok(None)
                } else {
                    Err(Reject::new(Status::BadRequest, "the head is incomplete"))
                };
            }
        }
    }

    /// Read exactly `length` bytes of body.
    ///
    /// The buffer grows in bounded steps as bytes arrive, never to the declared
    /// length up front. A rate floor ends a slow-body attack long before the
    /// body deadline does.
    pub fn read_body(
        &mut self,
        length: u64,
        config: &Config,
        deadline: Instant,
    ) -> Result<Vec<u8>, BodyError> {
        let length = usize::try_from(length).map_err(|_| {
            BodyError::Refused(Reject::new(
                Status::PayloadTooLarge,
                "the declared length exceeds this machine's addressable range",
            ))
        })?;
        if length > config.max_body {
            return Err(BodyError::Refused(Reject::new(
                Status::PayloadTooLarge,
                "the declared length exceeds the body cap",
            )));
        }

        let mut body: Vec<u8> = Vec::new();
        let started = Instant::now();

        // Whatever arrived alongside the head.
        let ready = (self.filled - self.at).min(length);
        body.extend_from_slice(&self.buf[self.at..self.at + ready]);
        self.at += ready;

        while body.len() < length {
            self.compact();
            if Instant::now() >= deadline {
                return Err(BodyError::Refused(Reject::new(
                    Status::RequestTimeout,
                    "the body deadline passed",
                )));
            }
            // Judged in milliseconds, and gated only on a grace period.
            //
            // The first version also required eight kilobytes to have arrived
            // before it would look, and truncated the elapsed time to whole
            // seconds. Between them that meant the check could not fire until
            // about eight seconds had passed, by which point the body deadline
            // was doing all the work and this was decoration. A rate floor that
            // cannot fire is worse than no rate floor, because the comment
            // above it says otherwise.
            let elapsed = started.elapsed();
            if elapsed >= RATE_GRACE {
                let required = (config.min_body_rate as u128 * elapsed.as_millis()) / 1000;
                if (body.len() as u128) < required {
                    return Err(BodyError::Refused(Reject::new(
                        Status::RequestTimeout,
                        "the body is arriving below the minimum rate",
                    )));
                }
            }

            let n = match self.fill(deadline) {
                Ok(n) => n,
                Err(reject) => return Err(BodyError::Refused(reject)),
            };
            if n == 0 {
                // The peer stopped mid-body. Nothing partial goes onward.
                return Err(BodyError::Truncated);
            }
            let take = (self.filled - self.at).min(length - body.len());
            body.extend_from_slice(&self.buf[self.at..self.at + take]);
            self.at += take;
        }
        Ok(body)
    }

    /// Read and throw away, bounded, so a close does not become an RST that
    /// erases the response we just wrote from the client's receive buffer.
    pub fn drain_briefly(&mut self, budget: usize, deadline: Instant) {
        let mut seen = self.filled - self.at;
        self.at = self.filled;
        while seen < budget && Instant::now() < deadline {
            self.compact();
            match self.fill(deadline) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    seen += n;
                    self.at = self.filled;
                }
            }
        }
    }

    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }
}

// ---------------------------------------------------------------------------
// Parsing, on bytes
// ---------------------------------------------------------------------------

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

/// SP and HTAB only. Not `char::is_whitespace`, which would eat a vertical tab
/// and a form feed that the grammar does not allow here.
fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if *first == b' ' || *first == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if *last == b' ' || *last == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// Split a head into lines on CRLF, and only on CRLF.
///
/// Deliberately not `split(b'\n')` with a trailing-CR strip. The scanner that
/// found the end of this head already refused a bare LF, and this refuses it
/// again: the strictness has to be a property of the parser rather than of the
/// order two functions happen to be called in, or a later refactor reopens the
/// hole without touching this file.
fn crlf_lines(head: &[u8]) -> Result<Vec<&[u8]>, Reject> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < head.len() {
        match head[i] {
            b'\n' => {
                return Err(Reject::new(Status::BadRequest, "a bare LF in the head"));
            }
            b'\r' => {
                if head.get(i + 1) != Some(&b'\n') {
                    return Err(Reject::new(
                        Status::BadRequest,
                        "a CR that is not part of CRLF",
                    ));
                }
                lines.push(&head[start..i]);
                i += 2;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start != head.len() {
        return Err(Reject::new(
            Status::BadRequest,
            "the head does not end with CRLF",
        ));
    }
    Ok(lines)
}

fn parse_head(head: &[u8], config: &Config) -> Result<Head, Reject> {
    let all = crlf_lines(head)?;
    let mut lines = all.into_iter();

    let request_line = lines
        .next()
        .ok_or_else(|| Reject::new(Status::BadRequest, "no request line"))?;
    if request_line.len() > config.max_request_line {
        return Err(Reject::new(
            Status::RequestHeaderFieldsTooLarge,
            "the request line exceeds its cap",
        ));
    }
    let (method, target, version) = split_request_line(request_line)?;

    // Version before anything else that could be interpreted: a client speaking
    // a protocol we do not speak gets told so rather than getting a parse error
    // about a grammar it never claimed to follow.
    if version != b"HTTP/1.1" {
        return if version.starts_with(b"HTTP/") && version.len() == 8 {
            Err(Reject::new(
                Status::HttpVersionNotSupported,
                "this server speaks HTTP/1.1 only",
            ))
        } else {
            Err(Reject::new(Status::BadRequest, "the version is malformed"))
        };
    }
    if !method.iter().copied().all(is_tchar) || method.is_empty() {
        return Err(Reject::new(Status::BadRequest, "the method is not a token"));
    }
    let path = parse_target(target)?;

    let mut content_length: Option<u64> = None;
    let mut content_type: Option<Vec<u8>> = None;
    let mut content_encoding: Option<Vec<u8>> = None;
    let mut expect: Option<Vec<u8>> = None;
    let mut host_seen = 0usize;
    let mut close_requested = false;
    let mut fields = 0usize;

    for line in lines {
        if line.is_empty() {
            break; // the terminator
        }
        fields += 1;
        if fields > config.max_header_count {
            return Err(Reject::new(
                Status::RequestHeaderFieldsTooLarge,
                "too many header fields",
            ));
        }
        if line.len() > config.max_header_line {
            return Err(Reject::new(
                Status::RequestHeaderFieldsTooLarge,
                "a header line exceeds its cap",
            ));
        }
        // A line starting with whitespace is an obsolete line fold. RFC 9112
        // says a server must reject it, and it is exactly how a header hides a
        // second header from one of two parsers.
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(Reject::new(
                Status::BadRequest,
                "an obsolete line fold in the header section",
            ));
        }

        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or_else(|| Reject::new(Status::BadRequest, "a header line with no colon"))?;
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if name.is_empty() || !name.iter().copied().all(is_tchar) {
            // Whitespace before the colon lands here, which is the other half
            // of the hidden-header trick.
            return Err(Reject::new(
                Status::BadRequest,
                "a header name outside the token set",
            ));
        }
        // Checked before trimming: a control byte must be refused, not removed.
        if value
            .iter()
            .any(|b| *b == 0 || (*b < 0x20 && *b != b'\t') || *b == 0x7f)
        {
            return Err(Reject::new(
                Status::BadRequest,
                "a control byte in a header value",
            ));
        }
        let value = trim_ows(value);

        // Every field below is a singleton. A duplicate is a rejection, never a
        // choice between first and last: which one a server picks is precisely
        // what two parsers in a row disagree about.
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(Reject::new(
                Status::NotImplemented,
                "this server does not implement transfer codings",
            ));
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(Reject::new(Status::BadRequest, "two Content-Length fields"));
            }
            content_length = Some(parse_content_length(value)?);
        } else if name.eq_ignore_ascii_case(b"content-type") {
            if content_type.is_some() {
                return Err(Reject::new(Status::BadRequest, "two Content-Type fields"));
            }
            content_type = Some(value.to_vec());
        } else if name.eq_ignore_ascii_case(b"content-encoding") {
            if content_encoding.is_some() {
                return Err(Reject::new(
                    Status::BadRequest,
                    "two Content-Encoding fields",
                ));
            }
            content_encoding = Some(value.to_vec());
        } else if name.eq_ignore_ascii_case(b"expect") {
            if expect.is_some() {
                return Err(Reject::new(Status::ExpectationFailed, "two Expect fields"));
            }
            expect = Some(value.to_vec());
        } else if name.eq_ignore_ascii_case(b"host") {
            host_seen += 1;
            if host_seen > 1 {
                return Err(Reject::new(Status::BadRequest, "two Host fields"));
            }
            validate_host(value)?;
        } else if name.eq_ignore_ascii_case(b"connection") {
            // A comma-separated list of tokens. Only `close` is recognised;
            // naming a framing field as a connection option is ignored, because
            // honouring it is how one parser is talked out of a header the
            // other one read.
            for option in value.split(|b| *b == b',') {
                if trim_ows(option).eq_ignore_ascii_case(b"close") {
                    close_requested = true;
                }
            }
        }
    }

    if host_seen != 1 {
        return Err(Reject::new(
            Status::BadRequest,
            "a request needs exactly one Host field",
        ));
    }

    let expect_continue = match expect.as_deref() {
        None => false,
        // Exactly the token, compared whole. A substring test would accept
        // `y 100-continue`, and an exporter that sent that is not one we should
        // be guessing for.
        Some(value) if value.eq_ignore_ascii_case(b"100-continue") => true,
        Some(_) => {
            return Err(Reject::new(
                Status::ExpectationFailed,
                "the only expectation this server understands is 100-continue",
            ));
        }
    };

    Ok(Head {
        method: if method == b"POST" {
            Method::Post
        } else {
            Method::Other
        },
        path,
        // Never inferred from the method, from Content-Type, or from bytes
        // sitting in the buffer.
        declared_length: content_length,
        content_type,
        content_encoding,
        expect_continue,
        close_requested,
    })
}

/// The three fields of a request line, still borrowed from the buffer.
type RequestLine<'a> = (&'a [u8], &'a [u8], &'a [u8]);

fn split_request_line(line: &[u8]) -> Result<RequestLine<'_>, Reject> {
    // Exactly one SP as each delimiter and exactly two delimiters. Not
    // `split_whitespace`: a HTAB or a double space is a different message to
    // two different parsers.
    let mut parts = line.split(|b| *b == b' ');
    let method = parts
        .next()
        .ok_or_else(|| Reject::new(Status::BadRequest, "an empty request line"))?;
    let target = parts
        .next()
        .ok_or_else(|| Reject::new(Status::BadRequest, "no request target"))?;
    let version = parts
        .next()
        .ok_or_else(|| Reject::new(Status::BadRequest, "no HTTP version"))?;
    if parts.next().is_some() {
        return Err(Reject::new(
            Status::BadRequest,
            "more than three fields in the request line",
        ));
    }
    if target.is_empty() {
        return Err(Reject::new(Status::BadRequest, "an empty request target"));
    }
    Ok((method, target, version))
}

/// Origin-form or absolute-form. Nothing else.
///
/// Asterisk-form is for `OPTIONS *` and authority-form is for `CONNECT`, and
/// this server implements neither, so accepting either shape would be accepting
/// a request it has no code to answer.
fn parse_target(target: &[u8]) -> Result<String, Reject> {
    let path_and_query: &[u8] = if target[0] == b'/' {
        target
    } else {
        // Absolute-form. The authority in the target wins and the Host field is
        // ignored entirely, which is what the specification says and also
        // removes the question of which one a proxy used.
        let rest = strip_scheme(target)?;
        match rest.iter().position(|b| *b == b'/') {
            Some(at) => &rest[at..],
            None => b"/",
        }
    };

    let path = match path_and_query.iter().position(|b| *b == b'?') {
        Some(at) => &path_and_query[..at],
        None => path_and_query,
    };

    // Grammar first, decoding second, and no repair in between.
    for b in path {
        if *b <= 0x20 || *b >= 0x7f {
            return Err(Reject::new(
                Status::BadRequest,
                "a control byte or non-ASCII byte in the request target",
            ));
        }
    }
    let decoded = percent_decode(path)?;
    // Routing is exact-match against a short list of known paths, so a decoded
    // traversal sequence cannot reach anything: it simply matches nothing and
    // becomes a 404. That is why there is no normalisation step here, and there
    // must not be one added.
    String::from_utf8(decoded)
        .map_err(|_| Reject::new(Status::BadRequest, "the request target is not valid UTF-8"))
}

fn strip_scheme(target: &[u8]) -> Result<&[u8], Reject> {
    for scheme in [b"http://".as_slice(), b"https://".as_slice()] {
        if target.len() > scheme.len() && target[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return Ok(&target[scheme.len()..]);
        }
    }
    Err(Reject::new(
        Status::BadRequest,
        "a request target that is neither origin-form nor absolute-form",
    ))
}

fn percent_decode(path: &[u8]) -> Result<Vec<u8>, Reject> {
    let mut out = Vec::with_capacity(path.len());
    let mut i = 0usize;
    while i < path.len() {
        if path[i] == b'%' {
            let hi = path
                .get(i + 1)
                .and_then(|b| (*b as char).to_digit(16))
                .ok_or_else(|| Reject::new(Status::BadRequest, "a truncated percent-escape"))?;
            let lo = path
                .get(i + 2)
                .and_then(|b| (*b as char).to_digit(16))
                .ok_or_else(|| Reject::new(Status::BadRequest, "a truncated percent-escape"))?;
            let byte = (hi * 16 + lo) as u8;
            // Decoded once, and a decoded control byte is refused rather than
            // carried: a NUL in a path is never anything but an attempt.
            if byte == 0 || byte < 0x20 || byte == 0x7f {
                return Err(Reject::new(
                    Status::BadRequest,
                    "a percent-escaped control byte in the request target",
                ));
            }
            out.push(byte);
            i += 3;
        } else {
            out.push(path[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn parse_content_length(value: &[u8]) -> Result<u64, Reject> {
    // Digits only. A leading plus, a leading minus, a hex prefix, whitespace or
    // an empty value are all things one parser accepts and another does not.
    if value.is_empty() || value.len() > 20 || !value.iter().all(|b| b.is_ascii_digit()) {
        return Err(Reject::new(
            Status::BadRequest,
            "Content-Length is not a plain decimal number",
        ));
    }
    let mut total = 0u64;
    for b in value {
        total = total
            .checked_mul(10)
            .and_then(|t| t.checked_add(u64::from(*b - b'0')))
            .ok_or_else(|| {
                Reject::new(
                    Status::PayloadTooLarge,
                    "Content-Length does not fit a 64-bit integer",
                )
            })?;
    }
    Ok(total)
}

fn validate_host(value: &[u8]) -> Result<(), Reject> {
    let bad = |why| Reject::new(Status::BadRequest, why);
    if value.is_empty() {
        return Err(bad("an empty Host field"));
    }
    if value.contains(&b'@') {
        return Err(bad("userinfo in a Host field"));
    }
    if value.iter().any(|b| *b == b' ' || *b == b'\t') {
        return Err(bad("whitespace in a Host field"));
    }
    // An IPv6 literal is bracketed and full of colons, so the port split is on
    // the last colon and only outside brackets.
    let host = if value[0] == b'[' {
        let close = value
            .iter()
            .position(|b| *b == b']')
            .ok_or_else(|| bad("an unterminated IPv6 literal in a Host field"))?;
        let after = &value[close + 1..];
        if !after.is_empty() {
            validate_port(after)?;
        }
        &value[..close + 1]
    } else {
        match value.iter().rposition(|b| *b == b':') {
            Some(at) => {
                validate_port(&value[at..])?;
                &value[..at]
            }
            None => value,
        }
    };
    if host.is_empty() {
        return Err(bad("a Host field with no host"));
    }
    Ok(())
}

fn validate_port(with_colon: &[u8]) -> Result<(), Reject> {
    let bad = Reject::new(Status::BadRequest, "a malformed port in a Host field");
    match with_colon {
        [b':', digits @ ..] if !digits.is_empty() && digits.iter().all(|b| b.is_ascii_digit()) => {
            Ok(())
        }
        // An empty port is grammatically legal and means the default. Anything
        // else is not.
        [b':'] => Ok(()),
        _ => Err(bad),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(raw: &str) -> Result<Head, Reject> {
        parse_head(raw.as_bytes(), &Config::default())
    }

    const OK: &str = "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n";

    #[test]
    fn an_ordinary_export_parses() {
        let h = head(OK).unwrap();
        assert_eq!(h.method, Method::Post);
        assert_eq!(h.path, "/v1/traces");
        assert_eq!(h.body_length(), 3);
        assert!(!h.close_requested);
        assert!(!h.expect_continue);
    }

    #[test]
    fn a_bare_lf_never_becomes_a_line_ending() {
        // The rule that keeps a proxy in front from disagreeing with us about
        // where this message ends. Enforced twice on purpose: once by the
        // scanner that finds the end of the head, and once here, so the
        // strictness survives a refactor that changes the order.
        for raw in [
            "POST /v1/traces HTTP/1.1\r\nHost: x\nX-Smuggled: 1\r\n\r\n",
            "POST /v1/traces HTTP/1.1\nHost: x\r\n\r\n",
            "POST /v1/traces HTTP/1.1\r\nHost: x\r\n\n",
        ] {
            assert_eq!(
                head(raw).unwrap_err().status,
                Status::BadRequest,
                "{raw:?} was accepted"
            );
        }
        // A lone CR is not a line ending either.
        assert_eq!(
            head("POST /v1/traces HTTP/1.1\rHost: x\r\n\r\n")
                .unwrap_err()
                .status,
            Status::BadRequest
        );
    }

    #[test]
    fn a_transfer_encoding_is_not_implemented_rather_than_interpreted() {
        // Refusing outright deletes the whole smuggling family rather than
        // trying to win an argument about precedence.
        for value in ["chunked", "identity", "gzip, chunked", "CHUNKED"] {
            let raw = format!(
                "POST /v1/traces HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: {value}\r\n\r\n"
            );
            assert_eq!(
                head(&raw).unwrap_err().status,
                Status::NotImplemented,
                "{value}"
            );
        }
    }

    #[test]
    fn a_declared_length_is_digits_or_it_is_nothing() {
        for value in [
            "+5",
            "-5",
            "0x10",
            "",
            "5 5",
            "5,5",
            "5.0",
            "18446744073709551616",
        ] {
            let raw =
                format!("POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length: {value}\r\n\r\n");
            assert!(head(&raw).is_err(), "{value:?} was accepted");
        }
        assert_eq!(
            head("POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length: 18446744073709551615\r\n\r\n")
                .unwrap()
                .body_length(),
            u64::MAX
        );
        // Surrounding space is optional whitespace the grammar allows and the
        // grammar strips. It is not whitespace *in* the value.
        assert_eq!(
            head("POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length:  5\t \r\n\r\n")
                .unwrap()
                .body_length(),
            5
        );
    }

    #[test]
    fn a_second_singleton_field_is_a_rejection_not_a_choice() {
        // Which of the two a server picks is exactly what two parsers in a row
        // disagree about, so it picks neither.
        for field in [
            "Content-Length: 1",
            "Content-Type: a/b",
            "Content-Encoding: gzip",
        ] {
            let raw = format!("POST /v1/traces HTTP/1.1\r\nHost: x\r\n{field}\r\n{field}\r\n\r\n");
            assert_eq!(
                head(&raw).unwrap_err().status,
                Status::BadRequest,
                "{field}"
            );
        }
        let two_hosts = "POST /v1/traces HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n";
        assert_eq!(head(two_hosts).unwrap_err().status, Status::BadRequest);
    }

    #[test]
    fn a_header_that_hides_a_second_header_is_refused() {
        let cases = [
            // Space before the colon.
            "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\n",
            // An obsolete line fold.
            "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length:\r\n 5\r\n\r\n",
            // A line with no colon at all.
            "POST /v1/traces HTTP/1.1\r\nHost: x\r\nnonsense\r\n\r\n",
            // An empty field name.
            "POST /v1/traces HTTP/1.1\r\nHost: x\r\n: value\r\n\r\n",
        ];
        for raw in cases {
            assert_eq!(
                head(raw).unwrap_err().status,
                Status::BadRequest,
                "{raw:?} was accepted"
            );
        }
    }

    #[test]
    fn a_control_byte_in_a_value_is_refused_rather_than_removed() {
        let raw = "POST /v1/traces HTTP/1.1\r\nHost: x\r\nX-A: a\u{0}b\r\n\r\n";
        assert_eq!(head(raw).unwrap_err().status, Status::BadRequest);
    }

    #[test]
    fn a_request_needs_exactly_one_host() {
        assert!(head("POST /v1/traces HTTP/1.1\r\nContent-Length: 0\r\n\r\n").is_err());
        for value in ["x", "example.com:4318", "[::1]:4318", "[::1]"] {
            let raw = format!("POST /v1/traces HTTP/1.1\r\nHost: {value}\r\n\r\n");
            assert!(head(&raw).is_ok(), "{value} was refused");
        }
        for value in [
            "user@example.com",
            "ex ample",
            "example:",
            "example:abc",
            "[::1",
        ] {
            let raw = format!("POST /v1/traces HTTP/1.1\r\nHost: {value}\r\n\r\n");
            // An empty port is legal; the rest are not.
            if value == "example:" {
                assert!(head(&raw).is_ok(), "{value}");
            } else {
                assert!(head(&raw).is_err(), "{value} was accepted");
            }
        }
    }

    #[test]
    fn only_http_1_1_is_spoken_and_the_rest_are_told_which() {
        assert_eq!(
            head("POST /v1/traces HTTP/1.0\r\nHost: x\r\n\r\n")
                .unwrap_err()
                .status,
            Status::HttpVersionNotSupported
        );
        assert_eq!(
            head("PRI * HTTP/2.0\r\nHost: x\r\n\r\n")
                .unwrap_err()
                .status,
            Status::HttpVersionNotSupported
        );
        // Grammar-invalid rather than merely different.
        for version in ["http/1.1", "HTTP/1.10", "HTTP/11", "HTTP", ""] {
            let raw = format!("POST /v1/traces {version}\r\nHost: x\r\n\r\n");
            assert_eq!(
                head(&raw).unwrap_err().status,
                Status::BadRequest,
                "{version:?}"
            );
        }
    }

    #[test]
    fn a_request_line_has_exactly_two_spaces() {
        for raw in [
            "POST  /v1/traces HTTP/1.1\r\nHost: x\r\n\r\n",
            "POST /v1/traces  HTTP/1.1\r\nHost: x\r\n\r\n",
            " POST /v1/traces HTTP/1.1\r\nHost: x\r\n\r\n",
            "POST\t/v1/traces HTTP/1.1\r\nHost: x\r\n\r\n",
            "POST /v1/traces\r\nHost: x\r\n\r\n",
            "POST /v1/traces HTTP/1.1 extra\r\nHost: x\r\n\r\n",
        ] {
            assert!(head(raw).is_err(), "{raw:?} was accepted");
        }
    }

    #[test]
    fn absolute_form_takes_its_authority_from_the_target() {
        let h = head("POST http://example.com/v1/traces HTTP/1.1\r\nHost: other\r\n\r\n").unwrap();
        assert_eq!(h.path, "/v1/traces");
        let h = head("POST https://example.com HTTP/1.1\r\nHost: other\r\n\r\n").unwrap();
        assert_eq!(h.path, "/");
    }

    #[test]
    fn the_shapes_this_server_has_no_code_for_are_refused() {
        for target in ["*", "example.com:443", "v1/traces", "?a=b"] {
            let raw = format!("POST {target} HTTP/1.1\r\nHost: x\r\n\r\n");
            assert!(head(&raw).is_err(), "{target} was accepted");
        }
    }

    #[test]
    fn a_target_is_decoded_once_and_never_repaired() {
        let h = head("POST /v1%2Ftraces HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        // Decoded, and it now matches no route, so it will be a 404. It is not
        // normalised into the real path and it is not decoded twice.
        assert_eq!(h.path, "/v1/traces");

        for target in ["/a%", "/a%2", "/a%zz", "/a%00b", "/a%0db"] {
            let raw = format!("POST {target} HTTP/1.1\r\nHost: x\r\n\r\n");
            assert!(head(&raw).is_err(), "{target} was accepted");
        }
    }

    #[test]
    fn a_query_string_is_not_part_of_the_route() {
        let h = head("POST /v1/traces?a=b HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(h.path, "/v1/traces");
    }

    #[test]
    fn an_expectation_is_matched_whole_or_refused() {
        assert!(
            head("POST /v1/traces HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\r\n")
                .unwrap()
                .expect_continue
        );
        assert!(
            head("POST /v1/traces HTTP/1.1\r\nHost: x\r\nExpect: 100-CONTINUE\r\n\r\n")
                .unwrap()
                .expect_continue
        );
        for value in [
            "y 100-continue",
            "100-continue, foo",
            "100-continue;x",
            "other",
        ] {
            let raw = format!("POST /v1/traces HTTP/1.1\r\nHost: x\r\nExpect: {value}\r\n\r\n");
            assert_eq!(
                head(&raw).unwrap_err().status,
                Status::ExpectationFailed,
                "{value:?}"
            );
        }
    }

    #[test]
    fn a_connection_option_cannot_talk_us_out_of_a_framing_field() {
        // Naming Content-Length as a connection option is a known trick for
        // getting one parser in a chain to ignore it. Only `close` is
        // recognised and the framing field stands.
        let raw = "POST /v1/traces HTTP/1.1\r\nHost: x\r\nConnection: close, Content-Length\r\nContent-Length: 7\r\n\r\n";
        let h = head(raw).unwrap();
        assert!(h.close_requested);
        assert_eq!(h.body_length(), 7);
    }

    #[test]
    fn no_framing_means_no_body() {
        // Never inferred from the method, from Content-Type, or from bytes that
        // happen to be sitting in the buffer.
        let h = head(
            "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\n\r\n",
        )
        .unwrap();
        assert_eq!(h.declared_length, None);
    }

    #[test]
    fn the_caps_are_counted_and_not_merely_declared() {
        let config = Config {
            max_header_count: 3,
            ..Config::default()
        };
        let many = (0..10).map(|i| format!("X-{i}: v\r\n")).collect::<String>();
        let raw = format!("POST /v1/traces HTTP/1.1\r\nHost: x\r\n{many}\r\n");
        assert_eq!(
            parse_head(raw.as_bytes(), &config).unwrap_err().status,
            Status::RequestHeaderFieldsTooLarge
        );

        let config = Config {
            max_request_line: 16,
            ..Config::default()
        };
        assert_eq!(
            parse_head(OK.as_bytes(), &config).unwrap_err().status,
            Status::RequestHeaderFieldsTooLarge
        );
    }

    #[test]
    fn trimming_takes_space_and_tab_and_nothing_else() {
        assert_eq!(trim_ows(b" \ta \t"), b"a");
        assert_eq!(trim_ows(b"a"), b"a");
        assert_eq!(trim_ows(b""), b"");
        // A vertical tab is not OWS, so it stays and the value keeps it. It was
        // already refused as a control byte before trimming.
        assert_eq!(trim_ows(b"\x0ba"), b"\x0ba");
    }
}
