//! One HTTP/1.1 client for the whole workspace, written rather than depended on.
//!
//! # Why this exists as its own crate
//!
//! Two things here speak HTTP: the RFC 3161 anchor, which POSTs a timestamp query
//! to an authority, and the S3 adapter, which needs every verb, the response status
//! and the response headers. The anchor's client was written first and is shaped
//! entirely around its one exchange: POST only, one path, 200 only, a body or an
//! error. Growing it into the second caller would have left a client whose contract
//! was "whatever the two callers happen to need".
//!
//! So the general client lives here and the anchor keeps its strictness where that
//! strictness belongs, in the anchor. Being able to say **one HTTP client** is also
//! what makes hand-writing the S3 adapter defensible instead of reckless: the whole
//! cost of not taking `aws-sdk-s3` is this file plus a signature.
//!
//! # What it deliberately does not do
//!
//! - **TLS only with the `tls` feature.** Without it `https` is refused by name
//!   rather than attempted and failed, so a configuration problem reads as one.
//!   Inbound transport security stays the deployment's job, a terminator in front,
//!   the same seam as ingest and the SQL port. Outbound has no such seam: nothing
//!   sits in front of a client reaching somebody else's object store, so the client
//!   has to do it. `rustls` on the same `aws-lc-rs` backend as the cryptographic
//!   provider, so a deployment links one implementation rather than two.
//! - **No redirects.** S3 answers `301` with `PermanentRedirect` when the region is
//!   wrong, and following it silently would move a write to a bucket the operator
//!   did not name. The status is returned and the caller decides.
//! - **No connection reuse.** One request per connection, `Connection: close`. Reuse
//!   needs the framing rules this client would then have to get right under
//!   concurrency, and a pooled connection is not what makes an object store fast.
//! - **No cookies, no auth helpers, no compression.** Nothing here needs them.
//!
//! # What it does do, because correctness needs it
//!
//! **Chunked responses are decoded.** This is not optional politeness: S3 answers
//! `ListObjectsV2` with `Transfer-Encoding: chunked` and no `Content-Length`, so a
//! client that refuses chunked cannot list a bucket. The anchor refuses chunked and
//! keeps refusing it, because a timestamp authority has no reason to send it.
//!
//! **A declared `Content-Length` must match the body.** A body one byte short is a
//! truncated object, and a truncated object fails a hash check later, somewhere the
//! reason is no longer visible.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[cfg(feature = "tls")]
pub mod tls;

/// The header section's ceiling, counted while reading rather than after.
const MAX_HEADERS: usize = 16 * 1024;

/// What a response may weigh unless the caller raises it.
///
/// A megabyte suits a timestamp token and an XML listing. The S3 adapter raises it
/// for object reads, deliberately and in one visible place.
pub const DEFAULT_MAX_RESPONSE: usize = 1 << 20;

/// The verbs this workspace sends. An enum rather than a string, because a typo in
/// a method reaches the server as a `501` from a system that had one job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Put,
    Post,
    Head,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Post => "POST",
            Self::Head => "HEAD",
            Self::Delete => "DELETE",
        }
    }
}

/// A request, built by the caller and sent as written.
///
/// `target` is the request line's target: a path, plus a query string if there is
/// one, already encoded. Encoding belongs to whoever knows the rules, and for S3
/// those rules are not the platform's.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn new(method: Method, target: impl Into<String>) -> Self {
        Self {
            method,
            target: target.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

/// A response, whatever its status. A `404` is an answer, not an error: only a
/// failure to obtain an answer is one.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// A header by name, case-insensitively, because HTTP field names are.
    ///
    /// S3 sends `ETag` and `x-amz-version-id`, and a client that matched case
    /// exactly would work against AWS and fail against a proxy that normalised it.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The seam a caller is written against, so tests do not need a network.
///
/// The S3 adapter holds one of these rather than a `Client`, which is what lets its
/// whole surface be exercised against a scripted peer, including the answers a real
/// store gives rarely and at the worst moment.
pub trait Http {
    fn send(&mut self, request: &Request) -> Result<Response, String>;
}

#[derive(Debug)]
pub enum UrlError {
    /// Not a URL this build can reach. Without the `tls` feature that means
    /// anything but `http://`, and with it, anything but `http://` or `https://`.
    NotHttp,
    /// No host between the scheme and the path.
    NoHost,
    /// A port that is not a number, or is zero.
    BadPort,
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(not(feature = "tls"))]
            Self::NotHttp => f.write_str(
                "only http:// is supported: this build has no TLS, which is the `tls` feature",
            ),
            #[cfg(feature = "tls")]
            Self::NotHttp => f.write_str("only http:// and https:// are supported"),
            Self::NoHost => f.write_str("the URL has no host"),
            Self::BadPort => f.write_str("the URL's port is not a usable number"),
        }
    }
}

impl std::error::Error for UrlError {}

/// Whether a connection is wrapped in TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Plain,
    #[cfg(feature = "tls")]
    Tls,
}

/// An HTTP/1.1 client bound to one origin.
#[derive(Debug, Clone)]
pub struct Client {
    // Both fields exist in every build so the two differ by as little as possible.
    // Without TLS nothing reads them, and a build that carried different fields
    // would be a second client to keep correct.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    scheme: Scheme,
    /// The host on its own, which TLS verifies the certificate against. Kept apart
    /// from `host` because that one carries the port when it is not the default,
    /// and a certificate is issued for a name, not for a name and a port.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    server_name: String,
    /// `host:port`, resolved per call rather than at construction, so a long-lived
    /// process follows DNS instead of pinning whatever it saw at startup.
    authority: String,
    /// The `Host` header: the authority without a default port, per RFC 9110.
    host: String,
    connect_timeout: Duration,
    io_timeout: Duration,
    max_response: usize,
    #[cfg(feature = "tls")]
    tls: tls::Tls,
}

impl Client {
    /// From an `http://host[:port]` origin. A path in the origin is kept out on
    /// purpose: the path belongs to the request, and an origin carrying one is
    /// usually a base URL somebody meant to join and did not.
    pub fn new(origin: &str) -> Result<Self, UrlError> {
        #[cfg(feature = "tls")]
        let (scheme, rest, default_port) = match origin.strip_prefix("https://") {
            Some(rest) => (Scheme::Tls, rest, 443u16),
            None => (
                Scheme::Plain,
                origin.strip_prefix("http://").ok_or(UrlError::NotHttp)?,
                80,
            ),
        };
        #[cfg(not(feature = "tls"))]
        let (scheme, rest, default_port) = (
            Scheme::Plain,
            origin.strip_prefix("http://").ok_or(UrlError::NotHttp)?,
            80u16,
        );

        let authority = rest.split('/').next().unwrap_or(rest);
        if authority.is_empty() {
            return Err(UrlError::NoHost);
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port: u16 = port.parse().map_err(|_| UrlError::BadPort)?;
                if port == 0 {
                    return Err(UrlError::BadPort);
                }
                (host, port)
            }
            None => (authority, default_port),
        };
        if host.is_empty() {
            return Err(UrlError::NoHost);
        }
        Ok(Self {
            scheme,
            server_name: host.to_owned(),
            authority: format!("{host}:{port}"),
            // RFC 9110: the default port for the scheme is omitted from Host.
            host: if port == default_port {
                host.to_owned()
            } else {
                format!("{host}:{port}")
            },
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
            max_response: DEFAULT_MAX_RESPONSE,
            #[cfg(feature = "tls")]
            tls: tls::Tls::new(),
        })
    }

    pub fn with_timeouts(mut self, connect: Duration, io: Duration) -> Self {
        self.connect_timeout = connect;
        self.io_timeout = io;
        self
    }

    pub fn with_max_response(mut self, bytes: usize) -> Self {
        self.max_response = bytes;
        self
    }

    /// Verify certificates against a private authority instead of the compiled-in
    /// public roots, which is the normal arrangement inside a bank.
    #[cfg(feature = "tls")]
    pub fn with_tls(mut self, tls: tls::Tls) -> Self {
        self.tls = tls;
        self
    }

    /// The `Host` header this client will send, which a signature has to agree with.
    pub fn host(&self) -> &str {
        &self.host
    }

    #[cfg(feature = "tls")]
    fn connect(&self) -> Result<tls::Stream, String> {
        let socket = self.connect_tcp()?;
        match self.scheme {
            Scheme::Plain => Ok(tls::Stream::Plain(socket)),
            Scheme::Tls => Ok(tls::Stream::Tls(Box::new(
                self.tls.wrap(&self.server_name, socket)?,
            ))),
        }
    }

    #[cfg(not(feature = "tls"))]
    fn connect(&self) -> Result<TcpStream, String> {
        self.connect_tcp()
    }

    fn connect_tcp(&self) -> Result<TcpStream, String> {
        let mut last = "no address resolved".to_owned();
        let addresses = self
            .authority
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {}: {e}", self.authority))?;
        for address in addresses {
            match TcpStream::connect_timeout(&address, self.connect_timeout) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(self.io_timeout))
                        .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
                        .map_err(|e| format!("cannot set a timeout: {e}"))?;
                    return Ok(stream);
                }
                Err(e) => last = format!("{address}: {e}"),
            }
        }
        Err(last)
    }
}

impl Http for Client {
    fn send(&mut self, request: &Request) -> Result<Response, String> {
        // Built before the socket on purpose: a refused header must read as a
        // refused header, not as whatever the connection did afterwards.
        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n",
            request.method.as_str(),
            request.target,
            self.host
        );
        for (name, value) in &request.headers {
            // A newline in a header value is request splitting, and the value comes
            // from a key an agent chose. Refused here rather than sent, because
            // every layer below this one would treat the result as two requests.
            if value.contains(['\r', '\n']) || name.contains(['\r', '\n']) {
                return Err(format!("the header {name} contains a line break"));
            }
            // This client writes `Host` itself, from the origin it was built with,
            // and a second one is not a duplicate to tidy up: RFC 9112 requires a
            // server to refuse the whole request, and the refusal arrives from the
            // HTTP layer with no application code and no useful body. A caller that
            // needs the host in a signature, as SigV4 does, signs it without sending
            // it. Refused here rather than dropped silently, because a caller that
            // set a *different* host meant something by it and deserves to be told
            // the request cannot carry it.
            if name.eq_ignore_ascii_case("host") {
                return Err(format!(
                    "the header {name} is written by this client from the origin it \
                     was built with, so a request must not carry its own"
                ));
            }
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        // Always sent, including as zero, so the peer never has to guess whether a
        // body follows. Some stores answer a PUT with no length by waiting.
        head.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
        head.push_str("Connection: close\r\n\r\n");

        let mut stream = self.connect()?;
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(&request.body))
            .and_then(|()| stream.flush())
            .map_err(|e| format!("cannot send the request: {e}"))?;

        read_message(&mut stream, self.max_response)
    }
}

/// Split a whole HTTP response into status, headers and body.
///
/// Separate from the socket so every framing rule can be tested against bytes.
pub fn parse_response(raw: &[u8], max_body: usize) -> Result<Response, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "the response has no header section".to_owned())?;
    if split > MAX_HEADERS {
        return Err(format!("the header section exceeded {MAX_HEADERS} bytes"));
    }
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|_| "the response head is not text".to_owned())?;
    let rest = &raw[split + 4..];

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "the response has no status line".to_owned())?;
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("cannot read a status code from {status_line:?}"))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }

    let chunked = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.as_str());
    let body = match chunked {
        Some(encoding) if encoding.eq_ignore_ascii_case("chunked") => dechunk(rest, max_body)?,
        Some(encoding) if encoding.eq_ignore_ascii_case("identity") => rest.to_vec(),
        Some(encoding) => {
            return Err(format!(
                "the peer used Transfer-Encoding: {encoding}, which this client does not decode"
            ));
        }
        None => {
            if let Some((_, declared)) = headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            {
                let declared: usize = declared
                    .parse()
                    .map_err(|_| format!("an unreadable Content-Length: {declared}"))?;
                // Not merely a bound. A body shorter than declared is a truncated
                // object, and a truncated object fails its hash check later, where
                // the reason is no longer visible.
                if declared != rest.len() {
                    return Err(format!(
                        "the peer declared {declared} bytes and sent {}",
                        rest.len()
                    ));
                }
            }
            rest.to_vec()
        }
    };
    if body.len() > max_body {
        return Err(format!("the response body exceeded {max_body} bytes"));
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Read until the peer stops, then let the framing decide whether that was the end.
///
/// Separate from `send` so it can be tested against a reader that ends the way a
/// real one does, which is the only reason this is not four lines inline.
///
/// **The two endings that matter.** A peer may close a TLS connection without
/// sending `close_notify`; Google Cloud Storage does. rustls reports that as
/// `UnexpectedEof` rather than an end of file, and it is right to: at the TLS layer
/// there is no way to tell a finished stream from one an attacker cut short.
///
/// HTTP can tell, because a response carries its own framing. So an unexpected end
/// is treated here as an end, and `parse_response` decides: a body shorter than its
/// `Content-Length` is refused, and an unfinished chunked body fails to decode. That
/// is what rustls's own manual recommends for a protocol that frames its messages,
/// and the alternative was what this client did until a live GCS bucket refused every
/// single request with a TLS error while the complete response sat in the buffer.
fn read_message(stream: &mut impl Read, max_response: usize) -> Result<Response, String> {
    let mut raw = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("cannot read the response: {e}")),
        };
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);
        // Checked while reading: a peer that sends for ever has to be stopped, not
        // measured afterwards.
        if raw.len() > max_response.saturating_add(MAX_HEADERS) {
            return Err(format!("the response exceeded {max_response} bytes"));
        }
    }
    parse_response(&raw, max_response)
}

/// Decode a chunked body, bounded at every step.
///
/// Needed because S3 answers a listing this way and never says how long it will be.
/// Chunk extensions after a `;` are ignored, which is what the grammar allows;
/// trailers after the final chunk are discarded, since nothing here reads one.
fn dechunk(mut rest: &[u8], max_body: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "a chunked body ended inside a chunk header".to_owned())?;
        let header = std::str::from_utf8(&rest[..line_end])
            .map_err(|_| "a chunk header is not text".to_owned())?;
        // A chunk size may carry extensions: `1a;name=value`.
        let size_text = header.split(';').next().unwrap_or(header).trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| format!("an unreadable chunk size {size_text:?}"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if out.len().saturating_add(size) > max_body {
            return Err(format!("a chunked body exceeded {max_body} bytes"));
        }
        if rest.len() < size + 2 {
            return Err("a chunked body ended inside a chunk".to_owned());
        }
        out.extend_from_slice(&rest[..size]);
        if &rest[size..size + 2] != b"\r\n" {
            return Err("a chunk was not followed by CRLF".to_owned());
        }
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_splits_into_authority_and_host() {
        let c = Client::new("http://s3.us-east-1.amazonaws.com").expect("a valid origin");
        assert_eq!(c.authority, "s3.us-east-1.amazonaws.com:80");
        assert_eq!(
            c.host, "s3.us-east-1.amazonaws.com",
            "the default port is omitted from Host"
        );

        let c = Client::new("http://127.0.0.1:9000").expect("a valid origin");
        assert_eq!(c.authority, "127.0.0.1:9000");
        assert_eq!(c.host, "127.0.0.1:9000", "a non-default port stays in Host");
    }

    #[test]
    fn schemes_this_build_cannot_reach_are_refused_by_name() {
        // `https` belongs in this list only when the build has no TLS. Attempting
        // it and failing at the handshake would report a connection problem for
        // what is a build-configuration problem.
        #[cfg(not(feature = "tls"))]
        let refused = ["https://s3.amazonaws.com", "s3.amazonaws.com", "ftp://x"];
        #[cfg(feature = "tls")]
        let refused = ["s3.amazonaws.com", "ftp://x"];

        for origin in refused {
            assert!(
                matches!(Client::new(origin), Err(UrlError::NotHttp)),
                "{origin} should be refused as unreachable by this build"
            );
        }
        assert!(matches!(Client::new("http://"), Err(UrlError::NoHost)));
        for origin in ["http://x:0", "http://x:port"] {
            assert!(
                matches!(Client::new(origin), Err(UrlError::BadPort)),
                "{origin} should be refused for its port"
            );
        }
    }

    /// The two things a scheme decides: the default port, and what `Host` omits.
    /// Both are easy to get half right, and a `Host` carrying `:443` is refused by
    /// several stores that are otherwise perfectly happy.
    #[cfg(feature = "tls")]
    #[test]
    fn an_https_origin_takes_the_port_and_the_host_header_its_scheme_implies() {
        let c = Client::new("https://s3.eu-central-1.amazonaws.com").expect("a valid origin");
        assert_eq!(c.authority, "s3.eu-central-1.amazonaws.com:443");
        assert_eq!(
            c.host, "s3.eu-central-1.amazonaws.com",
            "443 is the default for https and is omitted from Host"
        );
        assert_eq!(c.server_name, "s3.eu-central-1.amazonaws.com");
        assert_eq!(c.scheme, Scheme::Tls);

        let c = Client::new("https://minio.internal:9000").expect("a valid origin");
        assert_eq!(c.host, "minio.internal:9000", "a non-default port stays");
        assert_eq!(
            c.server_name, "minio.internal",
            "the certificate is verified against the name, never the authority"
        );

        // And plain http still takes 80, in the same build.
        let c = Client::new("http://127.0.0.1:9000").expect("a valid origin");
        assert_eq!(c.scheme, Scheme::Plain);
    }

    #[test]
    fn a_response_yields_its_status_headers_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nETag: \"abc\"\r\nContent-Length: 3\r\n\r\nxyz";
        let r = parse_response(raw, 1024).expect("a well formed response");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"xyz");
        assert_eq!(r.header("etag"), Some("\"abc\""));
        assert_eq!(
            r.header("ETAG"),
            Some("\"abc\""),
            "field names are case-insensitive"
        );
        assert_eq!(r.header("x-amz-version-id"), None);
    }

    /// A `404` is an answer. Only a failure to obtain an answer is an error, and
    /// treating a status as one is how the anchor's client could not be reused.
    #[test]
    fn a_non_success_status_is_returned_rather_than_raised() {
        let raw = b"HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\n\r\n";
        let r = parse_response(raw, 1024).expect("a status is not an error");
        assert_eq!(r.status, 412);
        assert!(r.body.is_empty());
    }

    /// S3 answers a listing chunked and never says how long it will be, so this is
    /// the difference between being able to list a bucket and not.
    #[test]
    fn a_chunked_body_is_decoded_including_extensions_and_trailers() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    4\r\n<Lis\r\n5;ext=1\r\ntBuck\r\n4\r\net/>\r\n0\r\nX-Trailer: ignored\r\n\r\n";
        let r = parse_response(raw, 1024).expect("chunked must decode");
        assert_eq!(r.body, b"<ListBucket/>".to_vec());
    }

    #[test]
    fn a_malformed_chunked_body_is_refused_rather_than_half_decoded() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nab\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nab\r\n0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabZZ0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n"[..],
        ] {
            assert!(
                parse_response(raw, 1024).is_err(),
                "a malformed chunked body must be refused"
            );
        }
    }

    #[test]
    fn a_chunked_body_cannot_exceed_the_ceiling() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n";
        let error = parse_response(raw, 8).expect_err("must be refused");
        assert!(error.contains("exceeded 8 bytes"), "{error}");
    }

    /// A body one byte short of what was declared is a truncated object, and a
    /// truncated object fails its hash check somewhere the reason is invisible.
    #[test]
    fn a_body_that_disagrees_with_its_declared_length_is_refused() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc";
        let error = parse_response(raw, 1024).expect_err("a short body must fail");
        assert!(error.contains("declared 4 bytes and sent 3"), "{error}");
    }

    #[test]
    fn an_unknown_transfer_encoding_is_refused_by_name() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nxx";
        let error = parse_response(raw, 1024).expect_err("must be refused");
        assert!(error.contains("gzip"), "{error}");
    }

    #[test]
    fn a_response_without_a_header_section_is_refused() {
        assert!(parse_response(b"HTTP/1.1 200 OK", 1024).is_err());
        assert!(parse_response(b"garbage\r\n\r\n", 1024).is_err());
    }

    /// The key an agent chose becomes a request target and header values. A line
    /// break in one is request splitting, and every layer below would read two
    /// requests where the caller wrote one.
    #[test]
    fn a_header_value_containing_a_line_break_is_refused_before_it_is_sent() {
        let mut client = Client::new("http://127.0.0.1:1").expect("a valid origin");
        let request = Request::new(Method::Put, "/k").header("x-amz-meta-a", "b\r\nHost: evil");
        let error = client.send(&request).expect_err("must be refused");
        assert!(error.contains("line break"), "{error}");
    }
}

#[cfg(test)]
mod unclean_endings {
    use super::*;

    /// A reader that hands over some bytes and then ends the way TLS ends when the
    /// peer forgets `close_notify`.
    struct EndsAbruptly {
        remaining: Vec<u8>,
    }

    impl Read for EndsAbruptly {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed connection without sending TLS close_notify",
                ));
            }
            let n = out.len().min(self.remaining.len());
            out[..n].copy_from_slice(&self.remaining[..n]);
            self.remaining.drain(..n);
            Ok(n)
        }
    }

    /// The ending Google gives, on a response that is whole.
    ///
    /// This is the bug that made every request to a live GCS bucket fail while the
    /// complete answer sat in the buffer.
    #[test]
    fn a_complete_response_survives_a_peer_that_forgets_close_notify() {
        let mut stream = EndsAbruptly {
            remaining: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
        };
        let response = read_message(&mut stream, 1 << 20).expect("the response is complete");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
    }

    /// The same ending on a response that is not whole, which must still be refused.
    ///
    /// This is the half that makes the other half safe: the reason rustls calls an
    /// unclean end an error is that an attacker can cut a stream short, and the only
    /// thing that makes ignoring it acceptable is that the framing catches it here.
    /// If this test ever passes, the fix above has become a hole.
    #[test]
    fn a_truncated_response_is_still_refused() {
        let mut stream = EndsAbruptly {
            remaining: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel".to_vec(),
        };
        let refused = read_message(&mut stream, 1 << 20);
        let why = refused.expect_err("a body shorter than its Content-Length is truncated");
        assert!(why.contains("declared 5 bytes and sent 3"), "{why}");
    }

    /// A chunked body cut before its terminator, which has no length to check
    /// against and must be caught by the decoder instead.
    #[test]
    fn a_truncated_chunked_response_is_still_refused() {
        let mut stream = EndsAbruptly {
            remaining: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel".to_vec(),
        };
        assert!(
            read_message(&mut stream, 1 << 20).is_err(),
            "an unfinished chunked body was accepted"
        );
    }
}
