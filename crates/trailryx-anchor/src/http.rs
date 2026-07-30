//! A [`Transport`] over plain HTTP, for the authorities that publish one.
//!
//! # Why plaintext is acceptable here, and only here
//!
//! Every public timestamping authority offers its TSP endpoint over `http://`
//! rather than `https://`, and that is not an oversight on their part:
//!
//! - **There is nothing confidential in the query.** It carries a SHA-384 of a
//!   Merkle root, which is a hash of a hash. An eavesdropper learns that this
//!   store anchored something at this moment, which they would learn from the TCP
//!   connection anyway.
//! - **Integrity comes from the signature, not the transport.** The response is
//!   signed by the authority, and this client verifies that signature against a
//!   pinned key. A tampered response fails verification. TLS would add a second,
//!   weaker check of the same thing.
//! - **Replay is stopped by the nonce**, which the token echoes and
//!   [`crate::tsp::binds_to`] insists on.
//!
//! So the honest statement is not "TLS was too hard", it is that the property TLS
//! would provide is already provided by the thing being transported. Said out
//! loud because "no TLS" usually is a compromise, and here it is not.
//!
//! # Why this is a hundred lines and not a HTTP client
//!
//! One POST, one response, one content type, no redirects, no keep-alive, no
//! chunked bodies, no compression. A response with a `Transfer-Encoding` is
//! refused rather than decoded: the whole family of framing disagreements is
//! deleted rather than defended against, which is the same choice
//! `trailryx-ingest` makes on the server side and for the same reason.
//!
//! Every bound here is a bound because the peer is not trusted, even though it is
//! an authority: an authority having a bad day should cost this process a timeout,
//! not its memory.
//!
//! [`Transport`]: crate::Transport

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::Transport;

/// A response larger than this is refused unread. A timestamp token is a few
/// kilobytes; a megabyte is an authority malfunctioning or something else
/// answering on its port.
pub const MAX_RESPONSE: usize = 1 << 20;

/// The header section's ceiling, counted while reading so a peer that never sends
/// the blank line is bounded rather than measured.
const MAX_HEADERS: usize = 16 * 1024;

/// A one-shot HTTP client for a single TSP endpoint.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    /// `host:port`, resolved per call rather than at construction so a long-lived
    /// store follows DNS.
    authority: String,
    /// The request target, beginning with `/`.
    path: String,
    /// The `Host` header, which is `authority` without a default port.
    host: String,
    connect_timeout: Duration,
    io_timeout: Duration,
}

#[derive(Debug)]
pub enum UrlError {
    /// Not an `http://` URL. `https` is refused by name rather than silently
    /// attempted and failed, since this client has no TLS.
    NotHttp,
    /// No host between the scheme and the path.
    NoHost,
    /// A port that is not a number, or is zero.
    BadPort,
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotHttp => f.write_str("only http:// is supported here; this client has no TLS"),
            Self::NoHost => f.write_str("the URL has no host"),
            Self::BadPort => f.write_str("the URL's port is not a usable number"),
        }
    }
}

impl std::error::Error for UrlError {}

impl HttpTransport {
    /// From an `http://host[:port]/path` URL, parsed strictly.
    pub fn new(url: &str) -> Result<Self, UrlError> {
        let rest = url.strip_prefix("http://").ok_or(UrlError::NotHttp)?;
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
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
            None => (authority, 80),
        };
        if host.is_empty() {
            return Err(UrlError::NoHost);
        }
        Ok(Self {
            authority: format!("{host}:{port}"),
            path: path.to_owned(),
            // RFC 9110: the default port is omitted from Host.
            host: if port == 80 {
                host.to_owned()
            } else {
                format!("{host}:{port}")
            },
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
        })
    }

    pub fn with_timeouts(mut self, connect: Duration, io: Duration) -> Self {
        self.connect_timeout = connect;
        self.io_timeout = io;
        self
    }

    fn connect(&self) -> Result<TcpStream, String> {
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

impl Transport for HttpTransport {
    fn exchange(&mut self, query: &[u8]) -> Result<Vec<u8>, String> {
        let mut stream = self.connect()?;

        // `Connection: close` because there is exactly one request per
        // connection: a kept-alive connection would need the framing rules this
        // client refuses to implement.
        let head = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/timestamp-query\r\n\
             Accept: application/timestamp-reply\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            self.path,
            self.host,
            query.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(query))
            .and_then(|()| stream.flush())
            .map_err(|e| format!("cannot send the query: {e}"))?;

        let mut raw = Vec::with_capacity(8192);
        let mut chunk = [0u8; 8192];
        loop {
            let read = stream
                .read(&mut chunk)
                .map_err(|e| format!("cannot read the response: {e}"))?;
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..read]);
            // The ceiling is checked while reading, not after: a peer that sends
            // for ever must be stopped, not measured.
            if raw.len() > MAX_RESPONSE {
                return Err(format!("the response exceeded {MAX_RESPONSE} bytes"));
            }
        }
        parse_response(&raw)
    }
}

/// Split a whole HTTP response into its status and its body.
///
/// Separate from the socket so it can be tested against bytes rather than against
/// a network.
pub fn parse_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "the response has no header section".to_owned())?;
    if split > MAX_HEADERS {
        return Err(format!("the header section exceeded {MAX_HEADERS} bytes"));
    }
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|_| "the response head is not text".to_owned())?;
    let body = &raw[split + 4..];

    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| "the response has no status line".to_owned())?;
    let code: u16 = status
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("cannot read a status code from {status:?}"))?;
    if code != 200 {
        return Err(format!("the authority answered {code}"));
    }

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        // A chunked or otherwise re-framed body is refused rather than decoded.
        // Deleting the family is cheaper than defending against it, and no
        // authority needs it for a four-kilobyte answer.
        if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            return Err(format!(
                "the response used Transfer-Encoding:{value}, which this client does not decode"
            ));
        }
        if name.trim().eq_ignore_ascii_case("content-length") {
            let declared: usize = value
                .trim()
                .parse()
                .map_err(|_| format!("an unreadable Content-Length:{value}"))?;
            // Not merely a bound: a body shorter than declared is a truncated
            // token, and a token missing its last byte fails to verify in a way
            // that looks like a bad authority.
            if declared != body.len() {
                return Err(format!(
                    "the authority declared {declared} bytes and sent {}",
                    body.len()
                ));
            }
        }
    }

    if body.is_empty() {
        return Err("the authority answered 200 with no body".to_owned());
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_splits_into_authority_path_and_host() {
        let t = HttpTransport::new("http://freetsa.org/tsr").expect("a valid URL");
        assert_eq!(t.authority, "freetsa.org:80");
        assert_eq!(t.path, "/tsr");
        assert_eq!(
            t.host, "freetsa.org",
            "the default port is omitted from Host"
        );

        let t = HttpTransport::new("http://tsa.example:3161/api/v1").expect("a valid URL");
        assert_eq!(t.authority, "tsa.example:3161");
        assert_eq!(t.path, "/api/v1");
        assert_eq!(t.host, "tsa.example:3161");

        let t = HttpTransport::new("http://tsa.example").expect("a valid URL");
        assert_eq!(t.path, "/", "a URL with no path targets the root");
    }

    /// `https` is refused by name. Attempting it and failing at the TLS handshake
    /// would report a connection problem for what is a configuration problem.
    #[test]
    fn https_and_other_schemes_are_refused_by_name() {
        for url in [
            "https://tsa.example/tsr",
            "tsa.example/tsr",
            "ftp://tsa.example",
        ] {
            assert!(
                matches!(HttpTransport::new(url), Err(UrlError::NotHttp)),
                "{url} should be refused as not http"
            );
        }
        assert!(matches!(
            HttpTransport::new("http:///tsr"),
            Err(UrlError::NoHost)
        ));
        for url in ["http://tsa.example:0/", "http://tsa.example:x/"] {
            assert!(
                matches!(HttpTransport::new(url), Err(UrlError::BadPort)),
                "{url} should be refused for its port"
            );
        }
    }

    #[test]
    fn a_two_hundred_with_a_body_yields_the_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(parse_response(raw), Ok(b"abc".to_vec()));
    }

    #[test]
    fn any_status_other_than_two_hundred_is_reported_with_its_code() {
        for (raw, code) in [
            (&b"HTTP/1.1 404 Not Found\r\n\r\nx"[..], "404"),
            (&b"HTTP/1.1 500 Oops\r\n\r\nx"[..], "500"),
            (
                &b"HTTP/1.1 301 Moved\r\nLocation: /elsewhere\r\n\r\nx"[..],
                "301",
            ),
        ] {
            let error = parse_response(raw).expect_err("a non-200 must fail");
            assert!(error.contains(code), "{error}");
        }
    }

    /// A body one byte short of what was declared is a truncated token, and a
    /// truncated token fails to verify in a way that looks like a bad authority.
    /// Caught here, where the reason is still visible.
    #[test]
    fn a_body_that_disagrees_with_its_declared_length_is_refused() {
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc";
        let error = parse_response(short).expect_err("a short body must fail");
        assert!(
            error.contains("declared 4") && error.contains("sent 3"),
            "{error}"
        );

        let long = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabc";
        assert!(parse_response(long).is_err());
    }

    #[test]
    fn a_transfer_encoding_is_refused_rather_than_decoded() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let error = parse_response(raw).expect_err("chunked must be refused");
        assert!(error.contains("Transfer-Encoding"), "{error}");
    }

    #[test]
    fn a_response_with_no_header_section_or_no_body_is_refused() {
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(parse_response(b"").is_err());
        let empty = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let error = parse_response(empty).expect_err("an empty body must fail");
        assert!(error.contains("no body"), "{error}");
    }

    /// The peer is an authority and still not trusted: a header section that
    /// never ends must be bounded rather than measured.
    #[test]
    fn an_oversized_header_section_is_refused() {
        let mut raw = b"HTTP/1.1 200 OK\r\n".to_vec();
        raw.extend(std::iter::repeat_n(b'X', MAX_HEADERS + 10));
        raw.extend_from_slice(b"\r\n\r\nbody");
        let error = parse_response(&raw).expect_err("an oversized head must fail");
        assert!(error.contains("header section"), "{error}");
    }
}
