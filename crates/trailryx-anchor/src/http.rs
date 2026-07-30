//! The TSP side of HTTP: one POST, one answer, and everything else refused.
//!
//! The socket, the framing and the response parsing live in `trailryx-http`, which
//! is the workspace's one HTTP client. What stays here is the part that is about
//! timestamping rather than about HTTP:
//!
//! - **Only `200` is an answer.** A `404` from a timestamp authority is a
//!   misconfigured URL, not a token, and a caller that had to distinguish statuses
//!   would be reimplementing this decision at every call site.
//! - **A `200` with no body is refused.** A token of zero bytes fails to parse
//!   later, and the error there names DER rather than the authority.
//! - **A chunked answer is refused.** The general client decodes chunked because S3
//!   cannot list a bucket otherwise. An authority sending a four-kilobyte token has
//!   no reason to, and accepting framing nothing needs is how a parser grows a
//!   surface.
//! - **The response ceiling stays at a megabyte.** A token is a few kilobytes; a
//!   megabyte is an authority malfunctioning, or something else on that port.

use std::time::Duration;

use trailryx_http::{Client, Http, Method, Request};

use crate::Transport;

/// A response larger than this is refused unread.
pub const MAX_RESPONSE: usize = trailryx_http::DEFAULT_MAX_RESPONSE;

pub use trailryx_http::UrlError;

/// A one-shot HTTP client for a single TSP endpoint.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: Client,
    /// The request target, beginning with `/`.
    path: String,
}

impl HttpTransport {
    /// From an `http://host[:port]/path` URL, parsed strictly.
    pub fn new(url: &str) -> Result<Self, UrlError> {
        let rest = url.strip_prefix("http://").ok_or(UrlError::NotHttp)?;
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        Ok(Self {
            client: Client::new(&format!("http://{authority}"))?,
            path: path.to_owned(),
        })
    }

    pub fn with_timeouts(mut self, connect: Duration, io: Duration) -> Self {
        self.client = self.client.with_timeouts(connect, io);
        self
    }
}

impl Transport for HttpTransport {
    fn exchange(&mut self, query: &[u8]) -> Result<Vec<u8>, String> {
        let request = Request::new(Method::Post, self.path.clone())
            .header("Content-Type", "application/timestamp-query")
            .header("Accept", "application/timestamp-reply")
            .body(query.to_vec());
        let response = self.client.send(&request)?;
        token_from(&response)
    }
}

/// The TSP policy on a response, separate from the socket so it can be tested
/// against bytes rather than against a network.
pub fn token_from(response: &trailryx_http::Response) -> Result<Vec<u8>, String> {
    if response.status != 200 {
        return Err(format!("the authority answered {}", response.status));
    }
    if let Some(encoding) = response.header("transfer-encoding") {
        return Err(format!(
            "the response used Transfer-Encoding:{encoding}, which this client does not decode"
        ));
    }
    if response.body.is_empty() {
        return Err("the authority answered 200 with no body".to_owned());
    }
    Ok(response.body.clone())
}

/// Parse a whole HTTP response and apply the TSP policy to it.
pub fn parse_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    let response = trailryx_http::parse_response(raw, MAX_RESPONSE)?;
    token_from(&response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_splits_into_authority_path_and_host() {
        let t = HttpTransport::new("http://freetsa.org/tsr").expect("a valid URL");
        assert_eq!(t.path, "/tsr");
        assert_eq!(
            t.client.host(),
            "freetsa.org",
            "the default port is omitted from Host"
        );

        let t = HttpTransport::new("http://tsa.example:3161/api/v1").expect("a valid URL");
        assert_eq!(t.path, "/api/v1");
        assert_eq!(t.client.host(), "tsa.example:3161");

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

    /// Only `200` is an answer here. A `404` is a misconfigured URL and a `301` is
    /// somebody else's endpoint: neither is a token.
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

    /// The general client decodes chunked, because S3 needs it. This one refuses
    /// it, because nothing an authority sends needs it.
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
        raw.extend(std::iter::repeat_n(b'X', 16 * 1024 + 10));
        raw.extend_from_slice(b"\r\n\r\nbody");
        let error = parse_response(&raw).expect_err("an oversized head must fail");
        assert!(error.contains("header section"), "{error}");
    }
}
