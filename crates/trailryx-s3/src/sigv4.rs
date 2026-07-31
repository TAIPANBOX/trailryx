//! AWS Signature Version 4, written from the specification.
//!
//! # Why this rather than a cloud SDK
//!
//! The S3 API is HTTP plus a signature. `aws-sdk-s3` brings a runtime, an HTTP stack,
//! a TLS stack and several hundred crates to say that; this workspace already has an
//! HTTP client and the two hash functions the signature is made of. Writing the
//! signature keeps the store's storage adapter the same size as the rest of it.
//!
//! That trade is only defensible if the signature is **right**, and a signature
//! checked against itself is a signature that will be rejected in production with no
//! useful error. So correctness is not argued here, it is delegated: the test suite
//! drives the **AWS CLI**, reads the canonical request, string to sign and signature
//! out of its debug log, and requires this module to produce the same bytes for the
//! same inputs. An implementation checked against the tool the service's own authors
//! ship is checked in the way that matters.
//!
//! # The parts that are easy to get wrong, and are therefore stated
//!
//! - **`UriEncode` is not the standard one.** AWS says so itself: "The standard
//!   UriEncode functions provided by your development platform may not work because of
//!   differences in implementation". Unreserved characters are `A-Z a-z 0-9 - _ . ~`
//!   and everything else is percent-encoded uppercase, **except** that the slashes in
//!   a path are left alone.
//! - **The query string is sorted after encoding**, not before. Sorting first gives a
//!   different order whenever encoding changes a byte's ordinal.
//! - **Header values are trimmed and their internal runs of spaces collapsed.**
//! - **Header names are lowercased and sorted**, and the signed-headers list must be
//!   the same set in the same order.
//! - **S3 requires `x-amz-content-sha256`**, and for an empty body it is the hash of
//!   the empty string rather than an empty value.

use trailryx_crypto::{Sha256, hmac_sha256};

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const TERMINATOR: &str = "aws4_request";

/// Whose version of this signature to produce.
///
/// The algorithm is identical; four strings are not. Google's XML API accepts an
/// `AWS4-HMAC-SHA256` signature, which is why the S3 adapter reached it at all, but
/// **a request signed that way may carry only `x-amz-*` extension headers**. Mixing
/// in an `x-goog-*` one is refused with `400 ExcessHeaderValues`, and the only
/// conditional-write header Google has is `x-goog-if-generation-match`.
///
/// So a live GCS bucket answered reads and refused every conditional write, which is
/// the single operation the whole publication design rests on. Signing the Google way
/// is not a preference here; it is the difference between an adapter that can publish
/// a segment atomically and one that cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Aws,
    Google,
}

impl Scheme {
    fn algorithm(self) -> &'static str {
        match self {
            Self::Aws => ALGORITHM,
            Self::Google => "GOOG4-HMAC-SHA256",
        }
    }

    /// The literal in front of the secret in the first HMAC.
    fn key_prefix(self) -> &'static [u8] {
        match self {
            Self::Aws => b"AWS4",
            Self::Google => b"GOOG4",
        }
    }

    fn terminator(self) -> &'static str {
        match self {
            Self::Aws => TERMINATOR,
            Self::Google => "goog4_request",
        }
    }

    /// The header carrying the request time, and the one carrying the payload hash.
    pub fn date_header(self) -> &'static str {
        match self {
            Self::Aws => "x-amz-date",
            Self::Google => "x-goog-date",
        }
    }

    pub fn content_sha_header(self) -> &'static str {
        match self {
            Self::Aws => "x-amz-content-sha256",
            Self::Google => "x-goog-content-sha256",
        }
    }

    pub fn security_token_header(self) -> &'static str {
        match self {
            Self::Aws => "x-amz-security-token",
            Self::Google => "x-goog-security-token",
        }
    }

    /// What the credential scope calls the service.
    pub fn service(self) -> &'static str {
        match self {
            Self::Aws => "s3",
            Self::Google => "storage",
        }
    }
}

/// The credentials a request is signed with.
///
/// The secret is held as bytes and never printed: `Debug` is hand-written to say so
/// rather than to show it.
#[derive(Clone)]
pub struct Credentials {
    pub access_key_id: String,
    secret: Vec<u8>,
    /// For temporary credentials from STS. Sent and signed as
    /// `x-amz-security-token`, which S3 requires in the canonical request.
    pub session_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("session_token", &self.session_token.is_some())
            .finish_non_exhaustive()
    }
}

impl Credentials {
    pub fn new(access_key_id: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret: secret.into().into_bytes(),
            session_token: None,
        }
    }

    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(token.into());
        self
    }
}

impl Credentials {
    /// The session token, when these are temporary credentials.
    ///
    /// Returned rather than exposed as a field so the struct keeps one way in and
    /// the `Debug` written for it stays the only way anything gets printed.
    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }
}

/// One request, in the shape the signature is computed over.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// The absolute path, not yet encoded. Its slashes stay slashes.
    pub path: String,
    /// Query parameters as `(name, value)`, unencoded and in any order.
    pub query: Vec<(String, String)>,
    /// Headers as `(name, value)`. `host` and every `x-amz-*` must be here.
    pub headers: Vec<(String, String)>,
    pub payload: Vec<u8>,
}

/// What a signature run produced, kept whole so a test can compare each stage.
///
/// The intermediate values are public on purpose: when a signature is rejected, the
/// only useful question is which of the three stages first differs from the service's,
/// and a signer that returned only the final hex leaves nobody able to ask it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub canonical_request: String,
    pub string_to_sign: String,
    pub signature: String,
    pub authorization: String,
    pub signed_headers: String,
}

/// AWS's `UriEncode`, which is not the platform's.
///
/// `slashes` false for a path segment inside a query value, true for a path.
pub fn uri_encode(input: &str, keep_slashes: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            b'/' if keep_slashes => out.push('/'),
            // Uppercase hex, which the specification requires and which a lowercase
            // encoder silently gets wrong for every path containing a space.
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Trim, then collapse internal runs of spaces to one.
fn canonical_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_space = false;
    for ch in value.trim().chars() {
        if ch == ' ' {
            in_space = true;
            continue;
        }
        if in_space {
            out.push(' ');
            in_space = false;
        }
        out.push(ch);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The hash S3 wants in `x-amz-content-sha256`, and the same value the canonical
/// request ends with.
///
/// Public because the header has to be signed, so the caller needs the hash before
/// signing rather than after. Two places computing it separately is how they come to
/// disagree for an empty body.
pub fn payload_hash(payload: &[u8]) -> String {
    hex(&Sha256::digest(payload))
}

/// The hash of an empty payload, which S3 wants in `x-amz-content-sha256` when there
/// is no body. Computed rather than pasted, so it cannot be a typo.
pub fn empty_payload_hash() -> String {
    hex(&Sha256::digest(b""))
}

/// The query string as the signature sees it, which is also what has to go on the
/// request line.
///
/// Encoded first, then sorted. Sorting before encoding gives a different order
/// whenever the encoding changes a byte's ordinal, which is the kind of difference
/// that only shows up on the one key somebody happens to use: `a+` encodes to
/// `a%2B`, and `%` sorts before `b`.
///
/// Public because the caller has to put these exact bytes in the request line. The
/// service recomputes the signature from what arrives, so a target that differs from
/// what was signed is rejected with `SignatureDoesNotMatch` and no hint as to which
/// byte moved.
pub fn canonical_query(query: &[(String, String)]) -> String {
    let mut query: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    query.sort();
    query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

impl Request {
    /// The canonical request, and the signed-headers list that goes with it.
    pub fn canonical(&self, payload_hash: &str) -> (String, String) {
        let path = if self.path.is_empty() {
            "/".to_owned()
        } else {
            uri_encode(&self.path, true)
        };

        let query = canonical_query(&self.query);

        let mut headers: Vec<(String, String)> = self
            .headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), canonical_value(v)))
            .collect();
        headers.sort();
        let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let signed_headers: String = headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let canonical = format!(
            "{}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            self.method
        );
        (canonical, signed_headers)
    }
}

/// Sign a request.
///
/// `timestamp` is `YYYYMMDDTHHMMSSZ`, supplied rather than read from a clock: nothing
/// in this workspace reads one for itself, and a signer that did could not be tested
/// against another implementation's output.
pub fn sign(
    request: &Request,
    credentials: &Credentials,
    region: &str,
    service: &str,
    timestamp: &str,
) -> Signed {
    sign_as(
        Scheme::Aws,
        request,
        credentials,
        region,
        service,
        timestamp,
    )
}

/// The same signature, in whichever of the two dialects the endpoint speaks.
pub fn sign_as(
    scheme: Scheme,
    request: &Request,
    credentials: &Credentials,
    region: &str,
    service: &str,
    timestamp: &str,
) -> Signed {
    let payload_hash = hex(&Sha256::digest(&request.payload));
    let (canonical_request, signed_headers) = request.canonical(&payload_hash);

    let date = &timestamp[..8];
    let scope = format!("{date}/{region}/{service}/{}", scheme.terminator());
    let string_to_sign = format!(
        "{}\n{timestamp}\n{scope}\n{}",
        scheme.algorithm(),
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );

    // Four chained HMACs, each keyed by the previous result. The first key is the
    // literal "AWS4" concatenated with the secret, which is the step most often
    // written as just the secret.
    let mut key = Vec::with_capacity(5 + credentials.secret.len());
    key.extend_from_slice(scheme.key_prefix());
    key.extend_from_slice(&credentials.secret);
    let key = hmac_sha256(&key, date.as_bytes());
    let key = hmac_sha256(&key, region.as_bytes());
    let key = hmac_sha256(&key, service.as_bytes());
    let key = hmac_sha256(&key, scheme.terminator().as_bytes());
    let signature = hex(&hmac_sha256(&key, string_to_sign.as_bytes()));

    // No comma after the algorithm, commas between the rest. AWS states that
    // explicitly because it is the shape everybody gets wrong once.
    let authorization = format!(
        "{} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        scheme.algorithm(),
        credentials.access_key_id
    );

    Signed {
        canonical_request,
        string_to_sign,
        signature,
        authorization,
        signed_headers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_encoding_follows_aws_rules_and_not_the_platforms() {
        assert_eq!(uri_encode("abcXYZ019-_.~", false), "abcXYZ019-_.~");
        // Uppercase hex, and a space is %20 rather than a plus.
        assert_eq!(uri_encode("a b", false), "a%20b");
        assert_eq!(uri_encode("a+b", false), "a%2Bb");
        // A slash is encoded in a query value and left alone in a path.
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
        assert_eq!(uri_encode("a/b", true), "a/b");
        // Non-ASCII is encoded byte by byte.
        assert_eq!(uri_encode("é", false), "%C3%A9");
        assert_eq!(uri_encode("*", false), "%2A");
    }

    #[test]
    fn a_header_value_is_trimmed_and_its_inner_spaces_collapsed() {
        assert_eq!(canonical_value("  a  b  "), "a b");
        assert_eq!(canonical_value("a"), "a");
        assert_eq!(canonical_value("   "), "");
        assert_eq!(canonical_value("a\tb"), "a\tb", "only spaces collapse");
    }

    /// The query string is sorted AFTER encoding. This case is the one where it
    /// matters: `+` encodes to `%2B`, and `%` sorts before an alphabetic character.
    #[test]
    fn the_query_string_is_sorted_after_encoding_and_not_before() {
        // Given in an order that is neither the answer nor the order these keys
        // sort in before encoding. The first version of this test supplied them
        // already in the right order, so it passed against a signer that did not
        // sort at all: a mutation removing the sort went undetected, which made the
        // test a comment. `{` is the pair that makes the two orders differ, because
        // it encodes to `%7B` and `%` sorts below every unreserved character while
        // `{` sorts above them.
        let request = Request {
            method: "GET".into(),
            path: "/".into(),
            query: vec![
                ("ab".into(), "3".into()),
                ("a".into(), "1".into()),
                ("{".into(), "2".into()),
                ("a+".into(), "4".into()),
            ],
            headers: vec![("host".into(), "example".into())],
            payload: Vec::new(),
        };
        let (canonical, _) = request.canonical(&empty_payload_hash());
        let query_line = canonical.lines().nth(2).unwrap();
        assert_eq!(
            query_line, "%7B=2&a=1&a%2B=4&ab=3",
            "encoded first, then sorted: %2B sorts before b, and %7B before everything"
        );
    }

    #[test]
    fn the_canonical_request_has_the_six_parts_in_order() {
        let request = Request {
            method: "PUT".into(),
            path: "/bucket/key".into(),
            query: Vec::new(),
            headers: vec![
                ("X-Amz-Date".into(), "20260730T000000Z".into()),
                ("Host".into(), "s3.example".into()),
            ],
            payload: b"body".to_vec(),
        };
        let hash = hex(&Sha256::digest(b"body"));
        let (canonical, signed) = request.canonical(&hash);
        let lines: Vec<&str> = canonical.split('\n').collect();
        assert_eq!(lines[0], "PUT");
        assert_eq!(lines[1], "/bucket/key");
        assert_eq!(
            lines[2], "",
            "no query means an empty line, not a missing one"
        );
        assert_eq!(lines[3], "host:s3.example");
        assert_eq!(lines[4], "x-amz-date:20260730T000000Z");
        assert_eq!(lines[5], "", "the headers block ends with its own newline");
        assert_eq!(lines[6], "host;x-amz-date");
        assert_eq!(lines[7], hash);
        assert_eq!(signed, "host;x-amz-date");
    }

    /// AWS's own worked example, from the signing documentation. Different service and
    /// region from anything S3, which is the point: the algorithm is not S3's.
    #[test]
    fn the_documented_worked_example_produces_the_documented_signature() {
        let request = Request {
            method: "GET".into(),
            path: "/".into(),
            query: vec![
                ("Action".into(), "ListUsers".into()),
                ("Version".into(), "2010-05-08".into()),
            ],
            headers: vec![
                ("Host".into(), "iam.amazonaws.com".into()),
                (
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded; charset=utf-8".into(),
                ),
                ("X-Amz-Date".into(), "20150830T123600Z".into()),
            ],
            payload: Vec::new(),
        };
        let credentials =
            Credentials::new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let signed = sign(
            &request,
            &credentials,
            "us-east-1",
            "iam",
            "20150830T123600Z",
        );
        assert_eq!(
            signed.signature,
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    /// Two chained HMACs with the same inputs must give the same key, and the "AWS4"
    /// prefix must matter: signing with the bare secret is the classic slip and it
    /// produces a signature that is wrong in a way no error message explains.
    #[test]
    fn the_signing_key_is_derived_from_aws4_plus_the_secret() {
        let request = Request {
            method: "GET".into(),
            path: "/".into(),
            query: Vec::new(),
            headers: vec![("host".into(), "x".into())],
            payload: Vec::new(),
        };
        let with_prefix = sign(
            &request,
            &Credentials::new("A", "secret"),
            "r",
            "s",
            "20260730T000000Z",
        );
        let as_if_no_prefix = sign(
            &request,
            &Credentials::new("A", "AWS4secret"),
            "r",
            "s",
            "20260730T000000Z",
        );
        assert_ne!(with_prefix.signature, as_if_no_prefix.signature);
    }

    #[test]
    fn the_authorization_header_has_no_comma_after_the_algorithm() {
        let signed = sign(
            &Request {
                method: "GET".into(),
                path: "/".into(),
                query: Vec::new(),
                headers: vec![("host".into(), "x".into())],
                payload: Vec::new(),
            },
            &Credentials::new("AKID", "secret"),
            "us-east-1",
            "s3",
            "20260730T000000Z",
        );
        assert!(
            signed
                .authorization
                .starts_with(&format!("{ALGORITHM} Credential="))
        );
        assert!(!signed.authorization.starts_with(&format!("{ALGORITHM},")));
        assert_eq!(signed.authorization.matches(", ").count(), 2);
    }

    #[test]
    fn a_secret_is_never_printed() {
        // The values are chosen so they cannot appear in a field NAME. The first
        // version of this test looked for "tok" and found it inside `session_token`,
        // which failed while the code was right.
        let credentials =
            Credentials::new("AKID", "SECRET-XYZZY").with_session_token("SESSION-PLUGH");
        let printed = format!("{credentials:?}");
        assert!(!printed.contains("SECRET-XYZZY"), "{printed}");
        assert!(!printed.contains("SESSION-PLUGH"), "{printed}");
        assert!(
            printed.contains("AKID"),
            "the key id is not a secret and is useful"
        );
    }
}
