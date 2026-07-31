//! Azure's Shared Key signature, which is nothing like SigV4.
//!
//! # Why this is a second signer rather than a third flavour
//!
//! Google's XML API is the S3 API, so that adapter is the same code with four names
//! changed. Azure is not: a different string to sign, a different canonicalisation,
//! a different key encoding, a different authorization header. Pretending otherwise
//! would produce a signer with two shapes inside it and a test suite that covers
//! neither properly.
//!
//! # The three rules that bite, each with its own test
//!
//! - **`Content-Length` is an empty line when it is zero**, not `0`. It was `0`
//!   until version 2015-02-21 and Microsoft documents the change with both strings
//!   side by side, which is a strong hint about how many people it caught. Every
//!   conditional create sends a body, but a delete or a metadata call does not.
//! - **The `Date` line is empty when `x-ms-date` is used.** The date still has to be
//!   in the signature, but through the canonicalised headers rather than through its
//!   own line, and putting it in both places produces a signature nobody accepts.
//! - **The canonicalised resource takes query parameters decoded, lowercased and
//!   sorted**, each on its own line as `name:value`, with multiple values for one
//!   name sorted and comma-joined. The path stays encoded exactly as it appears in
//!   the request; the query does not.
//!
//! The tests pin the two worked examples Microsoft publishes, byte for byte. That is
//! the same discipline the S3 signer gets from the AWS CLI: a signature checked only
//! against itself is one that gets rejected in production with no clue which stage
//! was wrong.

use trailryx_crypto::hmac_sha256;

/// The account and its key, which arrives base64 as Azure hands it out.
pub struct Credentials {
    pub account: String,
    key: Vec<u8>,
}

impl std::fmt::Debug for Credentials {
    /// Written by hand so no future `derive` can start printing the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("account", &self.account)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Credentials {
    /// From the base64 key as the portal shows it.
    ///
    /// `None` when the key is not base64, which is the difference between a
    /// signature nobody accepts and an error at startup.
    pub fn new(account: impl Into<String>, base64_key: &str) -> Option<Self> {
        Some(Self {
            account: account.into(),
            key: base64_decode(base64_key)?,
        })
    }
}

/// One request, in the shape the signature is computed over.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// The path as it appears in the request, already encoded.
    pub path: String,
    /// Query parameters, decoded.
    pub query: Vec<(String, String)>,
    /// Headers as `(name, value)`. Every `x-ms-*` one is signed.
    pub headers: Vec<(String, String)>,
    pub content_length: usize,
    pub content_type: Option<String>,
}

/// The canonicalised `x-ms-*` headers, one per line.
///
/// Lowercased, sorted, whitespace in values collapsed, each terminated by a newline.
/// An empty value keeps its line rather than disappearing, which changed in service
/// version 2016-05-31 and silently invalidates a signature written against the older
/// behaviour.
fn canonical_headers(headers: &[(String, String)]) -> String {
    let mut ms: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, _)| name.to_ascii_lowercase().starts_with("x-ms-"))
        .map(|(name, value)| (name.to_ascii_lowercase(), collapse(value)))
        .collect();
    ms.sort_by(|a, b| a.0.cmp(&b.0));
    ms.iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect()
}

/// Linear whitespace becomes one space, and the ends are trimmed.
fn collapse(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut space = false;
    for ch in value.trim().chars() {
        if ch.is_ascii_whitespace() {
            space = true;
            continue;
        }
        if space {
            out.push(' ');
            space = false;
        }
        out.push(ch);
    }
    out
}

/// `/account/path`, then one line per query parameter.
pub fn canonical_resource(account: &str, path: &str, query: &[(String, String)]) -> String {
    let mut out = format!("/{account}{path}");
    // Names lowercased and sorted; values for a repeated name sorted and joined by
    // commas. Both are documented, and both are invisible until the one request that
    // repeats a parameter fails to sign.
    let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
    for (name, value) in query {
        let name = name.to_ascii_lowercase();
        match grouped.iter_mut().find(|(n, _)| *n == name) {
            Some((_, values)) => values.push(value.clone()),
            None => grouped.push((name, vec![value.clone()])),
        }
    }
    grouped.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, mut values) in grouped {
        values.sort();
        out.push('\n');
        out.push_str(&name);
        out.push(':');
        out.push_str(&values.join(","));
    }
    out
}

/// The string Azure signs, in the order Azure documents.
pub fn string_to_sign(account: &str, request: &Request) -> String {
    // The `Date` line stays empty because every request here carries `x-ms-date`,
    // and Microsoft is explicit that the date belongs in one place or the other,
    // never both.
    let date_line = "";
    // Empty when zero, which stopped being `0` in version 2015-02-21.
    let length = if request.content_length == 0 {
        String::new()
    } else {
        request.content_length.to_string()
    };
    let header = |name: &str| -> String {
        request
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| collapse(v))
            .unwrap_or_default()
    };

    format!(
        "{method}\n{encoding}\n{language}\n{length}\n{md5}\n{content_type}\n{date_line}\n\
         {modified_since}\n{if_match}\n{if_none_match}\n{unmodified_since}\n{range}\n\
         {headers}{resource}",
        method = request.method.to_ascii_uppercase(),
        encoding = header("content-encoding"),
        language = header("content-language"),
        md5 = header("content-md5"),
        content_type = request.content_type.clone().unwrap_or_default(),
        modified_since = header("if-modified-since"),
        if_match = header("if-match"),
        if_none_match = header("if-none-match"),
        unmodified_since = header("if-unmodified-since"),
        range = header("range"),
        headers = canonical_headers(&request.headers),
        resource = canonical_resource(account, &request.path, &request.query),
    )
}

/// The `Authorization` header value for a request.
pub fn authorization(credentials: &Credentials, request: &Request) -> String {
    let to_sign = string_to_sign(&credentials.account, request);
    let signature = base64_encode(&hmac_sha256(&credentials.key, to_sign.as_bytes()));
    format!("SharedKey {}:{signature}", credentials.account)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Strict: one spelling of the bytes, padding required, nothing else accepted.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        ALPHABET
            .iter()
            .position(|a| *a == c)
            .map(|p| u32::try_from(p).unwrap_or_default())
    };
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && chunk[3] != b'=') {
            return None;
        }
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = if *c == b'=' { 0 } else { value(*c)? };
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    /// Microsoft's own worked example, byte for byte. A signer checked only against
    /// itself is one that gets rejected in production with no clue which stage was
    /// wrong, so this is the same discipline the S3 signer gets from the AWS CLI.
    #[test]
    fn the_documented_get_example_produces_the_documented_string() {
        let request = Request {
            method: "GET".into(),
            path: "/mycontainer".into(),
            query: vec![
                ("restype".into(), "container".into()),
                ("comp".into(), "metadata".into()),
                ("timeout".into(), "20".into()),
            ],
            headers: vec![
                header("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT"),
                header("x-ms-version", "2015-02-21"),
            ],
            content_length: 0,
            content_type: None,
        };
        assert_eq!(
            string_to_sign("myaccount", &request),
            "GET\n\n\n\n\n\n\n\n\n\n\n\n\
             x-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n\
             /myaccount/mycontainer\ncomp:metadata\nrestype:container\ntimeout:20"
        );
    }

    /// The second published example, which exists because of one field: a zero
    /// content length is an empty line, and used to be `0`. Microsoft prints both
    /// versions side by side, which says how many implementations it caught.
    #[test]
    fn a_zero_content_length_is_an_empty_line_and_not_a_zero() {
        let request = Request {
            method: "PUT".into(),
            path: "/mycontainer".into(),
            query: vec![
                ("restype".into(), "container".into()),
                ("timeout".into(), "30".into()),
            ],
            headers: vec![
                header("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT"),
                header("x-ms-version", "2015-02-21"),
            ],
            content_length: 0,
            content_type: None,
        };
        assert_eq!(
            string_to_sign("myaccount", &request),
            "PUT\n\n\n\n\n\n\n\n\n\n\n\n\
             x-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n\
             /myaccount/mycontainer\nrestype:container\ntimeout:30"
        );
        assert!(
            !string_to_sign("myaccount", &request).contains("\n0\n"),
            "a zero length must not appear as a zero"
        );
    }

    /// A body that is present takes its length, in the fourth line and nowhere else.
    #[test]
    fn a_body_puts_its_length_in_the_fourth_line() {
        let request = Request {
            method: "PUT".into(),
            path: "/c/b".into(),
            query: Vec::new(),
            headers: vec![
                header("x-ms-date", "d"),
                header("x-ms-blob-type", "BlockBlob"),
            ],
            content_length: 17,
            content_type: Some("application/octet-stream".into()),
        };
        let signed = string_to_sign("acct", &request);
        let lines: Vec<&str> = signed.split('\n').collect();
        assert_eq!(lines[0], "PUT");
        assert_eq!(lines[3], "17", "content length is the fourth line");
        assert_eq!(lines[5], "application/octet-stream");
        assert_eq!(
            lines[9], "",
            "if-none-match is the tenth line and empty when unset"
        );
    }

    /// The conditional create rides in the signature, on its own documented line.
    /// Sending it unsigned would let a proxy strip the one header that makes
    /// publication atomic.
    #[test]
    fn the_conditional_header_is_part_of_what_gets_signed() {
        let mut request = Request {
            method: "PUT".into(),
            path: "/c/b".into(),
            query: Vec::new(),
            headers: vec![header("x-ms-date", "d")],
            content_length: 3,
            content_type: None,
        };
        let without = string_to_sign("acct", &request);
        request.headers.push(header("if-none-match", "*"));
        let with = string_to_sign("acct", &request);
        assert_ne!(without, with);
        assert_eq!(with.split('\n').nth(9), Some("*"));
    }

    #[test]
    fn headers_are_lowercased_sorted_and_their_whitespace_collapsed() {
        let request = Request {
            method: "GET".into(),
            path: "/c".into(),
            query: Vec::new(),
            headers: vec![
                header("X-Ms-Version", "  2021-08-06  "),
                header("x-ms-date", "Mon,  1 Jan\t2026"),
                header("Authorization", "must not be signed"),
                header("Host", "must not be signed"),
            ],
            content_length: 0,
            content_type: None,
        };
        let signed = string_to_sign("acct", &request);
        assert!(signed.contains("x-ms-date:Mon, 1 Jan 2026\nx-ms-version:2021-08-06\n"));
        assert!(
            !signed.contains("must not be signed"),
            "only x-ms-* headers are canonicalised"
        );
    }

    /// A repeated parameter is one line with its values sorted and comma-joined,
    /// which is the case nobody writes until the request that needs it fails.
    #[test]
    fn a_repeated_query_parameter_becomes_one_sorted_line() {
        let resource = canonical_resource(
            "myaccount",
            "/mycontainer",
            &[
                ("restype".into(), "container".into()),
                ("comp".into(), "list".into()),
                ("include".into(), "snapshots".into()),
                ("include".into(), "metadata".into()),
                ("include".into(), "uncommittedblobs".into()),
            ],
        );
        assert_eq!(
            resource,
            "/myaccount/mycontainer\ncomp:list\ninclude:metadata,snapshots,uncommittedblobs\n\
             restype:container",
            "Microsoft's own List Blobs example"
        );
    }

    #[test]
    fn base64_round_trips_and_matches_the_published_vectors() {
        // RFC 4648.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(
                base64_encode(plain.as_bytes()),
                encoded,
                "encoding {plain:?}"
            );
            if !encoded.is_empty() {
                assert_eq!(
                    base64_decode(encoded).as_deref(),
                    Some(plain.as_bytes()),
                    "decoding {encoded:?}"
                );
            }
        }
    }

    #[test]
    fn a_key_that_is_not_base64_is_refused_at_construction() {
        assert!(Credentials::new("acct", "not base64!").is_none());
        assert!(Credentials::new("acct", "Zm9vYmFy").is_some());
        // Unpadded is refused: one spelling of the bytes, so a key that round-trips
        // through a config file cannot arrive as two different secrets.
        assert!(base64_decode("Zm8").is_none());
    }

    #[test]
    fn the_authorization_header_has_the_shape_azure_documents() {
        let credentials = Credentials::new("myaccount", "Zm9vYmFy").expect("a key");
        let request = Request {
            method: "GET".into(),
            path: "/c".into(),
            query: Vec::new(),
            headers: vec![header("x-ms-date", "d")],
            content_length: 0,
            content_type: None,
        };
        let value = authorization(&credentials, &request);
        assert!(value.starts_with("SharedKey myaccount:"), "{value}");
        let signature = value.trim_start_matches("SharedKey myaccount:");
        assert_eq!(
            base64_decode(signature).map(|b| b.len()),
            Some(32),
            "an HMAC-SHA256 is 32 bytes, base64 of it is what goes in the header"
        );
    }
}
