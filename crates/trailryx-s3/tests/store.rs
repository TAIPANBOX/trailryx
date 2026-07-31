//! The adapter against a store, over a real socket.
//!
//! The fake speaks enough S3 to answer the four operations, and it runs behind a
//! real `TcpListener` rather than behind a mock of the HTTP client. That is the
//! point: the request line, the header block, the body framing, the chunked listing
//! and the response parsing are all exercised, and those are exactly the places
//! where a hand-written client differs from an SDK.
//!
//! It also plays the store that quietly ignores `If-None-Match`, which is the one
//! kind of S3-compatible endpoint that can destroy a record without ever returning
//! an error.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use trailryx_contracts::{ObjectStore, PutOutcome, VersionId};
use trailryx_s3::{Addressing, Conditional, Credentials, FixedClock, Flavour, S3};

/// What the fake understood a request to be, so a test can assert on what was sent
/// and not only on what came back.
#[derive(Debug, Clone)]
struct Seen {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Which cloud the fake is pretending to be. The two differ in four places and
/// nowhere else, which is the claim the GCS tests exist to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cloud {
    Aws,
    Gcs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Honesty {
    /// Honours `If-None-Match: *` the way AWS documents.
    Conditional,
    /// Accepts the header, ignores it, and overwrites. Several S3-compatible stores
    /// behaved exactly like this, and nothing in the response says so.
    IgnoresPreconditions,
}

struct Fake {
    port: u16,
    seen: mpsc::Receiver<Seen>,
}

impl Fake {
    fn start(honesty: Honesty, requests: usize) -> Self {
        Self::start_as(Cloud::Aws, honesty, requests)
    }

    /// Serve `requests` exchanges and then stop.
    fn start_as(cloud: Cloud, honesty: Honesty, requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let (tx, seen) = mpsc::channel();
        thread::spawn(move || {
            // key -> versions, newest last. A version id is its index, which is
            // opaque to the adapter and is meant to be.
            let mut objects: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
            for _ in 0..requests {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                serve(stream, &mut objects, cloud, honesty, &tx);
            }
        });
        Self { port, seen }
    }

    fn gcs_store(&self) -> S3 {
        self.store(Conditional::IfNoneMatchStar)
            .with_flavour(Flavour::Gcs)
    }

    fn store(&self, conditional: Conditional) -> S3 {
        S3::new(
            &format!("http://127.0.0.1:{}", self.port),
            "records",
            "eu-central-1",
            Credentials::new("AKIAEXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            Addressing::Path,
            conditional,
        )
        .expect("a valid endpoint")
        // A fixed clock, so the signature over a given request is the same bytes
        // every run and a failure is a failure rather than a schedule.
        .with_clock(Box::new(FixedClock(1_772_323_200)))
    }
}

fn serve(
    mut stream: TcpStream,
    objects: &mut HashMap<String, Vec<Vec<u8>>>,
    cloud: Cloud,
    honesty: Honesty,
    tx: &mpsc::Sender<Seen>,
) {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read the head, then exactly as much body as was declared. A server that read
    // to EOF would work here and hang against a client that keeps the socket open.
    let head_end = loop {
        let read = stream.read(&mut chunk).unwrap_or(0);
        if read == 0 {
            break raw
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|at| at + 4)
                .unwrap_or(raw.len());
        }
        raw.extend_from_slice(&chunk[..read]);
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end.saturating_sub(4)]).into_owned();
    let mut lines = head.split("\r\n");
    let line = lines.next().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let declared: usize = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = raw[head_end..].to_vec();
    while body.len() < declared {
        let read = stream.read(&mut chunk).unwrap_or(0);
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }

    let seen = Seen {
        line: line.clone(),
        headers,
        body: body.clone(),
    };
    let _ = tx.send(seen.clone());

    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    // The fake is path-style, so the first segment is the bucket.
    let key = percent_decode(path.trim_start_matches('/'))
        .split_once('/')
        .map(|(_bucket, key)| key.to_owned())
        .unwrap_or_default();

    let listing = match cloud {
        Cloud::Aws => query.contains("list-type=2"),
        Cloud::Gcs => method == "GET" && key.is_empty(),
    };
    let response: Vec<u8> = if key.starts_with("forbidden/") {
        xml_error(
            403,
            "SignatureDoesNotMatch",
            "the request signature does not match",
        )
    } else if listing {
        list(objects, query, cloud)
    } else if method == "PUT" {
        let exists = objects.contains_key(&key);
        let conditional = match cloud {
            Cloud::Aws => seen.header("if-none-match").is_some(),
            // Google's own header, and the value it documents as "only if the
            // object does not currently exist".
            Cloud::Gcs => seen.header("x-goog-if-generation-match") == Some("0"),
        };
        if exists && conditional && honesty == Honesty::Conditional {
            xml_error(412, "PreconditionFailed", "the key was already taken")
        } else {
            let versions = objects.entry(key).or_default();
            versions.push(body);
            let header = match cloud {
                Cloud::Aws => "x-amz-version-id",
                Cloud::Gcs => "x-goog-generation",
            };
            format!(
                "HTTP/1.1 200 OK\r\n{header}: v{}\r\nETag: \"{}\"\r\nContent-Length: 0\r\n\r\n",
                versions.len(),
                versions.len()
            )
            .into_bytes()
        }
    } else if method == "GET" {
        let param = match cloud {
            Cloud::Aws => "versionId=",
            Cloud::Gcs => "generation=",
        };
        let wanted = query
            .split('&')
            .find_map(|p| p.strip_prefix(param))
            .map(percent_decode);
        match (objects.get(&key), wanted) {
            (Some(versions), None) => body_response(versions.last().cloned().unwrap_or_default()),
            (Some(versions), Some(v)) => match v
                .strip_prefix('v')
                .and_then(|n| n.parse::<usize>().ok())
                .and_then(|n| versions.get(n - 1))
            {
                Some(bytes) => body_response(bytes.clone()),
                None => xml_error(404, "NoSuchVersion", "no such version"),
            },
            (None, _) => xml_error(404, "NoSuchKey", "no such key"),
        }
    } else {
        xml_error(405, "MethodNotAllowed", "the fake serves GET and PUT")
    };

    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

/// A listing, two keys per page and chunked, because that is how S3 answers one and
/// a client that cannot decode chunked cannot list a bucket at all.
fn list(objects: &HashMap<String, Vec<Vec<u8>>>, query: &str, cloud: Cloud) -> Vec<u8> {
    let param = |name: &str| -> Option<String> {
        query
            .split('&')
            .find_map(|p| p.strip_prefix(&format!("{name}=")))
            .map(percent_decode)
    };
    let prefix = param("prefix").unwrap_or_default();
    let after = match cloud {
        Cloud::Aws => param("continuation-token"),
        Cloud::Gcs => param("marker"),
    }
    .unwrap_or_default();

    let mut keys: Vec<String> = objects
        .keys()
        .filter(|k| k.starts_with(&prefix))
        .cloned()
        .collect();
    keys.sort();
    let start = keys
        .iter()
        .position(|k| k.as_str() > after.as_str())
        .unwrap_or(keys.len());
    let page: Vec<String> = keys[start..].iter().take(2).cloned().collect();
    let truncated = keys.len() > start + page.len();

    let mut body = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult>");
    for key in &page {
        body.push_str(&format!(
            "<Contents><Key>{}</Key><Size>1</Size></Contents>",
            escape(key)
        ));
    }
    body.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    if truncated {
        match cloud {
            Cloud::Aws => body.push_str(&format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                escape(page.last().expect("a non-empty page"))
            )),
            // Deliberately absent: without a delimiter the marker-based listing
            // returns no NextMarker and the client is expected to continue from the
            // last key it received. A client that only read NextMarker would page
            // correctly until the day somebody stopped using a delimiter.
            Cloud::Gcs => {}
        }
    }
    body.push_str("</ListBucketResult>");

    let mut out = String::from("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n");
    out.push_str("Transfer-Encoding: chunked\r\n\r\n");
    // Split across two chunks on purpose: one chunk would pass even against a
    // decoder that ignored the framing and returned everything after the head.
    let (a, b) = body.split_at(body.len() / 2);
    out.push_str(&format!(
        "{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
        a.len(),
        b.len()
    ));
    out.into_bytes()
}

fn body_response(bytes: Vec<u8>) -> Vec<u8> {
    let mut out =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", bytes.len()).into_bytes();
    out.extend_from_slice(&bytes);
    out
}

fn xml_error(status: u16, code: &str, message: &str) -> Vec<u8> {
    let body = format!(
        "<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>{message}</Message></Error>"
    );
    format!(
        "HTTP/1.1 {status} {code}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;")
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------

/// The whole point of the adapter: two nodes seal the same segment, one wins, and
/// the loser is told it lost rather than being allowed to overwrite.
#[test]
fn a_second_publication_of_a_key_loses_the_race_rather_than_overwriting() {
    let fake = Fake::start(Honesty::Conditional, 3);
    let mut store = fake.store(Conditional::IfNoneMatchStar);

    let (first, version) = store
        .put_if_absent("segments/000001.trx", b"the winner's bytes")
        .expect("the first write");
    assert_eq!(first, PutOutcome::Written);
    assert_eq!(version, Some(VersionId("v1".to_owned())));

    let (second, version) = store
        .put_if_absent("segments/000001.trx", b"a different segment")
        .expect("the second write is an outcome, not an error");
    assert_eq!(second, PutOutcome::AlreadyExists);
    assert_eq!(
        version, None,
        "the loser wrote nothing, so it has no version to name"
    );

    assert_eq!(
        store.get("segments/000001.trx").expect("a read"),
        Some(b"the winner's bytes".to_vec()),
        "the winner's bytes survived"
    );

    let sent = fake.seen.recv().expect("the first request");
    assert_eq!(sent.line.split(' ').next(), Some("PUT"));
    assert_eq!(
        sent.body, b"the winner's bytes",
        "the body arrives whole, and its hash is what was signed"
    );
    assert_eq!(sent.header("if-none-match"), Some("*"));
    let authorization = sent.header("authorization").expect("a signature");
    assert!(
        authorization.contains("SignedHeaders=host;if-none-match;x-amz-content-sha256;x-amz-date"),
        "the condition must be signed, or a proxy could strip it: {authorization}"
    );
    assert!(
        authorization.contains("Credential=AKIAEXAMPLE/20260301/eu-central-1/s3/aws4_request"),
        "{authorization}"
    );
}

/// The store that answers `200` to a conditional write it ignored. Nothing in that
/// response is wrong on its face, which is why the check has to write twice.
#[test]
fn a_store_that_ignores_the_condition_is_caught_by_measuring_it() {
    let honest = Fake::start(Honesty::Conditional, 2);
    let mut store = honest.store(Conditional::IfNoneMatchStar);
    assert!(
        store.verify_conditional_writes("probe/trailryx").is_ok(),
        "an honest store must pass"
    );

    let liar = Fake::start(Honesty::IgnoresPreconditions, 2);
    let mut store = liar.store(Conditional::IfNoneMatchStar);
    let failure = store
        .verify_conditional_writes("probe/trailryx")
        .expect_err("a store that overwrites must be caught");
    assert!(
        failure.to_string().contains("ignores If-None-Match"),
        "{failure}"
    );
}

/// Configured honestly, an endpoint without conditional writes refuses to publish
/// rather than publishing something nobody can trust.
#[test]
fn without_a_conditional_write_the_adapter_refuses_to_publish_at_all() {
    let fake = Fake::start(Honesty::Conditional, 0);
    let mut store = fake.store(Conditional::Absent);
    let failure = store
        .put_if_absent("segments/000001.trx", b"bytes")
        .expect_err("publication must be refused");
    assert!(
        matches!(failure, trailryx_contracts::AdapterError::Unsupported(_)),
        "{failure}"
    );
    assert!(
        store
            .last_failure()
            .expect("the detail survives the contract")
            .to_string()
            .contains("overwrite"),
        "the operator has to be told what would have happened"
    );
}

/// A published object is read back by version, because the current object under a
/// key is whatever the last writer put there.
#[test]
fn a_version_is_readable_after_the_key_has_moved_on() {
    let fake = Fake::start(Honesty::IgnoresPreconditions, 4);
    let mut store = fake.store(Conditional::IfNoneMatchStar);

    let (_, first) = store.put_if_absent("k", b"one").expect("the first write");
    let first = first.expect("a version id");
    store.put_if_absent("k", b"two").expect("the second write");

    assert_eq!(
        store.get("k").expect("a read"),
        Some(b"two".to_vec()),
        "the key now holds the newer object"
    );
    assert_eq!(
        store.get_version("k", &first).expect("a versioned read"),
        Some(b"one".to_vec()),
        "and the published version is still readable"
    );
}

#[test]
fn a_missing_key_and_a_missing_version_are_absent_rather_than_errors() {
    let fake = Fake::start(Honesty::Conditional, 2);
    let mut store = fake.store(Conditional::IfNoneMatchStar);
    assert_eq!(store.get("nothing/here").expect("a read"), None);
    assert_eq!(
        store
            .get_version("nothing/here", &VersionId("v9".to_owned()))
            .expect("a versioned read"),
        None
    );
}

/// A listing that stops at the first page answers a completeness question with a
/// subset and no sign of the rest, which is the worst failure this store can have.
#[test]
fn a_listing_follows_every_continuation_token_to_the_end() {
    let fake = Fake::start(Honesty::Conditional, 5 + 3);
    let mut store = fake.store(Conditional::IfNoneMatchStar);
    for n in 1..=5 {
        store
            .put_if_absent(&format!("runs/2026-07-30/{n:06}.trx"), b"x")
            .expect("a write");
    }
    let keys = store.list("runs/2026-07-30/").expect("a listing");
    assert_eq!(
        keys,
        (1..=5)
            .map(|n| format!("runs/2026-07-30/{n:06}.trx"))
            .collect::<Vec<_>>(),
        "all five keys, across three pages of two"
    );
}

/// Keys are chosen by agents, and agents write keys with spaces, plus signs and
/// non-ASCII in them. Every one of those changes the canonical request, so a key
/// that round-trips is a signature that agreed with the service about the path.
#[test]
fn a_key_with_characters_that_change_the_signature_still_round_trips() {
    let awkward = "runs/a b+c~d/é/seg=1.trx";
    let fake = Fake::start(Honesty::Conditional, 3);
    let mut store = fake.store(Conditional::IfNoneMatchStar);

    store.put_if_absent(awkward, b"awkward").expect("a write");
    assert_eq!(
        store.get(awkward).expect("a read"),
        Some(b"awkward".to_vec())
    );
    assert_eq!(
        store.list("runs/").expect("a listing"),
        vec![awkward.to_owned()],
        "and the listing hands back the key as it was written, not as it was escaped"
    );

    let sent = fake.seen.recv().expect("the write");
    assert!(
        sent.line
            .contains("/records/runs/a%20b%2Bc~d/%C3%A9/seg%3D1.trx"),
        "the request line must carry AWS's encoding, not the platform's: {}",
        sent.line
    );
}

/// A refusal has to arrive with the store's own error code. `SignatureDoesNotMatch`
/// against `NoSuchBucket` is the difference between an hour and a minute, and the
/// contract's `&'static str` cannot carry either, which is why the rich method
/// exists and why the last failure is kept.
#[test]
fn a_refusal_keeps_the_stores_own_code_and_message() {
    let fake = Fake::start(Honesty::Conditional, 2);
    let mut store = fake.store(Conditional::IfNoneMatchStar);

    let failure = store
        .get_object("forbidden/segment.trx")
        .expect_err("a 403 is a refusal");
    match failure {
        trailryx_s3::Failure::Store {
            status,
            code,
            message,
        } => {
            assert_eq!(status, 403);
            assert_eq!(code, "SignatureDoesNotMatch");
            assert!(message.contains("signature"), "{message}");
        }
        other => panic!("expected the store's own words, got {other}"),
    }

    // And through the contract, where the detail is narrowed but not lost.
    let narrowed = store.get("forbidden/segment.trx").expect_err("a refusal");
    assert!(
        matches!(narrowed, trailryx_contracts::AdapterError::Rejected(_)),
        "a 403 will not succeed on retry: {narrowed}"
    );
    assert!(
        store
            .last_failure()
            .expect("kept for the operator")
            .to_string()
            .contains("SignatureDoesNotMatch")
    );
}

// ---------------------------------------------------------------------------
// Google Cloud Storage, which speaks the same API through four different names.

/// The claim this whole flavour rests on: the XML API is the S3 API, so the same
/// signer, the same client and the same XML reach both. What differs is the header
/// that makes a write conditional and the header that names the version.
#[test]
fn a_segment_publishes_atomically_to_google_too() {
    let fake = Fake::start_as(Cloud::Gcs, Honesty::Conditional, 3);
    let mut store = fake.gcs_store();

    let (first, version) = store
        .put_if_absent("segments/000001.trx", b"the winner's bytes")
        .expect("the first write");
    assert_eq!(first, PutOutcome::Written);
    assert_eq!(
        version,
        Some(VersionId("v1".to_owned())),
        "the generation comes back from x-goog-generation, not x-amz-version-id"
    );

    let (second, _) = store
        .put_if_absent("segments/000001.trx", b"a different segment")
        .expect("the second write is an outcome, not an error");
    assert_eq!(second, PutOutcome::AlreadyExists);
    assert_eq!(
        store.get("segments/000001.trx").expect("a read"),
        Some(b"the winner's bytes".to_vec())
    );

    let sent = fake.seen.recv().expect("the first request");
    assert_eq!(
        sent.header("x-goog-if-generation-match"),
        Some("0"),
        "Google's condition is a generation of zero, not an ETag wildcard"
    );
    assert!(
        sent.header("authorization").expect("a signature").contains(
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-goog-if-generation-match"
        ),
        "the condition has to be signed here too, or a proxy could strip it"
    );
}

/// The version read that survives an administrator, under Google's parameter name.
#[test]
fn a_generation_is_readable_after_the_key_has_moved_on() {
    let fake = Fake::start_as(Cloud::Gcs, Honesty::IgnoresPreconditions, 3);
    let mut store = fake.gcs_store();

    let (_, first) = store.put_if_absent("k", b"one").expect("the first write");
    store.put_if_absent("k", b"two").expect("the second write");
    assert_eq!(
        store
            .get_version("k", &first.expect("a generation"))
            .expect("a versioned read"),
        Some(b"one".to_vec()),
        "asked for with ?generation=, which is what this store answers to"
    );
}

/// The marker-based listing, and the case that catches a client written only
/// against the documented happy path: no NextMarker comes back, so continuing means
/// continuing from the last key received.
#[test]
fn a_listing_pages_by_marker_when_nothing_hands_back_a_token() {
    let fake = Fake::start_as(Cloud::Gcs, Honesty::Conditional, 5 + 3);
    let mut store = fake.gcs_store();
    for n in 1..=5 {
        store
            .put_if_absent(&format!("runs/2026-07-31/{n:06}.trx"), b"x")
            .expect("a write");
    }
    let keys = store.list("runs/2026-07-31/").expect("a listing");
    assert_eq!(
        keys,
        (1..=5)
            .map(|n| format!("runs/2026-07-31/{n:06}.trx"))
            .collect::<Vec<_>>(),
        "all five, across three pages, with no continuation token in sight"
    );
}
