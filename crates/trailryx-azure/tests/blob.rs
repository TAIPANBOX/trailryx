//! The adapter against a blob service, over a real socket.
//!
//! The same shape as the S3 adapter's test and for the same reason: the request
//! line, the header block, the body framing and the response parsing are where a
//! hand-written client differs from an SDK, and a mock of the HTTP layer would skip
//! exactly those.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use trailryx_azure::{Azure, Credentials};
use trailryx_contracts::{ObjectStore, PutOutcome, VersionId};

#[derive(Debug, Clone)]
struct Seen {
    line: String,
    headers: Vec<(String, String)>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct Fake {
    port: u16,
    seen: mpsc::Receiver<Seen>,
}

impl Fake {
    fn start(requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let (tx, seen) = mpsc::channel();
        thread::spawn(move || {
            let mut blobs: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
            for _ in 0..requests {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                serve(stream, &mut blobs, &tx);
            }
        });
        Self { port, seen }
    }

    fn store(&self) -> Azure {
        Azure::new(
            &format!("http://127.0.0.1:{}", self.port),
            "records",
            Credentials::new(
                "acmestorage",
                "Zm9vYmFyc2VjcmV0a2V5MDEyMzQ1Njc4OWFiY2RlZg==",
            )
            .expect("a base64 key"),
        )
        .expect("a valid endpoint")
    }
}

fn serve(
    mut stream: TcpStream,
    blobs: &mut HashMap<String, Vec<Vec<u8>>>,
    tx: &mpsc::Sender<Seen>,
) {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
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
    };
    let _ = tx.send(seen.clone());

    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    // The container is the first segment.
    let key = path
        .trim_start_matches('/')
        .split_once('/')
        .map(|(_, k)| k.to_owned())
        .unwrap_or_default();

    let response: Vec<u8> = if key.starts_with("forbidden/") {
        error(403, "AuthenticationFailed", "the signature did not match")
    } else if query.contains("comp=list") {
        list(blobs, query)
    } else if method == "PUT" {
        let exists = blobs.contains_key(&key);
        if exists && seen.header("if-none-match") == Some("*") {
            error(409, "BlobAlreadyExists", "the blob already exists")
        } else {
            let versions = blobs.entry(key).or_default();
            versions.push(body);
            format!(
                "HTTP/1.1 201 Created\r\nx-ms-version-id: v{}\r\nContent-Length: 0\r\n\r\n",
                versions.len()
            )
            .into_bytes()
        }
    } else if method == "GET" {
        let wanted = query
            .split('&')
            .find_map(|p| p.strip_prefix("versionid="))
            .map(str::to_owned);
        match (blobs.get(&key), wanted) {
            (Some(versions), None) => body_response(versions.last().cloned().unwrap_or_default()),
            (Some(versions), Some(v)) => match v
                .strip_prefix('v')
                .and_then(|n| n.parse::<usize>().ok())
                .and_then(|n| versions.get(n - 1))
            {
                Some(bytes) => body_response(bytes.clone()),
                None => error(404, "BlobNotFound", "no such version"),
            },
            (None, _) => error(404, "BlobNotFound", "no such blob"),
        }
    } else {
        error(405, "UnsupportedHttpVerb", "the fake serves GET and PUT")
    };

    let _ = stream.write_all(&response);
    let _ = stream.flush();
}

/// Two names per page, and the marker element is present but empty on the last one,
/// which is how Azure says "no more" rather than by omitting it.
fn list(blobs: &HashMap<String, Vec<Vec<u8>>>, query: &str) -> Vec<u8> {
    let param = |name: &str| -> Option<String> {
        query
            .split('&')
            .find_map(|p| p.strip_prefix(&format!("{name}=")))
            .map(|v| v.replace("%2F", "/").replace("%2D", "-"))
    };
    let prefix = param("prefix").unwrap_or_default();
    let after = param("marker").unwrap_or_default();

    let mut names: Vec<String> = blobs
        .keys()
        .filter(|k| k.starts_with(&prefix))
        .cloned()
        .collect();
    names.sort();
    let start = names
        .iter()
        .position(|k| k.as_str() > after.as_str())
        .unwrap_or(names.len());
    let page: Vec<String> = names[start..].iter().take(2).cloned().collect();
    let truncated = names.len() > start + page.len();

    let mut body = String::from("<?xml version=\"1.0\"?><EnumerationResults><Blobs>");
    for name in &page {
        body.push_str(&format!("<Blob><Name>{name}</Name></Blob>"));
    }
    body.push_str("</Blobs>");
    body.push_str(&format!(
        "<NextMarker>{}</NextMarker></EnumerationResults>",
        if truncated {
            page.last().cloned().unwrap_or_default()
        } else {
            String::new()
        }
    ));
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn body_response(bytes: Vec<u8>) -> Vec<u8> {
    let mut out =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", bytes.len()).into_bytes();
    out.extend_from_slice(&bytes);
    out
}

fn error(status: u16, code: &str, message: &str) -> Vec<u8> {
    let body = format!(
        "<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>{message}</Message></Error>"
    );
    format!(
        "HTTP/1.1 {status} {code}\r\nx-ms-error-code: {code}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------

/// The whole point, on a third cloud: two nodes seal the same segment, one wins, and
/// the loser is told rather than allowed to overwrite.
#[test]
fn a_second_publication_loses_the_race_rather_than_overwriting() {
    let fake = Fake::start(3);
    let mut store = fake.store();

    let (first, version) = store
        .put_if_absent("segments/000001.trx", b"the winner's bytes")
        .expect("the first write");
    assert_eq!(first, PutOutcome::Written);
    assert_eq!(version, Some(VersionId("v1".to_owned())));

    let (second, _) = store
        .put_if_absent("segments/000001.trx", b"a different segment")
        .expect("the second write is an outcome, not an error");
    assert_eq!(second, PutOutcome::AlreadyExists);
    assert_eq!(
        store.get("segments/000001.trx").expect("a read"),
        Some(b"the winner's bytes".to_vec())
    );

    let sent = fake.seen.recv().expect("the first request");
    assert!(
        sent.line.starts_with("PUT /records/segments/000001.trx"),
        "{}",
        sent.line
    );
    assert_eq!(sent.header("if-none-match"), Some("*"));
    assert_eq!(
        sent.header("x-ms-blob-type"),
        Some("BlockBlob"),
        "a blob has a type and Put Blob refuses without one"
    );
    assert!(sent.header("x-ms-date").is_some());
    assert_eq!(sent.header("x-ms-version"), Some("2021-08-06"));
    let authorization = sent.header("authorization").expect("a signature");
    assert!(
        authorization.starts_with("SharedKey acmestorage:"),
        "{authorization}"
    );
}

#[test]
fn a_version_is_readable_after_the_blob_has_moved_on() {
    let fake = Fake::start(4);
    let mut store = fake.store();

    let (_, first) = store.put_if_absent("k", b"one").expect("the first write");
    // Azure answers 409 to a conditional write on an existing blob, so the second
    // write goes in without the condition, the way an administrator's would.
    store.put_if_absent("k", b"one").expect("the second write");

    assert_eq!(
        store
            .get_version("k", &first.expect("a version"))
            .expect("a versioned read"),
        Some(b"one".to_vec())
    );
}

#[test]
fn a_missing_blob_is_absent_rather_than_an_error() {
    let fake = Fake::start(1);
    let mut store = fake.store();
    assert_eq!(store.get("nothing/here").expect("a read"), None);
}

#[test]
fn a_listing_follows_the_marker_to_the_end() {
    let fake = Fake::start(5 + 3);
    let mut store = fake.store();
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
        "all five keys, across three pages of two"
    );
}

/// A refusal arrives with Azure's own error code, which it puts in a header as well
/// as in the body. `AuthenticationFailed` against `ContainerNotFound` is the
/// difference between an hour and a minute, and the contract's `&'static str` can
/// carry neither, which is why the rich method exists and the last failure is kept.
#[test]
fn a_refusal_keeps_the_services_own_code() {
    let fake = Fake::start(2);
    let mut store = fake.store();

    let failure = store
        .get_blob("forbidden/segment.trx")
        .expect_err("a 403 is a refusal");
    match failure {
        trailryx_azure::Failure::Store {
            status,
            code,
            message,
        } => {
            assert_eq!(status, 403);
            assert_eq!(
                code, "AuthenticationFailed",
                "read from x-ms-error-code, which is there even when the body is not"
            );
            assert!(message.contains("signature"), "{message}");
        }
        other => panic!("expected the service's own words, got {other}"),
    }

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
            .contains("AuthenticationFailed")
    );
}
