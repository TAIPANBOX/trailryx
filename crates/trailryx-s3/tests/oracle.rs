//! The AWS CLI settles it.
//!
//! Everything in `sigv4`'s own tests compares this implementation against its author's
//! reading of the specification, which is exactly what a wrong implementation also
//! does. Here the **AWS CLI** signs the same request, its debug log gives up the
//! canonical request, the string to sign and the signature, and this crate has to
//! produce the same bytes.
//!
//! That is the tool the service's own authors ship, so agreeing with it is the only
//! evidence that matters before a request goes to a real endpoint. A signature that is
//! nearly right is rejected with `SignatureDoesNotMatch`, which says nothing about
//! which of the three stages first differed. This test says.
//!
//! It prints `skipped` and passes when the CLI is absent, and says so.

use std::process::Command;

use trailryx_s3::sigv4::{Credentials, Request, sign};

const KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";

fn have_cli() -> bool {
    Command::new("aws")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// What the CLI computed, pulled out of its debug log.
#[derive(Debug)]
struct FromCli {
    canonical_request: String,
    string_to_sign: String,
    signature: String,
    timestamp: String,
}

/// Run one operation against an endpoint nothing is listening on, and read the
/// signature out of the log. The connection failing is irrelevant: the signing happens
/// first and is logged before the socket is opened.
fn ask_cli(args: &[&str]) -> Option<FromCli> {
    let output = Command::new("aws")
        .args(args)
        .args([
            "--endpoint-url",
            "http://127.0.0.1:9",
            "--region",
            REGION,
            "--debug",
        ])
        .env("AWS_ACCESS_KEY_ID", KEY_ID)
        .env("AWS_SECRET_ACCESS_KEY", SECRET)
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .output()
        .ok()?;
    let log = String::from_utf8_lossy(&output.stderr).into_owned();

    // A multi-line block runs from its marker to the next LOG RECORD, and a log record
    // is recognised by botocore's own line prefix rather than by starting with a
    // digit. The first version of this cut at the next line beginning "20", which is
    // also how the string to sign's second line begins: it truncated the block to one
    // line and reported a mismatch while the signature was right. The harness was
    // wrong, not the code under test, and that is worth a comment because a broken
    // oracle is worse than no oracle.
    let block = |marker: &str| -> Option<String> {
        let start = log.find(marker)? + marker.len();
        let rest = &log[start..];
        let mut out: Vec<&str> = Vec::new();
        for line in rest.lines() {
            if line.contains(" - MainThread - ") {
                break;
            }
            out.push(line);
        }
        Some(out.join("\n"))
    };

    let canonical_request = block("CanonicalRequest:\n")?;
    let string_to_sign = block("StringToSign:\n")?;
    let signature = block("Signature:\n")?.trim().to_owned();
    // The timestamp the CLI chose, so this crate signs the same instant rather than
    // reading a clock of its own.
    let timestamp = canonical_request
        .lines()
        .find_map(|l| l.strip_prefix("x-amz-date:"))?
        .trim()
        .to_owned();

    Some(FromCli {
        canonical_request,
        string_to_sign,
        signature,
        timestamp,
    })
}

fn compare(theirs: &FromCli, ours: &trailryx_s3::sigv4::Signed, what: &str) {
    assert_eq!(
        ours.canonical_request, theirs.canonical_request,
        "{what}: the canonical request differs.\nours:\n{}\ntheirs:\n{}",
        ours.canonical_request, theirs.canonical_request
    );
    assert_eq!(
        ours.string_to_sign, theirs.string_to_sign,
        "{what}: the string to sign differs"
    );
    assert_eq!(
        ours.signature, theirs.signature,
        "{what}: the signature differs"
    );
}

/// A `HEAD`, the simplest signed request there is.
#[test]
fn the_cli_and_this_crate_agree_on_a_head_request() {
    if !have_cli() {
        println!("skipped: the AWS CLI is not on this machine, so nothing checked the signature");
        return;
    }
    let Some(theirs) = ask_cli(&[
        "s3api",
        "head-object",
        "--bucket",
        "demo-bucket",
        "--key",
        "some/object.bin",
    ]) else {
        println!("skipped: the CLI ran and its debug log did not carry a signature");
        return;
    };

    let request = Request {
        method: "HEAD".into(),
        path: "/demo-bucket/some/object.bin".into(),
        query: Vec::new(),
        headers: vec![
            ("host".into(), "127.0.0.1:9".into()),
            (
                "x-amz-content-sha256".into(),
                trailryx_s3::sigv4::empty_payload_hash(),
            ),
            ("x-amz-date".into(), theirs.timestamp.clone()),
        ],
        payload: Vec::new(),
    };
    let ours = sign(
        &request,
        &Credentials::new(KEY_ID, SECRET),
        REGION,
        "s3",
        &theirs.timestamp,
    );
    compare(&theirs, &ours, "head-object");
}

/// A key with characters the encoder has to get right: a space, a plus and a tilde.
/// This is where a platform's own URI encoder diverges from the one AWS specifies.
#[test]
fn the_cli_and_this_crate_agree_on_a_key_that_needs_encoding() {
    if !have_cli() {
        println!("skipped: the AWS CLI is not on this machine");
        return;
    }
    let key = "some dir/a+b~c/obj (1).bin";
    let Some(theirs) = ask_cli(&[
        "s3api",
        "head-object",
        "--bucket",
        "demo-bucket",
        "--key",
        key,
    ]) else {
        println!("skipped: no signature in the CLI's log");
        return;
    };

    // The path in the canonical request is the CLI's own encoding of it, which is what
    // this crate has to reproduce. Taken from the log rather than hand-encoded here,
    // so the test cannot agree with a mistake it made itself.
    let request = Request {
        method: "HEAD".into(),
        path: format!("/demo-bucket/{key}"),
        query: Vec::new(),
        headers: vec![
            ("host".into(), "127.0.0.1:9".into()),
            (
                "x-amz-content-sha256".into(),
                trailryx_s3::sigv4::empty_payload_hash(),
            ),
            ("x-amz-date".into(), theirs.timestamp.clone()),
        ],
        payload: Vec::new(),
    };
    let ours = sign(
        &request,
        &Credentials::new(KEY_ID, SECRET),
        REGION,
        "s3",
        &theirs.timestamp,
    );
    compare(&theirs, &ours, "a key needing encoding");
}

/// A listing, which carries query parameters and therefore exercises the part of the
/// canonicalisation that sorts after encoding.
#[test]
fn the_cli_and_this_crate_agree_on_a_request_with_query_parameters() {
    if !have_cli() {
        println!("skipped: the AWS CLI is not on this machine");
        return;
    }
    let Some(theirs) = ask_cli(&[
        "s3api",
        "list-objects-v2",
        "--bucket",
        "demo-bucket",
        "--prefix",
        "segments/",
        "--max-keys",
        "7",
    ]) else {
        println!("skipped: no signature in the CLI's log");
        return;
    };

    // The query the CLI actually sent, read back from its canonical request, so the
    // test is about canonicalisation rather than about guessing the CLI's parameters.
    let their_query = theirs.canonical_request.lines().nth(2).unwrap_or_default();
    let query: Vec<(String, String)> = their_query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(k), decode(v))
        })
        .collect();

    let request = Request {
        method: "GET".into(),
        path: "/demo-bucket".into(),
        query,
        headers: vec![
            ("host".into(), "127.0.0.1:9".into()),
            (
                "x-amz-content-sha256".into(),
                trailryx_s3::sigv4::empty_payload_hash(),
            ),
            ("x-amz-date".into(), theirs.timestamp.clone()),
        ],
        payload: Vec::new(),
    };
    let ours = sign(
        &request,
        &Credentials::new(KEY_ID, SECRET),
        REGION,
        "s3",
        &theirs.timestamp,
    );
    compare(&theirs, &ours, "list-objects-v2");
}

/// Percent-decode, so a query taken out of a canonical request can be handed back in
/// unencoded and re-encoded by the code under test.
fn decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
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
