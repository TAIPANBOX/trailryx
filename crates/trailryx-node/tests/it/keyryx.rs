//! The seal's signature and the witness beside it, end to end.
//!
//! The Keyryx here is a real HTTP server on a loopback port, answering the two
//! routes trailryx uses with the JSON Keyryx's API serves. Its signatures come from
//! OpenSSL, driven as a subprocess, for the reason `trailryx-store`'s signed-pack
//! tests give: this crate has no signing code and should not. If OpenSSL is not on
//! the machine the test says it skipped.
//!
//! Given / When / Then for each test is in CLAUDE.md, invariant 46.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use trailryx_agentevent::EnvelopeConfig;
use trailryx_node::keyryx::{
    KeyryxSigner, decode_base64, decode_base64url, encode_base64, encode_base64url,
    parse_attestation,
};
use trailryx_node::signing::{Outcome, drain, queued_roots, reconcile, signed_root, witnesses_for};
use trailryx_node::{Plane, SealPolicy, ingest_file, reader};
use trailryx_record::{Hash, ShardIx, SigAlg, TenantId, Timestamp};
use trailryx_sign::{
    SignError, Signer, WitnessAttestation, attest, root_statement, sign_root_unvalidated,
    witness_statement,
};
use trailryx_verify::{Level, verify};

const BEARER: &str = "trailryx-consumer-test-bearer";
const KID: &str = "kid-one";
const TRUST_DOMAIN: &str = "acme.example";
const T0: u64 = 1_785_000_000_000_000_000;
/// A second after the seal, when the root is first queued in these tests.
const T1: u64 = T0 + 1_000_000_000;

/// Two events that map to records, the same lines `events.rs` maps in its own suite.
const EVENTS: &str = concat!(
    r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:44.100Z","source":"tokenfuse","type":"budget_exhausted","severity":"critical","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","on_behalf_of":["user://acme.example/j.doe"],"data":{"budget_usd":2.0,"spent_usd":2.0}}"#,
    "\n",
    r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:45.000Z","source":"wardryx","type":"policy_deny","severity":"high","agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","data":{"policy":"prod-deploy"}}"#,
    "\n",
);

fn tenant() -> TenantId {
    TenantId::parse("acme").expect("a constant tenant parses")
}

fn skip(what: &str) {
    println!("skipped: {what} needs an openssl on PATH to produce a signature");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A data directory this process alone names (invariant 29), removed when the test
/// ends whether it passed or not (invariant 31).
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "trailryx-node-keyryx-{what}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// A key that is somebody else's code
// ---------------------------------------------------------------------------

/// An ES384 key made by OpenSSL, in a scratch directory that goes with the key.
struct Es384Key {
    key: PathBuf,
    public: Vec<u8>,
    scratch: PathBuf,
}

impl Drop for Es384Key {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

impl Es384Key {
    /// `None` when there is no usable OpenSSL, so the caller can say so.
    fn new(name: &str) -> Option<Self> {
        let scratch = std::env::temp_dir().join(format!(
            "trailryx-node-keyryx-key-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).ok()?;
        // Built before anything can fail, so a failed key still removes its directory.
        let mut made = Self {
            key: scratch.join("key.pem"),
            public: Vec::new(),
            scratch,
        };

        let generated = Command::new("openssl")
            .args(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out"])
            .arg(&made.key)
            .status()
            .ok()?;
        if !generated.success() {
            return None;
        }
        let spki = Command::new("openssl")
            .arg("ec")
            .arg("-in")
            .arg(&made.key)
            .args(["-pubout", "-outform", "DER"])
            .output()
            .ok()?;
        if !spki.status.success() || spki.stdout.len() < 97 {
            return None;
        }
        let public = spki.stdout[spki.stdout.len() - 97..].to_vec();
        if public[0] != 0x04 {
            return None;
        }
        made.public = public;
        Some(made)
    }

    /// The raw 96-byte signature over `message`, or `None` when OpenSSL refuses.
    fn sign_raw(&self, message: &[u8]) -> Option<Vec<u8>> {
        let path = self.scratch.join("message.bin");
        std::fs::write(&path, message).ok()?;
        let out = Command::new("openssl")
            .args(["dgst", "-sha384", "-sign"])
            .arg(&self.key)
            .arg(&path)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        der_to_raw(&out.stdout)
    }
}

impl Signer for Es384Key {
    fn algorithm(&self) -> SigAlg {
        SigAlg::Es384
    }

    fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn is_validated(&self) -> bool {
        // A command-line tool over temporary files is not a key management story.
        false
    }

    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        self.sign_raw(message)
            .ok_or_else(|| SignError::Unavailable("openssl refused to sign".to_owned()))
    }
}

/// `SEQUENCE { INTEGER r, INTEGER s }` to the fixed 96 bytes the format wants.
fn der_to_raw(der: &[u8]) -> Option<Vec<u8>> {
    if der.first()? != &0x30 {
        return None;
    }
    let mut at = if der[1] < 0x80 {
        2
    } else {
        2 + usize::from(der[1] & 0x7f)
    };
    let mut out = Vec::with_capacity(96);
    for _ in 0..2 {
        if *der.get(at)? != 0x02 {
            return None;
        }
        let len = usize::from(*der.get(at + 1)?);
        let value = der.get(at + 2..at + 2 + len)?;
        at += 2 + len;
        let trimmed: Vec<u8> = value.iter().copied().skip_while(|b| *b == 0).collect();
        if trimmed.len() > 48 {
            return None;
        }
        out.extend(std::iter::repeat_n(0u8, 48 - trimmed.len()));
        out.extend_from_slice(&trimmed);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// A Keyryx on a loopback port
// ---------------------------------------------------------------------------

/// What a test changes while Keyryx is running.
#[derive(Clone)]
struct Reply {
    bearer: String,
    kid: String,
    short_signature: bool,
}

/// Keyryx's consumer-facing routes for `trailryx-root`, served from `key`. Stops
/// when dropped, and the key goes with the thread that serves it.
struct Keyryx {
    origin: String,
    reply: Arc<Mutex<Reply>>,
    statements: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Keyryx {
    fn start(key: Es384Key) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let origin = format!("http://{}", listener.local_addr().expect("a bound address"));
        // Non-blocking so the loop can see the stop flag between connections.
        listener
            .set_nonblocking(true)
            .expect("a listener the stop flag can reach");
        let reply = Arc::new(Mutex::new(Reply {
            bearer: BEARER.to_owned(),
            kid: KID.to_owned(),
            short_signature: false,
        }));
        let statements = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (reply, statements, stop) = (
                Arc::clone(&reply),
                Arc::clone(&statements),
                Arc::clone(&stop),
            );
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => serve(stream, &key, &reply, &statements),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Self {
            origin,
            reply,
            statements,
            stop,
            worker: Some(worker),
        }
    }

    fn set_reply(&self, change: impl FnOnce(&mut Reply)) {
        change(&mut *self.reply.lock().expect("the reply lock"));
    }

    /// Every statement keyryx was sent to sign, in arrival order.
    fn statements(&self) -> Vec<Vec<u8>> {
        self.statements.lock().expect("the statement lock").clone()
    }
}

impl Drop for Keyryx {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read one request. Bounded by the socket's read timeout, which `serve` sets.
fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&raw[..head_end - 4]).into_owned();
    let mut lines = head.split("\r\n");
    let mut start = lines.next()?.split(' ');
    let method = start.next()?.to_owned();
    let target = start.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    let mut request = Request {
        method,
        target,
        headers,
        body: raw[head_end..].to_vec(),
    };
    let length: usize = request
        .header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while request.body.len() < length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        request.body.extend_from_slice(&chunk[..read]);
    }
    request.body.truncate(length);
    Some(request)
}

fn serve(
    mut stream: TcpStream,
    key: &Es384Key,
    reply: &Mutex<Reply>,
    statements: &Mutex<Vec<Vec<u8>>>,
) {
    // A fake that hangs is worse than one that is wrong: the run stops with no output
    // and no failing name. Both directions are bounded.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    let current = reply.lock().expect("the reply lock").clone();
    let (status, body) = match (request.method.as_str(), request.target.as_str()) {
        ("GET", "/v1/jwks/trailryx-root") => ("200 OK", jwks(key, &current.kid)),
        ("POST", "/v1/keys/trailryx-root/sign") => {
            answer_signature(&request, key, &current, statements)
        }
        _ => ("404 Not Found", r#"{"error":"Not Found"}"#.to_owned()),
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

/// The public key set, in the shape `GET /v1/jwks/{name}` answers with.
fn jwks(key: &Es384Key, kid: &str) -> String {
    format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-384","alg":"ES384","use":"sig","kid":"{kid}","x":"{}","y":"{}"}}]}}"#,
        encode_base64url(&key.public[1..49]),
        encode_base64url(&key.public[49..97]),
    )
}

fn answer_signature(
    request: &Request,
    key: &Es384Key,
    current: &Reply,
    statements: &Mutex<Vec<Vec<u8>>>,
) -> (&'static str, String) {
    if request.header("authorization") != Some(format!("Bearer {}", current.bearer).as_str()) {
        return ("401 Unauthorized", r#"{"error":"Unauthorized"}"#.to_owned());
    }
    let Some(statement) = field_value(&request.body, "statement_b64").and_then(decode_base64)
    else {
        return (
            "400 Bad Request",
            r#"{"error":"statement_not_base64"}"#.to_owned(),
        );
    };
    statements
        .lock()
        .expect("the statement lock")
        .push(statement.clone());
    let Some(mut signature) = key.sign_raw(&statement) else {
        return (
            "500 Internal Server Error",
            r#"{"error":"store_failed"}"#.to_owned(),
        );
    };
    if current.short_signature {
        signature.pop();
    }
    let body = format!(
        r#"{{"alg":"ES384","kid":"{}","signature_b64":"{}","public_key_b64":"{}"}}"#,
        current.kid,
        encode_base64(&signature),
        encode_base64(&key.public),
    );
    ("200 OK", body)
}

/// The value of a string member in a JSON body this fake built itself.
fn field_value<'a>(body: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(body).ok()?;
    let marker = format!("\"{name}\":\"");
    let start = text.find(&marker)? + marker.len();
    let rest = &text[start..];
    Some(&rest[..rest.find('"')?])
}

/// The origin of a loopback port nothing listens on, so a connection is refused at once.
fn unreachable_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let origin = format!("http://{}", listener.local_addr().expect("a bound address"));
    drop(listener);
    origin
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// Two mapped events sealed as one segment, the way `run` or `events` seals them.
fn seal_two_events(dir: &Path) {
    let policy = SealPolicy {
        seal_after_records: 64,
        seal_after_nanos: u64::MAX,
        sync_every: 1,
    };
    let (mut plane, _) = Plane::open(dir, ShardIx(0), tenant(), TRUST_DOMAIN, policy, 0x6b6579)
        .expect("a data directory opens");
    let cfg = EnvelopeConfig::new(tenant(), TRUST_DOMAIN).expect("a usable trust domain");
    let path = dir.join("events.ndjson");
    std::fs::write(&path, EVENTS).expect("the fixture is written");
    ingest_file(&mut plane, &cfg, &path, Timestamp(T0)).expect("the file is read");
    plane
        .seal(Timestamp(T0))
        .expect("a seal on request")
        .expect("a sealed segment");
}

/// The store root of what a reader holds, as the pack and the verifier compute it.
fn root_of(held: &reader::Sealed) -> Hash {
    reader::trees(held).1.root()
}

/// Write an attestation the way Keyryx's witness does: `<dir>/acme/<root>.json`,
/// with the root named by the file and the root attested in its contents.
fn write_attestation(
    witness_dir: &Path,
    file_root: Hash,
    attested: &WitnessAttestation,
    attested_root: Hash,
    segments: u64,
) {
    let tenant_dir = witness_dir.join("acme");
    std::fs::create_dir_all(&tenant_dir).expect("a witness directory");
    let body = format!(
        r#"{{"witness":"{}","tenant":"acme","store_root":"{}","segments":{segments},"seen_at":{},"algorithm":"es384","public_key":"{}","signature":"{}"}}"#,
        attested.witness,
        hex(attested_root.as_bytes()),
        attested.seen_at.as_nanos(),
        encode_base64url(&attested.public_key),
        encode_base64url(&attested.signature),
    );
    std::fs::write(
        tenant_dir.join(format!("{}.json", hex(file_root.as_bytes()))),
        body,
    )
    .expect("the attestation is written");
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------

#[test]
fn base64_is_rfc_4648_in_both_its_alphabets_and_strict_about_them() {
    for (raw, text) in [
        (&b""[..], ""),
        (&b"f"[..], "Zg=="),
        (&b"fo"[..], "Zm8="),
        (&b"foo"[..], "Zm9v"),
        (&b"foob"[..], "Zm9vYg=="),
        (&b"fooba"[..], "Zm9vYmE="),
        (&b"foobar"[..], "Zm9vYmFy"),
    ] {
        assert_eq!(encode_base64(raw), text, "standard encoding of {raw:?}");
        assert_eq!(decode_base64(text).as_deref(), Some(raw));
        assert_eq!(
            encode_base64url(raw),
            text.trim_end_matches('='),
            "url encoding of {raw:?}"
        );
    }

    // The two alphabets differ in exactly two characters, and each decoder takes
    // only its own.
    let disputed = [0xfbu8, 0xff, 0xbf];
    assert_eq!(encode_base64(&disputed), "+/+/");
    assert_eq!(encode_base64url(&disputed), "-_-_");
    assert_eq!(decode_base64("+/+/").as_deref(), Some(&disputed[..]));
    assert_eq!(decode_base64url("-_-_").as_deref(), Some(&disputed[..]));
    assert_eq!(decode_base64url("Zg").as_deref(), Some(&b"f"[..]));

    // Refused: padding missing where it belongs, a byte outside the alphabet, and
    // the other alphabet's characters.
    assert_eq!(decode_base64("Zg"), None);
    assert_eq!(decode_base64("Zm9v!"), None);
    assert_eq!(decode_base64("-_-_"), None);
    assert_eq!(decode_base64url("+/+/"), None);
}

#[test]
fn a_witness_attestation_keyryx_writes_reads_back_as_the_statement_keyryx_witnessed() {
    // The shared vector: the inputs of TestTheWitnessStatementIsTrailryxSignsBytes in
    // keyryx's internal/trailryx at origin/main 43bb8c4. The root is the 48 bytes
    // 9, 10, 11 ... 56, the public key is 0x04 then 96 bytes of 7.
    let root: [u8; 48] = std::array::from_fn(|i| 9 + i as u8);
    let mut public = vec![4u8];
    public.extend(std::iter::repeat_n(7u8, 96));
    let seen = 1_792_000_000_123_456_789u64;
    let json = format!(
        r#"{{"witness":"keyryx-witness","tenant":"acme","store_root":"{}","segments":2,"seen_at":{seen},"algorithm":"es384","public_key":"{}","signature":"{}"}}"#,
        hex(&root),
        encode_base64url(&public),
        encode_base64url(&[0u8; 96]),
    );

    let parsed = parse_attestation(json.as_bytes()).expect("the file keyryx writes parses");
    assert_eq!(parsed.tenant, "acme");
    assert_eq!(parsed.store_root, Hash(root));
    assert_eq!(parsed.segments, 2);
    let a = &parsed.attestation;
    assert_eq!(a.witness, "keyryx-witness");
    assert_eq!(a.seen_at, Timestamp(seen));
    assert_eq!(a.algorithm, SigAlg::Es384);
    assert_eq!(a.public_key, public);
    assert_eq!(a.signature, vec![0u8; 96]);

    // The bytes keyryx's witness signed: its WitnessStatement, the same fields in the
    // same order. Each is behind its length except the time, which is eight bytes.
    let mut want = b"trailryx/witness/v1\0".to_vec();
    push_field(&mut want, b"keyryx-witness");
    push_field(&mut want, &root);
    want.extend_from_slice(&seen.to_be_bytes());
    push_field(&mut want, b"es384");
    push_field(&mut want, &public);
    assert_eq!(
        witness_statement(
            &a.witness,
            parsed.store_root,
            a.seen_at,
            a.algorithm,
            &a.public_key
        ),
        want,
        "trailryx-sign's statement is the one keyryx signed"
    );

    // Refused: an algorithm keyryx does not witness with, and a signature or a key
    // of the wrong size.
    for (what, bad) in [
        (
            "es256",
            json.replace(r#""algorithm":"es384""#, r#""algorithm":"es256""#),
        ),
        (
            "a 95-byte signature",
            json.replace(&encode_base64url(&[0u8; 96]), &encode_base64url(&[0u8; 95])),
        ),
        (
            "a 96-byte key",
            json.replace(&encode_base64url(&public), &encode_base64url(&public[..96])),
        ),
    ] {
        assert!(
            parse_attestation(bad.as_bytes()).is_err(),
            "{what} was read"
        );
    }
}

#[test]
fn keyryx_signs_exactly_the_statement_it_is_given_and_answers_with_its_key() {
    let Some(key) = Es384Key::new("sign") else {
        skip("a keyryx signature");
        return;
    };
    let public = key.public.clone();
    let keyryx = Keyryx::start(key);
    let mut signer = KeyryxSigner::new(&keyryx.origin, BEARER).expect("a signer for the origin");
    signer.refresh().expect("the key set is read");
    assert_eq!(
        signer.public_key(),
        public,
        "the key a seal is signed under is the one keyryx holds"
    );

    let root = Hash([3u8; 48]);
    let signed = sign_root_unvalidated(&mut signer, &tenant(), root, 1, Timestamp(T1))
        .expect("keyryx signs the root");
    assert_eq!(signed.algorithm, SigAlg::Es384);
    assert_eq!(signed.public_key, public);
    assert_eq!(signed.signature.len(), 96);

    let statement = root_statement(&tenant(), root, 1, Timestamp(T1), SigAlg::Es384, &public);
    assert_eq!(
        keyryx.statements(),
        vec![statement],
        "keyryx was sent trailryx-sign's statement, and nothing else"
    );
}

#[test]
fn a_keyryx_outage_leaves_the_root_queued_and_the_records_sealed() {
    let dir = Scratch::new("outage");
    seal_two_events(dir.path());
    let root = root_of(&reader::read_sealed(dir.path(), ShardIx(0)).expect("the directory reads"));

    let queued = reconcile(dir.path(), ShardIx(0), &tenant(), Timestamp(T1))
        .expect("reconcile")
        .expect("a sealed root is queued");
    assert_eq!(queued, root);
    assert_eq!(
        queued_roots(dir.path()).expect("the queue reads"),
        vec![root],
        "the root is queued, not dropped"
    );

    let mut signer =
        KeyryxSigner::new(&unreachable_origin(), BEARER).expect("a signer for the origin");
    let outcome = drain(dir.path(), &mut signer).expect("an outage is an outcome, not an error");
    assert!(
        matches!(outcome, Outcome::Queued { waiting: 1, .. }),
        "{outcome:?}"
    );
    assert_eq!(
        queued_roots(dir.path()).expect("the queue reads"),
        vec![root]
    );
    assert!(
        signed_root(dir.path(), root)
            .expect("the signatures read")
            .is_none(),
        "nothing was signed"
    );

    // The seal stands whatever Keyryx did, and a pack built now says it is unsigned.
    let held =
        reader::read_sealed(dir.path(), ShardIx(0)).expect("the sealed records still read back");
    assert_eq!(held.records(), 2);
    let pack = reader::pack_attested(&held, &tenant(), None, Vec::new(), Timestamp(T1));
    let report = verify(&pack).expect("the pack parses");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "root-signature" && f.level == Level::Weak),
        "{:?}",
        report.findings
    );
}

#[test]
fn a_queued_root_is_signed_under_the_time_it_was_queued_once_keyryx_answers() {
    let Some(key) = Es384Key::new("late") else {
        skip("a late signature");
        return;
    };
    let public = key.public.clone();
    let dir = Scratch::new("late");
    seal_two_events(dir.path());
    let root = reconcile(dir.path(), ShardIx(0), &tenant(), Timestamp(T1))
        .expect("reconcile")
        .expect("a sealed root is queued");

    let mut down = KeyryxSigner::new(&unreachable_origin(), BEARER).expect("a signer");
    assert!(matches!(
        drain(dir.path(), &mut down).expect("the drain"),
        Outcome::Queued { .. }
    ));

    let keyryx = Keyryx::start(key);
    let mut up = KeyryxSigner::new(&keyryx.origin, BEARER).expect("a signer");
    up.refresh().expect("the key set is read");
    assert_eq!(
        drain(dir.path(), &mut up).expect("the drain"),
        Outcome::Signed(1)
    );
    assert!(
        queued_roots(dir.path())
            .expect("the queue reads")
            .is_empty()
    );

    let signed = signed_root(dir.path(), root)
        .expect("the signatures read")
        .expect("the root is signed");
    assert_eq!(
        signed.generated_at,
        Timestamp(T1),
        "signed under the time it was queued, not the time it drained"
    );
    assert_eq!(signed.signature.public_key, public);
    let statement = root_statement(&tenant(), root, 1, Timestamp(T1), SigAlg::Es384, &public);
    assert_eq!(keyryx.statements(), vec![statement]);
}

#[test]
fn a_pack_built_after_keyryx_signed_carries_the_signature_and_the_witness_the_verifier_reads() {
    let (Some(key), Some(mut witness_key)) = (Es384Key::new("root"), Es384Key::new("witness"))
    else {
        skip("a signed and witnessed pack");
        return;
    };
    let dir = Scratch::new("packed");
    let witness_dir = Scratch::new("packed-witness");
    seal_two_events(dir.path());
    let root = reconcile(dir.path(), ShardIx(0), &tenant(), Timestamp(T1))
        .expect("reconcile")
        .expect("a sealed root is queued");

    let keyryx = Keyryx::start(key);
    let mut signer = KeyryxSigner::new(&keyryx.origin, BEARER).expect("a signer");
    signer.refresh().expect("the key set is read");
    assert_eq!(
        drain(dir.path(), &mut signer).expect("the drain"),
        Outcome::Signed(1)
    );

    // An independent witness, its attestation filed the way keyryx files one.
    let attestation = attest(
        &mut witness_key,
        "keyryx-witness",
        root,
        Timestamp(T1 + 60_000_000_000),
    )
    .expect("the witness attests");
    write_attestation(witness_dir.path(), root, &attestation, root, 1);
    let witnesses = witnesses_for(witness_dir.path(), &tenant(), root).expect("the attestations");
    assert_eq!(
        witnesses.len(),
        1,
        "the attestation filed for this root is attached"
    );

    let signed = signed_root(dir.path(), root).expect("the signatures read");
    let held = reader::read_sealed(dir.path(), ShardIx(0)).expect("the directory reads back");
    let bytes = reader::pack_attested(
        &held,
        &tenant(),
        signed,
        witnesses,
        Timestamp(T1 + 5_000_000_000),
    );
    let report = verify(&bytes).expect("the pack parses");
    assert!(report.verified(), "{:?}", report.findings);

    let signed_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.check == "root-signature")
        .collect();
    assert_eq!(signed_findings.len(), 1, "{:?}", report.findings);
    assert_eq!(
        signed_findings[0].level,
        Level::Note,
        "{:?}",
        report.findings
    );
    assert!(
        signed_findings[0].detail.starts_with("\"es384\" by key "),
        "{:?}",
        report.findings
    );

    let witness_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.check == "witness")
        .collect();
    assert_eq!(witness_findings.len(), 1, "{:?}", report.findings);
    assert_eq!(
        witness_findings[0].level,
        Level::Note,
        "{:?}",
        report.findings
    );
    assert!(
        witness_findings[0].detail.contains("keyryx-witness"),
        "{:?}",
        report.findings
    );
}

#[test]
fn an_attestation_for_another_root_is_not_attached_to_this_one() {
    let Some(mut witness_key) = Es384Key::new("other") else {
        skip("an attestation for another root");
        return;
    };
    let witness_dir = Scratch::new("other-root");
    let root = Hash([5u8; 48]);
    let other = Hash([6u8; 48]);

    let for_root = attest(&mut witness_key, "keyryx-witness", root, Timestamp(T1))
        .expect("the witness attests");
    write_attestation(witness_dir.path(), root, &for_root, root, 1);
    // The control: an attestation under this root's own name is attached.
    assert_eq!(
        witnesses_for(witness_dir.path(), &tenant(), root)
            .expect("the attestations read")
            .len(),
        1
    );

    // Now the same file name holds an attestation of another root, correctly signed
    // for that root. Its name says one root and its contents say another.
    let for_other =
        attest(&mut witness_key, "keyryx-witness", other, Timestamp(T1)).expect("attests");
    write_attestation(witness_dir.path(), root, &for_other, other, 1);
    assert!(
        witnesses_for(witness_dir.path(), &tenant(), root)
            .expect("the attestations read")
            .is_empty(),
        "an attestation of another root was attached to this one"
    );
}

#[test]
fn a_signature_of_the_wrong_size_is_refused_and_its_root_stays_queued() {
    let Some(key) = Es384Key::new("short") else {
        skip("a short signature");
        return;
    };
    let dir = Scratch::new("short");
    seal_two_events(dir.path());
    let root = reconcile(dir.path(), ShardIx(0), &tenant(), Timestamp(T1))
        .expect("reconcile")
        .expect("a sealed root is queued");

    let keyryx = Keyryx::start(key);
    keyryx.set_reply(|r| r.short_signature = true);
    let mut signer = KeyryxSigner::new(&keyryx.origin, BEARER).expect("a signer");
    signer.refresh().expect("the key set is read");
    assert!(
        matches!(
            drain(dir.path(), &mut signer).expect("the drain"),
            Outcome::Queued { waiting: 1, .. }
        ),
        "a 95-byte signature was accepted"
    );
    assert!(
        signed_root(dir.path(), root)
            .expect("the signatures read")
            .is_none()
    );
    assert_eq!(
        queued_roots(dir.path()).expect("the queue reads"),
        vec![root]
    );

    // The control: once keyryx answers at full size, the same root is signed.
    keyryx.set_reply(|r| r.short_signature = false);
    assert_eq!(
        drain(dir.path(), &mut signer).expect("the drain"),
        Outcome::Signed(1)
    );
}

#[test]
fn a_key_set_that_changed_under_the_signer_is_refused_not_signed_under_the_old_key() {
    let Some(key) = Es384Key::new("rotated") else {
        skip("a rotated key");
        return;
    };
    let keyryx = Keyryx::start(key);
    let mut signer = KeyryxSigner::new(&keyryx.origin, BEARER).expect("a signer");
    signer.refresh().expect("the key set is read");
    // The control: the signer signs under the key it read.
    signer
        .sign(b"statement one")
        .expect("keyryx signs under the key the signer holds");

    // keyryx now answers under another kid, so the key the signer holds is no longer
    // the one that signs.
    keyryx.set_reply(|r| r.kid = "kid-two".to_owned());
    assert!(
        signer.sign(b"statement two").is_err(),
        "a signature under a key the signer did not read was accepted"
    );
}

#[test]
fn keyryx_refuses_a_bearer_it_did_not_issue() {
    let Some(key) = Es384Key::new("bearer") else {
        skip("a bearer check");
        return;
    };
    let keyryx = Keyryx::start(key);
    let mut signer = KeyryxSigner::new(&keyryx.origin, BEARER).expect("a signer");
    signer.refresh().expect("the key set is read");
    signer
        .sign(b"statement")
        .expect("the bearer keyryx issued signs");

    let mut stranger = KeyryxSigner::new(&keyryx.origin, "a-bearer-keyryx-never-issued")
        .expect("a signer for the origin");
    stranger
        .refresh()
        .expect("the key set is public, so a stranger may read it");
    assert!(
        stranger.sign(b"statement").is_err(),
        "a bearer keyryx did not issue signed"
    );
}
