//! The server, over a real socket, mostly from the attacker's side.
//!
//! Every case here is a thing somebody would actually send. The ones that look
//! like pedantry are the ones with a CVE class behind them: a bare line feed, a
//! second `Content-Length`, a body that arrives one byte a minute, a kilobyte
//! that inflates to a gigabyte.
//!
//! The assertion is nearly always the same shape: a complete answer, the right
//! status, the connection closed, and nothing handed to the store.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use trailryx_ingest::config::Config;
use trailryx_ingest::handler::Ingest;
use trailryx_ingest::server::{Server, Stopper, silent_log};
use trailryx_otlp::{Limits, MapperConfig, OtlpSource};
use trailryx_record::{TenantId, Timestamp};

const NOW: u64 = 1_700_000_000_000_000_000;

// ---------------------------------------------------------------------------
// A server on a throwaway port
// ---------------------------------------------------------------------------

struct Harness {
    address: SocketAddr,
    stopper: Stopper,
    server: Arc<Server>,
    ingest: Arc<Ingest>,
    handle: Option<std::thread::JoinHandle<()>>,
}

fn quick_config() -> Config {
    Config {
        bind: "127.0.0.1:0".parse().expect("a literal address parses"),
        // Short enough that the timing tests take a moment rather than a minute,
        // and the code path is identical either way.
        header_timeout: Duration::from_millis(400),
        body_timeout: Duration::from_millis(600),
        idle_timeout: Duration::from_millis(200),
        read_timeout: Duration::from_millis(150),
        write_timeout: Duration::from_millis(500),
        connection_lifetime: Duration::from_secs(5),
        ..Config::default()
    }
}

impl Harness {
    fn start(config: Config) -> Self {
        Self::with_limits(config, Limits::default())
    }

    /// A server whose decoder limits are small enough for a test to reach.
    fn with_limits(config: Config, limits: Limits) -> Self {
        let mapper = MapperConfig::new(TenantId::parse("acme").unwrap(), "acme.example").unwrap();
        let ingest = Arc::new(Ingest::new(
            OtlpSource::with_limits(mapper, limits),
            config,
            Box::new(|| Timestamp(NOW)),
        ));
        let server = Arc::new(Server::bind(Arc::clone(&ingest)).expect("port zero binds"));
        let address = server.address();
        let stopper = server.stopper();
        let running = Arc::clone(&server);
        let handle = std::thread::spawn(move || running.serve(silent_log()));
        Self {
            address,
            stopper,
            server,
            ingest,
            handle: Some(handle),
        }
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(self.address).expect("the server is listening");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("a timeout can be set");
        stream
    }

    /// Send bytes, read everything back until close or timeout.
    fn exchange(&self, raw: &[u8]) -> String {
        let mut stream = self.connect();
        stream.write_all(raw).expect("the server accepts bytes");
        let _ = stream.flush();
        read_all(&mut stream)
    }

    fn pending(&self) -> usize {
        self.ingest
            .with_source(|source| source.pending())
            .expect("the lock is healthy")
    }

    fn dropped_spans(&self) -> u32 {
        self.ingest
            .with_source(|source| source.dropped().spans)
            .expect("the lock is healthy")
    }

    fn malformed(&self) -> u32 {
        self.ingest
            .with_source(|source| source.wire_report().malformed_batches)
            .expect("the lock is healthy")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stopper.stop();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_all(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn status_of(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// A valid OTLP body
// ---------------------------------------------------------------------------

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn field(number: u32, body: &[u8]) -> Vec<u8> {
    let mut out = varint((u64::from(number) << 3) | 2);
    out.extend_from_slice(&varint(body.len() as u64));
    out.extend_from_slice(body);
    out
}

fn string_attr(key: &str, value: &str) -> Vec<u8> {
    let mut any = field(1, value.as_bytes());
    any = field(2, &any);
    let mut kv = field(1, key.as_bytes());
    kv.extend_from_slice(&any);
    kv
}

/// One span, mappable or not. A span with no trace id is one `map_span`
/// rejects, which is how the partial-success path gets exercised.
fn span(trace_id: Option<[u8; 16]>, span_id: u8) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(id) = trace_id {
        out.extend_from_slice(&field(1, &id));
    }
    out.extend_from_slice(&field(2, &[span_id; 8]));
    out.extend_from_slice(&field(5, b"chat"));
    // kind = CLIENT: field 6, wire type 0 (varint).
    out.extend_from_slice(&varint(6 << 3));
    out.extend_from_slice(&varint(3));
    // start and end, fixed64
    for number in [7u32, 8] {
        out.extend_from_slice(&varint((u64::from(number) << 3) | 1));
        out.extend_from_slice(&NOW.to_le_bytes());
    }
    out.extend_from_slice(&field(9, &string_attr("gen_ai.operation.name", "chat")));
    out
}

fn batch(spans: Vec<Vec<u8>>) -> Vec<u8> {
    let resource = field(1, &string_attr("service.name", "billing"));
    let mut scope_spans = field(1, &field(1, b"test"));
    for s in spans {
        scope_spans.extend_from_slice(&field(2, &s));
    }
    let mut resource_spans = field(1, &resource);
    resource_spans.extend_from_slice(&field(2, &scope_spans));
    field(1, &resource_spans)
}

fn good_batch() -> Vec<u8> {
    batch(vec![span(Some([0xab; 16]), 1)])
}

fn request(path: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("POST {path} HTTP/1.1\r\nHost: x\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn export(body: &[u8]) -> Vec<u8> {
    request(
        "/v1/traces",
        &[("Content-Type", "application/x-protobuf")],
        body,
    )
}

fn gzip(data: &[u8]) -> Option<Vec<u8>> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("gzip")
        .args(["-9", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(data).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

// ---------------------------------------------------------------------------
// It works at all
// ---------------------------------------------------------------------------

#[test]
fn a_stock_export_is_accepted_and_says_nothing_extra() {
    let h = Harness::start(quick_config());
    let response = h.exchange(&export(&good_batch()));
    assert_eq!(status_of(&response), 200, "{response}");
    assert!(
        response.contains("Content-Type: application/x-protobuf"),
        "{response}"
    );
    assert!(response.contains("Content-Length: 0"), "{response}");
    assert_eq!(h.pending(), 1);
}

#[test]
fn an_sdk_pointed_at_the_base_endpoint_still_gets_through() {
    // An SDK configured with OTEL_EXPORTER_OTLP_ENDPOINT rather than the
    // traces-specific variable posts to the root. Refusing it would be
    // refusing a correct client.
    let h = Harness::start(quick_config());
    let response = h.exchange(&request(
        "/",
        &[("Content-Type", "application/x-protobuf")],
        &good_batch(),
    ));
    assert_eq!(status_of(&response), 200, "{response}");
    assert_eq!(h.pending(), 1);
}

#[test]
fn a_gzipped_export_is_accepted_because_the_collector_sends_them() {
    let Some(compressed) = gzip(&good_batch()) else {
        println!("skipped: no gzip on PATH");
        return;
    };
    let h = Harness::start(quick_config());
    let response = h.exchange(&request(
        "/v1/traces",
        &[
            ("Content-Type", "application/x-protobuf"),
            ("Content-Encoding", "gzip"),
        ],
        &compressed,
    ));
    assert_eq!(status_of(&response), 200, "{response}");
    assert_eq!(h.pending(), 1);
}

#[test]
fn an_empty_export_succeeds() {
    let h = Harness::start(quick_config());
    let response = h.exchange(b"POST /v1/traces HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(status_of(&response), 200, "{response}");
}

#[test]
fn a_partly_mappable_batch_is_accepted_and_says_how_much_was_not() {
    // Two spans with no trace id: `map_span` refuses them, the store counts
    // them, and the client must be told without being told to resend.
    let h = Harness::start(quick_config());
    let body = batch(vec![
        span(Some([0xab; 16]), 1),
        span(None, 2),
        span(None, 3),
    ]);
    let response = h.exchange(&export(&body));
    assert_eq!(status_of(&response), 200, "{response}");
    // The partial-success submessage: field 1, then rejected_spans = 2.
    let at = response.find("\r\n\r\n").expect("a body follows") + 4;
    let bytes = response.as_bytes();
    assert_eq!(bytes[at], 0x0a, "{response}");
    assert!(response[at..].contains("could not be mapped"), "{response}");
    assert_eq!(h.pending(), 1, "the mappable span still arrived");
}

#[test]
fn an_undecodable_batch_is_refused_non_retryably_and_still_counted() {
    let h = Harness::start(quick_config());
    let response = h.exchange(&export(&[0xff; 64]));
    assert_eq!(status_of(&response), 400, "{response}");
    assert!(response.contains("Connection: close"), "{response}");
    assert_eq!(h.malformed(), 1, "the store still counted it");
    assert_eq!(h.pending(), 0);
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

#[test]
fn a_bare_line_feed_is_not_a_line_ending() {
    let h = Harness::start(quick_config());
    for raw in [
        "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length: 5\nX-Smuggled: 1\r\n\r\n",
        "POST /v1/traces HTTP/1.1\nHost: x\r\n\r\n",
        "POST /v1/traces HTTP/1.1\rHost: x\r\n\r\n",
    ] {
        let response = h.exchange(raw.as_bytes());
        assert_eq!(status_of(&response), 400, "{raw:?} gave {response}");
        assert!(response.contains("Connection: close"), "{response}");
    }
    assert_eq!(h.pending(), 0, "nothing reached the store");
}

#[test]
fn a_second_request_after_a_rejected_one_is_never_parsed() {
    // Both in one write, so the good request is already in our buffer when the
    // bad one is refused. It must not be answered.
    let h = Harness::start(quick_config());
    let mut raw =
        b"POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length: nonsense\r\n\r\n".to_vec();
    raw.extend_from_slice(&export(&good_batch()));

    let response = h.exchange(&raw);
    assert_eq!(status_of(&response), 400, "{response}");
    assert_eq!(
        response.matches("HTTP/1.1 ").count(),
        1,
        "exactly one response: {response}"
    );
    assert_eq!(h.pending(), 0, "the smuggled request reached the store");
}

#[test]
fn a_transfer_encoding_is_not_implemented_rather_than_reconciled() {
    let h = Harness::start(quick_config());
    for value in ["chunked", "identity", "gzip, chunked"] {
        let raw = format!(
            "POST /v1/traces HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: {value}\r\nContent-Length: 3\r\n\r\nabc"
        );
        let response = h.exchange(raw.as_bytes());
        assert_eq!(status_of(&response), 501, "{value} gave {response}");
    }
}

#[test]
fn a_declared_length_never_becomes_an_allocation() {
    let h = Harness::start(quick_config());
    let cases = [
        ("18446744073709551615", 413),
        ("+5", 400),
        ("0x10", 400),
        ("", 400),
    ];
    for (value, expected) in cases {
        let raw = format!(
            "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\nContent-Length: {value}\r\n\r\n"
        );
        let response = h.exchange(raw.as_bytes());
        assert_eq!(status_of(&response), expected, "{value:?} gave {response}");
    }
    // Two lengths that disagree, which is the smuggling shape.
    let raw =
        "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd";
    assert_eq!(status_of(&h.exchange(raw.as_bytes())), 400);
}

#[test]
fn a_header_that_hides_a_second_header_is_refused() {
    let h = Harness::start(quick_config());
    for raw in [
        "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\n",
        "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length:\r\n 5\r\n\r\n",
        "POST /v1/traces HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        "POST /v1/traces HTTP/1.1\r\n\r\n",
    ] {
        let response = h.exchange(raw.as_bytes());
        assert_eq!(status_of(&response), 400, "{raw:?} gave {response}");
    }
}

#[test]
fn a_header_section_that_never_ends_is_bounded() {
    let h = Harness::start(Config {
        max_header_section: 2048,
        ..quick_config()
    });

    let mut raw = b"POST /v1/traces HTTP/1.1\r\nHost: x\r\n".to_vec();
    for i in 0..500 {
        raw.extend_from_slice(format!("X-Filler-{i}: aaaaaaaaaaaaaaaa\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    let response = h.exchange(&raw);
    assert_eq!(status_of(&response), 431, "{response}");
}

#[test]
fn an_expectation_is_matched_whole() {
    let h = Harness::start(quick_config());
    for value in ["y 100-continue", "100-continue, foo", "other"] {
        let raw = format!("POST /v1/traces HTTP/1.1\r\nHost: x\r\nExpect: {value}\r\n\r\n");
        assert_eq!(
            status_of(&h.exchange(raw.as_bytes())),
            417,
            "{value:?} was accepted"
        );
    }

    // The real thing: an interim 100 and then the final answer.
    let body = good_batch();
    let raw = format!(
        "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut bytes = raw.into_bytes();
    bytes.extend_from_slice(&body);
    let response = h.exchange(&bytes);
    assert!(
        response.starts_with("HTTP/1.1 100 Continue\r\n\r\n"),
        "{response}"
    );
    assert!(response.contains("HTTP/1.1 200 OK"), "{response}");
}

// ---------------------------------------------------------------------------
// Routing and content
// ---------------------------------------------------------------------------

#[test]
fn the_other_signals_and_unknown_paths_are_named_rather_than_swallowed() {
    let h = Harness::start(quick_config());
    for path in ["/v1/metrics", "/v1/logs", "/nonsense", "/v1/traces/extra"] {
        let response = h.exchange(&request(
            path,
            &[("Content-Type", "application/x-protobuf")],
            &good_batch(),
        ));
        assert_eq!(status_of(&response), 404, "{path} gave {response}");
    }
}

#[test]
fn a_known_path_with_the_wrong_method_says_which_method() {
    let h = Harness::start(quick_config());
    let response = h.exchange(b"GET /v1/traces HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(status_of(&response), 405, "{response}");
    assert!(response.contains("Allow: POST"), "{response}");
}

#[test]
fn an_encoding_or_media_type_we_do_not_have_is_415_and_never_400() {
    // 415 is non-retryable and says "we do not do that", which is diagnosable.
    // 400 would read as corrupt telemetry and send somebody hunting the wrong bug.
    let h = Harness::start(quick_config());
    for (header, value) in [
        ("Content-Encoding", "zstd"),
        ("Content-Encoding", "deflate"),
        ("Content-Encoding", "gzip, gzip"),
        ("Content-Type", "application/json"),
        ("Content-Type", "text/plain"),
    ] {
        let mut headers = vec![("Content-Type", "application/x-protobuf")];
        if header == "Content-Type" {
            headers.clear();
        }
        headers.push((header, value));
        let response = h.exchange(&request("/v1/traces", &headers, &good_batch()));
        assert_eq!(
            status_of(&response),
            415,
            "{header}: {value} gave {response}"
        );
    }

    // A parameter on an otherwise correct type must be ignored, not refused.
    let response = h.exchange(&request(
        "/v1/traces",
        &[("Content-Type", "application/x-protobuf; charset=utf-8")],
        &good_batch(),
    ));
    assert_eq!(status_of(&response), 200, "{response}");
}

#[test]
fn nothing_from_the_request_reaches_the_response() {
    // A path and a User-Agent full of the CRLF injection shape, aimed at a 404.
    let h = Harness::start(quick_config());
    let raw = "POST /nonsense%20here HTTP/1.1\r\nHost: x\r\nUser-Agent: a\tb\r\n\r\n";
    let response = h.exchange(raw.as_bytes());
    assert_eq!(status_of(&response), 404, "{response}");
    assert!(!response.contains("X-Injected"), "{response}");
    assert!(!response.contains("nonsense"), "{response}");
    // Exactly one header/body boundary, so nothing split the message.
    assert_eq!(response.matches("\r\n\r\n").count(), 1, "{response}");
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

#[test]
fn a_body_over_the_cap_is_refused_before_it_is_read() {
    let h = Harness::start(Config {
        max_body: 512,
        ..quick_config()
    });

    let big = vec![0u8; 4096];
    let response = h.exchange(&request(
        "/v1/traces",
        &[("Content-Type", "application/x-protobuf")],
        &big,
    ));
    assert_eq!(status_of(&response), 413, "{response}");
    assert!(response.contains("Connection: close"), "{response}");
    assert_eq!(h.pending(), 0);
}

#[test]
fn a_small_gzip_body_cannot_become_a_large_one() {
    let Some(bomb) = gzip(&vec![0u8; 4 * 1024 * 1024]) else {
        println!("skipped: no gzip on PATH");
        return;
    };
    let h = Harness::start(Config {
        max_body: 64 * 1024,
        ..quick_config()
    });

    let response = h.exchange(&request(
        "/v1/traces",
        &[
            ("Content-Type", "application/x-protobuf"),
            ("Content-Encoding", "gzip"),
        ],
        &bomb,
    ));
    assert_eq!(status_of(&response), 413, "{response}");
    assert_eq!(h.pending(), 0);
}

#[test]
fn a_gzip_stream_that_lies_about_itself_is_refused() {
    let Some(good) = gzip(&good_batch()) else {
        println!("skipped: no gzip on PATH");
        return;
    };
    let h = Harness::start(quick_config());
    let mut broken = good.clone();
    let at = broken.len() - 8;
    broken[at] ^= 1;

    let response = h.exchange(&request(
        "/v1/traces",
        &[
            ("Content-Type", "application/x-protobuf"),
            ("Content-Encoding", "gzip"),
        ],
        &broken,
    ));
    assert_eq!(status_of(&response), 400, "{response}");
    assert_eq!(h.pending(), 0);
}

#[test]
fn a_truncated_body_never_becomes_half_a_record() {
    // The peer declares a length and then goes away. `accept` cannot tell a
    // truncated batch from a small one, so this is the only place it can be
    // stopped.
    let h = Harness::start(quick_config());
    let body = good_batch();
    let head = format!(
        "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\n\r\n",
        body.len() + 4096
    );
    let mut stream = h.connect();
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let response = read_all(&mut stream);

    assert!(
        response.is_empty(),
        "there was no message to answer: {response}"
    );
    assert_eq!(h.pending(), 0);
    assert_eq!(h.malformed(), 0, "nothing partial was handed onward");
}

// ---------------------------------------------------------------------------
// Time and room
// ---------------------------------------------------------------------------

#[test]
fn a_slow_sender_cannot_hold_a_thread() {
    let h = Harness::start(quick_config());
    let started = Instant::now();
    let mut stream = h.connect();
    // A trickle that never finishes the head.
    for _ in 0..40 {
        if stream.write_all(b"X").is_err() {
            break;
        }
        let _ = stream.flush();
        std::thread::sleep(Duration::from_millis(50));
    }
    let response = read_all(&mut stream);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the connection outlived its deadline"
    );
    // 408 if we got the deadline in first, or nothing if the peer's write
    // failed once we closed. Either way the thread is gone.
    if !response.is_empty() {
        assert!(
            matches!(status_of(&response), 408 | 400 | 431),
            "{response}"
        );
    }
    drop(stream);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(h.server.live_connections(), 0, "the guard did not run");
}

#[test]
fn the_connection_cap_answers_rather_than_disappearing() {
    // The header timeout is long enough that the first two connections are
    // still holding when the third arrives.
    let h = Harness::start(Config {
        max_connections: 2,
        header_timeout: Duration::from_millis(1500),
        idle_timeout: Duration::from_millis(1500),
        ..quick_config()
    });

    // Two connections that sit there saying nothing.
    let held: Vec<TcpStream> = (0..2).map(|_| h.connect()).collect();
    std::thread::sleep(Duration::from_millis(200));

    let response = h.exchange(&export(&good_batch()));
    assert_eq!(status_of(&response), 503, "{response}");
    assert!(response.contains("Retry-After: 1"), "{response}");
    assert!(response.contains("Connection: close"), "{response}");
    drop(held);
}

#[test]
fn a_full_queue_is_told_to_come_back_not_told_to_give_up() {
    let h = Harness::start(Config {
        max_pending: 1,
        ..quick_config()
    });

    // The first export fills the queue.
    assert_eq!(status_of(&h.exchange(&export(&good_batch()))), 200);
    assert_eq!(h.pending(), 1);

    let response = h.exchange(&export(&good_batch()));
    assert_eq!(status_of(&response), 503, "{response}");
    assert!(response.contains("Retry-After: 1"), "{response}");
    assert_eq!(h.pending(), 1, "the batch is still the client's");
}

#[test]
fn a_kept_alive_connection_serves_more_than_one_and_then_stops() {
    let h = Harness::start(Config {
        max_requests_per_connection: 3,
        ..quick_config()
    });

    let mut stream = h.connect();
    let one = export(&good_batch());
    for _ in 0..4 {
        if stream.write_all(&one).is_err() {
            break;
        }
        let _ = stream.flush();
        // Wait for the answer before sending the next, which is what a real
        // exporter does and what makes this keep-alive rather than pipelining.
        let mut chunk = [0u8; 4096];
        if stream.read(&mut chunk).unwrap_or(0) == 0 {
            break;
        }
    }
    drop(stream);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(h.pending(), 3, "three requests, then the connection closed");
}

#[test]
fn two_requests_in_one_write_are_not_pipelined() {
    // A real exporter waits for the response. Anything that does not is either
    // broken or trying something, and either way the connection closes rather
    // than being reused.
    let h = Harness::start(quick_config());
    let mut raw = export(&good_batch());
    raw.extend_from_slice(&export(&good_batch()));

    let response = h.exchange(&raw);
    assert_eq!(
        response.matches("HTTP/1.1 ").count(),
        1,
        "exactly one response: {response}"
    );
    assert_eq!(h.pending(), 1, "only the first request was served");
}

#[test]
fn only_http_1_1_is_spoken() {
    let h = Harness::start(quick_config());
    assert_eq!(
        status_of(&h.exchange(b"POST /v1/traces HTTP/1.0\r\nHost: x\r\n\r\n")),
        505
    );
    assert_eq!(
        status_of(&h.exchange(b"PRI * HTTP/2.0\r\nHost: x\r\n\r\n")),
        505
    );
}

#[test]
fn an_empty_export_that_says_so_is_accepted_rather_than_corrected() {
    // The bug this test exists for: `Content-Length: 0` and no Content-Length
    // at all were collapsed into the same value, so an SDK posting a
    // legitimate empty export with a Content-Type was told 411, its length was
    // missing. It had said its length. Its length was zero.
    let h = Harness::start(quick_config());
    let response = h.exchange(
        b"POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(status_of(&response), 200, "{response}");
}

#[test]
fn a_described_body_with_no_length_is_told_which_header_is_missing() {
    // The other half of the same distinction, which must keep working: it said
    // it was sending protobuf and never said how much, and there is no transfer
    // coding here to find out with.
    let h = Harness::start(quick_config());
    let response = h.exchange(
        b"POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\n\r\n",
    );
    assert_eq!(status_of(&response), 411, "{response}");
}

#[test]
fn a_trickled_body_is_cut_off_by_the_rate_floor_not_by_the_deadline() {
    // The rate floor's first version required eight kilobytes to have arrived
    // before it would look, and truncated elapsed time to whole seconds.
    // Between them it could not fire for about eight seconds, by which point
    // the body deadline was doing all the work. This asserts the floor itself
    // fires, by giving the deadline far more room than the floor needs.
    let h = Harness::start(Config {
        min_body_rate: 8 * 1024,
        body_timeout: Duration::from_secs(20),
        connection_lifetime: Duration::from_secs(30),
        ..quick_config()
    });

    let head = "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\nContent-Length: 200000\r\n\r\n";
    let started = Instant::now();
    let mut stream = h.connect();
    stream.write_all(head.as_bytes()).unwrap();
    for _ in 0..60 {
        if stream.write_all(&[0u8; 64]).is_err() {
            break;
        }
        let _ = stream.flush();
        std::thread::sleep(Duration::from_millis(100));
    }
    let response = read_all(&mut stream);
    let elapsed = started.elapsed();

    assert_eq!(status_of(&response), 408, "{response}");
    assert!(
        elapsed < Duration::from_secs(8),
        "the floor took {elapsed:?}, so the deadline is still doing the work"
    );
    assert_eq!(h.pending(), 0, "nothing partial was handed onward");
}

#[test]
fn a_quiet_kept_alive_connection_is_not_answered_at_all() {
    // The costliest defect the adversarial review found, and the most ordinary
    // case there is: after a response, a socket that goes quiet for longer than
    // the per-syscall read timeout used to receive a complete 408 for a request
    // that had never begun, and the client's real request, arriving a moment
    // later, was swallowed by the drain. 408 is not in this server's retry
    // table, so an exporter dropped the batch. With the shipped defaults the
    // read timeout is five seconds and so is an OTel exporter's batch delay.
    let h = Harness::start(Config {
        read_timeout: Duration::from_millis(120),
        idle_timeout: Duration::from_millis(1500),
        header_timeout: Duration::from_millis(1500),
        connection_lifetime: Duration::from_secs(10),
        ..quick_config()
    });

    let mut stream = h.connect();
    let one = export(&good_batch());
    stream.write_all(&one).unwrap();
    let mut chunk = [0u8; 4096];
    let n = stream.read(&mut chunk).unwrap();
    let first = String::from_utf8_lossy(&chunk[..n]).into_owned();
    assert_eq!(status_of(&first), 200, "{first}");

    // Longer than the per-syscall timeout, well inside the idle budget: exactly
    // the gap an exporter leaves between batches.
    std::thread::sleep(Duration::from_millis(400));

    stream.write_all(&one).unwrap();
    let _ = stream.flush();
    let second = read_all(&mut stream);
    assert_eq!(
        status_of(&second),
        200,
        "the second export was answered {second}"
    );
    assert_eq!(h.pending(), 2, "both batches reached the store");
}

#[test]
fn a_head_that_stops_arriving_is_still_answered() {
    // The other side of that fix. A syscall timeout no longer ends a phase, so
    // the phase deadline has to, or a half-sent head would hold a thread until
    // the connection's whole lifetime ran out.
    let h = Harness::start(Config {
        read_timeout: Duration::from_millis(100),
        header_timeout: Duration::from_millis(500),
        idle_timeout: Duration::from_millis(100),
        ..quick_config()
    });

    let started = Instant::now();
    let mut stream = h.connect();
    stream
        .write_all(b"POST /v1/traces HTTP/1.1\r\nHost: x\r\n")
        .unwrap();
    let _ = stream.flush();
    let response = read_all(&mut stream);

    assert!(
        started.elapsed() < Duration::from_secs(3),
        "a begun head outlived its phase: {:?}",
        started.elapsed()
    );
    assert_eq!(status_of(&response), 408, "{response}");
}

#[test]
fn a_compressed_body_is_charged_what_it_can_inflate_to() {
    // The critical finding. The in-flight budget charged the declared length, so
    // 256 connections of fifteen kilobytes each could hold four gigabytes of
    // decompressed bodies against a ceiling that had counted four megabytes.
    let Some(compressed) = gzip(&good_batch()) else {
        println!("skipped: no gzip on PATH");
        return;
    };
    // A budget with room for exactly one worst-case body.
    let h = Harness::start(Config {
        max_body: 64 * 1024,
        max_inflight_body: 64 * 1024,
        max_connections: 8,
        body_timeout: Duration::from_secs(3),
        ..quick_config()
    });

    // One small compressed request is charged the whole ceiling, so a second
    // concurrent one is shed rather than inflated.
    let head = format!(
        "POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-protobuf\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        compressed.len() + 32
    );
    let mut holding = h.connect();
    holding.write_all(head.as_bytes()).unwrap();
    holding.write_all(&compressed).unwrap();
    let _ = holding.flush();
    std::thread::sleep(Duration::from_millis(200));

    let response = h.exchange(&request(
        "/v1/traces",
        &[
            ("Content-Type", "application/x-protobuf"),
            ("Content-Encoding", "gzip"),
        ],
        &compressed,
    ));
    assert_eq!(status_of(&response), 503, "{response}");
    assert!(response.contains("Retry-After: 1"), "{response}");
    drop(holding);
}

#[test]
fn spans_dropped_at_our_own_limits_are_not_reported_as_full_success() {
    // The other critical finding. `submit` diffed the mapper's counter and the
    // wire counter and not the decoder's, so a batch whose spans were thrown
    // away at `max_spans` got a bare 200 with an empty body and the emitter was
    // told everything landed.
    let h = Harness::with_limits(
        quick_config(),
        Limits {
            max_spans: 10,
            ..Limits::default()
        },
    );
    let body = batch((0..12).map(|i| span(Some([0xab; 16]), i + 1)).collect());

    let response = h.exchange(&export(&body));
    assert_eq!(
        status_of(&response),
        200,
        "not a rejection: the batch arrived"
    );
    assert!(
        !response.ends_with("\r\n\r\n"),
        "a bare 200 would tell the emitter nothing was lost: {response}"
    );
    let at = response.find("\r\n\r\n").expect("a body follows") + 4;
    let bytes = response.as_bytes();
    assert_eq!(bytes[at], 0x0a, "a partial-success submessage: {response}");
    assert!(
        response[at..].contains("decode limits"),
        "and it must name why: {response}"
    );
    assert_eq!(h.dropped_spans(), 2);
    assert_eq!(h.pending(), 10);
}
