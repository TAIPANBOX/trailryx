//! The agent-token door, over a real socket.
//!
//! What this file holds, in the order a reader would ask about it: an agent
//! that presents its own token and proof gets its records in under its own
//! name; a span that names some other agent is refused, and the refusal is a
//! record under the name of the agent that sent it; and everything that is
//! not an agent's own token and proof for this request, at this moment, never
//! gets past the head.
//!
//! The tokens and proofs are fixed bytes, made by `tests/make_door_fixtures.py`
//! with TEST-ONLY keys and checked there by an implementation that shares no
//! code with this crate.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::wire::{NOW, field, quick_config, read_all, span, status_of, string_attr};
use trailryx_contracts::ingest::Ingest as Unit;
use trailryx_ingest::agent_door::{AgentTokenDoor, DoorConfig, DoorError};
use trailryx_ingest::handler::Ingest;
use trailryx_ingest::server::{Server, Stopper, silent_log};
use trailryx_json::{Event, Limits, Reader};
use trailryx_otlp::{MapperConfig, OtlpSource};
use trailryx_record::{EventType, Severity, TenantId, Timestamp, Verdict};

const FIXTURES: &str = include_str!("../vectors/agent-door-fixtures.json");

/// One string member of the fixture file, by path.
fn fixture(path: &[&str]) -> String {
    let mut r = Reader::new(FIXTURES.as_bytes(), Limits::default(), 1);
    assert_eq!(r.value().expect("json"), Event::ObjectStart);
    let mut depth = 0;
    loop {
        let name = r
            .next_name()
            .expect("a member")
            .unwrap_or_else(|| panic!("no {path:?} in the fixtures"))
            .into_owned();
        if name != path[depth] {
            r.skip_value().expect("skippable");
            continue;
        }
        depth += 1;
        let value = r.value().expect("a value");
        if depth == path.len() {
            return match value {
                Event::Str(s) => s.into_owned(),
                Event::Number(n) => String::from_utf8_lossy(n.raw()).into_owned(),
                other => panic!("{path:?} is {other:?}"),
            };
        }
        assert_eq!(value, Event::ObjectStart, "{path:?}");
    }
}

/// The JWKS member as raw JSON text: the door is configured from a file's
/// bytes, so it is given the bytes.
fn jwks() -> Vec<u8> {
    let start = FIXTURES.find("\"jwks\":").expect("a jwks") + "\"jwks\":".len();
    let mut r = Reader::new(&FIXTURES.as_bytes()[start..], Limits::default(), 1);
    let opened = r.value().expect("an object");
    r.skip_rest(&opened).expect("a whole object");
    FIXTURES.as_bytes()[start..start + r.offset()].to_vec()
}

fn now_secs() -> i64 {
    fixture(&["now"]).parse().expect("a clock")
}

fn config() -> DoorConfig {
    DoorConfig {
        issuer: fixture(&["issuer"]),
        audience: fixture(&["audience"]),
        origin: fixture(&["origin"]),
        trust_domain: fixture(&["trust_domain"]),
        scope: "acme".to_owned(),
        replay_cap: 64,
    }
}

struct Door {
    address: SocketAddr,
    stopper: Stopper,
    ingest: Arc<Ingest>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Door {
    fn start() -> Self {
        Self::at(now_secs())
    }

    /// A door whose clock reads `now`, in whole seconds.
    fn at(now: i64) -> Self {
        let door = AgentTokenDoor::new(config(), &jwks(), Box::new(move || now))
            .expect("the fixture configuration is usable");
        let mapper = MapperConfig::new(
            TenantId::parse("acme").unwrap(),
            &fixture(&["trust_domain"]),
        )
        .unwrap();
        let ingest = Arc::new(
            Ingest::new(
                OtlpSource::new(mapper),
                quick_config(),
                Box::new(|| Timestamp(NOW)),
            )
            .with_auth(door.into_gate()),
        );
        let server = Arc::new(Server::bind(Arc::clone(&ingest)).expect("port zero binds"));
        let address = server.address();
        let stopper = server.stopper();
        let running = Arc::clone(&server);
        let handle = std::thread::spawn(move || running.serve(silent_log()));
        Self {
            address,
            stopper,
            ingest,
            handle: Some(handle),
        }
    }

    fn exchange(&self, raw: &[u8]) -> String {
        let mut stream = TcpStream::connect(self.address).expect("the server is listening");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("a timeout can be set");
        stream.write_all(raw).expect("the server accepts bytes");
        let _ = stream.flush();
        read_all(&mut stream)
    }

    /// Everything the source would hand the store, taken.
    fn drain(&self) -> Vec<Unit> {
        use trailryx_contracts::contracts::Source;
        self.ingest
            .with_source(|source| source.poll(1024))
            .expect("the lock is healthy")
            .expect("a poll")
    }
}

impl Drop for Door {
    fn drop(&mut self) {
        self.stopper.stop();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// One resource named `service`, holding `spans`.
fn batch_for(service: &str, spans: Vec<Vec<u8>>) -> Vec<u8> {
    let resource = field(1, &string_attr("service.name", service));
    let mut scope_spans = field(1, &field(1, b"test"));
    for s in spans {
        scope_spans.extend_from_slice(&field(2, &s));
    }
    let mut resource_spans = field(1, &resource);
    resource_spans.extend_from_slice(&field(2, &scope_spans));
    field(1, &resource_spans)
}

/// A span that names its agent itself, which outranks the resource.
fn span_naming(agent: &str, trace: u8, span_id: u8) -> Vec<u8> {
    let mut s = span(Some([trace; 16]), span_id);
    s.extend_from_slice(&field(9, &string_attr("gen_ai.agent.id", agent)));
    s
}

fn post(headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut out = "POST /v1/traces HTTP/1.1\r\nHost: ingest.acme.example\r\n\
                   Content-Type: application/x-protobuf\r\n"
        .to_owned();
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn presented(token: &str, proof: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "Authorization",
            format!("DPoP {}", fixture(&["tokens", token])),
        ),
        ("DPoP", fixture(&["proofs", proof])),
    ]
}

fn billing_batch() -> Vec<u8> {
    batch_for("billing", vec![span(Some([0xab; 16]), 1)])
}

// ---------------------------------------------------------------------------
// The agent writes as itself
// ---------------------------------------------------------------------------

#[test]
fn an_agents_own_token_and_proof_get_its_records_in_under_its_name() {
    let door = Door::start();
    let response = door.exchange(&post(&presented("billing", "billing-1"), &billing_batch()));
    assert_eq!(status_of(&response), 200, "{response}");
    let units = door.drain();
    assert_eq!(units.len(), 1, "{units:?}");
    assert_eq!(
        units[0].meta.agent_id.as_str(),
        "agent://acme.example/billing"
    );
    assert_eq!(units[0].meta.event_type, EventType::ModelCall);
}

// ---------------------------------------------------------------------------
// ...and as nobody else
// ---------------------------------------------------------------------------

/// The case the whole change exists for. One agent holds a valid token and
/// sends a span saying another agent did something. Under the fleet secret
/// that span became a record in the other agent's name; here it does not, and
/// the attempt itself is written down under the name of the agent that made
/// it, in the run it named.
#[test]
fn a_span_naming_another_agent_is_refused_and_the_refusal_is_a_record_under_the_caller() {
    let door = Door::start();
    let response = door.exchange(&post(
        &presented("billing", "billing-2"),
        &batch_for("triage", vec![span(Some([0xcd; 16]), 1)]),
    ));
    // Partial success, not 403: the caller is who it says it is and may write
    // here, and an OTLP exporter must not retry a batch that will be refused
    // the same way every time.
    assert_eq!(status_of(&response), 200, "{response}");
    assert!(
        response.contains("another agent"),
        "the partial success does not say why: {response}"
    );

    let units = door.drain();
    assert!(
        units
            .iter()
            .all(|u| u.meta.agent_id.as_str() != "agent://acme.example/triage"),
        "a record was written in another agent's name: {units:?}"
    );
    assert_eq!(units.len(), 1, "exactly the refusal: {units:?}");
    let refusal = &units[0].meta;
    assert_eq!(refusal.agent_id.as_str(), "agent://acme.example/billing");
    assert_eq!(refusal.event_type, EventType::StoreEvent);
    assert_eq!(refusal.severity, Severity::Warning);
    assert_eq!(refusal.verdict, Some(Verdict::Denied));
    assert_eq!(
        refusal.run_id.as_str(),
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "the refusal lands in the run the span named"
    );

    let counted = door
        .ingest
        .with_source(|source| source.report().not_the_caller)
        .expect("the lock is healthy");
    assert_eq!(counted, 1);
}

/// One batch, two spans: the caller's own is kept and the other is refused.
/// Refusing the whole batch would lose the caller's evidence for another
/// agent's name, and keeping both would be the hole this closes.
#[test]
fn a_mixed_batch_keeps_the_callers_spans_and_refuses_the_rest() {
    let door = Door::start();
    let response = door.exchange(&post(
        &presented("billing", "billing-3"),
        &batch_for(
            "billing",
            vec![span(Some([0x11; 16]), 1), span_naming("triage", 0x22, 2)],
        ),
    ));
    assert_eq!(status_of(&response), 200, "{response}");
    let units = door.drain();
    let agents: Vec<(&str, EventType)> = units
        .iter()
        .map(|u| (u.meta.agent_id.as_str(), u.meta.event_type))
        .collect();
    assert_eq!(
        agents,
        vec![
            ("agent://acme.example/billing", EventType::ModelCall),
            ("agent://acme.example/billing", EventType::StoreEvent),
        ]
    );
}

/// The refusal also reaches the counters the store already writes down, so an
/// operator reading the anomaly record sees it beside every other loss.
#[test]
fn a_refused_span_is_in_the_anomaly_record_by_name() {
    let door = Door::start();
    let _ = door.exchange(&post(
        &presented("billing", "billing-4"),
        &batch_for("triage", vec![span(Some([0x33; 16]), 1)]),
    ));
    let anomaly = door
        .ingest
        .with_source(|source| source.anomaly_event(Timestamp(NOW)))
        .expect("the lock is healthy")
        .expect("an anomaly to report");
    let detail = String::from_utf8(anomaly.payload[0].bytes.clone()).expect("text");
    assert!(
        detail.contains("not_the_caller\t1\n"),
        "the anomaly record does not name the refusal: {detail}"
    );
}

// ---------------------------------------------------------------------------
// Everything else stops at the head
// ---------------------------------------------------------------------------

#[test]
fn an_agent_token_without_its_proof_is_401_and_reaches_no_further() {
    let door = Door::start();
    let response = door.exchange(&post(
        &[(
            "Authorization",
            format!("DPoP {}", fixture(&["tokens", "billing"])),
        )],
        &billing_batch(),
    ));
    assert_eq!(status_of(&response), 401, "{response}");
    assert!(door.drain().is_empty());
}

/// RFC 9449 section 7.2: a bound token presented as a bearer token is refused.
/// Otherwise the proof is optional and the binding is decoration.
#[test]
fn an_agent_token_presented_as_bearer_is_401_with_a_dpop_challenge() {
    let door = Door::start();
    let mut headers = presented("billing", "billing-5");
    headers[0].1 = format!("Bearer {}", fixture(&["tokens", "billing"]));
    let response = door.exchange(&post(&headers, &billing_batch()));
    assert_eq!(status_of(&response), 401, "{response}");
    assert!(
        response.contains("WWW-Authenticate: DPoP algs=\"ES256\"\r\n"),
        "{response}"
    );
    assert!(door.drain().is_empty());
}

#[test]
fn a_proof_is_single_use() {
    let door = Door::start();
    let request = post(&presented("billing", "billing-6"), &billing_batch());
    assert_eq!(status_of(&door.exchange(&request)), 200);
    let again = door.exchange(&request);
    assert_eq!(status_of(&again), 401, "{again}");
    assert_eq!(door.drain().len(), 1, "only the first presentation wrote");
}

/// A thief with the token and a key of their own: the proof verifies under its
/// own key, which is not the key the token is bound to.
#[test]
fn a_proof_by_any_key_but_the_bound_one_is_401() {
    let door = Door::start();
    let response = door.exchange(&post(&presented("billing", "stolen-1"), &billing_batch()));
    assert_eq!(status_of(&response), 401, "{response}");
    assert!(door.drain().is_empty());
}

#[test]
fn a_token_past_its_life_is_401() {
    // Issued at `now`, five minutes of life, thirty seconds of leeway.
    let door = Door::at(now_secs() + 330);
    let response = door.exchange(&post(&presented("billing", "billing-7"), &billing_batch()));
    assert_eq!(status_of(&response), 401, "{response}");
    assert!(door.drain().is_empty());
}

/// Invariant 35 at this door: the issuer may vouch for agents in many trust
/// domains, and this store writes for the one its operator configured.
#[test]
fn a_valid_token_for_another_trust_domain_is_403() {
    let door = Door::start();
    let response = door.exchange(&post(
        &presented("elsewhere", "elsewhere-1"),
        &billing_batch(),
    ));
    assert_eq!(status_of(&response), 403, "{response}");
    assert!(door.drain().is_empty());
}

/// RFC 9449 section 4.3, check one: not more than one DPoP field. Two proofs is
/// not a request to pick one.
#[test]
fn two_proofs_are_refused_rather_than_chosen() {
    let door = Door::start();
    let mut headers = presented("billing", "billing-8");
    headers.push(("DPoP", fixture(&["proofs", "billing-1"])));
    let response = door.exchange(&post(&headers, &billing_batch()));
    assert_eq!(status_of(&response), 400, "{response}");
    assert!(door.drain().is_empty());
}

/// Nothing a caller sent comes back in a refusal: a body that echoed a token
/// would write it into whatever log collects exporter failures.
#[test]
fn no_refusal_echoes_the_token_or_the_proof() {
    let door = Door::start();
    let token = fixture(&["tokens", "billing"]);
    let response = door.exchange(&post(&presented("billing", "stolen-1"), &billing_batch()));
    assert_eq!(status_of(&response), 401);
    let signature = token.rsplit('.').next().expect("three parts");
    assert!(!response.contains(signature), "{response}");
    assert!(!response.contains("agent://"), "{response}");
}

// ---------------------------------------------------------------------------
// A door that could not do its job does not open
// ---------------------------------------------------------------------------

#[test]
fn a_door_with_no_audience_no_issuer_or_no_key_will_not_start() {
    let clock = || -> Box<dyn Fn() -> i64 + Send> { Box::new(|| 0) };
    let no_audience = DoorConfig {
        audience: String::new(),
        ..config()
    };
    assert!(matches!(
        AgentTokenDoor::new(no_audience, &jwks(), clock()),
        Err(DoorError::NoAudience)
    ));
    let no_issuer = DoorConfig {
        issuer: String::new(),
        ..config()
    };
    assert!(matches!(
        AgentTokenDoor::new(no_issuer, &jwks(), clock()),
        Err(DoorError::NoIssuer)
    ));
    assert!(matches!(
        AgentTokenDoor::new(config(), br#"{"keys":[]}"#, clock()),
        Err(DoorError::Jwks(_))
    ));
    // A set holding a private member is a signing key in the wrong place, and
    // a door that loaded it would be a place signing keys collect.
    let leaked = String::from_utf8(jwks()).unwrap().replacen(
        "\"kid\"",
        "\"d\":\"AafCA3fmWi17mcNJceNQq6co8Et-8tF6tqzTz1tONCM\",\"kid\"",
        1,
    );
    assert!(matches!(
        AgentTokenDoor::new(config(), leaked.as_bytes(), clock()),
        Err(DoorError::Jwks(_))
    ));
}

#[test]
fn an_origin_must_be_a_scheme_and_an_authority_and_nothing_else() {
    for origin in [
        "",
        "ingest.acme.example",
        "https://",
        "https://ingest.acme.example/",
        "https://ingest.acme.example/v1",
        "https://ingest.acme.example?x=1",
        "https://user@ingest.acme.example",
    ] {
        let config = DoorConfig {
            origin: origin.to_owned(),
            ..config()
        };
        assert!(
            matches!(
                AgentTokenDoor::new(config, &jwks(), Box::new(|| 0)),
                Err(DoorError::Origin)
            ),
            "{origin:?} was accepted as an origin"
        );
    }
}
