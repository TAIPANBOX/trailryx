//! The federation rule, over real sockets and real mutual TLS.
//!
//! Everything here binds a loopback listener and completes a handshake. Nothing
//! is stubbed: a test that mocked the transport would agree with whatever the
//! transport does, including the mistakes, and the mistakes are the reason this
//! crate exists.

use std::net::SocketAddr;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use trailryx_federation::Registry;
use trailryx_federation_grpc::{
    ClientIdentity, GrpcPeer, Incompleteness, ServedProof, ServerIdentity, TransportError, fan_out,
    serve,
};
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};

/// A bound on every wait in this file.
///
/// Invariant 18: a test that hangs reports nothing at all, which is less than a
/// wrong answer tells you.
const PATIENCE: Duration = Duration::from_secs(5);

/// Any free loopback port. The address is an argument rather than a default so
/// that a peer meant to be reachable from another machine cannot get one by
/// forgetting to say so.
fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("a literal address")
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Ca {
    fn new(name: &str) -> Self {
        let key = KeyPair::generate().expect("a key pair");
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, name.to_owned());
        let cert = params.self_signed(&key).expect("a self-signed ca");
        Self { cert, key }
    }

    fn pem(&self) -> String {
        self.cert.pem()
    }

    /// A leaf whose subject alternative name is exactly `name`.
    ///
    /// That SAN is the peer's identity. Everything the completeness rule counts
    /// hangs off it being checked rather than announced.
    fn issue(&self, name: &str) -> (String, String) {
        let key = KeyPair::generate().expect("a key pair");
        let mut params = CertificateParams::new(vec![name.to_owned()]).expect("leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, name.to_owned());
        let cert = params
            .signed_by(&key, &self.cert, &self.key)
            .expect("a signed leaf");
        (cert.pem(), key.serialize_pem())
    }
}

/// One certificate authority for the whole federation, which is what a signed
/// peer registry implies: the registry says who the members are, and the CA is
/// how a member proves it is the one it claims.
struct Federation {
    ca: Ca,
}

impl Federation {
    fn new() -> Self {
        Self {
            ca: Ca::new("trailryx federation test ca"),
        }
    }

    fn server_identity(&self, name: &str) -> ServerIdentity {
        let (cert_pem, key_pem) = self.ca.issue(name);
        ServerIdentity {
            cert_pem,
            key_pem,
            client_ca_pem: self.ca.pem(),
        }
    }

    fn client_identity(&self, name: &str) -> ClientIdentity {
        let (cert_pem, key_pem) = self.ca.issue(name);
        ClientIdentity {
            cert_pem,
            key_pem,
            server_ca_pem: self.ca.pem(),
        }
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

fn record(seq: u64) -> Record {
    Record {
        id: RecordId(u128::from(seq)),
        tenant: TenantId::parse("acme").expect("a tenant"),
        shard: ShardIx(0),
        agent_id: AgentId::parse_strict("agent://acme.example/support").expect("an agent"),
        run_id: RunId::parse("run-1").expect("a run"),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(1_000 + seq)),
        decided_at: None,
        recorded_at: Timestamp(1_000 + seq),
        knowledge_as_of: None,
        clock_skew_nanos: None,
        event_type: EventType::ModelCall,
        severity: Severity::Info,
        basis: Basis::default(),
        caused_by: Vec::new(),
        outcome: Outcome::default(),
        payload: None,
        seq,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(1),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}

fn records(n: u64) -> Vec<Record> {
    (0..n).map(record).collect()
}

fn connect(fed: &Federation, name: &str, addr: SocketAddr) -> Result<GrpcPeer, TransportError> {
    GrpcPeer::connect(name, addr, fed.client_identity("eu-aws"), PATIENCE)
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// The roadmap's acceptance criterion for stage 12, over a wire rather than in
/// memory: a query across two environments yields a correct joint proof.
#[test]
fn two_environments_answering_over_real_sockets_compose_to_a_complete_answer() {
    let fed = Federation::new();

    let aws = serve(
        loopback(),
        records(2),
        ServedProof::Full,
        fed.server_identity("eu-aws"),
    )
    .expect("the aws peer starts");
    let gcp = serve(
        loopback(),
        records(3),
        ServedProof::Full,
        fed.server_identity("eu-gcp"),
    )
    .expect("the gcp peer starts");

    let mut peers = vec![
        connect(&fed, "eu-aws", aws.addr()).expect("aws accepts us"),
        connect(&fed, "eu-gcp", gcp.addr()).expect("gcp accepts us"),
    ];

    let registry = Registry::attested(7, vec!["eu-aws".to_owned(), "eu-gcp".to_owned()], true);
    let (federated, failures) = fan_out(&registry, &mut peers, "recorded_at >= 0");

    assert!(failures.is_empty(), "{failures:?}");
    assert!(
        federated.proof.is_full(),
        "both environments answered completely: {:?}",
        federated.proof
    );
    assert_eq!(federated.records.len(), 5);
    assert_eq!(federated.registry_version, 7);
    assert!(federated.silent.is_empty());
}

/// The attack the signed registry would otherwise not survive.
///
/// A node holding a valid federation certificate for `eu-gcp` is a member in
/// good standing. If it could answer as `on-prem` as well, it could satisfy the
/// completeness rule single-handed: every name in the registry accounted for,
/// by one machine, and the resulting answer stamped complete while a whole
/// environment was never asked. The name is therefore not something a peer
/// says, it is something its certificate proves.
#[test]
fn a_peer_cannot_answer_under_a_name_its_certificate_does_not_carry() {
    let fed = Federation::new();
    let gcp = serve(
        loopback(),
        records(3),
        ServedProof::Full,
        fed.server_identity("eu-gcp"),
    )
    .expect("the gcp peer starts");

    let impersonation = connect(&fed, "on-prem", gcp.addr());

    assert!(
        matches!(impersonation, Err(TransportError::Unreachable(_))),
        "a certificate for eu-gcp must not answer as on-prem, got {impersonation:?}"
    );
}

/// The registry names three environments and two are up. The rows that arrived
/// are still returned; what changes is the claim attached to them.
#[test]
fn a_forgotten_environment_breaks_the_proof_over_the_wire() {
    let fed = Federation::new();
    let aws = serve(
        loopback(),
        records(2),
        ServedProof::Full,
        fed.server_identity("eu-aws"),
    )
    .expect("the aws peer starts");
    let gcp = serve(
        loopback(),
        records(3),
        ServedProof::Full,
        fed.server_identity("eu-gcp"),
    )
    .expect("the gcp peer starts");

    let mut peers = vec![
        connect(&fed, "eu-aws", aws.addr()).expect("aws accepts us"),
        connect(&fed, "eu-gcp", gcp.addr()).expect("gcp accepts us"),
    ];

    let registry = Registry::attested(
        7,
        vec![
            "eu-aws".to_owned(),
            "eu-gcp".to_owned(),
            "on-prem".to_owned(),
        ],
        true,
    );
    let (federated, _) = fan_out(&registry, &mut peers, "recorded_at >= 0");

    assert!(
        !federated.proof.is_full(),
        "an answer missing a whole environment is not complete"
    );
    assert_eq!(federated.silent, vec!["on-prem".to_owned()]);
    assert_eq!(
        federated.records.len(),
        5,
        "the rows that did arrive are still returned"
    );
}

/// A peer that is down is silent, not empty. An error and an empty answer must
/// never reach a reader as the same thing, because one of them means "this
/// environment had nothing" and the other means "nobody asked it".
#[test]
fn an_environment_that_is_down_is_silent_rather_than_empty() {
    let fed = Federation::new();
    let aws = serve(
        loopback(),
        records(2),
        ServedProof::Full,
        fed.server_identity("eu-aws"),
    )
    .expect("the aws peer starts");

    let gcp_addr = {
        let gcp = serve(
            loopback(),
            Vec::new(),
            ServedProof::Full,
            fed.server_identity("eu-gcp"),
        )
        .expect("the gcp peer starts");
        let addr = gcp.addr();
        // Dropping it takes the runtime with it, which is this test's way of
        // pulling the plug on an environment.
        drop(gcp);
        addr
    };

    let mut peers = vec![connect(&fed, "eu-aws", aws.addr()).expect("aws accepts us")];
    assert!(
        connect(&fed, "eu-gcp", gcp_addr).is_err(),
        "an environment that is down cannot be connected to"
    );

    let registry = Registry::attested(9, vec!["eu-aws".to_owned(), "eu-gcp".to_owned()], true);
    let (federated, _) = fan_out(&registry, &mut peers, "recorded_at >= 0");

    assert!(!federated.proof.is_full());
    assert_eq!(federated.silent, vec!["eu-gcp".to_owned()]);
}

/// Mutual, not one-way. Without this the registry guards the composition while
/// the door stands open to anything that can route to the port.
///
/// **Where the refusal lands is not where it was first expected, and the
/// difference is a property of TLS 1.3 rather than of this code.** The server
/// sends its own Finished before it has processed the client's certificate, so
/// `connect` returns to an unauthorised client as if all were well and the
/// rejection surfaces on the first request. This test therefore asserts the
/// thing that actually matters and holds either way: an outsider ends the
/// exchange with no records. Asserting instead that `connect` fails would pass
/// on a stack that closed earlier and fail here for a reason that has nothing to
/// do with whether the door is locked.
#[test]
fn a_client_signed_by_another_authority_gets_no_records() {
    let fed = Federation::new();
    let outsider = Federation::new();

    let aws = serve(
        loopback(),
        records(2),
        ServedProof::Full,
        fed.server_identity("eu-aws"),
    )
    .expect("the aws peer starts");

    // Their own key, signed by their own authority, plus our CA so that they are
    // satisfied with us. The half they cannot forge is the half that stops them.
    let attempt = GrpcPeer::connect(
        "eu-aws",
        aws.addr(),
        ClientIdentity {
            server_ca_pem: fed.ca.pem(),
            ..outsider.client_identity("eu-aws")
        },
        PATIENCE,
    );

    match attempt {
        Err(_) => {}
        Ok(mut peer) => {
            let answer = peer.query_records("recorded_at >= 0");
            assert!(
                answer.is_err(),
                "an unauthorised client must not receive records, got {answer:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Peers that do not play by the rules
//
// These serve the generated types directly rather than going through `serve`,
// which is the point: the library offers no way to answer without a trailer, so
// a peer that does one has to be built here, by hand, the way a hostile one
// would be.
// ---------------------------------------------------------------------------

fn serve_hostile<S>(service: S, identity: ServerIdentity) -> (SocketAddr, tokio::runtime::Runtime)
where
    S: trailryx_federation_grpc::pb::federation_server::Federation,
{
    use trailryx_federation_grpc::pb::federation_server::FederationServer;

    // The hostile peers build their TLS by hand, so they also have to make the
    // same explicit choice `serve` makes for itself.
    trailryx_federation_grpc::use_aws_lc_rs();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind(loopback()))
        .expect("a port");
    let addr = listener.local_addr().expect("an address");

    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            &identity.cert_pem,
            &identity.key_pem,
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(
            &identity.client_ca_pem,
        ));

    let server = tonic::transport::Server::builder()
        .tls_config(tls)
        .expect("tls")
        .add_service(FederationServer::new(service));

    runtime.spawn(async move {
        let _ = server
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await;
    });

    (addr, runtime)
}

type Chunks = tokio_stream::Iter<
    std::vec::IntoIter<Result<trailryx_federation_grpc::pb::QueryChunk, tonic::Status>>,
>;

fn chunk_of(record: &Record) -> trailryx_federation_grpc::pb::QueryChunk {
    trailryx_federation_grpc::pb::QueryChunk {
        body: Some(trailryx_federation_grpc::pb::query_chunk::Body::Record(
            trailryx_federation_grpc::to_wire(record),
        )),
    }
}

/// Sends rows and then simply stops.
struct NoTrailer;

#[tonic::async_trait]
impl trailryx_federation_grpc::pb::federation_server::Federation for NoTrailer {
    type QueryStream = Chunks;

    async fn query(
        &self,
        _request: tonic::Request<trailryx_federation_grpc::pb::QueryRequest>,
    ) -> Result<tonic::Response<Self::QueryStream>, tonic::Status> {
        let chunks: Vec<_> = records(3).iter().map(|r| Ok(chunk_of(r))).collect();
        Ok(tonic::Response::new(tokio_stream::iter(chunks)))
    }
}

/// Closes the answer, then keeps talking.
struct RecordAfterTrailer;

#[tonic::async_trait]
impl trailryx_federation_grpc::pb::federation_server::Federation for RecordAfterTrailer {
    type QueryStream = Chunks;

    async fn query(
        &self,
        _request: tonic::Request<trailryx_federation_grpc::pb::QueryRequest>,
    ) -> Result<tonic::Response<Self::QueryStream>, tonic::Status> {
        let mut chunks: Vec<_> = records(1).iter().map(|r| Ok(chunk_of(r))).collect();
        chunks.push(Ok(trailryx_federation_grpc::pb::QueryChunk {
            body: Some(trailryx_federation_grpc::pb::query_chunk::Body::Trailer(
                trailryx_federation_grpc::pb::Trailer {
                    proof: 1, // FULL
                    reasons: Vec::new(),
                },
            )),
        }));
        chunks.push(Ok(chunk_of(&record(99))));
        Ok(tonic::Response::new(tokio_stream::iter(chunks)))
    }
}

/// The thesis of the whole crate, one layer below where it is usually stated.
///
/// Three rows arrive and the connection ends. Those three rows are real, they
/// verify, and they are a lie if anything reads them as the answer: the fourth
/// might never have been sent, or might have been dropped by a network, or
/// withheld by a peer that preferred a smaller answer. Since the claim rides at
/// the end, its absence is the signal, and the caller gets a refusal rather than
/// three good records and a wrong conclusion.
#[test]
fn a_stream_that_ends_before_its_trailer_is_refused_rather_than_read_as_complete() {
    let fed = Federation::new();
    let (addr, _rt) = serve_hostile(NoTrailer, fed.server_identity("eu-gcp"));

    let mut peer = connect(&fed, "eu-gcp", addr).expect("the handshake itself is fine");
    let answer = peer.query_records("recorded_at >= 0");

    assert_eq!(
        answer,
        Err(TransportError::Truncated),
        "rows without a claim about them are not an answer"
    );
}

/// The same failure from the other side: an answer that was closed and then
/// grew. Merging the extra row would mean the trailer described a set that is
/// not the set returned.
#[test]
fn a_record_arriving_after_the_trailer_is_refused() {
    let fed = Federation::new();
    let (addr, _rt) = serve_hostile(RecordAfterTrailer, fed.server_identity("eu-gcp"));

    let mut peer = connect(&fed, "eu-gcp", addr).expect("the handshake itself is fine");
    let answer = peer.query_records("recorded_at >= 0");

    assert!(
        matches!(answer, Err(TransportError::Malformed(_))),
        "got {answer:?}"
    );
}

/// A truncated peer inside a real fan-out. The composed answer must not be
/// full, and the peer must be named as silent rather than counted as answered.
#[test]
fn a_truncated_peer_is_silent_in_the_composed_answer() {
    let fed = Federation::new();
    let aws = serve(
        loopback(),
        records(2),
        ServedProof::Full,
        fed.server_identity("eu-aws"),
    )
    .expect("the aws peer starts");
    let (gcp_addr, _rt) = serve_hostile(NoTrailer, fed.server_identity("eu-gcp"));

    let mut peers = vec![
        connect(&fed, "eu-aws", aws.addr()).expect("aws accepts us"),
        connect(&fed, "eu-gcp", gcp_addr).expect("gcp accepts us"),
    ];

    let registry = Registry::attested(3, vec!["eu-aws".to_owned(), "eu-gcp".to_owned()], true);
    let (federated, failures) = fan_out(&registry, &mut peers, "recorded_at >= 0");

    assert!(!federated.proof.is_full());
    assert_eq!(federated.silent, vec!["eu-gcp".to_owned()]);
    assert_eq!(
        federated.records.len(),
        2,
        "the truncated peer contributes nothing, not a partial three"
    );
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].1, TransportError::Truncated);
}

/// A peer's own incompleteness survives the wire.
///
/// If the reason were dropped in transit, a federation of honest nodes would
/// round its own partial answers up to complete, one hop at a time.
#[test]
fn a_peers_own_partial_answer_stays_partial_after_crossing_the_wire() {
    let fed = Federation::new();
    let aws = serve(
        loopback(),
        records(2),
        ServedProof::Partial(vec![Incompleteness::PredicateOffProvableDimensions]),
        fed.server_identity("eu-aws"),
    )
    .expect("the aws peer starts");

    let mut peers = vec![connect(&fed, "eu-aws", aws.addr()).expect("aws accepts us")];
    let registry = Registry::attested(1, vec!["eu-aws".to_owned()], true);
    let (federated, failures) = fan_out(&registry, &mut peers, "payload_size > 10");

    assert!(failures.is_empty(), "{failures:?}");
    assert!(
        !federated.proof.is_full(),
        "the peer said its own answer was partial"
    );
    assert_eq!(federated.records.len(), 2);
}

/// The answering half ignores the predicate, and this pins it so that a real
/// server cannot inherit the behaviour without somebody deciding to.
///
/// `serve` is handed its records and its proof status, so a query has nothing
/// to narrow: the answer was decided before it arrived. That is right for a
/// harness and wrong for a store, and the two are one function call apart in
/// this workspace, because `PeerService` is the only implementation of the
/// answering half that exists.
///
/// The assertion is deliberately the CURRENT behaviour rather than the desired
/// one. A test asserting that a predicate narrows an answer would fail today
/// and would be deleted or ignored; a test asserting that it does NOT goes red
/// on the day somebody implements filtering, which is exactly when a person
/// should be reading this comment.
#[test]
fn a_predicate_does_not_narrow_what_this_harness_answers() {
    let fed = Federation::new();

    let peer = serve(
        loopback(),
        records(3),
        ServedProof::Full,
        fed.server_identity("eu-aws"),
    )
    .expect("the peer starts");

    let mut client = connect(&fed, "eu-aws", peer.addr()).expect("the peer accepts us");

    // A predicate that matches everything, and one that can match nothing at
    // all. A store would answer the second with an empty set.
    let everything = client
        .query_records("recorded_at >= 0")
        .expect("a query answers");
    let nothing = client
        .query_records("recorded_at >= 99999999999999")
        .expect("a query answers");

    assert_eq!(
        everything.records.len(),
        3,
        "the harness answers with what it was given"
    );
    assert_eq!(
        nothing.records.len(),
        3,
        "and answers the same to a predicate that could match nothing, because it \
         never applied one: if this line fails, filtering has been implemented and \
         PeerService::query's doc comment and VALIDATION.md both need revisiting"
    );
}
