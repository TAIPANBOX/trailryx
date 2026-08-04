//! The wire underneath the rule: a server that answers, a client that asks, and
//! mutual TLS deciding who either of them is talking to.
//!
//! # Why the name comes from the certificate
//!
//! The completeness rule counts answers against a signed registry of peer names.
//! That count is only worth something if a name cannot be claimed. If the peer
//! announced its own name in a field, any node that could reach the port could
//! satisfy the rule by calling itself whatever was missing, and "every peer
//! answered" would degrade into "something answered five times".
//!
//! So the name is never read from the payload. The client connects expecting a
//! specific name, TLS checks that the certificate presented actually carries it,
//! and the handshake fails if it does not. The registry entry is what the client
//! asked for, and the certificate is what makes the answer count. Nothing in the
//! response body participates in that decision.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tonic::{Request, Response, Status};

use trailryx_contracts::{PeerResponse, ProofStatus as PeerProof};
use trailryx_federation::{Federated, PeerAnswer, Registry, compose};
use trailryx_record::Record;

use crate::pb;

/// Why an exchange with a peer did not happen.
///
/// One type for both ends, because a caller composing an answer needs only one
/// distinction: did this peer answer, or not. What went wrong is for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The address would not accept a connection, or the handshake failed. This
    /// covers the certificate saying the wrong name, which is deliberate: a peer
    /// that cannot prove who it is has not answered.
    Unreachable(String),
    /// The far side answered with something this version cannot read.
    Malformed(String),
    /// The stream ended without its trailer. Kept separate from `Malformed`
    /// because it is the failure this design exists to catch.
    Truncated,
    /// The far side took longer than it was given.
    TimedOut,
    /// Local configuration is wrong: bad key material, a port we cannot bind.
    Local(String),
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unreachable(why) => write!(f, "peer unreachable: {why}"),
            Self::Malformed(why) => write!(f, "peer sent something unreadable: {why}"),
            Self::Truncated => write!(f, "the stream ended before its trailer"),
            Self::TimedOut => write!(f, "the peer ran out of time"),
            Self::Local(why) => write!(f, "local configuration: {why}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Why a served answer is not fully proved.
///
/// A closed vocabulary rather than a message. Two reasons: our own status types
/// carry `&'static str`, which cannot be built from bytes off a socket without
/// leaking them; and a free-text reason from a remote node is free text in the
/// metadata plane, which is forbidden outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incompleteness {
    PredicateOffProvableDimensions,
    SegmentUnavailable,
    ProofNotAttempted,
    PeerSetUnattested,
    UpstreamPeerIncomplete,
    /// A code from a newer peer. Named rather than dropped: "a reason we do not
    /// understand" is itself a reason, and treating it as no reason would round
    /// an incomplete answer up to a complete one.
    UnknownToThisVersion,
}

impl Incompleteness {
    pub fn as_static(self) -> &'static str {
        match self {
            Self::PredicateOffProvableDimensions => {
                "a peer's predicate fell outside the provable dimensions"
            }
            Self::SegmentUnavailable => "a peer could not read one of its own segments",
            Self::ProofNotAttempted => "a peer did not attempt a proof",
            Self::PeerSetUnattested => "a peer's own peer set is not attested",
            Self::UpstreamPeerIncomplete => "a peer's own upstream answer was incomplete",
            Self::UnknownToThisVersion => "a peer gave a reason this version does not know",
        }
    }
}

/// What a server has been asked to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServedProof {
    Full,
    Partial(Vec<Incompleteness>),
    NotAttempted(Incompleteness),
}

/// Key material for the side that answers.
///
/// `client_ca_pem` is what makes this mutual: without it the server would accept
/// a query from anyone who could route to the port, and the registry would be
/// guarding the composition while the door stood open.
#[derive(Debug, Clone)]
pub struct ServerIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    pub client_ca_pem: String,
}

/// Key material for the side that asks.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    pub server_ca_pem: String,
}

/// Choose the cryptographic provider for this process, explicitly.
///
/// # Why this exists, since it looks like something rustls should handle
///
/// rustls picks a provider from its own enabled features, and refuses to guess
/// when more than one is compiled in. In a workspace build more than one is:
/// `trailryx-sql` reaches `ring` through DataFusion and pgwire, while this crate
/// and `trailryx-http` ask for `aws-lc-rs`. Cargo unifies those features into
/// one rustls, both providers end up present, and the first TLS call panics
/// rather than silently picking one. That panic is the correct behaviour and it
/// is the reason this function is not optional.
///
/// Calling it is idempotent and the first caller in the process wins. **That
/// last part is a real limitation and not a tidy one:** if something else
/// installs `ring` before any federation traffic starts, this call is a no-op
/// and the transport runs on `ring` rather than on the FIPS-validated AWS-LC the
/// estate standardised on. Nothing here can detect that after the fact, so a
/// deployment that cares should call this before it starts anything else.
///
/// Found by running the workspace suite rather than this crate's own, 2026-08-04:
/// alone, the crate has one provider and every test passes.
pub fn use_aws_lc_rs() {
    // `Err` means somebody got here first, which the doc comment above is about.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn incompleteness_to_wire(r: Incompleteness) -> pb::PartialReason {
    match r {
        Incompleteness::PredicateOffProvableDimensions => {
            pb::PartialReason::PredicateOffProvableDimensions
        }
        Incompleteness::SegmentUnavailable => pb::PartialReason::SegmentUnavailable,
        Incompleteness::ProofNotAttempted => pb::PartialReason::ProofNotAttempted,
        Incompleteness::PeerSetUnattested => pb::PartialReason::PeerSetUnattested,
        Incompleteness::UpstreamPeerIncomplete => pb::PartialReason::UpstreamPeerIncomplete,
        // There is no wire code for "we did not recognise your code". Sending
        // UNSPECIFIED is honest: the far side will read it back as unknown.
        Incompleteness::UnknownToThisVersion => pb::PartialReason::Unspecified,
    }
}

fn incompleteness_from_wire(raw: i32) -> Incompleteness {
    match pb::PartialReason::try_from(raw) {
        Ok(pb::PartialReason::PredicateOffProvableDimensions) => {
            Incompleteness::PredicateOffProvableDimensions
        }
        Ok(pb::PartialReason::SegmentUnavailable) => Incompleteness::SegmentUnavailable,
        Ok(pb::PartialReason::ProofNotAttempted) => Incompleteness::ProofNotAttempted,
        Ok(pb::PartialReason::PeerSetUnattested) => Incompleteness::PeerSetUnattested,
        Ok(pb::PartialReason::UpstreamPeerIncomplete) => Incompleteness::UpstreamPeerIncomplete,
        Ok(pb::PartialReason::Unspecified) | Err(_) => Incompleteness::UnknownToThisVersion,
    }
}

fn trailer_for(proof: &ServedProof) -> pb::Trailer {
    match proof {
        ServedProof::Full => pb::Trailer {
            proof: pb::ProofStatus::Full.into(),
            reasons: Vec::new(),
        },
        ServedProof::Partial(reasons) => pb::Trailer {
            proof: pb::ProofStatus::Partial.into(),
            reasons: reasons
                .iter()
                .map(|r| i32::from(incompleteness_to_wire(*r)))
                .collect(),
        },
        ServedProof::NotAttempted(reason) => pb::Trailer {
            proof: pb::ProofStatus::None.into(),
            reasons: vec![i32::from(incompleteness_to_wire(*reason))],
        },
    }
}

/// The trailer, as the composing side reads it.
///
/// `PeerResponse` carries one reason where a trailer can carry several, so the
/// first is kept and the rest are dropped. Dropping them loses detail and never
/// loses the verdict: any reason at all means the answer is not full, which is
/// the only thing composition acts on.
fn proof_from_trailer(t: &pb::Trailer) -> Result<PeerProof, TransportError> {
    let first = t
        .reasons
        .first()
        .map_or(Incompleteness::UnknownToThisVersion, |r| {
            incompleteness_from_wire(*r)
        });
    match pb::ProofStatus::try_from(t.proof) {
        Ok(pb::ProofStatus::Full) => Ok(PeerProof::Full),
        Ok(pb::ProofStatus::Partial) => Ok(PeerProof::Partial(first.as_static())),
        Ok(pb::ProofStatus::None) => Ok(PeerProof::None),
        // A status this version cannot read is not an invitation to guess. It is
        // refused, and a refused peer is a silent one.
        Ok(pb::ProofStatus::Unspecified) | Err(_) => Err(TransportError::Malformed(
            "the trailer carried a proof status this version does not know".to_owned(),
        )),
    }
}

/// The answering half of a federation peer.
#[derive(Debug)]
struct PeerService {
    chunks: Vec<pb::QueryChunk>,
}

#[tonic::async_trait]
impl pb::federation_server::Federation for PeerService {
    type QueryStream = tokio_stream::Iter<std::vec::IntoIter<Result<pb::QueryChunk, Status>>>;

    async fn query(
        &self,
        _request: Request<pb::QueryRequest>,
    ) -> Result<Response<Self::QueryStream>, Status> {
        let chunks: Vec<Result<pb::QueryChunk, Status>> =
            self.chunks.iter().cloned().map(Ok).collect();
        Ok(Response::new(tokio_stream::iter(chunks)))
    }
}

/// A server that is up, and the address it is listening on.
///
/// Owns the runtime the listener runs on, so dropping it stops the peer. A test
/// that forgets to hold one gets a connection refused rather than a port that
/// outlives the run.
#[derive(Debug)]
pub struct RunningPeer {
    addr: SocketAddr,
    _runtime: Runtime,
}

impl RunningPeer {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Serve a fixed answer as a federation peer.
///
/// The records are encoded once, at start, and the trailer is appended last. The
/// ordering is the contract: everything before the trailer is data, and reaching
/// the end without one means the answer was cut off.
pub fn serve(
    bind: SocketAddr,
    records: Vec<Record>,
    proof: ServedProof,
    identity: ServerIdentity,
) -> Result<RunningPeer, TransportError> {
    let mut chunks: Vec<pb::QueryChunk> = records
        .iter()
        .map(|r| pb::QueryChunk {
            body: Some(pb::query_chunk::Body::Record(crate::to_wire(r))),
        })
        .collect();
    chunks.push(pb::QueryChunk {
        body: Some(pb::query_chunk::Body::Trailer(trailer_for(&proof))),
    });

    use_aws_lc_rs();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(&identity.cert_pem, &identity.key_pem))
        // What makes this mutual. Without it the registry would guard the
        // composition while the door stood open to anyone who could route here.
        .client_ca_root(Certificate::from_pem(&identity.client_ca_pem));

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| TransportError::Local(e.to_string()))?;

    let listener = runtime
        .block_on(TcpListener::bind(bind))
        .map_err(|e| TransportError::Local(e.to_string()))?;
    let addr = listener
        .local_addr()
        .map_err(|e| TransportError::Local(e.to_string()))?;

    let server = Server::builder()
        .tls_config(tls)
        .map_err(|e| TransportError::Local(e.to_string()))?
        .add_service(pb::federation_server::FederationServer::new(PeerService {
            chunks,
        }));

    runtime.spawn(async move {
        let _ = server
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });

    Ok(RunningPeer {
        addr,
        _runtime: runtime,
    })
}

/// One remote environment, reached over gRPC.
#[derive(Debug)]
pub struct GrpcPeer {
    name: String,
    client: pb::federation_client::FederationClient<Channel>,
    runtime: Runtime,
}

impl GrpcPeer {
    /// Connect, insisting on who is at the other end.
    ///
    /// `expected_name` is both the registry entry being satisfied and the name
    /// TLS is told to require of the certificate. Passing one and checking the
    /// other is the whole guarantee, so they are deliberately the same argument:
    /// there is no call shape in which a caller can verify one name and count
    /// the answer against another.
    pub fn connect(
        expected_name: &str,
        addr: SocketAddr,
        identity: ClientIdentity,
        timeout: Duration,
    ) -> Result<Self, TransportError> {
        use_aws_lc_rs();
        let tls = ClientTlsConfig::new()
            .domain_name(expected_name.to_owned())
            .ca_certificate(Certificate::from_pem(&identity.server_ca_pem))
            .identity(Identity::from_pem(&identity.cert_pem, &identity.key_pem));

        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| TransportError::Local(e.to_string()))?;

        let endpoint = Endpoint::from_shared(format!("https://{addr}"))
            .map_err(|e| TransportError::Local(e.to_string()))?
            .tls_config(tls)
            .map_err(|e| TransportError::Local(e.to_string()))?
            .connect_timeout(timeout)
            // Invariant 18, on the wire rather than in a test: an unbounded wait
            // reports nothing at all.
            .timeout(timeout);

        // Eager rather than lazy on purpose: the handshake is where the far
        // side's identity is decided, and a caller should not hold something
        // called `connect` that has not yet checked who answered.
        //
        // Note what this does and does not settle. It settles **their**
        // identity: a certificate that does not carry `expected_name` fails
        // here. It does not settle **ours**. Under TLS 1.3 the server sends its
        // Finished before processing the client certificate, so an unauthorised
        // client's `connect` succeeds and its first query is refused instead.
        // Measured against a real handshake, 2026-08-04; see
        // `a_client_signed_by_another_authority_gets_no_records`.
        let channel = runtime
            .block_on(endpoint.connect())
            .map_err(|e| TransportError::Unreachable(e.to_string()))?;

        Ok(Self {
            name: expected_name.to_owned(),
            client: pb::federation_client::FederationClient::new(channel),
            runtime,
        })
    }

    /// The name TLS verified. Not a name the peer sent.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Ask, and require a trailer.
    pub fn query_records(&mut self, predicate: &str) -> Result<PeerResponse, TransportError> {
        let request = pb::QueryRequest {
            predicate: predicate.to_owned(),
        };
        let client = &mut self.client;
        self.runtime.block_on(async move {
            let mut stream = client
                .query(request)
                .await
                .map_err(|e| TransportError::Unreachable(e.to_string()))?
                .into_inner();

            let mut records = Vec::new();
            let mut proof = None;

            while let Some(chunk) = stream
                .message()
                .await
                .map_err(|e| TransportError::Unreachable(e.to_string()))?
            {
                match chunk.body {
                    Some(pb::query_chunk::Body::Record(r)) => {
                        if proof.is_some() {
                            // Records after the trailer. Either the far side is
                            // broken or somebody is appending to a finished
                            // answer; both are refusals, not merges.
                            return Err(TransportError::Malformed(
                                "a record arrived after the trailer".to_owned(),
                            ));
                        }
                        records.push(
                            crate::from_wire(r)
                                .map_err(|e| TransportError::Malformed(e.to_string()))?,
                        );
                    }
                    Some(pb::query_chunk::Body::Trailer(t)) => {
                        proof = Some(proof_from_trailer(&t)?);
                    }
                    None => {
                        return Err(TransportError::Malformed("a chunk with no body".to_owned()));
                    }
                }
            }

            // The whole reason the status travels last. A stream that ends here
            // carried records and no claim about them, and the one thing that
            // must not happen is for those records to read as a complete answer.
            let proof = proof.ok_or(TransportError::Truncated)?;
            Ok(PeerResponse { records, proof })
        })
    }
}

/// Ask every connected peer, and compose under the rule.
///
/// The name attached to each answer is [`GrpcPeer::name`], which TLS verified at
/// the handshake. A peer that errors is left out of the answers entirely, which
/// is what puts it in `silent` and downgrades the proof: an error and an empty
/// result must never reach a reader as the same thing.
pub fn fan_out(
    registry: &Registry,
    peers: &mut [GrpcPeer],
    predicate: &str,
) -> (Federated, Vec<(String, TransportError)>) {
    let mut answers = Vec::new();
    let mut failures = Vec::new();
    for peer in peers.iter_mut() {
        let name = peer.name().to_owned();
        match peer.query_records(predicate) {
            Ok(response) => answers.push(PeerAnswer {
                peer: name,
                response,
            }),
            Err(e) => failures.push((name, e)),
        }
    }
    (compose(registry, answers), failures)
}
