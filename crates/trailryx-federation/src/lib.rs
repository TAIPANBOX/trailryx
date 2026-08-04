//! Federation: one question, several environments, one honest answer.
//!
//! # The scenario, and the one thing that must not happen
//!
//! Agents run in AWS, in Google Cloud and on somebody's own hardware. Each
//! environment has its own node holding its own records. The question is always the
//! same: *show me everything this agent did in March, everywhere.*
//!
//! Fanning the query out and merging the rows is the easy half. The half that
//! matters is what the merged answer is allowed to claim, because **forgetting one
//! node produces a smaller answer that looks exactly like a complete one**. A
//! federation that answers "here is everything" while a node was quietly left out is
//! worse than no federation: it turns a proof into a decoration.
//!
//! # The rule, in one sentence
//!
//! A federated answer is complete **if and only if** the peer set itself is
//! attested, every peer in that set answered, and every one of those answers was
//! itself complete. Anything else is partial, with the reason named.
//!
//! The first clause is the one people skip. Without a signed list of who the peers
//! are, "everybody answered" means "everybody I happened to ask", which is not a
//! statement about the world. That is why [`Registry`] cannot be built by hand: it
//! comes from bytes and a signature, or it comes marked unattested.
//!
//! # Why this is not new machinery
//!
//! It is the composition already used between shards inside one node, one level up.
//! Records compose into a segment, segments into a shard, shards into a store, and
//! stores into a federation, and each step asks the same question: is the set of
//! things I combined the set that exists? The transport and the registry are what
//! stage 12 adds; the rule was written once.

/// Verified replication: what a receiver checks before adopting a peer's
/// records. Composition above answers "did everyone answer"; this answers
/// "does what one of them said link up", and they are different questions.
pub mod replication;

use trailryx_contracts::{Peer, PeerResponse, ProofStatus as PeerProof};
use trailryx_record::Record;
use trailryx_store::query::ProofStatus;

/// Who the peers are, and whether anybody signed for that.
///
/// Deliberately not constructible with a list alone: the whole point is that an
/// unsigned list is a guess. [`Registry::attested`] takes bytes and a verdict from
/// a verifier the deployment supplies, so the signature check stays outside this
/// crate and the rule stays inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registry {
    /// Bumped whenever the membership changes, so an answer can say which set it
    /// was complete for. A registry without a version cannot be cited later.
    pub version: u32,
    peers: Vec<String>,
    attested: bool,
}

impl Registry {
    /// A registry somebody signed for.
    ///
    /// `verified` is the deployment's answer to "does this signature check out",
    /// computed with its own keys. Passing `false` is allowed and produces exactly
    /// what an unsigned list deserves: a registry that can never yield a full proof.
    pub fn attested(version: u32, peers: Vec<String>, verified: bool) -> Self {
        let mut peers = peers;
        peers.sort();
        peers.dedup();
        Self {
            version,
            peers,
            attested: verified,
        }
    }

    /// A list nobody signed for. Named so that reading the call site tells you what
    /// is wrong with it.
    pub fn unattested(version: u32, peers: Vec<String>) -> Self {
        Self::attested(version, peers, false)
    }

    /// The bytes a signature is computed over.
    ///
    /// Canonical because two nodes have to agree on them: sorted, deduplicated, with
    /// the version first and lengths in front of every name, so that a peer called
    /// `a` next to `b` cannot be confused with one called `ab`.
    pub fn signing_bytes(version: u32, peers: &[String]) -> Vec<u8> {
        let mut sorted: Vec<&String> = peers.iter().collect();
        sorted.sort();
        sorted.dedup();
        let mut out = b"trailryx/peer-registry/v1\0".to_vec();
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
        for peer in sorted {
            out.extend_from_slice(&(peer.len() as u32).to_be_bytes());
            out.extend_from_slice(peer.as_bytes());
        }
        out
    }

    pub fn is_attested(&self) -> bool {
        self.attested
    }

    pub fn peers(&self) -> &[String] {
        &self.peers
    }
}

/// What one peer said, with its name attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAnswer {
    pub peer: String,
    pub response: PeerResponse,
}

/// The merged answer, and what it is allowed to claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Federated {
    pub records: Vec<Record>,
    pub proof: ProofStatus,
    /// The registry version this answer was composed against, so a reader can ask
    /// later which set it was complete for. A claim of completeness without one
    /// cannot be checked a year afterwards.
    pub registry_version: u32,
    /// Peers in the registry that did not answer, by name.
    pub silent: Vec<String>,
    /// Peers that answered without being in the registry.
    pub unexpected: Vec<String>,
}

/// Merge what the peers said, and decide what the result may claim.
pub fn compose(registry: &Registry, answers: Vec<PeerAnswer>) -> Federated {
    let mut proof = ProofStatus::Full;

    // Clause one, and the one that is usually skipped. Without a signed set,
    // "everybody answered" only means "everybody I happened to ask".
    if !registry.is_attested() {
        proof.downgrade_public("the peer set is not attested");
    }

    let answered: Vec<&str> = answers.iter().map(|a| a.peer.as_str()).collect();
    let silent: Vec<String> = registry
        .peers()
        .iter()
        .filter(|p| !answered.contains(&p.as_str()))
        .cloned()
        .collect();
    if !silent.is_empty() {
        // The forgotten node. This is the failure the whole design exists to make
        // impossible to have silently.
        proof.downgrade_public("a peer in the registry did not answer");
    }

    let unexpected: Vec<String> = answers
        .iter()
        .filter(|a| !registry.peers().iter().any(|p| p == &a.peer))
        .map(|a| a.peer.clone())
        .collect();
    if !unexpected.is_empty() {
        // Rarer and stranger: rows arrived from a node the signed set does not
        // cover. The answer may well be bigger than complete, and "bigger than
        // complete" is not a thing anybody can act on.
        proof.downgrade_public("a peer answered that the registry does not list");
    }

    let mut records = Vec::new();
    for answer in answers {
        // A peer speaks the contract's vocabulary, which has one reason; a reader
        // gets the store's, which can hold several at once. The federated answer is
        // the place those meet.
        if !matches!(answer.response.proof, PeerProof::Full) {
            proof.downgrade_public("a peer's own answer was not complete");
        }
        records.extend(answer.response.records);
    }

    // Merged in the order the dimension is sorted by, so a federated answer reads
    // like a single node's: by time, then by the identity that breaks ties.
    records.sort_by(|a, b| a.recorded_at.cmp(&b.recorded_at).then(a.id.cmp(&b.id)));

    Federated {
        records,
        proof,
        registry_version: registry.version,
        silent,
        unexpected,
    }
}

/// Ask every peer and compose what comes back.
///
/// A peer that fails is not a peer that answered: its name stays in `silent` and the
/// proof is downgraded for it, because an error and an empty answer must never be
/// the same thing to a reader.
pub fn fan_out(registry: &Registry, peers: &mut [&mut dyn Peer], predicate: &str) -> Federated {
    let mut answers = Vec::new();
    for peer in peers.iter_mut() {
        let name = peer.descriptor().name.to_owned();
        match peer.query(predicate) {
            Ok(response) => answers.push(PeerAnswer {
                peer: name,
                response,
            }),
            Err(_) => continue,
        }
    }
    compose(registry, answers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_contracts::{AdapterError, AdapterResult, PeerDescriptor};

    fn peers(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    /// One record, built the way the store's own tests build them.
    fn record(seq: u64) -> Record {
        use trailryx_record::{
            AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, RecordId, RunId,
            SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
        };
        Record {
            id: RecordId(u128::from(seq)),
            tenant: TenantId::parse("acme").expect("a tenant"),
            shard: ShardIx(0),
            agent_id: AgentId::parse("agent://acme.example/support").expect("an agent"),
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

    fn answer(peer: &str, count: u64, proof: PeerProof) -> PeerAnswer {
        PeerAnswer {
            peer: peer.to_owned(),
            response: PeerResponse {
                records: (0..count).map(record).collect(),
                proof,
            },
        }
    }

    #[test]
    fn two_environments_that_both_answer_completely_compose_to_a_complete_answer() {
        let registry = Registry::attested(7, peers(&["eu-aws", "eu-gcp"]), true);
        let federated = compose(
            &registry,
            vec![
                answer("eu-aws", 2, PeerProof::Full),
                answer("eu-gcp", 3, PeerProof::Full),
            ],
        );
        assert!(federated.proof.is_full());
        assert_eq!(federated.records.len(), 5);
        assert_eq!(federated.registry_version, 7);
        assert!(federated.silent.is_empty());
    }

    /// The acceptance criterion, and the reason this crate exists: a forgotten node
    /// must break the proof rather than pass quietly.
    #[test]
    fn a_forgotten_peer_breaks_the_proof_instead_of_shrinking_the_answer() {
        let registry = Registry::attested(7, peers(&["eu-aws", "eu-gcp", "on-prem"]), true);
        let federated = compose(
            &registry,
            vec![
                answer("eu-aws", 2, PeerProof::Full),
                answer("eu-gcp", 3, PeerProof::Full),
            ],
        );
        assert!(
            !federated.proof.is_full(),
            "an answer missing a whole environment is not complete"
        );
        assert_eq!(federated.silent, vec!["on-prem".to_owned()]);
        assert_eq!(
            federated.records.len(),
            5,
            "the rows that did arrive are still returned; it is the claim that changes"
        );
    }

    /// Without a signed set, "everybody answered" means "everybody I asked", which
    /// is not a statement about the world.
    #[test]
    fn an_unattested_registry_can_never_yield_a_complete_answer() {
        let registry = Registry::unattested(1, peers(&["eu-aws"]));
        let federated = compose(&registry, vec![answer("eu-aws", 1, PeerProof::Full)]);
        assert!(!federated.proof.is_full());
        match federated.proof {
            ProofStatus::Partial { unproved } => {
                assert!(
                    unproved.iter().any(|r| r.contains("not attested")),
                    "{unproved:?}"
                );
            }
            other => panic!("expected a partial answer, got {other:?}"),
        }
    }

    #[test]
    fn a_peers_own_partial_answer_makes_the_federated_one_partial() {
        let registry = Registry::attested(2, peers(&["a", "b"]), true);
        let federated = compose(
            &registry,
            vec![
                answer("a", 1, PeerProof::Full),
                answer(
                    "b",
                    1,
                    PeerProof::Partial("a filter outside the sorted dimension"),
                ),
            ],
        );
        assert!(!federated.proof.is_full());
    }

    /// Rows from a node the signed set does not cover. The answer may be bigger than
    /// complete, and nobody can act on "bigger than complete".
    #[test]
    fn a_peer_nobody_signed_for_is_named_rather_than_quietly_included() {
        let registry = Registry::attested(3, peers(&["a"]), true);
        let federated = compose(
            &registry,
            vec![
                answer("a", 1, PeerProof::Full),
                answer("stranger", 1, PeerProof::Full),
            ],
        );
        assert!(!federated.proof.is_full());
        assert_eq!(federated.unexpected, vec!["stranger".to_owned()]);
    }

    /// The bytes two nodes have to agree on. Sorted and length-prefixed, so a set
    /// containing `a` and `b` cannot sign the same bytes as one containing `ab`.
    #[test]
    fn the_signing_bytes_do_not_depend_on_order_and_cannot_be_confused() {
        assert_eq!(
            Registry::signing_bytes(1, &peers(&["b", "a"])),
            Registry::signing_bytes(1, &peers(&["a", "b"]))
        );
        assert_ne!(
            Registry::signing_bytes(1, &peers(&["a", "b"])),
            Registry::signing_bytes(1, &peers(&["ab"]))
        );
        assert_ne!(
            Registry::signing_bytes(1, &peers(&["a"])),
            Registry::signing_bytes(2, &peers(&["a"])),
            "a version change is a different set to sign for"
        );
    }

    /// A peer that fails is not a peer that answered. Treating an error as an empty
    /// answer is how a broken environment becomes an environment with no records.
    #[test]
    fn a_peer_that_errors_is_silent_rather_than_empty() {
        struct Working;
        struct Broken;
        impl Peer for Working {
            fn descriptor(&self) -> PeerDescriptor {
                PeerDescriptor {
                    name: "works",
                    attested: true,
                }
            }
            fn query(&mut self, _: &str) -> AdapterResult<PeerResponse> {
                Ok(PeerResponse {
                    records: vec![record(1)],
                    proof: PeerProof::Full,
                })
            }
        }
        impl Peer for Broken {
            fn descriptor(&self) -> PeerDescriptor {
                PeerDescriptor {
                    name: "broken",
                    attested: true,
                }
            }
            fn query(&mut self, _: &str) -> AdapterResult<PeerResponse> {
                Err(AdapterError::Unavailable("the peer is down"))
            }
        }

        let registry = Registry::attested(4, peers(&["works", "broken"]), true);
        let mut working = Working;
        let mut broken = Broken;
        let federated = fan_out(
            &registry,
            &mut [&mut working as &mut dyn Peer, &mut broken],
            "agent = 'x'",
        );
        assert!(!federated.proof.is_full());
        assert_eq!(federated.silent, vec!["broken".to_owned()]);
        assert_eq!(federated.records.len(), 1);
    }
}
