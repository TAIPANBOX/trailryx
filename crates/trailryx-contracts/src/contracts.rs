//! The eight L1 contracts.
//!
//! Breadth comes from adapters, and adapters are only safe if the interface
//! they implement cannot be used to weaken a core guarantee. Each trait here
//! carries the guarantee it must preserve in its doc comment, and each has a
//! matching suite in [`crate::conformance`] that tries to catch it failing.
//!
//! Frozen at the end of stage 1. Adding a method later is a breaking change for
//! every adapter, so the shape is chosen now, deliberately, and left alone.

use crate::ingest::{Cursor, Ingest};
use trailryx_record::{Hash, PrincipalId, Record, Timestamp};

// ---------------------------------------------------------------------------
// Shared vocabulary
// ---------------------------------------------------------------------------

/// Whether something an adapter tells us can be believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// We produced it, or the adapter proves it cryptographically.
    Trusted,
    /// We were told. Recorded as such, never promoted silently.
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    AtMostOnce,
    AtLeastOnce,
    ExactlyOnce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ordering {
    /// Items arrive in the order the emitter produced them.
    Ordered,
    /// They do not, and a subagent's events can arrive after its parent's.
    Unordered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    Unavailable(&'static str),
    Rejected(&'static str),
    /// The adapter cannot honour the contract for this call. Distinct from a
    /// transient failure: it will not succeed on retry.
    Unsupported(&'static str),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(s) => write!(f, "unavailable: {s}"),
            Self::Rejected(s) => write!(f, "rejected: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}

impl std::error::Error for AdapterError {}

pub type AdapterResult<T> = Result<T, AdapterError>;

// ---------------------------------------------------------------------------
// 1. Source
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceDescriptor {
    pub name: &'static str,
    /// Can we believe the timestamps this source attaches?
    pub clock_trust: Trust,
    /// Can we believe the identities it claims?
    pub identity_trust: Trust,
    pub delivery: Delivery,
    pub ordering: Ordering,
}

/// Brings events in from somewhere else.
///
/// **Guarantee to preserve:** a source declares honestly what it can and cannot
/// vouch for. Nothing downstream upgrades an untrusted clock or identity; the
/// declaration is how the store knows to record disagreement rather than paper
/// over it.
pub trait Source {
    fn descriptor(&self) -> SourceDescriptor;

    /// Hand over at most `budget` items. Fewer is always allowed.
    fn poll(&mut self, budget: usize) -> AdapterResult<Vec<Ingest>>;

    /// Everything up to and including `cursor` is durably ours now.
    ///
    /// Must be idempotent: the same cursor twice is not an error, and a cursor
    /// older than one already acknowledged is a no-op, never a rewind.
    fn ack(&mut self, cursor: Cursor) -> AdapterResult<()>;
}

// ---------------------------------------------------------------------------
// 2. Sink
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lossiness {
    /// Everything in the record survives the trip.
    Lossless,
    /// Some fields do not. They are named, so an operator can see what a
    /// downstream copy will be missing before relying on it as evidence.
    Lossy { drops: &'static [&'static str] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkDescriptor {
    pub name: &'static str,
    pub lossiness: Lossiness,
    /// Whether this sink transports decrypted payload content.
    ///
    /// Declaring it is not a formality: a sink that ships prompts to a SIEM
    /// moves personal data outside the erasure boundary, and an operator has to
    /// be able to see that from the configuration rather than discover it.
    pub carries_payload: bool,
}

/// Sends data somewhere else.
///
/// **Guarantee to preserve:** a lossy sink says so and enumerates what it drops.
/// Silent loss downstream turns a copy into something that looks like evidence
/// and is not.
pub trait Sink {
    fn descriptor(&self) -> SinkDescriptor;
    fn emit(&mut self, batch: &[Record]) -> AdapterResult<()>;
    fn flush(&mut self) -> AdapterResult<()>;
}

// ---------------------------------------------------------------------------
// 3. ObjectStore
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Written,
    /// The key already existed. The caller lost the race and the stored bytes
    /// are somebody else's.
    AlreadyExists,
}

/// Cold storage for sealed segments.
///
/// **Guarantee to preserve:** [`ObjectStore::put_if_absent`] is atomic. That
/// single conditional write is what lets a segment be published without any
/// coordinator: no etcd, no Consul, no lock service. S3 gives it via
/// `If-None-Match`, GCS via `ifGenerationMatch`, Azure via ETag preconditions,
/// a filesystem via `rename` within one volume.
///
/// An implementation that overwrites instead would let two nodes publish
/// different bytes under one name, and every proof built on that segment would
/// depend on which one you happened to read.
pub trait ObjectStore {
    fn put_if_absent(&mut self, key: &str, bytes: &[u8]) -> AdapterResult<PutOutcome>;
    fn get(&mut self, key: &str) -> AdapterResult<Option<Vec<u8>>>;
    fn list(&mut self, prefix: &str) -> AdapterResult<Vec<String>>;
}

// ---------------------------------------------------------------------------
// 4. KeyProvider
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub Hash);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destroyed {
    /// The key existed and is now gone.
    Now,
    /// It was already gone. Destroying twice is not an error.
    Already,
}

/// Custody of the keys that make erasure real.
///
/// **Guarantee to preserve:** after [`KeyProvider::destroy`], `unwrap` for that
/// key fails forever, and a key id is never reissued. Erasure in this system is
/// the destruction of a key, so a provider that can resurrect one has quietly
/// turned "erased" into "hidden".
pub trait KeyProvider {
    /// Wrap a data key under a key-encryption key.
    fn wrap(&mut self, kek: KeyId, dek: &[u8]) -> AdapterResult<Vec<u8>>;
    fn unwrap(&mut self, kek: KeyId, wrapped: &[u8]) -> AdapterResult<Vec<u8>>;
    fn destroy(&mut self, kek: KeyId) -> AdapterResult<Destroyed>;
    fn exists(&self, kek: KeyId) -> bool;
}

// ---------------------------------------------------------------------------
// 5. Anchor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReceipt {
    pub root: Hash,
    pub at: Timestamp,
    pub evidence: Vec<u8>,
}

/// Fixes a root in time somewhere we do not control.
///
/// **Guarantee to preserve:** a receipt verifies for its own root and for no
/// other. Anchoring is the defence against back-dated forgery, and a receipt
/// that verifies loosely defends against nothing.
pub trait Anchor {
    fn submit(&mut self, root: Hash) -> AdapterResult<AnchorReceipt>;
    fn verify(&self, root: Hash, receipt: &AnchorReceipt) -> AdapterResult<bool>;
}

// ---------------------------------------------------------------------------
// 6. AuthProvider
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: PrincipalId,
    pub via: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    ReadMetadata,
    ReadPayload,
    Query,
    ProduceEvidence,
    Erase,
    Administer,
    /// Writing records in. Its own action rather than a reader's or an
    /// administrator's.
    ///
    /// Added when the ingest server needed it, and worth the breaking change:
    /// the alternative was every agent shipping telemetry holding a permission
    /// that also lets it erase people, which is not a permission an agent
    /// should be able to lose control of.
    Ingest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Who is asking, and what they may do.
///
/// **Guarantee to preserve:** deny by default, and decide deterministically.
/// Reading payload is a separate action from reading metadata on purpose:
/// most people who need the audit trail have no business reading the prompts
/// inside it.
pub trait AuthProvider {
    fn authenticate(&mut self, credential: &[u8]) -> AdapterResult<Principal>;
    fn authorize(&mut self, principal: &Principal, action: Action, scope: &str) -> Decision;
}

// ---------------------------------------------------------------------------
// 7. Peer
// ---------------------------------------------------------------------------

/// How much of an answer is actually proved.
///
/// Carried on every response, federated or local, because an answer whose
/// completeness is unknown must not be mistaken for one that is proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofStatus {
    /// Every predicate fell on a provable dimension and the proof checks out.
    Full,
    /// Some did not, or a member of the set could not be reached.
    Partial(&'static str),
    /// No proof was attempted.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerDescriptor {
    pub name: &'static str,
    /// Whether this peer is a member of the signed peer registry.
    ///
    /// Without an attested set, "here is everything" cannot be said honestly:
    /// forgetting one node would silently shrink the answer.
    pub attested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerResponse {
    pub records: Vec<Record>,
    pub proof: ProofStatus,
}

/// Another Trailryx node, in another environment.
///
/// **Guarantee to preserve:** an unattested peer never returns
/// [`ProofStatus::Full`]. The composition rule is the same one used between
/// shards inside a single node, which is why it is written once.
pub trait Peer {
    fn descriptor(&self) -> PeerDescriptor;
    fn query(&mut self, predicate: &str) -> AdapterResult<PeerResponse>;
}

// ---------------------------------------------------------------------------
// 8. ForeignTable
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForeignColumn {
    pub name: &'static str,
    pub sql_type: &'static str,
}

/// Somebody else's data, joinable from our SQL surface.
///
/// **Guarantee to preserve:** foreign rows are never provable. They did not come
/// from our journal, so a completeness proof cannot cover them, and any query
/// touching one comes back [`ProofStatus::Partial`]. Wired to DataFusion in
/// stage 10; declared now so the proof-status rule is designed in rather than
/// discovered later.
pub trait ForeignTable {
    fn name(&self) -> &str;
    fn columns(&self) -> &[ForeignColumn];
    fn scan(&mut self, predicate: &str) -> AdapterResult<Vec<Vec<String>>>;

    /// Always false. Provided as a method rather than a comment so an
    /// implementation that overrides it is visibly doing something wrong.
    fn provable(&self) -> bool {
        false
    }
}
