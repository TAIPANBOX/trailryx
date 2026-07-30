//! Reference implementations, and deliberately broken ones.
//!
//! The correct ones exist so an adapter author has something to read, and so
//! the conformance suite is exercised against something.
//!
//! The broken ones exist for a stronger reason. A suite that has never failed
//! is a suite nobody has tested, so each of the two most dangerous guarantees,
//! atomic publication and permanent key destruction, has a plausible wrong
//! implementation here, and the tests assert that the suite catches it. They
//! are not strawmen: overwriting on put and forgetting that a key was destroyed
//! are exactly what a hurried adapter does.
//!
//! **No cryptography here.** [`MemoryKeyProvider`] wraps with a reversible
//! scramble so the contract can be exercised. Real key handling arrives in
//! stage 7 on a FIPS-validated module.

use crate::contracts::{
    Action, AdapterError, AdapterResult, Anchor, AnchorReceipt, AuthProvider, Decision, Delivery,
    Destroyed, ForeignColumn, ForeignTable, KeyId, KeyProvider, Lossiness, ObjectStore, Ordering,
    Peer, PeerDescriptor, PeerResponse, Principal, ProofStatus, PutOutcome, Sink, SinkDescriptor,
    Source, SourceDescriptor, Trust, VersionId,
};
use crate::ingest::{Cursor, Ingest};
use std::collections::{BTreeMap, BTreeSet};
use trailryx_record::{Hash, PrincipalId, Record, Timestamp};

// ---------------------------------------------------------------------------
// ObjectStore
// ---------------------------------------------------------------------------

/// Correct: refuses to overwrite.
///
/// `Clone` so a test can hand the same objects to a second vault, which is how
/// "a restart, or another node" is written without a filesystem.
#[derive(Debug, Default, Clone)]
pub struct MemoryObjectStore {
    objects: BTreeMap<String, Vec<u8>>,
}

impl ObjectStore for MemoryObjectStore {
    fn put_if_absent(
        &mut self,
        key: &str,
        bytes: &[u8],
    ) -> AdapterResult<(PutOutcome, Option<VersionId>)> {
        if self.objects.contains_key(key) {
            return Ok((PutOutcome::AlreadyExists, None));
        }
        self.objects.insert(key.to_owned(), bytes.to_vec());
        // No versioning, and it says so with `None` rather than inventing a token it
        // could not honour. A caller then knows this deployment cannot offer the
        // protection a version-pinned read gives.
        Ok((PutOutcome::Written, None))
    }

    fn get(&mut self, key: &str) -> AdapterResult<Option<Vec<u8>>> {
        Ok(self.objects.get(key).cloned())
    }

    fn get_version(&mut self, _key: &str, _version: &VersionId) -> AdapterResult<Option<Vec<u8>>> {
        Err(AdapterError::Unsupported(
            "this store does not version objects, so a version cannot be read back",
        ))
    }

    fn list(&mut self, prefix: &str) -> AdapterResult<Vec<String>> {
        Ok(self
            .objects
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

/// Broken on purpose: a plain `put`, as most storage APIs offer by default.
///
/// Two nodes sealing the same segment would each believe they published it, and
/// which bytes a reader gets would depend on timing. Every proof over that
/// segment inherits the ambiguity.
#[derive(Debug, Default)]
pub struct OverwritingObjectStore {
    objects: BTreeMap<String, Vec<u8>>,
}

impl ObjectStore for OverwritingObjectStore {
    fn put_if_absent(
        &mut self,
        key: &str,
        bytes: &[u8],
    ) -> AdapterResult<(PutOutcome, Option<VersionId>)> {
        self.objects.insert(key.to_owned(), bytes.to_vec());
        Ok((PutOutcome::Written, None))
    }

    fn get(&mut self, key: &str) -> AdapterResult<Option<Vec<u8>>> {
        Ok(self.objects.get(key).cloned())
    }

    fn get_version(&mut self, _key: &str, _version: &VersionId) -> AdapterResult<Option<Vec<u8>>> {
        Err(AdapterError::Unsupported("no versioning here either"))
    }

    fn list(&mut self, prefix: &str) -> AdapterResult<Vec<String>> {
        Ok(self
            .objects
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

/// A store that versions objects the way S3 does, so the attack can be run.
///
/// Modelled on what the S3 documentation actually says rather than on what Object Lock
/// is assumed to do:
///
/// - A `PUT` over an existing key **succeeds** and creates a new version. Retention
///   and legal holds do not prevent it.
/// - A plain read returns the **newest** version.
/// - A delete returns success and hides the object from a plain read, while every
///   earlier version remains.
/// - A read by version id returns that version regardless of any of the above.
///
/// `put_if_absent` still refuses a second publication, because that is what the
/// conditional write is for. What this fake exists to show is that refusing the
/// conditional write is **not enough**: an actor with credentials does not need
/// `put_if_absent`, they can write the key directly, and a reader that asks for the
/// key alone gets their bytes.
#[derive(Debug, Default, Clone)]
pub struct VersioningObjectStore {
    /// Every version ever written, oldest first, per key.
    versions: BTreeMap<String, Vec<(VersionId, Vec<u8>)>>,
    /// Keys hidden by a delete marker. The versions stay.
    deleted: BTreeSet<String>,
    next: u64,
}

impl VersioningObjectStore {
    /// Write a new version regardless of what is there, the way an administrator with
    /// credentials can, and the way Object Lock does not prevent.
    pub fn overwrite(&mut self, key: &str, bytes: &[u8]) -> VersionId {
        self.next += 1;
        let version = VersionId(format!("v{}", self.next));
        self.versions
            .entry(key.to_owned())
            .or_default()
            .push((version.clone(), bytes.to_vec()));
        self.deleted.remove(key);
        version
    }

    /// A simple `DELETE`: succeeds, hides the key from a plain read, and destroys
    /// nothing.
    pub fn delete_marker(&mut self, key: &str) {
        self.deleted.insert(key.to_owned());
    }

    pub fn version_count(&self, key: &str) -> usize {
        self.versions.get(key).map_or(0, Vec::len)
    }
}

impl ObjectStore for VersioningObjectStore {
    fn put_if_absent(
        &mut self,
        key: &str,
        bytes: &[u8],
    ) -> AdapterResult<(PutOutcome, Option<VersionId>)> {
        if self.versions.contains_key(key) {
            return Ok((PutOutcome::AlreadyExists, None));
        }
        let version = self.overwrite(key, bytes);
        Ok((PutOutcome::Written, Some(version)))
    }

    fn get(&mut self, key: &str) -> AdapterResult<Option<Vec<u8>>> {
        if self.deleted.contains(key) {
            return Ok(None);
        }
        Ok(self
            .versions
            .get(key)
            .and_then(|v| v.last())
            .map(|(_, bytes)| bytes.clone()))
    }

    fn get_version(&mut self, key: &str, version: &VersionId) -> AdapterResult<Option<Vec<u8>>> {
        // A delete marker does not reach a version, which is the entire point.
        Ok(self.versions.get(key).and_then(|versions| {
            versions
                .iter()
                .find(|(id, _)| id == version)
                .map(|(_, bytes)| bytes.clone())
        }))
    }

    fn list(&mut self, prefix: &str) -> AdapterResult<Vec<String>> {
        Ok(self
            .versions
            .keys()
            .filter(|k| k.starts_with(prefix) && !self.deleted.contains(*k))
            .cloned()
            .collect())
    }
}

// ---------------------------------------------------------------------------
// KeyProvider
// ---------------------------------------------------------------------------

fn scramble(kek: KeyId, data: &[u8]) -> Vec<u8> {
    let k = kek.0.as_bytes();
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ k[i % k.len()] ^ 0x5a)
        .collect()
}

/// Correct: a destroyed key stays destroyed, and its id is never reused.
#[derive(Debug, Default)]
pub struct MemoryKeyProvider {
    live: BTreeSet<KeyId>,
    tombstones: BTreeSet<KeyId>,
}

impl KeyProvider for MemoryKeyProvider {
    fn wrap(&mut self, kek: KeyId, dek: &[u8]) -> AdapterResult<Vec<u8>> {
        if self.tombstones.contains(&kek) {
            return Err(AdapterError::Rejected("key id was destroyed"));
        }
        self.live.insert(kek);
        Ok(scramble(kek, dek))
    }

    fn unwrap(&mut self, kek: KeyId, wrapped: &[u8]) -> AdapterResult<Vec<u8>> {
        if !self.live.contains(&kek) {
            return Err(AdapterError::Rejected("no such key"));
        }
        Ok(scramble(kek, wrapped))
    }

    fn destroy(&mut self, kek: KeyId) -> AdapterResult<Destroyed> {
        let existed = self.live.remove(&kek);
        self.tombstones.insert(kek);
        Ok(if existed {
            Destroyed::Now
        } else {
            Destroyed::Already
        })
    }

    fn exists(&self, kek: KeyId) -> bool {
        self.live.contains(&kek)
    }
}

/// A custodian that **schedules** destruction, the way every real one does.
///
/// AWS KMS waits 7 to 30 days, GCP Cloud KMS 30 by default, and both let an
/// operator cancel during the window; see [`Destroyed::Scheduled`] for the
/// citations. This models that: `destroy` schedules, the key becomes unusable at
/// once, the material stays until `elapse` is called, and `cancel` brings it back
/// exactly as `CancelKeyDeletion` and `CryptoKeyVersions.restore` do.
///
/// It exists because a seam nobody ran is a seam nobody checked, and because the
/// interesting behaviour is not the happy path: it is that a caller must not report
/// erasure while a schedule is open. `trailryx-erasure` has a test that cancels a
/// schedule and confirms the payload comes back, which is the fact a controller has
/// to be prevented from hiding.
#[derive(Debug)]
pub struct SchedulingKeyProvider {
    live: BTreeSet<KeyId>,
    /// Scheduled, with the moment the custodian named. Still holding material.
    pending: BTreeMap<KeyId, Timestamp>,
    tombstones: BTreeSet<KeyId>,
    /// How far ahead this custodian schedules, in nanoseconds. A real one is days;
    /// a test needs a number it can reason about.
    window_nanos: u64,
    /// The custodian's clock, injected, because nothing in this workspace reads
    /// one for itself.
    now: Timestamp,
    /// Whether this custodian will undo a schedule. Both named providers will.
    reversible: bool,
}

impl SchedulingKeyProvider {
    pub fn new(now: Timestamp, window_nanos: u64) -> Self {
        Self {
            live: BTreeSet::new(),
            pending: BTreeMap::new(),
            tombstones: BTreeSet::new(),
            window_nanos,
            now,
            reversible: true,
        }
    }

    /// A custodian whose scheduling is one way, for a caller that wants to know
    /// the difference matters.
    pub fn irreversible(mut self) -> Self {
        self.reversible = false;
        self
    }

    pub fn advance_to(&mut self, now: Timestamp) {
        self.now = now;
    }

    /// The window closes: everything due is shredded for good.
    pub fn elapse(&mut self) -> usize {
        let due: Vec<KeyId> = self
            .pending
            .iter()
            .filter(|(_, at)| at.as_nanos() <= self.now.as_nanos())
            .map(|(k, _)| *k)
            .collect();
        for key in &due {
            self.pending.remove(key);
            self.tombstones.insert(*key);
        }
        due.len()
    }

    /// `CancelKeyDeletion`. The key comes back and every payload under it becomes
    /// readable again, which is the whole reason a scheduled destruction is not an
    /// erasure.
    pub fn cancel(&mut self, kek: KeyId) -> bool {
        if !self.reversible {
            return false;
        }
        if self.pending.remove(&kek).is_some() {
            self.live.insert(kek);
            return true;
        }
        false
    }

    pub fn scheduled_count(&self) -> usize {
        self.pending.len()
    }
}

impl KeyProvider for SchedulingKeyProvider {
    fn wrap(&mut self, kek: KeyId, dek: &[u8]) -> AdapterResult<Vec<u8>> {
        // A scheduled key is unusable, and a shredded one is gone. Neither may be
        // wrapped under: doing so would resurrect an id.
        if self.tombstones.contains(&kek) || self.pending.contains_key(&kek) {
            return Err(AdapterError::Rejected("key id is destroyed or scheduled"));
        }
        self.live.insert(kek);
        Ok(scramble(kek, dek))
    }

    fn unwrap(&mut self, kek: KeyId, wrapped: &[u8]) -> AdapterResult<Vec<u8>> {
        // The material still exists during the window and the custodian still
        // refuses to use it. That is what both providers document, and it is why
        // the contract's guarantee is "fails from now on" rather than "forever".
        if !self.live.contains(&kek) {
            return Err(AdapterError::Rejected("no such key"));
        }
        Ok(scramble(kek, wrapped))
    }

    fn destroy(&mut self, kek: KeyId) -> AdapterResult<Destroyed> {
        if self.tombstones.contains(&kek) {
            return Ok(Destroyed::Already);
        }
        // A second call must not move the date. An erasure job retries, and a
        // custodian that restarted its clock on every retry would schedule an
        // erasure that never lands.
        if let Some(at) = self.pending.get(&kek) {
            return Ok(Destroyed::Scheduled {
                effective_at: *at,
                reversible: self.reversible,
            });
        }
        if !self.live.remove(&kek) {
            return Ok(Destroyed::Already);
        }
        let at = Timestamp(self.now.as_nanos().saturating_add(self.window_nanos));
        self.pending.insert(kek, at);
        Ok(Destroyed::Scheduled {
            effective_at: at,
            reversible: self.reversible,
        })
    }

    fn exists(&self, kek: KeyId) -> bool {
        // "Can this be used", not "has the material been shredded". A scheduled key
        // answers no, and that is the honest answer to the question asked.
        self.live.contains(&kek)
    }
}

/// Broken on purpose: keeps no tombstone, so wrapping under a destroyed id
/// brings the key back and every payload under it becomes readable again.
///
/// This is what "erased" quietly becomes when a provider treats destruction as
/// a delete from a map.
#[derive(Debug, Default)]
pub struct ResurrectingKeyProvider {
    live: BTreeSet<KeyId>,
}

impl KeyProvider for ResurrectingKeyProvider {
    fn wrap(&mut self, kek: KeyId, dek: &[u8]) -> AdapterResult<Vec<u8>> {
        self.live.insert(kek);
        Ok(scramble(kek, dek))
    }

    fn unwrap(&mut self, kek: KeyId, wrapped: &[u8]) -> AdapterResult<Vec<u8>> {
        if !self.live.contains(&kek) {
            return Err(AdapterError::Rejected("no such key"));
        }
        Ok(scramble(kek, wrapped))
    }

    fn destroy(&mut self, kek: KeyId) -> AdapterResult<Destroyed> {
        Ok(if self.live.remove(&kek) {
            Destroyed::Now
        } else {
            Destroyed::Already
        })
    }

    fn exists(&self, kek: KeyId) -> bool {
        self.live.contains(&kek)
    }
}

// ---------------------------------------------------------------------------
// Source and Sink
// ---------------------------------------------------------------------------

/// Correct: declares an untrusted clock, acknowledges idempotently.
#[derive(Debug, Default)]
pub struct NullSource {
    acked: Cursor,
}

impl Source for NullSource {
    fn descriptor(&self) -> SourceDescriptor {
        SourceDescriptor {
            name: "null",
            clock_trust: Trust::Untrusted,
            identity_trust: Trust::Untrusted,
            delivery: Delivery::AtLeastOnce,
            ordering: Ordering::Unordered,
        }
    }

    fn poll(&mut self, _budget: usize) -> AdapterResult<Vec<Ingest>> {
        Ok(Vec::new())
    }

    fn ack(&mut self, cursor: Cursor) -> AdapterResult<()> {
        // Older cursors are a no-op, never a rewind.
        self.acked = self.acked.max(cursor);
        Ok(())
    }
}

/// Broken on purpose: claims its own clock can be trusted, which would switch
/// off skew detection for everything it sends.
#[derive(Debug, Default)]
pub struct SelfCertifyingSource;

impl Source for SelfCertifyingSource {
    fn descriptor(&self) -> SourceDescriptor {
        SourceDescriptor {
            name: "self-certifying",
            clock_trust: Trust::Trusted,
            identity_trust: Trust::Trusted,
            delivery: Delivery::ExactlyOnce,
            ordering: Ordering::Unordered,
        }
    }

    fn poll(&mut self, _budget: usize) -> AdapterResult<Vec<Ingest>> {
        Ok(Vec::new())
    }

    fn ack(&mut self, _cursor: Cursor) -> AdapterResult<()> {
        Ok(())
    }
}

/// Correct: says exactly what it drops.
#[derive(Debug, Default)]
pub struct CountingSink {
    pub emitted: usize,
}

impl Sink for CountingSink {
    fn descriptor(&self) -> SinkDescriptor {
        SinkDescriptor {
            name: "counting",
            lossiness: Lossiness::Lossy {
                drops: &["basis", "caused_by", "payload"],
            },
            carries_payload: false,
        }
    }

    fn emit(&mut self, batch: &[Record]) -> AdapterResult<()> {
        self.emitted += batch.len();
        Ok(())
    }

    fn flush(&mut self) -> AdapterResult<()> {
        Ok(())
    }
}

/// Broken on purpose: declares itself lossy without naming anything, which
/// tells an operator nothing while looking like a disclosure.
#[derive(Debug, Default)]
pub struct VaguelyLossySink;

impl Sink for VaguelyLossySink {
    fn descriptor(&self) -> SinkDescriptor {
        SinkDescriptor {
            name: "vague",
            lossiness: Lossiness::Lossy { drops: &[] },
            carries_payload: false,
        }
    }

    fn emit(&mut self, _batch: &[Record]) -> AdapterResult<()> {
        Ok(())
    }

    fn flush(&mut self) -> AdapterResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Anchor, auth, peer, foreign
// ---------------------------------------------------------------------------

/// Correct: the receipt is bound to its root.
#[derive(Debug, Default)]
pub struct EchoAnchor {
    pub submissions: usize,
}

impl Anchor for EchoAnchor {
    fn submit(&mut self, root: Hash) -> AdapterResult<AnchorReceipt> {
        self.submissions += 1;
        Ok(AnchorReceipt {
            root,
            at: Timestamp(1_800_000_000_000_000_000),
            evidence: root.as_bytes().to_vec(),
        })
    }

    fn verify(&self, root: Hash, receipt: &AnchorReceipt) -> AdapterResult<bool> {
        Ok(receipt.root == root && receipt.evidence == root.as_bytes())
    }
}

/// Broken on purpose: verifies anything, so it proves nothing.
#[derive(Debug, Default)]
pub struct LenientAnchor;

impl Anchor for LenientAnchor {
    fn submit(&mut self, root: Hash) -> AdapterResult<AnchorReceipt> {
        Ok(AnchorReceipt {
            root,
            at: Timestamp(0),
            evidence: Vec::new(),
        })
    }

    fn verify(&self, _root: Hash, _receipt: &AnchorReceipt) -> AdapterResult<bool> {
        Ok(true)
    }
}

/// Correct: denies by default, separates payload access from metadata access.
#[derive(Debug, Default)]
pub struct StaticAuth;

impl AuthProvider for StaticAuth {
    fn authenticate(&mut self, credential: &[u8]) -> AdapterResult<Principal> {
        if credential.is_empty() {
            return Err(AdapterError::Rejected("empty credential"));
        }
        Ok(Principal {
            id: PrincipalId::parse("user://auditor")
                .map_err(|_| AdapterError::Rejected("built-in principal id is malformed"))?,
            via: "static",
        })
    }

    fn authorize(&mut self, _principal: &Principal, action: Action, scope: &str) -> Decision {
        if scope != "tenant-a" {
            return Decision::Deny;
        }
        match action {
            Action::ReadMetadata | Action::Query | Action::ProduceEvidence => Decision::Allow,
            // Reading the trail and reading the prompts in it are different
            // permissions. So is writing to it: this principal is an auditor,
            // and an auditor who can also write is not an auditor.
            Action::ReadPayload | Action::Erase | Action::Administer | Action::Ingest => {
                Decision::Deny
            }
        }
    }
}

/// Correct: attested, so it may claim a full proof.
#[derive(Debug, Default)]
pub struct LocalPeer;

impl Peer for LocalPeer {
    fn descriptor(&self) -> PeerDescriptor {
        PeerDescriptor {
            name: "local",
            attested: true,
        }
    }

    fn query(&mut self, _predicate: &str) -> AdapterResult<PeerResponse> {
        Ok(PeerResponse {
            records: Vec::new(),
            proof: ProofStatus::Full,
        })
    }
}

/// Broken on purpose: outside the signed registry, yet claims a full proof.
/// Forgetting one such node would shrink an answer without anyone noticing.
#[derive(Debug, Default)]
pub struct OverconfidentPeer;

impl Peer for OverconfidentPeer {
    fn descriptor(&self) -> PeerDescriptor {
        PeerDescriptor {
            name: "overconfident",
            attested: false,
        }
    }

    fn query(&mut self, _predicate: &str) -> AdapterResult<PeerResponse> {
        Ok(PeerResponse {
            records: Vec::new(),
            proof: ProofStatus::Full,
        })
    }
}

/// Correct: foreign data, and it says so.
#[derive(Debug, Default)]
pub struct StaticForeignTable;

impl ForeignTable for StaticForeignTable {
    fn name(&self) -> &str {
        "crm_accounts"
    }

    fn columns(&self) -> &[ForeignColumn] {
        &[
            ForeignColumn {
                name: "account_id",
                sql_type: "text",
            },
            ForeignColumn {
                name: "tier",
                sql_type: "text",
            },
        ]
    }

    fn scan(&mut self, _predicate: &str) -> AdapterResult<Vec<Vec<String>>> {
        Ok(Vec::new())
    }
}

/// Broken on purpose: claims foreign rows can be covered by a proof.
#[derive(Debug, Default)]
pub struct ProvableForeignTable;

impl ForeignTable for ProvableForeignTable {
    fn name(&self) -> &str {
        "wishful"
    }

    fn columns(&self) -> &[ForeignColumn] {
        &[ForeignColumn {
            name: "x",
            sql_type: "text",
        }]
    }

    fn scan(&mut self, _predicate: &str) -> AdapterResult<Vec<Vec<String>>> {
        Ok(Vec::new())
    }

    fn provable(&self) -> bool {
        true
    }
}
