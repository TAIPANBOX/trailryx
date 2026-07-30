//! Sealing payloads, opening them, and making them unreachable.
//!
//! # Erasure without deletion
//!
//! Nothing here deletes anything. [`trailryx_contracts::contracts::ObjectStore`]
//! has no delete method and that is not an omission: the payload surface is the
//! large one, the replicated one, the backed-up one, often the write-once one,
//! and a design that needs to delete from it will fail quietly the first time a
//! backup is restored.
//!
//! So the ciphertext stays forever and the key does not. After
//! [`Vault::forget`] the bytes are still in the object store, still in every
//! replica, still in every backup, and unreadable in all of them. That is the
//! only version of erasure that is true rather than administrative.
//!
//! # What survives, and why the chain still verifies
//!
//! A record commits to its payload by hash, size, class and key id. It does not
//! contain the payload. Destroying the key changes none of those four fields,
//! so every hash chain, every Merkle root and every proof issued before the
//! erasure still verifies afterwards, unchanged.
//!
//! That is the property the whole product turns on, and it is tested rather
//! than asserted: seal, prove, erase, prove again.

use crate::aead::{Aead, KeySource};
use crate::envelope::{Envelope, EnvelopeError, associated_data};
use crate::subject::{KeyLedger, SubjectHandle, kek_for_record, kek_for_subject};
use trailryx_contracts::contracts::{
    AdapterError, Destroyed, KeyId, KeyProvider, ObjectStore, PutOutcome,
};
use trailryx_contracts::ingest::{MetaDraft, PayloadPart};
use trailryx_crypto::Sha384;
use trailryx_record::{
    AgentId, Basis, EventType, Hash, MapperVersion, PayloadClass, PayloadRef, RecordId, RunId,
    Severity, TenantId, Timestamp, Untrusted, Verdict,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// The primitives are not fit for a deployment. See [`Vault::unvalidated`].
    Unvalidated(&'static str),
    Adapter(AdapterError),
    Envelope(EnvelopeError),
    /// Nothing under that key. Not the same as erased: an erased payload has an
    /// envelope and no key.
    Missing,
    /// The envelope names a different key than the record does, so the object
    /// was replaced with another record's.
    WrongKey,
    /// It opened, and to something other than what the record commits to.
    WrongContent,
    /// The key is gone. This is what a successful erasure looks like from here.
    Erased,
    /// A manifest already exists under its own content hash and does not hash to
    /// it. Either the store is not content-addressing what we asked it to, or
    /// something replaced the evidence.
    ManifestMismatch,
    Malformed(&'static str),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unvalidated(what) => write!(f, "{what} is not a validated implementation"),
            Self::Adapter(e) => write!(f, "{e}"),
            Self::Envelope(e) => write!(f, "{e}"),
            Self::Missing => write!(f, "no envelope stored"),
            Self::WrongKey => write!(f, "the envelope belongs to a different record"),
            Self::WrongContent => write!(f, "the payload is not what the record commits to"),
            Self::ManifestMismatch => {
                write!(f, "a stored erasure manifest does not hash to its own name")
            }
            Self::Erased => write!(f, "the key was destroyed"),
            Self::Malformed(what) => write!(f, "malformed payload blob: {what}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<AdapterError> for VaultError {
    fn from(e: AdapterError) -> Self {
        Self::Adapter(e)
    }
}

impl From<EnvelopeError> for VaultError {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

/// How restrictive a class is, most restrictive first.
///
/// A blob of several parts takes the class of its most restrictive one, because
/// access is decided from that single field and the alternative is deciding
/// access from the least sensitive thing in the blob.
///
/// The order is a judgement and worth stating as one: what the person wrote,
/// then what was generated about them, then what was derived from what they
/// wrote, then what was fetched about them, then what was retrieved, then our
/// own notes.
fn restrictiveness(class: PayloadClass) -> u8 {
    match class {
        PayloadClass::Prompt => 0,
        PayloadClass::Completion => 1,
        PayloadClass::ToolArguments => 2,
        PayloadClass::ToolResult => 3,
        PayloadClass::Document => 4,
        PayloadClass::Diagnostic => 5,
    }
}

/// Several classified parts as one blob, so one record has one payload.
///
/// The classes travel inside the blob rather than beside it, so opening it
/// returns the parts exactly as they were handed over. The record's own class
/// is the most restrictive of them.
pub fn encode_parts(parts: &[PayloadPart]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"TRXB\x01");
    out.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    for part in parts {
        let name = part.class.as_str().as_bytes();
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out.extend_from_slice(&(part.bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&part.bytes);
    }
    out
}

pub fn decode_parts(blob: &[u8]) -> Result<Vec<PayloadPart>, VaultError> {
    let mut at = 0usize;
    let mut take = |n: usize| -> Result<&[u8], VaultError> {
        let end = at.checked_add(n).ok_or(VaultError::Malformed("length"))?;
        let slice = blob
            .get(at..end)
            .ok_or(VaultError::Malformed("truncated"))?;
        at = end;
        Ok(slice)
    };
    if take(5)? != b"TRXB\x01" {
        return Err(VaultError::Malformed("not a payload blob"));
    }
    let mut count = [0u8; 4];
    count.copy_from_slice(take(4)?);
    let count = u32::from_le_bytes(count) as usize;

    let mut parts = Vec::new();
    for _ in 0..count {
        let name_len = usize::from(take(1)?[0]);
        let name = std::str::from_utf8(take(name_len)?)
            .map_err(|_| VaultError::Malformed("class name"))?
            .to_owned();
        let class = PayloadClass::ALL
            .iter()
            .copied()
            .find(|c| c.as_str() == name)
            .ok_or(VaultError::Malformed("unknown class"))?;
        let mut len = [0u8; 8];
        len.copy_from_slice(take(8)?);
        let len = usize::try_from(u64::from_le_bytes(len))
            .map_err(|_| VaultError::Malformed("part length"))?;
        parts.push(PayloadPart::new(class, take(len)?.to_vec()));
    }
    Ok(parts)
}

/// What a [`Vault::forget`] actually did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forgotten {
    pub keys_destroyed: u32,
    /// Keys already gone. Erasing twice is not an error and not a lie either.
    pub keys_already_gone: u32,
    pub manifest: Hash,
    pub manifest_size: u64,
    /// The subject's own key id, which is what an auditor holding the handle
    /// recomputes to check this erasure was the one they asked for.
    ///
    /// Returned to the caller, who already holds the handle, and never written
    /// into a record: see the note on `memory_ref` in `erasure_draft`.
    pub subject_key: KeyId,
    /// What the erasure record carries instead: a hash of `subject_key`, so the
    /// record is findable by a handle holder and useless to everybody else.
    pub tag: Hash,
    pub draft: MetaDraft,
}

/// Payload custody: seal, open, attribute, forget.
#[derive(Debug)]
pub struct Vault<O, K, A, S> {
    tenant: TenantId,
    trust_domain: String,
    store: O,
    provider: K,
    aead: A,
    keys: S,
    ledger: KeyLedger,
    erasures: u64,
}

impl<O: ObjectStore, K: KeyProvider, A: Aead, S: KeySource> Vault<O, K, A, S> {
    /// Refuses anything that is not fit for a deployment.
    pub fn new(
        tenant: TenantId,
        trust_domain: &str,
        store: O,
        provider: K,
        aead: A,
        keys: S,
    ) -> Result<Self, VaultError> {
        if !aead.is_validated() {
            return Err(VaultError::Unvalidated("the cipher"));
        }
        if !keys.is_validated() {
            return Err(VaultError::Unvalidated("the key source"));
        }
        Ok(Self::unvalidated(
            tenant,
            trust_domain,
            store,
            provider,
            aead,
            keys,
        ))
    }

    /// The same thing without the check.
    ///
    /// Named so that a reviewer reading the line knows what is wrong with it.
    /// Tests use this; a deployment using it is a deployment whose payloads are
    /// protected by something nobody certified.
    pub fn unvalidated(
        tenant: TenantId,
        trust_domain: &str,
        store: O,
        provider: K,
        aead: A,
        keys: S,
    ) -> Self {
        Self {
            tenant,
            trust_domain: trust_domain.to_owned(),
            store,
            provider,
            aead,
            keys,
            ledger: KeyLedger::new(),
            erasures: 0,
        }
    }

    fn object_key(&self, record: RecordId) -> String {
        format!("payload/{}/{:032x}", self.tenant.as_str(), record.0)
    }

    /// Encrypt a record's payload and store it.
    ///
    /// Always under a key belonging to this record and to nobody. A subject, if
    /// one is known now, gets that key added to their set, which is the same
    /// thing attribution does later.
    ///
    /// It used to seal under the subject's own key when the subject was known at
    /// write time, and that put the subject into the metadata plane: `key_id` is
    /// a cleartext field on every record, so every record about one person
    /// carried one identical value and the whole store grouped by subject for
    /// anybody who could read metadata. A per-record key cannot do that, and it
    /// costs nothing, because forgetting works off the ledger row either way.
    pub fn seal(
        &mut self,
        record: RecordId,
        parts: &[PayloadPart],
        subject: Option<&SubjectHandle>,
    ) -> Result<PayloadRef, VaultError> {
        let blob = encode_parts(parts);
        let hash = Sha384::digest(&blob);
        let class = parts
            .iter()
            .map(|p| p.class)
            .min_by_key(|c| restrictiveness(*c))
            .unwrap_or(PayloadClass::Diagnostic);

        let kek = kek_for_record(&self.tenant, record);
        if let Some(s) = subject {
            // Registered at seal time, not at erasure time. A key nobody
            // recorded is a key nobody destroys.
            self.ledger.attribute(s, kek);
        }

        let dek = self.keys.fresh_dek();
        let nonce = self.keys.fresh_nonce();
        let aad = associated_data(record, class, hash, kek);
        let ciphertext = self.aead.seal(&dek, &nonce, &aad, &blob);
        let wrapped_dek = self.provider.wrap(kek, dek.as_bytes())?;

        let envelope = Envelope {
            kek,
            nonce,
            wrapped_dek,
            ciphertext,
        };
        self.store
            .put_if_absent(&self.object_key(record), &envelope.encode())?;

        Ok(PayloadRef {
            hash,
            size_bytes: blob.len() as u64,
            class,
            key_id: kek.0,
        })
    }

    /// Get a payload back, or find out why not.
    pub fn open(
        &mut self,
        record: RecordId,
        reference: &PayloadRef,
    ) -> Result<Vec<PayloadPart>, VaultError> {
        let bytes = self
            .store
            .get(&self.object_key(record))?
            .ok_or(VaultError::Missing)?;
        let envelope = Envelope::decode(&bytes)?;

        // The record says which key. If the stored envelope says another, the
        // object was replaced, and going on would open somebody else's payload
        // under this record's name.
        if envelope.kek.0 != reference.key_id {
            return Err(VaultError::WrongKey);
        }
        if !self.provider.exists(envelope.kek) {
            return Err(VaultError::Erased);
        }

        let dek = self
            .provider
            .unwrap(envelope.kek, &envelope.wrapped_dek)
            .map_err(|_| VaultError::Erased)?;
        if dek.len() != crate::aead::KEY_BYTES {
            return Err(VaultError::Malformed("wrapped key is the wrong size"));
        }
        let mut key = [0u8; crate::aead::KEY_BYTES];
        key.copy_from_slice(&dek);
        let dek = crate::aead::Dek::new(key);

        let aad = associated_data(record, reference.class, reference.hash, envelope.kek);
        let blob = self
            .aead
            .open(&dek, &envelope.nonce, &aad, &envelope.ciphertext)
            .ok_or(VaultError::WrongContent)?;

        // The record commits to the plaintext hash. Checking it here means a
        // payload that opens to the wrong bytes is caught even if the cipher
        // somehow accepted it.
        if Sha384::digest(&blob) != reference.hash {
            return Err(VaultError::WrongContent);
        }
        decode_parts(&blob)
    }

    /// Say that a payload turned out to be about somebody.
    ///
    /// Adds its key to the subject's set. Nothing is re-encrypted and nothing
    /// is rewritten, which is the whole reason this design works: there is no
    /// old copy left behind for a restored backup to expose.
    pub fn attribute(&mut self, reference: &PayloadRef, subject: &SubjectHandle) -> bool {
        self.ledger.attribute(subject, KeyId(reference.key_id))
    }

    /// Destroy every key that opens anything about this subject.
    ///
    /// Idempotent. A second call finds nothing left and says so rather than
    /// failing, because a controller re-running an erasure job must not be
    /// punished for it.
    pub fn forget(
        &mut self,
        subject: &SubjectHandle,
        recorded_at: Timestamp,
    ) -> Result<Forgotten, VaultError> {
        let subject_key = kek_for_subject(&self.tenant, subject);
        // Read the row; do not drop it yet. `KeyLedger::drop_subject` documents
        // the rule verbatim, and this function used to break it: the row went
        // first, then the destroy loop, so one `Unavailable` from a KMS halfway
        // through left the surviving keys with nothing anywhere recording that
        // they must die. The retry every erasure job performs then found an
        // empty row and wrote "we hold nothing about this person" while three of
        // four payloads were still readable.
        let keys = self.ledger.keys_of(subject);

        let mut destroyed = 0u32;
        let mut already = 0u32;
        let mut entries = Vec::new();
        for key in &keys {
            match self.provider.destroy(*key)? {
                Destroyed::Now => destroyed += 1,
                Destroyed::Already => already += 1,
            }
            entries.push(manifest_entry(subject_key, *key));
        }
        // Every key is gone, so the row is safe to forget. `destroy` is
        // idempotent, which is what makes the retry after a partial failure
        // correct rather than merely possible.
        self.ledger.drop_subject(subject);

        // Sorted, so the manifest does not leak the order keys were created in,
        // which is the order the records were written in.
        entries.sort();

        let manifest = encode_manifest(&entries);
        let manifest_hash = Sha384::digest(&manifest);
        let tag = erasure_tag(subject_key);
        self.erasures += 1;

        // Named by its own content. A per-process counter named it before, so a
        // restart or a second node began at one again and wrote to a key that
        // already existed: `put_if_absent` reported `AlreadyExists` exactly as
        // its contract promises, the outcome was discarded with `?`, and the
        // second erasure's manifest was never stored anywhere while its record
        // committed to the hash of it.
        let object_key = format!("erasure/{}", manifest_hash.to_hex());
        if self.store.put_if_absent(&object_key, &manifest)? == PutOutcome::AlreadyExists {
            // Content-addressed, so this is the same bytes by construction
            // unless the store handed back something else, and that is worth
            // finding out about rather than assuming.
            match self.store.get(&object_key)? {
                Some(bytes) if Sha384::digest(&bytes) == manifest_hash => {}
                _ => return Err(VaultError::ManifestMismatch),
            }
        }

        let draft = self.erasure_draft(recorded_at, tag, manifest_hash, destroyed + already)?;

        Ok(Forgotten {
            keys_destroyed: destroyed,
            keys_already_gone: already,
            manifest: manifest_hash,
            manifest_size: manifest.len() as u64,
            subject_key,
            tag,
            draft,
        })
    }

    /// The record that says an erasure happened, without saying who it was.
    fn erasure_draft(
        &self,
        recorded_at: Timestamp,
        tag: Hash,
        manifest_hash: Hash,
        keys: u32,
    ) -> Result<MetaDraft, VaultError> {
        let agent_id =
            AgentId::parse_strict(format!("agent://{}/trailryx.erasure", self.trust_domain))
                .map_err(|_| VaultError::Malformed("trust domain"))?;
        // From the erasure's own content and subject rather than from a counter,
        // for the same reason as the manifest key: two vaults each starting at
        // one gave two different erasures the same run id.
        let mut seed = Vec::with_capacity(112);
        seed.extend_from_slice(b"trailryx.erasure.run.v1");
        seed.extend_from_slice(tag.as_bytes());
        seed.extend_from_slice(manifest_hash.as_bytes());
        let run = Sha384::digest(&seed).to_hex();
        let run_id = RunId::parse(format!("erasure-{}", &run[..32]))
            .map_err(|_| VaultError::Malformed("run id"))?;

        Ok(MetaDraft {
            // The store speaking about itself, so no mapper was involved.
            mapper: MapperVersion::UNMAPPED,
            tenant: self.tenant.clone(),
            agent_id,
            run_id,
            parent_run_id: None,
            on_behalf_of: Vec::new(),
            // The store speaking about itself, so the clock is genuinely ours.
            occurred_at: Untrusted::new(recorded_at),
            decided_at: None,
            event_type: EventType::Erasure,
            severity: Severity::Notice,
            basis: Basis {
                // A tag over the subject's key id, not the key id itself.
                //
                // This field held `subject_key` and that was the single worst
                // privacy defect in the store. `memory_ref` is cleartext
                // metadata: indexed, projected into Parquet, committed into
                // Merkle roots and shipped inside evidence packs. Publishing the
                // subject key there handed everybody the one input the erasure
                // manifest's entries were supposed to require, so anybody with
                // metadata access could recompute
                // `manifest_entry(subject_key, record.payload.key_id)` for every
                // record and read off exactly which records had belonged to the
                // person who asked to be forgotten. A for-loop undid the
                // erasure's whole purpose.
                //
                // One more hash fixes it and keeps what the field was for: a
                // handle holder derives `subject_key`, tags it, and matches this
                // record; nobody can go the other way, so the manifest stays
                // unrecomputable without the handle. What still carries the rest
                // is the pseudonym's entropy, which is why `SubjectHandle` is a
                // token and `docs/identifiers.md` says it must not be guessable.
                memory_ref: Some(tag),
                ..Basis::default()
            },
            // Nothing to erase is a real answer and a different one from having
            // erased something. A controller has to be able to say both.
            verdict: Some(if keys > 0 {
                Verdict::Allowed
            } else {
                Verdict::NotApplicable
            }),
            error: None,
            latency_micros: None,
            tokens_in: Some(keys),
            tokens_out: None,
            cost_micros: None,
        })
    }

    /// The reference an erasure record points at: the manifest, in the clear.
    pub fn manifest_ref(&self, forgotten: &Forgotten) -> PayloadRef {
        PayloadRef {
            hash: forgotten.manifest,
            size_bytes: forgotten.manifest_size,
            class: PayloadClass::Diagnostic,
            // The manifest is not encrypted: it names no payloads and no
            // people, only opaque entries. A key id here would suggest it can
            // be erased, and it must not be: it is the evidence the erasure
            // happened.
            key_id: Hash::ZERO,
        }
    }

    pub fn ledger(&self) -> &KeyLedger {
        &self.ledger
    }

    pub fn store_mut(&mut self) -> &mut O {
        &mut self.store
    }

    pub fn provider_mut(&mut self) -> &mut K {
        &mut self.provider
    }
}

/// What the erasure record carries in place of the subject's key id.
///
/// A one-way step, so the record is matchable by whoever can derive
/// `subject_key` from a handle and gives nothing to a reader who cannot. The
/// difference is not cosmetic: `subject_key` is the missing input to
/// [`manifest_entry`], and while the record published it the manifest could be
/// intersected with the store by anybody at all.
pub fn erasure_tag(subject_key: KeyId) -> Hash {
    let mut seed = Vec::with_capacity(80);
    seed.extend_from_slice(b"trailryx.erasure.subject.v1");
    seed.extend_from_slice(subject_key.0.as_bytes());
    Sha384::digest(&seed)
}

/// One line of an erasure manifest.
///
/// Not the destroyed key id itself. Listing those would let anybody with
/// metadata access intersect the manifest with the records and learn exactly
/// which records belonged to the person who asked to be forgotten. Hashing each
/// one together with the subject's key id keeps the entry verifiable by
/// somebody holding the handle and meaningless to everybody else.
///
/// That last sentence was false for one commit, and not because of anything in
/// this function: the erasure record published `subject_key` in a cleartext
/// metadata field, so both inputs were public and the entry was recomputable by
/// everybody. The asymmetry lives entirely in who can derive `subject_key`, and
/// that is now nobody without the handle.
pub fn manifest_entry(subject_key: KeyId, destroyed: KeyId) -> Hash {
    let mut seed = Vec::with_capacity(112);
    seed.extend_from_slice(b"trailryx.erasure.entry.v1");
    seed.extend_from_slice(subject_key.0.as_bytes());
    seed.extend_from_slice(destroyed.0.as_bytes());
    Sha384::digest(&seed)
}

fn encode_manifest(entries: &[Hash]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + entries.len() * 48);
    out.extend_from_slice(b"TRXE\x01");
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        out.extend_from_slice(entry.as_bytes());
    }
    out
}

/// Read a manifest back: how many keys died, and their opaque entries.
pub fn decode_manifest(bytes: &[u8]) -> Result<Vec<Hash>, VaultError> {
    if bytes.len() < 9 || &bytes[..5] != b"TRXE\x01" {
        return Err(VaultError::Malformed("not an erasure manifest"));
    }
    let mut count = [0u8; 4];
    count.copy_from_slice(&bytes[5..9]);
    let count = u32::from_le_bytes(count) as usize;
    if bytes.len() != 9 + count * 48 {
        return Err(VaultError::Malformed("manifest length"));
    }
    Ok((0..count)
        .map(|i| {
            let mut h = [0u8; 48];
            h.copy_from_slice(&bytes[9 + i * 48..9 + (i + 1) * 48]);
            Hash(h)
        })
        .collect())
}
