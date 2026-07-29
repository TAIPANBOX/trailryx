//! Whose data it is, and which keys have to die for them to be forgotten.
//!
//! # The mechanic the plan got wrong
//!
//! The roadmap said: wrap a payload's data key under a tenant key while the
//! subject is unknown, and when the subject is later identified, re-wrap under
//! a subject key and destroy the old wrapping.
//!
//! That does not work, and the reason is the same property that makes
//! crypto-erasure worth having. The old wrapping was written to storage that is
//! replicated, backed up and often write-once. "Destroy the old wrapping" means
//! delete an object, and if we could reliably delete objects we would not need
//! crypto-erasure at all. Leave the old envelope in place and the tenant key
//! still opens it, so a subject who asked to be forgotten is one restored
//! backup away from being remembered.
//!
//! So attribution here does not re-wrap anything.
//!
//! - A payload whose subject is known is sealed under that **subject's key**.
//! - A payload whose subject is unknown is sealed under a **key of its own**,
//!   derived from the record id, belonging to nobody.
//! - Attribution **adds** that key to the subject's set. Nothing is rewritten,
//!   so nothing has to be deleted.
//! - Forgetting destroys every key in the set.
//!
//! The cost is more keys. The benefit is that erasure never depends on deleting
//! anything, which is the only version of erasure that survives contact with a
//! backup.
//!
//! # Where those keys live
//!
//! Not one cloud KMS key each: at a dollar a key a month that is absurd, and
//! the arithmetic is a fair objection to make. A `KeyProvider` implementation
//! holds a key table encrypted under a single KMS key. What matters is the
//! shape rather than the storage: the erasable surface is small, cheap and
//! genuinely deletable, and the enormous immutable surface is ciphertext that
//! never needs deleting.
//!
//! # What the pseudonym does and does not hide
//!
//! A subject handle is operator-supplied and pseudonymous, as
//! `docs/identifiers.md` requires. Its key id is a hash of it, so somebody
//! holding the handle can confirm that this subject's keys were destroyed, and
//! somebody without it learns nothing.
//!
//! That asymmetry is not a leak, it is the requirement. An erasure nobody can
//! verify is an erasure nobody has to perform.

use std::collections::{BTreeMap, BTreeSet};
use trailryx_contracts::contracts::KeyId;
use trailryx_crypto::Sha384;
use trailryx_record::{IdError, RecordId, TenantId};

/// An operator's pseudonym for a data subject.
///
/// Same character set as every other identifier in the store, for the same
/// reason: it is a token in the metadata plane, and free text there is a hole
/// through which content arrives.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectHandle(String);

impl SubjectHandle {
    pub const MAX_BYTES: usize = 64;

    pub fn parse(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        if s.is_empty() {
            return Err(IdError::Empty);
        }
        if s.len() > Self::MAX_BYTES {
            return Err(IdError::TooLong {
                max: Self::MAX_BYTES,
                got: s.len(),
            });
        }
        if let Some((at, ch)) = s.char_indices().find(|(_, c)| {
            !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
        }) {
            return Err(IdError::BadChar { at, ch });
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn derive(label: &[u8], tenant: &TenantId, tail: &[u8]) -> KeyId {
    let mut seed = Vec::with_capacity(64 + tail.len());
    seed.extend_from_slice(b"trailryx.kek.v1");
    seed.push(0);
    seed.extend_from_slice(label);
    seed.push(0);
    // The tenant is inside the derivation, so the same subject handle in two
    // tenants is two different keys. Otherwise erasing a person in one tenant
    // would erase them in another, which is somebody else's data.
    seed.extend_from_slice(tenant.as_str().as_bytes());
    seed.push(0);
    seed.extend_from_slice(tail);
    KeyId(Sha384::digest(&seed))
}

/// The key covering everything known to be about one subject.
pub fn kek_for_subject(tenant: &TenantId, subject: &SubjectHandle) -> KeyId {
    derive(b"subject", tenant, subject.as_str().as_bytes())
}

/// A key belonging to one record and to nobody.
///
/// Used when the subject is not known at write time, which is the normal case:
/// an agent rarely knows whose data is in a prompt at the moment it sends one.
pub fn kek_for_record(tenant: &TenantId, record: RecordId) -> KeyId {
    derive(b"record", tenant, &record.0.to_le_bytes())
}

/// Which keys have to die for a subject to be forgotten.
///
/// Small by construction: one row per subject, a few key ids each. Small is the
/// point. This is the part of the system that must support real deletion, and
/// keeping it small is what makes real deletion affordable.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeyLedger {
    rows: BTreeMap<SubjectHandle, BTreeSet<KeyId>>,
}

impl KeyLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a key holds something about this subject.
    ///
    /// Idempotent: attributing the same payload twice is one key, not two, and
    /// a re-run of an attribution job must not double anything.
    pub fn attribute(&mut self, subject: &SubjectHandle, kek: KeyId) -> bool {
        self.rows.entry(subject.clone()).or_default().insert(kek)
    }

    pub fn keys_of(&self, subject: &SubjectHandle) -> Vec<KeyId> {
        self.rows
            .get(subject)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn knows(&self, subject: &SubjectHandle) -> bool {
        self.rows.contains_key(subject)
    }

    /// Forget that the subject ever had a row.
    ///
    /// Called after the keys are destroyed, not before: a row dropped first
    /// would leave keys nobody knows to destroy, which is the failure mode
    /// where a system believes it erased somebody and did not.
    pub fn drop_subject(&mut self, subject: &SubjectHandle) -> Vec<KeyId> {
        self.rows
            .remove(subject)
            .map(|s| s.into_iter().collect())
            .unwrap_or_default()
    }

    pub fn subjects(&self) -> usize {
        self.rows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(s: &str) -> TenantId {
        TenantId::parse(s).unwrap()
    }

    fn subject(s: &str) -> SubjectHandle {
        SubjectHandle::parse(s).unwrap()
    }

    #[test]
    fn a_handle_is_a_token_not_a_sentence() {
        assert!(SubjectHandle::parse("subject-8f21ac").is_ok());
        assert!(SubjectHandle::parse("Ivan Petrenko").is_err());
        assert!(SubjectHandle::parse("ivan@example.com").is_err());
        assert!(SubjectHandle::parse("").is_err());
        assert!(SubjectHandle::parse("x".repeat(65)).is_err());
    }

    #[test]
    fn one_subject_in_two_tenants_is_two_keys() {
        // Otherwise forgetting somebody in one tenant reaches into another
        // tenant's records, which are not ours to touch.
        assert_ne!(
            kek_for_subject(&tenant("acme"), &subject("s-1")),
            kek_for_subject(&tenant("globex"), &subject("s-1"))
        );
    }

    #[test]
    fn a_subject_key_and_a_record_key_never_collide() {
        // Both are hashes of a tenant and a tail. Without the label in the
        // derivation, a subject handle could be chosen to collide with a record
        // key and one erasure would take out somebody else's payload.
        let t = tenant("acme");
        assert_ne!(
            kek_for_subject(&t, &subject("record")),
            kek_for_record(&t, RecordId(1))
        );
    }

    #[test]
    fn the_same_inputs_always_derive_the_same_key() {
        // Erasure has to find the key again years later, from the handle alone.
        let t = tenant("acme");
        assert_eq!(
            kek_for_subject(&t, &subject("s-1")),
            kek_for_subject(&t, &subject("s-1"))
        );
        assert_eq!(
            kek_for_record(&t, RecordId(7)),
            kek_for_record(&t, RecordId(7))
        );
        assert_ne!(
            kek_for_record(&t, RecordId(7)),
            kek_for_record(&t, RecordId(8))
        );
    }

    #[test]
    fn attributing_twice_adds_one_key() {
        let mut ledger = KeyLedger::new();
        let key = kek_for_record(&tenant("acme"), RecordId(1));
        assert!(ledger.attribute(&subject("s-1"), key));
        assert!(!ledger.attribute(&subject("s-1"), key));
        assert_eq!(ledger.keys_of(&subject("s-1")).len(), 1);
    }

    #[test]
    fn dropping_a_subject_returns_what_still_has_to_die() {
        let mut ledger = KeyLedger::new();
        let t = tenant("acme");
        ledger.attribute(&subject("s-1"), kek_for_record(&t, RecordId(1)));
        ledger.attribute(&subject("s-1"), kek_for_record(&t, RecordId(2)));
        assert_eq!(ledger.drop_subject(&subject("s-1")).len(), 2);
        assert!(!ledger.knows(&subject("s-1")));
        assert!(ledger.drop_subject(&subject("s-1")).is_empty());
    }
}
