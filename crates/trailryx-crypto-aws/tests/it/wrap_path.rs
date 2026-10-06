//! The hybrid KEM on the path that actually wraps a payload key.
//!
//! Everything in `src/` proves the KEM against itself. This proves it against
//! `Vault::seal` and `Vault::open`, which is the only path in the workspace where a
//! payload key is wrapped at all, and the path that had no key exchange in it until
//! 7 August 2026.
//!
//! **What this is not run under, stated because it is the honest half.** `Vault::new`
//! refuses any provider whose cipher and key source answer `is_validated() == false`,
//! and both answer `cfg!(feature = "fips")`. So the configuration a deployment would
//! run reaches this code only in a `--features fips` build, which
//! `scripts/fips-build.sh` compiles and which no test here executes. These tests use
//! `Vault::unvalidated` and `PredictableKeys`, exactly as the acceptance demo does and
//! for the same reason: the mechanics above the seam are what is under test.

use trailryx_contracts::contracts::{KeyProvider, ObjectStore};
use trailryx_contracts::fakes::MemoryObjectStore;
use trailryx_contracts::ingest::PayloadPart;
use trailryx_crypto_aws::hybrid::CIPHERTEXT_BYTES;
use trailryx_crypto_aws::{AwsAead, CustodyKey, HybridKeyProvider, PersistedKeyProvider};
use trailryx_erasure::aead::KeySource;
use trailryx_erasure::vault::Vault;
use trailryx_erasure::{Envelope, PredictableKeys, SubjectHandle, kek_for_record};
use trailryx_record::{PayloadClass, RecordId, TenantId, Timestamp};

type Deployed = Vault<MemoryObjectStore, HybridKeyProvider, AwsAead, PredictableKeys>;

fn tenant() -> TenantId {
    TenantId::parse("acme").expect("a tenant")
}

fn vault() -> Deployed {
    // `unvalidated` because `AwsAead::is_validated()` is `cfg!(feature = "fips")` and
    // this build is not that one. The line is named so a reviewer reading it knows.
    Vault::unvalidated(
        tenant(),
        "acme.example",
        MemoryObjectStore::default(),
        HybridKeyProvider::new(),
        AwsAead,
        PredictableKeys::new(),
    )
}

fn parts() -> Vec<PayloadPart> {
    vec![PayloadPart::new(
        PayloadClass::Prompt,
        b"what the person actually typed".to_vec(),
    )]
}

#[test]
fn a_payload_sealed_through_the_hybrid_custodian_comes_back() {
    let mut vault = vault();
    let reference = vault.seal(RecordId(1), &parts(), None).expect("a seal");
    assert_eq!(
        vault.open(RecordId(1), &reference).expect("an open"),
        parts()
    );
}

/// **The test that goes red if the wrap path stops being hybrid.**
///
/// It reads the envelope the vault actually stored, which is what a deployment would
/// have on disk, and measures the wrapped key against the shape only a hybrid
/// encapsulation produces. A provider that wrapped with a symmetric key, or with
/// ML-KEM alone, or with X25519 alone, gives a different length, and each of those is
/// a real thing somebody could substitute without any test above this one noticing.
#[test]
fn the_wrapped_key_in_the_stored_envelope_is_a_hybrid_encapsulation() {
    let mut vault = vault();
    vault.seal(RecordId(1), &parts(), None).expect("a seal");

    let key = format!("payload/{}/{:032x}", tenant().as_str(), 1u128);
    let bytes = vault
        .store_mut()
        .get(&key)
        .expect("the store answered")
        .expect("an envelope was stored");
    let envelope = Envelope::decode(&bytes).expect("an envelope");

    // version + ML-KEM-768 ciphertext + ephemeral X25519 key + nonce + AES-GCM(dek)
    assert_eq!(
        envelope.wrapped_dek.len(),
        1 + CIPHERTEXT_BYTES + 12 + 32 + 16
    );
    assert_eq!(CIPHERTEXT_BYTES, 1088 + 32);
    assert_eq!(envelope.kek, kek_for_record(&tenant(), RecordId(1)));

    // And the data key is not in it. Trivially true and cheap to hold: a wrap that
    // regressed to the identity would still have the right length if it were padded.
    // `PredictableKeys` is deterministic, so the data key the vault used is the
    // first one this source yields, and it can be recomputed here.
    let dek = PredictableKeys::new().fresh_dek();
    assert!(
        !envelope
            .wrapped_dek
            .windows(32)
            .any(|w| w == dek.as_bytes()),
        "the data key is in the wrapped form in the clear"
    );
}

/// Erasure, through the seam, with a real KEM behind it.
///
/// This is the property the whole store is bought for: the ciphertext stays in the
/// object store and stops being readable, and nothing was deleted to achieve it.
#[test]
fn forgetting_a_subject_makes_the_payload_unreadable_and_deletes_nothing() {
    let mut vault = vault();
    let subject = SubjectHandle::parse("subject-token-0001").expect("a handle");
    let reference = vault
        .seal(RecordId(1), &parts(), Some(&subject))
        .expect("a seal");

    let key = format!("payload/{}/{:032x}", tenant().as_str(), 1u128);
    let before = vault.store_mut().get(&key).expect("a read").expect("bytes");

    let forgotten = vault.forget(&subject, Timestamp(1)).expect("an erasure");
    assert_eq!(forgotten.keys_destroyed, 1);
    assert!(forgotten.is_complete());

    let after = vault.store_mut().get(&key).expect("a read").expect("bytes");
    assert_eq!(
        before, after,
        "the ciphertext must still be there, unchanged"
    );
    assert!(vault.open(RecordId(1), &reference).is_err());
}

/// Two records, two key-encryption keys, two independent encapsulations.
///
/// Forgetting one subject must not reach the other's payload, and with a per-record
/// KEM that is a property of the custodian rather than of the ledger.
#[test]
fn one_erasure_does_not_reach_another_records_payload() {
    let mut vault = vault();
    let one = SubjectHandle::parse("subject-token-0001").expect("a handle");
    let two = SubjectHandle::parse("subject-token-0002").expect("a handle");
    let a = vault
        .seal(RecordId(1), &parts(), Some(&one))
        .expect("a seal");
    let b = vault
        .seal(RecordId(2), &parts(), Some(&two))
        .expect("a seal");

    vault.forget(&one, Timestamp(1)).expect("an erasure");
    assert!(vault.open(RecordId(1), &a).is_err());
    assert_eq!(vault.open(RecordId(2), &b).expect("an open"), parts());
}

/// **The same path, with a custodian that keeps its keys, across a restart.**
///
/// This is the claim the whole store rests on and the one the in-memory custodian
/// cannot make: a payload sealed by one process is opened by the next. Both planes
/// are rebuilt, because both have to be. The object store is a fake that lives in
/// memory, so its bytes are carried over by hand exactly as a real object store would
/// carry them; the custodian is not, and that is the half under test.
#[test]
fn a_payload_sealed_before_a_restart_opens_after_one() {
    let dir = std::env::temp_dir().join(format!("trailryx-wrap-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key = format!("payload/{}/{:032x}", tenant().as_str(), 1u128);

    let root = CustodyKey::from_bytes([5u8; 32]);
    let mut first = Vault::unvalidated(
        tenant(),
        "acme.example",
        MemoryObjectStore::default(),
        PersistedKeyProvider::open(&dir, root).expect("a custodian"),
        AwsAead,
        PredictableKeys::new(),
    );
    let reference = first.seal(RecordId(1), &parts(), None).expect("a seal");
    let envelope = first
        .store_mut()
        .get(&key)
        .expect("the store answered")
        .expect("an envelope");
    drop(first);

    // A second process: a new custodian over the same directory, a new store holding
    // what the first one published.
    let mut store = MemoryObjectStore::default();
    store.put_if_absent(&key, &envelope).expect("the envelope");
    let root = CustodyKey::from_bytes([5u8; 32]);
    let mut second = Vault::unvalidated(
        tenant(),
        "acme.example",
        store,
        PersistedKeyProvider::open(&dir, root).expect("a custodian"),
        AwsAead,
        PredictableKeys::new(),
    );
    let opened = second.open(RecordId(1), &reference);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        opened.expect("an open after a restart"),
        parts(),
        "a payload sealed by the previous process did not open"
    );
}

/// A wrapped key from one custodian is not readable by another.
///
/// The recipient key pairs live in the process, so this is what a restart looks like
/// from the outside, and it is stated as a test rather than left to be discovered:
/// `HybridKeyProvider` persists nothing and its module documentation says so. The
/// test above is the same shape with the custodian that does.
#[test]
fn a_second_custodian_cannot_open_the_first_ones_wrapped_key() {
    let mut first = HybridKeyProvider::new();
    let kek = kek_for_record(&tenant(), RecordId(1));
    let wrapped = first.wrap(kek, &[7u8; 32]).expect("a wrap");

    let mut second = HybridKeyProvider::new();
    assert!(second.unwrap(kek, &wrapped).is_err());
    // And it does not quietly mint a fresh key pair under that id and answer with
    // something else: the id is unknown to it, so it refuses.
    assert!(!second.exists(kek));
}
