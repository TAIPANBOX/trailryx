//! Erasure, tried from every angle somebody would try it from.
//!
//! The claim being tested is narrow and strong: after a subject is forgotten,
//! nothing recovers their payloads, and every proof issued before the erasure
//! still verifies after it. Both halves matter. Either one alone is easy.
//!
//! # What is not tested here yet, and why that is not a hole
//!
//! The roadmap asks for recovery to be attempted through every path: caches,
//! columnar projections, exports, backups, a replication log. None of those
//! exist yet. The paths that exist are tried, and the rule for the ones that do
//! not is that each arrives with its own attempt in this file. A path added
//! without one is a path nobody checked.

use trailryx_contracts::contracts::{KeyId, KeyProvider, ObjectStore};
use trailryx_contracts::fakes::{MemoryKeyProvider, MemoryObjectStore};
use trailryx_contracts::ingest::PayloadPart;
use trailryx_crypto::Sha384;
use trailryx_erasure::aead::Aead;
use trailryx_erasure::vault::Vault;
use trailryx_erasure::{
    KeySource, PredictableKeys, Sha384Ctr, SubjectHandle, VaultError, decode_manifest,
    kek_for_record, kek_for_subject, manifest_entry,
};
use trailryx_index::segment::Segment;
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, PayloadClass, PayloadRef,
    Record, RecordId, RunId, SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};
use trailryx_store::query::{ProofStatus, Query, query_segment};

const NOW: Timestamp = Timestamp(1_700_000_000_000_000_000);

type TestVault = Vault<MemoryObjectStore, MemoryKeyProvider, Sha384Ctr, PredictableKeys>;

fn vault() -> TestVault {
    Vault::unvalidated(
        TenantId::parse("acme").unwrap(),
        "acme.example",
        MemoryObjectStore::default(),
        MemoryKeyProvider::default(),
        Sha384Ctr,
        PredictableKeys::new(),
    )
}

fn subject(s: &str) -> SubjectHandle {
    SubjectHandle::parse(s).unwrap()
}

fn parts() -> Vec<PayloadPart> {
    vec![
        PayloadPart::new(
            PayloadClass::Prompt,
            b"what is the balance for Ivan".to_vec(),
        ),
        PayloadPart::new(PayloadClass::Completion, b"it is 12 UAH".to_vec()),
    ]
}

#[test]
fn a_sealed_payload_comes_back() {
    let mut v = vault();
    let reference = v
        .seal(RecordId(1), &parts(), Some(&subject("s-1")))
        .unwrap();
    assert_eq!(v.open(RecordId(1), &reference).unwrap(), parts());
}

#[test]
fn the_record_takes_the_class_of_its_most_restrictive_part() {
    // Access is decided from one field, so it has to be the strict one. A blob
    // holding a prompt and a diagnostic that read as "diagnostic" would be
    // handed to everybody entitled to read diagnostics.
    let mut v = vault();
    let mixed = vec![
        PayloadPart::new(PayloadClass::Diagnostic, b"span.name\tchat".to_vec()),
        PayloadPart::new(PayloadClass::Prompt, b"my account number is".to_vec()),
    ];
    let reference = v.seal(RecordId(1), &mixed, None).unwrap();
    assert_eq!(reference.class, PayloadClass::Prompt);
}

#[test]
fn an_erased_payload_does_not_come_back_by_any_path_we_have() {
    let mut v = vault();
    let subject = subject("s-1");
    let reference = v.seal(RecordId(1), &parts(), Some(&subject)).unwrap();

    let before = v
        .store_mut()
        .get("payload/acme/00000000000000000000000000000001")
        .unwrap()
        .unwrap();

    v.forget(&subject, NOW).unwrap();

    // 1. The front door.
    assert_eq!(v.open(RecordId(1), &reference), Err(VaultError::Erased));

    // 2. The object store, which still has every byte. Nothing was deleted and
    //    nothing needed to be: that is the point of doing it this way.
    let after = v
        .store_mut()
        .get("payload/acme/00000000000000000000000000000001")
        .unwrap()
        .unwrap();
    assert_eq!(before, after, "the ciphertext is untouched");

    // 3. The plaintext is not sitting in it.
    assert!(!contains(&after, b"Ivan"), "plaintext in the object store");
    assert!(!contains(&after, b"12 UAH"));

    // 4. The key provider, asked directly. The record's own key, because a
    //    payload is always sealed under one of those now: sealing under the
    //    subject's key put the subject into `payload.key_id`, which is cleartext
    //    metadata, so every record about one person carried one identical value
    //    and the store grouped by subject for anybody who could read metadata.
    let kek = kek_for_record(&TenantId::parse("acme").unwrap(), RecordId(1));
    assert_eq!(reference.key_id, kek.0);
    assert!(!v.provider_mut().exists(kek));
    assert!(v.provider_mut().unwrap(kek, b"anything").is_err());

    // 5. Re-creating the key under the same id, which is the move that would
    //    turn "erased" back into "readable". The contract forbids reissuing a
    //    destroyed id and this is what that clause is for.
    assert!(
        v.provider_mut().wrap(kek, &[0u8; 32]).is_err(),
        "a destroyed key id was reissued"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn the_chain_still_verifies_after_an_erasure() {
    // The property the product turns on. A record commits to its payload by
    // hash, size, class and key id, and destroying a key changes none of them,
    // so a proof issued yesterday still checks out today.
    let mut v = vault();
    let subject = subject("s-1");

    let mut sealed = Vec::new();
    for i in 1..=4u128 {
        let reference = v
            .seal(
                RecordId(i),
                &parts(),
                if i % 2 == 0 { Some(&subject) } else { None },
            )
            .unwrap();
        sealed.push(record(i, reference));
    }
    let leaves: Vec<(Record, Hash)> = sealed
        .iter()
        .map(|r| {
            (
                r.clone(),
                Sha384::digest(format!("link-{}", r.id.0).as_bytes()),
            )
        })
        .collect();
    let segment = Segment::seal(SegmentId(1), ShardIx(0), Hash::ZERO, &leaves).unwrap();

    let root_before = segment.manifest().clone();
    let query = Query::point(
        trailryx_index::completeness::Dimension::RunId,
        b"run-1".to_vec(),
    );
    let answer_before = query_segment(&segment, &query);
    assert_eq!(answer_before.proof, ProofStatus::Full);
    assert_eq!(answer_before.records.len(), 4);

    let forgotten = v.forget(&subject, NOW).unwrap();
    assert!(forgotten.keys_destroyed > 0);

    // Same segment, same proof, same root. Nothing about the erasure touched
    // the evidence, because the evidence never held the payload.
    assert_eq!(*segment.manifest(), root_before);
    let answer_after = query_segment(&segment, &query);
    assert_eq!(answer_after.proof, ProofStatus::Full);
    assert_eq!(answer_after.records, answer_before.records);

    // And the payloads those still-provable records point at are gone for the
    // erased subject and intact for everybody else.
    assert_eq!(
        v.open(RecordId(2), &sealed[1].payload.clone().unwrap()),
        Err(VaultError::Erased)
    );
    assert!(
        v.open(RecordId(1), &sealed[0].payload.clone().unwrap())
            .is_ok()
    );
}

#[test]
fn an_erasure_is_itself_a_record_and_does_not_name_the_person() {
    let mut v = vault();
    let handle = subject("s-8f21ac");
    v.seal(RecordId(1), &parts(), Some(&handle)).unwrap();

    let forgotten = v.forget(&handle, NOW).unwrap();
    let draft = &forgotten.draft;

    assert_eq!(draft.event_type, EventType::Erasure);
    assert_eq!(draft.severity, Severity::Notice);
    assert_eq!(
        draft.verdict,
        Some(trailryx_record::Verdict::Allowed),
        "something was erased"
    );
    assert_eq!(draft.tokens_in, Some(1), "one key died");

    // The record says an erasure happened. It does not say whose, which would
    // defeat the erasure it is recording.
    let rendered = format!("{draft:?}");
    assert!(!rendered.contains("s-8f21ac"), "{rendered}");
    assert!(!rendered.contains("Ivan"), "{rendered}");
}

#[test]
fn the_manifest_is_verifiable_by_whoever_holds_the_handle() {
    // Somebody must be able to check that their erasure happened. Somebody else
    // must not be able to work out which records were theirs.
    let tenant = TenantId::parse("acme").unwrap();
    let mut v = vault();
    let handle = subject("s-1");
    let reference = v.seal(RecordId(7), &parts(), None).unwrap();
    v.attribute(&reference, &handle);

    let forgotten = v.forget(&handle, NOW).unwrap();
    // Named by its own content. A per-process counter named it before, so a
    // second vault started at one again and its manifest was silently never
    // written while its record committed to the hash of it.
    let manifest = v
        .store_mut()
        .get(&format!("erasure/{}", forgotten.manifest.to_hex()))
        .unwrap()
        .expect("the manifest is stored under its own hash");
    let entries = decode_manifest(&manifest).unwrap();
    assert_eq!(entries.len(), 1);

    // With the handle: recompute and find it.
    let expected = manifest_entry(
        kek_for_subject(&tenant, &handle),
        kek_for_record(&tenant, RecordId(7)),
    );
    assert!(
        entries.contains(&expected),
        "the subject cannot verify their own erasure"
    );
    assert_eq!(forgotten.subject_key, kek_for_subject(&tenant, &handle));

    // Without it: the record's own key id is public and derivable, and it still
    // does not appear. Otherwise anybody with metadata access could intersect
    // the manifest with the records and learn exactly whose they were.
    let record_key = kek_for_record(&tenant, RecordId(7));
    assert!(!entries.contains(&record_key.0));
    assert!(!contains(&manifest, record_key.0.as_bytes()));
}

#[test]
fn attribution_rewrites_nothing() {
    // The mechanic the roadmap got wrong. Re-wrapping would leave the old
    // envelope in storage that cannot be deleted, and the old key would still
    // open it. Here attribution only adds a key to a set.
    let mut v = vault();
    let before = {
        v.seal(RecordId(1), &parts(), None).unwrap();
        v.store_mut()
            .get("payload/acme/00000000000000000000000000000001")
            .unwrap()
            .unwrap()
    };
    let reference = {
        let mut v2 = vault();
        v2.seal(RecordId(1), &parts(), None).unwrap()
    };

    assert!(v.attribute(&reference, &subject("s-1")));
    let after = v
        .store_mut()
        .get("payload/acme/00000000000000000000000000000001")
        .unwrap()
        .unwrap();
    assert_eq!(before, after, "attribution touched the stored bytes");

    // And it still reaches the payload when the subject asks to be forgotten.
    v.forget(&subject("s-1"), NOW).unwrap();
    assert_eq!(v.open(RecordId(1), &reference), Err(VaultError::Erased));
}

#[test]
fn erasing_twice_is_honest_about_the_second_time() {
    let mut v = vault();
    let handle = subject("s-1");
    v.seal(RecordId(1), &parts(), Some(&handle)).unwrap();

    let first = v.forget(&handle, NOW).unwrap();
    assert_eq!(first.keys_destroyed, 1);
    assert_eq!(first.keys_already_gone, 0);

    let second = v.forget(&handle, NOW).unwrap();
    assert_eq!(second.keys_destroyed, 0);
    assert_eq!(
        second.draft.verdict,
        Some(trailryx_record::Verdict::NotApplicable),
        "nothing left to erase is a different answer from having erased"
    );
}

#[test]
fn erasing_somebody_we_hold_nothing_about_is_a_real_answer() {
    // A controller has to be able to say "we hold nothing about this person"
    // and have it be a recorded fact rather than silence.
    let mut v = vault();
    let forgotten = v.forget(&subject("never-heard-of"), NOW).unwrap();
    assert_eq!(forgotten.keys_destroyed, 0);
    assert_eq!(
        forgotten.draft.verdict,
        Some(trailryx_record::Verdict::NotApplicable)
    );
    assert_eq!(forgotten.draft.event_type, EventType::Erasure);
}

#[test]
fn forgetting_one_person_leaves_everybody_else_readable() {
    let mut v = vault();
    let a = v
        .seal(RecordId(1), &parts(), Some(&subject("s-1")))
        .unwrap();
    let b = v
        .seal(RecordId(2), &parts(), Some(&subject("s-2")))
        .unwrap();

    v.forget(&subject("s-1"), NOW).unwrap();

    assert_eq!(v.open(RecordId(1), &a), Err(VaultError::Erased));
    assert!(v.open(RecordId(2), &b).is_ok(), "erasure reached too far");
}

#[test]
fn one_tenants_erasure_cannot_reach_another_tenants_records() {
    // The same pseudonym in two tenants is two people as far as we know, and
    // acting otherwise would delete somebody else's data on a name collision.
    let acme = TenantId::parse("acme").unwrap();
    let globex = TenantId::parse("globex").unwrap();
    let handle = subject("s-1");
    assert_ne!(
        kek_for_subject(&acme, &handle),
        kek_for_subject(&globex, &handle)
    );
}

#[test]
fn an_envelope_from_another_record_is_refused() {
    // Somebody with write access to the object store swaps two payloads. The
    // record says which key its payload was sealed under, so the swap is caught
    // before anything is decrypted.
    let mut v = vault();
    let one = v
        .seal(RecordId(1), &parts(), Some(&subject("s-1")))
        .unwrap();
    v.seal(
        RecordId(2),
        &[PayloadPart::new(
            PayloadClass::Prompt,
            b"someone else".to_vec(),
        )],
        Some(&subject("s-2")),
    )
    .unwrap();

    let other = v
        .store_mut()
        .get("payload/acme/00000000000000000000000000000002")
        .unwrap()
        .unwrap();

    // The object store refuses to overwrite, so the swap is staged the way an
    // attacker with storage access would actually do it: a store where record
    // one's slot holds record two's envelope.
    let mut planted = vault();
    planted
        .store_mut()
        .put_if_absent("payload/acme/00000000000000000000000000000001", &other)
        .unwrap();
    assert_eq!(planted.open(RecordId(1), &one), Err(VaultError::WrongKey));
}

#[test]
fn a_vault_cannot_be_built_on_stand_ins_by_accident() {
    let built = Vault::new(
        TenantId::parse("acme").unwrap(),
        "acme.example",
        MemoryObjectStore::default(),
        MemoryKeyProvider::default(),
        Sha384Ctr,
        PredictableKeys::new(),
    );
    assert!(matches!(built, Err(VaultError::Unvalidated(_))));
    assert!(!Sha384Ctr.is_validated());
    assert!(!PredictableKeys::new().is_validated());
}

fn record(id: u128, payload: PayloadRef) -> Record {
    Record {
        id: RecordId(id),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse("agent://acme.example/billing").unwrap(),
        run_id: RunId::parse("run-1").unwrap(),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(1_000 + id as u64)),
        decided_at: None,
        recorded_at: Timestamp(1_000 + id as u64),
        knowledge_as_of: None,
        clock_skew_nanos: None,
        event_type: EventType::ModelCall,
        severity: Severity::Info,
        basis: Basis::default(),
        caused_by: Vec::new(),
        outcome: Outcome::default(),
        payload: Some(payload),
        seq: id as u64,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(1),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}

#[test]
fn the_metadata_plane_cannot_relink_a_forgotten_subject_to_their_records() {
    // The worst defect the core review found, and it needed no keys, no
    // ciphertext and no privileged access: only the metadata plane and the
    // manifest, both of which an evidence pack hands over on purpose.
    //
    // The erasure record used to publish `subject_key` in `basis.memory_ref`, a
    // cleartext field. `manifest_entry` is a hash of `subject_key` and the
    // destroyed key id, and the destroyed key id is `payload.key_id`, also
    // cleartext. So both inputs were public, every entry was recomputable by
    // anybody, and a for-loop over the store read off precisely which records
    // had belonged to the person who asked to be forgotten. The comment above
    // `manifest_entry` said that was the thing it prevented.
    let tenant = TenantId::parse("acme").unwrap();
    let mut v = vault();
    let handle = subject("u-8f3a91");

    let theirs: Vec<(RecordId, PayloadRef)> = [11u128, 22]
        .iter()
        .map(|n| {
            let r = RecordId(*n);
            (r, v.seal(r, &parts(), None).unwrap())
        })
        .collect();
    let somebody_else = RecordId(33);
    let other_ref = v.seal(somebody_else, &parts(), None).unwrap();
    for (_, reference) in &theirs {
        assert!(v.attribute(reference, &handle));
    }

    let forgotten = v.forget(&handle, NOW).unwrap();
    let manifest = v
        .store_mut()
        .get(&format!("erasure/{}", forgotten.manifest.to_hex()))
        .unwrap()
        .unwrap();
    let entries = decode_manifest(&manifest).unwrap();
    assert_eq!(entries.len(), 2);

    // The attacker's whole toolkit: the erasure record's metadata and every
    // record's `payload.key_id`. No handle.
    let published = forgotten
        .draft
        .basis
        .memory_ref
        .expect("the record still points at its erasure");
    let all = [
        (theirs[0].0, theirs[0].1.key_id),
        (theirs[1].0, theirs[1].1.key_id),
        (somebody_else, other_ref.key_id),
    ];
    let linked: Vec<RecordId> = all
        .iter()
        .filter(|(_, key_id)| entries.contains(&manifest_entry(KeyId(published), KeyId(*key_id))))
        .map(|(id, _)| *id)
        .collect();
    assert!(
        linked.is_empty(),
        "the metadata plane relinked {linked:?} to a forgotten subject"
    );

    // And the published value is not a subject key by any other route either:
    // not the key itself, and not equal to any record's key id (which is what
    // sealing under a subject key used to make it).
    assert_ne!(published, forgotten.subject_key.0);
    for (_, key_id) in &all {
        assert_ne!(
            published, *key_id,
            "a record's key id equals the erasure record's, so the store groups by subject"
        );
    }

    // Whoever does hold the handle still verifies their own erasure, which is
    // the asymmetry the design claims and the reason it is not simply removed.
    let subject_key = kek_for_subject(&tenant, &handle);
    assert_eq!(published, trailryx_erasure::vault::erasure_tag(subject_key));
    let found: Vec<RecordId> = all
        .iter()
        .filter(|(_, key_id)| entries.contains(&manifest_entry(subject_key, KeyId(*key_id))))
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(found, vec![theirs[0].0, theirs[1].0]);
}

#[test]
fn a_kms_failure_halfway_leaves_the_row_for_the_retry() {
    // `forget` dropped the ledger row before destroying anything, which is the
    // exact order `KeyLedger::drop_subject` documents as forbidden: "a row
    // dropped first would leave keys nobody knows to destroy, which is the
    // failure mode where a system believes it erased somebody and did not".
    //
    // One `Unavailable` from a KMS is all it took. The row was already gone, so
    // the controller's retry found nothing, returned `NotApplicable` ("we hold
    // nothing about this person"), and the surviving payloads stayed readable
    // with no key id left anywhere to say they had to die.
    let mut v = Vault::unvalidated(
        TenantId::parse("acme").unwrap(),
        "acme.example",
        MemoryObjectStore::default(),
        FailsOnceOnDestroy::default(),
        Sha384Ctr,
        PredictableKeys::new(),
    );
    let handle = subject("s-1");
    let mut refs = Vec::new();
    for n in 1..=4u128 {
        let r = RecordId(n);
        let reference = v.seal(r, &parts(), None).unwrap();
        v.attribute(&reference, &handle);
        refs.push((r, reference));
    }

    let first = v.forget(&handle, NOW);
    assert!(first.is_err(), "a failing destroy has to be reported");

    // The retry, which is what any erasure job does. It must find work to do.
    let second = v.forget(&handle, NOW).expect("the retry completes");
    assert_eq!(
        second.keys_destroyed + second.keys_already_gone,
        4,
        "the retry saw {} of 4 keys",
        second.keys_destroyed + second.keys_already_gone
    );
    assert_eq!(
        second.draft.verdict,
        Some(trailryx_record::Verdict::Allowed)
    );

    for (record, reference) in &refs {
        assert_eq!(
            v.open(*record, reference),
            Err(VaultError::Erased),
            "record {record:?} is still readable after an erasure said it was done"
        );
    }
}

/// A KMS that drops one request, which is the ordinary thing a KMS does.
#[derive(Debug, Default)]
struct FailsOnceOnDestroy {
    inner: MemoryKeyProvider,
    destroys: u32,
}

impl KeyProvider for FailsOnceOnDestroy {
    fn wrap(
        &mut self,
        kek: trailryx_contracts::contracts::KeyId,
        dek: &[u8],
    ) -> trailryx_contracts::contracts::AdapterResult<Vec<u8>> {
        self.inner.wrap(kek, dek)
    }

    fn unwrap(
        &mut self,
        kek: trailryx_contracts::contracts::KeyId,
        wrapped: &[u8],
    ) -> trailryx_contracts::contracts::AdapterResult<Vec<u8>> {
        self.inner.unwrap(kek, wrapped)
    }

    fn destroy(
        &mut self,
        kek: trailryx_contracts::contracts::KeyId,
    ) -> trailryx_contracts::contracts::AdapterResult<trailryx_contracts::contracts::Destroyed>
    {
        self.destroys += 1;
        if self.destroys == 2 {
            return Err(trailryx_contracts::contracts::AdapterError::Unavailable(
                "kms timeout",
            ));
        }
        self.inner.destroy(kek)
    }

    fn exists(&self, kek: trailryx_contracts::contracts::KeyId) -> bool {
        self.inner.exists(kek)
    }
}

#[test]
fn two_vaults_erasing_do_not_write_over_each_others_evidence() {
    // The manifest object key was a per-process counter, so a restart or a
    // second node began at one again and wrote to a name that already existed.
    // `put_if_absent` reported `AlreadyExists` exactly as its contract promises;
    // the outcome was discarded, so the second erasure's manifest existed
    // nowhere while its record committed to the hash of it. The two erasures
    // also shared a run id.
    let tenant = TenantId::parse("acme").unwrap();
    let shared = MemoryObjectStore::default();

    let mut first = Vault::unvalidated(
        tenant.clone(),
        "acme.example",
        shared.clone(),
        MemoryKeyProvider::default(),
        Sha384Ctr,
        PredictableKeys::new(),
    );
    let a = subject("s-a");
    let ref_a = first.seal(RecordId(1), &parts(), Some(&a)).unwrap();
    assert!(!ref_a.key_id.is_zero());
    let one = first.forget(&a, NOW).unwrap();

    // A second vault over the same store: a restart, or another node.
    let mut second = Vault::unvalidated(
        tenant,
        "acme.example",
        first.store_mut().clone(),
        MemoryKeyProvider::default(),
        Sha384Ctr,
        PredictableKeys::new(),
    );
    let b = subject("s-b");
    second.seal(RecordId(2), &parts(), Some(&b)).unwrap();
    let two = second.forget(&b, NOW).unwrap();

    assert_ne!(
        one.manifest, two.manifest,
        "different erasures, one manifest"
    );
    assert_ne!(
        one.draft.run_id, two.draft.run_id,
        "two erasures shared a run id"
    );
    for f in [&one, &two] {
        let stored = second
            .store_mut()
            .get(&format!("erasure/{}", f.manifest.to_hex()))
            .unwrap()
            .expect("both manifests are stored");
        assert_eq!(
            Sha384::digest(&stored),
            f.manifest,
            "a record commits to evidence bytes the store does not hold"
        );
    }
}
