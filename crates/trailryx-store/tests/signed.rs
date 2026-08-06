//! A signed, witnessed pack, checked end to end.
//!
//! The signer here is OpenSSL, driven as a subprocess. That is deliberate and
//! not laziness: this repository contains no signing code and should not, so a
//! test that needs a signature has to get one from somebody who has a key. It
//! also means the signatures the verifier accepts were made by an
//! implementation with no shared ancestry with ours.
//!
//! If OpenSSL is not on the machine the test says it skipped. A check that
//! quietly passes when it did not run is the thing this project exists against.

use std::path::PathBuf;
use std::process::Command;
use trailryx_crypto::{Sha384, chain_step};
use trailryx_index::segment::{Segment, ShardTree, StoreTree};
use trailryx_journal::wire::encode_record;
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, SigAlg, TenantId, Timestamp, Untrusted,
};
use trailryx_sign::{RootSignature, SignError, Signer, attest, sign_root_unvalidated};
use trailryx_store::evidence::PackBuilder;
use trailryx_verify::{Level, verify};

const GENERATED_AT: Timestamp = Timestamp(1_700_000_000_000_000_000);

/// A plausible place for a shard's first chain to begin.
///
/// Not `Hash::ZERO`: a journal derives its first segment's start from the file's
/// own header, so zero is a value no journal produces and the verifier says so.
/// This fixture builds a segment by hand and has to look like something a journal
/// made.
fn genesis() -> Hash {
    Sha384::digest(b"trailryx-test/segment-genesis")
}

// ---------------------------------------------------------------------------
// A signer that is somebody else's code
// ---------------------------------------------------------------------------

struct Openssl {
    key: PathBuf,
    public: Vec<u8>,
    scratch: PathBuf,
}

/// Nothing wiped this scratch, which was survivable while its path was a constant:
/// eleven directories, reused by every run forever. It stopped being survivable when
/// the path gained a process id, because that makes eleven NEW directories on every
/// run, and each one holds the EC private key `new` generated. Measured on this
/// commit's parent: five runs of the affected suites left 71 directories and 55
/// private keys in `$TMPDIR`.
///
/// Each `Openssl` owns its own scratch and every fixture name in this file is
/// distinct, so this wipe cannot reach a directory another test thread is using.
impl Drop for Openssl {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

impl Openssl {
    /// `None` when there is no usable OpenSSL, so the caller can say so.
    fn new(name: &str) -> Option<Self> {
        let scratch =
            std::env::temp_dir().join(format!("trailryx-sign-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&scratch).ok()?;
        let key = scratch.join("key.pem");

        let made = Command::new("openssl")
            .args(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out"])
            .arg(&key)
            .status()
            .ok()?;
        if !made.success() {
            return None;
        }

        let spki = Command::new("openssl")
            .arg("ec")
            .arg("-in")
            .arg(&key)
            .args(["-pubout", "-outform", "DER"])
            .output()
            .ok()?;
        if !spki.status.success() || spki.stdout.len() < 97 {
            return None;
        }
        let public = spki.stdout[spki.stdout.len() - 97..].to_vec();
        if public[0] != 0x04 {
            return None;
        }

        Some(Self {
            key,
            public,
            scratch,
        })
    }
}

impl Signer for Openssl {
    fn algorithm(&self) -> SigAlg {
        SigAlg::Es384
    }

    fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn is_validated(&self) -> bool {
        // A command-line tool driven over temporary files is not a key
        // management story. It signs correctly and it is not a deployment.
        false
    }

    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let path = self.scratch.join("message.bin");
        std::fs::write(&path, message).map_err(|e| SignError::Unavailable(e.to_string()))?;
        let out = Command::new("openssl")
            .args(["dgst", "-sha384", "-sign"])
            .arg(&self.key)
            .arg(&path)
            .output()
            .map_err(|e| SignError::Unavailable(e.to_string()))?;
        if !out.status.success() {
            return Err(SignError::Unavailable("openssl refused to sign".into()));
        }
        der_to_raw(&out.stdout).ok_or_else(|| SignError::Unavailable("unreadable DER".into()))
    }
}

/// `SEQUENCE { INTEGER r, INTEGER s }` to the fixed 96 bytes the format wants.
///
/// DER lets the same number be written more than one way, and this project does
/// not accept two spellings of anything it hashes.
fn der_to_raw(der: &[u8]) -> Option<Vec<u8>> {
    if der.first()? != &0x30 {
        return None;
    }
    let mut at = if der[1] < 0x80 {
        2
    } else {
        2 + usize::from(der[1] & 0x7f)
    };
    let mut out = Vec::with_capacity(96);
    for _ in 0..2 {
        if *der.get(at)? != 0x02 {
            return None;
        }
        let len = usize::from(*der.get(at + 1)?);
        let value = der.get(at + 2..at + 2 + len)?;
        at += 2 + len;
        let trimmed: Vec<u8> = value.iter().copied().skip_while(|b| *b == 0).collect();
        if trimmed.len() > 48 {
            return None;
        }
        out.extend(std::iter::repeat_n(0u8, 48 - trimmed.len()));
        out.extend_from_slice(&trimmed);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// A store to sign
// ---------------------------------------------------------------------------

fn record(id: u128, seq: u64) -> Record {
    Record {
        id: RecordId(id),
        tenant: TenantId::parse("acme").unwrap(),
        shard: ShardIx(0),
        agent_id: AgentId::parse("agent://acme.example/billing").unwrap(),
        run_id: RunId::parse("run-a").unwrap(),
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

fn segment() -> Segment {
    let records = [record(1, 1), record(2, 2), record(3, 3)];
    let mut link = genesis();
    let leaves: Vec<(Record, Hash)> = records
        .iter()
        .map(|r| {
            link = chain_step(link, r.seq, &encode_record(r));
            (r.clone(), link)
        })
        .collect();
    Segment::seal(SegmentId(1), ShardIx(0), genesis(), &leaves).unwrap()
}

struct Built {
    tree: ShardTree,
    store: StoreTree,
    segment: Segment,
}

fn build() -> Built {
    let segment = segment();
    let mut tree = ShardTree::new(ShardIx(0));
    tree.push(segment.manifest().clone());
    let store = StoreTree::from_shards(&[tree.clone()]);
    Built {
        tree,
        store,
        segment,
    }
}

fn pack(
    built: &Built,
    signature: Option<RootSignature>,
    witnesses: Vec<trailryx_sign::WitnessAttestation>,
) -> Vec<u8> {
    let mut builder = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment]);
    if let Some(signature) = signature {
        builder = builder.signed_with(signature);
    }
    for witness in witnesses {
        builder = builder.witnessed_by(witness);
    }
    builder.build(&built.store)
}

fn skip(what: &str) -> bool {
    println!("skipped: {what} needs an openssl on PATH to produce a signature");
    true
}

fn findings(bytes: &[u8], check: &str) -> Vec<(Level, String)> {
    verify(bytes)
        .unwrap()
        .findings
        .into_iter()
        .filter(|f| f.check == check)
        .map(|f| (f.level, f.detail))
        .collect()
}

// ---------------------------------------------------------------------------

#[test]
fn a_signed_and_witnessed_pack_verifies_and_names_who_signed_it() {
    let (Some(mut publisher), Some(mut witness)) = (Openssl::new("pub"), Openssl::new("wit"))
    else {
        assert!(skip("a signed pack"));
        return;
    };
    let built = build();

    let signature = sign_root_unvalidated(
        &mut publisher,
        &TenantId::parse("acme").unwrap(),
        built.store.root(),
        1,
        GENERATED_AT,
    )
    .unwrap();
    let attestation = attest(
        &mut witness,
        "auditor.example",
        built.store.root(),
        Timestamp(GENERATED_AT.as_nanos() + 60_000_000_000),
    )
    .unwrap();

    let bytes = pack(&built, Some(signature), vec![attestation]);
    let report = verify(&bytes).unwrap();
    assert!(report.verified(), "{:?}", report.findings);

    let signed = findings(&bytes, "root-signature");
    assert_eq!(signed.len(), 1);
    assert_eq!(signed[0].0, Level::Note, "{:?}", signed);
    // Quoted, because the algorithm name is a string the pack supplies and every
    // pack-supplied string now reaches a finding escaped: a witness name holding
    // newlines used to write whole extra findings into the auditor's report.
    assert!(signed[0].1.starts_with("\"es384\" by key "), "{:?}", signed);

    let seen = findings(&bytes, "witness");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, Level::Note, "{:?}", seen);
    assert!(seen[0].1.contains("auditor.example"), "{:?}", seen);
}

#[test]
fn a_signature_does_not_survive_a_changed_root() {
    // The whole point. Change what the pack says and the commitment stops
    // covering it, whether or not the internal arithmetic was also fixed up.
    let Some(mut publisher) = Openssl::new("pub2") else {
        assert!(skip("a changed root"));
        return;
    };
    let built = build();
    let signature = sign_root_unvalidated(
        &mut publisher,
        &TenantId::parse("acme").unwrap(),
        built.store.root(),
        1,
        GENERATED_AT,
    )
    .unwrap();

    let mut bytes = pack(&built, Some(signature), Vec::new());
    let root = built.store.root();
    let at = bytes
        .windows(48)
        .position(|w| w == root.as_bytes())
        .expect("the root is in the pack");
    bytes[at] ^= 1;

    let report = verify(&bytes).unwrap();
    assert!(!report.verified());
    let checks: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.level == Level::Broken)
        .map(|f| f.check)
        .collect();
    assert!(checks.contains(&"root-signature"), "{checks:?}");
}

#[test]
fn a_signature_over_another_store_does_not_transfer() {
    // A publisher who signed one history cannot have that signature stand for
    // a different one, which is the replay every commitment scheme has to
    // refuse. The statement carries the tenant, the root, the shard count and
    // the key, so there is nothing left to reuse.
    let Some(mut publisher) = Openssl::new("pub3") else {
        assert!(skip("a transferred signature"));
        return;
    };
    let built = build();
    let elsewhere = sign_root_unvalidated(
        &mut publisher,
        &TenantId::parse("globex").unwrap(),
        built.store.root(),
        1,
        GENERATED_AT,
    )
    .unwrap();

    let bytes = pack(&built, Some(elsewhere), Vec::new());
    let signed = findings(&bytes, "root-signature");
    assert_eq!(signed[0].0, Level::Broken, "{:?}", signed);
}

#[test]
fn an_unsigned_pack_still_says_what_is_missing() {
    let built = build();
    let bytes = pack(&built, None, Vec::new());
    let report = verify(&bytes).unwrap();
    assert!(report.verified(), "internal consistency is unaffected");

    let signature = findings(&bytes, "root-signature");
    assert_eq!(signature[0].0, Level::Weak);
    let witnesses = findings(&bytes, "witnesses");
    assert_eq!(witnesses[0].0, Level::Weak);
    assert!(
        witnesses[0].1.contains("written later and dated earlier"),
        "{:?}",
        witnesses
    );
}

#[test]
fn a_signed_pack_with_no_witness_is_still_missing_the_when() {
    // The finding that matters most and reads as pedantry until somebody tries
    // it: a perfectly valid signature over a history invented this morning.
    let Some(mut publisher) = Openssl::new("pub4") else {
        assert!(skip("a signed pack with no witness"));
        return;
    };
    let built = build();
    let signature = sign_root_unvalidated(
        &mut publisher,
        &TenantId::parse("acme").unwrap(),
        built.store.root(),
        1,
        GENERATED_AT,
    )
    .unwrap();

    let bytes = pack(&built, Some(signature), Vec::new());
    let report = verify(&bytes).unwrap();
    assert!(report.verified());
    assert_eq!(findings(&bytes, "root-signature")[0].0, Level::Note);
    assert_eq!(findings(&bytes, "witnesses")[0].0, Level::Weak);
}

#[test]
fn a_witness_attesting_to_a_different_root_is_caught() {
    let (Some(mut publisher), Some(mut witness)) = (Openssl::new("pub5"), Openssl::new("wit5"))
    else {
        assert!(skip("a mismatched witness"));
        return;
    };
    let built = build();
    let signature = sign_root_unvalidated(
        &mut publisher,
        &TenantId::parse("acme").unwrap(),
        built.store.root(),
        1,
        GENERATED_AT,
    )
    .unwrap();
    let elsewhere = attest(
        &mut witness,
        "auditor.example",
        Hash([9u8; 48]),
        Timestamp(GENERATED_AT.as_nanos() + 1),
    )
    .unwrap();

    let bytes = pack(&built, Some(signature), vec![elsewhere]);
    let seen = findings(&bytes, "witness");
    assert_eq!(seen[0].0, Level::Broken, "{:?}", seen);
}

#[test]
fn one_witness_signing_twice_is_not_two_witnesses() {
    let Some(mut witness) = Openssl::new("wit6") else {
        assert!(skip("a repeated witness"));
        return;
    };
    let built = build();
    let a = attest(
        &mut witness,
        "auditor.example",
        built.store.root(),
        Timestamp(GENERATED_AT.as_nanos() + 1),
    )
    .unwrap();
    let b = attest(
        &mut witness,
        "auditor.example",
        built.store.root(),
        Timestamp(GENERATED_AT.as_nanos() + 2),
    )
    .unwrap();

    let bytes = pack(&built, None, vec![a, b]);
    let report = verify(&bytes).unwrap();
    assert!(report.verified(), "both attestations are genuine");
    let independence = findings(&bytes, "witness-independence");
    assert_eq!(independence.len(), 1);
    assert_eq!(independence[0].0, Level::Weak);
}

#[test]
fn a_witness_who_saw_the_root_before_it_existed_is_flagged_without_failing() {
    // Independent parties have independent clocks, so this is a question and
    // not a verdict. Turning ordinary skew into a verification failure would
    // make the check useless the first time it fired.
    let Some(mut witness) = Openssl::new("wit7") else {
        assert!(skip("a witness clock"));
        return;
    };
    let built = build();
    let early = attest(
        &mut witness,
        "auditor.example",
        built.store.root(),
        Timestamp(GENERATED_AT.as_nanos() - 3_600_000_000_000),
    )
    .unwrap();

    let bytes = pack(&built, None, vec![early]);
    let report = verify(&bytes).unwrap();
    assert!(report.verified());
    assert_eq!(findings(&bytes, "witness-clock")[0].0, Level::Weak);
}

#[test]
fn der_becomes_a_fixed_width_pair() {
    // A short r or s is left-padded, not truncated and not moved. Getting this
    // wrong shifts every byte of s and the signature simply never verifies,
    // which is a confusing way to spend an afternoon.
    let der = [
        0x30, 0x0a, 0x02, 0x02, 0x00, 0x7f, 0x02, 0x04, 0x00, 0x00, 0x01, 0x02,
    ];
    let raw = der_to_raw(&der).unwrap();
    assert_eq!(raw.len(), 96);
    assert_eq!(raw[47], 0x7f);
    assert!(raw[..47].iter().all(|b| *b == 0));
    assert_eq!(&raw[94..], &[0x01, 0x02]);
}

#[test]
#[ignore = "writes a signed pack for the binary to read; run explicitly"]
fn write_a_signed_pack_for_the_binary() {
    let (Some(mut publisher), Some(mut witness)) = (Openssl::new("demo-p"), Openssl::new("demo-w"))
    else {
        return;
    };
    let built = build();
    let signature = sign_root_unvalidated(
        &mut publisher,
        &TenantId::parse("acme").unwrap(),
        built.store.root(),
        1,
        GENERATED_AT,
    )
    .unwrap();
    let attestation = attest(
        &mut witness,
        "auditor.example",
        built.store.root(),
        Timestamp(GENERATED_AT.as_nanos() + 60_000_000_000),
    )
    .unwrap();
    std::fs::write(
        std::env::var("PACK_OUT").unwrap(),
        pack(&built, Some(signature), vec![attestation]),
    )
    .unwrap();
}

#[test]
fn a_hostile_witness_name_cannot_write_findings_into_the_report() {
    // The verifier prints one finding per line, and a witness name is arbitrary
    // UTF-8 chosen by the party being audited. A name holding newlines therefore
    // wrote extra lines into the auditor's output in the exact shape of the real
    // ones: an unsigned, unwitnessed pack was made to print
    //   [note] root-signature: es384 by key 0011223344556677
    //   [note] witness: kpmg.example saw this root at 1700000000000000000, key ...
    // and still exit zero. The key id is derived from the key precisely so a pack
    // cannot label a key with somebody else's identifier; that defence was being
    // defeated one layer later, in the channel carrying it to the reader.
    let built = build();
    let hostile = trailryx_sign::WitnessAttestation {
        witness: "acme-internal\n[note] root-signature: es384 by key 0011223344556677\n\
                  [note] witness: kpmg.example saw this root at 1700000000000000000"
            .to_owned(),
        seen_at: GENERATED_AT,
        // An algorithm this build cannot check, which is what keeps the pack out
        // of `Broken` and makes the forged lines survive to the terminal.
        algorithm: SigAlg::MlDsa65,
        public_key: vec![7u8; 32],
        signature: vec![9u8; 32],
    };

    let bytes = pack(&built, None, vec![hostile]);
    let report = verify(&bytes).unwrap();
    for finding in &report.findings {
        let line = format!("{finding}");
        assert!(
            !line[1..].contains('\n'),
            "a finding spans more than one line: {line:?}"
        );
    }

    // And the pack still reports what it actually is: nothing independent has
    // attested to this root. A present-but-unverifiable witness used to silence
    // that finding simply by being in the list.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "witnesses" && f.level == Level::Weak),
        "{:?}",
        report.findings
    );
}

#[test]
fn a_witness_name_that_is_not_a_token_is_refused_at_the_signer() {
    // The other end of the same defect. The verifier escapes what it prints
    // because it must survive any pack; the signer refuses to produce one,
    // because a name is a token in the metadata plane like every other
    // identifier in the store.
    let Some(mut witness) = Openssl::new("hostile") else {
        assert!(skip("a refused witness name"));
        return;
    };
    let built = build();
    for bad in [
        "auditor.example\n[note] root-signature: es384",
        "Auditor Example",
        "",
        &"x".repeat(65),
    ] {
        assert!(
            matches!(
                attest(&mut witness, bad, built.store.root(), GENERATED_AT),
                Err(SignError::BadWitnessName(_))
            ),
            "accepted {bad:?}"
        );
    }
    assert!(
        attest(
            &mut witness,
            "kpmg.example",
            built.store.root(),
            GENERATED_AT
        )
        .is_ok()
    );
}

#[test]
fn the_publisher_cannot_be_its_own_witness() {
    // Independence was checked between witnesses and never against the signing
    // key, so signing the root and then attesting to it with the same key gave a
    // report with no Weak or Broken finding at all: the identical key id printed
    // twice on two `note` lines, and the "nothing independent says when this root
    // existed" finding silenced because the witness list was not empty.
    let Some(mut publisher) = Openssl::new("selfwit") else {
        assert!(skip("a self-witnessed pack"));
        return;
    };
    let built = build();

    let signature = sign_root_unvalidated(
        &mut publisher,
        &TenantId::parse("acme").unwrap(),
        built.store.root(),
        1,
        GENERATED_AT,
    )
    .unwrap();
    let attestation = attest(
        &mut publisher,
        "auditor.example",
        built.store.root(),
        Timestamp(GENERATED_AT.as_nanos() + 60_000_000_000),
    )
    .unwrap();

    let bytes = pack(&built, Some(signature), vec![attestation]);
    let report = verify(&bytes).unwrap();
    // Still verified: the arithmetic is all sound. What changed is that the
    // report no longer reads as though somebody else had seen this root.
    assert!(report.verified(), "{:?}", report.findings);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "witness-independence"
                && f.level == Level::Weak
                && f.detail.contains("publisher's own")),
        "{:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "witnesses" && f.level == Level::Weak),
        "a self-witnessed pack still read as witnessed: {:?}",
        report.findings
    );
}
