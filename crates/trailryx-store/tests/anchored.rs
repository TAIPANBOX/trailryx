//! A pack with a real timestamp token in it, verified end to end.
//!
//! This is where the two independent readers of a token are pinned to agree.
//! `trailryx-anchor` obtains and fully verifies the token, using
//! `trailryx-asn1`; the offline verifier reads it again with its own ninety-line
//! reader, because that crate has no dependencies on purpose. Two readers of the
//! same bytes are two chances to disagree, so a real token from a real authority
//! goes through both.
//!
//! What each one is responsible for is different, and the tests say so:
//!
//! - `trailryx-anchor` checks the CMS signature against a pinned key. That is
//!   the cryptographic claim.
//! - the verifier checks that the token commits to **this** pack's root, and
//!   reports out loud that it did not check the signature.
//!
//! The authority is OpenSSL, run locally. If `openssl ts` is unusable the tests
//! say they skipped, and which tool was missing.

use std::path::{Path, PathBuf};
use std::process::Command;

use trailryx_anchor::{Rfc3161, Transport, Trust, tsp};
use trailryx_contracts::contracts::Anchor as _;
use trailryx_crypto::{Sha384, chain_step};
use trailryx_index::segment::{Segment, ShardTree, StoreTree};
use trailryx_journal::wire::encode_record;
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};
use trailryx_store::evidence::PackBuilder;
use trailryx_verify::{Level, verify};

const GENERATED_AT: Timestamp = Timestamp(1_700_000_000_000_000_000);
const NONCE: u64 = 0x0BAD_C0DE_1234_5678;

// ---------------------------------------------------------------------------
// A local authority, made of OpenSSL
// ---------------------------------------------------------------------------

struct Tsa {
    dir: PathBuf,
    public_key: Vec<u8>,
}

impl Drop for Tsa {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[derive(Debug, Clone)]
struct TsaClient {
    dir: PathBuf,
}

fn run(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|e| format!("openssl did not start: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "openssl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

fn have_openssl_ts() -> bool {
    Command::new("openssl")
        .args(["ts", "-help"])
        .output()
        .is_ok_and(|o| {
            let text = String::from_utf8_lossy(&o.stderr).to_lowercase()
                + &String::from_utf8_lossy(&o.stdout).to_lowercase();
            text.contains("-reply")
        })
}

const TSA_CONF: &str = "\
[ req ]
distinguished_name = dn
prompt = no
x509_extensions = tsa_ext

[ dn ]
CN = Trailryx Pack Test TSA

[ tsa_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping

[ tsa ]
default_tsa = tsa_config

[ tsa_config ]
serial = ./tsa_serial
crypto_device = builtin
signer_cert = ./tsa.pem
certs = ./tsa.pem
signer_key = ./tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
ess_cert_id_alg = sha256
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
";

impl Tsa {
    fn new(name: &str) -> Option<Self> {
        let dir = std::env::temp_dir().join(format!("trailryx-pack-tsa-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok()?;
        std::fs::write(dir.join("tsa.cnf"), TSA_CONF).ok()?;
        std::fs::write(dir.join("tsa_serial"), "01\n").ok()?;
        run(
            &dir,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-noenc",
                "-keyout",
                "tsa.key",
                "-out",
                "tsa.pem",
                "-days",
                "2",
                "-config",
                "tsa.cnf",
                "-extensions",
                "tsa_ext",
            ],
        )
        .ok()?;
        run(
            &dir,
            &[
                "x509", "-in", "tsa.pem", "-pubkey", "-noout", "-out", "tsa.pub",
            ],
        )
        .ok()?;
        run(
            &dir,
            &[
                "pkey",
                "-pubin",
                "-in",
                "tsa.pub",
                "-outform",
                "DER",
                "-out",
                "tsa.pub.der",
            ],
        )
        .ok()?;
        let public_key = std::fs::read(dir.join("tsa.pub.der")).ok()?;
        Some(Self { dir, public_key })
    }

    fn key(&self) -> trailryx_anchor::RsaPublicKey {
        trailryx_anchor::RsaPublicKey::from_spki(&self.public_key).expect("OpenSSL's own key")
    }

    fn client(&self) -> TsaClient {
        TsaClient {
            dir: self.dir.clone(),
        }
    }
}

impl Transport for TsaClient {
    fn exchange(&mut self, query: &[u8]) -> Result<Vec<u8>, String> {
        std::fs::write(self.dir.join("query.tsq"), query).map_err(|e| e.to_string())?;
        run(
            &self.dir,
            &[
                "ts",
                "-reply",
                "-config",
                "tsa.cnf",
                "-queryfile",
                "query.tsq",
                "-out",
                "reply.tsr",
            ],
        )?;
        std::fs::read(self.dir.join("reply.tsr")).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// A pack, the smallest one that verifies
// ---------------------------------------------------------------------------

fn genesis() -> Hash {
    Sha384::digest(b"trailryx-test/segment-genesis")
}

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

struct Built {
    tree: ShardTree,
    store: StoreTree,
    segment: Segment,
}

fn build() -> Built {
    let records = [record(1, 1), record(2, 2), record(3, 3)];
    let mut link = genesis();
    let leaves: Vec<(Record, Hash)> = records
        .iter()
        .map(|r| {
            link = chain_step(link, r.seq, &encode_record(r));
            (r.clone(), link)
        })
        .collect();
    let segment = Segment::seal(SegmentId(1), ShardIx(0), genesis(), &leaves).unwrap();
    let mut tree = ShardTree::new(ShardIx(0));
    tree.push(segment.manifest().clone());
    let store = StoreTree::from_shards(&[tree.clone()]);
    Built {
        tree,
        store,
        segment,
    }
}

fn findings(bytes: &[u8], check: &str) -> Vec<(Level, String)> {
    verify(bytes)
        .expect("the pack parses")
        .findings
        .into_iter()
        .filter(|f| f.check == check)
        .map(|f| (f.level, f.detail))
        .collect()
}

fn skip(what: &str) {
    println!("skipped: {what} needs a usable `openssl ts`");
}

/// Obtain a token over `root` from a fresh authority.
fn anchor_over(name: &str, root: Hash) -> Option<(Tsa, Vec<u8>)> {
    let tsa = Tsa::new(name)?;
    let mut anchor = Rfc3161::new(
        Box::new(tsa.client()),
        Trust::PinnedKey(tsa.key()),
        Box::new(|| NONCE),
    );
    let receipt = anchor.submit(root).ok()?;
    Some((tsa, receipt.evidence))
}

// ---------------------------------------------------------------------------
// The happy path, and what each side is responsible for
// ---------------------------------------------------------------------------

/// A pack carrying a token over its own root: the verifier confirms the binding
/// and says plainly that it did not check the signature.
#[test]
fn a_pack_anchored_over_its_own_root_verifies_and_names_what_it_did_not_check() {
    if !have_openssl_ts() {
        return skip("an anchored pack");
    }
    let built = build();
    let root = built.store.root();
    let Some((tsa, token)) = anchor_over("happy", root) else {
        return skip("an anchored pack");
    };

    let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .anchored_by("test-tsa", root, NONCE, token.clone())
        .build(&built.store);

    let anchors = findings(&bytes, "anchor");
    assert_eq!(anchors.len(), 1, "{anchors:?}");
    assert_eq!(anchors[0].0, Level::Note, "{anchors:?}");
    assert!(
        anchors[0].1.contains("test-tsa") && anchors[0].1.contains("stamped this root"),
        "{anchors:?}"
    );
    // The token's own nonce matched the challenge the pack recorded, so nothing
    // says freshness could not be checked.
    assert!(
        findings(&bytes, "anchor-freshness").is_empty(),
        "the nonce should have matched: {:?}",
        findings(&bytes, "anchor-freshness")
    );

    // The verifier must not imply it checked the signature. This is the finding
    // that keeps it honest, and it is a `weak` rather than a note because a
    // reader who stops at the notes should still see it.
    let unchecked = findings(&bytes, "anchor-signature");
    assert_eq!(unchecked.len(), 1, "{unchecked:?}");
    assert_eq!(unchecked[0].0, Level::Weak);
    assert!(
        unchecked[0].1.contains("did not check") && unchecked[0].1.contains("openssl ts -verify"),
        "the finding must say what was not checked and how to check it: {unchecked:?}"
    );

    // And the other reader, in the crate that does check it.
    let attested = tsp::attest(&token, &tsa.key()).expect("the signature verifies");
    assert!(
        tsp::binds_to(&attested.claim, &tsp::imprint_of(root.as_bytes()), NONCE).is_ok(),
        "the fully verifying reader must agree the token is over this root"
    );
}

/// Both readers on the same bytes must reach the same conclusion about what the
/// token stamped. Two readers are two chances to disagree, and this is the test
/// that would catch it.
#[test]
fn the_verifiers_reader_and_the_anchor_crates_reader_agree_on_the_imprint() {
    if !have_openssl_ts() {
        return skip("cross-checking the two token readers");
    }
    let built = build();
    let root = built.store.root();
    let Some((tsa, token)) = anchor_over("agree", root) else {
        return skip("cross-checking the two token readers");
    };

    let mine = trailryx_verify::tsp::read(&token).expect("the verifier reads it");
    let theirs = tsp::attest(&token, &tsa.key()).expect("the anchor crate verifies it");

    assert_eq!(
        mine.imprint, theirs.claim.imprint,
        "the two readers disagree about what the authority stamped"
    );
    assert_eq!(
        mine.at, theirs.claim.at,
        "the two readers disagree about when"
    );
    assert!(mine.covers(&{
        let mut h = [0u8; 48];
        h.copy_from_slice(root.as_bytes());
        h
    }));
}

// ---------------------------------------------------------------------------
// The cases a verifier exists for
// ---------------------------------------------------------------------------

/// The store says the token is about this root and the token says otherwise. A
/// pack must never be allowed to describe its own evidence, and this is the
/// shape that attack takes.
#[test]
fn a_token_over_another_root_presented_as_this_one_is_broken_and_not_a_note() {
    if !have_openssl_ts() {
        return skip("a mislabelled anchor");
    }
    let built = build();
    let root = built.store.root();
    let other = Hash([0x99u8; 48]);
    let Some((_tsa, token)) = anchor_over("mislabelled", other) else {
        return skip("a mislabelled anchor");
    };

    // The pack claims the anchor covers its own root. The token disagrees.
    let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .anchored_by("lying-tsa", root, NONCE, token)
        .build(&built.store);

    let anchors = findings(&bytes, "anchor");
    assert_eq!(anchors.len(), 1, "{anchors:?}");
    assert_eq!(
        anchors[0].0,
        Level::Broken,
        "a token that stamps a different digest must be BROKEN: {anchors:?}"
    );
    assert!(
        anchors[0].1.contains("false"),
        "the finding should say the pack's own description is false: {anchors:?}"
    );
    assert!(
        !verify(&bytes).expect("parses").verified(),
        "a pack whose own description of its evidence is false must not verify"
    );
}

/// An anchor over a root that is not this pack's root proves nothing about this
/// pack, however valid the token is.
#[test]
fn an_anchor_declaring_a_root_this_pack_does_not_have_is_broken() {
    if !have_openssl_ts() {
        return skip("an anchor over a foreign root");
    }
    let built = build();
    let other = Hash([0x77u8; 48]);
    let Some((_tsa, token)) = anchor_over("foreign", other) else {
        return skip("an anchor over a foreign root");
    };

    let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .anchored_by("other-tsa", other, NONCE, token)
        .build(&built.store);

    let anchors = findings(&bytes, "anchor");
    assert_eq!(anchors.len(), 1, "{anchors:?}");
    assert_eq!(anchors[0].0, Level::Broken, "{anchors:?}");
    assert!(anchors[0].1.contains("another history"), "{anchors:?}");
}

/// A pack that carries something it calls a token and is not one.
#[test]
fn an_unreadable_token_is_broken_rather_than_ignored() {
    let built = build();
    let root = built.store.root();
    for junk in [
        vec![],
        vec![0x30, 0x80, 0x00, 0x00],
        b"not der at all".to_vec(),
        vec![0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
    ] {
        let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
            .shard(&built.tree, &[&built.segment])
            .anchored_by("junk-tsa", root, NONCE, junk.clone())
            .build(&built.store);
        let anchors = findings(&bytes, "anchor");
        assert_eq!(anchors.len(), 1, "{junk:?} -> {anchors:?}");
        assert_eq!(
            anchors[0].0,
            Level::Broken,
            "{} bytes of junk must be BROKEN: {anchors:?}",
            junk.len()
        );
    }
}

/// Every truncation of a real token must be refused, and none may panic. The
/// pack comes from the party being audited.
#[test]
fn every_truncation_of_a_real_token_is_refused_and_never_panics() {
    if !have_openssl_ts() {
        return skip("the truncation sweep over a real token in a pack");
    }
    let built = build();
    let root = built.store.root();
    let Some((_tsa, token)) = anchor_over("truncate", root) else {
        return skip("the truncation sweep over a real token in a pack");
    };

    // Stepped rather than exhaustive: each step builds and verifies a whole pack,
    // and every tenth byte covers every field boundary in a token this size.
    for cut in (0..token.len()).step_by(10) {
        let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
            .shard(&built.tree, &[&built.segment])
            .anchored_by("cut-tsa", root, NONCE, token[..cut].to_vec())
            .build(&built.store);
        let anchors = findings(&bytes, "anchor");
        assert_eq!(anchors.len(), 1, "cut at {cut}: {anchors:?}");
        assert_eq!(
            anchors[0].0,
            Level::Broken,
            "a token cut at {cut} bytes was not refused: {anchors:?}"
        );
    }
}

/// With an anchor present, the verifier must stop saying nothing independent
/// places this root in time. Without one, it must keep saying it.
#[test]
fn an_anchor_answers_the_finding_that_nothing_places_this_root_in_time() {
    if !have_openssl_ts() {
        return skip("the interaction between anchors and the witness finding");
    }
    let built = build();
    let root = built.store.root();

    let bare = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .build(&built.store);
    assert_eq!(
        findings(&bare, "witnesses").len(),
        1,
        "an unanchored, unwitnessed pack must say nothing places it in time"
    );

    let Some((_tsa, token)) = anchor_over("answers", root) else {
        return skip("the interaction between anchors and the witness finding");
    };
    let anchored = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .anchored_by("test-tsa", root, NONCE, token)
        .build(&built.store);
    assert!(
        findings(&anchored, "witnesses").is_empty(),
        "a bound anchor does place the root in time, so the finding should be gone: {:?}",
        findings(&anchored, "witnesses")
    );
}

/// A nonce that does not match the recorded challenge is a replay this pack cannot
/// rule out, and the verifier must say so rather than reporting the anchor as good.
#[test]
fn a_token_whose_nonce_disagrees_with_the_recorded_challenge_is_broken() {
    if !have_openssl_ts() {
        return skip("the nonce cross-check");
    }
    let built = build();
    let root = built.store.root();
    let Some((_tsa, token)) = anchor_over("nonce", root) else {
        return skip("the nonce cross-check");
    };

    // The token echoes NONCE. The pack claims a different challenge was sent.
    let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .anchored_by("swapped-tsa", root, NONCE ^ 1, token)
        .build(&built.store);

    let anchors = findings(&bytes, "anchor");
    assert_eq!(anchors.len(), 1, "{anchors:?}");
    assert_eq!(anchors[0].0, Level::Broken, "{anchors:?}");
    assert!(anchors[0].1.contains("different nonce"), "{anchors:?}");
}

/// An anchor of a kind this build does not read is reported as unread, never as
/// broken. A pack anchored by something newer must not be condemned by an older
/// verifier, which is the rule already applied to signature algorithms.
#[test]
fn an_anchor_kind_this_build_cannot_read_is_unread_and_not_broken() {
    let built = build();
    let root = built.store.root();
    for (kind, name) in [
        (
            trailryx_store::evidence::ANCHOR_TRANSPARENCY_LOG,
            "transparency log",
        ),
        (
            trailryx_store::evidence::ANCHOR_SIGNED_ARTIFACT,
            "signed artifact",
        ),
        (200u8, "an unknown kind"),
    ] {
        let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
            .shard(&built.tree, &[&built.segment])
            .anchored(
                kind,
                "future-party",
                "slh-dsa-sha2-128s",
                root,
                Vec::new(),
                b"evidence this build does not parse".to_vec(),
            )
            .build(&built.store);

        let anchors = findings(&bytes, "anchor");
        assert_eq!(anchors.len(), 1, "{name}: {anchors:?}");
        assert_eq!(
            anchors[0].0,
            Level::Weak,
            "{name} must be unread, not broken: {anchors:?}"
        );
        assert!(anchors[0].1.contains(name), "{name}: {anchors:?}");
        assert!(
            verify(&bytes).expect("parses").verified(),
            "{name}: an unread anchor must not stop a pack verifying"
        );
    }
}

/// A version 2 pack has no anchors and must still verify. A pack written by an
/// older commit keeps verifying, which is the same promise the frozen record
/// format makes.
#[test]
fn a_version_two_pack_still_parses() {
    let built = build();
    let mut bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .build(&built.store);
    assert_eq!(bytes[7], 3, "this build writes version 3");
    bytes[7] = 2;
    let report = verify(&bytes).expect("a version 2 pack must still parse");
    assert!(
        report.findings.iter().all(|f| f.check != "anchor"),
        "a version 2 pack has no anchors"
    );

    bytes[7] = 4;
    assert!(
        verify(&bytes).is_err(),
        "a version this build does not know must be refused rather than half-read"
    );
}

// ---------------------------------------------------------------------------
// What the coverage layer makes of a real pack
// ---------------------------------------------------------------------------
//
// The mapping is derived from the verifier's findings, so the only honest input to
// it is a pack somebody actually built. These assertions are here rather than in
// `trailryx-compliance` because that is where the packs are.

use trailryx_compliance::{Coverage, Framework, Requirement, assess, render};

/// An anchored pack must satisfy the attestation requirement, and the same pack
/// without the anchor must not. That difference is the whole reason the layer
/// derives its answers instead of declaring them.
#[test]
fn coverage_changes_when_the_evidence_changes() {
    if !have_openssl_ts() {
        return skip("the coverage layer against a real anchored pack");
    }
    let built = build();
    let root = built.store.root();
    let Some((_tsa, token)) = anchor_over("coverage", root) else {
        return skip("the coverage layer against a real anchored pack");
    };

    let bare = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .build(&built.store);
    let anchored = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .anchored_by("test-tsa", root, NONCE, token)
        .build(&built.store);

    let bare_report = verify(&bare).expect("parses");
    let anchored_report = verify(&anchored).expect("parses");

    // The requirement the anchor exists to satisfy, asked directly. This is the
    // difference the anchor makes and it is measurable on its own.
    assert!(
        !Requirement::TimeAttested.satisfied_by(&bare_report),
        "an unanchored, unwitnessed pack must not count as attested"
    );
    assert!(
        Requirement::TimeAttested.satisfied_by(&anchored_report),
        "a pack with a bound token must count as attested"
    );

    // And the count does NOT move, which is the more interesting fact. The one
    // obligation needing an attestation needs a signed root first, and this
    // fixture is unsigned, so the anchor changes what is missing without changing
    // how much is shown. An earlier version of this test asserted the count went
    // up and was wrong about the fixture rather than about the design.
    let without = assess(&bare_report);
    let with = assess(&anchored_report);
    assert_eq!(
        with.shown(),
        without.shown(),
        "an unsigned pack cannot demonstrate the integrity obligation either way"
    );

    let integrity = |a: &trailryx_compliance::Assessment| {
        a.for_framework(Framework::Soc2)
            .find(|l| l.obligation.reference.starts_with("Integrity"))
            .map(|l| l.coverage)
            .expect("the obligation is in the mapping")
    };
    // Both report the same first missing piece, and it is the signature.
    for (name, coverage) in [
        ("bare", integrity(&without)),
        ("anchored", integrity(&with)),
    ] {
        assert_eq!(
            coverage,
            Coverage::NotInThisPack(Requirement::SignedRoot),
            "{name}: the missing piece should be named as the signature"
        );
    }
}

/// A broken pack must demonstrate nothing, and the rendered report must say so
/// rather than printing a table a reader could quote out of context.
#[test]
fn a_broken_pack_shows_nothing_and_the_report_stays_honest() {
    let built = build();
    let mut bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .anchored_by("junk-tsa", built.store.root(), NONCE, vec![0x30, 0x00])
        .build(&built.store);
    // Also corrupt a record, so the pack fails on its own arithmetic and not only
    // on the anchor.
    let at = bytes.len() - 40;
    bytes[at] ^= 0xFF;

    let report = verify(&bytes).expect("parses");
    assert!(!report.verified());
    let assessment = assess(&report);
    assert_eq!(assessment.shown(), 0, "a broken pack demonstrates nothing");

    let text = render(&assessment).to_lowercase();
    assert!(text.contains("not legal advice"));
    assert!(!text.contains("compliant"));
    assert!(!text.contains("conforms to"));
}

/// Every framework appears in the rendered report, including the draft standard
/// and including the obligations nothing bears on. A report that printed only the
/// wins is a report somebody will quote as complete.
#[test]
fn the_rendered_report_names_every_framework_and_every_no() {
    let built = build();
    let bytes = PackBuilder::new(TenantId::parse("acme").unwrap(), GENERATED_AT)
        .shard(&built.tree, &[&built.segment])
        .build(&built.store);
    let text = render(&assess(&verify(&bytes).expect("parses")));

    for framework in [
        Framework::EuAiAct,
        Framework::PrEn24970,
        Framework::Sr117,
        Framework::Soc2,
    ] {
        assert!(
            text.contains(framework.name()),
            "{} is missing from the report",
            framework.name()
        );
    }
    for reference in ["Article 12(3)", "Article 19(1)", "Article 113"] {
        assert!(text.contains(reference), "{reference} is missing");
    }
    assert!(text.contains("[not addressed]"));
    assert!(text.contains("[operator]"));
    assert!(text.contains("not cited in the Official Journal"));
}
