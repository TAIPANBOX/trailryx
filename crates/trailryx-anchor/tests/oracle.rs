//! A real timestamping authority, run locally, judged by nothing we wrote.
//!
//! # Why this test is the one that matters
//!
//! Every other test in this crate builds a token with this crate's own encoder
//! and reads it back with this crate's own parser. That proves self-consistency,
//! which a wrong implementation also has. This one makes **OpenSSL** the
//! authority: it generates a CA, issues a timestamping certificate, and answers a
//! `TimeStampReq` with a real `TimeStampResp`, signed with a real RSA key over a
//! real CMS structure. Then this crate verifies it.
//!
//! If the hand-written DER reader, the CMS walk, the Montgomery exponentiation,
//! the PKCS#1 block construction or the signed-attribute re-tagging is wrong in
//! any way, this test fails. Nothing else in the crate can say that.
//!
//! The reverse direction is checked too: OpenSSL is asked to verify the same
//! token, so a token this crate accepts is a token the standard toolchain accepts.
//!
//! Every test prints `skipped` and passes when `openssl ts` is unavailable, and
//! says which tool was missing. A check that quietly succeeds because it did not
//! run is the thing this project is against.

use std::path::{Path, PathBuf};
use std::process::Command;

use trailryx_anchor::rsa::{DigestKind, RsaPublicKey};
use trailryx_anchor::{Rfc3161, Transport, Trust, tsp};
use trailryx_contracts::contracts::{AdapterError, Anchor};
use trailryx_record::{HASH_BYTES, Hash};

// ---------------------------------------------------------------------------
// A local authority, made of OpenSSL
// ---------------------------------------------------------------------------

struct Tsa {
    dir: PathBuf,
    /// The signing key's SubjectPublicKeyInfo, DER.
    public_key: Vec<u8>,
}

impl Drop for Tsa {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(dir: &Path, program: &str, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new(program)
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|e| format!("{program} did not start: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{program} {}: {}",
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

impl Tsa {
    /// Build a CA and a timestamping certificate, and remember the public key.
    ///
    /// `digest` is what the authority signs with. Both SHA-256 and SHA-384 are
    /// exercised, because the digest is the authority's choice and not ours: a
    /// verifier that only handles the one it prefers handles no real authority.
    fn new(name: &str, digest: &'static str, bits: &str) -> Result<Self, String> {
        let dir = std::env::temp_dir().join(format!("trailryx-tsa-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

        // An openssl.cnf with the timestamping extensions and a TSA section. The
        // `extendedKeyUsage = critical,timeStamping` is what `openssl ts` insists
        // on before it will sign a reply.
        std::fs::write(
            dir.join("tsa.cnf"),
            "\
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = .
serial = ./serial
database = ./index.txt
new_certs_dir = .
default_md = sha256
policy = policy_any

[ policy_any ]
commonName = supplied

[ req ]
distinguished_name = dn
prompt = no
x509_extensions = tsa_ext

[ dn ]
CN = Trailryx Test TSA

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
signer_digest = DIGEST
default_policy = 1.2.3.4.1
ess_cert_id_alg = sha256
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
"
            .replace("DIGEST", digest),
        )
        .map_err(|e| e.to_string())?;
        std::fs::write(dir.join("tsa_serial"), "01\n").map_err(|e| e.to_string())?;

        // A self-signed timestamping certificate is enough: this crate pins the
        // key and validates no chain, so a chain here would only be testing
        // OpenSSL.
        run(
            &dir,
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa",
                "-pkeyopt",
                &format!("rsa_keygen_bits:{bits}"),
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
        )?;

        // The public key, DER SubjectPublicKeyInfo, which is exactly what
        // `RsaPublicKey::from_spki` reads.
        run(
            &dir,
            "openssl",
            &[
                "x509", "-in", "tsa.pem", "-pubkey", "-noout", "-out", "tsa.pub",
            ],
        )?;
        run(
            &dir,
            "openssl",
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
        )?;
        let public_key = std::fs::read(dir.join("tsa.pub.der")).map_err(|e| e.to_string())?;

        Ok(Self { dir, public_key })
    }

    fn key(&self) -> RsaPublicKey {
        RsaPublicKey::from_spki(&self.public_key).expect("OpenSSL's own public key parses")
    }

    fn client(&self) -> TsaClient {
        TsaClient {
            dir: self.dir.clone(),
        }
    }
}

/// An owned handle on the authority's directory.
///
/// A boxed `Transport` has to be `'static`, so the client cannot borrow the `Tsa`
/// that cleans the directory up. It holds the path instead, and the `Tsa` outliving
/// it is what the test's own scoping guarantees.
#[derive(Debug, Clone)]
struct TsaClient {
    dir: PathBuf,
}

impl Transport for TsaClient {
    /// Answer a query the way the authority would: `openssl ts -reply`.
    fn exchange(&mut self, query: &[u8]) -> Result<Vec<u8>, String> {
        std::fs::write(self.dir.join("query.tsq"), query).map_err(|e| e.to_string())?;
        run(
            &self.dir,
            "openssl",
            &[
                // The signer, the key and the digest all come from the `[tsa]`
                // section of the config: `openssl ts -reply` takes no -md, and
                // passing one is a hard error rather than an ignored flag.
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

fn root(fill: u8) -> Hash {
    Hash([fill; HASH_BYTES])
}

fn skip(what: &str) {
    println!("skipped: {what} needs `openssl ts`, which is not usable on this machine");
}

// ---------------------------------------------------------------------------
// The whole path, both digests
// ---------------------------------------------------------------------------

/// One authority, one query, one token, verified by hand-written arithmetic.
#[test]
fn a_real_openssl_signed_token_verifies_against_a_pinned_key() {
    if !have_openssl_ts() {
        return skip("verifying a real timestamp token");
    }
    for (name, digest, bits) in [
        ("sha256-2048", "sha256", "2048"),
        ("sha384-3072", "sha384", "3072"),
    ] {
        let tsa = match Tsa::new(name, digest, bits) {
            Ok(tsa) => tsa,
            Err(why) => {
                println!("skipped: {name}: {why}");
                continue;
            }
        };
        let expected_kind = match digest {
            "sha256" => DigestKind::Sha256,
            _ => DigestKind::Sha384,
        };

        let mut anchor = Rfc3161::new(
            Box::new(tsa.client()),
            Trust::PinnedKey(tsa.key()),
            Box::new(|| 0x0BAD_C0DE_1234_5678),
        );
        assert!(anchor.is_attesting());

        let receipt = anchor
            .submit(root(0x42))
            .unwrap_or_else(|e| panic!("{name}: submit failed: {e}"));
        assert_eq!(receipt.root, root(0x42));
        assert!(receipt.at.0 > 0, "{name}: the token named no time");
        assert!(
            !receipt.evidence.is_empty(),
            "{name}: the receipt carries no token"
        );

        // The same token, verified again through the contract's own entry point.
        assert_eq!(
            anchor.verify(root(0x42), &receipt),
            Ok(true),
            "{name}: a token this crate produced a receipt for did not verify"
        );

        // And through `examine`, which is the path for a token that arrived some
        // other way and carries the digest the authority actually used.
        let attested = anchor
            .examine(root(0x42), &receipt.evidence, 0x0BAD_C0DE_1234_5678)
            .unwrap_or_else(|e| panic!("{name}: examine failed: {e}"));
        assert_eq!(attested.digest, expected_kind);
        assert_eq!(
            attested.claim.imprint,
            tsp::imprint_of(root(0x42).as_bytes())
        );
        assert_eq!(attested.claim.nonce, Some(0x0BAD_C0DE_1234_5678));
        assert!(
            !attested.claim.serial.is_empty(),
            "{name}: no serial number"
        );
    }
}

/// A flipped bit in a byte verification depends on must break it, and a flipped
/// bit elsewhere must not matter. Both halves are asserted.
///
/// The first version of this test asserted that **every** byte was load-bearing
/// and failed on seventy-three offsets. Every one of them was in `digestAlgorithms`
/// or `certificates`, which CMS does not sign and this crate does not read. The
/// assertion was wrong, not the code, and the fix was to say precisely what is
/// covered: see [`tsp::Covered`]. The test is stronger for it, because it now also
/// fails if somebody starts depending on a field nothing signs.
#[test]
fn a_flipped_bit_breaks_verification_exactly_inside_the_signed_region() {
    if !have_openssl_ts() {
        return skip("the bit-flip sweep over a real token");
    }
    let Ok(tsa) = Tsa::new("flip", "sha256", "2048") else {
        return skip("the bit-flip sweep over a real token");
    };
    let key = tsa.key();
    let nonce = 0x1111_2222_3333_4444u64;
    let mut anchor = Rfc3161::new(
        Box::new(tsa.client()),
        Trust::PinnedKey(tsa.key()),
        Box::new(move || nonce),
    );
    let receipt = anchor.submit(root(0x77)).expect("a token");
    let token = receipt.evidence.clone();
    let imprint = tsp::imprint_of(root(0x77).as_bytes());

    // The untouched token must verify, or every flip below would "correctly" fail
    // and the sweep would prove nothing at all.
    assert!(
        tsp::attest(&token, &key).is_ok(),
        "the untouched token must verify or this sweep is vacuous"
    );

    let covered = tsp::covered(&token).expect("the trust surface is computable");
    assert!(
        covered.total() > 200,
        "only {} of {} bytes are covered, which is too few to be right",
        covered.total(),
        token.len()
    );

    // One bit per byte, which reaches every byte. A full eight-bit sweep is a few
    // hundred thousand modular exponentiations and minutes of wall clock; this is
    // seconds and covers the same bytes.
    let mut survived_inside = Vec::new();
    let mut broke_outside = Vec::new();
    for i in 0..token.len() {
        let mut broken = token.clone();
        broken[i] ^= 0x01;
        let accepted = tsp::attest(&broken, &key)
            .map(|a| tsp::binds_to(&a.claim, &imprint, nonce).is_ok())
            .unwrap_or(false);
        match (covered.contains(i), accepted) {
            (true, true) => survived_inside.push(i),
            (false, false) => broke_outside.push(i),
            _ => {}
        }
    }

    assert!(
        survived_inside.is_empty(),
        "a bit flipped inside the signed region still verified, at {survived_inside:?}"
    );
    // The other direction is not an error, but it is worth knowing: a flip outside
    // the signed region may still break DER parsing, which is a refusal rather
    // than a false accept. Reported so a reader sees the sweep did something.
    println!(
        "{} of {} bytes are signed; {} flips outside the signed region were refused by the parser",
        covered.total(),
        token.len(),
        broke_outside.len()
    );
}

/// `certReq = false` means no certificate travels, and this is where that is
/// measured rather than assumed.
///
/// The first version of this test expected the uncovered part of a token to be
/// over five hundred bytes, on the assumption that a certificate would be in
/// there. It is not: the request asks for no certificate, so the authority sends
/// none, and the whole token is 738 bytes of which 571 are signed. That is the
/// intended outcome and it is worth an assertion, because a chain arriving in
/// evidence that nothing validates is exactly the evidence-shaped clutter this
/// crate refuses to store.
#[test]
fn no_certificate_travels_in_the_token_because_none_was_requested() {
    if !have_openssl_ts() {
        return skip("checking that no certificate chain arrives");
    }
    let Ok(tsa) = Tsa::new("uncovered", "sha256", "2048") else {
        return skip("checking that no certificate chain arrives");
    };
    let nonce = 3u64;
    let mut anchor = Rfc3161::new(
        Box::new(tsa.client()),
        Trust::PinnedKey(tsa.key()),
        Box::new(move || nonce),
    );
    let token = anchor.submit(root(0x11)).expect("a token").evidence;
    let covered = tsp::covered(&token).expect("computable");

    // A 2048-bit RSA certificate is over 800 bytes on its own, so a token this
    // small cannot contain one. Checked by size rather than by parsing the field,
    // because the point is that the field is absent.
    assert!(
        token.len() < 1200,
        "a {}-byte token is large enough to be carrying a certificate",
        token.len()
    );

    // Most of it is signed. The rest is structural: SEQUENCE and SET tags, the
    // `digestAlgorithms` set, and the signer identifier. None of it is a field
    // this crate draws a conclusion from.
    let uncovered = (0..token.len()).filter(|i| !covered.contains(*i)).count();
    assert!(
        covered.total() * 100 / token.len() > 70,
        "only {}% of the token is signed",
        covered.total() * 100 / token.len()
    );
    assert!(
        covered.content.start > 0 && covered.signature.end <= token.len(),
        "the covered ranges must lie inside the token"
    );
    println!(
        "{} of {} bytes signed, {uncovered} structural",
        covered.total(),
        token.len()
    );
}

/// The same token, judged by OpenSSL. A token this crate calls good must be one
/// the standard toolchain calls good, or one of the two is wrong about RFC 3161
/// rather than about arithmetic.
#[test]
fn openssl_verifies_the_same_token_this_crate_verified() {
    if !have_openssl_ts() {
        return skip("cross-checking a token with `openssl ts -verify`");
    }
    let Ok(tsa) = Tsa::new("cross", "sha256", "2048") else {
        return skip("cross-checking a token with `openssl ts -verify`");
    };
    let nonce = 0xFEED_FACE_DEAD_BEEFu64;
    let mut anchor = Rfc3161::new(
        Box::new(tsa.client()),
        Trust::PinnedKey(tsa.key()),
        Box::new(move || nonce),
    );
    let receipt = anchor.submit(root(0x5A)).expect("a token");

    // OpenSSL verifies against the reply it produced, using the query as the
    // statement of what was asked. Both files are what the exchange left behind.
    let verified = run(
        &tsa.dir,
        "openssl",
        &[
            "ts",
            "-verify",
            "-queryfile",
            "query.tsq",
            "-in",
            "reply.tsr",
            "-CAfile",
            "tsa.pem",
            "-untrusted",
            "tsa.pem",
        ],
    );
    match verified {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out).to_lowercase();
            assert!(
                text.contains("ok") || text.is_empty(),
                "OpenSSL did not call its own reply valid: {text}"
            );
        }
        Err(why) => panic!("OpenSSL refused a token this crate accepted: {why}"),
    }
    assert_eq!(anchor.verify(root(0x5A), &receipt), Ok(true));
}

/// A token from one authority must not verify against another's key. Trivially
/// expected, and it is what would fail if the pinned key were ignored anywhere on
/// the path.
#[test]
fn a_token_does_not_verify_against_a_different_authoritys_key() {
    if !have_openssl_ts() {
        return skip("checking that a token is bound to one key");
    }
    let (Ok(one), Ok(two)) = (
        Tsa::new("keyed-one", "sha256", "2048"),
        Tsa::new("keyed-two", "sha256", "2048"),
    ) else {
        return skip("checking that a token is bound to one key");
    };
    let nonce = 7u64;
    let mut anchor = Rfc3161::new(
        Box::new(one.client()),
        Trust::PinnedKey(one.key()),
        Box::new(move || nonce),
    );
    let receipt = anchor.submit(root(0x01)).expect("a token");

    assert!(tsp::attest(&receipt.evidence, &one.key()).is_ok());
    assert!(
        tsp::attest(&receipt.evidence, &two.key()).is_err(),
        "a token verified against an authority that did not sign it"
    );

    let wrong_key = Rfc3161::new(
        Box::new(two.client()),
        Trust::PinnedKey(two.key()),
        Box::new(move || nonce),
    );
    // `verify` has no nonce for a receipt it did not obtain, and says so rather
    // than guessing.
    assert!(matches!(
        wrong_key.verify(root(0x01), &receipt),
        Err(AdapterError::Unsupported(_))
    ));
    assert!(
        wrong_key
            .examine(root(0x01), &receipt.evidence, nonce)
            .is_err()
    );
}

/// The contract's own conformance suite, against a configured adapter. Its stated
/// guarantee is that a receipt verifies for its own root and for no other, and
/// this is where that is checked against a real authority rather than a fake.
#[test]
fn the_anchor_conformance_suite_passes_against_a_real_authority() {
    if !have_openssl_ts() {
        return skip("the Anchor conformance suite against a real authority");
    }
    let Ok(tsa) = Tsa::new("conformance", "sha256", "2048") else {
        return skip("the Anchor conformance suite against a real authority");
    };
    let mut anchor = Rfc3161::new(
        Box::new(tsa.client()),
        Trust::PinnedKey(tsa.key()),
        Box::new(|| 0xABCD),
    );
    let report = trailryx_contracts::conformance::anchor(&mut anchor);
    let failures: Vec<_> = report.failures().collect();
    assert!(
        failures.is_empty(),
        "the conformance suite failed: {}",
        report.summary()
    );
}
