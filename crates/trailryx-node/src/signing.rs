//! The queue between a sealed store root and the Keyryx signature over it.
//!
//! A seal does not wait for a signature. The root a seal makes is queued beside the data and
//! signed when Keyryx answers, under the time it was queued: the verifier checks a signature
//! against the pack's `generated_at`, so signing late under a later time would be a different
//! statement from the one the node made. A pack built while a root waits says it is unsigned,
//! which the verifier reports. Nothing is dropped, and nothing is signed silently.
//!
//! On disk, beside the data:
//!
//! ```text
//! signing/pending/<root hex>   the tenant and the time the root was queued under
//! signing/signed/<root hex>    the signature, the time it covers and the key that made it
//! ```

use std::path::{Path, PathBuf};

use trailryx_index::segment::{ShardTree, StoreTree};
use trailryx_record::{Hash, ShardIx, SigAlg, TenantId, Timestamp};
use trailryx_sign::{RootSignature, WitnessAttestation, root_statement, sign_root_unvalidated};

use crate::keyryx::{KeyryxSigner, hex_decode, hex_encode, parse_attestation};
use crate::plane::{PlaneError, sealed_manifests, write_committing};

/// What one [`drain`] left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing was waiting, so Keyryx was not asked.
    Clear,
    /// This many roots were signed by this call.
    Signed(usize),
    /// Keyryx would not sign the next root. It and the roots after it stay queued, and
    /// `why` says what happened.
    Queued { waiting: usize, why: String },
}

/// A root's signature, the root it is over, and the time the signature covers. A pack takes
/// this time as its own `generated_at`, because the verifier checks the signature against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRoot {
    pub store_root: Hash,
    pub generated_at: Timestamp,
    pub signature: RootSignature,
}

/// A root waiting for its signature, with the tenant and the time it was queued under.
struct Pending {
    root: Hash,
    tenant: TenantId,
    generated_at: Timestamp,
}

/// Queue the current root of `shard` unless it is already signed or already queued. Returns
/// that root, or `None` when nothing is sealed yet.
pub fn reconcile(
    dir: &Path,
    shard: ShardIx,
    tenant: &TenantId,
    now: Timestamp,
) -> Result<Option<Hash>, PlaneError> {
    let Some(root) = current_root(dir, shard)? else {
        return Ok(None);
    };
    let name = hex_encode(root.as_bytes());
    if signed_path(dir, &name).exists() || pending_path(dir, &name).exists() {
        return Ok(Some(root));
    }
    let body = format!(
        "tenant={}\ngenerated_at={}\n",
        tenant.as_str(),
        now.as_nanos()
    );
    let path = pending_path(dir, &name);
    create_parent(&path)?;
    write_committing(&path, body.as_bytes()).map_err(|e| io_error(&path, e))?;
    Ok(Some(root))
}

/// Queue the current root and sign what is queued. What a seal calls once it has sealed.
pub fn sign_sealed(
    dir: &Path,
    shard: ShardIx,
    tenant: &TenantId,
    signer: &mut KeyryxSigner,
    now: Timestamp,
) -> Result<Outcome, PlaneError> {
    reconcile(dir, shard, tenant, now)?;
    drain(dir, signer)
}

/// Sign every queued root, oldest first, each under the time it was queued. Stops at the
/// first root Keyryx will not sign: that one and the rest stay queued.
pub fn drain(dir: &Path, signer: &mut KeyryxSigner) -> Result<Outcome, PlaneError> {
    let pending = read_pending(dir)?;
    if pending.is_empty() {
        return Ok(Outcome::Clear);
    }
    let total = pending.len();
    if let Err(why) = signer.refresh() {
        return Ok(Outcome::Queued {
            waiting: total,
            why: why.to_string(),
        });
    }
    let mut signed = 0;
    for queued in pending {
        // Keyryx's ES384 is not a certified module, so the signer says it is not validated
        // and this is the one call that signs an unvalidated signer, on purpose.
        match sign_root_unvalidated(signer, &queued.tenant, queued.root, 1, queued.generated_at) {
            Ok(signature) => {
                // What Keyryx returned is checked before it is kept. A signature that does not
                // verify leaves the root queued, so a pack says it is unsigned rather than
                // carrying a signature that was never made over this root.
                if let Err(why) = check_root_signature(&queued, &signature) {
                    return Ok(Outcome::Queued {
                        waiting: total - signed,
                        why,
                    });
                }
                store_signature(dir, &queued, &signature)?;
                signed += 1;
            }
            Err(why) => {
                return Ok(Outcome::Queued {
                    waiting: total - signed,
                    why: why.to_string(),
                });
            }
        }
    }
    Ok(Outcome::Signed(signed))
}

/// The check a seal makes on a signature Keyryx returned, before it is kept: that it verifies
/// under the key it names, over the statement this seal made for this root and time. The
/// signer that produced it is not trusted to say so.
fn check_root_signature(queued: &Pending, signature: &RootSignature) -> Result<(), String> {
    if signature.algorithm != SigAlg::Es384 {
        return Err(format!(
            "keyryx's root signature is {:?}, which this node does not check",
            signature.algorithm
        ));
    }
    let statement = root_statement(
        &queued.tenant,
        queued.root,
        1,
        queued.generated_at,
        signature.algorithm,
        &signature.public_key,
    );
    trailryx_verify::p384::verify(&signature.public_key, &statement, &signature.signature)
        .map_err(|why| format!("keyryx's signature over the root does not verify: {why}"))
}

/// Every root still waiting for a signature, oldest first.
pub fn queued_roots(dir: &Path) -> Result<Vec<Hash>, PlaneError> {
    Ok(read_pending(dir)?.into_iter().map(|p| p.root).collect())
}

/// The signature over `root`, if one was made.
pub fn signed_root(dir: &Path, root: Hash) -> Result<Option<SignedRoot>, PlaneError> {
    let path = signed_path(dir, &hex_encode(root.as_bytes()));
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error(&path, e)),
    };
    let signed = parse_signed(root, &text)
        .map_err(|why| PlaneError::Refused(format!("{}: {why}", path.display())))?;
    Ok(Some(signed))
}

/// The witness attestations filed for `root` under `tenant`, read from the folder Keyryx's
/// witness writes to. A file whose contents name another root or tenant is not attached.
pub fn witnesses_for(
    witness_dir: &Path,
    tenant: &TenantId,
    root: Hash,
) -> Result<Vec<WitnessAttestation>, PlaneError> {
    let path = witness_dir
        .join(tenant.as_str())
        .join(format!("{}.json", hex_encode(root.as_bytes())));
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_error(&path, e)),
    };
    let attested = parse_attestation(&bytes)
        .map_err(|why| PlaneError::Refused(format!("{}: {why}", path.display())))?;
    if attested.tenant != tenant.as_str() || attested.store_root != root {
        return Ok(Vec::new());
    }
    Ok(vec![attested.attestation])
}

/// The store root of one shard's sealed segments, as a pack derives it. `None` when nothing
/// is sealed.
fn current_root(dir: &Path, shard: ShardIx) -> Result<Option<Hash>, PlaneError> {
    let manifests = sealed_manifests(dir, shard)?;
    if manifests.is_empty() {
        return Ok(None);
    }
    let mut tree = ShardTree::new(shard);
    for (_, manifest) in manifests {
        tree.push(manifest);
    }
    Ok(Some(StoreTree::from_shards(&[tree]).root()))
}

fn store_signature(
    dir: &Path,
    queued: &Pending,
    signature: &RootSignature,
) -> Result<(), PlaneError> {
    let name = hex_encode(queued.root.as_bytes());
    let body = format!(
        "generated_at={}\nalgorithm=es384\npublic_key={}\nsignature={}\n",
        queued.generated_at.as_nanos(),
        hex_encode(&signature.public_key),
        hex_encode(&signature.signature),
    );
    let path = signed_path(dir, &name);
    create_parent(&path)?;
    write_committing(&path, body.as_bytes()).map_err(|e| io_error(&path, e))?;
    // The signature is durable before the root leaves the queue, so a crash between the
    // two signs the root again rather than losing it.
    let waiting = pending_path(dir, &name);
    match std::fs::remove_file(&waiting) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_error(&waiting, e)),
    }
}

fn read_pending(dir: &Path) -> Result<Vec<Pending>, PlaneError> {
    let folder = dir.join("signing").join("pending");
    let entries = match std::fs::read_dir(&folder) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_error(&folder, e)),
    };
    let mut pending = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| io_error(&folder, e))?;
        let name = entry.file_name();
        // A name that is not a root is a temporary a crash left behind, not a root.
        let Some(root) = name.to_str().and_then(parse_root) else {
            continue;
        };
        let path = entry.path();
        let text = std::fs::read_to_string(&path).map_err(|e| io_error(&path, e))?;
        let queued = parse_pending(root, &text)
            .map_err(|why| PlaneError::Refused(format!("{}: {why}", path.display())))?;
        pending.push(queued);
    }
    pending.sort_by_key(|p| p.generated_at);
    Ok(pending)
}

fn parse_pending(root: Hash, text: &str) -> Result<Pending, String> {
    let mut tenant: Option<&str> = None;
    let mut generated_at: Option<u64> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("the line {line:?} is not key=value"));
        };
        match key {
            "tenant" => tenant = Some(value),
            "generated_at" => {
                generated_at = Some(
                    value
                        .parse()
                        .map_err(|_| format!("generated_at {value:?} is not a number"))?,
                );
            }
            other => return Err(format!("the field {other:?} is not one this queue writes")),
        }
    }
    let tenant = tenant.ok_or_else(|| "no tenant".to_owned())?;
    let generated_at = generated_at.ok_or_else(|| "no generated_at".to_owned())?;
    Ok(Pending {
        root,
        tenant: TenantId::parse(tenant)
            .map_err(|_| format!("tenant {tenant:?} is not an identifier"))?,
        generated_at: Timestamp(generated_at),
    })
}

fn parse_signed(root: Hash, text: &str) -> Result<SignedRoot, String> {
    let mut generated_at: Option<u64> = None;
    let mut public_key: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("the line {line:?} is not key=value"));
        };
        match key {
            "generated_at" => {
                generated_at = Some(
                    value
                        .parse()
                        .map_err(|_| format!("generated_at {value:?} is not a number"))?,
                );
            }
            "algorithm" => {
                if value != "es384" {
                    return Err(format!("the algorithm {value:?} is not es384"));
                }
            }
            "public_key" => {
                public_key = Some(hex_decode(value).ok_or("public_key is not hex")?);
            }
            "signature" => {
                signature = Some(hex_decode(value).ok_or("signature is not hex")?);
            }
            other => return Err(format!("the field {other:?} is not one this queue writes")),
        }
    }
    let generated_at = generated_at.ok_or_else(|| "no generated_at".to_owned())?;
    let public_key = public_key.ok_or_else(|| "no public_key".to_owned())?;
    let signature = signature.ok_or_else(|| "no signature".to_owned())?;
    if public_key.len() != 97 || public_key[0] != 0x04 {
        return Err("public_key is not an uncompressed P-384 point".to_owned());
    }
    if signature.len() != 96 {
        return Err("signature is not 96 bytes".to_owned());
    }
    Ok(SignedRoot {
        store_root: root,
        generated_at: Timestamp(generated_at),
        signature: RootSignature {
            algorithm: SigAlg::Es384,
            public_key,
            signature,
        },
    })
}

/// A root's name on disk: lowercase hex of its 48 bytes, and nothing else.
fn parse_root(name: &str) -> Option<Hash> {
    if name.bytes().any(|b| b.is_ascii_control()) {
        return None;
    }
    let bytes = hex_decode(name)?;
    <[u8; 48]>::try_from(bytes).ok().map(Hash)
}

fn pending_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("signing").join("pending").join(name)
}

fn signed_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("signing").join("signed").join(name)
}

fn io_error(path: &Path, e: std::io::Error) -> PlaneError {
    PlaneError::Io(format!("{}: {e}", path.display()))
}

/// Make the folder a file is about to go in, and say what went wrong if it cannot.
fn create_parent(path: &Path) -> Result<(), PlaneError> {
    match path.parent() {
        Some(parent) => std::fs::create_dir_all(parent).map_err(|e| io_error(parent, e)),
        None => Ok(()),
    }
}

/// The queue is files on a disk an operator can reach, so every reader of it is
/// held against what a torn write, a stray file or a hand edit would leave.
#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: Hash = Hash([0x5a; 48]);

    fn hex(bytes: &[u8]) -> String {
        hex_encode(bytes)
    }

    fn signed_text(public_key: &[u8], signature: &[u8]) -> String {
        format!(
            "generated_at=7\nalgorithm=es384\npublic_key={}\nsignature={}\n",
            hex(public_key),
            hex(signature)
        )
    }

    fn point() -> Vec<u8> {
        let mut key = vec![0x11; 97];
        key[0] = 0x04;
        key
    }

    #[test]
    fn a_root_is_named_by_exactly_ninety_six_lowercase_hex_digits() {
        let name = hex(ROOT.as_bytes());
        assert_eq!(name.len(), 96);
        assert_eq!(parse_root(&name), Some(ROOT));
        assert_eq!(parse_root(&name.to_uppercase()), None, "upper case");
        assert_eq!(parse_root(&name[..94]), None, "one byte short");
        assert_eq!(parse_root(&format!("{name}00")), None, "one byte long");
        assert_eq!(parse_root(&format!("{name}.part")), None, "a temporary");
        assert_eq!(parse_root(&"zz".repeat(48)), None, "not hex");
        assert_eq!(parse_root(""), None);
    }

    #[test]
    fn a_pending_entry_names_its_tenant_and_time_and_nothing_else() {
        let read = parse_pending(ROOT, "tenant=acme\ngenerated_at=42\n")
            .map(|p| (p.root, p.tenant.as_str().to_owned(), p.generated_at));
        assert_eq!(read, Ok((ROOT, "acme".to_owned(), Timestamp(42))));

        let refused = [
            ("tenant=acme\ngenerated_at=42\ntorn", "is not key=value"),
            (
                "tenant=acme\ngenerated_at=42\nsigner=x",
                "is not one this queue writes",
            ),
            (
                "tenant=acme\ngenerated_at=soon",
                "generated_at \"soon\" is not a number",
            ),
            ("generated_at=42", "no tenant"),
            ("tenant=acme", "no generated_at"),
            (
                "tenant=Not A Tenant\ngenerated_at=1",
                "is not an identifier",
            ),
            ("", "no tenant"),
        ];
        for (text, why) in refused {
            let got = parse_pending(ROOT, text).err().unwrap_or_default();
            assert!(got.contains(why), "{text:?} gave {got:?}, not {why:?}");
        }
    }

    #[test]
    fn a_signed_entry_is_an_es384_signature_of_the_right_shape_or_it_is_refused() {
        let ok =
            parse_signed(ROOT, &signed_text(&point(), &[0x22; 96])).expect("a well formed entry");
        assert_eq!(ok.store_root, ROOT);
        assert_eq!(ok.generated_at, Timestamp(7));
        assert_eq!(ok.signature.algorithm, SigAlg::Es384);
        assert_eq!(ok.signature.public_key, point());
        assert_eq!(ok.signature.signature, vec![0x22; 96]);

        let mut compressed = point();
        compressed[0] = 0x02;
        let good = signed_text(&point(), &[0x22; 96]);
        let refused = [
            (
                good.replace("es384", "es256"),
                "the algorithm \"es256\" is not es384",
            ),
            (
                good.replace("public_key=04", "public_key=zz"),
                "public_key is not hex",
            ),
            (
                good.replace("signature=22", "signature=2"),
                "signature is not hex",
            ),
            (
                good.replace("generated_at=7", "generated_at=x"),
                "is not a number",
            ),
            (good.replace("algorithm=", "algorithm"), "is not key=value"),
            (format!("{good}witness=x\n"), "is not one this queue writes"),
            (
                signed_text(&point()[..96], &[0x22; 96]),
                "not an uncompressed P-384 point",
            ),
            (
                signed_text(&compressed, &[0x22; 96]),
                "not an uncompressed P-384 point",
            ),
            (
                signed_text(&point(), &[0x22; 95]),
                "signature is not 96 bytes",
            ),
            (
                signed_text(&point(), &[0x22; 97]),
                "signature is not 96 bytes",
            ),
        ];
        for (text, why) in refused {
            let got = parse_signed(ROOT, &text).err().unwrap_or_default();
            assert!(got.contains(why), "{text:?} gave {got:?}, not {why:?}");
        }
        for missing in ["generated_at", "public_key", "signature"] {
            let text: String = good
                .lines()
                .filter(|l| !l.starts_with(missing))
                .map(|l| format!("{l}\n"))
                .collect();
            assert_eq!(
                parse_signed(ROOT, &text).err(),
                Some(format!("no {missing}")),
                "an entry without {missing} was read"
            );
        }
    }

    #[test]
    fn the_queue_on_disk_skips_temporaries_and_refuses_an_entry_it_cannot_read() {
        let dir = std::env::temp_dir().join(format!(
            "trailryx-node-signing-queue-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let nothing_yet = (queued_roots(&dir).map(|r| r.len()), signed_root(&dir, ROOT));

        let name = hex(ROOT.as_bytes());
        let pending = pending_path(&dir, &name);
        create_parent(&pending).expect("the queue folder");
        std::fs::write(&pending, "tenant=acme\ngenerated_at=3\n").expect("an entry");
        std::fs::write(pending_path(&dir, &format!("{name}.part")), "torn").expect("a temporary");
        let one = queued_roots(&dir);

        std::fs::write(&pending, "tenant=acme\n").expect("a torn entry");
        let torn = queued_roots(&dir).map(|r| r.len());

        let signed = signed_path(&dir, &name);
        create_parent(&signed).expect("the signed folder");
        std::fs::write(&signed, signed_text(&point(), &[0x22; 96])).expect("a signature");
        let found = signed_root(&dir, ROOT).map(|s| s.map(|s| s.generated_at));
        std::fs::write(&signed, "algorithm=es256\n").expect("a bad signature");
        let bad = signed_root(&dir, ROOT).map(|s| s.is_some());
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            nothing_yet.0.ok(),
            Some(0),
            "no queue folder is an empty queue"
        );
        assert_eq!(
            nothing_yet.1.ok(),
            Some(None),
            "no signature yet is not an error"
        );
        assert_eq!(
            one.ok(),
            Some(vec![ROOT]),
            "the temporary was read as a root"
        );
        let torn = torn.expect_err("a torn entry was read as a root");
        assert!(torn.to_string().contains("no generated_at"), "{torn}");
        assert_eq!(found.ok(), Some(Some(Timestamp(7))));
        let bad = bad.expect_err("a signature that is not es384 was kept");
        assert!(bad.to_string().contains("is not es384"), "{bad}");
    }

    #[test]
    fn no_attestation_on_disk_is_no_witness_rather_than_an_error() {
        let dir = std::env::temp_dir().join(format!(
            "trailryx-node-signing-witness-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let tenant = TenantId::parse("acme").expect("a tenant");
        let none = witnesses_for(&dir, &tenant, ROOT).map(|w| w.len());
        let folder = dir.join("acme");
        std::fs::create_dir_all(&folder).expect("the witness folder");
        std::fs::write(
            folder.join(format!("{}.json", hex(ROOT.as_bytes()))),
            b"not json",
        )
        .expect("a corrupt attestation");
        let corrupt = witnesses_for(&dir, &tenant, ROOT).map(|w| w.len());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(none.ok(), Some(0));
        assert!(corrupt.is_err(), "a corrupt attestation was read as none");
    }
}
