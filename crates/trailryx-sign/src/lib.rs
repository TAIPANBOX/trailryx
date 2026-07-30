//! What gets signed, and what a witness attests to.
//!
//! # The two different claims
//!
//! A pack that verifies proves it is internally consistent. It does not prove
//! it is the real history, and those are separate claims needing separate
//! evidence.
//!
//! **A signature** says who published a root. Somebody holding the key
//! committed to this exact store at this exact size, and cannot later produce a
//! different history under the same signature.
//!
//! **A witness** says the root already existed at a certain time. That is the
//! part a signature cannot give, because the signer chooses the timestamp they
//! sign. Nothing stops an operator from signing a convenient history tomorrow
//! and dating it yesterday, and the only defence is somebody else, independent,
//! saying they saw the root when they say they saw it.
//!
//! So the two together answer different questions and neither substitutes for
//! the other: the signature answers *whose*, the witnesses answer *when*.
//!
//! # Why witnesses rather than a timestamping authority
//!
//! RFC 3161 is the obvious answer and it arrives as an adapter later. It needs
//! an ASN.1 parser, CMS, RSA verification and a certificate chain, all of which
//! would have to live in the offline verifier, and that crate's whole value is
//! that a person can read it. A witness attestation is the same ECDSA
//! signature over a different statement, so the verifier learns nothing new to
//! check it, and several independent witnesses are a stronger claim than one
//! authority anyway. It is the model transparency logs settled on.
//!
//! # No private key is ever in this crate
//!
//! [`Signer`] is a seam. A deployment puts a cloud key store or an HSM behind
//! it. Nothing here generates, holds, derives or serialises a private key, and
//! there is deliberately no implementation of the trait in this repository:
//! tests drive it through OpenSSL, which is somebody else's code.

use trailryx_crypto::Sha384;
use trailryx_record::{Hash, SigAlg, TenantId, Timestamp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The key store refused or was unreachable.
    Unavailable(String),
    /// The signer is not fit for a deployment.
    Unvalidated(&'static str),
    /// The signature came back the wrong size for its algorithm.
    BadLength { expected: usize, got: usize },
    /// A witness name that is not a bounded token.
    ///
    /// The name travels inside the pack and ends up on a line of the offline
    /// verifier's report. Free text there was a forgery channel: a name holding
    /// newlines wrote whole extra findings into an auditor's output, including a
    /// `[note] root-signature: es384 by key ...` line on a pack with no
    /// signature at all. The verifier escapes what it prints, and this stops us
    /// producing one in the first place.
    BadWitnessName(&'static str),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(why) => write!(f, "the key store said: {why}"),
            Self::Unvalidated(what) => write!(f, "{what} is not a validated signer"),
            Self::BadWitnessName(why) => write!(f, "a witness name {why}"),
            Self::BadLength { expected, got } => {
                write!(
                    f,
                    "a signature of {got} bytes where {expected} were expected"
                )
            }
        }
    }
}

impl std::error::Error for SignError {}

/// Something that holds a private key, somewhere that is not here.
pub trait Signer {
    fn algorithm(&self) -> SigAlg;

    /// The public key, uncompressed: `0x04 || X || Y`.
    fn public_key(&self) -> Vec<u8>;

    /// Whether this signer is fit for a deployment, on the same terms as the
    /// cipher seam: a correct implementation nobody certified still says no.
    fn is_validated(&self) -> bool;

    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// A key's identity: the hash of its public bytes.
///
/// Derived rather than assigned, so a pack cannot label a key with somebody
/// else's identifier. The verifier recomputes it and a mismatch is a finding,
/// which closes the obvious trick of presenting an attacker's key under a name
/// the auditor recognises.
pub fn key_id(public_key: &[u8]) -> Hash {
    let mut seed = Vec::with_capacity(public_key.len() + 32);
    seed.extend_from_slice(b"trailryx/key-id/v1\0");
    seed.extend_from_slice(public_key);
    Sha384::digest(&seed)
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The exact bytes a publisher signs.
///
/// Length-prefixed and domain-separated, so no signature over one thing can be
/// replayed as a signature over another. The shard count is in there even
/// though the root is built from the shards: a Merkle root does not commit its
/// own leaf count, and saying the number out loud costs eight bytes.
pub fn root_statement(
    tenant: &TenantId,
    store_root: Hash,
    shards: u32,
    generated_at: Timestamp,
    algorithm: SigAlg,
    public_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"trailryx/signed-root/v1\0");
    field(&mut out, tenant.as_str().as_bytes());
    field(&mut out, store_root.as_bytes());
    out.extend_from_slice(&shards.to_be_bytes());
    out.extend_from_slice(&generated_at.as_nanos().to_be_bytes());
    field(&mut out, algorithm.as_str().as_bytes());
    // The key is inside its own statement, so a signature cannot be presented
    // as having come from a different key than the one that made it.
    field(&mut out, public_key);
    out
}

/// What one witness asserts: this root existed, and I saw it then.
pub fn witness_statement(
    witness: &str,
    store_root: Hash,
    seen_at: Timestamp,
    algorithm: SigAlg,
    public_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"trailryx/witness/v1\0");
    field(&mut out, witness.as_bytes());
    field(&mut out, store_root.as_bytes());
    out.extend_from_slice(&seen_at.as_nanos().to_be_bytes());
    field(&mut out, algorithm.as_str().as_bytes());
    field(&mut out, public_key);
    out
}

/// A publisher's signature over a store root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSignature {
    pub algorithm: SigAlg,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl RootSignature {
    pub fn key_id(&self) -> Hash {
        key_id(&self.public_key)
    }
}

/// An independent assertion that a root existed at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessAttestation {
    pub witness: String,
    pub seen_at: Timestamp,
    pub algorithm: SigAlg,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl WitnessAttestation {
    pub fn key_id(&self) -> Hash {
        key_id(&self.public_key)
    }
}

fn expected_length(algorithm: SigAlg) -> Option<usize> {
    match algorithm {
        SigAlg::Es384 => Some(96),
        SigAlg::Es256 => Some(64),
        // Sizes we do not police here because nothing produces them yet.
        SigAlg::MlDsa65 | SigAlg::SlhDsa => None,
    }
}

/// Sign a store root, refusing a signer that is not fit for a deployment.
pub fn sign_root(
    signer: &mut impl Signer,
    tenant: &TenantId,
    store_root: Hash,
    shards: u32,
    generated_at: Timestamp,
) -> Result<RootSignature, SignError> {
    if !signer.is_validated() {
        return Err(SignError::Unvalidated("the signer"));
    }
    sign_root_unvalidated(signer, tenant, store_root, shards, generated_at)
}

/// The same without the check, for a test driving a signer nobody certified.
///
/// Named so a reviewer reading the line knows what is wrong with it.
pub fn sign_root_unvalidated(
    signer: &mut impl Signer,
    tenant: &TenantId,
    store_root: Hash,
    shards: u32,
    generated_at: Timestamp,
) -> Result<RootSignature, SignError> {
    let algorithm = signer.algorithm();
    let public_key = signer.public_key();
    let statement = root_statement(
        tenant,
        store_root,
        shards,
        generated_at,
        algorithm,
        &public_key,
    );
    let signature = signer.sign(&statement)?;
    check_length(algorithm, &signature)?;
    Ok(RootSignature {
        algorithm,
        public_key,
        signature,
    })
}

/// Have a witness attest that a root existed at a time.
pub fn attest(
    signer: &mut impl Signer,
    witness: &str,
    store_root: Hash,
    seen_at: Timestamp,
) -> Result<WitnessAttestation, SignError> {
    check_witness_name(witness)?;
    let algorithm = signer.algorithm();
    let public_key = signer.public_key();
    let statement = witness_statement(witness, store_root, seen_at, algorithm, &public_key);
    let signature = signer.sign(&statement)?;
    check_length(algorithm, &signature)?;
    Ok(WitnessAttestation {
        witness: witness.to_owned(),
        seen_at,
        algorithm,
        public_key,
        signature,
    })
}

/// The same charset every other identifier in the store uses, for the same
/// reason: this is a token in the metadata plane, and free text there is a hole
/// through which anything at all arrives.
pub const MAX_WITNESS_NAME: usize = 64;

fn check_witness_name(witness: &str) -> Result<(), SignError> {
    if witness.is_empty() {
        return Err(SignError::BadWitnessName("is empty"));
    }
    if witness.len() > MAX_WITNESS_NAME {
        return Err(SignError::BadWitnessName("is longer than 64 bytes"));
    }
    if !witness
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(SignError::BadWitnessName(
            "holds something outside [a-z0-9._-]",
        ));
    }
    Ok(())
}

fn check_length(algorithm: SigAlg, signature: &[u8]) -> Result<(), SignError> {
    if let Some(expected) = expected_length(algorithm)
        && signature.len() != expected
    {
        // Caught here rather than at the verifier: a signer returning DER when
        // the format wants a fixed-width pair is a configuration mistake, and
        // it should fail where somebody can still fix it.
        return Err(SignError::BadLength {
            expected,
            got: signature.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId::parse("acme").unwrap()
    }

    #[test]
    fn a_root_statement_and_a_witness_statement_can_never_collide() {
        // Otherwise a witness could be tricked into signing something that
        // reads as a publisher's commitment, or the other way round.
        let root = Hash([1u8; 48]);
        let a = root_statement(&tenant(), root, 1, Timestamp(5), SigAlg::Es384, b"k");
        let b = witness_statement("acme", root, Timestamp(5), SigAlg::Es384, b"k");
        assert_ne!(a, b);
        assert!(a.starts_with(b"trailryx/signed-root/v1\0"));
        assert!(b.starts_with(b"trailryx/witness/v1\0"));
    }

    #[test]
    fn every_field_changes_the_statement() {
        let base = root_statement(
            &tenant(),
            Hash([1u8; 48]),
            1,
            Timestamp(5),
            SigAlg::Es384,
            b"k",
        );
        let variants = [
            root_statement(
                &TenantId::parse("globex").unwrap(),
                Hash([1u8; 48]),
                1,
                Timestamp(5),
                SigAlg::Es384,
                b"k",
            ),
            root_statement(
                &tenant(),
                Hash([2u8; 48]),
                1,
                Timestamp(5),
                SigAlg::Es384,
                b"k",
            ),
            root_statement(
                &tenant(),
                Hash([1u8; 48]),
                2,
                Timestamp(5),
                SigAlg::Es384,
                b"k",
            ),
            root_statement(
                &tenant(),
                Hash([1u8; 48]),
                1,
                Timestamp(6),
                SigAlg::Es384,
                b"k",
            ),
            root_statement(
                &tenant(),
                Hash([1u8; 48]),
                1,
                Timestamp(5),
                SigAlg::Es256,
                b"k",
            ),
            root_statement(
                &tenant(),
                Hash([1u8; 48]),
                1,
                Timestamp(5),
                SigAlg::Es384,
                b"j",
            ),
        ];
        for v in variants {
            assert_ne!(base, v);
        }
    }

    #[test]
    fn length_prefixes_stop_two_fields_from_becoming_one() {
        // Without them, tenant "ab" with root "c" and tenant "a" with root "bc"
        // would be the same bytes, and a signature over one would cover the
        // other.
        let a = witness_statement("ab", Hash([0u8; 48]), Timestamp(1), SigAlg::Es384, b"c");
        let b = witness_statement("a", Hash([0u8; 48]), Timestamp(1), SigAlg::Es384, b"bc");
        assert_ne!(a, b);
    }

    #[test]
    fn a_key_id_follows_from_the_key_and_nothing_else() {
        assert_eq!(key_id(b"abc"), key_id(b"abc"));
        assert_ne!(key_id(b"abc"), key_id(b"abd"));
        assert_ne!(key_id(b"abc"), Sha384::digest(b"abc"), "domain separated");
    }
}
