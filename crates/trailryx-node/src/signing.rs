//! The queue between a sealed store root and the Keyryx signature over it.
//!
//! Red-first scaffold: every function here answers as today's build does (nothing
//! is queued, nothing is signed), so the tests in `tests/it/keyryx.rs` compile and
//! fail on their assertions.

use std::path::Path;

use trailryx_record::{Hash, ShardIx, TenantId, Timestamp};
use trailryx_sign::{RootSignature, WitnessAttestation};

use crate::keyryx::KeyryxSigner;
use crate::plane::PlaneError;

/// What one [`drain`] left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing was waiting.
    Clear,
    /// This many roots were signed by this call.
    Signed(usize),
    /// Keyryx could not sign. The roots stay queued, and `why` says what happened.
    Queued { waiting: usize, why: String },
}

/// A root's signature, with the time it was signed under. The verifier checks the
/// signature against the pack's own `generated_at`, so the pack takes this time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRoot {
    pub generated_at: Timestamp,
    pub signature: RootSignature,
}

/// Queue the current store root of `shard` if it is neither signed nor queued.
/// Returns that root, or `None` when no segment is sealed yet.
pub fn reconcile(
    dir: &Path,
    shard: ShardIx,
    tenant: &TenantId,
    now: Timestamp,
) -> Result<Option<Hash>, PlaneError> {
    let _ = (dir, shard, tenant, now);
    Ok(None)
}

/// Every root still waiting for a signature.
pub fn queued_roots(dir: &Path) -> Result<Vec<Hash>, PlaneError> {
    let _ = dir;
    Ok(Vec::new())
}

/// Sign every queued root, oldest first, under the time each was queued.
pub fn drain(dir: &Path, signer: &mut KeyryxSigner) -> Result<Outcome, PlaneError> {
    let _ = (dir, signer);
    Ok(Outcome::Clear)
}

/// The signature over `root`, if one was made.
pub fn signed_root(dir: &Path, root: Hash) -> Result<Option<SignedRoot>, PlaneError> {
    let _ = (dir, root);
    Ok(None)
}

/// The witness attestations filed for `root` under `tenant`. A file whose name or
/// contents name another root is refused, not attached.
pub fn witnesses_for(
    witness_dir: &Path,
    tenant: &TenantId,
    root: Hash,
) -> Result<Vec<WitnessAttestation>, PlaneError> {
    let _ = (witness_dir, tenant, root);
    Ok(Vec::new())
}
