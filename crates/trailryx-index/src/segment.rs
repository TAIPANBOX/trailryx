//! Segments, and the one recursion that composes proofs at every level.
//!
//! ```text
//! record → segment → shard → store → federation
//! ```
//!
//! Each level is a Merkle tree over the roots of the level below, and the same
//! verification code serves all of them. That is deliberate: composing shard
//! proofs inside one node and composing peer proofs across clouds are the same
//! problem, so writing it twice would mean two chances to get it wrong.
//!
//! # Skipping a segment has to be checkable
//!
//! An answer that spans a store does not want to carry an empty proof from
//! every segment that obviously cannot match. But skipping one is only sound if
//! the verifier can confirm the segment really could not have matched, and the
//! only thing it can confirm is what the manifest commits to.
//!
//! So a segment may be excluded **only** on a dimension whose bounds the
//! manifest carries, which today means time. On every other dimension each
//! segment must answer, even if the answer is empty. Anything looser would let
//! an omission hide behind the word "irrelevant".

use crate::completeness::{CompletenessProof, Dimension, ProofFailure, SortedIndex};
use crate::merkle::{InclusionProof, MerkleTree, leaf_hash};
use trailryx_crypto::{Digest, Hash, Sha384, digests_equal};
use trailryx_record::{Algorithms, Record, SegmentId, ShardIx, Timestamp};

/// What a sealed segment commits to.
///
/// One hash over this covers the records, every index built on them, and the
/// metadata a verifier needs in order to reason about what the segment could
/// possibly have contained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentManifest {
    pub format_version: u16,
    pub segment: SegmentId,
    pub shard: ShardIx,
    pub records: u64,
    /// Merkle root over record leaves in journal order.
    pub history_root: Hash,
    /// Index roots, in the fixed order of [`Dimension::ALL`].
    pub index_roots: Vec<(Dimension, Hash)>,
    /// Time bounds, which are the only thing that may justify skipping this
    /// segment when answering a range query.
    pub first_recorded_at: Timestamp,
    pub last_recorded_at: Timestamp,
    pub algorithms: Algorithms,
}

impl SegmentManifest {
    /// The commitment. Everything above the segment refers to this.
    pub fn root(&self) -> Hash {
        let mut h = Sha384::new();
        h.update(b"trailryx/segment-manifest/v1\0");
        h.update(&self.format_version.to_be_bytes());
        h.update(&self.segment.0.to_be_bytes());
        h.update(&self.shard.0.to_be_bytes());
        h.update(&self.records.to_be_bytes());
        h.update(self.history_root.as_bytes());
        // Fixed order, so two honest sealers agree byte for byte.
        for (d, r) in &self.index_roots {
            h.update(d.as_str().as_bytes());
            h.update(&[0]);
            h.update(r.as_bytes());
        }
        h.update(&self.first_recorded_at.as_nanos().to_be_bytes());
        h.update(&self.last_recorded_at.as_nanos().to_be_bytes());
        h.update(&[algorithm_code(self.algorithms)]);
        h.finish()
    }

    pub fn index_root(&self, d: Dimension) -> Option<Hash> {
        self.index_roots
            .iter()
            .find(|(dim, _)| *dim == d)
            .map(|(_, r)| *r)
    }

    /// Whether a time range could possibly touch this segment.
    fn overlaps_time(&self, lo: u64, hi: u64) -> bool {
        !(hi < self.first_recorded_at.as_nanos() || lo > self.last_recorded_at.as_nanos())
    }
}

fn algorithm_code(a: Algorithms) -> u8 {
    // One byte is enough while there is one choice per slot; it exists so the
    // manifest commits to which algorithms produced it, which is what the 2030
    // migration will need in order to enumerate what to re-sign.
    use trailryx_record::{HashAlg, KemAlg, SigAlg};
    let h = match a.hash {
        HashAlg::Sha384 => 1u8,
    };
    let s = match a.signature {
        SigAlg::Es256 => 1u8,
        SigAlg::MlDsa65 => 2,
        SigAlg::SlhDsa => 3,
    };
    let k = match a.kem {
        KemAlg::X25519MlKem768 => 1u8,
    };
    (h << 5) | (s << 2) | k
}

/// A sealed segment: immutable, and the unit everything above is built from.
#[derive(Debug, Clone)]
pub struct Segment {
    manifest: SegmentManifest,
    indexes: Vec<SortedIndex>,
    history: MerkleTree,
}

impl Segment {
    /// Seal records into a segment. Records arrive in journal order.
    pub fn seal(segment: SegmentId, shard: ShardIx, records: &[Record]) -> Self {
        let history = MerkleTree::from_leaf_hashes(
            records
                .iter()
                .map(|r| leaf_hash(&r.seq.to_be_bytes()))
                .collect(),
        );

        let with_leaves: Vec<(Record, Hash)> = records
            .iter()
            .enumerate()
            .map(|(i, r)| (r.clone(), history.leaf(i).expect("leaf exists")))
            .collect();

        let indexes: Vec<SortedIndex> = Dimension::ALL
            .iter()
            .map(|d| SortedIndex::build(*d, &with_leaves))
            .collect();

        let first = records
            .iter()
            .map(|r| r.recorded_at)
            .min()
            .unwrap_or(Timestamp::ZERO);
        let last = records
            .iter()
            .map(|r| r.recorded_at)
            .max()
            .unwrap_or(Timestamp::ZERO);

        let manifest = SegmentManifest {
            format_version: 1,
            segment,
            shard,
            records: records.len() as u64,
            history_root: history.root(),
            index_roots: indexes.iter().map(|i| (i.dimension(), i.root())).collect(),
            first_recorded_at: first,
            last_recorded_at: last,
            algorithms: records.first().map(|r| r.algorithms).unwrap_or_default(),
        };

        Self {
            manifest,
            indexes,
            history,
        }
    }

    pub fn manifest(&self) -> &SegmentManifest {
        &self.manifest
    }

    pub fn root(&self) -> Hash {
        self.manifest.root()
    }

    pub fn history(&self) -> &MerkleTree {
        &self.history
    }

    pub fn index(&self, d: Dimension) -> Option<&SortedIndex> {
        self.indexes.iter().find(|i| i.dimension() == d)
    }

    pub fn range(&self, d: Dimension, lo: &[u8], hi: &[u8]) -> Option<CompletenessProof> {
        self.index(d).map(|i| i.range(lo, hi))
    }
}

/// A shard: an ordered list of sealed segments.
#[derive(Debug, Clone)]
pub struct ShardTree {
    shard: ShardIx,
    manifests: Vec<SegmentManifest>,
    tree: MerkleTree,
}

impl ShardTree {
    pub fn new(shard: ShardIx) -> Self {
        Self {
            shard,
            manifests: Vec::new(),
            tree: MerkleTree::new(),
        }
    }

    pub fn push(&mut self, manifest: SegmentManifest) {
        self.tree.push_leaf(leaf_of(manifest.root()));
        self.manifests.push(manifest);
    }

    pub fn shard(&self) -> ShardIx {
        self.shard
    }

    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    pub fn len(&self) -> usize {
        self.manifests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.manifests.is_empty()
    }

    pub fn manifests(&self) -> &[SegmentManifest] {
        &self.manifests
    }

    pub fn inclusion(&self, i: usize) -> Option<InclusionProof> {
        self.tree.inclusion_proof(i, self.tree.len())
    }
}

/// The store: an ordered list of shards, fixed at creation.
///
/// Fixed because shard identity is part of a proof path. Re-splitting later
/// would invalidate every proof already issued, so the count is chosen once,
/// generously, and a different count means a new epoch with explicit lineage
/// rather than a rebuild of this one.
#[derive(Debug, Clone, Default)]
pub struct StoreTree {
    shard_roots: Vec<Hash>,
    tree: MerkleTree,
}

impl StoreTree {
    pub fn from_shards(shards: &[ShardTree]) -> Self {
        let shard_roots: Vec<Hash> = shards.iter().map(ShardTree::root).collect();
        let tree = MerkleTree::from_leaf_hashes(shard_roots.iter().map(|r| leaf_of(*r)).collect());
        Self { shard_roots, tree }
    }

    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    pub fn shards(&self) -> usize {
        self.shard_roots.len()
    }

    pub fn shard_root(&self, i: usize) -> Option<Hash> {
        self.shard_roots.get(i).copied()
    }

    pub fn inclusion(&self, i: usize) -> Option<InclusionProof> {
        self.tree.inclusion_proof(i, self.tree.len())
    }
}

fn leaf_of(h: Hash) -> Hash {
    leaf_hash(h.as_bytes())
}

/// What one segment contributed to a store-wide answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentContribution {
    /// The segment answered, with a proof covering its own index.
    ///
    /// The proof is boxed because it dwarfs the other variant, and a vector of
    /// these would otherwise pay the larger size for every skipped segment.
    Answered {
        manifest: SegmentManifest,
        manifest_proof: InclusionProof,
        proof: Box<CompletenessProof>,
    },
    /// The segment was skipped because its committed time bounds put it outside
    /// the range. Only legitimate on the time dimension.
    ExcludedByTime {
        manifest: SegmentManifest,
        manifest_proof: InclusionProof,
    },
}

impl SegmentContribution {
    fn manifest(&self) -> &SegmentManifest {
        match self {
            Self::Answered { manifest, .. } | Self::ExcludedByTime { manifest, .. } => manifest,
        }
    }

    fn manifest_proof(&self) -> &InclusionProof {
        match self {
            Self::Answered { manifest_proof, .. } | Self::ExcludedByTime { manifest_proof, .. } => {
                manifest_proof
            }
        }
    }
}

/// One shard's contribution to a store-wide answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardContribution {
    pub shard: ShardIx,
    pub shard_root: Hash,
    pub shard_proof: InclusionProof,
    pub segments: Vec<SegmentContribution>,
}

/// A store-wide answer, with everything needed to show nothing was left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeProof {
    pub dimension: Dimension,
    pub shards: Vec<ShardContribution>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositeFailure {
    /// Fewer shards answered than the store contains. The failure the whole
    /// construction exists to catch: forgetting a node silently shrinks an
    /// answer.
    ShardMissing {
        expected: usize,
        got: usize,
    },
    ShardNotInStore {
        shard: ShardIx,
    },
    SegmentNotInShard {
        shard: ShardIx,
        at: usize,
    },
    /// A segment was skipped whose committed bounds do not exclude the range.
    ExclusionNotJustified {
        shard: ShardIx,
        at: usize,
    },
    /// A segment was skipped on a dimension where the manifest commits to no
    /// bounds, so the exclusion cannot be checked at all.
    ExclusionNotCheckable {
        dimension: Dimension,
    },
    /// A segment's own completeness proof did not hold.
    SegmentProof {
        shard: ShardIx,
        at: usize,
        why: ProofFailure,
    },
    /// The proof was verified against an index root the manifest does not name.
    IndexRootMissing {
        shard: ShardIx,
        at: usize,
    },
}

impl CompositeProof {
    pub fn matched(&self) -> usize {
        self.shards
            .iter()
            .flat_map(|s| &s.segments)
            .map(|c| match c {
                SegmentContribution::Answered { proof, .. } => proof.matched(),
                SegmentContribution::ExcludedByTime { .. } => 0,
            })
            .sum()
    }

    /// Verify the whole answer against the store root.
    ///
    /// `shards_in_store` is not taken from the proof: a proof that could state
    /// how many shards exist could also understate it, which is exactly the
    /// omission being guarded against. It comes from the store's own committed
    /// configuration.
    pub fn verify(
        &self,
        dimension: Dimension,
        lo: &[u8],
        hi: &[u8],
        store_root: Hash,
        shards_in_store: usize,
    ) -> Result<(), CompositeFailure> {
        if self.shards.len() != shards_in_store {
            return Err(CompositeFailure::ShardMissing {
                expected: shards_in_store,
                got: self.shards.len(),
            });
        }

        // Checked up front, because it is a property of the answer's shape
        // rather than of any one segment: on a dimension whose bounds nothing
        // commits to, "this segment could not have matched" is an unverifiable
        // claim, and no amount of valid proofs elsewhere repairs it.
        if dimension != Dimension::RecordedAt
            && self
                .shards
                .iter()
                .flat_map(|s| &s.segments)
                .any(|c| matches!(c, SegmentContribution::ExcludedByTime { .. }))
        {
            return Err(CompositeFailure::ExclusionNotCheckable { dimension });
        }

        for (i, sc) in self.shards.iter().enumerate() {
            if sc.shard_proof.index != i
                || sc.shard_proof.size != shards_in_store
                || !sc.shard_proof.verify(leaf_of(sc.shard_root), store_root)
            {
                return Err(CompositeFailure::ShardNotInStore { shard: sc.shard });
            }

            for (j, contribution) in sc.segments.iter().enumerate() {
                let manifest = contribution.manifest();
                let mp = contribution.manifest_proof();
                if mp.index != j
                    || mp.size != sc.segments.len()
                    || !mp.verify(leaf_of(manifest.root()), sc.shard_root)
                {
                    return Err(CompositeFailure::SegmentNotInShard {
                        shard: sc.shard,
                        at: j,
                    });
                }

                match contribution {
                    SegmentContribution::ExcludedByTime { manifest, .. } => {
                        let (lo_n, hi_n) = (be_u64(lo), be_u64(hi));
                        if manifest.overlaps_time(lo_n, hi_n) {
                            return Err(CompositeFailure::ExclusionNotJustified {
                                shard: sc.shard,
                                at: j,
                            });
                        }
                    }
                    SegmentContribution::Answered {
                        manifest, proof, ..
                    } => {
                        let Some(index_root) = manifest.index_root(dimension) else {
                            return Err(CompositeFailure::IndexRootMissing {
                                shard: sc.shard,
                                at: j,
                            });
                        };
                        proof.verify(dimension, lo, hi, index_root).map_err(|why| {
                            CompositeFailure::SegmentProof {
                                shard: sc.shard,
                                at: j,
                                why,
                            }
                        })?;
                    }
                }
            }
        }

        let _ = digests_equal(&store_root, &store_root);
        Ok(())
    }
}

fn be_u64(key: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    let n = key.len().min(8);
    b[8 - n..].copy_from_slice(&key[key.len() - n..]);
    u64::from_be_bytes(b)
}
