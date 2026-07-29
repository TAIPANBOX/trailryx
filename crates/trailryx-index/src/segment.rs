//! Segments, and the one recursion that composes proofs at every level.
//!
//! ```text
//! record → segment → shard → store → federation
//! ```
//!
//! Each level is a Merkle tree over the level below, and the same verification
//! code serves all of them. Composing shard proofs inside one node and composing
//! peer proofs across clouds are the same problem, so writing it twice would be
//! two chances to get it wrong.
//!
//! # One rule underneath all of this
//!
//! > **A verifier must never learn the shape of an answer from the answer.**
//!
//! How many shards exist, how many segments a shard holds, how many entries an
//! index has, what span a segment covers: each has to come from something
//! committed, because a server able to state a number is a server able to
//! understate it. The first version of this file got that right for the shard
//! count and wrong for everything else, and every one of those mistakes
//! produced an answer that verified while hiding records.

use crate::completeness::{CompletenessProof, Dimension, Entry, ProofFailure, SortedIndex};
use crate::merkle::{InclusionProof, MerkleTree, empty_root, leaf_hash};
use trailryx_crypto::{Digest, Hash, Sha384, digests_equal};
use trailryx_record::{Algorithms, Record, SegmentId, ShardIx, Timestamp};

/// What a sealed segment commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentManifest {
    pub format_version: u16,
    pub segment: SegmentId,
    pub shard: ShardIx,
    pub records: u64,
    /// Merkle root over the records' chain links, in journal order.
    pub history_root: Hash,
    /// Index roots, in the fixed order of [`Dimension::ALL`].
    pub index_roots: Vec<(Dimension, Hash)>,
    /// The shard's chain head before this segment's first record, and after its
    /// last.
    ///
    /// Without them a shard's segments are independent chains, and deleting a
    /// whole file leaves every remaining one internally valid.
    pub chain_before: Hash,
    pub chain_after: Hash,
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
        h.update(self.chain_before.as_bytes());
        h.update(self.chain_after.as_bytes());
        // Length-prefixed and in fixed order, so two honest sealers agree byte
        // for byte and no run of entries can be reinterpreted as another.
        h.update(&(self.index_roots.len() as u64).to_be_bytes());
        for (d, r) in &self.index_roots {
            let name = d.as_str().as_bytes();
            h.update(&(name.len() as u64).to_be_bytes());
            h.update(name);
            h.update(r.as_bytes());
        }
        h.update(&self.first_recorded_at.as_nanos().to_be_bytes());
        h.update(&self.last_recorded_at.as_nanos().to_be_bytes());
        h.update(&algorithm_code(self.algorithms));
        h.finish()
    }

    pub fn index_root(&self, d: Dimension) -> Option<Hash> {
        self.index_roots
            .iter()
            .find(|(dim, _)| *dim == d)
            .map(|(_, r)| *r)
    }
}

/// One byte per slot, so a future algorithm cannot alias an existing one the
/// way a packed byte would.
fn algorithm_code(a: Algorithms) -> [u8; 3] {
    use trailryx_record::{HashAlg, KemAlg, SigAlg};
    [
        match a.hash {
            HashAlg::Sha384 => 1,
        },
        match a.signature {
            SigAlg::Es256 => 1,
            SigAlg::MlDsa65 => 2,
            SigAlg::SlhDsa => 3,
        },
        match a.kem {
            KemAlg::X25519MlKem768 => 1,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// Two entries would occupy the same position in the same dimension, which
    /// makes every range covering both permanently unverifiable: a data
    /// condition turning into a denial of service.
    DuplicateKey { dimension: Dimension, seq: u64 },
    /// The segment mixes algorithms, so one manifest cannot say which produced
    /// it, and the migration those fields exist for could not enumerate it.
    MixedAlgorithms,
}

/// A sealed segment: immutable, and the unit everything above is built from.
#[derive(Debug, Clone)]
pub struct Segment {
    manifest: SegmentManifest,
    indexes: Vec<SortedIndex>,
    history: MerkleTree,
}

impl Segment {
    /// Seal records into a segment.
    ///
    /// Takes each record **with its chain link**, and the link is what becomes
    /// the history leaf. The first version hashed the sequence number, so the
    /// history root was a function of a set of integers: two segments differing
    /// in verdict, cost, tenant and payload reference produced identical roots,
    /// and a completeness proof said nothing about the records a query would
    /// return beside it.
    pub fn seal(
        segment: SegmentId,
        shard: ShardIx,
        chain_before: Hash,
        records: &[(Record, Hash)],
    ) -> Result<Self, SealError> {
        if let Some((first, _)) = records.first()
            && records
                .iter()
                .any(|(r, _)| r.algorithms != first.algorithms)
        {
            return Err(SealError::MixedAlgorithms);
        }

        let history = MerkleTree::from_leaf_hashes(
            records
                .iter()
                .map(|(_, link)| leaf_hash(link.as_bytes()))
                .collect(),
        );

        let indexes: Vec<SortedIndex> = Dimension::ALL
            .iter()
            .map(|d| SortedIndex::build(*d, records))
            .collect();

        for idx in &indexes {
            if let Some(seq) = idx.first_duplicate_position() {
                return Err(SealError::DuplicateKey {
                    dimension: idx.dimension(),
                    seq,
                });
            }
        }

        let first = records
            .iter()
            .map(|(r, _)| r.recorded_at)
            .min()
            .unwrap_or(Timestamp::ZERO);
        let last = records
            .iter()
            .map(|(r, _)| r.recorded_at)
            .max()
            .unwrap_or(Timestamp::ZERO);

        let manifest = SegmentManifest {
            format_version: 1,
            segment,
            shard,
            records: records.len() as u64,
            history_root: history.root(),
            index_roots: indexes.iter().map(|i| (i.dimension(), i.root())).collect(),
            chain_before,
            chain_after: records.last().map(|(_, l)| *l).unwrap_or(chain_before),
            first_recorded_at: first,
            last_recorded_at: last,
            algorithms: records
                .first()
                .map(|(r, _)| r.algorithms)
                .unwrap_or_default(),
        };

        Ok(Self {
            manifest,
            indexes,
            history,
        })
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

    /// The evidence a skip has to be backed by: the first and last entries of
    /// the time index, each with an inclusion proof. `None` for an empty
    /// segment, whose emptiness the manifest already commits to.
    pub fn time_span(&self) -> Option<Box<TimeSpan>> {
        let idx = self.index(Dimension::RecordedAt)?;
        if idx.is_empty() {
            return None;
        }
        let last = idx.len() - 1;
        Some(Box::new(TimeSpan {
            min: idx.entry(0)?.clone(),
            min_proof: idx.inclusion(0)?,
            max: idx.entry(last)?.clone(),
            max_proof: idx.inclusion(last)?,
        }))
    }
}

/// Proof of what a segment's time index actually spans.
///
/// Committed bounds in the manifest are written by the sealer, and the sealer
/// is the party being audited. A skip justified by its own declaration is a
/// skip justified by nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeSpan {
    pub min: Entry,
    pub min_proof: InclusionProof,
    pub max: Entry,
    pub max_proof: InclusionProof,
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
        self.tree.push_leaf(leaf_hash(manifest.root().as_bytes()));
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

/// The leaf a shard occupies in the store tree.
///
/// It commits the segment **count** as well as the root. Without that, an
/// answer omitting every segment of a shard passed: the per-segment loop simply
/// never ran, and nothing else looked.
fn shard_leaf(shard: ShardIx, segments: usize, root: Hash) -> Hash {
    let mut h = Sha384::new();
    h.update(b"trailryx/store-leaf/v1\0");
    h.update(&shard.0.to_be_bytes());
    h.update(&(segments as u64).to_be_bytes());
    h.update(root.as_bytes());
    leaf_hash(h.finish().as_bytes())
}

/// The store: an ordered list of shards, fixed at creation.
#[derive(Debug, Clone, Default)]
pub struct StoreTree {
    shards: Vec<(ShardIx, usize, Hash)>,
    tree: MerkleTree,
}

impl StoreTree {
    pub fn from_shards(shards: &[ShardTree]) -> Self {
        let entries: Vec<(ShardIx, usize, Hash)> = shards
            .iter()
            .map(|s| (s.shard(), s.len(), s.root()))
            .collect();
        let tree = MerkleTree::from_leaf_hashes(
            entries
                .iter()
                .map(|(ix, n, r)| shard_leaf(*ix, *n, *r))
                .collect(),
        );
        Self {
            shards: entries,
            tree,
        }
    }

    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    pub fn shards(&self) -> usize {
        self.shards.len()
    }

    pub fn inclusion(&self, i: usize) -> Option<InclusionProof> {
        self.tree.inclusion_proof(i, self.tree.len())
    }
}

/// What one segment contributed to a store-wide answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentContribution {
    /// The segment answered. Boxed because it dwarfs the other variant.
    Answered {
        manifest: SegmentManifest,
        manifest_proof: InclusionProof,
        proof: Box<CompletenessProof>,
    },
    /// The segment was skipped because its time index provably lies outside the
    /// range. `span` is absent only for a segment the manifest says is empty.
    ExcludedByTime {
        manifest: SegmentManifest,
        manifest_proof: InclusionProof,
        /// Boxed for the same reason as the answer: neither variant should
        /// make a vector of the other pay its size.
        span: Option<Box<TimeSpan>>,
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
    /// How many segments this shard holds. Committed in the store leaf, so a
    /// contribution cannot quietly answer with fewer.
    pub segments_in_shard: usize,
    pub shard_proof: InclusionProof,
    pub segments: Vec<SegmentContribution>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeProof {
    pub dimension: Dimension,
    pub shards: Vec<ShardContribution>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositeFailure {
    ShardMissing {
        expected: usize,
        got: usize,
    },
    ShardNotInStore {
        shard: ShardIx,
    },
    /// A shard answered with fewer segments than its store leaf commits to.
    SegmentsMissing {
        shard: ShardIx,
        expected: usize,
        got: usize,
    },
    SegmentNotInShard {
        shard: ShardIx,
        at: usize,
    },
    /// A manifest claims a shard other than the one presenting it.
    ManifestShardMismatch {
        shard: ShardIx,
        at: usize,
    },
    ExclusionNotJustified {
        shard: ShardIx,
        at: usize,
    },
    ExclusionNotCheckable {
        dimension: Dimension,
    },
    /// A skip was offered without proof of what the segment actually spans.
    ExclusionUnproven {
        shard: ShardIx,
        at: usize,
    },
    SegmentProof {
        shard: ShardIx,
        at: usize,
        why: ProofFailure,
    },
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
    /// `shards_in_store` comes from the store's committed configuration. Every
    /// other count in here is committed too, for the same reason.
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

        // A property of the answer's shape, checked before anything else: on a
        // dimension whose extent nothing commits to, "this segment could not
        // have matched" is unverifiable, and valid proofs elsewhere do not
        // repair it.
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
            if !sc.shard_proof.verify_at(
                shard_leaf(sc.shard, sc.segments_in_shard, sc.shard_root),
                store_root,
                i,
                shards_in_store,
            ) {
                return Err(CompositeFailure::ShardNotInStore { shard: sc.shard });
            }

            if sc.segments.len() != sc.segments_in_shard {
                return Err(CompositeFailure::SegmentsMissing {
                    shard: sc.shard,
                    expected: sc.segments_in_shard,
                    got: sc.segments.len(),
                });
            }

            for (j, contribution) in sc.segments.iter().enumerate() {
                let manifest = contribution.manifest();
                if manifest.shard != sc.shard {
                    return Err(CompositeFailure::ManifestShardMismatch {
                        shard: sc.shard,
                        at: j,
                    });
                }
                if !contribution.manifest_proof().verify_at(
                    leaf_hash(manifest.root().as_bytes()),
                    sc.shard_root,
                    j,
                    sc.segments_in_shard,
                ) {
                    return Err(CompositeFailure::SegmentNotInShard {
                        shard: sc.shard,
                        at: j,
                    });
                }

                let size = usize::try_from(manifest.records).unwrap_or(usize::MAX);

                match contribution {
                    SegmentContribution::ExcludedByTime { manifest, span, .. } => {
                        let time_root = manifest.index_root(Dimension::RecordedAt).ok_or(
                            CompositeFailure::IndexRootMissing {
                                shard: sc.shard,
                                at: j,
                            },
                        )?;

                        match span {
                            // An empty segment excludes itself from everything,
                            // and its emptiness is committed twice over.
                            None => {
                                if manifest.records != 0
                                    || !digests_equal(&time_root, &empty_root())
                                {
                                    return Err(CompositeFailure::ExclusionUnproven {
                                        shard: sc.shard,
                                        at: j,
                                    });
                                }
                            }
                            Some(s) => {
                                let bounded =
                                    s.min_proof.verify_at(s.min.leaf_hash(), time_root, 0, size)
                                        && s.max_proof.verify_at(
                                            s.max.leaf_hash(),
                                            time_root,
                                            size.saturating_sub(1),
                                            size,
                                        );
                                if !bounded {
                                    return Err(CompositeFailure::ExclusionUnproven {
                                        shard: sc.shard,
                                        at: j,
                                    });
                                }
                                // The same byte comparison the range check
                                // uses, so the two orderings cannot disagree.
                                let outside =
                                    s.max.key.as_slice() < lo || s.min.key.as_slice() > hi;
                                if !outside {
                                    return Err(CompositeFailure::ExclusionNotJustified {
                                        shard: sc.shard,
                                        at: j,
                                    });
                                }
                            }
                        }
                    }
                    SegmentContribution::Answered { proof, .. } => {
                        let Some(index_root) = manifest.index_root(dimension) else {
                            return Err(CompositeFailure::IndexRootMissing {
                                shard: sc.shard,
                                at: j,
                            });
                        };
                        proof
                            .verify(dimension, lo, hi, index_root, size)
                            .map_err(|why| CompositeFailure::SegmentProof {
                                shard: sc.shard,
                                at: j,
                                why,
                            })?;
                    }
                }
            }
        }

        Ok(())
    }
}
