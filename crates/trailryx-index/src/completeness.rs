//! Proof of completeness.
//!
//! This is the reason the engine is written rather than assembled. No existing
//! database answers the question an auditor actually asks:
//!
//! > These are the rows. Now prove that they are **all** of them.
//!
//! # How it works
//!
//! For each provable dimension, a segment gets a Merkle tree over its entries
//! **sorted by that dimension**. Sorting is what makes absence provable: in a
//! sorted list, showing two adjacent entries proves nothing lies between them,
//! because there is no index left for it to occupy.
//!
//! A range answer therefore carries:
//!
//! - the matching entries, with an inclusion proof each;
//! - proof that their positions are **contiguous**, starting at a stated index;
//! - the entry immediately **before** the range, whose key must fall below it;
//! - the entry immediately **after**, whose key must fall above it.
//!
//! Together those leave nowhere for an omitted record to hide. Any record that
//! matched would have to occupy an index, and every index between the two
//! boundaries is accounted for.
//!
//! # The limit, stated rather than implied
//!
//! Completeness is provable **only for predicates on a sorted dimension**.
//! Proving that a filter over an arbitrary field returned everything would mean
//! committing to a full scan, which is a different and far more expensive
//! structure. So the store fixes a small set of provable dimensions and answers
//! everything else honestly as a filter without a proof. A product that implied
//! otherwise would fall apart at the first serious audit.
//!
//! # Size
//!
//! Each entry currently carries its own inclusion proof, so a range of `k`
//! entries costs `k · log n` hashes. A multiproof over a contiguous range
//! shares almost all of those nodes and is the obvious optimisation, deferred
//! until there is a benchmark to measure it against.

use crate::merkle::{InclusionProof, MerkleTree};
use trailryx_crypto::{Digest, Hash, Sha384, digests_equal};
use trailryx_record::{EventType, Record};

/// A dimension a proof can cover.
///
/// Fixed, and short. Each one costs a sorted index per segment, and each one is
/// a promise that has to hold forever, because segments are immutable once
/// sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dimension {
    RecordedAt,
    AgentId,
    RunId,
    EventType,
}

impl Dimension {
    pub const ALL: &'static [Self] = &[
        Self::RecordedAt,
        Self::AgentId,
        Self::RunId,
        Self::EventType,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecordedAt => "recorded_at",
            Self::AgentId => "agent_id",
            Self::RunId => "run_id",
            Self::EventType => "event_type",
        }
    }

    /// The sort key for a record in this dimension.
    ///
    /// Byte order must equal value order, which is why timestamps are
    /// big-endian and enums are a single byte: a key whose lexicographic order
    /// disagreed with its semantic order would make range answers wrong in a
    /// way no proof would catch, because the proof would be about the wrong
    /// ordering.
    pub fn key_of(self, r: &Record) -> Vec<u8> {
        match self {
            Self::RecordedAt => r.recorded_at.as_nanos().to_be_bytes().to_vec(),
            Self::AgentId => r.agent_id.as_str().as_bytes().to_vec(),
            Self::RunId => r.run_id.as_str().as_bytes().to_vec(),
            Self::EventType => vec![event_code(r.event_type)],
        }
    }

    /// Key for a timestamp bound, for building a range query.
    pub fn time_key(nanos: u64) -> Vec<u8> {
        nanos.to_be_bytes().to_vec()
    }

    pub fn event_key(e: EventType) -> Vec<u8> {
        vec![event_code(e)]
    }
}

fn event_code(e: EventType) -> u8 {
    match e {
        EventType::RequestReceived => 1,
        EventType::ModelCall => 2,
        EventType::ToolCall => 3,
        EventType::PolicyDecision => 4,
        EventType::BudgetCheck => 5,
        EventType::MemoryAccess => 6,
        EventType::Delegation => 7,
        EventType::RunCompleted => 8,
        EventType::Erasure => 9,
        EventType::StoreEvent => 10,
    }
}

/// One position in a sorted index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: Vec<u8>,
    /// Tiebreaker, so equal keys still have a total order and the sort is
    /// deterministic across rebuilds.
    pub seq: u64,
    /// The record's leaf in the journal's history tree, binding this index
    /// entry to an actual record rather than to a key somebody invented.
    pub record_leaf: Hash,
}

impl Entry {
    pub fn leaf_hash(&self) -> Hash {
        let mut h = Sha384::new();
        h.update(&[0x00]); // leaf domain, as in the tree itself
        h.update(&(self.key.len() as u64).to_be_bytes());
        h.update(&self.key);
        h.update(&self.seq.to_be_bytes());
        h.update(self.record_leaf.as_bytes());
        h.finish()
    }
}

/// A sorted, authenticated index over one segment in one dimension.
#[derive(Debug, Clone)]
pub struct SortedIndex {
    dimension: Dimension,
    entries: Vec<Entry>,
    tree: MerkleTree,
}

impl SortedIndex {
    pub fn build(dimension: Dimension, records: &[(Record, Hash)]) -> Self {
        let mut entries: Vec<Entry> = records
            .iter()
            .map(|(r, leaf)| Entry {
                key: dimension.key_of(r),
                seq: r.seq,
                record_leaf: *leaf,
            })
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key).then(a.seq.cmp(&b.seq)));

        let tree = MerkleTree::from_leaf_hashes(entries.iter().map(Entry::leaf_hash).collect());
        Self {
            dimension,
            entries,
            tree,
        }
    }

    pub fn dimension(&self) -> Dimension {
        self.dimension
    }

    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Answer a range query with everything needed to prove nothing is missing.
    pub fn range(&self, lo: &[u8], hi: &[u8]) -> CompletenessProof {
        let size = self.entries.len();
        let first = self.entries.partition_point(|e| e.key.as_slice() < lo);
        let after = self.entries.partition_point(|e| e.key.as_slice() <= hi);

        let entries: Vec<Entry> = self.entries[first..after].to_vec();
        let entry_proofs: Vec<InclusionProof> = (first..after)
            .map(|i| self.tree.inclusion_proof(i, size).expect("index in range"))
            .collect();

        let left = (first > 0).then(|| {
            (
                self.entries[first - 1].clone(),
                self.tree
                    .inclusion_proof(first - 1, size)
                    .expect("index in range"),
            )
        });
        let right = (after < size).then(|| {
            (
                self.entries[after].clone(),
                self.tree
                    .inclusion_proof(after, size)
                    .expect("index in range"),
            )
        });

        CompletenessProof {
            dimension: self.dimension,
            size,
            first_index: first,
            entries,
            entry_proofs,
            left_boundary: left,
            right_boundary: right,
        }
    }
}

/// Why a proof did not hold. An auditor is owed the reason, not a boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofFailure {
    WrongDimension,
    CountMismatch,
    /// An entry is not in the tree the root describes.
    EntryNotInTree {
        at: usize,
    },
    /// Positions are not consecutive, so something could sit in the gap.
    NotContiguous {
        expected: usize,
        got: usize,
    },
    /// A returned entry falls outside the range it claims to answer.
    OutsideRange {
        at: usize,
    },
    /// The answer is not sorted, so adjacency proves nothing.
    OutOfOrder {
        at: usize,
    },
    /// The range does not start at the beginning and no left boundary was given.
    MissingLeftBoundary,
    MissingRightBoundary,
    /// A boundary was given that does not bound: it falls inside the range, so
    /// a matching record could still be hiding beyond it.
    BoundaryDoesNotBound {
        side: &'static str,
    },
    BoundaryNotInTree {
        side: &'static str,
    },
    /// A boundary was supplied, but not for the position that bounds the answer.
    /// Trimming an answer and leaving the old boundary behind looks like this.
    BoundaryAtWrongPosition {
        side: &'static str,
        expected: usize,
        got: usize,
    },
    /// A boundary was supplied where the range already reaches the edge.
    SpuriousBoundary {
        side: &'static str,
    },
}

/// A range answer together with the evidence that it is the whole answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletenessProof {
    pub dimension: Dimension,
    pub size: usize,
    pub first_index: usize,
    pub entries: Vec<Entry>,
    pub entry_proofs: Vec<InclusionProof>,
    pub left_boundary: Option<(Entry, InclusionProof)>,
    pub right_boundary: Option<(Entry, InclusionProof)>,
}

impl CompletenessProof {
    pub fn matched(&self) -> usize {
        self.entries.len()
    }

    /// Check the answer against the root, for the range it claims to cover.
    pub fn verify(
        &self,
        dimension: Dimension,
        lo: &[u8],
        hi: &[u8],
        root: Hash,
    ) -> Result<(), ProofFailure> {
        if self.dimension != dimension {
            return Err(ProofFailure::WrongDimension);
        }
        if self.entries.len() != self.entry_proofs.len() {
            return Err(ProofFailure::CountMismatch);
        }

        for (k, (entry, proof)) in self.entries.iter().zip(&self.entry_proofs).enumerate() {
            let expected = self.first_index + k;
            if proof.index != expected || proof.size != self.size {
                return Err(ProofFailure::NotContiguous {
                    expected,
                    got: proof.index,
                });
            }
            if !proof.verify(entry.leaf_hash(), root) {
                return Err(ProofFailure::EntryNotInTree { at: k });
            }
            if entry.key.as_slice() < lo || entry.key.as_slice() > hi {
                return Err(ProofFailure::OutsideRange { at: k });
            }
            if k > 0 {
                let prev = &self.entries[k - 1];
                if (prev.key.as_slice(), prev.seq) >= (entry.key.as_slice(), entry.seq) {
                    return Err(ProofFailure::OutOfOrder { at: k });
                }
            }
        }

        // Left edge: either the range starts the index, or the entry before it
        // must sit strictly below the lower bound.
        match (&self.left_boundary, self.first_index) {
            (None, 0) => {}
            (None, _) => return Err(ProofFailure::MissingLeftBoundary),
            (Some(_), 0) => {
                return Err(ProofFailure::SpuriousBoundary { side: "left" });
            }
            (Some((entry, proof)), first) => {
                if proof.index != first - 1 {
                    return Err(ProofFailure::BoundaryAtWrongPosition {
                        side: "left",
                        expected: first - 1,
                        got: proof.index,
                    });
                }
                if proof.size != self.size {
                    return Err(ProofFailure::BoundaryNotInTree { side: "left" });
                }
                if !proof.verify(entry.leaf_hash(), root) {
                    return Err(ProofFailure::BoundaryNotInTree { side: "left" });
                }
                if entry.key.as_slice() >= lo {
                    return Err(ProofFailure::BoundaryDoesNotBound { side: "left" });
                }
            }
        }

        let after = self.first_index + self.entries.len();
        match (&self.right_boundary, after == self.size) {
            (None, true) => {}
            (None, false) => return Err(ProofFailure::MissingRightBoundary),
            (Some(_), true) => {
                return Err(ProofFailure::SpuriousBoundary { side: "right" });
            }
            (Some((entry, proof)), false) => {
                if proof.index != after {
                    return Err(ProofFailure::BoundaryAtWrongPosition {
                        side: "right",
                        expected: after,
                        got: proof.index,
                    });
                }
                if proof.size != self.size {
                    return Err(ProofFailure::BoundaryNotInTree { side: "right" });
                }
                if !proof.verify(entry.leaf_hash(), root) {
                    return Err(ProofFailure::BoundaryNotInTree { side: "right" });
                }
                if entry.key.as_slice() <= hi {
                    return Err(ProofFailure::BoundaryDoesNotBound { side: "right" });
                }
            }
        }

        let _ = digests_equal(&root, &root);
        Ok(())
    }
}
