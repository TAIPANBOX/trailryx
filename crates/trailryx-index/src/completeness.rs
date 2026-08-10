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
    /// The record's own id. Sorted by it, a segment answers "here is record X"
    /// with a proof, which is what an evidence pack and a causal traversal both
    /// need.
    RecordId,
    RecordedAt,
    AgentId,
    RunId,
    EventType,
}

impl Dimension {
    pub const ALL: &'static [Self] = &[
        Self::RecordId,
        Self::RecordedAt,
        Self::AgentId,
        Self::RunId,
        Self::EventType,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecordId => "id",
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
            // Big-endian, so byte order is id order. A ULID sorts by time,
            // which makes this index useful beyond point lookup.
            Self::RecordId => r.id.0.to_be_bytes().to_vec(),
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

    /// The index key for a value as a **reader** sees it, rendered as text.
    ///
    /// This exists for the SQL facade, and it exists here rather than there for one
    /// reason: a key derivation that is written twice is a key derivation that will
    /// drift. If the facade computed a key itself and got one byte different, its
    /// range would miss records the index holds and the completeness proof would be
    /// about a range nobody asked for. So every key comes from this file.
    ///
    /// The text form is the projection's, because the projection is what a reader
    /// queries: a record id is 32 hex characters, an event type is its name.
    /// `None` means the literal does not name a value on this dimension, which the
    /// caller must treat as "not provable" rather than as an empty range.
    pub fn key_from_text(self, text: &str) -> Option<Vec<u8>> {
        Some(match self {
            Self::RecordId => {
                // 32 hex characters, as `record_id` is projected. A shorter or
                // longer literal is not a record id, and padding one would build a
                // range around a value nobody meant.
                if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                let mut out = Vec::with_capacity(16);
                for i in (0..32).step_by(2) {
                    out.push(u8::from_str_radix(&text[i..i + 2], 16).ok()?);
                }
                out
            }
            Self::RecordedAt => text.parse::<u64>().ok()?.to_be_bytes().to_vec(),
            Self::AgentId | Self::RunId => text.as_bytes().to_vec(),
            Self::EventType => {
                let event = EventType::ALL.iter().find(|e| e.as_str() == text)?;
                vec![event_code(*event)]
            }
        })
    }

    /// The same, for a literal that arrived as an integer rather than as text.
    ///
    /// Only the numeric dimension has one. A SQL comparison of `run_id` against a
    /// number is a comparison this store cannot prove, and answering it with a key
    /// derived from a rendering would be answering a different question.
    pub fn key_from_i64(self, value: i64) -> Option<Vec<u8>> {
        match self {
            Self::RecordedAt => u64::try_from(value).ok().map(|v| v.to_be_bytes().to_vec()),
            Self::EventType => {
                let code = u8::try_from(value).ok()?;
                // Only a code that names an event type. A raw byte nobody defined
                // would build a range over nothing while looking like a filter.
                EventType::ALL
                    .iter()
                    .any(|e| event_code(*e) == code)
                    .then_some(vec![code])
            }
            _ => None,
        }
    }

    pub fn id_key(id: trailryx_record::RecordId) -> Vec<u8> {
        id.0.to_be_bytes().to_vec()
    }

    pub fn event_key(e: EventType) -> Vec<u8> {
        vec![event_code(e)]
    }
}

/// The index key for an event type, which must be the journal's own discriminant.
///
/// The same byte, and not merely a byte with the same ordering: `trailryx-verify`
/// reads `event_type` straight out of the record as one opaque byte and uses it as
/// the index key, so if this function and `trailryx_journal::wire` ever disagreed,
/// the offline verifier would rebuild a different index from the same records and
/// condemn a pack that was correct. That is the strongest reason a new code is
/// appended in both places at once and never renumbered in either.
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
        EventType::NotificationDispatched => 11,
        EventType::IdentityFinding => 12,
    }
}

#[cfg(test)]
mod key_from_literal_tests {
    use super::*;
    use trailryx_record::{RecordId, Timestamp};

    /// The property the function exists for: a key built from a reader's literal
    /// must be byte-identical to the key built from the record. Anything else and a
    /// range misses records the index holds while the proof says it was complete.
    #[test]
    fn a_key_from_text_equals_the_key_from_the_record() {
        let id = RecordId(0x0123_4567_89ab_cdef_0011_2233_4455_6677);
        assert_eq!(
            Dimension::RecordId.key_from_text("0123456789abcdef0011223344556677"),
            Some(Dimension::id_key(id))
        );
        assert_eq!(
            Dimension::RecordedAt.key_from_text("1700000000000000000"),
            Some(Dimension::time_key(
                Timestamp(1_700_000_000_000_000_000).as_nanos()
            ))
        );
        assert_eq!(
            Dimension::EventType.key_from_text("model_call"),
            Some(vec![event_code(EventType::ModelCall)])
        );
        assert_eq!(
            Dimension::RunId.key_from_text("run-a"),
            Some(b"run-a".to_vec())
        );
    }

    /// A literal that does not name a value must be `None`, never a padded or
    /// truncated key. A key built around a value nobody meant is a range whose
    /// completeness proof is about the wrong question.
    #[test]
    fn a_literal_that_names_nothing_is_refused_rather_than_coerced() {
        for text in [
            "",
            "0123",
            "zzzz456789abcdef0011223344556677",
            "0123456789abcdef00112233445566778899",
        ] {
            assert_eq!(
                Dimension::RecordId.key_from_text(text),
                None,
                "{text:?} is not a record id"
            );
        }
        assert_eq!(Dimension::RecordedAt.key_from_text("-1"), None);
        assert_eq!(Dimension::RecordedAt.key_from_text("not a number"), None);
        assert_eq!(Dimension::EventType.key_from_text("no_such_event"), None);
    }

    #[test]
    fn an_integer_literal_resolves_only_where_the_dimension_is_numeric() {
        assert_eq!(
            Dimension::RecordedAt.key_from_i64(1_700_000_000_000_000_000),
            Some(1_700_000_000_000_000_000u64.to_be_bytes().to_vec())
        );
        assert_eq!(Dimension::RecordedAt.key_from_i64(-1), None);
        // An event code nobody defined is not a filter, it is a range over nothing.
        assert_eq!(Dimension::EventType.key_from_i64(2), Some(vec![2]));
        assert_eq!(Dimension::EventType.key_from_i64(200), None);
        assert_eq!(Dimension::RunId.key_from_i64(5), None);
        assert_eq!(Dimension::AgentId.key_from_i64(5), None);
        assert_eq!(Dimension::RecordId.key_from_i64(5), None);
    }

    /// Every event type must be reachable by name, or a query on one of them would
    /// silently be unprovable.
    #[test]
    fn every_event_type_resolves_by_its_own_name() {
        for event in EventType::ALL {
            assert_eq!(
                Dimension::EventType.key_from_text(event.as_str()),
                Some(vec![event_code(*event)]),
                "{} did not resolve",
                event.as_str()
            );
        }
    }
}

/// One position in a sorted index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: Vec<u8>,
    /// Tiebreaker, so equal keys still have a total order and the sort is
    /// deterministic across rebuilds.
    pub seq: u64,
    /// The chain link covering the record this entry points at.
    ///
    /// The link, not a leaf and not a sequence number: it is what the journal
    /// produced over the record's actual bytes, so an index entry is bound to a
    /// record rather than to a key somebody invented. Naming it `record_leaf`
    /// while it held a link was a small lie that would have cost somebody an
    /// afternoon.
    pub record_link: Hash,
}

impl Entry {
    pub fn leaf_hash(&self) -> Hash {
        let mut h = Sha384::new();
        h.update(&[0x00]); // leaf domain, as in the tree itself
        h.update(&(self.key.len() as u64).to_be_bytes());
        h.update(&self.key);
        h.update(&self.seq.to_be_bytes());
        h.update(self.record_link.as_bytes());
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
                record_link: *leaf,
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

    pub fn entry(&self, i: usize) -> Option<&Entry> {
        self.entries.get(i)
    }

    pub fn inclusion(&self, i: usize) -> Option<InclusionProof> {
        self.tree.inclusion_proof(i, self.entries.len())
    }

    /// The sequence number of the first entry whose `(key, seq)` position is
    /// not strictly greater than its predecessor's.
    ///
    /// Two entries at the same position make every range covering both
    /// permanently unverifiable, because the answer can never be strictly
    /// ordered. Catching it at seal turns a data condition that would deny
    /// service into a refusal to seal.
    pub fn first_duplicate_position(&self) -> Option<u64> {
        self.entries
            .windows(2)
            .find(|w| (w[0].key.as_slice(), w[0].seq) >= (w[1].key.as_slice(), w[1].seq))
            .map(|w| w[1].seq)
    }

    /// Answer a range query with everything needed to prove nothing is missing.
    pub fn range(&self, lo: &[u8], hi: &[u8]) -> CompletenessProof {
        let size = self.entries.len();
        let first = self.entries.partition_point(|e| e.key.as_slice() < lo);
        // A reversed range yields `after < first`. Clamping keeps it an empty
        // answer instead of a panic: a query surface will eventually forward
        // whatever a caller typed, and a slice index is not the place to find
        // out.
        let after = self
            .entries
            .partition_point(|e| e.key.as_slice() <= hi)
            .max(first);

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
    /// The index is not the size the caller's committed data says it is.
    WrongSize {
        expected: usize,
        got: usize,
    },
    /// An empty answer was offered for an index that is not empty.
    EmptyAnswerAgainstNonEmptyIndex,
    /// An index with nothing in it answered with something in it.
    ///
    /// The `size == 0` branch validates the root and then has nothing left to
    /// compare an entry against, because an empty tree has no positions. So the
    /// entries have to be refused outright rather than checked: an answer that
    /// declares `size: 0` and carries four entries copied from another segment
    /// verified against the empty root and reported four matches.
    EntriesAgainstEmptyIndex,
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
    /// `expected_size` is how many entries the index holds, and it comes from
    /// the caller: from a committed manifest, never from this proof.
    ///
    /// Without it an answer could simply declare `size: 0`, in which case there
    /// are no entries to check, no boundaries to demand, and the root is never
    /// read at all. That proof verified against every root, including a root
    /// belonging to a segment full of matching records.
    pub fn verify(
        &self,
        dimension: Dimension,
        lo: &[u8],
        hi: &[u8],
        root: Hash,
        expected_size: usize,
    ) -> Result<(), ProofFailure> {
        if self.dimension != dimension {
            return Err(ProofFailure::WrongDimension);
        }
        if self.size != expected_size {
            return Err(ProofFailure::WrongSize {
                expected: expected_size,
                got: self.size,
            });
        }
        if self.entries.len() != self.entry_proofs.len() {
            return Err(ProofFailure::CountMismatch);
        }
        if self.size == 0 {
            // An empty index has exactly one honest root, so an empty answer is
            // still an answer about something.
            if !digests_equal(&root, &crate::merkle::empty_root()) {
                return Err(ProofFailure::EmptyAnswerAgainstNonEmptyIndex);
            }
            // And then the answer itself has to be empty. Pinning the root was
            // the first half of this fix and left the second half undone: every
            // loop below is skipped for `size == 0`, so entries copied out of
            // another segment were never compared against anything and
            // `matched()` reported them. That is the file's own rule broken at
            // the one place it is easiest to break: a verifier learned the shape
            // of the answer from the answer.
            if !self.entries.is_empty()
                || !self.entry_proofs.is_empty()
                || self.first_index != 0
                || self.left_boundary.is_some()
                || self.right_boundary.is_some()
            {
                return Err(ProofFailure::EntriesAgainstEmptyIndex);
            }
            return Ok(());
        }

        for (k, (entry, proof)) in self.entries.iter().zip(&self.entry_proofs).enumerate() {
            let expected = self.first_index + k;
            if proof.index != expected || proof.size != self.size {
                return Err(ProofFailure::NotContiguous {
                    expected,
                    got: proof.index,
                });
            }
            if !proof.verify_at(entry.leaf_hash(), root, expected, self.size) {
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
                if !proof.verify_at(entry.leaf_hash(), root, first - 1, self.size) {
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
                if !proof.verify_at(entry.leaf_hash(), root, after, self.size) {
                    return Err(ProofFailure::BoundaryNotInTree { side: "right" });
                }
                if entry.key.as_slice() <= hi {
                    return Err(ProofFailure::BoundaryDoesNotBound { side: "right" });
                }
            }
        }

        Ok(())
    }
}
