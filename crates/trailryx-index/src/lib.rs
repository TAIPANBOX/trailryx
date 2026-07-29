//! The authenticated index.
//!
//! Two structures, because two different things need proving and one structure
//! cannot do both.
//!
//! [`merkle`] holds an RFC 6962 tree, which answers "this record is in the log"
//! and, more importantly, "the log of size n contains everything the log of size
//! m contained, in the same order". That second one is the machine-checkable
//! form of *append-only*.
//!
//! [`completeness`] holds a sorted index per segment per dimension, which
//! answers the question no existing database answers: **these are all of them**.
//! Sorting is what makes absence provable, because in a sorted list two adjacent
//! entries leave no index for anything between them to occupy.
//!
//! The limit is stated rather than implied: completeness is provable only for
//! predicates on a sorted dimension. Everything else is a filter without a
//! proof, and the API says so.

pub mod completeness;
pub mod merkle;
pub mod segment;

pub use completeness::{CompletenessProof, Dimension, Entry, ProofFailure, SortedIndex};
pub use merkle::{ConsistencyProof, InclusionProof, MerkleTree, empty_root, leaf_hash, node_hash};
pub use segment::{
    CompositeFailure, CompositeProof, SealError, Segment, SegmentContribution, SegmentManifest,
    ShardContribution, ShardTree, StoreTree, TimeSpan,
};
