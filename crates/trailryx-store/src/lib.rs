//! The seam between the journal and the authenticated index.
//!
//! Two halves that had no joint until now. The journal is the truth on disk;
//! the index is what makes an answer provable. Sealing is where one becomes the
//! other, and it is worth being strict at exactly this point, because a
//! mistake here is a segment that commits to something other than what the
//! journal holds, and every proof above it inherits the discrepancy.
//!
//! The rule the seam enforces: **a segment may only commit to records the
//! journal actually accepted, in the order it accepted them, with the chain
//! links it produced.** Nothing here invents a leaf.

pub mod causal;
pub mod cold;
pub mod evidence;
pub mod query;
pub mod seal;
pub mod tier;

pub use causal::{Bounds, Hop, Reconstruction, Stopped, reconstruct};
pub use evidence::PackBuilder;
pub use query::{Answer, Filter, ProofStatus, Query, query_segment};
pub use seal::{SealOutcome, SealedSegment, StoreError, seal_segment};
