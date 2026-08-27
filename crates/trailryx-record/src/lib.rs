//! The canonical Trailryx record.
//!
//! Two ideas carry this crate.
//!
//! **The record is not a span.** It keeps four clocks instead of one, several
//! parents instead of one, and a `basis` block that says what the system knew
//! when it decided. Tracing has no equivalent of the last one, which is why an
//! audit built on spans can describe what happened but not why it was allowed.
//!
//! **The plane boundary is an invariant.** Metadata holds typed fields only:
//! identifiers, enums, hashes, numbers, timestamps. Any free text lives solely
//! in the encrypted payload plane, under a subject key. [`schema`] states it,
//! checks it, and the test suite fails the build on a breach, because the
//! failure mode is quiet: personal data sitting outside the encrypted plane
//! survives erasure and turns the central promise into a false one.
//!
//! No dependencies, by design: the offline verifier grows out of this crate and
//! has to stay small enough for an auditor to read in one sitting.

pub mod hash;
pub mod ids;
pub mod record;
pub mod schema;
pub mod time;

pub use hash::{HASH_BYTES, Hash};
pub use ids::{
    AgentId, IdError, IssuerId, KeyThumbprint, ModelId, PolicyVersion, PrincipalId, RecordId,
    RunId, SegmentId, ShardIx, TenantId, TokenId, ToolName,
};
pub use record::{
    Algorithms, Basis, DelegationProof, ErrorCode, EventType, HashAlg, KemAlg, MapperVersion,
    Outcome, PROVABLE_DIMENSIONS, PayloadClass, PayloadRef, Record, Severity, SigAlg, Verdict,
};
pub use schema::{Field, Kind, Pii, Plane, RECORD_V1, RECORD_V2, Schema, Violation};
pub use time::{CLOCK_SKEW_THRESHOLD_NANOS, SkewVerdict, Timestamp, Untrusted, assess_skew};
