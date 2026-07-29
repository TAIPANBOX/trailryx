//! Sealing a journal into a segment.
//!
//! # Why this is a separate crate
//!
//! The journal knows about storage and knows nothing about proofs. The index
//! knows about proofs and never touches a file. Neither should learn the
//! other's job, so the joint lives here, in the one place that depends on both.
//!
//! # Only what is durable
//!
//! Sealing takes the **acked** prefix, not everything the walk returned. A
//! segment is published, anchored and handed to auditors; committing to records
//! that were on the file but not yet durable would mean a crash could leave a
//! published root describing data that no longer exists. The journal already
//! distinguishes the two, so the seam only has to respect it.

use trailryx_crypto::Hash;
use trailryx_index::completeness::Dimension;
use trailryx_index::segment::{SealError, Segment, SegmentManifest};
use trailryx_journal::journal::{Journal, JournalError, StoppedBecause};
use trailryx_record::{Record, SegmentId, ShardIx};
use trailryx_sim::Io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Journal(JournalError),
    Seal(SealError),
    /// The journal stopped for a reason a seal must not paper over. Sealing a
    /// prefix of a file whose tail was rewritten would publish a root for
    /// records nobody can account for.
    JournalSuspect(StoppedBecause),
    /// The journal came back with less than it had promised.
    DurabilityViolation {
        promised: u64,
        recovered: u64,
    },
}

impl From<JournalError> for StoreError {
    fn from(e: JournalError) -> Self {
        Self::Journal(e)
    }
}

impl From<SealError> for StoreError {
    fn from(e: SealError) -> Self {
        Self::Seal(e)
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Journal(e) => write!(f, "journal: {e}"),
            Self::Seal(e) => write!(f, "seal: {e:?}"),
            Self::JournalSuspect(s) => write!(f, "journal is suspect: {s:?}"),
            Self::DurabilityViolation {
                promised,
                recovered,
            } => write!(f, "promised {promised} records, recovered {recovered}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// A segment together with the journal state it was sealed from.
#[derive(Debug)]
pub struct SealedSegment {
    pub segment: Segment,
    /// How many records the segment covers.
    pub records: u64,
    /// The chain head the next segment must start from.
    pub chain_after: Hash,
}

impl SealedSegment {
    pub fn manifest(&self) -> &SegmentManifest {
        self.segment.manifest()
    }
}

#[derive(Debug)]
pub enum SealOutcome {
    Sealed(Box<SealedSegment>),
    /// Nothing durable to seal yet. Not an error: a segment is sealed on a
    /// schedule, and an idle shard is a normal thing to find.
    NothingDurable,
}

/// Seal the durable prefix of a journal into a segment.
///
/// `chain_before` is the head the previous segment ended on, so a shard's
/// segments form one chain rather than a set of independent ones.
pub fn seal_segment<I: Io>(
    journal: &Journal,
    segment: SegmentId,
    shard: ShardIx,
    chain_before: Hash,
    io: &mut I,
) -> Result<SealOutcome, StoreError> {
    let walked = journal.read_all(io)?;

    // A torn tail is ordinary and the acked prefix is unaffected by it. A chain
    // that does not follow, or a file belonging to somebody else, is not
    // something to seal a prefix of and move on from.
    match walked.stopped_because {
        StoppedBecause::EndOfFile | StoppedBecause::TornTail(_) => {}
        other => return Err(StoreError::JournalSuspect(other)),
    }

    let acked = journal.acked();
    let available = walked.records.len() as u64;
    if available < acked {
        return Err(StoreError::DurabilityViolation {
            promised: acked,
            recovered: available,
        });
    }
    if acked == 0 {
        return Ok(SealOutcome::NothingDurable);
    }

    let durable: Vec<(Record, Hash)> = walked
        .records
        .into_iter()
        .take(usize::try_from(acked).unwrap_or(usize::MAX))
        .collect();

    let chain_after = durable.last().map(|(_, l)| *l).unwrap_or(chain_before);
    let sealed = Segment::seal(segment, shard, chain_before, &durable)?;

    Ok(SealOutcome::Sealed(Box::new(SealedSegment {
        segment: sealed,
        records: acked,
        chain_after,
    })))
}

/// Every dimension a sealed segment can answer with a proof.
pub fn provable_dimensions() -> &'static [Dimension] {
    Dimension::ALL
}
