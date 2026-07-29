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
    /// The segment was told its chain begins somewhere its records do not.
    ///
    /// Almost always a caller that passed `Hash::ZERO`, or the head of a
    /// different file, where [`ChainStart::Genesis`] was meant.
    ChainDoesNotStartThere {
        declared: Hash,
        actual: Hash,
    },
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
            Self::ChainDoesNotStartThere { declared, actual } => write!(
                f,
                "the segment declares its chain begins at {} and its first record continues from {}",
                &declared.to_hex()[..16],
                &actual.to_hex()[..16]
            ),
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
/// Where the chain begins is not a parameter. It used to be, and the wrong value
/// was `Hash::ZERO`, which compiled, sealed, built an evidence pack, and failed
/// only in the offline verifier four stages downstream. The journal knows where
/// its own chain started, so it is asked.
pub fn seal_segment<I: Io>(
    journal: &Journal,
    segment: SegmentId,
    shard: ShardIx,
    io: &mut I,
) -> Result<SealOutcome, StoreError> {
    let chain_before = journal.genesis_head();
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

    // Belt and braces now that the start comes from the journal rather than a
    // caller. `Segment::seal` cannot make this check itself: recomputing a link
    // needs the canonical codec, which lives on the journal's side of the seam.
    if let Some((first, _)) = durable.first()
        && first.prev_hash != chain_before
    {
        return Err(StoreError::ChainDoesNotStartThere {
            declared: chain_before,
            actual: first.prev_hash,
        });
    }

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
