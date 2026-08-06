//! Reading a data directory back, in another process.
//!
//! # What a read is here, and why it is not a `get`
//!
//! A sealed segment is not stored twice. What is on disk is the journal's own
//! bytes and a manifest, so reading one back means **rebuilding** it: walk the
//! journal, recompute every chain link, seal the records again, and compare the
//! manifest that falls out with the manifest that was published. That is the same
//! discipline `trailryx_store::tier` applies to a segment fetched from an object
//! store, for the same reason: the bytes came from somewhere this process does
//! not control, and the whole product is a claim about bytes not having changed.
//!
//! The comparison is strong because the manifest commits to the history root, to
//! all five index roots and to both chain ends. A byte altered anywhere in the
//! body produces a different manifest and the read is refused rather than
//! answered.
//!
//! # Nothing here writes
//!
//! Not even to repair. `Journal::open` recovers, which means it writes a header
//! onto a file that has none and truncates a tail it will not trust, and a reader
//! that repaired what it was auditing would be repairing the evidence. So this
//! goes through [`Journal::walk_bytes`], which is the same walk with no write
//! path attached.

use std::path::Path;

use trailryx_index::segment::{Segment, ShardTree, StoreTree};
use trailryx_journal::journal::{ChainStart, Journal};
use trailryx_record::{Hash, Record, ShardIx, TenantId, Timestamp};
use trailryx_store::evidence::PackBuilder;

use crate::plane::{PlaneError, journal_name, sealed_manifests};

#[derive(Debug)]
pub enum ReadError {
    Io(String),
    /// The directory holds something this reader will not answer from, and the
    /// message names the segment and what did not add up.
    Refused(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Refused(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<PlaneError> for ReadError {
    fn from(e: PlaneError) -> Self {
        Self::Refused(e.to_string())
    }
}

/// Every sealed segment of one shard, rebuilt from the journal's own bytes.
#[derive(Debug)]
pub struct Sealed {
    pub shard: ShardIx,
    pub segments: Vec<Segment>,
}

impl Sealed {
    pub fn records(&self) -> usize {
        self.segments.iter().map(|s| s.records().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

/// Rebuild every sealed segment in a data directory.
pub fn read_sealed(dir: &Path, shard: ShardIx) -> Result<Sealed, ReadError> {
    let mut segments = Vec::new();
    for (segment, manifest) in sealed_manifests(dir, shard)? {
        let path = dir.join(journal_name(shard, segment));
        let bytes = std::fs::read(&path)
            .map_err(|e| ReadError::Io(format!("{segment}: {}: {e}", path.display())))?;

        // The manifest says where this segment's chain begins, and the walk checks
        // that claim rather than believing it: a file opened under the wrong
        // predecessor fails at its very first record.
        let walked = Journal::walk_bytes(&bytes, ChainStart::After(manifest.chain_before))
            .map_err(|e| ReadError::Refused(format!("{segment}: {e}")))?;
        let available = walked.records.len() as u64;
        if available < manifest.records {
            return Err(ReadError::Refused(format!(
                "{segment}: its manifest declares {} records and the journal walks {available} \
                 ({:?}), so the file is not the file that was sealed",
                manifest.records, walked.stopped_because
            )));
        }

        // Only the sealed prefix. A journal may hold more than its manifest
        // covers, which is what a crash between the seal and the roll leaves, and
        // those records belong to no segment yet.
        let durable: Vec<(Record, Hash)> = walked
            .records
            .into_iter()
            .take(usize::try_from(manifest.records).unwrap_or(usize::MAX))
            .collect();

        let rebuilt = Segment::seal(segment, shard, manifest.chain_before, &durable)
            .map_err(|e| ReadError::Refused(format!("{segment}: {e:?}")))?;
        if *rebuilt.manifest() != manifest {
            return Err(ReadError::Refused(format!(
                "{segment}: the journal does not rebuild the manifest published for it, so \
                 those bytes are not the ones that were sealed"
            )));
        }
        segments.push(rebuilt);
    }
    Ok(Sealed { shard, segments })
}

/// The shard and store trees over what a reader holds.
///
/// Built here rather than in each caller, because the segments and the tree have
/// to be the same segments in the same order and a mismatched pair produces a
/// pack that fails its own verification.
pub fn trees(held: &Sealed) -> (ShardTree, StoreTree) {
    let mut shard = ShardTree::new(held.shard);
    for segment in &held.segments {
        shard.push(segment.manifest().clone());
    }
    let store = StoreTree::from_shards(&[shard.clone()]);
    (shard, store)
}

/// An evidence pack over everything a reader holds.
///
/// Unsigned and unwitnessed, and the verifier says so rather than reporting a
/// clean bill: signing needs a key custodian, which this process does not have,
/// and `trailryx-sign` is deliberately a seam with no implementation in this
/// repository. What the pack does prove is that the records, the chain and every
/// root are consistent with one another, checked by code that shares none of ours.
pub fn pack(held: &Sealed, tenant: &TenantId, at: Timestamp) -> Vec<u8> {
    let (shard, store) = trees(held);
    let segments: Vec<&Segment> = held.segments.iter().collect();
    PackBuilder::new(tenant.clone(), at)
        .shard(&shard, &segments)
        .build(&store)
}
