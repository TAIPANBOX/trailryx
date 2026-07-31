//! The cold tier: a sealed segment put into object storage, and read back.
//!
//! # What goes into the store, and in what shape
//!
//! Two objects per segment, which is what `trailryx-publish` needs and what §6.1 of
//! the architecture asks for:
//!
//! - the **body**, the segment's records exactly as the journal wrote them, at a key
//!   containing the body's own digest;
//! - the **manifest object**, written last under a conditional write, which is the
//!   commit point.
//!
//! The manifest object is not the bare [`SegmentManifest`]. It is that manifest with
//! the body's digest in front of it, and the reason is the invariant `trailryx-publish`
//! documents and cannot check: **the manifest must commit to the body.** Without the
//! digest, a reader who found the manifest would have to guess which body belongs to
//! it, and "guess" is not a word that belongs in a store like this.
//!
//! This envelope is an object-store concern, not a record-format one. Nothing here
//! touches the frozen format: the manifest inside it is encoded exactly as the
//! evidence pack encodes it, and the records are the journal's own bytes.
//!
//! # What `fetch` checks, and what it deliberately leaves to the verifier
//!
//! It checks what it can check on its own and says so, rather than implying more:
//!
//! - the body's digest matches the digest the manifest object commits to, so a body
//!   altered in the bucket is refused rather than returned;
//! - the manifest names the shard and segment that were asked for, so an object
//!   moved to another key is refused;
//! - the number of records matches what the manifest declares.
//!
//! It does **not** recompute the history root or the index roots. Those are the
//! verifier's job, deliberately: recomputing them means re-deriving every chain link,
//! which is exactly the work `trailryx-verify` exists to do independently, and doing
//! it here in the same process from the same code would prove that this code agrees
//! with itself. A caller who wants the full verdict runs the verifier over an
//! evidence pack, which is the path that already has two implementations.

use trailryx_contracts::{ObjectStore, VersionId};
use trailryx_index::SegmentManifest;
use trailryx_publish::{Publication, PublishError, Published, body_digest, publish};
use trailryx_record::{Hash, SegmentId, ShardIx};

use crate::evidence::{decode_manifest, encode_manifest};

/// The envelope's own version, so a reader can refuse bytes it does not understand
/// rather than misread them.
const ENVELOPE_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColdError {
    /// The object store refused, or could not be reached, or two publishers sealed
    /// different segments under one number.
    Publish(PublishError),
    /// The store answered and the bytes were not what this reader can use.
    Malformed(&'static str),
    /// The manifest was there and the body it names was not. A publication
    /// interrupted between its two writes leaves exactly this, and it is why the
    /// manifest is written second.
    BodyMissing,
    /// The body's digest is not the digest the manifest commits to. Somebody
    /// replaced the object under a key the manifest still points at.
    BodyAltered,
    /// The manifest under this key describes a different segment.
    WrongSegment,
    /// The store could not be read.
    Unavailable,
}

impl std::fmt::Display for ColdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Publish(e) => write!(f, "publication failed: {e}"),
            Self::Malformed(what) => write!(f, "the stored bytes are unreadable: {what}"),
            Self::BodyMissing => f.write_str(
                "the manifest is published and the body it names is absent, which is a \
                 publication interrupted between its two writes",
            ),
            Self::BodyAltered => f.write_str(
                "the body under the key this manifest names is not the body it committed to",
            ),
            Self::WrongSegment => {
                f.write_str("the manifest under this key describes a different segment")
            }
            Self::Unavailable => f.write_str("the object store could not be read"),
        }
    }
}

impl std::error::Error for ColdError {}

/// A segment read back out of cold storage, with what was checked on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub manifest: SegmentManifest,
    /// The records, in journal order, exactly as they were written.
    pub records: Vec<Vec<u8>>,
}

/// The records as one object: a count, then each record length-prefixed.
///
/// The same shape the evidence pack uses for its record section, so the two agree
/// about what a segment's bytes are.
pub fn encode_body(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(records.len() as u64).to_be_bytes());
    for record in records {
        out.extend_from_slice(&(record.len() as u32).to_be_bytes());
        out.extend_from_slice(record);
    }
    out
}

pub fn decode_body(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ColdError> {
    if bytes.len() < 8 {
        return Err(ColdError::Malformed("a body shorter than its own count"));
    }
    let count = u64::from_be_bytes(bytes[..8].try_into().expect("eight bytes"));
    // A declared count is not an allocation. A body claiming four billion records
    // would otherwise reserve for four billion before reading the second one.
    let mut out = Vec::new();
    let mut rest = &bytes[8..];
    for _ in 0..count {
        if rest.len() < 4 {
            return Err(ColdError::Malformed("a record length past the end"));
        }
        let len = u32::from_be_bytes(rest[..4].try_into().expect("four bytes")) as usize;
        rest = &rest[4..];
        if rest.len() < len {
            return Err(ColdError::Malformed("a record shorter than it declared"));
        }
        out.push(rest[..len].to_vec());
        rest = &rest[len..];
    }
    if !rest.is_empty() {
        return Err(ColdError::Malformed("bytes after the last record"));
    }
    Ok(out)
}

/// The manifest with the digest of the body it belongs to in front of it.
pub fn encode_envelope(body_digest: &Hash, manifest: &SegmentManifest) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    out.extend_from_slice(body_digest.as_bytes());
    out.extend_from_slice(&encode_manifest(manifest));
    out
}

pub fn decode_envelope(bytes: &[u8]) -> Result<(Hash, SegmentManifest), ColdError> {
    if bytes.len() < 2 + 48 {
        return Err(ColdError::Malformed("an envelope shorter than its header"));
    }
    let version = u16::from_be_bytes(bytes[..2].try_into().expect("two bytes"));
    if version != ENVELOPE_VERSION {
        return Err(ColdError::Malformed(
            "an envelope version this reader predates",
        ));
    }
    let mut body_digest = [0u8; 48];
    body_digest.copy_from_slice(&bytes[2..50]);
    let manifest =
        decode_manifest(&bytes[50..]).ok_or(ColdError::Malformed("an unreadable manifest"))?;
    Ok((Hash(body_digest), manifest))
}

fn manifest_key(shard: ShardIx, segment: SegmentId) -> String {
    Publication {
        shard,
        segment,
        manifest: Vec::new(),
        body: Vec::new(),
    }
    .manifest_key()
}

/// Publish a sealed segment to cold storage.
///
/// `records` are the journal's own bytes, in journal order. `attempts` bounds the
/// retries inside one call; the delay between calls is the caller's, because nothing
/// here has a clock.
pub fn publish_segment(
    store: &mut dyn ObjectStore,
    manifest: &SegmentManifest,
    records: &[Vec<u8>],
    attempts: u32,
) -> Result<Published, ColdError> {
    let body = encode_body(records);
    let publication = Publication {
        shard: manifest.shard,
        segment: manifest.segment,
        manifest: encode_envelope(&body_digest(&body), manifest),
        body,
    };
    publish(store, &publication, attempts).map_err(ColdError::Publish)
}

/// Read a published segment back, refusing anything that does not match what was
/// committed to.
pub fn fetch_segment(
    store: &mut dyn ObjectStore,
    shard: ShardIx,
    segment: SegmentId,
) -> Result<Option<Fetched>, ColdError> {
    let key = manifest_key(shard, segment);
    let Some(envelope) = store.get(&key).map_err(|_| ColdError::Unavailable)? else {
        return Ok(None);
    };
    let (committed_digest, manifest) = decode_envelope(&envelope)?;
    if manifest.shard != shard || manifest.segment != segment {
        return Err(ColdError::WrongSegment);
    }

    let body_key = Publication {
        shard,
        segment,
        manifest: Vec::new(),
        body: Vec::new(),
    }
    .body_key_for(&committed_digest);
    let Some(body) = store.get(&body_key).map_err(|_| ColdError::Unavailable)? else {
        return Err(ColdError::BodyMissing);
    };
    // Checked even though the key contains the digest: the key says what the object
    // should be, and only the bytes say what it is.
    if body_digest(&body) != committed_digest {
        return Err(ColdError::BodyAltered);
    }

    let records = decode_body(&body)?;
    if records.len() as u64 != manifest.records {
        return Err(ColdError::Malformed(
            "the body holds a different number of records than the manifest declares",
        ));
    }
    Ok(Some(Fetched { manifest, records }))
}

/// The same read, by the version the store named when the manifest was committed.
///
/// This is the read that survives an administrator: a plain `get` returns whatever
/// is under the key now, and a version returns what was published.
pub fn fetch_published_manifest(
    store: &mut dyn ObjectStore,
    shard: ShardIx,
    segment: SegmentId,
    version: &VersionId,
) -> Result<Option<(Hash, SegmentManifest)>, ColdError> {
    let key = manifest_key(shard, segment);
    match store
        .get_version(&key, version)
        .map_err(|_| ColdError::Unavailable)?
    {
        Some(bytes) => decode_envelope(&bytes).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_contracts::fakes::{MemoryObjectStore, VersioningObjectStore};
    use trailryx_index::Dimension;
    use trailryx_record::{Algorithms, Timestamp};

    fn manifest(shard: u16, segment: u64, records: u64) -> SegmentManifest {
        SegmentManifest {
            format_version: 1,
            segment: SegmentId(segment),
            shard: ShardIx(shard),
            records,
            history_root: Hash([7u8; 48]),
            index_roots: Dimension::ALL
                .iter()
                .map(|d| (*d, Hash([9u8; 48])))
                .collect(),
            chain_before: Hash([1u8; 48]),
            chain_after: Hash([2u8; 48]),
            first_recorded_at: Timestamp(100),
            last_recorded_at: Timestamp(900),
            algorithms: Algorithms::default(),
        }
    }

    fn records() -> Vec<Vec<u8>> {
        vec![b"first record".to_vec(), b"second".to_vec(), Vec::new()]
    }

    #[test]
    fn a_published_segment_reads_back_exactly() {
        let mut store = MemoryObjectStore::default();
        let m = manifest(3, 42, 3);
        assert!(matches!(
            publish_segment(&mut store, &m, &records(), 1),
            Ok(Published::Committed { .. })
        ));

        let fetched = fetch_segment(&mut store, ShardIx(3), SegmentId(42))
            .expect("a read")
            .expect("a published segment");
        assert_eq!(fetched.manifest, m, "every field survives the round trip");
        assert_eq!(fetched.records, records());
    }

    #[test]
    fn a_segment_nobody_published_is_absent_rather_than_an_error() {
        let mut store = MemoryObjectStore::default();
        assert_eq!(
            fetch_segment(&mut store, ShardIx(0), SegmentId(1)).expect("a read"),
            None
        );
    }

    /// The body is written first and the manifest second, so an interrupted
    /// publication leaves a body nobody can find and the segment reads as absent.
    /// That is the whole reason for the order.
    #[test]
    fn a_publication_interrupted_before_its_commit_reads_as_absent() {
        let mut store = MemoryObjectStore::default();
        let m = manifest(1, 7, 3);
        let body = encode_body(&records());
        store
            .put_if_absent(
                &Publication {
                    shard: m.shard,
                    segment: m.segment,
                    manifest: Vec::new(),
                    body: body.clone(),
                }
                .body_key(),
                &body,
            )
            .expect("the body lands");

        assert_eq!(
            fetch_segment(&mut store, ShardIx(1), SegmentId(7)).expect("a read"),
            None,
            "a body without a manifest is not a published segment"
        );
    }

    /// The defence that matters: somebody with write access replaces the object
    /// under the key the manifest names. The key still resolves and the bytes are
    /// not what was committed to.
    #[test]
    fn a_body_altered_in_the_bucket_is_refused_rather_than_returned() {
        let mut store = VersioningObjectStore::default();
        let m = manifest(2, 9, 3);
        publish_segment(&mut store, &m, &records(), 1).expect("published");

        let body_key = Publication {
            shard: m.shard,
            segment: m.segment,
            manifest: Vec::new(),
            body: encode_body(&records()),
        }
        .body_key();
        let tampered = encode_body(&vec![b"a record nobody sealed".to_vec(); 3]);
        store.overwrite(&body_key, &tampered);

        assert_eq!(
            fetch_segment(&mut store, ShardIx(2), SegmentId(9)),
            Err(ColdError::BodyAltered)
        );
    }

    #[test]
    fn a_manifest_describing_another_segment_is_refused() {
        let mut store = VersioningObjectStore::default();
        let m = manifest(4, 11, 3);
        publish_segment(&mut store, &m, &records(), 1).expect("published");

        // Move the envelope to the key of a different segment, which is what an
        // operator reorganising a bucket does by accident.
        let envelope = store
            .get(&manifest_key(ShardIx(4), SegmentId(11)))
            .expect("a read")
            .expect("an envelope");
        store.overwrite(&manifest_key(ShardIx(4), SegmentId(12)), &envelope);

        assert_eq!(
            fetch_segment(&mut store, ShardIx(4), SegmentId(12)),
            Err(ColdError::WrongSegment)
        );
    }

    #[test]
    fn a_manifest_survives_encoding_with_every_field_intact() {
        for (shard, segment, count) in [(0u16, 0u64, 0u64), (65535, u64::MAX, 12), (7, 42, 1)] {
            let m = manifest(shard, segment, count);
            let bytes = encode_envelope(&Hash([3u8; 48]), &m);
            let (digest, decoded) = decode_envelope(&bytes).expect("a round trip");
            assert_eq!(digest, Hash([3u8; 48]));
            assert_eq!(decoded, m);
        }
    }

    #[test]
    fn every_truncation_of_an_envelope_is_an_error_and_never_a_panic() {
        let bytes = encode_envelope(&Hash([3u8; 48]), &manifest(1, 2, 3));
        for cut in 0..bytes.len() {
            assert!(
                decode_envelope(&bytes[..cut]).is_err(),
                "a truncated envelope must not decode"
            );
        }
        // And a byte appended is not a manifest either: the decoder requires the
        // bytes to end where the manifest ends.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode_envelope(&extra).is_err());
    }

    #[test]
    fn a_body_that_lies_about_its_own_shape_is_refused() {
        assert!(decode_body(&[]).is_err());
        // A count of four billion with nothing behind it.
        let mut lying = u64::MAX.to_be_bytes().to_vec();
        lying.extend_from_slice(&[0, 0, 0, 1, b'x']);
        assert!(decode_body(&lying).is_err());
        // A record longer than what follows it.
        let mut short = 1u64.to_be_bytes().to_vec();
        short.extend_from_slice(&[0, 0, 0, 99, b'x']);
        assert!(decode_body(&short).is_err());
        // Bytes after the last record.
        let mut trailing = encode_body(&records());
        trailing.push(0);
        assert!(decode_body(&trailing).is_err());
    }
}
