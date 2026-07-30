//! Publishing a sealed segment to cold storage, atomically, with no coordinator.
//!
//! # The protocol, and where it comes from
//!
//! Two objects, in this order:
//!
//! 1. the **segment body**, at a key that contains its own digest;
//! 2. the **manifest**, at a key derived from the shard and the segment number.
//!
//! The manifest is written last and with a conditional write, and that single write
//! is the commit point: a segment is published if and only if its manifest is there.
//! A body without a manifest is invisible and costs storage, which is a cost a
//! lifecycle rule can clean up; a manifest without a body would be a published
//! commitment to bytes nobody can read, which is not recoverable at all. So the
//! order is not a preference.
//!
//! This is the shape Thanos uses for a TSDB block (`meta.json` written last, blocks
//! without it ignored), the shape Iceberg uses for a metadata pointer, and the shape
//! Delta uses for a log entry. All three converged on it because it is what an
//! object store can actually promise: no multi-object transaction, one conditional
//! write.
//!
//! # The retry that looks like a conflict
//!
//! A conditional write returns `AlreadyExists` when somebody got there first, and
//! **also when the somebody was us**. A publisher that timed out, retried, and found
//! its own manifest in place would report a conflict with itself, which is either a
//! false alarm or, worse, a reason to publish under a different name and split the
//! record in two.
//!
//! Every system that gets this right carries an idempotency token: Kafka's producer
//! id and sequence, Stripe's idempotency key, Delta's transaction identifiers. Here
//! the token is the manifest itself. It is a deterministic function of what was
//! sealed, so "is this mine?" is answered by reading the stored manifest back and
//! comparing bytes. No extra state, nothing to keep in sync, and it answers the
//! harder question at the same time:
//!
//! - **the same bytes** means this segment is published, by us or by a peer that
//!   sealed the identical records. Success either way.
//! - **different bytes** means two publishers sealed *different* records under one
//!   segment number. That is a real divergence and it is reported loudly, because
//!   every proof over that segment would otherwise depend on which copy a reader
//!   happened to fetch.
//!
//! # What this crate does not do
//!
//! It does not retry on a schedule and it does not sleep, because it has no clock:
//! a caller passes an attempt budget and decides the delays. It does not know what a
//! manifest means, only that it is bytes with a digest. And it never deletes: a
//! failed publication leaves an orphan body, which the operator's lifecycle rule
//! removes, because a publisher that cleans up after itself is a publisher that can
//! delete somebody else's segment on a bad day.

use trailryx_contracts::{AdapterError, ObjectStore, PutOutcome, VersionId};
use trailryx_crypto::{Digest, Sha384};
use trailryx_record::{Hash, SegmentId, ShardIx};

pub mod faults;

/// A sealed segment, in the only shape publication cares about.
///
/// The manifest arrives already encoded: this crate publishes bytes and refuses to
/// have an opinion about their meaning, so the encoding stays in one place and a
/// change to it cannot silently change what gets published.
///
/// # The one invariant the caller owns
///
/// **The manifest must commit to the body**, by carrying its digest or by carrying
/// the roots the body is built from. This crate cannot check that, because it
/// deliberately cannot read a manifest, and the consequence of getting it wrong is
/// not visible here: the body key names its content, so a body that does not match
/// its manifest simply sits at a different key and the manifest points at nothing
/// a reader can find. The real `SegmentManifest` in `trailryx-index` satisfies this by
/// construction, since its root covers the history and index roots of exactly those
/// records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    pub shard: ShardIx,
    pub segment: SegmentId,
    /// The encoded segment manifest. This is the commit point.
    pub manifest: Vec<u8>,
    /// The segment body.
    pub body: Vec<u8>,
}

impl Publication {
    /// Where the body goes: the key carries the body's own digest.
    ///
    /// Content addressing is what makes the body's conditional write free of the
    /// question the manifest's needs answered. `AlreadyExists` on a key that names
    /// the content means the content is already there, so there is nothing to read
    /// back and compare, and a retry of a half-finished publication costs one
    /// refused write rather than a re-upload.
    pub fn body_key(&self) -> String {
        format!(
            "segments/{}/{:016x}-{}.trx",
            self.shard,
            self.segment.0,
            digest(&self.body).to_hex()
        )
    }

    /// Where the manifest goes. Derived from identity alone, because this key is
    /// what two publishers have to race for.
    pub fn manifest_key(&self) -> String {
        format!("manifests/{}/{:016x}.mf", self.shard, self.segment.0)
    }
}

fn digest(bytes: &[u8]) -> Hash {
    let mut h = Sha384::new();
    h.update(b"trailryx/published-object/v1\0");
    h.update(bytes);
    h.finish()
}

/// What a publication turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    /// This call wrote the manifest. The segment is published now, by us.
    Committed { version: Option<VersionId> },
    /// The manifest was already there and is byte-identical to ours.
    ///
    /// Either a retry of our own write whose acknowledgement was lost, or a peer
    /// that sealed the identical records. Both are success, and the caller cannot
    /// tell them apart, because there is nothing here that would let it.
    AlreadyPublished,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// The store could not be reached, or refused, and the attempt budget ran out.
    /// Nothing was committed, and calling again later is the right thing to do.
    Unavailable { attempts: u32, last: AdapterError },
    /// The store cannot honour the contract: no conditional write, no versioning.
    /// A retry will not change it.
    Unsupported(&'static str),
    /// Two publishers sealed different records under one segment number.
    ///
    /// The store now holds somebody else's manifest under a name this publisher
    /// believes is its own. Nothing is overwritten and nothing is deleted: the
    /// operator is told, because the alternative is a record whose meaning depends
    /// on which copy a reader fetched.
    Diverged {
        key: String,
        ours: Hash,
        theirs: Hash,
    },
    /// The manifest was refused as already present and then could not be read back,
    /// so whether this publisher won cannot be established. Reported rather than
    /// assumed in either direction.
    Indeterminate { key: String },
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { attempts, last } => write!(
                f,
                "nothing was published after {attempts} attempts; the last was {last}"
            ),
            Self::Unsupported(why) => write!(f, "this store cannot publish a segment: {why}"),
            Self::Diverged { key, ours, theirs } => write!(
                f,
                "two publishers sealed different segments under {key}: ours is {}, the \
                 stored one is {}",
                ours.to_hex(),
                theirs.to_hex()
            ),
            Self::Indeterminate { key } => write!(
                f,
                "{key} was refused as already present and could not be read back, so \
                 whether this segment is published is unknown"
            ),
        }
    }
}

impl std::error::Error for PublishError {}

/// Publish a sealed segment, retrying transient failures up to `attempts` times.
///
/// `attempts` counts tries, not retries, so `1` means no retry at all. The delay
/// between them is the caller's, because this crate has no clock and a publisher
/// that slept would be untestable at any scale worth testing.
pub fn publish(
    store: &mut dyn ObjectStore,
    publication: &Publication,
    attempts: u32,
) -> Result<Published, PublishError> {
    let attempts = attempts.max(1);

    // The body first. Its key names its content, so a second publisher writing the
    // same bytes and a retry of our own write are the same event and neither needs
    // reading back.
    let body_key = publication.body_key();
    retrying(
        attempts,
        |store| store.put_if_absent(&body_key, &publication.body),
        store,
    )?;

    // The manifest last, and this write is the commit.
    let manifest_key = publication.manifest_key();
    let outcome = retrying(
        attempts,
        |store| store.put_if_absent(&manifest_key, &publication.manifest),
        store,
    )?;

    match outcome {
        (PutOutcome::Written, version) => Ok(Published::Committed { version }),
        (PutOutcome::AlreadyExists, _) => {
            // Somebody wrote this manifest. Possibly us, on an attempt whose
            // acknowledgement never arrived. Read it back and let the bytes say.
            let stored = retrying(attempts, |store| store.get(&manifest_key), store)?;
            match stored {
                Some(stored) if stored == publication.manifest => Ok(Published::AlreadyPublished),
                Some(stored) => Err(PublishError::Diverged {
                    key: manifest_key,
                    ours: digest(&publication.manifest),
                    theirs: digest(&stored),
                }),
                // Refused as present, then absent. A delete between the two calls,
                // or a store whose read is not consistent with its write. Either way
                // this publisher cannot say whether the segment is published, and
                // saying so is better than picking the comfortable answer.
                None => Err(PublishError::Indeterminate { key: manifest_key }),
            }
        }
    }
}

/// Retry a call while it fails transiently, and stop the moment it will not.
///
/// `Unsupported` is never retried: it is the store saying it cannot do this at all,
/// and repeating the request only delays telling the operator.
fn retrying<T>(
    attempts: u32,
    mut call: impl FnMut(&mut dyn ObjectStore) -> Result<T, AdapterError>,
    store: &mut dyn ObjectStore,
) -> Result<T, PublishError> {
    let mut last = AdapterError::Unavailable("not attempted");
    for _ in 0..attempts {
        match call(store) {
            Ok(value) => return Ok(value),
            Err(AdapterError::Unsupported(why)) => return Err(PublishError::Unsupported(why)),
            Err(other) => last = other,
        }
    }
    Err(PublishError::Unavailable { attempts, last })
}

/// Read a published segment back by the version the store named when it was
/// committed, which is the only read that survives an administrator.
///
/// A store that answers `Unsupported` here is a deployment where WORM protects
/// nothing, and that is worth knowing before a regulator asks rather than after.
pub fn read_published(
    store: &mut dyn ObjectStore,
    key: &str,
    version: &VersionId,
) -> Result<Option<Vec<u8>>, AdapterError> {
    store.get_version(key, version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_contracts::fakes::MemoryObjectStore;

    fn publication(segment: u64, body: &[u8]) -> Publication {
        Publication {
            shard: ShardIx(0),
            segment: SegmentId(segment),
            manifest: format!("manifest for {segment} over {}", body.len()).into_bytes(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn a_publication_writes_the_body_before_the_manifest() {
        let mut store = MemoryObjectStore::default();
        let p = publication(1, b"records");
        assert!(matches!(
            publish(&mut store, &p, 1),
            Ok(Published::Committed { .. })
        ));
        assert_eq!(
            store.get(&p.body_key()).expect("a read"),
            Some(b"records".to_vec())
        );
        assert_eq!(
            store.get(&p.manifest_key()).expect("a read"),
            Some(p.manifest.clone())
        );
    }

    /// The retry that looks like a conflict. A publisher whose acknowledgement was
    /// lost must recognise its own manifest rather than report a rival.
    #[test]
    fn republishing_the_same_segment_is_success_and_not_a_conflict() {
        let mut store = MemoryObjectStore::default();
        let p = publication(1, b"records");
        publish(&mut store, &p, 1).expect("the first publication");
        assert_eq!(
            publish(&mut store, &p, 1),
            Ok(Published::AlreadyPublished),
            "the same segment published twice is the same segment"
        );
    }

    /// Two publishers, one segment number, different records. Nothing is
    /// overwritten and the operator is told which two manifests disagree.
    #[test]
    fn two_publishers_sealing_different_records_is_reported_rather_than_resolved() {
        let mut store = MemoryObjectStore::default();
        let ours = publication(1, b"our records");
        let theirs = Publication {
            manifest: b"a different manifest".to_vec(),
            ..publication(1, b"their records")
        };
        publish(&mut store, &theirs, 1).expect("the rival got there first");

        let failure = publish(&mut store, &ours, 1).expect_err("must not be resolved quietly");
        match failure {
            PublishError::Diverged {
                key,
                ours: a,
                theirs: b,
            } => {
                assert_eq!(key, ours.manifest_key());
                assert_ne!(a, b);
            }
            other => panic!("expected a divergence, got {other}"),
        }
        assert_eq!(
            store.get(&ours.manifest_key()).expect("a read"),
            Some(b"a different manifest".to_vec()),
            "the rival's manifest is untouched"
        );
    }

    /// A store that cannot do conditional writes must be reported at once. Burning
    /// the attempt budget on it delays the only useful message by exactly the length
    /// of the retry policy, and the answer will not change.
    #[test]
    fn an_unsupported_store_is_reported_immediately_rather_than_retried() {
        #[derive(Default)]
        struct Cannot {
            calls: usize,
        }
        impl ObjectStore for Cannot {
            fn put_if_absent(
                &mut self,
                _key: &str,
                _bytes: &[u8],
            ) -> Result<(PutOutcome, Option<VersionId>), AdapterError> {
                self.calls += 1;
                Err(AdapterError::Unsupported("no conditional write here"))
            }
            fn get(&mut self, _key: &str) -> Result<Option<Vec<u8>>, AdapterError> {
                unreachable!("publication must stop before any read")
            }
            fn get_version(
                &mut self,
                _key: &str,
                _version: &VersionId,
            ) -> Result<Option<Vec<u8>>, AdapterError> {
                unreachable!("publication must stop before any read")
            }
            fn list(&mut self, _prefix: &str) -> Result<Vec<String>, AdapterError> {
                unreachable!("publication must stop before any listing")
            }
        }

        let mut store = Cannot::default();
        let failure = publish(&mut store, &publication(1, b"records"), 5)
            .expect_err("an unsupported store cannot publish");
        assert!(matches!(failure, PublishError::Unsupported(_)), "{failure}");
        assert_eq!(
            store.calls, 1,
            "it must be asked once, not once per attempt"
        );
    }

    #[test]
    fn a_body_key_names_its_own_content_and_a_manifest_key_names_its_identity() {
        let a = publication(7, b"one");
        let b = publication(7, b"two");
        assert_ne!(
            a.body_key(),
            b.body_key(),
            "different bytes cannot share a body key"
        );
        assert_eq!(
            a.manifest_key(),
            b.manifest_key(),
            "the same segment number is exactly what two publishers race for"
        );
        assert!(
            a.manifest_key().starts_with("manifests/s0/"),
            "{}",
            a.manifest_key()
        );
    }
}
