//! What S3 Object Lock actually protects, and what it does not.
//!
//! The architecture says WORM means "even an administrator with rights cannot
//! overwrite the segment". Read against the S3 documentation that is true in one
//! retention mode and only if the reader asks for a version:
//!
//! > Retention periods and legal holds **don't prevent new versions of the object
//! > from being created**, or delete markers to be added on top of the object.
//!
//! So Object Lock protects a **version**, not a key. An actor with credentials can
//! always write a new version, and every reader that asks for the key alone gets it.
//! And a plain `DELETE` returns `200 OK`, inserts a delete marker, and the object
//! vanishes from an ordinary read while the locked version sits underneath.
//!
//! `VersioningObjectStore` models exactly that behaviour, so the attack can be run
//! rather than described. Each test is one sentence from the documentation.

use trailryx_contracts::contracts::{ObjectStore, PutOutcome};
use trailryx_contracts::fakes::{MemoryObjectStore, VersioningObjectStore};

const KEY: &str = "segments/0001.manifest";
const HONEST: &[u8] = b"the segment as it was sealed";
const FORGED: &[u8] = b"the segment somebody would rather you read";

/// The conditional write refuses a second publisher. That is what it is for, and it
/// is **not enough**: an actor with credentials does not need `put_if_absent`.
#[test]
fn the_conditional_write_stops_a_second_publisher_and_not_an_administrator() {
    let mut store = VersioningObjectStore::default();
    let (outcome, version) = store.put_if_absent(KEY, HONEST).unwrap();
    assert_eq!(outcome, PutOutcome::Written);
    let version = version.expect("a versioning store must say what it wrote");

    // A second publisher, refused.
    let (outcome, _) = store.put_if_absent(KEY, FORGED).unwrap();
    assert_eq!(outcome, PutOutcome::AlreadyExists);

    // An administrator, not refused. This is the S3 behaviour the documentation
    // describes, and Object Lock does not change it.
    store.overwrite(KEY, FORGED);
    assert_eq!(
        store.get(KEY).unwrap().as_deref(),
        Some(FORGED),
        "a plain read now returns the forged bytes, which is the whole problem"
    );

    // And the published version is still there, untouched, for a reader who asks.
    assert_eq!(
        store.get_version(KEY, &version).unwrap().as_deref(),
        Some(HONEST),
        "reading by version is what makes Object Lock protect anything"
    );
}

/// A delete succeeds, hides the object, and destroys nothing. A reader that treats
/// absence as "it was never published" would be wrong in the most damaging direction.
#[test]
fn a_delete_marker_hides_the_object_and_the_version_survives() {
    let mut store = VersioningObjectStore::default();
    let (_, version) = store.put_if_absent(KEY, HONEST).unwrap();
    let version = version.expect("a version");

    store.delete_marker(KEY);

    assert_eq!(
        store.get(KEY).unwrap(),
        None,
        "an ordinary read sees nothing, which is what a delete marker does"
    );
    assert!(
        !store.list("segments/").unwrap().contains(&KEY.to_owned()),
        "and a listing does not show it either"
    );
    assert_eq!(
        store.get_version(KEY, &version).unwrap().as_deref(),
        Some(HONEST),
        "the locked version is intact underneath, and unreachable to anybody who does \
         not know to ask for it"
    );
}

/// Several forgeries do not reach the published version, however many there are.
#[test]
fn no_number_of_later_versions_reaches_the_published_one() {
    let mut store = VersioningObjectStore::default();
    let (_, version) = store.put_if_absent(KEY, HONEST).unwrap();
    let version = version.expect("a version");

    for i in 0..8 {
        store.overwrite(KEY, format!("forgery {i}").as_bytes());
    }
    store.delete_marker(KEY);
    store.overwrite(KEY, FORGED);

    assert_eq!(store.version_count(KEY), 10);
    assert_eq!(
        store.get_version(KEY, &version).unwrap().as_deref(),
        Some(HONEST)
    );
}

/// A store with no versioning says so, rather than handing out a token it cannot
/// honour. A caller then knows this deployment cannot offer the protection, which is
/// the thing that must not be assumed: "we enabled Object Lock" is a sentence that
/// ends up in a compliance document.
#[test]
fn a_store_without_versioning_admits_it_rather_than_pretending() {
    let mut store = MemoryObjectStore::default();
    let (outcome, version) = store.put_if_absent(KEY, HONEST).unwrap();
    assert_eq!(outcome, PutOutcome::Written);
    assert!(
        version.is_none(),
        "a store with no versioning must not invent a token"
    );
    assert!(
        store
            .get_version(KEY, &trailryx_contracts::contracts::VersionId("v1".into()))
            .is_err(),
        "and it must refuse a version read rather than answering from the key"
    );
}

/// Both stores pass the contract's own suite, so the version check is part of the
/// contract rather than a property of one fake.
#[test]
fn both_stores_satisfy_the_object_store_contract() {
    for (name, report) in [
        (
            "memory",
            trailryx_contracts::conformance::object_store(&mut MemoryObjectStore::default()),
        ),
        (
            "versioning",
            trailryx_contracts::conformance::object_store(&mut VersioningObjectStore::default()),
        ),
    ] {
        let failures: Vec<_> = report.failures().map(|c| c.name).collect();
        assert!(failures.is_empty(), "{name}: {failures:?}");
    }
}
