//! Publication under a store that fails, across seeds.
//!
//! This is stage 11's acceptance criterion written as a test: a segment publishes
//! atomically, double publication is impossible, and **a simulator injecting
//! conditional-write failures produces no divergence**.
//!
//! Every run is a seed. A failing seed is a command somebody else can run, which is
//! the only reason a probabilistic test is worth having.

use trailryx_contracts::{ObjectStore, fakes::MemoryObjectStore};
use trailryx_publish::faults::{FaultyStore, StoreFaults};
use trailryx_publish::{Publication, PublishError, Published, publish};
use trailryx_record::{SegmentId, ShardIx};

const SEEDS: u64 = 200;
/// Attempts inside one `publish` call. The caller's rounds are separate, because a
/// real publisher comes back after a delay rather than hammering the store.
const ATTEMPTS: u32 = 3;
const ROUNDS: usize = 40;

fn publication(segment: u64, records: &str) -> Publication {
    Publication {
        shard: ShardIx(3),
        segment: SegmentId(segment),
        manifest: format!("root over [{records}]").into_bytes(),
        body: format!("segment body: {records}").into_bytes(),
    }
}

/// One publisher, a store having a bad afternoon. It must converge on publishing
/// exactly this segment, and it must never mistake its own lost write for a rival.
#[test]
fn a_publisher_converges_and_never_reports_a_conflict_with_itself() {
    let mut converged = 0;
    let mut saw_a_lost_acknowledgement = 0;

    for seed in 0..SEEDS {
        let mut store = FaultyStore::new(MemoryObjectStore::default(), seed, StoreFaults::HOSTILE);
        let ours = publication(1, "a,b,c");
        let mut rounds = 0;
        let outcome = loop {
            rounds += 1;
            match publish(&mut store, &ours, ATTEMPTS) {
                Ok(published) => break Some(published),
                Err(PublishError::Unavailable { .. }) if rounds < ROUNDS => continue,
                Err(PublishError::Unavailable { .. }) => break None,
                // Anything else from a single publisher is the protocol confusing
                // itself, which is the whole thing this test exists to forbid.
                Err(other) => panic!("seed {seed}: {other}"),
            }
        };

        let Some(outcome) = outcome else { continue };
        converged += 1;
        if outcome == Published::AlreadyPublished {
            // The only way a single publisher can meet its own manifest is a write
            // whose acknowledgement was lost. If this never happened, the fault
            // that matters was never exercised and this test proves less than it
            // appears to.
            saw_a_lost_acknowledgement += 1;
        }

        let stored = store
            .inner()
            .get(&ours.manifest_key())
            .expect("the store is readable at the end")
            .unwrap_or_else(|| panic!("seed {seed}: it claimed success and published nothing"));
        assert_eq!(
            stored, ours.manifest,
            "seed {seed}: the published manifest is not the one that was sealed"
        );

        // Exactly one manifest was ever written to that key, whatever the caller
        // was told along the way. This is the invariant a coordinator would have
        // been for.
        let writes = store
            .committed
            .iter()
            .filter(|k| **k == ours.manifest_key())
            .count();
        assert_eq!(
            writes, 1,
            "seed {seed}: the manifest was written {writes} times"
        );
    }

    assert_eq!(
        converged, SEEDS,
        "every seed must reach a decision within {ROUNDS} rounds"
    );
    assert!(
        saw_a_lost_acknowledgement > 10,
        "only {saw_a_lost_acknowledgement} of {SEEDS} seeds exercised a lost acknowledgement, \
         which is too few for this test to be measuring the fault it exists for"
    );
}

/// Two publishers that sealed the same records. Both are right, and neither may be
/// told it lost anything: their manifests are identical, so there is nothing to
/// resolve.
///
/// Note what this test may **not** assert: that somebody reports `Committed`. Under a
/// lost acknowledgement the write lands and the answer does not, so the publisher
/// retries, meets its own manifest, and is correctly told `AlreadyPublished`. The
/// segment is published and nobody was ever told they wrote it. The first version of
/// this test demanded a `Committed` and failed on seed 17 for exactly that reason:
/// the assertion was wrong, and it was wrong about the one behaviour this crate
/// exists to get right.
#[test]
fn two_publishers_that_agree_both_succeed() {
    for seed in 0..SEEDS {
        let mut store = FaultyStore::new(MemoryObjectStore::default(), seed, StoreFaults::HOSTILE);
        let ours = publication(9, "a,b,c");
        let theirs = publication(9, "a,b,c");

        let mut succeeded = 0;
        for who in [&ours, &theirs] {
            for _ in 0..ROUNDS {
                match publish(&mut store, who, ATTEMPTS) {
                    Ok(_) => {
                        succeeded += 1;
                        break;
                    }
                    Err(PublishError::Unavailable { .. }) => continue,
                    Err(other) => panic!("seed {seed}: {other}"),
                }
            }
        }
        assert_eq!(
            succeeded, 2,
            "seed {seed}: publishers that agree must both be told they succeeded"
        );
        assert_eq!(
            store.inner().get(&ours.manifest_key()).expect("a read"),
            Some(ours.manifest.clone()),
            "seed {seed}: and the agreed manifest is what is stored"
        );
        let writes = store
            .committed
            .iter()
            .filter(|k| **k == ours.manifest_key())
            .count();
        assert_eq!(
            writes, 1,
            "seed {seed}: two agreeing publishers still write the manifest once"
        );
    }
}

/// Two publishers that sealed **different** records under one segment number. This
/// is the case a coordinator was supposed to prevent, and the conditional write
/// does: one wins, the other is told, and nothing is overwritten.
#[test]
fn two_publishers_that_disagree_cannot_both_publish() {
    let mut divergences = 0;

    for seed in 0..SEEDS {
        let mut store = FaultyStore::new(MemoryObjectStore::default(), seed, StoreFaults::HOSTILE);
        let ours = publication(9, "a,b,c");
        let theirs = publication(9, "a,b,d");

        let mut winners = Vec::new();
        for who in [&ours, &theirs] {
            for _ in 0..ROUNDS {
                match publish(&mut store, who, ATTEMPTS) {
                    // Either variant means this publisher's own manifest is the one
                    // in the store, so the claim is checked against the bytes rather
                    // than believed.
                    Ok(_) => {
                        assert_eq!(
                            store.inner().get(&who.manifest_key()).expect("a read"),
                            Some(who.manifest.clone()),
                            "seed {seed}: a publisher was told it succeeded and the store \
                             holds somebody else's manifest"
                        );
                        winners.push(who.manifest.clone());
                        break;
                    }
                    Err(PublishError::Diverged {
                        ours: a, theirs: b, ..
                    }) => {
                        assert_ne!(a, b, "seed {seed}: a divergence between identical bytes");
                        divergences += 1;
                        break;
                    }
                    Err(PublishError::Unavailable { .. }) => continue,
                    Err(PublishError::Indeterminate { .. }) => break,
                    Err(other) => panic!("seed {seed}: {other}"),
                }
            }
        }

        assert_eq!(
            winners.len(),
            1,
            "seed {seed}: exactly one publisher may publish under one segment number"
        );
        assert_eq!(
            store.inner().get(&ours.manifest_key()).expect("a read"),
            Some(winners[0].clone()),
            "seed {seed}: the winner's manifest must be untouched"
        );
        // Both bodies may exist, because content addressing gives them different
        // keys. That is correct and is what a lifecycle rule is for: the loser's
        // body is an orphan, not a competing segment.
        assert!(
            store
                .inner()
                .get(&ours.body_key())
                .expect("a read")
                .is_some()
                || store
                    .inner()
                    .get(&theirs.body_key())
                    .expect("a read")
                    .is_some(),
            "seed {seed}: at least the winner's body must be stored"
        );
    }

    assert!(
        divergences > SEEDS / 2,
        "only {divergences} of {SEEDS} seeds reached the divergence, so the losing \
         publisher mostly never got far enough to be told"
    );
}

/// With no faults at all, the protocol is two writes and nothing else. Worth
/// pinning: a retry loop that quietly did extra work on the happy path would show
/// up here and nowhere else.
#[test]
fn the_happy_path_is_exactly_two_writes() {
    let mut store = FaultyStore::new(MemoryObjectStore::default(), 0, StoreFaults::NONE);
    let ours = publication(1, "a");
    assert!(matches!(
        publish(&mut store, &ours, ATTEMPTS),
        Ok(Published::Committed { .. })
    ));
    assert_eq!(
        store.committed,
        vec![ours.body_key(), ours.manifest_key()],
        "the body first, the manifest last, and nothing else"
    );
}
