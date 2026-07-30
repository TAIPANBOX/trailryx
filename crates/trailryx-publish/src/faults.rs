//! An object store that fails the way object stores actually fail.
//!
//! The same shape as [`trailryx_sim::IoFaults`] and `BusFaults`, for the same
//! reason: a fault model that is a struct of rates, driven by the seeded RNG, so a
//! failing run is a seed somebody else can rerun.
//!
//! # The fault that matters
//!
//! `unavailable_ppm` is the easy one: the call fails and nothing happened. Every
//! retry loop handles it, which is why it finds almost nothing.
//!
//! `lost_ack_ppm` is the one worth building. **The write reaches the store and the
//! answer does not reach the caller.** A timeout, a reset connection, a load
//! balancer that gave up. The caller sees a failure and retries, and the retry hits
//! a key that now exists, written by nobody but itself. A publisher that reads
//! `AlreadyExists` as "a rival published" would then report a conflict with itself
//! and, if it responded by publishing under another name, would split one segment
//! into two.
//!
//! Nothing distinguishes a lost acknowledgement from a genuine race at the moment it
//! happens. The only way through is to compare what is stored against what was going
//! to be written, which is what the protocol does, and this fault is how that gets
//! tested rather than asserted.

use trailryx_contracts::{AdapterError, AdapterResult, ObjectStore, PutOutcome, VersionId};
use trailryx_sim::{RngExt, SimRng};

/// Rates in parts per million, the same unit the rest of the simulator uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreFaults {
    /// The call fails and nothing happened.
    pub unavailable_ppm: u32,
    /// The write happens and the caller is told it failed. The lost acknowledgement.
    pub lost_ack_ppm: u32,
    /// A read fails. Separate from `unavailable_ppm` because the protocol's read is
    /// the step that decides whether a refused write was its own, and a store that
    /// writes fine and reads badly is a real deployment, not a contrived one.
    pub read_error_ppm: u32,
}

impl StoreFaults {
    /// Everything off.
    pub const NONE: Self = Self {
        unavailable_ppm: 0,
        lost_ack_ppm: 0,
        read_error_ppm: 0,
    };

    /// A deliberately bad afternoon in one region.
    pub const HOSTILE: Self = Self {
        unavailable_ppm: 150_000,
        lost_ack_ppm: 120_000,
        read_error_ppm: 80_000,
    };
}

/// Wraps any store and makes it misbehave deterministically.
#[derive(Debug)]
pub struct FaultyStore<S: ObjectStore> {
    inner: S,
    rng: SimRng,
    faults: StoreFaults,
    /// Every write the store actually performed, including the ones the caller was
    /// told had failed. A test asserts on this: it is the difference between what
    /// happened and what the caller believes happened.
    pub committed: Vec<String>,
}

impl<S: ObjectStore> FaultyStore<S> {
    pub fn new(inner: S, seed: u64, faults: StoreFaults) -> Self {
        Self {
            inner,
            rng: SimRng::new(seed),
            faults,
            committed: Vec::new(),
        }
    }

    pub fn inner(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: ObjectStore> ObjectStore for FaultyStore<S> {
    fn put_if_absent(
        &mut self,
        key: &str,
        bytes: &[u8],
    ) -> AdapterResult<(PutOutcome, Option<VersionId>)> {
        if self.rng.chance_ppm(self.faults.unavailable_ppm) {
            return Err(AdapterError::Unavailable("the store was unreachable"));
        }
        let lost = self.rng.chance_ppm(self.faults.lost_ack_ppm);
        let outcome = self.inner.put_if_absent(key, bytes)?;
        if outcome.0 == PutOutcome::Written {
            self.committed.push(key.to_owned());
        }
        if lost {
            // The write is done. The caller will never know it.
            return Err(AdapterError::Unavailable(
                "the store answered after the connection was gone",
            ));
        }
        Ok(outcome)
    }

    fn get(&mut self, key: &str) -> AdapterResult<Option<Vec<u8>>> {
        if self.rng.chance_ppm(self.faults.read_error_ppm) {
            return Err(AdapterError::Unavailable("the read failed"));
        }
        self.inner.get(key)
    }

    fn get_version(&mut self, key: &str, version: &VersionId) -> AdapterResult<Option<Vec<u8>>> {
        if self.rng.chance_ppm(self.faults.read_error_ppm) {
            return Err(AdapterError::Unavailable("the read failed"));
        }
        self.inner.get_version(key, version)
    }

    fn list(&mut self, prefix: &str) -> AdapterResult<Vec<String>> {
        if self.rng.chance_ppm(self.faults.read_error_ppm) {
            return Err(AdapterError::Unavailable("the listing failed"));
        }
        self.inner.list(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_contracts::fakes::MemoryObjectStore;

    /// The fault this module exists for, stated as a test: the caller is told the
    /// write failed, and the object is there.
    #[test]
    fn a_lost_acknowledgement_leaves_the_write_in_place() {
        let mut store = FaultyStore::new(
            MemoryObjectStore::default(),
            1,
            StoreFaults {
                lost_ack_ppm: 1_000_000,
                ..StoreFaults::NONE
            },
        );
        let failure = store
            .put_if_absent("k", b"bytes")
            .expect_err("the caller must be told it failed");
        assert!(matches!(failure, AdapterError::Unavailable(_)), "{failure}");
        assert_eq!(
            store.get("k").expect("a read"),
            Some(b"bytes".to_vec()),
            "and yet the object is there, which is the whole problem"
        );
        assert_eq!(store.committed, vec!["k".to_owned()]);
    }

    #[test]
    fn the_same_seed_produces_the_same_faults() {
        let run = |seed: u64| {
            let mut store =
                FaultyStore::new(MemoryObjectStore::default(), seed, StoreFaults::HOSTILE);
            (0..50)
                .map(|n| {
                    store
                        .put_if_absent(&format!("k{n}"), b"x")
                        .map(|(outcome, _)| outcome)
                        .map_err(|e| e.to_string())
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(run(7), run(7), "a seed is the whole state");
        assert_ne!(run(7), run(8), "and different seeds do different things");
    }
}
