//! Minting record identities.
//!
//! # Why not a counter
//!
//! The version of this that lived in the demo used one, with a comment saying it
//! stood in for a ULID. It stood in badly. A counter restarts at one when the
//! process does, so the first record after a restart claims an identity a record
//! already has, the journal's deduplication reports it as a duplicate, and the
//! record is dropped. Silent loss, from the one field that must not collide.
//!
//! A ULID cannot do that, because its high bits are the clock. Two records minted
//! in different milliseconds have different ids whatever happened in between, and
//! two minted in the same millisecond differ in the low bits.
//!
//! # Why the time comes from the record
//!
//! The 48-bit timestamp is taken from the record's own `recorded_at` rather than
//! from a clock this module reads. `RecordId` is one of the five provable
//! dimensions and its index sorts on the big-endian bytes, so an id that sorts by
//! time makes that index useful for a time range as well as a point lookup. That
//! only holds if the time in the id is the time in the record.
//!
//! # Monotonic, within one shard
//!
//! Strictly increasing per assembler, which is per shard: the store is
//! shared-nothing and one shard is one thread. Two assemblers on the same shard
//! would be two minters of one identity space, which is a thing this type cannot
//! prevent and its caller must not do.
//!
//! Within a millisecond the standard monotonic rule applies: keep the timestamp
//! and increment the random part rather than drawing a fresh one, so ordering
//! holds even for records that arrive faster than the clock ticks.

use trailryx_record::{RecordId, Timestamp};
use trailryx_sim::rng::Rng;

/// Bits of the identifier that are not the timestamp.
const RANDOM_BITS: u32 = 80;
const RANDOM_MASK: u128 = (1u128 << RANDOM_BITS) - 1;
/// The largest millisecond a 48-bit field holds.
///
/// Unreachable from a [`Timestamp`], and the arithmetic is worth writing down
/// because the clamp below looks like it might matter: a `u64` of nanoseconds
/// runs out around the year 2554, which is 18.4 million million milliseconds,
/// and this field holds 281 million million. So the guard is free and never
/// fires, and it stays in case the timestamp type ever widens.
const MAX_MS: u128 = (1u128 << 48) - 1;

#[derive(Debug)]
pub struct Ids<R> {
    rng: R,
    last: u128,
}

impl<R: Rng> Ids<R> {
    pub fn new(rng: R) -> Self {
        Self { rng, last: 0 }
    }

    /// The next identity for a record recorded at this time.
    pub fn mint(&mut self, recorded_at: Timestamp) -> RecordId {
        let ms = (u128::from(recorded_at.as_nanos()) / 1_000_000).min(MAX_MS);
        let mut candidate = (ms << RANDOM_BITS) | (self.random() & RANDOM_MASK);

        // A clock that went backwards, or two records inside one millisecond.
        // Either way the answer is the same: stay at the last timestamp and step
        // the low bits, so the sequence is strictly increasing whatever the clock
        // does. An id that went backwards would put a record earlier in its own
        // index than the record it was caused by.
        if candidate <= self.last {
            candidate = self.last.saturating_add(1);
        }
        self.last = candidate;
        RecordId(candidate)
    }

    fn random(&mut self) -> u128 {
        // Two draws, because eighty bits do not fit in one.
        (u128::from(self.rng.next_u64()) << 16) | u128::from(self.rng.next_u64() & 0xffff)
    }

    /// The millisecond an identity was minted in.
    ///
    /// Not used by the assembler. It exists because the whole argument for a
    /// ULID over a counter is that this function can exist at all.
    pub fn millisecond_of(id: RecordId) -> u64 {
        (id.0 >> RANDOM_BITS) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_sim::rng::SimRng;

    fn ids(seed: u64) -> Ids<SimRng> {
        Ids::new(SimRng::new(seed))
    }

    #[test]
    fn an_identity_carries_the_time_it_was_recorded_at() {
        let mut ids = ids(1);
        let at = Timestamp(1_700_000_000_123_456_789);
        let id = ids.mint(at);
        assert_eq!(
            Ids::<SimRng>::millisecond_of(id),
            1_700_000_000_123,
            "the high bits are the millisecond"
        );
    }

    #[test]
    fn identities_sort_by_time() {
        // Which is the whole reason the record id is a provable dimension: the
        // index over it answers a time range as well as a point lookup.
        let mut ids = ids(2);
        let early = ids.mint(Timestamp(1_700_000_000_000_000_000));
        let later = ids.mint(Timestamp(1_700_000_060_000_000_000));
        assert!(early.0 < later.0);
        assert!(
            early.0.to_be_bytes() < later.0.to_be_bytes(),
            "and so do the bytes"
        );
    }

    #[test]
    fn two_records_in_one_millisecond_still_increase() {
        let mut ids = ids(3);
        let at = Timestamp(1_700_000_000_000_000_000);
        let a = ids.mint(at);
        let b = ids.mint(at);
        let c = ids.mint(at);
        assert!(a.0 < b.0 && b.0 < c.0);
        assert_eq!(
            Ids::<SimRng>::millisecond_of(a),
            Ids::<SimRng>::millisecond_of(c),
            "and they stay in the millisecond they belong to"
        );
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_take_the_ids_with_it() {
        // NTP corrections happen. An id that went backwards would put a record
        // earlier in its own index than the record that caused it.
        let mut ids = ids(4);
        let first = ids.mint(Timestamp(1_700_000_060_000_000_000));
        let second = ids.mint(Timestamp(1_700_000_000_000_000_000));
        assert!(second.0 > first.0);
    }

    #[test]
    fn a_restart_does_not_reissue_an_identity() {
        // The defect this type exists to prevent. A counter restarts at one, the
        // journal reports the next record as a duplicate of one already in it,
        // and the record is dropped without anything counting it.
        let at = Timestamp(1_700_000_000_000_000_000);
        let before: Vec<RecordId> = (0..5).map(|_| ids(5).mint(at)).collect();

        // A fresh process, a fresh assembler, a later millisecond.
        let mut after = ids(99);
        let next = after.mint(Timestamp(1_700_000_000_001_000_000));
        assert!(
            before.iter().all(|old| old.0 < next.0),
            "an identity minted after a restart collided with one from before"
        );
    }

    #[test]
    fn the_same_seed_and_the_same_times_mint_the_same_identities() {
        // Determinism, so a simulated run is reproducible from its seed.
        let times = [1_700_000_000_000_000_000u64, 1_700_000_000_000_100_000];
        let run = |seed| -> Vec<u128> {
            let mut ids = ids(seed);
            times.iter().map(|t| ids.mint(Timestamp(*t)).0).collect()
        };
        assert_eq!(run(7), run(7));
        assert_ne!(run(7), run(8));
    }

    #[test]
    fn the_timestamp_field_cannot_be_overflowed_from_a_timestamp() {
        // The clamp in `mint` looks load-bearing and is not, which is worth a
        // test rather than a comment: the largest instant a `u64` of nanoseconds
        // can name is far inside the 48-bit millisecond field, so the guard
        // never fires and nothing wraps.
        let mut ids = ids(9);
        let id = ids.mint(Timestamp(u64::MAX));
        let ms = Ids::<SimRng>::millisecond_of(id);
        assert_eq!(ms, u64::MAX / 1_000_000);
        assert!(u128::from(ms) < MAX_MS, "the field is wider than the clock");
    }
}
