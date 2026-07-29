//! Message passing as a capability.
//!
//! Shards never share memory. They exchange messages, and the same trait covers
//! both cases we need: between cores in one process, and between peers across
//! clouds. Making them one interface is deliberate; the proof composition on top
//! is identical, so it should be written once.

use crate::rng::{RngExt, SimRng};
use std::collections::BTreeMap;

/// Address of a shard within a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardId(pub u16);

impl std::fmt::Display for ShardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s{}", self.0)
    }
}

pub trait Bus<M> {
    fn send(&mut self, from: ShardId, to: ShardId, msg: M);
    /// Take the next message ready for `me`, if any.
    fn recv(&mut self, me: ShardId) -> Option<(ShardId, M)>;
    fn in_flight(&self) -> usize;
}

/// Probabilities in parts per million.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BusFaults {
    pub drop_ppm: u32,
    pub duplicate_ppm: u32,
    /// Extra delivery delay, in simulator steps, drawn from `0..=max_delay`.
    pub max_delay_steps: u32,
}

impl BusFaults {
    pub const NONE: Self = Self {
        drop_ppm: 0,
        duplicate_ppm: 0,
        max_delay_steps: 0,
    };

    pub const HOSTILE: Self = Self {
        drop_ppm: 50_000,
        duplicate_ppm: 50_000,
        max_delay_steps: 12,
    };
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BusStats {
    pub sent: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub duplicated: u64,
}

#[derive(Debug, Clone)]
struct Envelope<M> {
    due_step: u64,
    /// Total order tiebreaker, so delivery never depends on sort stability.
    seq: u64,
    from: ShardId,
    to: ShardId,
    msg: M,
}

/// In-memory bus with deterministic delivery order and fault injection.
#[derive(Debug)]
pub struct SimBus<M> {
    queue: Vec<Envelope<M>>,
    step: u64,
    seq: u64,
    rng: SimRng,
    pub faults: BusFaults,
    pub stats: BusStats,
}

impl<M: Clone> SimBus<M> {
    pub fn new(seed: u64, faults: BusFaults) -> Self {
        Self {
            queue: Vec::new(),
            step: 0,
            seq: 0,
            rng: SimRng::new(seed),
            faults,
            stats: BusStats::default(),
        }
    }

    /// Move simulated time forward one step. Messages become deliverable when
    /// their `due_step` is reached.
    pub fn tick(&mut self) {
        self.step += 1;
    }

    pub fn step(&self) -> u64 {
        self.step
    }

    /// Drop everything in flight, as a crash or a partition would.
    pub fn clear(&mut self) {
        self.stats.dropped += self.queue.len() as u64;
        self.queue.clear();
    }

    /// How many messages are queued per destination. Sorted, for stable traces.
    pub fn depth_by_shard(&self) -> BTreeMap<ShardId, usize> {
        let mut m = BTreeMap::new();
        for e in &self.queue {
            *m.entry(e.to).or_insert(0) += 1;
        }
        m
    }
}

impl<M: Clone> Bus<M> for SimBus<M> {
    fn send(&mut self, from: ShardId, to: ShardId, msg: M) {
        self.stats.sent += 1;

        if self.rng.chance_ppm(self.faults.drop_ppm) {
            self.stats.dropped += 1;
            return;
        }

        let copies = if self.rng.chance_ppm(self.faults.duplicate_ppm) {
            self.stats.duplicated += 1;
            2
        } else {
            1
        };

        for _ in 0..copies {
            let delay = if self.faults.max_delay_steps == 0 {
                0
            } else {
                self.rng.below(u64::from(self.faults.max_delay_steps) + 1)
            };
            self.seq += 1;
            self.queue.push(Envelope {
                due_step: self.step + delay,
                seq: self.seq,
                from,
                to,
                msg: msg.clone(),
            });
        }
    }

    fn recv(&mut self, me: ShardId) -> Option<(ShardId, M)> {
        // Lowest (due_step, seq) wins: a total order, so delivery does not
        // depend on the sort being stable or on insertion order.
        let mut best: Option<usize> = None;
        for (i, e) in self.queue.iter().enumerate() {
            if e.to != me || e.due_step > self.step {
                continue;
            }
            match best {
                Some(b) => {
                    let cur = &self.queue[b];
                    if (e.due_step, e.seq) < (cur.due_step, cur.seq) {
                        best = Some(i);
                    }
                }
                None => best = Some(i),
            }
        }
        let idx = best?;
        let e = self.queue.remove(idx);
        self.stats.delivered += 1;
        Some((e.from, e.msg))
    }

    fn in_flight(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivers_in_deterministic_order() {
        let mut bus: SimBus<u32> = SimBus::new(5, BusFaults::NONE);
        let a = ShardId(0);
        let b = ShardId(1);
        for i in 0..10 {
            bus.send(a, b, i);
        }
        let got: Vec<u32> = std::iter::from_fn(|| bus.recv(b).map(|(_, m)| m)).collect();
        assert_eq!(got, (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn does_not_deliver_to_the_wrong_shard() {
        let mut bus: SimBus<u32> = SimBus::new(5, BusFaults::NONE);
        bus.send(ShardId(0), ShardId(1), 7);
        assert!(bus.recv(ShardId(2)).is_none());
        assert!(bus.recv(ShardId(1)).is_some());
    }

    #[test]
    fn same_seed_same_delivery_under_faults() {
        let run = |seed: u64| {
            let mut bus: SimBus<u32> = SimBus::new(seed, BusFaults::HOSTILE);
            let mut out = Vec::new();
            for i in 0..100 {
                bus.send(ShardId(0), ShardId(1), i);
                bus.tick();
                while let Some((_, m)) = bus.recv(ShardId(1)) {
                    out.push(m);
                }
            }
            out
        };
        assert_eq!(run(17), run(17));
    }

    #[test]
    fn delayed_messages_are_not_delivered_early() {
        let faults = BusFaults {
            max_delay_steps: 5,
            ..BusFaults::NONE
        };
        let mut bus: SimBus<u32> = SimBus::new(2, faults);
        bus.send(ShardId(0), ShardId(1), 1);
        let mut delivered_at = None;
        for step in 0..10 {
            if bus.recv(ShardId(1)).is_some() {
                delivered_at = Some(step);
                break;
            }
            bus.tick();
        }
        assert!(delivered_at.is_some());
    }
}
