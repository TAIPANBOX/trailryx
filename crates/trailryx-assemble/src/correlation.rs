//! Remembering what a source called things, for as long as that is useful.
//!
//! A source names events in its own terms: a span id, a message id, an offset.
//! Those names are matched against each other to turn a parent reference into a
//! `caused_by` edge over our own record ids, and then they are done. They never
//! reach a record, which is why
//! [`trailryx_contracts::ingest::MetaDraft`] has no field for one.
//!
//! # Why it is bounded
//!
//! The version of this that lived in the demo was an unbounded map. A demo runs
//! for a second and exits, so it never mattered there; a receiver runs for
//! months and would accumulate every span id it had ever seen. That is a leak
//! whose symptom is a store that gets slower and then stops.
//!
//! A window is the right shape rather than a compromise: a parent and its child
//! are milliseconds apart in a trace, so a window of tens of thousands of names
//! covers the real distance by orders of magnitude.
//!
//! What the window does **not** fix is arrival order, and the first version of
//! this claimed it did. "A parent arrives before its child by construction" is
//! false for OpenTelemetry, the only source in the tree: a span is exported when
//! it ends, and a child ends inside its parent, so a batch arrives children
//! first. No window size helps with that, because resolution happened before the
//! current event was remembered. [`super::Assembler::adopt_batch`] is the fix:
//! remember every name in a batch, then resolve.
//!
//! A parent genuinely out of the window is still not something to guess about.
//! The edge is absent, and [`super::Assembler::unresolved_parents`] counts it, so
//! an absent edge is visible rather than indistinguishable from an event that
//! never had a parent.

use std::collections::{BTreeMap, VecDeque};
use trailryx_contracts::ingest::SourceKey;
use trailryx_record::RecordId;

/// The most recent source names, and what we called them.
#[derive(Debug)]
pub struct Correlation {
    seen: BTreeMap<SourceKey, RecordId>,
    order: VecDeque<SourceKey>,
    capacity: usize,
}

impl Correlation {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: BTreeMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// What we called the event a source named this.
    pub fn resolve(&self, key: &SourceKey) -> Option<RecordId> {
        self.seen.get(key).copied()
    }

    /// Remember a name, evicting the oldest if the window is full.
    ///
    /// A repeat of a name already held updates nothing: the first record to claim
    /// a source name keeps it. A source that reuses a span id is either broken or
    /// trying something, and either way the edge should point at the event that
    /// arrived first rather than at whichever arrived last.
    pub fn remember(&mut self, key: SourceKey, id: RecordId) {
        if self.seen.contains_key(&key) {
            return;
        }
        self.seen.insert(key, id);
        self.order.push_back(key);
        if self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SourceKey {
        SourceKey::new(&[n; 8]).expect("eight bytes is a key")
    }

    #[test]
    fn a_name_resolves_to_what_we_called_it() {
        let mut c = Correlation::new(4);
        c.remember(key(1), RecordId(10));
        assert_eq!(c.resolve(&key(1)), Some(RecordId(10)));
        assert_eq!(c.resolve(&key(2)), None);
    }

    #[test]
    fn the_window_is_bounded_and_drops_the_oldest() {
        // The leak this type exists to prevent: a receiver runs for months.
        let mut c = Correlation::new(3);
        for n in 1..=5 {
            c.remember(key(n), RecordId(u128::from(n)));
        }
        assert_eq!(c.len(), 3);
        assert_eq!(c.resolve(&key(1)), None, "the oldest went");
        assert_eq!(c.resolve(&key(2)), None);
        assert_eq!(c.resolve(&key(5)), Some(RecordId(5)));
    }

    #[test]
    fn a_reused_name_belongs_to_whoever_claimed_it_first() {
        // A source reusing a span id is broken or trying something. Either way
        // the edge should point at the event that arrived first.
        let mut c = Correlation::new(4);
        c.remember(key(1), RecordId(10));
        c.remember(key(1), RecordId(20));
        assert_eq!(c.resolve(&key(1)), Some(RecordId(10)));
        assert_eq!(c.len(), 1, "and it does not take a second slot");
    }

    #[test]
    fn a_capacity_of_zero_still_holds_one() {
        // A window that holds nothing would silently drop every edge, which is
        // worse than a small window and impossible to notice.
        let mut c = Correlation::new(0);
        assert_eq!(c.capacity(), 1);
        c.remember(key(1), RecordId(1));
        assert_eq!(c.resolve(&key(1)), Some(RecordId(1)));
    }
}
