//! Four times, and the trust boundary between them.
//!
//! A record carries four timestamps because an audit needs to separate four
//! different questions, and collapsing them is how audit trails become
//! unusable:
//!
//! | Field | Question | Whose clock |
//! |---|---|---|
//! | `occurred_at` | when did it happen in the world | the emitter's, **untrusted** |
//! | `decided_at` | when was the decision taken | the emitter's, untrusted |
//! | `recorded_at` | when did we write it down | ours, trusted |
//! | `knowledge_as_of` | what state of knowledge was it decided against | ours |
//!
//! The trust boundary is in the type system: an untrusted timestamp is wrapped
//! and cannot be used where a trusted one is expected without saying so.

use std::fmt;

/// Nanoseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub const ZERO: Self = Self(0);

    pub fn as_nanos(self) -> u64 {
        self.0
    }

    /// Absolute distance between two instants, in nanoseconds.
    pub fn distance(self, other: Self) -> u64 {
        self.0.abs_diff(other.0)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ns", self.0)
    }
}

/// A value we were told rather than one we observed.
///
/// No `Deref`, no `From`, and the accessor is deliberately wordy. Reading an
/// untrusted value should be a visible act at the call site, because the whole
/// class of timestamp bugs comes from forgetting which clock a number came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Untrusted<T>(T);

impl<T> Untrusted<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn as_untrusted(&self) -> &T {
        &self.0
    }

    pub fn into_untrusted(self) -> T {
        self.0
    }
}

impl<T: fmt::Display> fmt::Display for Untrusted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}~", self.0)
    }
}

/// How far an emitter's clock may drift from ours before we treat the gap as
/// an event in its own right rather than silently correcting it.
///
/// Silent correction is the tempting option and the wrong one: it destroys the
/// evidence that the clocks disagreed, which is sometimes the finding.
pub const CLOCK_SKEW_THRESHOLD_NANOS: u64 = 5_000_000_000; // 5 s

/// What we concluded about an emitter's clock for one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkewVerdict {
    /// Within threshold.
    Acceptable { skew_nanos: u64 },
    /// Beyond threshold. The record is still stored; the disagreement is
    /// recorded alongside it.
    Excessive { skew_nanos: u64 },
}

impl SkewVerdict {
    pub fn is_excessive(self) -> bool {
        matches!(self, Self::Excessive { .. })
    }

    pub fn skew_nanos(self) -> u64 {
        match self {
            Self::Acceptable { skew_nanos } | Self::Excessive { skew_nanos } => skew_nanos,
        }
    }
}

/// Compare what we were told against what we saw.
pub fn assess_skew(occurred_at: Untrusted<Timestamp>, recorded_at: Timestamp) -> SkewVerdict {
    let skew_nanos = occurred_at.as_untrusted().distance(recorded_at);
    if skew_nanos > CLOCK_SKEW_THRESHOLD_NANOS {
        SkewVerdict::Excessive { skew_nanos }
    } else {
        SkewVerdict::Acceptable { skew_nanos }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_clocks_are_acceptable() {
        let v = assess_skew(
            Untrusted::new(Timestamp(1_000_000_000)),
            Timestamp(1_500_000_000),
        );
        assert!(!v.is_excessive());
        assert_eq!(v.skew_nanos(), 500_000_000);
    }

    #[test]
    fn a_clock_far_ahead_is_excessive() {
        let v = assess_skew(
            Untrusted::new(Timestamp(60_000_000_000)),
            Timestamp(1_000_000_000),
        );
        assert!(v.is_excessive());
    }

    #[test]
    fn a_clock_far_behind_is_equally_excessive() {
        // Direction does not matter: disagreement does.
        let v = assess_skew(
            Untrusted::new(Timestamp(1_000_000_000)),
            Timestamp(60_000_000_000),
        );
        assert!(v.is_excessive());
    }

    #[test]
    fn untrusted_does_not_silently_become_trusted() {
        // Compile-time property, asserted here as documentation: the only way
        // out of the wrapper is a method whose name says what you are doing.
        let u = Untrusted::new(Timestamp(7));
        assert_eq!(u.as_untrusted().as_nanos(), 7);
        assert_eq!(u.into_untrusted(), Timestamp(7));
    }
}
