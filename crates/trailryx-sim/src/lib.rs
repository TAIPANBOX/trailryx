//! Deterministic simulation substrate for Trailryx.
//!
//! Everything the core is not allowed to reach for on its own lives here:
//! time, randomness, storage and message passing. Each is a trait with a real
//! implementation and a simulated one, so a seed reproduces a run exactly.
//!
//! This crate knows nothing about records, journals or proofs. It is the seam,
//! and the seam has to exist before the first line of the journal is written:
//! injectable interfaces cannot be retrofitted into a finished core.

pub mod bus;
pub mod clock;
pub mod io;
pub mod rng;
pub mod trace;

pub use bus::{Bus, BusFaults, BusStats, ShardId, SimBus};
pub use clock::{Clock, SimClock, SystemClock};
pub use io::{FileId, Io, IoError, IoFaults, IoResult, IoStats, SimIo, StdIo};
pub use rng::{Rng, RngExt, SimRng};
pub use trace::Trace;

/// An invariant that stays on in release builds.
///
/// Debug assertions are not enough here: a violated integrity invariant means
/// the store is about to record something untrue, and failing loudly is better
/// than persisting a lie. Use [`debug_invariant!`] for expensive checks.
#[macro_export]
macro_rules! invariant {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            panic!("INVARIANT VIOLATED at {}:{}: {}", file!(), line!(), format_args!($($arg)*));
        }
    };
    ($cond:expr) => {
        $crate::invariant!($cond, "{}", stringify!($cond))
    };
}

/// An invariant too expensive to keep in release builds.
#[macro_export]
macro_rules! debug_invariant {
    ($($t:tt)*) => {
        #[cfg(debug_assertions)]
        { $crate::invariant!($($t)*); }
    };
}

/// The capabilities a core operation is allowed to use, passed explicitly.
///
/// Separate fields rather than accessor methods so several can be borrowed at
/// once, and so a reader can see at the call site exactly what a function is
/// able to touch.
#[derive(Debug)]
pub struct Parts<'a, C: Clock, R: Rng, I: Io, B> {
    pub clock: &'a C,
    pub rng: &'a mut R,
    pub io: &'a mut I,
    pub bus: &'a mut B,
    pub trace: &'a mut Trace,
}

#[cfg(test)]
mod tests {
    #[test]
    fn invariant_holds_quietly() {
        crate::invariant!(1 + 1 == 2, "arithmetic still works");
    }

    #[test]
    #[should_panic(expected = "INVARIANT VIOLATED")]
    fn invariant_panics_loudly() {
        crate::invariant!(false, "deliberate");
    }
}
