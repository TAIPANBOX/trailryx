//! Time as a capability.
//!
//! Two clocks, deliberately separate, because the record model needs both and
//! they are not equally trustworthy:
//!
//! - **monotonic** never goes backwards, used for durations and ordering;
//! - **wall** can jump (NTP correction, admin, virtualisation) and is the one
//!   that ends up in `recorded_at`.
//!
//! The simulator can move them independently, which is how clock-skew faults
//! get tested instead of assumed away.

pub trait Clock {
    /// Monotonic nanoseconds since an arbitrary origin. Never decreases.
    fn mono_nanos(&self) -> u64;

    /// Wall-clock nanoseconds since the Unix epoch. May jump in either direction.
    fn wall_nanos(&self) -> u64;
}

/// Fully controlled clock. Time only moves when the simulator says so.
#[derive(Debug, Clone)]
pub struct SimClock {
    mono: u64,
    wall: u64,
}

impl SimClock {
    /// `start_wall` is nanoseconds since the Unix epoch.
    pub fn new(start_wall: u64) -> Self {
        Self {
            mono: 0,
            wall: start_wall,
        }
    }

    /// Advance both clocks by `nanos`.
    pub fn advance(&mut self, nanos: u64) {
        self.mono = self.mono.saturating_add(nanos);
        self.wall = self.wall.saturating_add(nanos);
    }

    /// Jump the wall clock without touching the monotonic one. This is what an
    /// NTP correction looks like from inside the process, and it is the fault
    /// that silently corrupts naive timestamping.
    pub fn jump_wall(&mut self, delta_nanos: i64) {
        self.wall = if delta_nanos >= 0 {
            self.wall.saturating_add(delta_nanos.unsigned_abs())
        } else {
            self.wall.saturating_sub(delta_nanos.unsigned_abs())
        };
    }
}

impl Clock for SimClock {
    fn mono_nanos(&self) -> u64 {
        self.mono
    }

    fn wall_nanos(&self) -> u64 {
        self.wall
    }
}

/// Real clock. Only used outside the simulator.
#[derive(Debug)]
pub struct SystemClock {
    base: std::time::Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            base: std::time::Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn mono_nanos(&self) -> u64 {
        u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn wall_nanos(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_moves_both() {
        let mut c = SimClock::new(1_000);
        c.advance(500);
        assert_eq!(c.mono_nanos(), 500);
        assert_eq!(c.wall_nanos(), 1_500);
    }

    #[test]
    fn wall_can_jump_backwards_monotonic_cannot() {
        let mut c = SimClock::new(10_000);
        c.advance(1_000);
        let mono_before = c.mono_nanos();
        c.jump_wall(-5_000);
        assert_eq!(c.wall_nanos(), 6_000);
        assert_eq!(c.mono_nanos(), mono_before);
    }
}
