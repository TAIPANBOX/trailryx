//! Randomness as a capability.
//!
//! The core never reaches for entropy on its own. Everything random arrives
//! through this trait, so a seed fully determines a run.

/// A source of pseudo-random numbers.
pub trait Rng {
    fn next_u64(&mut self) -> u64;
}

/// Conveniences on top of [`Rng`], blanket-implemented.
pub trait RngExt: Rng {
    /// Uniform-ish value in `0..n`. Uses modulo, so it carries a tiny bias for
    /// `n` near `u64::MAX`. Fine for fault selection, never use for keys.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }

    /// True with probability `ppm / 1_000_000`.
    fn chance_ppm(&mut self, ppm: u32) -> bool {
        if ppm == 0 {
            return false;
        }
        self.below(1_000_000) < u64::from(ppm)
    }

    /// Deterministically derive an independent stream from this one.
    fn fork(&mut self) -> SimRng {
        SimRng::new(self.next_u64())
    }
}

impl<T: Rng + ?Sized> RngExt for T {}

/// splitmix64. Small, fast, and reproducible across platforms and versions,
/// which is the only property that matters here.
#[derive(Debug, Clone)]
pub struct SimRng {
    state: u64,
}

impl SimRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn seed(&self) -> u64 {
        self.state
    }
}

impl Rng for SimRng {
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = SimRng::new(42);
        let mut b = SimRng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = SimRng::new(1);
        let mut b = SimRng::new(2);
        let differs = (0..100).any(|_| a.next_u64() != b.next_u64());
        assert!(differs);
    }

    #[test]
    fn forked_streams_are_independent_but_reproducible() {
        let mut a = SimRng::new(7);
        let mut b = SimRng::new(7);
        let mut fa = a.fork();
        let mut fb = b.fork();
        assert_eq!(fa.next_u64(), fb.next_u64());
    }
}
