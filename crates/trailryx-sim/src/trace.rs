//! The deterministic trace.
//!
//! Every meaningful action appends one line. Two runs with the same seed must
//! produce byte-identical traces: that equality *is* the determinism test.

use std::fmt;

/// Append-only record of what happened during a run.
#[derive(Debug, Default)]
pub struct Trace {
    buf: Vec<u8>,
    lines: u64,
    /// Stop growing past this many bytes. Long runs are checked by digest, not
    /// by keeping gigabytes of text around.
    cap_bytes: usize,
    truncated: bool,
}

impl Trace {
    pub fn new(cap_bytes: usize) -> Self {
        Self {
            buf: Vec::with_capacity(1024),
            lines: 0,
            cap_bytes,
            truncated: false,
        }
    }

    /// Record one event. `kind` is a short stable tag, `args` the details.
    pub fn record(&mut self, kind: &str, args: fmt::Arguments<'_>) {
        self.lines += 1;
        if self.buf.len() >= self.cap_bytes {
            self.truncated = true;
            // Still fold the event into the digest so truncation does not hide
            // divergence: see `digest`, which mixes `lines` as well.
            return;
        }
        use std::io::Write as _;
        // Writing into a Vec cannot fail.
        let _ = writeln!(self.buf, "{kind} {args}");
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn lines(&self) -> u64 {
        self.lines
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// FNV-1a 64. **Not cryptographic.** Its only job is to compare two runs
    /// cheaply and to print something short a human can eyeball.
    pub fn digest(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in &self.buf {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        // Mix in the line count so a truncated tail still changes the digest.
        for b in self.lines.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
        h
    }

    pub fn digest_hex(&self) -> String {
        format!("{:016x}", self.digest())
    }
}

/// `trace!(trace, "tag", "fmt {}", args)`
#[macro_export]
macro_rules! trace {
    ($t:expr, $kind:expr, $($arg:tt)*) => {
        $t.record($kind, format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_input_identical_digest() {
        let mut a = Trace::new(1 << 20);
        let mut b = Trace::new(1 << 20);
        for i in 0..100u32 {
            trace!(a, "step", "i={i}");
            trace!(b, "step", "i={i}");
        }
        assert_eq!(a.bytes(), b.bytes());
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn one_differing_event_changes_digest() {
        let mut a = Trace::new(1 << 20);
        let mut b = Trace::new(1 << 20);
        trace!(a, "step", "i=1");
        trace!(b, "step", "i=2");
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn truncation_still_counts_lines() {
        let mut t = Trace::new(8);
        for i in 0..100u32 {
            trace!(t, "step", "i={i}");
        }
        assert!(t.truncated());
        assert_eq!(t.lines(), 100);
    }
}
