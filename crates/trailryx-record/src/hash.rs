//! A hash value, carried as bytes.
//!
//! The algorithm itself arrives in stage 3 with a validated implementation.
//! What matters now is the shape: 384 bits, because CNSA 2.0 wants SHA-384 or
//! better and a product that fails its own scanner is not sellable.

use std::fmt;

pub const HASH_BYTES: usize = 48; // 384 bits

/// A 384-bit digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; HASH_BYTES]);

impl Hash {
    pub const ZERO: Self = Self([0u8; HASH_BYTES]);

    pub fn as_bytes(&self) -> &[u8; HASH_BYTES] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(HASH_BYTES * 2);
        for b in self.0 {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
        }
        s
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != HASH_BYTES * 2 {
            return None;
        }
        let bytes = s.as_bytes();
        let mut out = [0u8; HASH_BYTES];
        for (i, out_b) in out.iter_mut().enumerate() {
            let hi = (bytes[i * 2] as char).to_digit(16)?;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
            *out_b = u8::try_from(hi * 16 + lo).ok()?;
        }
        Some(Self(out))
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Short form, so traces stay readable. Never use it to compare.
impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = self.to_hex();
        write!(f, "Hash({}…)", &h[..12])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let mut b = [0u8; HASH_BYTES];
        for (i, x) in b.iter_mut().enumerate() {
            *x = u8::try_from(i).unwrap_or(0);
        }
        let h = Hash(b);
        assert_eq!(Hash::from_hex(&h.to_hex()), Some(h));
    }

    #[test]
    fn bad_hex_is_refused_not_guessed() {
        assert_eq!(Hash::from_hex("short"), None);
        assert_eq!(Hash::from_hex(&"z".repeat(HASH_BYTES * 2)), None);
    }

    #[test]
    fn zero_is_recognisable() {
        assert!(Hash::ZERO.is_zero());
        assert_eq!(Hash::ZERO.to_hex().len(), HASH_BYTES * 2);
    }
}
