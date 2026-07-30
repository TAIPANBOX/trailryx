//! Just enough big-integer arithmetic to verify an RSA signature.
//!
//! # Why this exists at all
//!
//! Public timestamping authorities sign with RSA. DigiCert, Sectigo, FreeTSA and
//! Apple all do; ECDSA timestamping services are rare enough that supporting
//! only ECDSA would mean supporting no authority anybody actually uses. So the
//! choice was between depending on a crypto library, which this workspace does
//! not do, and writing modular exponentiation. This is the second one.
//!
//! # Why it is safe to be this small
//!
//! **Only public operations happen here.** Verifying a signature uses the
//! public modulus and the public exponent on a public signature, so there is no
//! secret to leak through timing, no blinding to get wrong and no key material
//! to zero. That is a much weaker requirement than a signing implementation
//! faces, and it is the reason a verify-only bignum is a reasonable thing to
//! hand-write while a signing one would not be.
//!
//! Nothing here is constant time and nothing here needs to be. It says so
//! rather than leaving somebody to assume otherwise: this module must never be
//! used for a private-key operation.
//!
//! # Why Montgomery rather than long division
//!
//! Modular reduction by division needs Knuth's Algorithm D, whose quotient-digit
//! estimation and correction step is the classic place a hand-written bignum is
//! subtly wrong for one input in a million. Montgomery multiplication needs only
//! multiply, add and a conditional subtract, so there is no estimate to get
//! wrong. The one precomputation it needs, `R^2 mod n`, is produced by repeated
//! doubling, which is obviously correct at the cost of being slow once.
//!
//! An RSA modulus is odd by construction, which is Montgomery's only
//! precondition, and [`Modulus::new`] refuses an even one rather than producing
//! nonsense.

use core::cmp::Ordering;

/// Limbs, least significant first.
type Limbs = Vec<u64>;

/// A modulus prepared for Montgomery arithmetic.
#[derive(Debug, Clone)]
pub struct Modulus {
    n: Limbs,
    /// `-n[0]^-1 mod 2^64`, the CIOS reduction factor.
    n0inv: u64,
    /// `R^2 mod n`, where `R = 2^(64 * limbs)`.
    r2: Limbs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BigError {
    /// A modulus of zero, or one that is even. Montgomery needs an odd modulus
    /// and every RSA modulus is odd, so an even one is a malformed key rather
    /// than an unsupported case.
    NotOddModulus,
    /// A modulus below three. Nothing meaningful reduces modulo one or two, and
    /// an RSA modulus that small is not a key.
    ModulusTooSmall,
    /// The value is at least as large as the modulus. For RSA verification this
    /// means a signature that is not a valid element, which is a rejection
    /// rather than something to reduce and continue with.
    NotReduced,
    /// Wider than this implementation will accept. The bound exists because the
    /// input is a public key from a party being audited, and an unbounded one is
    /// an unbounded amount of work.
    TooWide,
}

impl std::fmt::Display for BigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotOddModulus => f.write_str("the modulus is even, so it is not an RSA modulus"),
            Self::ModulusTooSmall => f.write_str("the modulus is too small to be a key"),
            Self::NotReduced => f.write_str("the value is not less than the modulus"),
            Self::TooWide => f.write_str("the value is wider than this implementation accepts"),
        }
    }
}

impl std::error::Error for BigError {}

/// 16384 bits. Larger than any RSA key in use and small enough that the work is
/// bounded when the input is chosen by somebody else.
pub const MAX_LIMBS: usize = 256;

impl Modulus {
    /// `bytes` is the modulus, big-endian, as it appears in a DER INTEGER with
    /// its sign byte already stripped.
    pub fn new(bytes: &[u8]) -> Result<Self, BigError> {
        let n = from_be_bytes(bytes)?;
        if n.is_empty() {
            return Err(BigError::ModulusTooSmall);
        }
        if n[0] & 1 == 0 {
            return Err(BigError::NotOddModulus);
        }
        if n.len() == 1 && n[0] < 3 {
            return Err(BigError::ModulusTooSmall);
        }
        let n0inv = inv_2_64(n[0]).wrapping_neg();
        let r2 = compute_r2(&n);
        Ok(Self { n, n0inv, r2 })
    }

    pub fn limbs(&self) -> usize {
        self.n.len()
    }

    /// The modulus in bytes, which is the length an RSA signature must have.
    pub fn byte_len(&self) -> usize {
        let top = self.n[self.n.len() - 1];
        (self.n.len() - 1) * 8 + (8 - (top.leading_zeros() as usize / 8))
    }

    /// `base^exponent mod n`, with `base` big-endian and `exponent` a small
    /// public value.
    ///
    /// Returns the result big-endian, left-padded to [`Self::byte_len`], which
    /// is the form PKCS#1 expects.
    pub fn pow(&self, base: &[u8], exponent: u64) -> Result<Vec<u8>, BigError> {
        let mut b = from_be_bytes(base)?;
        b.resize(self.n.len(), 0);
        if cmp(&b, &self.n) != Ordering::Less {
            return Err(BigError::NotReduced);
        }
        if exponent == 0 {
            let mut out = vec![0u8; self.byte_len()];
            let last = out.len() - 1;
            out[last] = 1;
            return Ok(out);
        }

        // Into Montgomery form once, out once. Everything between is
        // mont_mul, which is where the correctness argument lives.
        let base_mont = self.mont_mul(&b, &self.r2);
        let mut acc = base_mont.clone();
        // Square and multiply, most significant bit first, skipping the leading
        // one that `acc` already accounts for.
        let bits = 64 - exponent.leading_zeros();
        for i in (0..bits - 1).rev() {
            acc = self.mont_mul(&acc, &acc);
            if exponent >> i & 1 == 1 {
                acc = self.mont_mul(&acc, &base_mont);
            }
        }
        let mut one = vec![0u64; self.n.len()];
        one[0] = 1;
        let result = self.mont_mul(&acc, &one);
        Ok(to_be_bytes(&result, self.byte_len()))
    }

    /// CIOS Montgomery multiplication: `a * b * R^-1 mod n`.
    ///
    /// Both inputs are `n.len()` limbs and strictly below `n`; so is the result.
    fn mont_mul(&self, a: &[u64], b: &[u64]) -> Limbs {
        let k = self.n.len();
        debug_assert_eq!(a.len(), k);
        debug_assert_eq!(b.len(), k);
        // One extra limb for the carry the loop can produce, which is why the
        // final conditional subtract needs to look at it as well as at the
        // comparison against n.
        let mut t = vec![0u64; k + 1];
        let mut overflow = 0u64;

        for &b_i in b.iter().take(k) {
            // t += a * b[i]
            let mut carry = 0u128;
            for j in 0..k {
                let sum = u128::from(t[j]) + u128::from(a[j]) * u128::from(b_i) + carry;
                t[j] = sum as u64;
                carry = sum >> 64;
            }
            let sum = u128::from(t[k]) + carry;
            t[k] = sum as u64;
            overflow = overflow.wrapping_add((sum >> 64) as u64);

            // t += m * n, chosen so the low limb becomes zero, then shift right
            // one limb.
            let m = t[0].wrapping_mul(self.n0inv);
            let low = u128::from(t[0]) + u128::from(m) * u128::from(self.n[0]);
            debug_assert_eq!(low as u64, 0, "the reduction factor did not clear a limb");
            let mut carry = low >> 64;
            for j in 1..k {
                let sum = u128::from(t[j]) + u128::from(m) * u128::from(self.n[j]) + carry;
                t[j - 1] = sum as u64;
                carry = sum >> 64;
            }
            let sum = u128::from(t[k]) + carry;
            t[k - 1] = sum as u64;
            t[k] = overflow.wrapping_add((sum >> 64) as u64);
            overflow = 0;
        }

        // The result is below 2n, so at most one subtraction is needed. The
        // carry limb is part of the comparison: a value of exactly 2^(64k) is
        // greater than n while its low limbs alone may not be.
        let mut result = t[..k].to_vec();
        if t[k] != 0 || cmp(&result, &self.n) != Ordering::Less {
            sub_in_place(&mut result, &self.n);
        }
        result
    }
}

/// `R^2 mod n` by doubling, `2 * 64 * k` times.
///
/// Deliberately the slow, obvious method: each step is a shift and a
/// conditional subtract, so there is no estimate and nothing to get subtly
/// wrong. It runs once per key.
fn compute_r2(n: &[u64]) -> Limbs {
    let k = n.len();
    let mut acc = vec![0u64; k];
    acc[0] = 1;
    for _ in 0..(2 * 64 * k) {
        // acc = 2 * acc mod n
        let mut carry = 0u64;
        for limb in acc.iter_mut() {
            let doubled = (*limb << 1) | carry;
            carry = *limb >> 63;
            *limb = doubled;
        }
        if carry != 0 || cmp(&acc, n) != Ordering::Less {
            sub_in_place(&mut acc, n);
        }
    }
    acc
}

/// `x^-1 mod 2^64` by Newton iteration, for odd `x`.
///
/// Each step doubles the number of correct bits, so five steps from a
/// three-bit-correct start covers 64.
fn inv_2_64(x: u64) -> u64 {
    debug_assert_eq!(
        x & 1,
        1,
        "only an odd value is invertible mod a power of two"
    );
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(inv)));
    }
    debug_assert_eq!(x.wrapping_mul(inv), 1);
    inv
}

fn cmp(a: &[u64], b: &[u64]) -> Ordering {
    debug_assert_eq!(a.len(), b.len());
    for i in (0..a.len()).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

fn sub_in_place(a: &mut [u64], b: &[u64]) {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        a[i] = d;
        borrow = u64::from(b1) | u64::from(b2);
    }
}

/// Big-endian bytes to limbs, with leading zero bytes dropped.
fn from_be_bytes(bytes: &[u8]) -> Result<Limbs, BigError> {
    let trimmed = bytes
        .iter()
        .position(|b| *b != 0)
        .map_or(&[][..], |i| &bytes[i..]);
    if trimmed.len() > MAX_LIMBS * 8 {
        return Err(BigError::TooWide);
    }
    let mut limbs = Vec::with_capacity(trimmed.len() / 8 + 1);
    for chunk in trimmed.rchunks(8) {
        let mut value = 0u64;
        for byte in chunk {
            value = (value << 8) | u64::from(*byte);
        }
        limbs.push(value);
    }
    Ok(limbs)
}

fn to_be_bytes(limbs: &[u64], width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    // Little-endian limbs into a big-endian buffer, so position zero is the last
    // byte. Anything above `width` is a leading zero and is dropped: the caller
    // asked for the modulus's width and a value below it has no bytes up there.
    for (position, byte) in limbs
        .iter()
        .flat_map(|limb| limb.to_le_bytes())
        .enumerate()
        .take(width)
    {
        out[width - 1 - position] = byte;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Montgomery's one precondition. An even modulus has no inverse mod a power
    /// of two, so the reduction factor would be meaningless and every result
    /// would be wrong while looking like a number.
    #[test]
    fn an_even_modulus_is_refused_rather_than_producing_nonsense() {
        assert!(matches!(
            Modulus::new(&[0x10]).err(),
            Some(BigError::NotOddModulus)
        ));
        assert!(matches!(
            Modulus::new(&be("00")).err(),
            Some(BigError::ModulusTooSmall)
        ));
        assert!(matches!(
            Modulus::new(&[0x01]).err(),
            Some(BigError::ModulusTooSmall)
        ));
        assert!(matches!(
            Modulus::new(&vec![0xFFu8; MAX_LIMBS * 8 + 1]).err(),
            Some(BigError::TooWide)
        ));
    }

    #[test]
    fn small_powers_agree_with_arithmetic_done_by_hand() {
        let m = Modulus::new(&[0x0D]).expect("13 is an odd modulus");
        // 5^3 mod 13 = 125 mod 13 = 8
        assert_eq!(m.pow(&[5], 3).expect("in range"), vec![8]);
        // 7^0 mod 13 = 1
        assert_eq!(m.pow(&[7], 0).expect("in range"), vec![1]);
        // 1^65537 mod 13 = 1
        assert_eq!(m.pow(&[1], 65_537).expect("in range"), vec![1]);
        // 0^5 mod 13 = 0
        assert_eq!(m.pow(&[0], 5).expect("in range"), vec![0]);
    }

    #[test]
    fn a_value_at_or_above_the_modulus_is_refused() {
        let m = Modulus::new(&[0x0D]).expect("odd");
        assert_eq!(m.pow(&[13], 3), Err(BigError::NotReduced));
        assert_eq!(m.pow(&[14], 3), Err(BigError::NotReduced));
        assert!(m.pow(&[12], 3).is_ok());
    }

    #[test]
    fn the_byte_length_matches_the_modulus_and_not_its_limb_count() {
        assert_eq!(Modulus::new(&be("0d")).expect("odd").byte_len(), 1);
        assert_eq!(Modulus::new(&be("0101")).expect("odd").byte_len(), 2);
        assert_eq!(
            Modulus::new(&be("ffffffffffffffff"))
                .expect("odd")
                .byte_len(),
            8
        );
        // Nine bytes is two limbs, and the length must still be nine.
        assert_eq!(
            Modulus::new(&be("01ffffffffffffffff"))
                .expect("odd")
                .byte_len(),
            9
        );
    }

    #[test]
    fn the_inverse_mod_two_to_the_sixtyfour_is_an_inverse() {
        for x in [1u64, 3, 5, 0xFFFF_FFFF_FFFF_FFFF, 0x1234_5678_9ABC_DEF1] {
            assert_eq!(x.wrapping_mul(inv_2_64(x)), 1, "{x:#x}");
        }
    }

    #[test]
    fn leading_zero_bytes_do_not_change_a_value() {
        let m = Modulus::new(&be("0000000d")).expect("odd after trimming");
        assert_eq!(m.limbs(), 1);
        assert_eq!(m.pow(&be("00000005"), 3).expect("in range"), vec![8]);
    }
}
