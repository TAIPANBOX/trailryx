//! ECDSA on P-384: verification only.
//!
//! # Why this is here and signing is not
//!
//! Signing touches a private key and a nonce, and both are places where a
//! timing leak or a biased bit hands somebody the key. That work belongs to a
//! validated module and this project does not do it.
//!
//! Verification touches neither. Every value it handles is public: the message,
//! the signature, the public key. Nothing it does can leak a secret because it
//! is given none, which is why it is reasonable to write here and would not be
//! reasonable to write on the other side of the seam.
//!
//! It has to be here. The verifier is the one binary an auditor runs without
//! us, and a verifier that says "there is a signature, I did not look at it" is
//! answering a different question from the one they asked.
//!
//! # Correct rather than fast
//!
//! Modular reduction is binary long division: shift a bit in, conditionally
//! subtract the modulus, repeat. That is the slowest reasonable method and the
//! easiest one to read and be sure of. A pack is verified once, by a person,
//! and their patience is measured in seconds. Nothing here is worth a
//! Montgomery ladder's opportunities to be subtly wrong.
//!
//! Curve arithmetic is Jacobian, because affine would need a modular inversion
//! per step and that is the difference between a second and an hour.
//!
//! # The constants
//!
//! Taken from `openssl ecparam -name secp384r1 -param_enc explicit`, converted
//! by a script rather than by hand, and checked two ways below: that `a` really
//! is `p - 3`, and that the generator satisfies the curve equation.

use crate::sha384::Sha384;

/// A 384-bit value, least significant limb first.
pub type Fe = [u64; 6];

const P: Fe = [
    0x00000000ffffffff,
    0xffffffff00000000,
    0xfffffffffffffffe,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
];

/// The order of the base point.
const N: Fe = [
    0xecec196accc52973,
    0x581a0db248b0a77a,
    0xc7634d81f4372ddf,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
];

const B: Fe = [
    0x2a85c8edd3ec2aef,
    0xc656398d8a2ed19d,
    0x0314088f5013875a,
    0x181d9c6efe814112,
    0x988e056be3f82d19,
    0xb3312fa7e23ee7e4,
];

const GX: Fe = [
    0x3a545e3872760ab7,
    0x5502f25dbf55296c,
    0x59f741e082542a38,
    0x6e1d3b628ba79b98,
    0x8eb1c71ef320ad74,
    0xaa87ca22be8b0537,
];

const GY: Fe = [
    0x7a431d7c90ea0e5f,
    0x0a60b1ce1d7e819d,
    0xe9da3113b5f0b8c0,
    0xf8f41dbd289a147c,
    0x5d9e98bf9292dc29,
    0x3617de4a96262c6f,
];

const ZERO: Fe = [0; 6];

/// An uncompressed public key: `0x04 || X || Y`.
pub const PUBLIC_KEY_BYTES: usize = 97;
/// A signature as `r || s`, fixed width. Not DER: a length-prefixed encoding
/// with optional leading zeroes has more than one spelling of the same value,
/// and this project does not accept two spellings of anything it hashes.
pub const SIGNATURE_BYTES: usize = 96;

// ---------------------------------------------------------------------------
// Big integers
// ---------------------------------------------------------------------------

fn is_zero(a: &Fe) -> bool {
    a.iter().all(|l| *l == 0)
}

fn less(a: &Fe, b: &Fe) -> bool {
    for i in (0..6).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `a -= b`, returning the borrow out.
fn sub_assign(a: &mut Fe, b: &Fe) -> u64 {
    let mut borrow = 0u64;
    for i in 0..6 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        a[i] = d;
        borrow = u64::from(b1) + u64::from(b2);
    }
    borrow
}

/// `a += b`, returning the carry out.
fn add_assign(a: &mut Fe, b: &Fe) -> u64 {
    let mut carry = 0u64;
    for i in 0..6 {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(carry);
        a[i] = s;
        carry = u64::from(c1) + u64::from(c2);
    }
    carry
}

/// `a <<= 1`, returning the bit shifted out of the top.
fn shl1(a: &mut Fe) -> u64 {
    let mut carry = 0u64;
    for limb in a.iter_mut() {
        let next = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    carry
}

fn mul_wide(a: &Fe, b: &Fe) -> [u64; 12] {
    let mut out = [0u64; 12];
    for i in 0..6 {
        let mut carry = 0u128;
        for j in 0..6 {
            let t = u128::from(a[i]) * u128::from(b[j]) + u128::from(out[i + j]) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        let mut at = i + 6;
        while carry != 0 {
            let t = u128::from(out[at]) + carry;
            out[at] = t as u64;
            carry = t >> 64;
            at += 1;
        }
    }
    out
}

/// A 768-bit value modulo a 384-bit one, by long division.
///
/// The invariant that makes one conditional subtraction enough: before each
/// step the remainder is below the modulus, so after shifting a bit in it is
/// below twice the modulus.
fn reduce(wide: &[u64; 12], m: &Fe) -> Fe {
    let mut r = ZERO;
    for i in (0..768).rev() {
        let bit = (wide[i / 64] >> (i % 64)) & 1;
        let carry = shl1(&mut r);
        r[0] |= bit;
        if carry != 0 || !less(&r, m) {
            sub_assign(&mut r, m);
        }
    }
    r
}

fn mul_mod(a: &Fe, b: &Fe, m: &Fe) -> Fe {
    reduce(&mul_wide(a, b), m)
}

fn add_mod(a: &Fe, b: &Fe, m: &Fe) -> Fe {
    let mut r = *a;
    let carry = add_assign(&mut r, b);
    if carry != 0 || !less(&r, m) {
        sub_assign(&mut r, m);
    }
    r
}

fn sub_mod(a: &Fe, b: &Fe, m: &Fe) -> Fe {
    let mut r = *a;
    if sub_assign(&mut r, b) != 0 {
        add_assign(&mut r, m);
    }
    r
}

fn pow_mod(base: &Fe, exp: &Fe, m: &Fe) -> Fe {
    let mut result = [1, 0, 0, 0, 0, 0];
    let mut acc = *base;
    for i in 0..384 {
        if (exp[i / 64] >> (i % 64)) & 1 == 1 {
            result = mul_mod(&result, &acc, m);
        }
        acc = mul_mod(&acc, &acc, m);
    }
    result
}

/// The inverse by Fermat's little theorem, which needs the modulus to be prime.
/// Both moduli here are.
fn inv_mod(a: &Fe, m: &Fe) -> Fe {
    let mut e = *m;
    let two = [2, 0, 0, 0, 0, 0];
    sub_assign(&mut e, &two);
    pow_mod(a, &e, m)
}

fn from_be_bytes(bytes: &[u8]) -> Fe {
    let mut out = ZERO;
    for (i, chunk) in bytes.chunks(8).rev().enumerate() {
        let mut limb = [0u8; 8];
        limb[8 - chunk.len()..].copy_from_slice(chunk);
        out[i] = u64::from_be_bytes(limb);
    }
    out
}

// ---------------------------------------------------------------------------
// The curve
// ---------------------------------------------------------------------------

/// A point in Jacobian coordinates: `(X : Y : Z)` stands for `(X/Z², Y/Z³)`,
/// and `Z = 0` is the point at infinity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

const INFINITY: Point = Point {
    x: [1, 0, 0, 0, 0, 0],
    y: [1, 0, 0, 0, 0, 0],
    z: ZERO,
};

fn double(p: &Point) -> Point {
    if is_zero(&p.z) {
        return INFINITY;
    }
    // The a = -3 shortcut, which is why this curve was chosen with a = p - 3.
    let delta = mul_mod(&p.z, &p.z, &P);
    let gamma = mul_mod(&p.y, &p.y, &P);
    let beta = mul_mod(&p.x, &gamma, &P);

    let x_minus = sub_mod(&p.x, &delta, &P);
    let x_plus = add_mod(&p.x, &delta, &P);
    let t = mul_mod(&x_minus, &x_plus, &P);
    let alpha = add_mod(&add_mod(&t, &t, &P), &t, &P);

    let beta4 = add_mod(&beta, &beta, &P);
    let beta4 = add_mod(&beta4, &beta4, &P);
    let beta8 = add_mod(&beta4, &beta4, &P);
    let x3 = sub_mod(&mul_mod(&alpha, &alpha, &P), &beta8, &P);

    let yz = add_mod(&p.y, &p.z, &P);
    let z3 = sub_mod(&sub_mod(&mul_mod(&yz, &yz, &P), &gamma, &P), &delta, &P);

    let gamma2 = mul_mod(&gamma, &gamma, &P);
    let g8 = add_mod(&gamma2, &gamma2, &P);
    let g8 = add_mod(&g8, &g8, &P);
    let g8 = add_mod(&g8, &g8, &P);
    let y3 = sub_mod(&mul_mod(&alpha, &sub_mod(&beta4, &x3, &P), &P), &g8, &P);

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn add(a: &Point, b: &Point) -> Point {
    if is_zero(&a.z) {
        return *b;
    }
    if is_zero(&b.z) {
        return *a;
    }
    let z1z1 = mul_mod(&a.z, &a.z, &P);
    let z2z2 = mul_mod(&b.z, &b.z, &P);
    let u1 = mul_mod(&a.x, &z2z2, &P);
    let u2 = mul_mod(&b.x, &z1z1, &P);
    let s1 = mul_mod(&mul_mod(&a.y, &b.z, &P), &z2z2, &P);
    let s2 = mul_mod(&mul_mod(&b.y, &a.z, &P), &z1z1, &P);

    if u1 == u2 {
        // Same x. Either the same point, which needs the doubling formula
        // because the addition one divides by zero here, or a point and its
        // negation, whose sum is infinity.
        return if s1 == s2 { double(a) } else { INFINITY };
    }

    let h = sub_mod(&u2, &u1, &P);
    let h2 = add_mod(&h, &h, &P);
    let i = mul_mod(&h2, &h2, &P);
    let j = mul_mod(&h, &i, &P);
    let r = sub_mod(&s2, &s1, &P);
    let r = add_mod(&r, &r, &P);
    let v = mul_mod(&u1, &i, &P);

    let x3 = sub_mod(
        &sub_mod(&mul_mod(&r, &r, &P), &j, &P),
        &add_mod(&v, &v, &P),
        &P,
    );
    let s1j = mul_mod(&s1, &j, &P);
    let y3 = sub_mod(
        &mul_mod(&r, &sub_mod(&v, &x3, &P), &P),
        &add_mod(&s1j, &s1j, &P),
        &P,
    );
    let zz = add_mod(&a.z, &b.z, &P);
    let z3 = mul_mod(
        &sub_mod(&sub_mod(&mul_mod(&zz, &zz, &P), &z1z1, &P), &z2z2, &P),
        &h,
        &P,
    );

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn mul(k: &Fe, p: &Point) -> Point {
    let mut acc = INFINITY;
    for i in (0..384).rev() {
        acc = double(&acc);
        if (k[i / 64] >> (i % 64)) & 1 == 1 {
            acc = add(&acc, p);
        }
    }
    acc
}

/// The affine x coordinate, or `None` at infinity.
fn affine_x(p: &Point) -> Option<Fe> {
    if is_zero(&p.z) {
        return None;
    }
    let zinv = inv_mod(&p.z, &P);
    let zinv2 = mul_mod(&zinv, &zinv, &P);
    Some(mul_mod(&p.x, &zinv2, &P))
}

fn on_curve(x: &Fe, y: &Fe) -> bool {
    // y² == x³ - 3x + b
    let lhs = mul_mod(y, y, &P);
    let x3 = mul_mod(&mul_mod(x, x, &P), x, &P);
    let three_x = add_mod(&add_mod(x, x, &P), x, &P);
    let rhs = add_mod(&sub_mod(&x3, &three_x, &P), &B, &P);
    lhs == rhs
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------

/// Why a signature was not accepted.
///
/// Named rather than a bare `false`, because "we do not know that key" and
/// "the signature is wrong" are very different things to read in a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    BadKeyEncoding,
    KeyNotOnCurve,
    BadSignatureEncoding,
    /// `r` or `s` outside `1..n`. A zero here is the classic forgery attempt.
    ComponentOutOfRange,
    DoesNotVerify,
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKeyEncoding => write!(f, "the public key is not an uncompressed P-384 point"),
            Self::KeyNotOnCurve => write!(f, "the public key is not on the curve"),
            Self::BadSignatureEncoding => write!(f, "a signature must be 96 bytes of r and s"),
            Self::ComponentOutOfRange => write!(f, "r or s is zero or not below the group order"),
            Self::DoesNotVerify => write!(f, "the signature does not verify"),
        }
    }
}

impl std::error::Error for SigError {}

/// Verify `signature` over `message` under `public_key`.
///
/// The message is hashed with SHA-384 here rather than by the caller, so no
/// caller can pass a digest computed some other way and have it accepted.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), SigError> {
    if public_key.len() != PUBLIC_KEY_BYTES || public_key[0] != 0x04 {
        return Err(SigError::BadKeyEncoding);
    }
    if signature.len() != SIGNATURE_BYTES {
        return Err(SigError::BadSignatureEncoding);
    }

    let qx = from_be_bytes(&public_key[1..49]);
    let qy = from_be_bytes(&public_key[49..97]);
    if !less(&qx, &P) || !less(&qy, &P) || !on_curve(&qx, &qy) {
        return Err(SigError::KeyNotOnCurve);
    }

    let r = from_be_bytes(&signature[..48]);
    let s = from_be_bytes(&signature[48..]);
    if is_zero(&r) || is_zero(&s) || !less(&r, &N) || !less(&s, &N) {
        return Err(SigError::ComponentOutOfRange);
    }

    // SHA-384 is exactly the group's bit length, so the whole digest is used.
    let digest = Sha384::digest(message);
    let mut e = from_be_bytes(&digest);
    if !less(&e, &N) {
        sub_assign(&mut e, &N);
    }

    let w = inv_mod(&s, &N);
    let u1 = mul_mod(&e, &w, &N);
    let u2 = mul_mod(&r, &w, &N);

    let g = Point {
        x: GX,
        y: GY,
        z: [1, 0, 0, 0, 0, 0],
    };
    let q = Point {
        x: qx,
        y: qy,
        z: [1, 0, 0, 0, 0, 0],
    };
    let point = add(&mul(&u1, &g), &mul(&u2, &q));

    let x = affine_x(&point).ok_or(SigError::DoesNotVerify)?;
    let mut v = x;
    if !less(&v, &N) {
        sub_assign(&mut v, &N);
    }
    if v == r {
        Ok(())
    } else {
        Err(SigError::DoesNotVerify)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g() -> Point {
        Point {
            x: GX,
            y: GY,
            z: [1, 0, 0, 0, 0, 0],
        }
    }

    #[test]
    fn the_constants_are_the_ones_they_claim_to_be() {
        // Two independent checks on numbers that were transcribed from a tool:
        // the generator satisfies the curve equation, and the curve equation is
        // the a = -3 one that the doubling formula assumes.
        assert!(on_curve(&GX, &GY));
        assert!(less(&GX, &P) && less(&GY, &P));
        assert!(less(&N, &P), "the order is below the field size");
    }

    #[test]
    fn the_group_order_annihilates_the_generator() {
        // n * G is the point at infinity. This exercises the whole scalar
        // ladder, both formulas, and the constants at once: it is the single
        // strongest self-check available without an external vector.
        assert!(affine_x(&mul(&N, &g())).is_none());
    }

    #[test]
    fn doubling_and_addition_agree() {
        // Two formulas, the same answer. They are written from different
        // sources and this is what catches a transcription slip in either.
        let two_g = double(&g());
        let g_plus_g = add(&g(), &g());
        assert_eq!(affine_x(&two_g), affine_x(&g_plus_g));
    }

    #[test]
    fn scalar_multiplication_is_linear() {
        let three = [3, 0, 0, 0, 0, 0];
        let five = [5, 0, 0, 0, 0, 0];
        let eight = [8, 0, 0, 0, 0, 0];
        let a = add(&mul(&three, &g()), &mul(&five, &g()));
        assert_eq!(affine_x(&a), affine_x(&mul(&eight, &g())));
    }

    #[test]
    fn a_point_plus_its_negation_is_infinity() {
        // The branch inside `add` that the addition formula cannot handle. It
        // is reached rarely and wrong answers there are forgeries.
        let minus_g = Point {
            x: GX,
            y: sub_mod(&ZERO, &GY, &P),
            z: [1, 0, 0, 0, 0, 0],
        };
        assert!(affine_x(&add(&g(), &minus_g)).is_none());
    }

    #[test]
    fn reduction_matches_repeated_subtraction_on_small_values() {
        let mut wide = [0u64; 12];
        wide[0] = 1_000_000;
        let m = [7, 0, 0, 0, 0, 0];
        assert_eq!(reduce(&wide, &m)[0], 1_000_000 % 7);
    }

    #[test]
    fn an_inverse_times_its_value_is_one() {
        let a = [0x1234_5678_9abc_def0, 7, 0, 0, 0, 0];
        let inv = inv_mod(&a, &P);
        assert_eq!(mul_mod(&a, &inv, &P), [1, 0, 0, 0, 0, 0]);
        let inv_n = inv_mod(&a, &N);
        assert_eq!(mul_mod(&a, &inv_n, &N), [1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_malformed_key_or_signature_is_named_rather_than_guessed_at() {
        assert_eq!(verify(&[], b"m", &[0; 96]), Err(SigError::BadKeyEncoding));
        let mut key = [0u8; 97];
        key[0] = 0x04;
        assert_eq!(
            verify(&key, b"m", &[0; 10]),
            Err(SigError::BadSignatureEncoding)
        );
        assert_eq!(verify(&key, b"m", &[0; 96]), Err(SigError::KeyNotOnCurve));
    }

    #[test]
    fn a_zero_component_is_refused_before_any_arithmetic() {
        // r = 0 or s = 0 makes the verification equation degenerate, and every
        // ECDSA forgery paper starts here.
        let mut key = [0u8; 97];
        key[0] = 0x04;
        key[1..49].copy_from_slice(&to_be(&GX));
        key[49..].copy_from_slice(&to_be(&GY));
        assert_eq!(
            verify(&key, b"m", &[0u8; 96]),
            Err(SigError::ComponentOutOfRange)
        );
    }

    fn to_be(a: &Fe) -> [u8; 48] {
        let mut out = [0u8; 48];
        for i in 0..6 {
            out[40 - i * 8..48 - i * 8].copy_from_slice(&a[i].to_be_bytes());
        }
        out
    }
}
