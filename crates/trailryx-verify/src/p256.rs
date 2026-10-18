//! ECDSA on P-256 with SHA-256: verification only.
//!
//! # Why it is here, when no evidence pack is signed with it
//!
//! Every signature this store makes is ES384 and [`crate::p384`] checks it.
//! P-256 arrives from outside: an agent's own access token is ES256, signed by
//! the estate's issuer, and the proof of possession presented with it is ES256,
//! signed by the agent. The ingest door has to check both before it believes a
//! word of either, and it may not take a cryptography crate to do it, for the
//! reason this crate depends on nothing: whoever has to trust the door is
//! asked to read the check rather than to trust its author.
//!
//! So it lives beside the P-384 verifier, written the same way and for the
//! same reason, and nothing in the pack verifier calls it.
//!
//! # Why verification is reasonable to write and signing is not
//!
//! The same argument as [`crate::p384`]: every value here is public, the
//! message, the signature and the key, so there is no secret for a timing
//! difference to leak. Signing touches a private key and a nonce and belongs to
//! a validated module.
//!
//! # Where this differs from the P-384 file, and why
//!
//! The P-384 verifier reduces by binary long division because a pack is
//! verified once, by a person, and their patience is measured in seconds. This
//! one runs at a network door, twice per request, before the caller has proved
//! anything at all: a slow refusal there is a cost a stranger chooses how often
//! to impose. So multiplication is Montgomery's (the CIOS form, one modulus at a
//! time), which turns a reduction of 512 shift-and-subtract steps into four
//! word multiplications.
//!
//! That is a place to be subtly wrong, and two things stand between it and a
//! wrong answer. The long division the P-384 file trusts is kept here, for the
//! tests only, and every Montgomery product is compared against it on values
//! chosen to hit the carries. And Project Wycheproof's P-256 cases, built
//! specifically to catch arithmetic that is right on random inputs and wrong
//! on edge ones, run in `tests/it/p256.rs` with every stated answer required.
//!
//! # The three checks a verifier is judged by
//!
//! - **`r` and `s` in `[1, n-1]`.** `r = s = 0` verified under every key for
//!   every message in a widely deployed verifier (CVE-2022-21449).
//! - **The key is a point on this curve.** Nothing in the addition formulas
//!   reads `b`, so a point from another curve would be computed with as though
//!   it belonged to this one, in a group its sender chose: the invalid-curve
//!   attack. A test below forges a signature that verifies under exactly such
//!   a key when this check is skipped.
//! - **The verification equation itself**, `x(u1 G + u2 Q) mod n == r`.
//!
//! The point at infinity cannot be expressed in the uncompressed encoding, and
//! the all-zero coordinate pair a missing key decodes to is not on the curve,
//! so both fall to the second check.

use crate::sha256;

/// A 256-bit value, least significant limb first.
pub type Fe = [u64; 4];

/// The field prime, 2^256 - 2^224 + 2^192 + 2^96 - 1.
const P: Fe = [
    0xffffffffffffffff,
    0x00000000ffffffff,
    0x0000000000000000,
    0xffffffff00000001,
];

/// The order of the base point.
const N: Fe = [
    0xf3b9cac2fc632551,
    0xbce6faada7179e84,
    0xffffffffffffffff,
    0xffffffff00000000,
];

const B: Fe = [
    0x3bce3c3e27d2604b,
    0x651d06b0cc53b0f6,
    0xb3ebbd55769886bc,
    0x5ac635d8aa3a93e7,
];

const GX: Fe = [
    0xf4a13945d898c296,
    0x77037d812deb33a0,
    0xf8bce6e563a440f2,
    0x6b17d1f2e12c4247,
];

const GY: Fe = [
    0xcbb6406837bf51f5,
    0x2bce33576b315ece,
    0x8ee7eb4a7c0f9e16,
    0x4fe342e2fe1a7f9b,
];

const ZERO: Fe = [0; 4];
const ONE: Fe = [1, 0, 0, 0];

/// A modulus and the two constants Montgomery multiplication needs for it.
///
/// Both were computed by a script, and neither is trusted on that basis: the
/// tests check `inv * m[0] == -1 (mod 2^64)` and that `r2` is `2^512 mod m` by
/// long division.
#[derive(Debug, Clone, Copy)]
struct Modulus {
    m: Fe,
    /// `-m^-1 mod 2^64`.
    inv: u64,
    /// `R^2 mod m`, with `R = 2^256`. Multiplying by it enters the domain.
    r2: Fe,
}

const FP: Modulus = Modulus {
    m: P,
    inv: 0x0000000000000001,
    r2: [
        0x0000000000000003,
        0xfffffffbffffffff,
        0xfffffffffffffffe,
        0x00000004fffffffd,
    ],
};

const FN: Modulus = Modulus {
    m: N,
    inv: 0xccd1c8aaee00bc4f,
    r2: [
        0x83244c95be79eea2,
        0x4699799c49bd6fa6,
        0x2845b2392b6bec59,
        0x66e12d94f3d95620,
    ],
};

/// An uncompressed public key: `0x04 || X || Y`.
pub const PUBLIC_KEY_BYTES: usize = 65;
/// A signature as `r || s`, fixed width: the JWS form (RFC 7518 section 3.4).
/// Not DER, for the reason [`crate::p384::SIGNATURE_BYTES`] gives.
pub const SIGNATURE_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// Big integers
// ---------------------------------------------------------------------------

fn is_zero(a: &Fe) -> bool {
    a.iter().all(|l| *l == 0)
}

fn less(a: &Fe, b: &Fe) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `a -= b`, returning the borrow out.
fn sub_assign(a: &mut Fe, b: &Fe) -> u64 {
    let mut borrow = 0u64;
    for i in 0..4 {
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
    for i in 0..4 {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(carry);
        a[i] = s;
        carry = u64::from(c1) + u64::from(c2);
    }
    carry
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

/// `a * b * R^-1 mod m`, for `a, b < m`.
///
/// Coarsely Integrated Operand Scanning: one row of the schoolbook product, then
/// one word of reduction, four times. After each round the low word is zero by
/// construction and is shifted away, so the running value never needs more than
/// six words. It stays below `2m`, which is why one conditional subtraction at
/// the end is enough, and that bound is the thing the tests below lean on.
fn mont_mul(a: &Fe, b: &Fe, md: &Modulus) -> Fe {
    let m = &md.m;
    let mut t = [0u64; 6];
    for &bi in b.iter() {
        // t += a * b[i]
        let mut carry = 0u128;
        for j in 0..4 {
            let v = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + carry;
            t[j] = v as u64;
            carry = v >> 64;
        }
        let v = u128::from(t[4]) + carry;
        t[4] = v as u64;
        t[5] = (v >> 64) as u64;

        // t += q * m, with q chosen so the low word becomes zero; then t >>= 64.
        let q = t[0].wrapping_mul(md.inv);
        let v = u128::from(t[0]) + u128::from(q) * u128::from(m[0]);
        let mut carry = v >> 64;
        for j in 1..4 {
            let v = u128::from(t[j]) + u128::from(q) * u128::from(m[j]) + carry;
            t[j - 1] = v as u64;
            carry = v >> 64;
        }
        let v = u128::from(t[4]) + carry;
        t[3] = v as u64;
        t[4] = t[5] + (v >> 64) as u64;
        t[5] = 0;
    }
    let mut r = [t[0], t[1], t[2], t[3]];
    if t[4] != 0 || !less(&r, m) {
        sub_assign(&mut r, m);
    }
    r
}

fn to_mont(a: &Fe, md: &Modulus) -> Fe {
    mont_mul(a, &md.r2, md)
}

fn from_mont(a: &Fe, md: &Modulus) -> Fe {
    mont_mul(a, &ONE, md)
}

/// `a^-1` in the Montgomery domain, by Fermat: both moduli here are prime.
fn mont_inv(a: &Fe, md: &Modulus) -> Fe {
    let mut e = md.m;
    sub_assign(&mut e, &[2, 0, 0, 0]);
    let mut result = to_mont(&ONE, md);
    for i in (0..256).rev() {
        result = mont_mul(&result, &result, md);
        if (e[i / 64] >> (i % 64)) & 1 == 1 {
            result = mont_mul(&result, a, md);
        }
    }
    result
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
// The curve, with every coordinate in the Montgomery domain of p
// ---------------------------------------------------------------------------

/// A point in Jacobian coordinates: `(X : Y : Z)` stands for `(X/Z², Y/Z³)`,
/// and `Z = 0` is the point at infinity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

fn fmul(a: &Fe, b: &Fe) -> Fe {
    mont_mul(a, b, &FP)
}

fn fadd(a: &Fe, b: &Fe) -> Fe {
    add_mod(a, b, &P)
}

fn fsub(a: &Fe, b: &Fe) -> Fe {
    sub_mod(a, b, &P)
}

/// Infinity. Any nonzero `X` and `Y` with `Z = 0`; the ones of the domain.
fn infinity() -> Point {
    let one = to_mont(&ONE, &FP);
    Point {
        x: one,
        y: one,
        z: ZERO,
    }
}

/// Affine coordinates, given as plain integers, into a Jacobian point.
fn lift(x: &Fe, y: &Fe) -> Point {
    Point {
        x: to_mont(x, &FP),
        y: to_mont(y, &FP),
        z: to_mont(&ONE, &FP),
    }
}

/// The same formulas as the P-384 file, `dbl-2001-b`: P-256 also has a = -3.
fn double(p: &Point) -> Point {
    if is_zero(&p.z) {
        return *p;
    }
    let delta = fmul(&p.z, &p.z);
    let gamma = fmul(&p.y, &p.y);
    let beta = fmul(&p.x, &gamma);

    let t = fmul(&fsub(&p.x, &delta), &fadd(&p.x, &delta));
    let alpha = fadd(&fadd(&t, &t), &t);

    let beta4 = fadd(&beta, &beta);
    let beta4 = fadd(&beta4, &beta4);
    let beta8 = fadd(&beta4, &beta4);
    let x3 = fsub(&fmul(&alpha, &alpha), &beta8);

    let yz = fadd(&p.y, &p.z);
    let z3 = fsub(&fsub(&fmul(&yz, &yz), &gamma), &delta);

    let gamma2 = fmul(&gamma, &gamma);
    let g8 = fadd(&gamma2, &gamma2);
    let g8 = fadd(&g8, &g8);
    let g8 = fadd(&g8, &g8);
    let y3 = fsub(&fmul(&alpha, &fsub(&beta4, &x3)), &g8);

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// `add-2007-bl`, with the two cases it cannot handle taken first.
fn add(a: &Point, b: &Point) -> Point {
    if is_zero(&a.z) {
        return *b;
    }
    if is_zero(&b.z) {
        return *a;
    }
    let z1z1 = fmul(&a.z, &a.z);
    let z2z2 = fmul(&b.z, &b.z);
    let u1 = fmul(&a.x, &z2z2);
    let u2 = fmul(&b.x, &z1z1);
    let s1 = fmul(&fmul(&a.y, &b.z), &z2z2);
    let s2 = fmul(&fmul(&b.y, &a.z), &z1z1);

    if u1 == u2 {
        // Same x. The same point needs the doubling formula, because the
        // addition one divides by zero here; a point and its negation sum to
        // infinity. Wycheproof's PointDuplication cases live in this branch.
        return if s1 == s2 { double(a) } else { infinity() };
    }

    let h = fsub(&u2, &u1);
    let h2 = fadd(&h, &h);
    let i = fmul(&h2, &h2);
    let j = fmul(&h, &i);
    let r = fsub(&s2, &s1);
    let r = fadd(&r, &r);
    let v = fmul(&u1, &i);

    let x3 = fsub(&fsub(&fmul(&r, &r), &j), &fadd(&v, &v));
    let s1j = fmul(&s1, &j);
    let y3 = fsub(&fmul(&r, &fsub(&v, &x3)), &fadd(&s1j, &s1j));
    let zz = fadd(&a.z, &b.z);
    let z3 = fmul(&fsub(&fsub(&fmul(&zz, &zz), &z1z1), &z2z2), &h);

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// `k * p`, most significant bit first. `k` is a plain integer.
fn mul(k: &Fe, p: &Point) -> Point {
    let mut acc = infinity();
    for i in (0..256).rev() {
        acc = double(&acc);
        if (k[i / 64] >> (i % 64)) & 1 == 1 {
            acc = add(&acc, p);
        }
    }
    acc
}

/// The affine x coordinate as a plain integer, or `None` at infinity.
fn affine_x(p: &Point) -> Option<Fe> {
    if is_zero(&p.z) {
        return None;
    }
    let zinv = mont_inv(&p.z, &FP);
    let zinv2 = fmul(&zinv, &zinv);
    Some(from_mont(&fmul(&p.x, &zinv2), &FP))
}

/// `y² == x³ - 3x + b`, for plain integers already below p.
fn on_curve(x: &Fe, y: &Fe) -> bool {
    let (x, y) = (to_mont(x, &FP), to_mont(y, &FP));
    let lhs = fmul(&y, &y);
    let x3 = fmul(&fmul(&x, &x), &x);
    let three_x = fadd(&fadd(&x, &x), &x);
    let rhs = fadd(&fsub(&x3, &three_x), &to_mont(&B, &FP));
    lhs == rhs
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------

/// Why a signature was not accepted. Named rather than a bare `false`, for the
/// reason [`crate::p384::SigError`] gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    BadKeyEncoding,
    /// Not on P-256, or a coordinate not below the field prime.
    KeyNotOnCurve,
    BadSignatureEncoding,
    /// `r` or `s` outside `[1, n-1]`.
    ComponentOutOfRange,
    DoesNotVerify,
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKeyEncoding => write!(f, "the public key is not an uncompressed P-256 point"),
            Self::KeyNotOnCurve => write!(f, "the public key is not on P-256"),
            Self::BadSignatureEncoding => write!(f, "a signature must be 64 bytes of r and s"),
            Self::ComponentOutOfRange => write!(f, "r or s is zero or not below the group order"),
            Self::DoesNotVerify => write!(f, "the signature does not verify"),
        }
    }
}

impl std::error::Error for SigError {}

/// Verify `signature` over `message` under `public_key`, ES256.
///
/// The message is hashed with SHA-256 here rather than by the caller, so no
/// caller can pass a digest computed some other way and have it accepted.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), SigError> {
    let (qx, qy) = public_point(public_key)?;
    if signature.len() != SIGNATURE_BYTES {
        return Err(SigError::BadSignatureEncoding);
    }

    let r = from_be_bytes(&signature[..32]);
    let s = from_be_bytes(&signature[32..]);
    if is_zero(&r) || is_zero(&s) || !less(&r, &N) || !less(&s, &N) {
        return Err(SigError::ComponentOutOfRange);
    }

    verify_point(&lift(&qx, &qy), &sha256::digest(message), &r, &s)
}

/// Whether `public_key` is an uncompressed point on P-256, checked exactly as
/// [`verify`] checks it. For a caller loading keys before any signature
/// arrives, so a key that could never verify anything is refused at startup
/// rather than discovered by the first request that names it.
pub fn check_public_key(public_key: &[u8]) -> Result<(), SigError> {
    public_point(public_key).map(|_| ())
}

fn public_point(public_key: &[u8]) -> Result<(Fe, Fe), SigError> {
    if public_key.len() != PUBLIC_KEY_BYTES || public_key[0] != 0x04 {
        return Err(SigError::BadKeyEncoding);
    }
    let qx = from_be_bytes(&public_key[1..33]);
    let qy = from_be_bytes(&public_key[33..65]);
    if !less(&qx, &P) || !less(&qy, &P) || !on_curve(&qx, &qy) {
        return Err(SigError::KeyNotOnCurve);
    }
    Ok((qx, qy))
}

/// The equation alone, for a point already accepted and `r`, `s` already in
/// range. Separate so the test that forges against an off-curve key can show
/// the forgery is real, which is the only way to know the check above matters.
fn verify_point(q: &Point, digest: &[u8; 32], r: &Fe, s: &Fe) -> Result<(), SigError> {
    // SHA-256 is exactly the group's bit length, so the whole digest is used,
    // and it is below 2^256 < 2n, so one subtraction reduces it.
    let mut e = from_be_bytes(digest);
    if !less(&e, &N) {
        sub_assign(&mut e, &N);
    }

    let w = mont_inv(&to_mont(s, &FN), &FN);
    let u1 = from_mont(&mont_mul(&to_mont(&e, &FN), &w, &FN), &FN);
    let u2 = from_mont(&mont_mul(&to_mont(r, &FN), &w, &FN), &FN);

    let point = add(&mul(&u1, &lift(&GX, &GY)), &mul(&u2, q));
    let mut v = affine_x(&point).ok_or(SigError::DoesNotVerify)?;
    // x is below p, which is below 2n, so one subtraction reduces it mod n.
    if !less(&v, &N) {
        sub_assign(&mut v, &N);
    }
    if v == *r {
        Ok(())
    } else {
        Err(SigError::DoesNotVerify)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // The oracle: the P-384 file's long division, at this width, test-only.
    // -----------------------------------------------------------------------

    fn mul_wide(a: &Fe, b: &Fe) -> [u64; 8] {
        let mut out = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = u128::from(a[i]) * u128::from(b[j]) + u128::from(out[i + j]) + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            out[i + 4] = carry as u64;
        }
        out
    }

    fn reduce(wide: &[u64; 8], m: &Fe) -> Fe {
        let mut r = ZERO;
        for i in (0..512).rev() {
            let bit = (wide[i / 64] >> (i % 64)) & 1;
            let mut carry = 0u64;
            for limb in r.iter_mut() {
                let next = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            r[0] |= bit;
            if carry != 0 || !less(&r, m) {
                sub_assign(&mut r, m);
            }
        }
        r
    }

    fn slow_mul(a: &Fe, b: &Fe, m: &Fe) -> Fe {
        reduce(&mul_wide(a, b), m)
    }

    /// xorshift, so the values are spread over every limb and every carry.
    fn values(seed: u64, m: &Fe) -> Vec<Fe> {
        let mut state = seed;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut out = vec![ZERO, ONE, {
            let mut top = *m;
            sub_assign(&mut top, &ONE);
            top
        }];
        for _ in 0..400 {
            let mut v = [next(), next(), next(), next()];
            // Below m by construction: clear until it is.
            while !less(&v, m) {
                v[3] >>= 1;
            }
            out.push(v);
        }
        // Values with long runs of one bit, where carries chain furthest.
        for limbs in [
            [u64::MAX, u64::MAX, u64::MAX, 0],
            [u64::MAX, 0, u64::MAX, 0],
        ] {
            if less(&limbs, m) {
                out.push(limbs);
            }
        }
        out
    }

    #[test]
    fn the_montgomery_constants_are_the_ones_they_claim_to_be() {
        for md in [FP, FN] {
            assert_eq!(
                md.inv.wrapping_mul(md.m[0]),
                u64::MAX,
                "inv is not -m^-1 mod 2^64"
            );
            // R^2 mod m, by long division of 2^512.
            let mut wide = [0u64; 8];
            wide[7] = 1 << 63;
            // 2^511 mod m, doubled once more modulo m.
            let half = reduce(&wide, &md.m);
            assert_eq!(add_mod(&half, &half, &md.m), md.r2);
        }
    }

    #[test]
    fn montgomery_products_agree_with_long_division() {
        for (md, seed) in [(FP, 0x9e37_79b9_7f4a_7c15u64), (FN, 0xd1b5_4a32_d192_ed03)] {
            let vs = values(seed, &md.m);
            for pair in vs.windows(2) {
                let (a, b) = (pair[0], pair[1]);
                let got = from_mont(&mont_mul(&to_mont(&a, &md), &to_mont(&b, &md), &md), &md);
                assert_eq!(got, slow_mul(&a, &b, &md.m), "{a:x?} * {b:x?}");
            }
        }
    }

    /// The case random values never reach. Before its last step a Montgomery
    /// product lies in `[0, 2m)`, and the final subtraction is all that brings
    /// a value in `[m, 2^256)` back below `m`. For these two moduli that window
    /// is about one product in 2^33, so the comparison above, over four hundred
    /// random pairs, passed with the subtraction deleted: measured, as a
    /// surviving mutant, before this test existed.
    ///
    /// So the window is reached on purpose. With `b = m - 1` and
    /// `a = (-d R) mod m`, the product is `a b ≡ d R (mod m)`, and working the
    /// reduction through gives exactly `m + d` before the subtraction, for any
    /// small `d`. The right answer is `d`.
    #[test]
    fn a_product_that_lands_between_m_and_two_to_the_256_is_still_reduced() {
        for md in [FP, FN] {
            let mut r_mod_m = [0u64; 8];
            r_mod_m[4] = 1;
            let r_mod_m = reduce(&r_mod_m, &md.m);
            let mut m_minus_one = md.m;
            sub_assign(&mut m_minus_one, &ONE);
            for d in 1u64..=4 {
                // a = -(d R) mod m
                let d_r = slow_mul(&[d, 0, 0, 0], &r_mod_m, &md.m);
                let a = sub_mod(&ZERO, &d_r, &md.m);
                assert_eq!(
                    mont_mul(&a, &m_minus_one, &md),
                    [d, 0, 0, 0],
                    "d = {d}, modulus {:x?}",
                    md.m
                );
            }
        }
    }

    #[test]
    fn an_inverse_times_its_value_is_one() {
        for md in [FP, FN] {
            for a in values(7, &md.m)
                .into_iter()
                .filter(|v| !is_zero(v))
                .take(40)
            {
                let am = to_mont(&a, &md);
                let product = from_mont(&mont_mul(&am, &mont_inv(&am, &md), &md), &md);
                assert_eq!(product, ONE, "{a:x?}");
            }
        }
    }

    #[test]
    fn the_constants_are_the_ones_they_claim_to_be() {
        assert!(on_curve(&GX, &GY));
        assert!(less(&GX, &P) && less(&GY, &P));
        assert!(less(&N, &P), "the order is below the field size");
        // a = -3, which the doubling formula assumes: checked by the generator
        // satisfying the equation written with -3x above.
    }

    #[test]
    fn the_group_order_annihilates_the_generator() {
        assert!(affine_x(&mul(&N, &lift(&GX, &GY))).is_none());
        let mut n_minus_one = N;
        sub_assign(&mut n_minus_one, &ONE);
        // (n - 1) G is -G: same x, so this exercises the last doubling and
        // addition of the ladder against an answer known in advance.
        assert_eq!(affine_x(&mul(&n_minus_one, &lift(&GX, &GY))), Some(GX));
    }

    #[test]
    fn doubling_and_addition_agree() {
        let g = lift(&GX, &GY);
        assert_eq!(affine_x(&double(&g)), affine_x(&add(&g, &g)));
    }

    #[test]
    fn scalar_multiplication_is_linear() {
        let g = lift(&GX, &GY);
        let a = add(&mul(&[3, 0, 0, 0], &g), &mul(&[5, 0, 0, 0], &g));
        assert_eq!(affine_x(&a), affine_x(&mul(&[8, 0, 0, 0], &g)));
    }

    /// 2G against its known x coordinate, `7cf27b18...47669978`, recomputed
    /// with Python's integers for this test, so the formulas are checked
    /// against arithmetic that shares nothing with them.
    #[test]
    fn two_g_is_the_published_point() {
        let two_g = from_be_bytes(&[
            0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5,
            0x1a, 0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc,
            0x47, 0x66, 0x99, 0x78,
        ]);
        assert_eq!(affine_x(&double(&lift(&GX, &GY))), Some(two_g));
    }

    #[test]
    fn a_point_plus_its_negation_is_infinity() {
        let minus_gy = sub_mod(&ZERO, &GY, &P);
        assert!(affine_x(&add(&lift(&GX, &GY), &lift(&GX, &minus_gy))).is_none());
    }

    /// The invalid-curve attack, carried out, so the on-curve check is held by
    /// a forgery rather than by a sentence.
    ///
    /// `(x0, 0)` lies on `y² = x³ - 3x + b'` for `b' = -(x0³ - 3x0)`, and it has
    /// order two there: doubling it gives `Z = 2YZ = 0`. The formulas never read
    /// `b`, so handed that point as a key they compute in the attacker's curve,
    /// where `u2 Q` is `Q` or infinity by the parity of `u2`. Choose `k`, set
    /// `r = x(kG)` and `s = e / k`; then `u1 = k`, and whenever `u2 = r / s` is
    /// even the equation reads `x(kG) == r`, which holds. No private key was
    /// involved, for any message.
    #[test]
    fn an_off_curve_key_would_accept_a_forgery_and_is_refused() {
        let message = b"written by nobody who holds a key";
        let digest = sha256::digest(message);
        let mut e = from_be_bytes(&digest);
        if !less(&e, &N) {
            sub_assign(&mut e, &N);
        }
        let x0: Fe = [5, 0, 0, 0];
        let order_two = lift(&x0, &ZERO);
        assert!(affine_x(&double(&order_two)).is_none(), "order two");
        assert!(!on_curve(&x0, &ZERO));

        let mut forged = None;
        for k in 2u64..200 {
            let k: Fe = [k, 0, 0, 0];
            let r = affine_x(&mul(&k, &lift(&GX, &GY))).expect("kG is finite");
            let mut r = r;
            if !less(&r, &N) {
                sub_assign(&mut r, &N);
            }
            let kinv = mont_inv(&to_mont(&k, &FN), &FN);
            let s = from_mont(&mont_mul(&to_mont(&e, &FN), &kinv, &FN), &FN);
            let w = mont_inv(&to_mont(&s, &FN), &FN);
            let u2 = from_mont(&mont_mul(&to_mont(&r, &FN), &w, &FN), &FN);
            if u2[0] & 1 == 0 {
                forged = Some((r, s));
                break;
            }
        }
        let (r, s) = forged.expect("half of all k give an even u2");

        // The forgery is real: the equation alone accepts it.
        assert_eq!(verify_point(&order_two, &digest, &r, &s), Ok(()));

        // And the verifier does not, because the key is not on the curve.
        let mut key = [0u8; PUBLIC_KEY_BYTES];
        key[0] = 0x04;
        key[32] = 5;
        let mut signature = [0u8; SIGNATURE_BYTES];
        for i in 0..4 {
            signature[24 - i * 8..32 - i * 8].copy_from_slice(&r[i].to_be_bytes());
            signature[56 - i * 8..64 - i * 8].copy_from_slice(&s[i].to_be_bytes());
        }
        assert_eq!(
            verify(&key, message, &signature),
            Err(SigError::KeyNotOnCurve)
        );
    }
}
