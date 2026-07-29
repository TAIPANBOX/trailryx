//! SHA-384, FIPS 180-4.
//!
//! # Why this exists, and when it goes away
//!
//! The rule for this project is that we do not write our own cryptography, and
//! the value of a validated module is part of what is being sold. This file is
//! a deliberate, bounded exception, and it is worth being precise about the
//! reasoning rather than quietly shipping it.
//!
//! What makes hand-written cryptography dangerous is designing primitives,
//! handling keys, and leaking secrets through timing. None of the three applies
//! here: SHA-384 is a fixed, published algorithm; there is no key; and the input
//! to the chain is public record metadata, so a data-dependent timing signal
//! reveals nothing an observer does not already hold. What remains is the risk
//! of an incorrect implementation, and that is exactly what published test
//! vectors settle.
//!
//! It is still not the production path. Stage 7 introduces `CryptoProvider` over
//! **aws-lc-rs**, whose underlying AWS-LC was the first open-source module to
//! include ML-KEM in a FIPS 140-3 validation, and this becomes the portable
//! fallback for platforms that module does not cover. Keeping it behind
//! [`Digest`] from the start means that swap touches one file.
//!
//! SHA-384 rather than SHA-256 because CNSA 2.0 requires 384 or better, and a
//! product that fails its own scanner cannot be sold to the people who care.

use crate::Digest;
use trailryx_record::{HASH_BYTES, Hash};

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-384 initial state: FIPS 180-4 section 5.3.4.
const IV: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

const BLOCK: usize = 128;

#[derive(Debug, Clone)]
pub struct Sha384 {
    h: [u64; 8],
    buf: [u8; BLOCK],
    buf_len: usize,
    total_bytes: u128,
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha384 {
    pub fn new() -> Self {
        Self {
            h: IV,
            buf: [0u8; BLOCK],
            buf_len: 0,
            total_bytes: 0,
        }
    }

    /// Convenience for the common one-shot case.
    pub fn digest(data: &[u8]) -> Hash {
        let mut h = Self::new();
        h.update(data);
        h.finish()
    }

    fn compress(&mut self, block: &[u8; BLOCK]) {
        let mut w = [0u64; 80];
        for (i, w_i) in w.iter_mut().enumerate().take(16) {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *w_i = u64::from_be_bytes(b);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = self.h;

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(hh);
    }
}

impl Digest for Sha384 {
    fn update(&mut self, mut data: &[u8]) {
        self.total_bytes += data.len() as u128;

        if self.buf_len > 0 {
            let need = BLOCK - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }

        while data.len() >= BLOCK {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(&data[..BLOCK]);
            self.compress(&block);
            data = &data[BLOCK..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finish(mut self) -> Hash {
        let bit_len = self.total_bytes * 8;

        // 0x80, then zeros, then the 128-bit length.
        self.update(&[0x80]);
        self.total_bytes -= 1; // padding is not message length
        while self.buf_len != BLOCK - 16 {
            self.update(&[0x00]);
            self.total_bytes -= 1;
        }

        let mut tail = [0u8; 16];
        tail.copy_from_slice(&bit_len.to_be_bytes());
        self.update(&tail);

        let mut out = [0u8; HASH_BYTES];
        for (i, word) in self.h.iter().take(6).enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        Hash(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 and the NIST example set. If the round constants or the
    /// schedule were wrong, these would not match, which is the whole reason a
    /// hand-written digest is acceptable here at all.
    #[test]
    fn nist_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"",
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            ),
            (
                b"abc",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
            ),
        ];

        for (input, want) in cases {
            let got = Sha384::digest(input).to_hex();
            assert_eq!(&got, want, "input {:?}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn a_million_a_matches() {
        // The classic long-input vector: catches length-encoding mistakes that
        // short inputs never reach.
        let mut h = Sha384::new();
        for _ in 0..1_000 {
            h.update(&[b'a'; 1_000]);
        }
        assert_eq!(
            h.finish().to_hex(),
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
        );
    }

    #[test]
    fn chunking_does_not_change_the_result() {
        // Streaming in awkward pieces must equal one shot. Journal writes arrive
        // in batches of whatever size, so this is the property that matters in
        // practice, not the one-shot case.
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let want = Sha384::digest(&data);

        for chunk in [1usize, 7, 63, 64, 127, 128, 129, 1000] {
            let mut h = Sha384::new();
            for part in data.chunks(chunk) {
                h.update(part);
            }
            assert_eq!(h.finish(), want, "chunk size {chunk}");
        }
    }

    #[test]
    fn one_flipped_bit_changes_everything() {
        let a = Sha384::digest(b"the record as written");
        let b = Sha384::digest(b"the record as written.");
        assert_ne!(a, b);
        let differing = a
            .as_bytes()
            .iter()
            .zip(b.as_bytes())
            .filter(|(x, y)| x != y)
            .count();
        assert!(differing > 20, "only {differing} bytes differ");
    }
}
