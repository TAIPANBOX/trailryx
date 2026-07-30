//! SHA-256, for reading other people's signatures and for nothing else.
//!
//! # Why this is here when the store uses SHA-384
//!
//! Nothing Trailryx writes is hashed with SHA-256. Every chain, every Merkle
//! root, every record digest and every published root is SHA-384, and that is
//! not negotiable: the record format is frozen and its hashes are 48 bytes wide.
//!
//! This exists because **a third party chooses the digest for its own
//! signature**. A timestamping authority signs its token with
//! `sha256WithRSAEncryption` more often than not, and the CMS structure around
//! that token carries a SHA-256 digest of its own content. Verifying what
//! somebody else signed means computing the hash they used, not the one we
//! prefer.
//!
//! So the rule is one sentence: **SHA-256 appears on the verification side of a
//! third-party signature and nowhere else.** It deliberately does not implement
//! [`crate::Digest`], whose output is a 48-byte [`Hash`], so a call site cannot
//! reach for it where the store expects a store hash and get a shorter digest
//! zero-padded into place. The type system refusing is better than a comment
//! asking.
//!
//! [`Hash`]: crate::Hash

/// SHA-256 output width.
pub const SHA256_BYTES: usize = 32;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    /// Message length in **bits**, which is what the padding encodes. Counted
    /// here rather than derived at the end, because a byte count converted late
    /// is a byte count that can overflow after the last update.
    bits: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: INITIAL,
            buffer: [0; 64],
            buffered: 0,
            bits: 0,
        }
    }

    pub fn digest(data: &[u8]) -> [u8; SHA256_BYTES] {
        let mut h = Self::new();
        h.update(data);
        h.finish()
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.bits = self.bits.wrapping_add((data.len() as u64).wrapping_mul(8));
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 64 {
                // The buffer did not fill, so `data` is spent. Returning here is
                // the whole fix for a defect the one-shot vectors could not see:
                // the first version fell through to the tail assignment below,
                // which set `buffered` to the length of an empty tail and threw
                // away everything that had been buffered. Feeding "abc" one byte
                // at a time produced the digest of "c".
                debug_assert!(data.is_empty());
                return;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }
        let mut chunks = data.chunks_exact(64);
        for block in &mut chunks {
            let mut fixed = [0u8; 64];
            fixed.copy_from_slice(block);
            self.compress(&fixed);
        }
        let tail = chunks.remainder();
        self.buffer[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
    }

    pub fn finish(mut self) -> [u8; SHA256_BYTES] {
        let bits = self.bits;
        self.update_raw(&[0x80]);
        while self.buffered != 56 {
            self.update_raw(&[0x00]);
        }
        self.update_raw(&bits.to_be_bytes());
        debug_assert_eq!(self.buffered, 0, "padding did not land on a block boundary");

        let mut out = [0u8; SHA256_BYTES];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// `update` without touching the bit counter, for the padding itself.
    fn update_raw(&mut self, data: &[u8]) {
        for byte in data {
            self.buffer[self.buffered] = *byte;
            self.buffered += 1;
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The vectors from FIPS 180-4 and RFC 6234. Written out rather than
    /// generated, because a self-generated vector proves nothing.
    #[test]
    fn the_published_vectors_match() {
        let cases: [(&[u8], &str); 4] = [
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                hex(&Sha256::digest(input)),
                expected,
                "input of {} bytes",
                input.len()
            );
        }
    }

    /// A million 'a's: the vector that catches a length counter that overflows a
    /// u32 or a padding routine that mishandles many blocks.
    #[test]
    fn the_million_a_vector_matches() {
        let mut h = Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex(&h.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// Feeding the same bytes in every chunking must give the same digest. This
    /// is where a buffering bug lives, and it is invisible to a one-shot test.
    #[test]
    fn any_chunking_of_the_same_input_gives_the_same_digest() {
        let input: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();
        let once = Sha256::digest(&input);
        for chunk in [1usize, 2, 3, 7, 31, 55, 63, 64, 65, 127, 128, 129, 499] {
            let mut h = Sha256::new();
            for part in input.chunks(chunk) {
                h.update(part);
            }
            assert_eq!(
                h.finish(),
                once,
                "chunked into {chunk}-byte pieces gave a different digest"
            );
        }
    }

    /// Every length around a block boundary, where padding either fits in the
    /// last block or forces another one.
    #[test]
    fn every_length_across_two_block_boundaries_is_stable_under_chunking() {
        for len in 0..200usize {
            let input: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let once = Sha256::digest(&input);
            let mut h = Sha256::new();
            for byte in &input {
                h.update(&[*byte]);
            }
            assert_eq!(h.finish(), once, "length {len} disagreed byte by byte");
        }
    }
}
