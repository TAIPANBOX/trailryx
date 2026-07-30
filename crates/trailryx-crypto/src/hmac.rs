//! HMAC-SHA256, for signing requests to somebody else's service.
//!
//! # Why this is here, and the same warning [`crate::sha256`] carries
//!
//! Nothing Trailryx writes is authenticated with HMAC. This exists because AWS
//! Signature Version 4 is built out of four chained HMAC-SHA256 operations, and an
//! object-store client that cannot sign a request cannot talk to an object store.
//!
//! So the rule is one sentence, the same as its digest's: **HMAC-SHA256 appears on
//! the request-signing side of somebody else's protocol and nowhere else.** No chain,
//! no root and no record uses it.
//!
//! # Constant time
//!
//! [`verify`] compares in constant time. The signing path does not need it and does
//! not claim it: a signature computed from a secret is not compared against anything
//! here, it is sent. Where a comparison does happen it is against a value an attacker
//! may choose, which is the case that needs the guarantee.

use crate::sha256::{SHA256_BYTES, Sha256};

/// SHA-256's block size, which is what pads the key.
const BLOCK: usize = 64;

/// `HMAC-SHA256(key, message)`, RFC 2104.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; SHA256_BYTES] {
    // A key longer than the block is replaced by its digest. Truncating instead is
    // the classic mistake and it silently makes different keys equal.
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..SHA256_BYTES].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner = Sha256::new();
    let mut block = [0u8; BLOCK];
    for (out, byte) in block.iter_mut().zip(padded.iter()) {
        *out = byte ^ 0x36;
    }
    inner.update(&block);
    inner.update(message);
    let inner = inner.finish();

    let mut outer = Sha256::new();
    for (out, byte) in block.iter_mut().zip(padded.iter()) {
        *out = byte ^ 0x5c;
    }
    outer.update(&block);
    outer.update(&inner);
    outer.finish()
}

/// Constant-time comparison of two tags.
pub fn verify(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 4231's test vectors for HMAC-SHA-256, written out rather than generated.
    #[test]
    fn the_published_vectors_match() {
        // Case 1
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Case 2: a key shorter than the block, a longer message.
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Case 3
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 20], &[0xdd; 50])),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
        // Case 6: a key LONGER than the block, which must be hashed and not truncated.
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        // Case 7: a long key and a long message together.
        //
        // Written as one concatenated literal rather than a wrapped one, because the
        // vector is exact and a line continuation would put spaces in the message. The
        // first version of this test dodged that by asserting the digest's LENGTH,
        // which is a test that passes for any implementation at all.
        let case7 = concat!(
            "This is a test using a larger than block-size key and a larger than ",
            "block-size data. The key needs to be hashed before being used by the HMAC ",
            "algorithm."
        );
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 131], case7.as_bytes())),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    /// A key of exactly the block size, and one byte either side. The three cases the
    /// padding logic branches on, and the boundary is where it goes wrong.
    #[test]
    fn keys_at_the_block_boundary_are_padded_rather_than_truncated() {
        let short = hmac_sha256(&[0x11; 63], b"m");
        let exact = hmac_sha256(&[0x11; 64], b"m");
        let long = hmac_sha256(&[0x11; 65], b"m");
        assert_ne!(short, exact);
        assert_ne!(exact, long);
        // A 65-byte key is hashed to 32 bytes, so it must equal HMAC with that digest
        // as the key. Truncating to 64 instead would make this fail.
        assert_eq!(long, hmac_sha256(&Sha256::digest(&[0x11; 65]), b"m"));
    }

    #[test]
    fn an_empty_key_and_an_empty_message_are_still_defined() {
        assert_eq!(hex(&hmac_sha256(b"", b"")).len(), 64);
        assert_ne!(hmac_sha256(b"", b""), hmac_sha256(b"", b"x"));
        assert_ne!(hmac_sha256(b"", b""), hmac_sha256(b"x", b""));
    }

    #[test]
    fn verification_is_length_safe_and_agrees_with_equality() {
        let tag = hmac_sha256(b"k", b"m");
        assert!(verify(&tag, &hmac_sha256(b"k", b"m")));
        assert!(!verify(&tag, &hmac_sha256(b"k", b"n")));
        assert!(!verify(&tag, &tag[..31]));
        assert!(!verify(&[], &tag));
    }
}
