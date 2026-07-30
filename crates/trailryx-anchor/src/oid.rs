//! The object identifiers this crate compares against, encoded.
//!
//! Stored as the DER arc bytes rather than as dotted strings, because every use
//! is a comparison against what came off the wire and decoding both sides to
//! compare them would be work done only to be undone. The dotted form is in the
//! comment beside each one so a reader can check it against the registry.
//!
//! There is no lookup table and no way to ask "what is this OID". An unknown OID
//! here is an unknown OID, not a name to render: this crate refuses algorithms it
//! does not implement rather than reporting them.

/// 2.16.840.1.101.3.4.2.1, id-sha256.
pub const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// 2.16.840.1.101.3.4.2.2, id-sha384.
pub const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

/// 1.2.840.113549.1.1.1, rsaEncryption.
pub const RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

/// 1.2.840.113549.1.1.11, sha256WithRSAEncryption.
pub const SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

/// 1.2.840.113549.1.1.12, sha384WithRSAEncryption.
pub const SHA384_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];

/// 1.2.840.113549.1.7.2, id-signedData.
pub const SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

/// 1.2.840.113549.1.9.16.1.4, id-ct-TSTInfo.
pub const TST_INFO: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];

/// 1.2.840.113549.1.9.3, id-contentType.
pub const CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];

/// 1.2.840.113549.1.9.4, id-messageDigest.
pub const MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every constant must be a well-formed OID by the reader's own rules. A
    /// typo in one of these bytes would produce a constant that never matches
    /// anything, and the failure would look like "the TSA used an algorithm we
    /// do not support" forever.
    #[test]
    fn every_constant_parses_as_an_object_identifier() {
        let all: [(&str, &[u8]); 9] = [
            ("SHA256", SHA256),
            ("SHA384", SHA384),
            ("RSA_ENCRYPTION", RSA_ENCRYPTION),
            ("SHA256_WITH_RSA", SHA256_WITH_RSA),
            ("SHA384_WITH_RSA", SHA384_WITH_RSA),
            ("SIGNED_DATA", SIGNED_DATA),
            ("TST_INFO", TST_INFO),
            ("CONTENT_TYPE", CONTENT_TYPE),
            ("MESSAGE_DIGEST", MESSAGE_DIGEST),
        ];
        for (name, arcs) in all {
            let encoded = trailryx_asn1::oid(arcs);
            let parsed = trailryx_asn1::Der::new(&encoded)
                .oid()
                .unwrap_or_else(|e| panic!("{name} is not a valid OID: {e}"));
            assert_eq!(parsed.as_bytes(), arcs, "{name} did not round-trip");
        }
    }

    /// Two constants that are equal would make a comparison accept the wrong
    /// algorithm silently. Checked rather than eyeballed.
    #[test]
    fn no_two_constants_are_the_same_bytes() {
        let all: [&[u8]; 9] = [
            SHA256,
            SHA384,
            RSA_ENCRYPTION,
            SHA256_WITH_RSA,
            SHA384_WITH_RSA,
            SIGNED_DATA,
            TST_INFO,
            CONTENT_TYPE,
            MESSAGE_DIGEST,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "two OID constants are identical");
            }
        }
    }
}
