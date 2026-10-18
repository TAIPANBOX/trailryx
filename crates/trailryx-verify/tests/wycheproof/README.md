# Project Wycheproof, vendored

`ecdsa_secp256r1_sha256_p1363_test.json` is copied byte for byte from Project
Wycheproof, <https://github.com/C2SP/wycheproof>, path
`testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json` at commit
`7a325932231bd7a724c791c8b0d65ea4d6d2f435` (12 October 2026). SHA-256 of the
file: `c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986`.

It is licensed under the Apache License, Version 2.0, the same licence as this
repository. The licence text Wycheproof ships is beside it as `LICENSE`.

## Why the P1363 file and not the DER one

Wycheproof publishes the same ECDSA P-256 SHA-256 cases in two encodings. The
DER file tests an ASN.1 signature parser as much as it tests ECDSA. A JWS
signature (RFC 7518 section 3.4) is the fixed-width `r || s` that IEEE P1363
defines, which is the only form `trailryx_verify::p256::verify` accepts, so the
P1363 file is the one whose every case is a statement about this verifier.

## What the test holds

`tests/it/p256.rs` runs every case and requires each one's stated result:
`valid` must verify and `invalid` must not. The file contains no `acceptable`
cases, and the test refuses to run if one appears rather than deciding for it.
Do not edit the JSON: refresh it from upstream, and update the commit and the
digest above in the same change.
