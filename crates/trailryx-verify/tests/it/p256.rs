//! ECDSA P-256, against signatures we did not make and cases we did not choose.
//!
//! The P-384 tests next door use vectors OpenSSL signed. These use Project
//! Wycheproof, whose cases were built to break verifiers: `r` or `s` of zero, of
//! `n`, of `n + r`; hashes with long runs of one bit; public keys at the edges of
//! the field; signatures where a careless Shamir ladder meets the point at
//! infinity half way. Every case says what a correct verifier answers, and this
//! test requires that answer for every one of them.

use trailryx_json::{Event, Limits, Reader};
use trailryx_verify::p256::{self, SigError};

const WYCHEPROOF: &str = include_str!("../wycheproof/ecdsa_secp256r1_sha256_p1363_test.json");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// One Wycheproof case, flattened with its group's key.
#[derive(Debug)]
struct Case {
    id: u64,
    comment: String,
    flags: Vec<String>,
    key: Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
    result: String,
}

/// The file's own count, and every case in it.
fn wycheproof() -> (u64, String, Vec<Case>) {
    let mut r = Reader::new(WYCHEPROOF.as_bytes(), Limits::default(), 1);
    assert_eq!(r.value().expect("json"), Event::ObjectStart);
    let mut declared = 0;
    let mut algorithm = String::new();
    let mut cases = Vec::new();
    while let Some(name) = r.next_name().expect("a member") {
        match name.as_ref() {
            "numberOfTests" => {
                let Event::Number(n) = r.value().expect("a number") else {
                    panic!("numberOfTests is not a number")
                };
                declared = n.as_u64().expect("a count");
            }
            "algorithm" => {
                let Event::Str(s) = r.value().expect("a string") else {
                    panic!("algorithm is not a string")
                };
                algorithm = s.into_owned();
            }
            "testGroups" => {
                assert_eq!(r.value().expect("array"), Event::ArrayStart);
                while r.next_element().expect("a group") {
                    read_group(&mut r, &mut cases);
                }
            }
            _ => r.skip_value().expect("skippable"),
        }
    }
    r.finish().expect("one document");
    (declared, algorithm, cases)
}

fn string(r: &mut Reader<'_>) -> String {
    match r.value().expect("a value") {
        Event::Str(s) => s.into_owned(),
        other => panic!("expected a string, got {other:?}"),
    }
}

fn read_group(r: &mut Reader<'_>, out: &mut Vec<Case>) {
    assert_eq!(r.value().expect("group"), Event::ObjectStart);
    let mut key = Vec::new();
    let mut sha = String::new();
    let mut tests = Vec::new();
    while let Some(name) = r.next_name().expect("a member") {
        match name.as_ref() {
            "sha" => sha = string(r),
            "publicKey" => {
                assert_eq!(r.value().expect("key"), Event::ObjectStart);
                while let Some(field) = r.next_name().expect("a member") {
                    match field.as_ref() {
                        "uncompressed" => key = unhex(&string(r)),
                        "curve" => assert_eq!(string(r), "secp256r1"),
                        _ => r.skip_value().expect("skippable"),
                    }
                }
            }
            "tests" => {
                assert_eq!(r.value().expect("tests"), Event::ArrayStart);
                while r.next_element().expect("a test") {
                    tests.push(read_test(r));
                }
            }
            _ => r.skip_value().expect("skippable"),
        }
    }
    assert_eq!(sha, "SHA-256", "a group hashed with something else");
    assert!(!key.is_empty(), "a group with no uncompressed key");
    for mut case in tests {
        case.key = key.clone();
        out.push(case);
    }
}

fn read_test(r: &mut Reader<'_>) -> Case {
    assert_eq!(r.value().expect("test"), Event::ObjectStart);
    let mut case = Case {
        id: 0,
        comment: String::new(),
        flags: Vec::new(),
        key: Vec::new(),
        msg: Vec::new(),
        sig: Vec::new(),
        result: String::new(),
    };
    while let Some(name) = r.next_name().expect("a member") {
        match name.as_ref() {
            "tcId" => {
                let Event::Number(n) = r.value().expect("a number") else {
                    panic!("tcId is not a number")
                };
                case.id = n.as_u64().expect("an id");
            }
            "comment" => case.comment = string(r),
            "msg" => case.msg = unhex(&string(r)),
            "sig" => case.sig = unhex(&string(r)),
            "result" => case.result = string(r),
            "flags" => {
                assert_eq!(r.value().expect("flags"), Event::ArrayStart);
                while r.next_element().expect("a flag") {
                    case.flags.push(string(r));
                }
            }
            _ => r.skip_value().expect("skippable"),
        }
    }
    case
}

#[test]
fn every_wycheproof_case_gets_the_answer_it_states() {
    let (declared, algorithm, cases) = wycheproof();
    assert_eq!(algorithm, "ECDSA");
    // A reader that silently skipped a group would pass every case it did read.
    assert_eq!(
        cases.len() as u64,
        declared,
        "the file declares {declared} tests and {} were read",
        cases.len()
    );

    let mut wrong = Vec::new();
    let (mut valid, mut invalid) = (0, 0);
    for case in &cases {
        let expected = match case.result.as_str() {
            "valid" => true,
            "invalid" => false,
            // Not present in the vendored file. If a refresh adds one, the
            // decision about it is a person's, not this loop's.
            other => panic!(
                "tcId {} says {other:?}, which this test does not decide",
                case.id
            ),
        };
        let got = p256::verify(&case.key, &case.msg, &case.sig);
        if got.is_ok() != expected {
            wrong.push(format!(
                "tcId {} ({}; {:?}): expected {}, got {got:?}",
                case.id, case.comment, case.flags, case.result
            ));
        }
        if expected {
            valid += 1;
        } else {
            invalid += 1;
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} Wycheproof cases answered wrongly:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
    // The two halves, so a verifier that refuses everything or accepts
    // everything cannot pass by the file happening to lean one way.
    assert!(
        valid > 100 && invalid > 50,
        "{valid} valid, {invalid} invalid"
    );
    println!("{valid} accepted and {invalid} refused, as Wycheproof states");
}

/// The case classes that exist because a verifier somewhere got them wrong. Each
/// must be present in the file, or the test above proves less than it reads as.
#[test]
fn the_dangerous_classes_are_all_in_the_file() {
    let (_, _, cases) = wycheproof();
    for flag in [
        "InvalidSignature",
        "RangeCheck",
        "ModularInverse",
        "PointDuplication",
        "EdgeCaseShamirMultiplication",
        "ArithmeticError",
        "SpecialCaseHash",
        "EdgeCasePublicKey",
        "SignatureSize",
    ] {
        let n = cases
            .iter()
            .filter(|c| c.flags.iter().any(|f| f == flag))
            .count();
        assert!(n > 0, "no case flagged {flag}");
    }
}

fn first_valid() -> Case {
    let (_, _, cases) = wycheproof();
    cases
        .into_iter()
        .find(|c| c.result == "valid" && c.flags.iter().any(|f| f == "ValidSignature"))
        .expect("a plain valid case")
}

/// Exhaustive over one real signature: 512 bits, each flipped, each refused. A
/// verifier that ignores a bit somewhere is one somebody can forge against, and
/// a spot check would not find which bit.
#[test]
fn every_single_bit_of_a_signature_matters() {
    let case = first_valid();
    assert_eq!(p256::verify(&case.key, &case.msg, &case.sig), Ok(()));
    for byte in 0..case.sig.len() {
        for bit in 0..8 {
            let mut broken = case.sig.clone();
            broken[byte] ^= 1 << bit;
            assert!(
                p256::verify(&case.key, &case.msg, &broken).is_err(),
                "flipping bit {bit} of byte {byte} still verified"
            );
        }
    }
}

/// And of the message, which is the half a forger controls.
#[test]
fn every_single_bit_of_the_message_matters() {
    let case = first_valid();
    for byte in 0..case.msg.len() {
        for bit in 0..8 {
            let mut broken = case.msg.clone();
            broken[byte] ^= 1 << bit;
            assert_eq!(
                p256::verify(&case.key, &broken, &case.sig),
                Err(SigError::DoesNotVerify),
                "flipping bit {bit} of message byte {byte} still verified"
            );
        }
    }
}

/// A point that is not on P-256 is refused before any arithmetic, by name. The
/// arithmetic never reads `b`, so a key from another curve would otherwise be
/// computed with as though it belonged here: the invalid-curve attack.
#[test]
fn a_key_off_the_curve_is_refused_by_name() {
    let case = first_valid();
    let mut key = case.key.clone();
    key[64] ^= 1;
    assert_eq!(
        p256::verify(&key, &case.msg, &case.sig),
        Err(SigError::KeyNotOnCurve)
    );
    // The all-zero point is what an absent key decodes to. It is not on the
    // curve, because b is not zero, and it must not be read as infinity either.
    let mut zero = vec![0u8; p256::PUBLIC_KEY_BYTES];
    zero[0] = 0x04;
    assert_eq!(
        p256::verify(&zero, &case.msg, &case.sig),
        Err(SigError::KeyNotOnCurve)
    );
}

/// A coordinate at or above the field prime is not a field element, even when
/// its value reduced would be. Two spellings of one key is one too many.
#[test]
fn a_coordinate_past_the_field_is_refused() {
    let case = first_valid();
    let mut key = case.key.clone();
    // x + p overflows 256 bits for any x on this curve except tiny ones, so the
    // test uses the one spelling that fits: every byte 0xff, which is above p.
    key[1..33].copy_from_slice(&[0xff; 32]);
    assert_eq!(
        p256::verify(&key, &case.msg, &case.sig),
        Err(SigError::KeyNotOnCurve)
    );
}

#[test]
fn encodings_other_than_the_fixed_width_ones_are_named() {
    let case = first_valid();
    let mut compressed = case.key[..33].to_vec();
    compressed[0] = 0x02;
    assert_eq!(
        p256::verify(&compressed, &case.msg, &case.sig),
        Err(SigError::BadKeyEncoding)
    );
    let mut wrong_tag = case.key.clone();
    wrong_tag[0] = 0x06;
    assert_eq!(
        p256::verify(&wrong_tag, &case.msg, &case.sig),
        Err(SigError::BadKeyEncoding)
    );
    assert_eq!(
        p256::verify(&case.key, &case.msg, &case.sig[..63]),
        Err(SigError::BadSignatureEncoding)
    );
    let mut long = case.sig.clone();
    long.push(0);
    assert_eq!(
        p256::verify(&case.key, &case.msg, &long),
        Err(SigError::BadSignatureEncoding)
    );
}

/// `r` and `s` each in `[1, n-1]`. Zero is the classic forgery (CVE-2022-21449
/// accepted `r = s = 0` for every message under every key), and `n` itself is
/// zero spelled differently.
#[test]
fn a_component_of_zero_or_of_n_is_refused_by_name() {
    let case = first_valid();
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let (r, s) = case.sig.split_at(32);
    for (label, bad) in [
        ("r = 0", [[0u8; 32].as_slice(), s].concat()),
        ("s = 0", [r, [0u8; 32].as_slice()].concat()),
        ("r = n", [N.as_slice(), s].concat()),
        ("s = n", [r, N.as_slice()].concat()),
        ("r = s = 0", vec![0u8; 64]),
    ] {
        assert_eq!(
            p256::verify(&case.key, &case.msg, &bad),
            Err(SigError::ComponentOutOfRange),
            "{label}"
        );
    }
}
