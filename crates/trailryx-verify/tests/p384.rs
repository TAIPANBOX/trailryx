//! The signature check, against signatures we did not make.
//!
//! Everything else about the verifier can be checked by reasoning. This cannot:
//! an ECDSA implementation that agrees with itself is worth nothing, because a
//! single misunderstanding of the specification would be present on both sides
//! of the comparison. So the vectors are produced by OpenSSL, and the test
//! includes as many rejections as acceptances. Accepting a valid signature is
//! the easy half; refusing an invalid one is the half that matters.

use trailryx_verify::p384::verify;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn openssl_signs_and_we_agree_on_every_case() {
    let text = include_str!("p384_vectors.txt");
    let mut valid = 0;
    let mut invalid = 0;

    for (line_no, line) in text.lines().enumerate() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(parts.len(), 4, "line {}", line_no + 1);
        let key = unhex(parts[0]);
        let message = unhex(parts[1]);
        let signature = unhex(parts[2]);
        let expected = parts[3] == "1";

        let got = verify(&key, &message, &signature);
        assert_eq!(
            got.is_ok(),
            expected,
            "line {}: expected {}, got {:?}",
            line_no + 1,
            if expected { "valid" } else { "invalid" },
            got
        );
        if expected {
            valid += 1;
        } else {
            invalid += 1;
        }
    }

    assert!(valid >= 10, "only {valid} valid vectors");
    assert!(
        invalid >= valid,
        "{invalid} rejections against {valid} acceptances: the rejections are the half that matters"
    );
    println!("{valid} accepted, {invalid} refused, all as OpenSSL intended");
}

#[test]
fn every_single_bit_of_a_signature_matters() {
    // Exhaustive over one real signature: 768 bits, each flipped, each of which
    // must be refused. A verifier that ignores a bit somewhere is a verifier
    // somebody can forge against, and a spot check would not find it.
    let text = include_str!("p384_vectors.txt");
    let first = text
        .lines()
        .find(|l| !l.starts_with('#') && l.trim_end().ends_with(" 1"))
        .expect("a valid vector");
    let parts: Vec<&str> = first.split_whitespace().collect();
    let key = unhex(parts[0]);
    let message = unhex(parts[1]);
    let signature = unhex(parts[2]);
    assert!(verify(&key, &message, &signature).is_ok());

    for byte in 0..signature.len() {
        for bit in 0..8 {
            let mut broken = signature.clone();
            broken[byte] ^= 1 << bit;
            assert!(
                verify(&key, &message, &broken).is_err(),
                "byte {byte} bit {bit} was flipped and the signature still verified"
            );
        }
    }
}
