//! Our inflate against the system's gzip.
//!
//! A decompressor tested only against streams it produced itself proves
//! nothing, and this one produces none: it cannot compress. So the streams come
//! from `gzip`, which has been in use for thirty years, and the test asserts we
//! recover exactly what went in.
//!
//! Where gzip is missing the test says it skipped. A check that quietly passes
//! when it did not run is the thing this project exists against.

use std::io::Write;
use std::process::{Command, Stdio};
use trailryx_ingest::inflate::{Bounds, InflateError, gunzip};

/// Compress with the system tool, or `None` if there is not one.
fn gzip(data: &[u8], level: &str) -> Option<Vec<u8>> {
    let mut child = Command::new("gzip")
        .arg(level)
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(data).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status.success().then_some(out.stdout)
}

fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("one byte", vec![b'x']),
        ("a run", vec![b'a'; 100_000]),
        (
            "incompressible",
            // A linear congruential sequence: no runs, no repeats a
            // back-reference can use, so this exercises literals and stored
            // blocks rather than matches.
            (0..200_000u32)
                .scan(12345u32, |s, _| {
                    *s = s.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    Some((*s >> 16) as u8)
                })
                .collect(),
        ),
        (
            "protobuf-ish",
            (0..50_000)
                .flat_map(|i| [0x0a, 0x04, (i % 251) as u8, 0x00, 0x01, 0x02])
                .collect(),
        ),
        ("long distance matches", {
            let mut v: Vec<u8> = (0..40_000).map(|i| (i % 97) as u8).collect();
            let head = v.clone();
            v.extend_from_slice(&head);
            v
        }),
    ]
}

#[test]
fn everything_gzip_produces_comes_back_exactly() {
    let Some(_) = gzip(b"probe", "-6") else {
        println!("skipped: no gzip on PATH to produce streams with");
        return;
    };

    let bounds = Bounds {
        max_output: 8 * 1024 * 1024,
        ..Bounds::default()
    };
    let mut checked = 0;
    for (name, data) in corpus() {
        // Every level, because they select different block types: -1 leans on
        // stored and fixed blocks, -9 on dynamic ones.
        for level in ["-1", "-6", "-9"] {
            let compressed = gzip(&data, level).expect("gzip works, it worked a moment ago");
            let out = gunzip(&compressed, bounds).unwrap_or_else(|e| {
                panic!(
                    "{name} at {level}: {e} ({} compressed bytes)",
                    compressed.len()
                )
            });
            assert_eq!(out, data, "{name} at {level}");
            checked += 1;
        }
    }
    assert_eq!(checked, corpus().len() * 3);
}

#[test]
fn a_small_body_cannot_become_a_large_one() {
    // The bomb. A megabyte of zeroes compresses to about a kilobyte, and the
    // cap has to stop the decode rather than measure the damage afterwards.
    let Some(bomb) = gzip(&vec![0u8; 4 * 1024 * 1024], "-9") else {
        println!("skipped: no gzip on PATH");
        return;
    };
    assert!(
        bomb.len() < 32 * 1024,
        "the bomb should be small: {}",
        bomb.len()
    );

    let bounds = Bounds {
        max_output: 64 * 1024,
        ..Bounds::default()
    };
    assert_eq!(gunzip(&bomb, bounds), Err(InflateError::OutputTooLarge));
}

#[test]
fn a_stream_that_lies_about_itself_is_refused() {
    let Some(good) = gzip(b"the quick brown fox jumps over the lazy dog", "-6") else {
        println!("skipped: no gzip on PATH");
        return;
    };
    assert!(gunzip(&good, Bounds::default()).is_ok());

    // A corrupted checksum. The data still inflates, and it is not the data
    // that was sent.
    let mut bad_crc = good.clone();
    let at = bad_crc.len() - 8;
    bad_crc[at] ^= 1;
    assert_eq!(
        gunzip(&bad_crc, Bounds::default()),
        Err(InflateError::ChecksumMismatch)
    );

    // A corrupted length.
    let mut bad_len = good.clone();
    let at = bad_len.len() - 4;
    bad_len[at] ^= 1;
    assert!(matches!(
        gunzip(&bad_len, Bounds::default()),
        Err(InflateError::LengthMismatch) | Err(InflateError::ChecksumMismatch)
    ));

    // Truncated at every point. None of them may panic and none may return
    // bytes, because a partial body handed onward is half a batch written on
    // somebody else's cue.
    for n in 0..good.len() {
        let result = gunzip(&good[..n], Bounds::default());
        assert!(result.is_err(), "a {n}-byte prefix decoded");
    }
}

#[test]
fn a_ratio_no_real_payload_reaches_is_refused_even_under_the_cap() {
    // The absolute cap alone still lets a few kilobytes buy the whole limit,
    // over and over, across connections. The ratio is what makes the
    // attacker's cost proportional to ours.
    let Some(bomb) = gzip(&vec![0u8; 8 * 1024 * 1024], "-9") else {
        println!("skipped: no gzip on PATH");
        return;
    };
    let bounds = Bounds {
        max_output: 64 * 1024 * 1024,
        max_ratio: 50,
        ratio_after_input: 1024,
    };
    assert_eq!(gunzip(&bomb, bounds), Err(InflateError::RatioTooHigh));
}

#[test]
fn a_stream_with_optional_headers_still_decodes() {
    // gzip -N stores the original filename, which exercises the FNAME skip.
    // Real collectors do not set it; a proxy in the middle might.
    let Some(_) = gzip(b"probe", "-6") else {
        println!("skipped: no gzip on PATH");
        return;
    };
    let dir = std::env::temp_dir().join("trailryx-gzip-name");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("a-name-worth-storing.bin");
    std::fs::write(&path, b"contents").unwrap();

    let out = Command::new("gzip").args(["-N", "-c"]).arg(&path).output();
    let Ok(out) = out else {
        println!("skipped: gzip cannot store names here");
        return;
    };
    if !out.status.success() {
        println!("skipped: gzip cannot store names here");
        return;
    }
    assert_eq!(gunzip(&out.stdout, Bounds::default()).unwrap(), b"contents");
}
