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

    // Correctness only, so the ratio policy does not answer a question this
    // test is not asking. The corpus deliberately includes a run of one byte,
    // which compresses better than two hundred to one and is refused by the
    // shipped bounds on purpose: whether that is the right policy is what
    // `the_ratio_cap_fires_at_the_settings_the_server_actually_ships` and
    // `an_ordinary_body_is_not_mistaken_for_a_bomb` are for.
    let bounds = Bounds {
        max_output: 8 * 1024 * 1024,
        max_ratio: usize::MAX,
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
        ratio_after_output: 64 * 1024,
    };
    assert_eq!(gunzip(&bomb, bounds), Err(InflateError::RatioTooHigh));
}

#[test]
fn the_ratio_cap_fires_at_the_settings_the_server_actually_ships() {
    // The test above proved the check works when handed settings chosen to make
    // it work. An adversarial review measured the shipped ones and found the
    // gate opened at 32 KiB of consumed input while a 16 MiB bomb is 16 KiB, so
    // the cap could not fire on any bomb worth sending. It was decoration with
    // a comment claiming otherwise.
    let Some(bomb) = gzip(&vec![0u8; 16 * 1024 * 1024 - 1], "-9") else {
        println!("skipped: no gzip on PATH");
        return;
    };
    assert!(
        bomb.len() < 32 * 1024,
        "the whole point is that the input is smaller than the old gate: {}",
        bomb.len()
    );
    assert_eq!(
        gunzip(&bomb, Bounds::default()),
        Err(InflateError::RatioTooHigh),
        "the shipped bounds must refuse this, not merely survive it"
    );
}

#[test]
fn an_ordinary_body_is_not_mistaken_for_a_bomb() {
    // The other side of moving the gate. A real payload compresses a few times
    // over, and refusing one with a 413 whose stated reason is false would be a
    // worse bug than the one being fixed.
    let Some(_) = gzip(b"probe", "-6") else {
        println!("skipped: no gzip on PATH");
        return;
    };
    for (name, data) in corpus() {
        for level in ["-1", "-6", "-9"] {
            let compressed = gzip(&data, level).expect("gzip works");
            let ratio = data.len() / compressed.len().max(1);
            if ratio >= Bounds::default().max_ratio {
                continue; // a run of one byte is genuinely a bomb-shaped thing
            }
            assert_eq!(
                gunzip(&compressed, Bounds::default()),
                Ok(data.clone()),
                "{name} at {level} was refused, ratio {ratio}"
            );
        }
    }
}

#[test]
fn a_body_of_nothing_but_block_headers_is_bounded() {
    // Empty blocks produce no output, so neither the output cap nor the ratio
    // cap has anything to measure. A review found 16 MiB of them burning
    // twenty-one seconds of processor time with both caps silent.
    //
    // Built by hand: a stream of non-final empty fixed blocks. Each is three
    // bits of header and seven of end-of-block, so they pack about six to five
    // bytes.
    // Ten bits per block: three of header, seven of end-of-block, which the
    // fixed code spells as seven zero bits.
    let mut bits: Vec<bool> = Vec::new();
    for _ in 0..400_000 {
        bits.extend([false, true, false]);
        bits.extend([false; 7]);
    }
    // A final empty block, so the stream is well formed if anything gets there.
    bits.extend([true, true, false]);
    bits.extend([false; 7]);

    let mut deflate = vec![0u8; bits.len().div_ceil(8)];
    for (at, bit) in bits.iter().enumerate() {
        if *bit {
            deflate[at / 8] |= 1 << (at % 8);
        }
    }

    let mut stream = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff];
    stream.extend_from_slice(&deflate);
    stream.extend_from_slice(&0u32.to_le_bytes()); // the CRC of nothing
    stream.extend_from_slice(&0u32.to_le_bytes()); // and its length

    let started = std::time::Instant::now();
    let outcome = gunzip(&stream, Bounds::default());
    let elapsed = started.elapsed();

    // Either it is refused as too much work, or it decodes to nothing quickly.
    // What must not happen is minutes of processor time on half a megabyte.
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "half a megabyte of block headers took {elapsed:?}"
    );
    match outcome {
        Err(InflateError::TooMuchWork) | Ok(_) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn an_incomplete_huffman_code_is_refused_like_every_other_decoder_refuses_it() {
    // A code whose lengths do not fill the tree has bit patterns that decode to
    // nothing. Every zlib-based decoder refuses one; this accepted them until a
    // review pointed out that a stream the rest of the world rejects produced a
    // body we handed to the store.
    //
    // Checked through the front door, because `Huffman` is private: a dynamic
    // block whose code-length code is under-subscribed.
    let mut stream = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff];
    // A dynamic block header declaring a single one-bit code length, which
    // leaves half the tree unreachable.
    stream.extend_from_slice(&[0x05, 0x00, 0x02, 0x00, 0x00, 0x00]);
    stream.extend_from_slice(&0u32.to_le_bytes());
    stream.extend_from_slice(&0u32.to_le_bytes());
    let outcome = gunzip(&stream, Bounds::default());
    assert!(outcome.is_err(), "{outcome:?}");
}

#[test]
fn the_trailer_must_be_where_the_stream_ended() {
    // The trailer was read from the last eight bytes whatever came before them,
    // which a review caught two ways: bytes hidden between the end of the
    // deflate data and the trailer were ignored, and a legal multi-member stream
    // was refused as a checksum mismatch rather than as what it is.
    let Some(good) = gzip(b"a short body", "-6") else {
        println!("skipped: no gzip on PATH");
        return;
    };
    assert!(gunzip(&good, Bounds::default()).is_ok());

    // Eight bytes of anything, spliced in front of the trailer.
    let mut padded = good[..good.len() - 8].to_vec();
    padded.extend_from_slice(b"smuggled");
    padded.extend_from_slice(&good[good.len() - 8..]);
    assert_eq!(
        gunzip(&padded, Bounds::default()),
        Err(InflateError::TrailerNotWhereTheStreamEnded)
    );

    // Two members concatenated, which `gzip -c a b` produces and which this
    // does not support: named, rather than reported as corruption.
    let mut two = good.clone();
    two.extend_from_slice(&good);
    assert_eq!(
        gunzip(&two, Bounds::default()),
        Err(InflateError::TrailerNotWhereTheStreamEnded)
    );
}

#[test]
fn a_stream_with_optional_headers_still_decodes() {
    // gzip -N stores the original filename, which exercises the FNAME skip.
    // Real collectors do not set it; a proxy in the middle might.
    let Some(_) = gzip(b"probe", "-6") else {
        println!("skipped: no gzip on PATH");
        return;
    };
    let dir = std::env::temp_dir().join(format!("trailryx-gzip-name-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("a-name-worth-storing.bin");
    std::fs::write(&path, b"contents").unwrap();

    let out = Command::new("gzip").args(["-N", "-c"]).arg(&path).output();
    // The file was only ever gzip's input, and this wipe is ABOVE the two early
    // returns so that a machine where gzip cannot store names is not left with a
    // directory either. Nothing wiped this path while it was a constant, which cost
    // one stale directory; with a process id in it, it costs one on every run.
    let _ = std::fs::remove_dir_all(&dir);
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
