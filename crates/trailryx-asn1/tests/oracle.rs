//! The reader and the writer, judged by somebody else's code.
//!
//! A hand-written DER implementation checked only against itself proves that it
//! is self-consistent, which is exactly what a wrong implementation also is.
//! Three outside judges are used here:
//!
//! - **`openssl asn1parse`** reads what this crate writes. If OpenSSL cannot
//!   parse it, or reads a different value out of it, the writer is wrong.
//! - **`python3`'s `datetime`** computes epoch seconds independently. The
//!   civil-date arithmetic in this crate is the part most likely to be off by a
//!   day, and it was: the first version of one unit test had a hand-computed
//!   expectation that was wrong by sixteen days.
//! - **`openssl asn1parse -genconf`** writes what this crate reads, so the
//!   round-trip is checked in both directions rather than one.
//!
//! Every test here prints `skipped` and passes when its tool is absent. A check
//! that silently succeeds because it did not run is worse than no check, so it
//! says which one it was.

use std::process::Command;
use trailryx_asn1::{Der, integer_u64, octet_string, oid, sequence, tag, tlv};

fn have(tool: &str, args: &[&str]) -> bool {
    Command::new(tool)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn skip(what: &str, tool: &str) {
    println!("skipped: {what} needs {tool}, which is not on this machine");
}

/// `openssl asn1parse -inform DER`, with the input on stdin.
fn asn1parse(der: &[u8]) -> Option<String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("openssl")
        .args(["asn1parse", "-inform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.as_mut()?.write_all(der).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

// ---------------------------------------------------------------------------
// OpenSSL reads what we write
// ---------------------------------------------------------------------------

#[test]
fn openssl_parses_what_this_writer_emits() {
    if !have("openssl", &["version"]) {
        return skip("the writer's output being readable by OpenSSL", "openssl");
    }
    // sha384 (2.16.840.1.101.3.4.2.2) wrapped the way an AlgorithmIdentifier is.
    let sha384 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    let encoded = sequence(&[
        integer_u64(1),
        sequence(&[
            sequence(&[oid(&sha384), trailryx_asn1::null()]),
            octet_string(&[0xAB; 48]),
        ]),
        integer_u64(0x1234_5678),
        trailryx_asn1::boolean(true),
    ]);

    let parsed = asn1parse(&encoded).expect("OpenSSL parses our DER");
    for expected in ["SEQUENCE", "INTEGER", "OCTET STRING", "BOOLEAN", "sha384"] {
        assert!(
            parsed.contains(expected),
            "OpenSSL did not see a {expected} in our encoding:\n{parsed}"
        );
    }
    // 0x12345678 read back by somebody else's integer decoder.
    assert!(
        parsed.contains("12345678") || parsed.contains("305419896"),
        "OpenSSL read a different integer than we wrote:\n{parsed}"
    );
}

/// The long-form boundary in both directions. 127 and 128 bytes are where a
/// length encoder changes shape, and 255 and 256 are where it grows a byte.
#[test]
fn openssl_agrees_on_every_length_where_the_encoding_changes_shape() {
    if !have("openssl", &["version"]) {
        return skip("length agreement with OpenSSL", "openssl");
    }
    for size in [
        0usize, 1, 126, 127, 128, 129, 254, 255, 256, 257, 1000, 70_000,
    ] {
        let encoded = octet_string(&vec![0x5A; size]);
        let parsed = asn1parse(&encoded)
            .unwrap_or_else(|| panic!("OpenSSL refused our {size}-byte OCTET STRING"));
        assert!(
            parsed.contains(&format!("l={size:>4}")) || parsed.contains(&format!("l= {size}")),
            "OpenSSL read a different length for {size} bytes:\n{parsed}"
        );
    }
}

// ---------------------------------------------------------------------------
// We read what OpenSSL writes
// ---------------------------------------------------------------------------

/// The other direction. `-genconf` makes OpenSSL the writer, so this checks the
/// reader against an encoder nobody here wrote.
#[test]
fn this_reader_accepts_what_openssl_emits() {
    if !have("openssl", &["version"]) {
        return skip("reading OpenSSL's own DER", "openssl");
    }
    // Per process. The directory name was a constant and the wipe at the end of this
    // test names it by path rather than by ownership, so one run deleted `gen.cnf`
    // and `gen.der` while another run's OpenSSL was reading them. Measured 6 August
    // 2026 at six concurrent runs: 7 of 30 processes failed, in five rounds of five.
    let dir = std::env::temp_dir().join(format!("trailryx-asn1-oracle-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let conf = dir.join("gen.cnf");
    let der = dir.join("gen.der");
    std::fs::write(
        &conf,
        "asn1 = SEQUENCE:body\n\
         [body]\n\
         version = INTEGER:1\n\
         name = FORMAT:ASCII,OCTETSTRING:abcdef\n\
         big = INTEGER:305419896\n\
         flag = BOOLEAN:yes\n\
         when = GENERALIZEDTIME:20260730143000Z\n",
    )
    .expect("the config is writable");

    let generated = Command::new("openssl")
        .args([
            "asn1parse",
            "-genconf",
            conf.to_str().expect("a utf-8 path"),
            "-out",
            der.to_str().expect("a utf-8 path"),
            "-noout",
        ])
        .output();
    let Ok(output) = generated else {
        return skip("reading OpenSSL's own DER", "a working openssl asn1parse");
    };
    if !output.status.success() {
        return skip("reading OpenSSL's own DER", "openssl asn1parse -genconf");
    }
    let bytes = std::fs::read(&der).expect("OpenSSL wrote the file");

    let mut outer = Der::new(&bytes);
    let mut body = outer
        .take_nested(tag::SEQUENCE)
        .expect("OpenSSL wrote a SEQUENCE we can open");
    assert_eq!(body.integer_u64(), Ok(1));
    assert_eq!(body.octet_string(), Ok(&b"abcdef"[..]));
    assert_eq!(body.integer_u64(), Ok(305_419_896));
    assert_eq!(body.boolean(), Ok(true));
    assert_eq!(body.generalized_time(), Ok(1_785_421_800));
    assert_eq!(body.expect_end(), Ok(()));
    assert_eq!(outer.expect_end(), Ok(()));

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Python owns the calendar
// ---------------------------------------------------------------------------

/// Every day of a decade, plus the leap-century cases, against `datetime`.
///
/// This is the test that matters most in the crate: an anchor's entire claim is
/// the instant it names, and a calendar that is one day out on some dates would
/// place a root in the wrong day while parsing cleanly. A sweep rather than a
/// handful of cases, because the wrong ones are never the ones somebody picks.
#[test]
fn python_agrees_on_every_date_in_a_decade_and_on_the_century_leap_rules() {
    if !have("python3", &["-c", "1"]) {
        return skip("calendar agreement", "python3");
    }
    let script = r#"
import sys
from datetime import datetime, timezone, timedelta
out = []
d = datetime(2020, 1, 1, tzinfo=timezone.utc)
end = datetime(2030, 1, 1, tzinfo=timezone.utc)
while d < end:
    out.append("%s %d" % (d.strftime("%Y%m%d%H%M%S"), int(d.timestamp())))
    d += timedelta(days=1)
for y in (1896, 1900, 1904, 2000, 2024, 2100, 2400):
    for spec in ("0228235959", "0301000000"):
        t = datetime.strptime("%d%s" % (y, spec), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        out.append("%s %d" % (t.strftime("%Y%m%d%H%M%S"), int(t.timestamp())))
print("\n".join(out))
"#;
    let out = Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3 runs");
    assert!(out.status.success(), "the oracle script failed");
    let table = String::from_utf8(out.stdout).expect("utf-8");

    let mut checked = 0usize;
    for line in table.lines() {
        let Some((stamp, expected)) = line.split_once(' ') else {
            continue;
        };
        let expected: i64 = expected.parse().expect("an integer from python");
        let encoded = tlv(tag::GENERALIZED_TIME, format!("{stamp}Z").as_bytes());
        assert_eq!(
            Der::new(&encoded).generalized_time(),
            Ok(expected),
            "{stamp}Z: python says {expected}"
        );
        checked += 1;
    }
    assert!(checked > 3650, "only {checked} dates were checked");
}

/// The dates that do not exist. Python refuses them, and so must this.
#[test]
fn python_and_this_reader_refuse_the_same_impossible_dates() {
    if !have("python3", &["-c", "1"]) {
        return skip("agreement on impossible dates", "python3");
    }
    let script = r#"
from datetime import datetime
cases = []
for y in (1900, 2023, 2024, 2100):
    for m in range(1, 14):
        for d in (0, 1, 28, 29, 30, 31, 32):
            cases.append("%04d%02d%02d120000" % (y, m, d))
for s in cases:
    try:
        datetime.strptime(s, "%Y%m%d%H%M%S")
        print("ok %s" % s)
    except ValueError:
        print("bad %s" % s)
"#;
    let out = Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3 runs");
    let table = String::from_utf8(out.stdout).expect("utf-8");

    let mut agreed = 0usize;
    for line in table.lines() {
        let Some((verdict, stamp)) = line.split_once(' ') else {
            continue;
        };
        let encoded = tlv(tag::GENERALIZED_TIME, format!("{stamp}Z").as_bytes());
        let ours = Der::new(&encoded).generalized_time();
        match verdict {
            "ok" => assert!(ours.is_ok(), "{stamp}Z: python accepts it and we do not"),
            "bad" => assert!(
                ours.is_err(),
                "{stamp}Z: python calls this date impossible and we parsed it"
            ),
            _ => continue,
        }
        agreed += 1;
    }
    assert!(agreed > 300, "only {agreed} dates were compared");
}
