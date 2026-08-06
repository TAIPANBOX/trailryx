//! RFC 3339 instants, because the envelope carries one and a record needs
//! nanoseconds.
//!
//! # Nothing is repaired
//!
//! A string that is not an instant produces no time, and the line is refused and
//! counted rather than stamped with a plausible one. A timestamp is the field an
//! auditor orders a trail by, and a value invented here would be a value nobody
//! could tell from one an emitter sent.
//!
//! Two consequences of that rule are worth stating because they look like
//! omissions:
//!
//! - **A leap second is refused.** RFC 3339 permits `:60` and no arithmetic here
//!   can hold it: the epoch count has no room for it, so it would have to become
//!   `:59` or the following second, and both are a time the producer did not
//!   send.
//! - **A year before 1970 is refused**, because a record's timestamp is unsigned.
//!
//! The civil arithmetic is Howard Hinnant's `days_from_civil`, which is the same
//! conversion `trailryx-s3`, `trailryx-azure`, `trailryx-asn1` and the SQL
//! dialect already carry. Four copies of one algorithm is three too many and the
//! alternative today is a core crate taking a date API it has no other use for;
//! what keeps them honest is that each one is pinned to a table of known instants.

use trailryx_record::Timestamp;

/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)` to nanoseconds since the epoch.
///
/// The offset forms are accepted rather than refused, because they are legal RFC
/// 3339 and refusing them would lose events from a producer that is doing nothing
/// wrong. `T` and `Z` are accepted in either case, which the grammar allows.
pub fn parse_rfc3339(text: &str) -> Option<Timestamp> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let digits = |from: usize, to: usize| -> Option<i64> {
        let slice = text.get(from..to)?;
        if !slice.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        slice.parse::<i64>().ok()
    };
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || !(bytes[10] == b'T' || bytes[10] == b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }

    let (year, month, day) = (digits(0, 4)?, digits(5, 7)?, digits(8, 10)?);
    let (hour, minute, second) = (digits(11, 13)?, digits(14, 16)?, digits(17, 19)?);
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    // Not `<= 60`: see the note about leap seconds at the top of this file.
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut at = 19;
    let mut nanos_of_second = 0i64;
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if at == start {
            return None;
        }
        // Nine digits or fewer are the fraction; anything past nanosecond
        // precision is truncated rather than rounded, because rounding would
        // move an event, and a producer with more precision than this store has
        // is telling us something we cannot hold either way.
        let taken = (at - start).min(9);
        let mut value = text.get(start..start + taken)?.parse::<i64>().ok()?;
        for _ in taken..9 {
            value *= 10;
        }
        nanos_of_second = value;
    }

    let offset_seconds = match bytes.get(at) {
        Some(b'Z') | Some(b'z') if at + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) if at + 6 == bytes.len() => {
            if bytes[at + 3] != b':' {
                return None;
            }
            let hours = digits(at + 1, at + 3)?;
            let minutes = digits(at + 4, at + 6)?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let magnitude = hours * 3_600 + minutes * 60;
            if *sign == b'+' { magnitude } else { -magnitude }
        }
        _ => return None,
    };

    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)?
        .checked_sub(offset_seconds)?;
    let nanos = seconds
        .checked_mul(1_000_000_000)?
        .checked_add(nanos_of_second)?;
    u64::try_from(nanos).ok().map(Timestamp)
}

/// Howard Hinnant's `days_from_civil`: a civil date to days since 1970-01-01.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned to instants whose epoch seconds are known independently, including
    /// the two the specification's own examples carry, a leap day, and the
    /// century rule both ways.
    #[test]
    fn known_instants_convert_exactly() {
        for (text, seconds, nanos) in [
            ("1970-01-01T00:00:00Z", 0i64, 0i64),
            ("2026-07-09T03:12:44.100Z", 1_783_566_764, 100_000_000),
            ("2026-07-09T03:12:44Z", 1_783_566_764, 0),
            // A leap day, and the year 2000, which the century rule makes a leap
            // year and the four-hundred rule saves.
            ("2024-02-29T12:00:00Z", 1_709_208_000, 0),
            ("2000-02-29T00:00:00Z", 951_782_400, 0),
            ("2100-03-01T00:00:00Z", 4_107_542_400, 0),
            // The same instant, three spellings.
            ("2026-07-09T05:12:44+02:00", 1_783_566_764, 0),
            ("2026-07-09T01:12:44-02:00", 1_783_566_764, 0),
            ("2026-07-09t03:12:44z", 1_783_566_764, 0),
            // Past nanosecond precision, truncated rather than rounded.
            (
                "2026-07-09T03:12:44.1234567891Z",
                1_783_566_764,
                123_456_789,
            ),
        ] {
            let want = Timestamp((seconds * 1_000_000_000 + nanos) as u64);
            assert_eq!(parse_rfc3339(text), Some(want), "{text}");
        }
    }

    #[test]
    fn anything_that_is_not_an_instant_produces_no_time() {
        for text in [
            "",
            "2026-07-09",
            "2026-07-09 03:12:44Z",
            "2026-07-09T03:12:44",
            "2026-07-09T03:12:44+0200",
            "2026-07-09T03:12:44.Z",
            "2026-13-09T03:12:44Z",
            "2026-02-30T03:12:44Z",
            "2025-02-29T03:12:44Z",
            "2026-07-09T24:00:00Z",
            // A leap second, refused rather than moved to another second.
            "2026-06-30T23:59:60Z",
            // Before the epoch, which a record's unsigned timestamp cannot hold.
            "1969-12-31T23:59:59Z",
            "not a time at all",
        ] {
            assert_eq!(parse_rfc3339(text), None, "{text:?} must not parse");
        }
    }
}
