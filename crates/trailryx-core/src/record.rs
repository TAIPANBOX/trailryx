//! A placeholder on-disk record, and the recovery rule that goes with it.
//!
//! This is **not** the Trailryx record model: that arrives in stage 1. What it
//! is, deliberately, is the same *shape*: self-delimiting, checksummed, and
//! recovered by walking forward until the first thing that does not verify.
//!
//! Keeping the shape now means stage 2 replaces the body without touching the
//! simulator or the durability tests built around it.

pub const MAGIC: u8 = 0xA7;
pub const RECORD_LEN: usize = 1 + 8 + 4; // magic + seq + crc

/// CRC-32 (IEEE), bitwise. Not cryptographic, and not meant to be: its job is
/// to spot a torn tail, not to resist an adversary. Integrity against tampering
/// is the hash chain's job, in stage 2.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

pub fn encode(seq: u64) -> [u8; RECORD_LEN] {
    let mut buf = [0u8; RECORD_LEN];
    buf[0] = MAGIC;
    buf[1..9].copy_from_slice(&seq.to_le_bytes());
    let crc = crc32(&buf[0..9]);
    buf[9..13].copy_from_slice(&crc.to_le_bytes());
    buf
}

/// Outcome of walking a journal file from the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Recovered {
    /// Records that verified, in order, with no gap.
    pub count: u64,
    /// Highest sequence number that verified. Zero means nothing usable.
    pub max_seq: u64,
    /// Bytes after the last good record. Non-zero means a torn tail was found
    /// and discarded, which is a normal outcome of a crash, not an error.
    pub discarded_bytes: u64,
    /// A record verified but its sequence broke the expected order. That is
    /// **not** a normal outcome: it means the writer, not the disk, is wrong.
    pub out_of_order: bool,
}

/// Walk the file, accept the longest valid prefix, discard the rest explicitly.
pub fn recover(bytes: &[u8]) -> Recovered {
    let mut out = Recovered::default();
    let mut off = 0usize;

    while off + RECORD_LEN <= bytes.len() {
        let rec = &bytes[off..off + RECORD_LEN];
        if rec[0] != MAGIC {
            break;
        }
        let want = crc32(&rec[0..9]);
        let got = u32::from_le_bytes([rec[9], rec[10], rec[11], rec[12]]);
        if want != got {
            break;
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&rec[1..9]);
        let seq = u64::from_le_bytes(seq_bytes);

        if seq != out.max_seq + 1 {
            out.out_of_order = true;
            break;
        }

        out.count += 1;
        out.max_seq = seq;
        off += RECORD_LEN;
    }

    out.discarded_bytes = (bytes.len() - off) as u64;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal(n: u64) -> Vec<u8> {
        (1..=n).flat_map(encode).collect()
    }

    #[test]
    fn clean_journal_recovers_fully() {
        let r = recover(&journal(10));
        assert_eq!(r.count, 10);
        assert_eq!(r.max_seq, 10);
        assert_eq!(r.discarded_bytes, 0);
        assert!(!r.out_of_order);
    }

    #[test]
    fn torn_tail_is_discarded_not_guessed() {
        let mut j = journal(5);
        j.truncate(j.len() - 4); // cut the last record in half
        let r = recover(&j);
        assert_eq!(r.max_seq, 4);
        assert_eq!(r.discarded_bytes, RECORD_LEN as u64 - 4);
    }

    #[test]
    fn a_flipped_bit_stops_recovery_there() {
        // Corrupt the *second* record, so the first must still be accepted.
        let mut j = journal(5);
        j[RECORD_LEN + 2] ^= 0x01;
        let r = recover(&j);
        assert_eq!(r.max_seq, 1, "the good prefix must survive");
        assert_eq!(r.discarded_bytes, (4 * RECORD_LEN) as u64);
    }

    #[test]
    fn corruption_in_the_first_record_yields_nothing() {
        let mut j = journal(5);
        j[2] ^= 0x01;
        let r = recover(&j);
        assert_eq!(r.max_seq, 0);
        assert_eq!(r.discarded_bytes, (5 * RECORD_LEN) as u64);
    }

    #[test]
    fn empty_file_is_valid_and_empty() {
        let r = recover(&[]);
        assert_eq!(r.count, 0);
        assert_eq!(r.max_seq, 0);
    }

    #[test]
    fn a_gap_in_sequence_is_a_writer_bug_not_a_disk_one() {
        let mut j = encode(1).to_vec();
        j.extend_from_slice(&encode(3)); // 2 is missing
        let r = recover(&j);
        assert_eq!(r.max_seq, 1);
        assert!(r.out_of_order);
    }
}
