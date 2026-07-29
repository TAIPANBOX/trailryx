//! The checks.
//!
//! Each one recomputes something the pack states and compares. Nothing in the
//! pack is believed except the record bytes themselves, and those are believed
//! only in the sense that everything else is derived from them: if they were
//! altered, every root computed from them moves.
//!
//! # What this cannot tell you
//!
//! That the store did not simply invent a consistent history. A pack is
//! internally provable; whether it is the *real* history is what a signature
//! over the store root and an external anchor establish, and the verifier says
//! plainly when it has neither. An auditor who checks a pack and stops there
//! has checked arithmetic, not honesty.
//!
//! # Old algorithms
//!
//! A retired algorithm is reported as **weak** and still verified. Dropping
//! support would mean that the day SHA-384 is retired, every pack issued before
//! that day stops verifying, and evidence that expires is not evidence. The
//! verifier's job is to say what a root was computed with, not to refuse to
//! look.

use crate::merkle::{leaf_hash, root_of};
use crate::pack::{Pack, PackError, Segment};
use crate::record::{Fields, fields, key_for};
use crate::sha384::{Hash, Sha384};

/// How bad a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// The pack verifies and this is worth knowing anyway.
    Note,
    /// It verifies, and something about it is weaker than it should be.
    Weak,
    /// It does not verify.
    Broken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub check: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = match self.level {
            Level::Note => "note",
            Level::Weak => "weak",
            Level::Broken => "BROKEN",
        };
        write!(f, "[{tag}] {}: {}", self.check, self.detail)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub records_checked: u64,
    pub segments_checked: u64,
}

impl Report {
    fn note(&mut self, check: &'static str, detail: impl Into<String>) {
        self.findings.push(Finding {
            level: Level::Note,
            check,
            detail: detail.into(),
        });
    }

    fn weak(&mut self, check: &'static str, detail: impl Into<String>) {
        self.findings.push(Finding {
            level: Level::Weak,
            check,
            detail: detail.into(),
        });
    }

    fn broken(&mut self, check: &'static str, detail: impl Into<String>) {
        self.findings.push(Finding {
            level: Level::Broken,
            check,
            detail: detail.into(),
        });
    }

    /// Whether everything the pack claims about itself holds.
    pub fn verified(&self) -> bool {
        !self.findings.iter().any(|f| f.level == Level::Broken)
    }
}

const CHAIN_DOMAIN: &[u8] = b"trailryx/chain/v1\0";

fn chain_step(prev: &Hash, seq: u64, record_bytes: &[u8]) -> Hash {
    let mut h = Sha384::new();
    h.update(CHAIN_DOMAIN);
    h.update(prev);
    h.update(&seq.to_be_bytes());
    h.update(&(record_bytes.len() as u64).to_be_bytes());
    h.update(record_bytes);
    h.finish()
}

fn entry_leaf(key: &[u8], seq: u64, link: &Hash) -> Hash {
    let mut h = Sha384::new();
    h.update(&[0x00]);
    h.update(&(key.len() as u64).to_be_bytes());
    h.update(key);
    h.update(&seq.to_be_bytes());
    h.update(link);
    h.finish()
}

fn manifest_root(s: &Segment) -> Hash {
    let mut h = Sha384::new();
    h.update(b"trailryx/segment-manifest/v1\0");
    h.update(&s.format_version.to_be_bytes());
    h.update(&s.segment.to_be_bytes());
    h.update(&s.shard.to_be_bytes());
    h.update(&s.records.to_be_bytes());
    h.update(&s.history_root);
    h.update(&s.chain_before);
    h.update(&s.chain_after);
    h.update(&(s.index_roots.len() as u64).to_be_bytes());
    for (name, root) in &s.index_roots {
        h.update(&(name.len() as u64).to_be_bytes());
        h.update(name.as_bytes());
        h.update(root);
    }
    h.update(&s.first_recorded_at.to_be_bytes());
    h.update(&s.last_recorded_at.to_be_bytes());
    h.update(&s.algorithms);
    h.finish()
}

fn shard_leaf(shard: u16, segments: u64, root: &Hash) -> Hash {
    let mut h = Sha384::new();
    h.update(b"trailryx/store-leaf/v1\0");
    h.update(&shard.to_be_bytes());
    h.update(&segments.to_be_bytes());
    h.update(root);
    leaf_hash(&h.finish())
}

fn hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect::<String>()[..16].to_owned()
}

/// Check a pack, top to bottom.
pub fn verify(bytes: &[u8]) -> Result<Report, PackError> {
    let pack = Pack::parse(bytes)?;
    let mut report = Report::default();

    check_algorithms(&pack, &mut report);
    check_signature(&pack, &mut report);

    // Shards, in the order the header declares. The store tree is built over
    // that order, so a pack listing them differently produces a different root
    // and says so.
    if pack.shards.len() != pack.header.shard_count as usize {
        report.broken(
            "shard-count",
            format!(
                "the header says {} shards and the pack carries {}",
                pack.header.shard_count,
                pack.shards.len()
            ),
        );
    }

    for shard in &pack.shards {
        let mut segments: Vec<&Segment> = pack
            .segments
            .iter()
            .filter(|s| s.shard == shard.shard)
            .collect();
        segments.sort_by_key(|s| s.segment);

        if segments.len() != shard.segment_count as usize {
            report.broken(
                "segment-count",
                format!(
                    "shard {} says {} segments and the pack carries {}",
                    shard.shard,
                    shard.segment_count,
                    segments.len()
                ),
            );
        }

        let mut previous_chain_after: Option<Hash> = None;
        let mut manifest_leaves = Vec::with_capacity(segments.len());

        for segment in &segments {
            check_segment(&pack, segment, &mut report);
            report.segments_checked += 1;

            // A shard's segments are one chain. Without this, deleting a whole
            // segment leaves every remaining one internally valid.
            if let Some(previous) = previous_chain_after
                && previous != segment.chain_before
            {
                report.broken(
                    "chain-across-segments",
                    format!(
                        "segment {} starts at {} and the one before it ended at {}",
                        segment.segment,
                        hex(&segment.chain_before),
                        hex(&previous)
                    ),
                );
            }
            previous_chain_after = Some(segment.chain_after);
            manifest_leaves.push(leaf_hash(&manifest_root(segment)));
        }

        let derived = root_of(&manifest_leaves);
        if derived != shard.root {
            report.broken(
                "shard-root",
                format!(
                    "shard {} declares {} and its segments give {}",
                    shard.shard,
                    hex(&shard.root),
                    hex(&derived)
                ),
            );
        }
    }

    let store_leaves: Vec<Hash> = pack
        .shards
        .iter()
        .map(|s| shard_leaf(s.shard, u64::from(s.segment_count), &s.root))
        .collect();
    let derived_store = root_of(&store_leaves);
    if derived_store != pack.header.store_root {
        report.broken(
            "store-root",
            format!(
                "the pack declares {} and its shards give {}",
                hex(&pack.header.store_root),
                hex(&derived_store)
            ),
        );
    }

    // Records the pack carries that no segment claims. A pack is allowed to be
    // a subset of a store; it is not allowed to hold records nothing accounts
    // for, because nothing would then check them.
    for set in &pack.record_sets {
        if !pack
            .segments
            .iter()
            .any(|s| s.shard == set.shard && s.segment == set.segment)
        {
            report.broken(
                "orphan-records",
                format!(
                    "{} records for shard {} segment {}, which the pack does not describe",
                    set.records.len(),
                    set.shard,
                    set.segment
                ),
            );
        }
    }

    Ok(report)
}

fn check_segment(pack: &Pack, segment: &Segment, report: &mut Report) {
    let Some(set) = pack.records_for(segment.shard, segment.segment) else {
        report.broken(
            "records-present",
            format!(
                "segment {} of shard {} has no records in the pack",
                segment.segment, segment.shard
            ),
        );
        return;
    };

    if set.records.len() as u64 != segment.records {
        report.broken(
            "record-count",
            format!(
                "segment {} claims {} records and carries {}",
                segment.segment,
                segment.records,
                set.records.len()
            ),
        );
    }

    // Every record is read from its own bytes. Nothing here comes from a field
    // the pack states beside them.
    let mut parsed: Vec<Fields> = Vec::with_capacity(set.records.len());
    for (i, bytes) in set.records.iter().enumerate() {
        match fields(bytes) {
            Ok(f) => parsed.push(f),
            Err(e) => {
                report.broken(
                    "record-decodes",
                    format!("record {i} of segment {}: {e}", segment.segment),
                );
                return;
            }
        }
    }

    // The chain, rebuilt from chain_before through every record's own bytes.
    let mut link = segment.chain_before;
    let mut links = Vec::with_capacity(parsed.len());
    for (i, (f, bytes)) in parsed.iter().zip(&set.records).enumerate() {
        link = chain_step(&link, f.seq, bytes);
        links.push(link);
        if i > 0 && f.seq <= parsed[i - 1].seq {
            report.broken(
                "sequence-increases",
                format!(
                    "record {i} of segment {} has seq {} after {}",
                    segment.segment,
                    f.seq,
                    parsed[i - 1].seq
                ),
            );
        }
    }
    report.records_checked += parsed.len() as u64;

    if !parsed.is_empty() && link != segment.chain_after {
        report.broken(
            "chain-within-segment",
            format!(
                "segment {} ends at {} and its records give {}",
                segment.segment,
                hex(&segment.chain_after),
                hex(&link)
            ),
        );
    }

    // The leaf is the *hash of* the link, not the link. Both are 48 bytes, so
    // getting it wrong produces a plausible root that never matches, and the
    // prefix is what keeps a link from being usable as an internal node.
    let history_leaves: Vec<Hash> = links.iter().map(|l| leaf_hash(l)).collect();
    let history = root_of(&history_leaves);
    if history != segment.history_root {
        report.broken(
            "history-root",
            format!(
                "segment {} declares {} and its records give {}",
                segment.segment,
                hex(&segment.history_root),
                hex(&history)
            ),
        );
    }

    if !parsed.is_empty() {
        let first = parsed.iter().map(|f| f.recorded_at).min().unwrap_or(0);
        let last = parsed.iter().map(|f| f.recorded_at).max().unwrap_or(0);
        if first != segment.first_recorded_at || last != segment.last_recorded_at {
            // The sealer writes these and the sealer is the party being
            // audited. A segment whose declared span excludes a query is a
            // segment the store may skip when answering it.
            report.broken(
                "time-span",
                format!(
                    "segment {} declares {}..{} and its records span {first}..{last}",
                    segment.segment, segment.first_recorded_at, segment.last_recorded_at
                ),
            );
        }
    }

    for (dimension, declared) in &segment.index_roots {
        check_index(segment, dimension, declared, &parsed, &links, report);
    }
}

/// Rebuild one dimension's index and compare.
///
/// This is the check that discharges an assumption the store makes about
/// itself. Inside the store, an index is sorted because the code that built it
/// sorted it; here the order is rebuilt from the records and then verified to
/// be strictly increasing. A completeness proof means nothing over an index
/// that is not sorted, and until this ran, nothing outside the store had
/// checked that it was.
fn check_index(
    segment: &Segment,
    dimension: &str,
    declared: &Hash,
    parsed: &[Fields],
    links: &[Hash],
    report: &mut Report,
) {
    let mut entries: Vec<(Vec<u8>, u64, Hash)> = Vec::with_capacity(parsed.len());
    for (f, link) in parsed.iter().zip(links) {
        let Some(key) = key_for(dimension, f) else {
            report.weak(
                "index-dimension",
                format!(
                    "segment {} indexes {dimension:?}, which this verifier cannot rebuild, so its root was not checked",
                    segment.segment
                ),
            );
            return;
        };
        entries.push((key, f.seq, *link));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    for pair in entries.windows(2) {
        if (pair[0].0.as_slice(), pair[0].1) >= (pair[1].0.as_slice(), pair[1].1) {
            report.broken(
                "index-strictly-sorted",
                format!(
                    "segment {} has two entries at one position in {dimension}, so no range covering both can be proved",
                    segment.segment
                ),
            );
            return;
        }
    }

    let leaves: Vec<Hash> = entries
        .iter()
        .map(|(key, seq, link)| entry_leaf(key, *seq, link))
        .collect();
    let derived = root_of(&leaves);
    if derived != *declared {
        report.broken(
            "index-root",
            format!(
                "segment {} declares {} for {dimension} and its records give {}",
                segment.segment,
                hex(declared),
                hex(&derived)
            ),
        );
    }
}

fn check_algorithms(pack: &Pack, report: &mut Report) {
    let [hash, signature, kem] = pack.header.algorithms;
    match hash {
        1 => {}
        // Never "unsupported". A pack sealed under an algorithm this verifier
        // has retired must still verify, or evidence has an expiry date.
        other => report.weak(
            "hash-algorithm",
            format!("code {other} is not one this verifier knows; roots were checked as SHA-384"),
        ),
    }
    if signature == 3 {
        report.note(
            "signature-algorithm",
            "SLH-DSA: hash-based, chosen for long-lived anchors",
        );
    }
    if kem != 1 {
        report.weak(
            "kem-algorithm",
            format!("code {kem} is not one this verifier knows"),
        );
    }
    for segment in &pack.segments {
        if segment.algorithms != pack.header.algorithms {
            report.note(
                "mixed-algorithms",
                format!(
                    "segment {} was sealed under different algorithms from the pack header, which is what a migration looks like",
                    segment.segment
                ),
            );
        }
    }
}

fn check_signature(pack: &Pack, report: &mut Report) {
    if pack.header.signature.is_empty() {
        report.weak(
            "root-signature",
            "the store root carries no signature, so this pack proves it is self-consistent and not who published it",
        );
    } else {
        report.note(
            "root-signature",
            format!(
                "{} bytes present, not checked by this version",
                pack.header.signature.len()
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_with_only_notes_verifies() {
        let mut r = Report::default();
        r.note("x", "y");
        r.weak("a", "b");
        assert!(r.verified());
        r.broken("c", "d");
        assert!(!r.verified());
    }

    #[test]
    fn the_chain_step_is_domain_separated() {
        // A link must not be reproducible as a plain hash of the same bytes.
        let a = chain_step(&[0u8; 48], 1, b"body");
        let b = Sha384::digest(b"body");
        assert_ne!(a, b);
    }

    #[test]
    fn an_entry_leaf_binds_the_key_length() {
        // Without the length, keys "ab" + seq and "a" + something can collide,
        // and two different records occupy one index position.
        let x = entry_leaf(b"ab", 1, &[0u8; 48]);
        let y = entry_leaf(b"a", 1, &[0u8; 48]);
        assert_ne!(x, y);
    }
}
