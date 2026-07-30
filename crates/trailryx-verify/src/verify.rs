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
use crate::pack::{AnchorKind, Pack, PackError, Segment};
use crate::record::{Fields, fields, key_for};
use crate::sha384::{HASH_BYTES, Hash, Sha384};

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

/// A string the pack supplied, rendered so it cannot pretend to be a finding.
///
/// `main` prints one finding per line, and witness names and algorithm names are
/// arbitrary UTF-8 chosen by the party being audited. A name containing newlines
/// therefore wrote extra lines into the auditor's report, in the exact shape of
/// the real ones: an unsigned, unwitnessed pack was made to print
/// `[note] root-signature: es384 by key ...` and
/// `[note] witness: kpmg.example saw this root at ...`, and still exit zero.
///
/// The key id is derived from the key precisely so a pack cannot label a key with
/// somebody else's identifier. That defence is sound and was being defeated one
/// layer later, in the channel that carries it to the reader.
///
/// So: quoted, escaped, and bounded. Escaped rather than refused, because a
/// verifier should not withhold a verdict on evidence over a bad label.
fn quoted(s: &str) -> String {
    const MAX: usize = 64;
    let mut out = String::with_capacity(MAX + 8);
    out.push('"');
    for (n, c) in s.chars().enumerate() {
        if n == MAX {
            out.push('\u{2026}');
            break;
        }
        for e in c.escape_debug() {
            out.push(e);
        }
    }
    out.push('"');
    out
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

    // Every (shard, segment) the walk below actually checked, so the record sets
    // can be held to the ones that were reached rather than the ones that exist.
    let mut visited: Vec<(u16, u64)> = Vec::new();

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

        // Contiguous from one, or a whole segment is missing from an end where
        // the pairwise chain check cannot see it. Dropping the middle of a shard
        // breaks a pair; dropping the oldest or the newest does not, and the
        // numbering is the only thing left that notices.
        //
        // A pack is a complete snapshot of the shards it lists, not a slice of
        // one: the store root is recomputed from everything present, so a
        // subset would not verify against it anyway.
        for (at, segment) in segments.iter().enumerate() {
            let expected = at as u64 + 1;
            if segment.segment != expected {
                report.broken(
                    "segment-numbering",
                    format!(
                        "shard {} jumps to segment {} where {} was expected, so a segment is missing",
                        shard.shard, segment.segment, expected
                    ),
                );
                break;
            }
        }

        // What this cannot check, said rather than left to be assumed. The first
        // segment of a shard begins at a head derived from its journal file's own
        // header, and the header is not in the pack, so its starting point is
        // taken on the pack's word. Every later segment's start is checked
        // against the one before it.
        if let Some(first) = segments.first() {
            if first.chain_before == [0u8; HASH_BYTES] {
                report.broken(
                    "first-segment-start",
                    format!(
                        "shard {} begins at a zero chain head, which no journal produces",
                        shard.shard
                    ),
                );
            } else {
                report.note(
                    "first-segment-start",
                    format!(
                        "shard {} begins at {}, which this pack asserts and does not prove: the \
                         journal header it derives from is not carried here",
                        shard.shard,
                        hex(&first.chain_before)
                    ),
                );
            }
        }

        let mut previous_chain_after: Option<Hash> = None;
        let mut manifest_leaves = Vec::with_capacity(segments.len());

        for segment in &segments {
            check_segment(&pack, segment, &mut report);
            report.segments_checked += 1;
            visited.push((segment.shard, segment.segment));

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

    // Nothing in the pack may go unread.
    //
    // Verification is a top-down walk from `pack.shards`, and for one release
    // that was the whole traversal: a segment naming a shard the header did not
    // list was reached by nothing, so `check_segment` never ran on it, and the
    // records hanging off it were never parsed, chained, counted or mentioned.
    // Appending two sections to a signed pack put a whole fabricated shard
    // inside it and the report was byte-identical to the untouched pack's,
    // signature and all, because the signature covers the store root and the
    // store root is derived from `pack.shards` alone.
    //
    // The check that was here tested only that *some* segment named the same
    // (shard, segment) as a record set. That is the letter of the invariant its
    // own comment states and not the substance: a segment that is itself
    // unaccounted for accounts for nothing. So the traversal has to be
    // complete in both directions, and `Pack`'s fields are public, which means a
    // consumer enumerating a VERIFIED pack must find nothing in it that no check
    // touched.
    for segment in &pack.segments {
        if !pack.shards.iter().any(|sh| sh.shard == segment.shard) {
            report.broken(
                "orphan-segment",
                format!(
                    "segment {} claims shard {}, which the pack does not list, so nothing checked it",
                    segment.segment, segment.shard
                ),
            );
        }
    }

    // Records the pack carries that no *checked* segment claims. A pack is
    // allowed to be a subset of a store; it is not allowed to hold records
    // nothing accounts for, because nothing would then check them.
    for set in &pack.record_sets {
        if !visited.contains(&(set.shard, set.segment)) {
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
        // Contiguous from one, not merely increasing.
        //
        // One segment is one journal file and a journal numbers each file from
        // one, so the whole sequence is known in advance and every number in it
        // has to be present. Checking only that it increased left a gap
        // undetectable: drop the seq-2 record from a three-record segment,
        // recompute the roots, and the report was identical to the honest pack's
        // apart from a smaller count. Nothing said the sequence jumped.
        //
        // This does tie the verifier to how the writer numbers records. That is
        // deliberate and the alternative is worse: a completeness claim that
        // cannot see a hole in the middle of the thing it is counting.
        let expected = i as u64 + 1;
        if f.seq != expected {
            report.broken(
                "sequence-contiguous",
                format!(
                    "segment {} has seq {} at position {i} where {expected} was expected, so a record is missing",
                    segment.segment, f.seq
                ),
            );
        }
    }
    report.records_checked += parsed.len() as u64;

    // Unconditionally, including for a segment with no records. `link` starts at
    // `chain_before`, so an empty segment is required to declare
    // `chain_after == chain_before`, which is exactly what sealing an empty
    // segment produces.
    //
    // The `!parsed.is_empty()` guard that used to be here made every segment slot
    // a free splice point. Replace a segment's manifest with an empty one that
    // keeps its original `chain_after`, carry zero records for it, and recompute
    // the roots: the records vanish from the middle of a shard,
    // `chain-across-segments` sees the same head on both sides and is satisfied,
    // history_root and every index root collapse to the empty root, and the
    // verifier printed a clean bill. It is the precise evasion of the test that
    // catches a *shortened* segment, which relies on `chain_after` moving.
    if link != segment.chain_after {
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

    // The sealer writes these and the sealer is the party being audited. A
    // segment whose declared span excludes a query is a segment the store may
    // skip when answering it, so an empty segment must not be allowed to declare
    // a span either: that would let it claim a window it holds nothing for.
    let (first, last) = if parsed.is_empty() {
        (0, 0)
    } else {
        (
            parsed.iter().map(|f| f.recorded_at).min().unwrap_or(0),
            parsed.iter().map(|f| f.recorded_at).max().unwrap_or(0),
        )
    };
    if first != segment.first_recorded_at || last != segment.last_recorded_at {
        report.broken(
            "time-span",
            format!(
                "segment {} declares {}..{} and its records span {first}..{last}",
                segment.segment, segment.first_recorded_at, segment.last_recorded_at
            ),
        );
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

/// Who published this root, and when did anybody else see it.
///
/// Two separate questions with two separate answers, and neither substitutes
/// for the other. A signature says whose history this is. It says nothing about
/// when the history was written, because the publisher chooses the timestamp
/// they sign: a store can be reconstructed today, signed today and dated last
/// year, and the signature will verify perfectly.
///
/// Only somebody independent saying they saw the root rules that out.
fn check_signature(pack: &Pack, report: &mut Report) {
    let Some(signature) = &pack.signature else {
        report.weak(
            "root-signature",
            "no signature, so this pack proves it is self-consistent and not who published it",
        );
        check_witnesses(pack, None, report);
        return;
    };

    let statement = root_statement(
        &pack.header.tenant,
        &pack.header.store_root,
        pack.header.shard_count,
        pack.header.generated_at,
        &signature.algorithm,
        &signature.public_key,
    );

    match check_one(&signature.algorithm, &signature.public_key, &statement, &signature.signature) {
        Checked::Good => report.note(
            "root-signature",
            format!(
                "{} by key {}",
                quoted(&signature.algorithm),
                hex(&key_id(&signature.public_key))
            ),
        ),
        Checked::Bad(why) => report.broken(
            "root-signature",
            format!("the signature over this root does not verify: {why}"),
        ),
        Checked::Unknown => report.weak(
            "root-signature",
            format!(
                "signed with {}, which this verifier cannot check, so the root is unattributed here",
                quoted(&signature.algorithm)
            ),
        ),
    }

    check_witnesses(pack, Some(key_id(&signature.public_key)), report);
}

/// `publisher` is the key that signed the root, when there was one and it was a
/// key this build can read. A witness under that key is the publisher attesting
/// to their own root, which is not independence and not evidence.
fn check_witnesses(pack: &Pack, publisher: Option<Hash>, report: &mut Report) {
    let anchored = check_anchors(pack, report);
    // Counted rather than assumed from a non-empty list. A witness whose
    // algorithm this build cannot check, or whose key is the publisher's own,
    // used to silence the finding below simply by being present, so the pack
    // read as witnessed when nothing independent had attested to anything.
    let mut independent = 0usize;
    let mut seen_keys: Vec<Hash> = Vec::new();
    for witness in &pack.witnesses {
        let id = key_id(&witness.public_key);
        let statement = witness_statement(
            &witness.witness,
            &pack.header.store_root,
            witness.seen_at,
            &witness.algorithm,
            &witness.public_key,
        );

        match check_one(
            &witness.algorithm,
            &witness.public_key,
            &statement,
            &witness.signature,
        ) {
            Checked::Good => {
                let is_publisher = publisher == Some(id);
                let is_repeat = seen_keys.contains(&id);
                if !is_publisher && !is_repeat {
                    independent += 1;
                }
                report.note(
                    "witness",
                    format!(
                        "{} saw this root at {}, key {}",
                        quoted(&witness.witness),
                        witness.seen_at,
                        hex(&id)
                    ),
                );
            }
            Checked::Bad(why) => report.broken(
                "witness",
                format!(
                    "{} attests to this root and the attestation does not verify: {why}",
                    quoted(&witness.witness)
                ),
            ),
            Checked::Unknown => report.weak(
                "witness",
                format!(
                    "{} attests with {}, which this verifier cannot check",
                    quoted(&witness.witness),
                    quoted(&witness.algorithm)
                ),
            ),
        }

        if publisher == Some(id) {
            // The whole value of a witness is that somebody else saw the root.
            // The verifier printed the same key id twice, on two `note` lines,
            // and said nothing.
            report.weak(
                "witness-independence",
                format!(
                    "{} attests under key {}, which is the publisher's own, so nothing independent \
                     attests to this root",
                    quoted(&witness.witness),
                    hex(&id)
                ),
            );
        }

        if witness.seen_at < pack.header.generated_at {
            // Not a failure. Independent parties have independent clocks and
            // turning skew into a verification error would be wrong. But a
            // witness cannot see a root before it exists, so one of the two
            // clocks is wrong and somebody should know which.
            report.weak(
                "witness-clock",
                format!(
                    "{} claims to have seen this root before it was generated, so a clock disagrees",
                    quoted(&witness.witness)
                ),
            );
        }

        if seen_keys.contains(&id) {
            report.weak(
                "witness-independence",
                format!(
                    "two attestations under key {}, which is one witness signing twice",
                    hex(&id)
                ),
            );
        }
        seen_keys.push(id);
    }

    if independent == 0 && anchored == 0 {
        report.weak(
            "witnesses",
            "nothing independent says when this root existed, so nothing here rules out a history \
             written later and dated earlier",
        );
    }
}

/// Timestamp tokens: does each one commit to this pack's root?
///
/// Returns how many did. That count is what stops the finding above from saying
/// "nothing independent says when this root existed" when a token from an
/// authority is sitting in the pack.
///
/// # What is checked here and what is not
///
/// The binding is checked: the token's imprint against a hash computed from the
/// root this pack carries. The authority's **signature is not**, because that
/// needs CMS, RSA and a certificate chain, and this verifier being readable in an
/// hour is the answer to "who checked your code".
///
/// So every anchor produces a `weak` finding as well as its result, naming the
/// command that completes the check. A verifier that reported an anchor as good
/// when it had not verified the signature would be making exactly the kind of
/// claim this whole crate exists to avoid.
fn check_anchors(pack: &Pack, report: &mut Report) -> usize {
    let mut bound = 0usize;
    for anchor in &pack.anchors {
        let where_ = quoted(&anchor.authority);

        // An anchor over a root that is not this pack's root says nothing about
        // this pack, however valid it is. Checked before the token is read, so a
        // token for somebody else's history cannot even be reported on.
        if anchor.root != pack.header.store_root {
            report.broken(
                "anchor",
                format!(
                    "the token from {where_} is over a different root than this pack's, so it \
                     attests to another history"
                ),
            );
            continue;
        }

        // A kind this build does not read is reported as unread, never as broken.
        // A pack anchored by something newer must not be condemned by an older
        // verifier, which is the same rule as for a signature algorithm.
        if anchor.kind != AnchorKind::Tsp {
            report.weak(
                "anchor",
                format!(
                    "{where_} anchored this root by {}, which this build does not read, so \
                     nothing here confirms or denies it",
                    anchor.kind.name()
                ),
            );
            continue;
        }

        let stamped = match crate::tsp::read(&anchor.evidence) {
            Ok(stamped) => stamped,
            Err(why) => {
                report.broken(
                    "anchor",
                    format!("the token from {where_} is not a readable timestamp token: {why}"),
                );
                continue;
            }
        };

        if !stamped.covers(&anchor.root) {
            // The store said this token was about this root and the token says
            // otherwise. This is the case a verifier exists for: a pack cannot be
            // allowed to describe its own evidence.
            report.broken(
                "anchor",
                format!(
                    "the token from {where_} stamps a different digest than this root, so the \
                     pack's own description of it is false"
                ),
            );
            continue;
        }

        // The token's own nonce against the challenge the store recorded. This is
        // what makes the pack's account of the exchange checkable rather than
        // merely stated: without it a replayed response for the same root is
        // indistinguishable from a fresh one, and a root does not change between
        // retries.
        match (anchor.nonce(), stamped.nonce) {
            (Some(sent), Some(echoed)) if sent == echoed => {}
            (Some(_), Some(_)) => {
                report.broken(
                    "anchor",
                    format!(
                        "the token from {where_} echoes a different nonce than the challenge this \
                         pack records, so it is not an answer to the request the pack describes"
                    ),
                );
                continue;
            }
            _ => {
                // Not broken: RFC 3161 makes the nonce optional, and an older
                // pack may not have recorded the challenge. But an anchor whose
                // freshness cannot be checked does not rule out a replay, and
                // saying nothing here would let it read as though it did.
                report.weak(
                    "anchor-freshness",
                    format!(
                        "the token from {where_} carries no nonce this pack can match, so nothing \
                         here rules out a replay of an older response for the same root"
                    ),
                );
            }
        }

        bound += 1;
        report.note(
            "anchor",
            format!(
                "{where_} stamped this root at {} (seconds since the epoch), {} by {} bytes of \
                 evidence",
                stamped.at,
                anchor.kind.name(),
                anchor.evidence.len()
            ),
        );
        report.weak(
            "anchor-signature",
            format!(
                "this verifier checked that {where_}'s token is over this root and did not check \
                 the authority's signature; verify it with `openssl ts -verify` against their \
                 published certificate",
            ),
        );

        // An authority cannot stamp a root before the root exists. Not a failure:
        // two independent clocks disagree by construction, and turning skew into a
        // verification error would be wrong. But somebody should know which clock
        // is wrong, and by how much.
        let generated_at_seconds = (pack.header.generated_at / 1_000_000_000) as i64;
        if stamped.at < generated_at_seconds {
            report.weak(
                "anchor-clock",
                format!(
                    "{where_} stamped this root {} seconds before the pack says it was generated, \
                     so a clock disagrees",
                    generated_at_seconds - stamped.at
                ),
            );
        }
    }
    bound
}

enum Checked {
    Good,
    Bad(&'static str),
    /// An algorithm this build cannot check. Never a failure: a pack sealed
    /// under something newer must not be reported as broken by an older
    /// verifier, only as unchecked.
    Unknown,
}

fn check_one(algorithm: &str, public_key: &[u8], statement: &[u8], signature: &[u8]) -> Checked {
    match algorithm {
        "es384" => match crate::p384::verify(public_key, statement, signature) {
            Ok(()) => Checked::Good,
            Err(e) => Checked::Bad(match e {
                crate::p384::SigError::BadKeyEncoding => {
                    "the key is not an uncompressed P-384 point"
                }
                crate::p384::SigError::KeyNotOnCurve => "the key is not on the curve",
                crate::p384::SigError::BadSignatureEncoding => "the signature is the wrong size",
                crate::p384::SigError::ComponentOutOfRange => "r or s is out of range",
                crate::p384::SigError::DoesNotVerify => "the arithmetic does not come out",
            }),
        },
        _ => Checked::Unknown,
    }
}

/// A key's identity, derived from the key itself.
///
/// Recomputed rather than read from the pack, so a key cannot be presented
/// under a name an auditor recognises while being somebody else's key.
fn key_id(public_key: &[u8]) -> Hash {
    let mut h = Sha384::new();
    h.update(b"trailryx/key-id/v1\0");
    h.update(public_key);
    h.finish()
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The bytes a publisher signs, rebuilt here from the pack.
///
/// Written out again rather than shared with the store, for the reason the
/// whole crate exists: the format is what the two sides have in common, not the
/// code. A shared function would make a mistake in it invisible.
fn root_statement(
    tenant: &str,
    store_root: &Hash,
    shards: u32,
    generated_at: u64,
    algorithm: &str,
    public_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"trailryx/signed-root/v1\0");
    field(&mut out, tenant.as_bytes());
    field(&mut out, store_root);
    out.extend_from_slice(&shards.to_be_bytes());
    out.extend_from_slice(&generated_at.to_be_bytes());
    field(&mut out, algorithm.as_bytes());
    field(&mut out, public_key);
    out
}

fn witness_statement(
    witness: &str,
    store_root: &Hash,
    seen_at: u64,
    algorithm: &str,
    public_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"trailryx/witness/v1\0");
    field(&mut out, witness.as_bytes());
    field(&mut out, store_root);
    out.extend_from_slice(&seen_at.to_be_bytes());
    field(&mut out, algorithm.as_bytes());
    field(&mut out, public_key);
    out
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
