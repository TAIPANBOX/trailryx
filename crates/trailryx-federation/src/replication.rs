//! Verified replication: what a receiver must check before it accepts records
//! a peer sent it.
//!
//! # The gap this closes
//!
//! Federated read composes what peers say and refuses to call the result
//! complete when the peer set is not attested. That is a statement about
//! *coverage*: everyone who should have answered did. It says nothing about
//! whether any one of them told the truth about its own history.
//!
//! Replication is where that matters. Accepting a peer's records into a store
//! means adopting its history, and a registry entry is authorisation, not
//! evidence: it says this peer is allowed to speak, not that what it says
//! links up. Until this module existed, a peer the registry trusted was
//! trusted about its own chain, which is the one number the rest of this
//! system never takes on trust from anybody, including itself (`store::tier`
//! recomputes links rather than reading them back).
//!
//! # What is actually checked
//!
//! Each record carries the chain head *before* it (`prev_hash`) and its
//! position (`seq`). The link is `chain_step(prev, seq, bytes)`. So for two
//! consecutive records the receiver can recompute the sender's arithmetic:
//!
//! ```text
//! r[i+1].prev_hash  ==  chain_step(r[i].prev_hash, r[i].seq, encode(r[i]))
//! ```
//!
//! and every step of a run therefore checks itself, with no state from
//! anywhere else. A record altered, moved, removed or duplicated inside the
//! run breaks the equality at that point and the run is refused from there.
//!
//! # What is NOT checked, and why it has its own function
//!
//! The **first** `prev_hash` in a run is a claim with nothing behind it. It is
//! whatever the sender says its head was, and a receiver holding no prior head
//! for that shard cannot contradict it. A peer that invented an entire history
//! from a fabricated starting point passes an unanchored check, because every
//! link in a fabricated chain is internally consistent: that is what a chain
//! is.
//!
//! So there are two entry points, not one with a flag. [`accept_from`] takes
//! the head the receiver already holds and refuses a run that does not
//! continue it. [`accept_unanchored`] does not, and is named so that choosing
//! the weaker check is a visible act in the calling code rather than a
//! `None` somebody stopped noticing.
//!
//! # The assumption underneath, stated because it is load-bearing
//!
//! The receiver hashes bytes **it produced** by encoding the record it
//! decoded, not bytes the sender sent. It therefore assumes the two encoders
//! agree byte for byte. That is exactly what invariant 7 promises (the record
//! format is frozen; a change is a new version plus a migration) and what
//! `encoding_is_canonical` in `trailryx-journal` tests. It is written down
//! here because if it ever stops holding, this module does not report a
//! disagreement about encoding: it reports a broken chain, and somebody goes
//! looking for an attacker.

use trailryx_crypto::{Hash, chain_step, digests_equal};
use trailryx_journal::wire::encode_record;
use trailryx_record::{Record, ShardIx};

/// Why a run of replicated records was refused.
///
/// Every variant names the sequence number it failed at, because a refusal
/// that says only "broken" leaves the operator diffing two histories by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Nothing to check. Separate from a passing empty result on purpose: a
    /// caller that treats "no records" as "accepted" advances nothing and
    /// should say so out loud.
    Empty,
    /// The run does not continue the head this receiver holds. The peer is
    /// talking about a different history, or about the same one from a
    /// different point.
    NotAContinuation { expected: Hash, claimed: Hash },
    /// A gap or a repeat. `seq` is contiguous by construction on the writing
    /// side, so this is either loss in transit or a sender that is skipping.
    NotContiguous { at_seq: u64, expected: u64 },
    /// The arithmetic does not reproduce. This is the one that means the bytes
    /// are not what produced the chain the sender claims.
    LinkBroken { at_seq: u64 },
    /// One chain per shard. A run that changes shard part way through is two
    /// histories in one stream, and accepting it would interleave them.
    ShardChanged { at_seq: u64, expected: ShardIx },
}

/// What a receiver may write down after a run verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The chain head after the last record, which is what the receiver stores
    /// as the point the next run must continue from.
    pub head: Hash,
    /// How many records the run carried.
    pub records: u64,
    /// The sequence number of the last record, so a caller can record the
    /// position without re-reading the run.
    pub last_seq: u64,
    /// False when the run's first link was taken on the sender's word, which
    /// is the case [`accept_unanchored`] exists for. Present so that a value
    /// crossing a function boundary still carries the weaker claim with it:
    /// the choice is made at the call site and the consequence travels.
    pub anchored: bool,
}

/// Verify a run against the head this receiver already holds for the shard.
///
/// This is the check worth having. The first link is not a claim here: it must
/// equal `head`, so the run has to continue a history the receiver can already
/// account for.
pub fn accept_from(head: Hash, shard: ShardIx, records: &[Record]) -> Result<Accepted, Refusal> {
    let first = records.first().ok_or(Refusal::Empty)?;
    if !digests_equal(&first.prev_hash, &head) {
        return Err(Refusal::NotAContinuation {
            expected: head,
            claimed: first.prev_hash,
        });
    }
    walk(shard, records).map(|mut a| {
        a.anchored = true;
        a
    })
}

/// Verify a run with nothing to anchor its first link to.
///
/// Deliberately not `accept_from(.., None, ..)`. This proves the run is
/// internally consistent and **nothing about where it starts**, so a peer that
/// fabricated a history from an invented head passes. Use it only where the
/// receiver genuinely holds no prior head for the shard, and treat the result
/// as what it is: evidence that the sender did not contradict itself.
pub fn accept_unanchored(shard: ShardIx, records: &[Record]) -> Result<Accepted, Refusal> {
    if records.is_empty() {
        return Err(Refusal::Empty);
    }
    walk(shard, records)
}

/// The part both entry points share: one chain, one shard, contiguous, and the
/// arithmetic reproducing at every step.
///
/// Written once rather than twice because the two entry points differ in
/// exactly one question, which is asked before this is called.
fn walk(shard: ShardIx, records: &[Record]) -> Result<Accepted, Refusal> {
    let mut link = records[0].prev_hash;
    let mut expect_seq = records[0].seq;

    for record in records {
        if record.shard != shard {
            return Err(Refusal::ShardChanged {
                at_seq: record.seq,
                expected: shard,
            });
        }
        if record.seq != expect_seq {
            return Err(Refusal::NotContiguous {
                at_seq: record.seq,
                expected: expect_seq,
            });
        }
        // The record's own claim about where it sits, checked against where
        // the arithmetic has arrived. On the first record these are the same
        // value by construction; from the second onwards this is the check.
        if !digests_equal(&record.prev_hash, &link) {
            return Err(Refusal::LinkBroken { at_seq: record.seq });
        }
        // Bytes produced here, never taken from the wire. See the module note:
        // a link that travelled with the record would be the sender vouching
        // for itself.
        link = chain_step(link, record.seq, &encode_record(record));
        expect_seq += 1;
    }

    Ok(Accepted {
        head: link,
        records: records.len() as u64,
        last_seq: expect_seq - 1,
        anchored: false,
    })
}
