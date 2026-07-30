//! The append-only journal.
//!
//! One per shard, and the source of truth for everything above it. Projections,
//! indexes and exports are derived and can be thrown away; this cannot.
//!
//! The durability contract is written out in `docs/durability.md` and enforced
//! here. In one sentence: **every sequence number reported as acked survives any
//! crash**. Nothing else in the system means anything if that is not true.

use crate::wire::{
    self, Frame, WireError, decode_frame, decode_record, decode_segment_header, encode_frame,
    encode_record, encode_segment_header,
};
use std::collections::{BTreeMap, VecDeque};
use trailryx_crypto::{ChainState, Hash};
use trailryx_record::{Record, RecordId, SegmentId, ShardIx, Timestamp};
use trailryx_sim::{Clock, FileId, Io, IoError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    Io(IoError),
    Wire(WireError),
    /// The file exists but is not one of ours, or is a version we do not read.
    NotAJournal(WireError),
    /// The file is a journal, for somebody else.
    WrongOwner {
        file_shard: ShardIx,
        file_segment: SegmentId,
    },
    /// The header did not decode on a file too long to be only a header.
    ///
    /// A crash can leave a torn header, and a torn header means an empty
    /// journal: the crash model keeps a prefix, so bytes after the header
    /// cannot exist if the header never finished landing. A header that fails
    /// to decode on a file with records behind it is therefore something else
    /// entirely, and an adversarial review measured what the old code did with
    /// it: one flipped bit in the twenty-byte header, and recovery truncated
    /// five acked records to nothing and reported an empty, unsuspicious file.
    /// Refusing leaves the bytes for an operator to salvage.
    CorruptHeader {
        why: WireError,
        file_bytes: u64,
    },
    /// The walk stopped, but bytes that still parse as records follow.
    ///
    /// Recovery truncates whatever follows the last good record, which is
    /// correct for a crash and destructive for corruption: a bad checksum in an
    /// early frame would take every valid record after it, and report the
    /// routine `TornTail` while doing so. A decodable frame past the stopping
    /// point is proof this was not a torn tail, so recovery stops instead of
    /// deleting evidence.
    CorruptMidFile {
        at_offset: u64,
        why: StoppedBecause,
        next_good_frame: u64,
    },
}

impl From<IoError> for JournalError {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Wire(e) => write!(f, "wire: {e}"),
            Self::NotAJournal(e) => write!(f, "not a journal: {e}"),
            Self::WrongOwner {
                file_shard,
                file_segment,
            } => write!(f, "journal belongs to {file_shard} {file_segment}"),
            Self::CorruptHeader { why, file_bytes } => write!(
                f,
                "header of a {file_bytes}-byte journal did not decode ({why}), \
                 so the file has records behind a header a crash cannot explain"
            ),
            Self::CorruptMidFile {
                at_offset,
                why,
                next_good_frame,
            } => write!(
                f,
                "journal stopped at byte {at_offset} ({why:?}) but a frame at \
                 byte {next_good_frame} still parses, so this is corruption \
                 rather than a torn tail"
            ),
        }
    }
}

impl std::error::Error for JournalError {}

pub type JournalResult<T> = Result<T, JournalError>;

/// What happened to one append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Appended {
    /// Fully on the file. Not durable yet: that needs a sync.
    Written { seq: u64, link: Hash },
    /// Seen before, at this position. The store is idempotent on record id, so
    /// at-least-once sources are safe to point at it.
    Duplicate { seq: u64 },
    /// A different record is still going to disk. This one was **not** taken:
    /// finish the outstanding one first, or count a gap.
    ///
    /// The first version silently ignored the argument in this case and
    /// returned `Written` for the *previous* record, so a caller was told its
    /// record had landed when the record had been dropped and nothing counted
    /// it. `docs/durability.md` §5 calls silent loss the one behaviour that
    /// would make the product dishonest.
    Busy { pending_seq: u64 },
    /// The device would not take it all. The record stays outstanding and the
    /// next call continues it from where it stopped; no new record starts
    /// meanwhile, because orphaned bytes mid-stream would cut the journal in
    /// two at the next recovery.
    Stalled { written_bytes: usize },
}

/// Why recovery stopped where it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoppedBecause {
    /// The file ended cleanly on a record boundary.
    EndOfFile,
    /// A frame was cut short. The ordinary shape of a crash.
    TornTail(WireError),
    /// A frame parsed but its chain link did not follow. Not a disk problem:
    /// something rewrote history, or the writer is wrong.
    ChainBroken { at_seq: u64 },
    /// A record inside the file belongs to a different shard or segment than
    /// the header says. One file cannot be two journals.
    WrongOwner { at_seq: u64 },
}

/// Acked data that did not come back. Not our bug when the disk lied, but never
/// something to discover from a silently lowered watermark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurabilityViolation {
    pub promised: u64,
    pub recovered: u64,
}

/// The result of walking a journal file once.
///
/// One walk, used by recovery and by reading alike. Two implementations of
/// "read the journal" is two sets of rules about what counts as valid, and the
/// weaker one becomes the foundation of whatever is built next: the first
/// version's `read_all` checked the chain link but not the sequence or the
/// previous head, and returned a silent prefix when it stopped.
#[derive(Debug)]
pub struct Walked {
    /// Each record with the chain link that covers it.
    ///
    /// The pair, not the record alone: this is exactly what sealing a segment
    /// consumes, and the link is what a segment's history commits to. Handing
    /// back bare records would put the caller in the position of inventing a
    /// leaf, which is how the first version of sealing ended up committing to
    /// sequence numbers.
    pub records: Vec<(Record, Hash)>,
    pub chain: ChainState,
    pub good_bytes: u64,
    pub stopped_because: StoppedBecause,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    pub records: u64,
    pub max_seq: u64,
    pub head: Hash,
    pub good_bytes: u64,
    pub discarded_bytes: u64,
    pub stopped_because: StoppedBecause,
    /// Set when less came back than had been promised durable.
    pub durability_violation: Option<DurabilityViolation>,
}

impl Recovered {
    /// A torn tail is expected after a crash. A broken chain is not, and
    /// neither is losing something that was promised durable. The difference
    /// decides whether this is a routine restart or an incident.
    pub fn is_suspicious(&self) -> bool {
        matches!(self.stopped_because, StoppedBecause::ChainBroken { .. })
            || self.durability_violation.is_some()
    }
}

/// Bounded memory of record ids already accepted.
///
/// Bounded on purpose: an unbounded set is a slow leak that only shows up in
/// the deployments that matter. A source retrying older than the window is a
/// source that is badly misconfigured, and the duplicate then lands in the
/// journal where it is visible rather than silently absorbed.
#[derive(Debug)]
pub struct DedupWindow {
    /// Position each id landed at, so a duplicate can be told where its
    /// original went rather than where the journal happens to be now.
    seen: BTreeMap<RecordId, u64>,
    order: VecDeque<RecordId>,
    capacity: usize,
}

impl DedupWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: BTreeMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    pub fn contains(&self, id: RecordId) -> bool {
        self.seen.contains_key(&id)
    }

    /// Where this id landed, if it is still in the window.
    pub fn position(&self, id: RecordId) -> Option<u64> {
        self.seen.get(&id).copied()
    }

    fn remember(&mut self, id: RecordId, seq: u64) {
        if self.seen.insert(id, seq).is_none() {
            self.order.push_back(id);
            if self.order.len() > self.capacity {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[derive(Debug)]
struct Pending {
    bytes: Vec<u8>,
    done: usize,
    seq: u64,
    link: Hash,
    id: RecordId,
}

/// Where a journal file's hash chain begins.
///
/// An enum because the alternative is a `Hash` parameter whose wrong value,
/// `Hash::ZERO`, compiles and produces a journal that recovers, seals, and fails
/// only in an offline verifier several stages downstream. A shard's segments are
/// one chain, and the only way to say "this is the beginning" without being able
/// to say it by accident is to have a word for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStart {
    /// The first segment of this shard. The chain starts at a genesis derived
    /// from the file's own header, so a file cannot be adopted as a different
    /// shard's or a different segment's.
    First,
    /// A later segment, continuing from the head the previous one ended on.
    ///
    /// The chain starts there literally, which is what makes a shard's segments
    /// one chain rather than a set of independent ones. It also means reopening
    /// this file under a different predecessor fails at the very first record,
    /// so the file cannot be quietly re-pointed either.
    After(Hash),
}

#[derive(Debug)]
pub struct Journal {
    file: FileId,
    shard: ShardIx,
    segment: SegmentId,
    created_at: Timestamp,
    start: ChainStart,
    /// Where this file's chain started. See [`Journal::genesis_head`].
    genesis: Hash,
    chain: ChainState,
    /// Records fully on the file, durable or not.
    written: u64,
    /// Records promised durable. Never decreases while the process lives.
    acked: u64,
    /// Offset just past the last complete record.
    good_bytes: u64,
    since_sync: u64,
    sync_every: u64,
    pending: Option<Pending>,
    dedup: DedupWindow,
    /// Records the store knows it did not keep. Counted, never silent: an audit
    /// trail with an unexplained hole is worse than one that says where it is.
    gaps: u64,
    degraded: bool,
}

impl Journal {
    /// Open or create, and recover whatever is already there.
    pub fn open<I: Io, C: Clock>(
        shard: ShardIx,
        segment: SegmentId,
        name: &str,
        sync_every: u64,
        start: ChainStart,
        io: &mut I,
        clock: &C,
    ) -> JournalResult<(Self, Recovered)> {
        let file = io.create(name)?;

        let mut j = Self {
            file,
            shard,
            segment,
            created_at: Timestamp(clock.wall_nanos()),
            start,
            // Replaced by recovery, which is where the header exists to derive
            // it from. Zero here would be a lie for exactly as long as the next
            // line takes to run, and recovery cannot fail to set it.
            genesis: Hash::ZERO,
            chain: ChainState::genesis(),
            written: 0,
            acked: 0,
            good_bytes: 0,
            since_sync: 0,
            sync_every: sync_every.max(1),
            pending: None,
            dedup: DedupWindow::new(65_536),
            gaps: 0,
            degraded: false,
        };
        let report = j.recover(io)?;
        Ok((j, report))
    }

    /// Make sure the file starts with a segment header, writing one if it does
    /// not. Returns the header length.
    ///
    /// No `fsync` here on purpose. A header that did not survive a crash means
    /// an empty journal, which is exactly what recovery would conclude anyway,
    /// and demanding a successful flush before the store will open turns a
    /// momentarily unhappy disk into a store that refuses to start.
    fn ensure_header<I: Io>(&mut self, io: &mut I) -> JournalResult<usize> {
        let bytes = io.read_all(self.file)?;
        match decode_segment_header(&bytes) {
            Ok(h) => {
                // The file says who it belongs to, and we say who we are. If
                // those disagree the file is not ours to read, let alone to
                // append to: checking each record against the file's own header
                // would have accepted the whole thing, because the file is
                // perfectly consistent with itself.
                if h.shard != self.shard || h.segment != self.segment {
                    return Err(JournalError::WrongOwner {
                        file_shard: h.shard,
                        file_segment: h.segment,
                    });
                }
                return Ok(h.len);
            }
            // A new file. Nothing to protect, everything to initialise.
            Err(_) if bytes.is_empty() => {}
            // Ours but torn: start the segment clean. Only when the file is
            // short enough that the header is all it could hold, because the
            // truncation below is unconditional and a crash cannot produce a
            // bad header with records behind it. Without the length test, one
            // flipped bit in the header deleted the whole journal and recovery
            // reported it empty and unremarkable.
            Err(WireError::Truncated) | Err(WireError::BadCrc)
                if bytes.len() <= wire::MAX_SEGMENT_HEADER_LEN => {}
            Err(e @ (WireError::Truncated | WireError::BadCrc)) => {
                return Err(JournalError::CorruptHeader {
                    why: e,
                    file_bytes: bytes.len() as u64,
                });
            }
            // Not ours, or a version we do not read. Truncating here would
            // destroy somebody else's file because a path was mistyped, or
            // destroy our own because a newer build wrote it. Refuse instead:
            // this is the case `NotAJournal` was added for and never wired to.
            Err(e) => return Err(JournalError::NotAJournal(e)),
        }

        io.truncate(self.file, 0)?;
        let header = encode_segment_header(self.shard, self.segment, self.created_at);
        let mut done = 0usize;
        let mut attempts = 0u32;
        while done < header.len() {
            attempts += 1;
            if attempts > 10_000 {
                return Err(JournalError::Io(IoError::NoSpace));
            }
            match io.append(self.file, &header[done..]) {
                Ok(n) => done += n,
                // Both are backpressure, not failure: try again.
                Err(IoError::NoSpace) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(header.len())
    }

    /// Walk a journal file once, applying every rule in `docs/durability.md`
    /// §3: the frame parses and its checksum matches, the record decodes, the
    /// sequence follows, the previous head matches, the chain link recomputes,
    /// and the record belongs to this shard and segment.
    fn walk(bytes: &[u8], header: &wire::SegmentHeader, genesis: Hash) -> Walked {
        let mut chain = ChainState::resume(genesis, 0);
        let mut off = header.len;
        let mut records = Vec::new();
        let mut stopped = StoppedBecause::EndOfFile;

        while off < bytes.len() {
            let frame: Frame<'_> = match decode_frame(&bytes[off..]) {
                Ok(f) => f,
                Err(e) => {
                    stopped = StoppedBecause::TornTail(e);
                    break;
                }
            };
            let rec = match decode_record(frame.body) {
                Ok(r) => r,
                Err(e) => {
                    stopped = StoppedBecause::TornTail(e);
                    break;
                }
            };

            let expect_seq = chain.length() + 1;
            if rec.shard != header.shard || rec.segment_id != header.segment {
                stopped = StoppedBecause::WrongOwner { at_seq: expect_seq };
                break;
            }

            let prev = chain.head();
            if rec.seq != expect_seq
                || rec.prev_hash != prev
                || !ChainState::verify_step(prev, rec.seq, frame.body, frame.chain_link)
            {
                stopped = StoppedBecause::ChainBroken { at_seq: expect_seq };
                break;
            }

            chain.append(frame.body);
            records.push((rec, frame.chain_link));
            off += frame.total_len;
        }

        Walked {
            records,
            chain,
            good_bytes: off as u64,
            stopped_because: stopped,
        }
    }

    /// The first offset at or after `from` where a whole frame parses.
    ///
    /// The discriminator between a crash and corruption. A crash keeps a prefix
    /// of what was written, so the bytes after the last good record are at worst
    /// an unfinished frame and nothing complete can follow them. Anything that
    /// does parse was written deliberately, whether by us before something
    /// mangled an earlier frame or by somebody editing the file.
    ///
    /// The frame's CRC does the work; the record decode after it is belt and
    /// braces, because a stray `FRAME_MAGIC` inside a record body is common and
    /// a stray byte sequence that also satisfies a CRC32 is not.
    fn next_parsable_frame(bytes: &[u8], from: usize) -> Option<usize> {
        let mut at = from;
        while at < bytes.len() {
            if bytes[at] == wire::FRAME_MAGIC {
                if let Ok(frame) = decode_frame(&bytes[at..]) {
                    if decode_record(frame.body).is_ok() {
                        return Some(at);
                    }
                }
            }
            at += 1;
        }
        None
    }

    /// Where this file's chain started.
    ///
    /// Kept so a caller sealing the first segment of a file can ask rather than
    /// guess. Guessing produces a segment whose declared chain does not match
    /// its own records, and the only thing that notices is the offline verifier,
    /// at the far end of a pipeline.
    pub fn genesis_head(&self) -> Hash {
        self.genesis
    }

    /// Where the **first** segment of a shard starts.
    ///
    /// The header rather than zero, so a file opened under a different shard or
    /// segment produces a different chain from its first link and cannot be
    /// quietly adopted as another journal. A continuing segment does not use
    /// this: it starts at its predecessor's head, and the header equality check
    /// in `ensure_header` is what keeps its identity honest.
    fn genesis(header_bytes: &[u8]) -> Hash {
        let mut h = trailryx_crypto::Sha384::new();
        trailryx_crypto::Digest::update(&mut h, b"trailryx/segment-genesis/v1\0");
        trailryx_crypto::Digest::update(&mut h, header_bytes);
        trailryx_crypto::Digest::finish(h)
    }

    /// Read the file back, adopt the longest prefix that verifies, and cut off
    /// whatever follows.
    ///
    /// Truncation is not optional. Appending after bytes that failed to verify
    /// would break the journal permanently: every later recovery would stop at
    /// the same offset while the writer kept believing it was making progress.
    pub fn recover<I: Io>(&mut self, io: &mut I) -> JournalResult<Recovered> {
        let header_len = self.ensure_header(io)?;
        let bytes = io.read_all(self.file)?;
        let header = decode_segment_header(&bytes).map_err(JournalError::NotAJournal)?;
        // A continuing segment starts where the previous one ended, which is
        // what makes a shard's segments one chain. The first segment of a shard
        // has no predecessor, so it starts at a genesis derived from its own
        // header: not zero, so a file cannot be adopted as a different shard's.
        let genesis = match self.start {
            ChainStart::First => Self::genesis(&bytes[..header_len]),
            ChainStart::After(head) => head,
        };
        self.genesis = genesis;

        let walked = Self::walk(&bytes, &header, genesis);
        let discarded = bytes.len() as u64 - walked.good_bytes;

        // Truncation is how a crash is repaired, and the only justification for
        // it is that nothing of value follows. A frame that still parses past
        // the stopping point says the opposite: this is corruption, or somebody
        // rewrote a frame in the middle, and the records after it are evidence.
        // The old code deleted them and called it `TornTail`.
        if discarded > 0 {
            if let Some(at) = Self::next_parsable_frame(&bytes, walked.good_bytes as usize) {
                return Err(JournalError::CorruptMidFile {
                    at_offset: walked.good_bytes,
                    why: walked.stopped_because,
                    next_good_frame: at as u64,
                });
            }
            io.truncate(self.file, walked.good_bytes)?;
        }

        for (rec, _) in &walked.records {
            self.dedup.remember(rec.id, rec.seq);
        }

        let promised = self.acked;
        let recovered = walked.chain.length();
        let violation = (recovered < promised).then_some(DurabilityViolation {
            promised,
            recovered,
        });

        self.chain = walked.chain;
        self.written = recovered;
        self.acked = self.acked.min(recovered);
        self.since_sync = 0;
        self.pending = None;
        self.degraded = false;
        // The field means "offset just past the last complete record", and it
        // only ever counted frames this instance appended: it omitted the header
        // on a fresh file and stayed at zero across a restart, so a caller using
        // it for size-based rollover would never roll. `Walked::good_bytes` is
        // the true offset and already includes the header.
        self.good_bytes = walked.good_bytes;

        Ok(Recovered {
            records: walked.records.len() as u64,
            max_seq: recovered,
            head: self.chain.head(),
            good_bytes: walked.good_bytes,
            discarded_bytes: discarded,
            stopped_because: walked.stopped_because,
            durability_violation: violation,
        })
    }

    /// Stamp a record with its position in the chain and put it on the file.
    ///
    /// The caller's `seq`, `prev_hash` and `segment_id` are overwritten: the
    /// journal owns them, because they are what the chain is made of.
    pub fn append<I: Io>(&mut self, record: &Record, io: &mut I) -> JournalResult<Appended> {
        // A record already going to disk must finish before any other starts,
        // and the caller has to be told which one it is talking about.
        if let Some(p) = self.pending.as_ref() {
            if p.id != record.id {
                return Ok(Appended::Busy { pending_seq: p.seq });
            }
        } else {
            if let Some(seq) = self.dedup.position(record.id) {
                return Ok(Appended::Duplicate { seq });
            }

            let seq = self.written + 1;
            let mut stamped = record.clone();
            stamped.seq = seq;
            stamped.prev_hash = self.chain.head();
            stamped.segment_id = self.segment;
            stamped.shard = self.shard;

            let body = encode_record(&stamped);
            let link = trailryx_crypto::chain_step(self.chain.head(), seq, &body);
            let frame = encode_frame(&body, &link);

            self.pending = Some(Pending {
                bytes: frame,
                done: 0,
                seq,
                link,
                id: record.id,
            });
        }

        self.push_pending(io)
    }

    fn push_pending<I: Io>(&mut self, io: &mut I) -> JournalResult<Appended> {
        let Some(p) = self.pending.as_mut() else {
            return Ok(Appended::Stalled { written_bytes: 0 });
        };

        let mut stalled = false;
        while p.done < p.bytes.len() && !stalled {
            match io.append(self.file, &p.bytes[p.done..]) {
                // No progress this round. Come back rather than spin.
                Ok(0) => stalled = true,
                Ok(n) => p.done += n,
                Err(IoError::NoSpace) => {
                    self.degraded = true;
                    stalled = true;
                }
                Err(e) => return Err(e.into()),
            }
        }

        if p.done < p.bytes.len() {
            return Ok(Appended::Stalled {
                written_bytes: p.done,
            });
        }

        let p = self.pending.take().expect("checked above");
        let body_len = p.bytes.len();
        self.chain = ChainState::resume(p.link, p.seq);
        self.written = p.seq;
        self.good_bytes += body_len as u64;
        self.since_sync += 1;
        self.degraded = false;
        self.dedup.remember(p.id, p.seq);

        Ok(Appended::Written {
            seq: p.seq,
            link: p.link,
        })
    }

    /// Whether a sync is due under the configured policy.
    pub fn sync_due(&self) -> bool {
        self.since_sync >= self.sync_every
    }

    /// Make everything written so far durable and move the acked watermark.
    ///
    /// A failed sync promises nothing: the watermark stays exactly where it was.
    /// That is the whole discipline, and it is one line.
    pub fn sync<I: Io>(&mut self, io: &mut I) -> JournalResult<u64> {
        match io.fsync(self.file) {
            Ok(()) => {
                self.acked = self.written;
                self.since_sync = 0;
                self.degraded = false;
                Ok(self.acked)
            }
            Err(e) => {
                self.degraded = true;
                Err(e.into())
            }
        }
    }

    /// Record that something was lost. Counted rather than swallowed.
    pub fn note_gap(&mut self) {
        self.gaps += 1;
    }

    pub fn acked(&self) -> u64 {
        self.acked
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    pub fn head(&self) -> Hash {
        self.chain.head()
    }

    pub fn gaps(&self) -> u64 {
        self.gaps
    }

    pub fn degraded(&self) -> bool {
        self.degraded
    }

    pub fn shard(&self) -> ShardIx {
        self.shard
    }

    /// Offset just past the last complete record, header included.
    ///
    /// The same number [`Recovered::good_bytes`] reports, so a caller sizing a
    /// segment for rollover measures the file rather than its own appends.
    pub fn good_bytes(&self) -> u64 {
        self.good_bytes
    }

    pub fn dedup_len(&self) -> usize {
        self.dedup.len()
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Read every record back, applying exactly the rules recovery applies.
    ///
    /// Returns why it stopped alongside what it found, so a caller cannot
    /// mistake a truncated prefix for the whole journal.
    pub fn read_all<I: Io>(&self, io: &mut I) -> JournalResult<Walked> {
        let bytes = io.read_all(self.file)?;
        let header = decode_segment_header(&bytes).map_err(JournalError::NotAJournal)?;
        // The head this file's chain actually began at, not a fresh derivation
        // from the header. Recomputing it here was correct while every file
        // started at its own genesis and became wrong the moment a segment could
        // continue the one before it: a continuing file would walk from the wrong
        // start and report its own first record as a broken chain.
        Ok(Self::walk(&bytes, &header, self.genesis))
    }
}

/// Bytes a frame adds around a record body, for size accounting in tests.
pub fn frame_overhead(body_len: usize) -> usize {
    encode_frame(&vec![0u8; body_len], &Hash::ZERO).len() - body_len
}

pub use wire::FORMAT_VERSION;
