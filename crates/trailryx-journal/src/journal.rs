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
use std::collections::{BTreeSet, VecDeque};
use trailryx_crypto::{ChainState, Hash};
use trailryx_record::{Record, RecordId, SegmentId, ShardIx, Timestamp};
use trailryx_sim::{Clock, FileId, Io, IoError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    Io(IoError),
    Wire(WireError),
    /// The file exists but is not one of ours, or is a version we do not read.
    NotAJournal(WireError),
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
        }
    }
}

impl std::error::Error for JournalError {}

pub type JournalResult<T> = Result<T, JournalError>;

/// Newtype so the header length cannot be confused with any other offset.
#[derive(Debug, Clone, Copy)]
struct SegmentHeaderLen(usize);

/// What happened to one append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Appended {
    /// Fully on the file. Not durable yet: that needs a sync.
    Written { seq: u64, link: Hash },
    /// Seen before. The store is idempotent on record id, so at-least-once
    /// sources are safe to point at it.
    Duplicate { seq: u64 },
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    pub records: u64,
    pub max_seq: u64,
    pub head: Hash,
    pub good_bytes: u64,
    pub discarded_bytes: u64,
    pub stopped_because: StoppedBecause,
}

impl Recovered {
    /// A torn tail is expected after a crash. A broken chain is not, and the
    /// difference decides whether this is a routine restart or an incident.
    pub fn is_suspicious(&self) -> bool {
        matches!(self.stopped_because, StoppedBecause::ChainBroken { .. })
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
    seen: BTreeSet<RecordId>,
    order: VecDeque<RecordId>,
    capacity: usize,
}

impl DedupWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: BTreeSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    pub fn contains(&self, id: RecordId) -> bool {
        self.seen.contains(&id)
    }

    fn remember(&mut self, id: RecordId) {
        if self.seen.insert(id) {
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

#[derive(Debug)]
pub struct Journal {
    file: FileId,
    shard: ShardIx,
    segment: SegmentId,
    created_at: Timestamp,
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
        io: &mut I,
        clock: &C,
    ) -> JournalResult<(Self, Recovered)> {
        let file = io.create(name)?;

        let mut j = Self {
            file,
            shard,
            segment,
            created_at: Timestamp(clock.wall_nanos()),
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
        if let Ok(h) = decode_segment_header(&bytes) {
            return Ok(h.len);
        }

        // Missing or torn. Start the segment clean rather than appending after
        // bytes nothing can interpret.
        io.truncate(self.file, 0)?;
        let header = encode_segment_header(self.shard, self.created_at);
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

    /// Read the file back, adopt the longest prefix that verifies, and cut off
    /// whatever follows.
    ///
    /// Truncation is not optional. Appending after bytes that failed to verify
    /// would break the journal permanently: every later recovery would stop at
    /// the same offset while the writer kept believing it was making progress.
    pub fn recover<I: Io>(&mut self, io: &mut I) -> JournalResult<Recovered> {
        let header_len = self.ensure_header(io)?;
        let bytes = io.read_all(self.file)?;
        let header = SegmentHeaderLen(header_len);

        let mut chain = ChainState::genesis();
        let mut off = header.0;
        let mut records = 0u64;
        let mut stopped = StoppedBecause::EndOfFile;
        let mut ids = Vec::new();

        loop {
            if off >= bytes.len() {
                break;
            }
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
            let prev = chain.head();
            if rec.seq != expect_seq
                || rec.prev_hash != prev
                || !ChainState::verify_step(prev, rec.seq, frame.body, frame.chain_link)
            {
                stopped = StoppedBecause::ChainBroken { at_seq: expect_seq };
                break;
            }

            chain.append(frame.body);
            records += 1;
            ids.push(rec.id);
            off += frame.total_len;
        }

        let good_bytes = off as u64;
        let discarded = bytes.len() as u64 - good_bytes;

        if discarded > 0 {
            io.truncate(self.file, good_bytes)?;
        }

        for id in ids {
            self.dedup.remember(id);
        }

        self.chain = chain;
        self.written = self.chain.length();
        self.acked = self.acked.min(self.written);
        self.good_bytes = good_bytes;
        self.since_sync = 0;
        self.pending = None;
        self.degraded = false;

        Ok(Recovered {
            records,
            max_seq: self.chain.length(),
            head: self.chain.head(),
            good_bytes,
            discarded_bytes: discarded,
            stopped_because: stopped,
        })
    }

    /// Stamp a record with its position in the chain and put it on the file.
    ///
    /// The caller's `seq`, `prev_hash` and `segment_id` are overwritten: the
    /// journal owns them, because they are what the chain is made of.
    pub fn append<I: Io>(&mut self, record: &Record, io: &mut I) -> JournalResult<Appended> {
        if self.pending.is_none() {
            if self.dedup.contains(record.id) {
                return Ok(Appended::Duplicate { seq: self.written });
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
        self.dedup.remember(p.id);

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

    pub fn good_bytes(&self) -> u64 {
        self.good_bytes
    }

    pub fn dedup_len(&self) -> usize {
        self.dedup.len()
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Read every record back, verifying the chain as it goes.
    pub fn read_all<I: Io>(&self, io: &mut I) -> JournalResult<Vec<Record>> {
        let bytes = io.read_all(self.file)?;
        let Ok(header) = decode_segment_header(&bytes) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let mut chain = ChainState::genesis();
        let mut off = header.len;

        while off < bytes.len() {
            let Ok(frame) = decode_frame(&bytes[off..]) else {
                break;
            };
            let Ok(rec) = decode_record(frame.body) else {
                break;
            };
            if !ChainState::verify_step(chain.head(), rec.seq, frame.body, frame.chain_link) {
                break;
            }
            chain.append(frame.body);
            out.push(rec);
            off += frame.total_len;
        }
        Ok(out)
    }
}

/// Bytes a frame adds around a record body, for size accounting in tests.
pub fn frame_overhead(body_len: usize) -> usize {
    encode_frame(&vec![0u8; body_len], &Hash::ZERO).len() - body_len
}

pub use wire::FORMAT_VERSION;
