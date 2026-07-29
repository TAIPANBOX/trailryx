//! One shard: single-threaded, owns its own journal, talks only by messages.
//!
//! Stage 0 gives it just enough behaviour to make the durability contract
//! testable: append, sync, ack, recover, and exchange a message with a peer.
//! The real journal replaces the body in stage 2; the contract stays.

use crate::record::{self, RECORD_LEN, Recovered};
use trailryx_sim::{Bus, Clock, FileId, Io, IoError, Parts, Rng, ShardId, invariant, trace};

/// Messages between shards. Deliberately tiny: stage 0 only needs to prove the
/// bus works and stays deterministic under faults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Ping { nonce: u64 },
    Pong { nonce: u64 },
}

/// The durability contract, in one sentence:
///
/// > every sequence number reported as acked survives any crash.
///
/// Everything the shard does is arranged so this holds, and the simulator
/// exists to try to break it.
#[derive(Debug)]
pub struct Shard {
    pub id: ShardId,
    file: FileId,
    /// Highest sequence written to the file, durable or not.
    written: u64,
    /// Highest sequence we have promised is durable. Never decreases.
    acked: u64,
    /// Set when a sync failed: we keep writing but stop promising.
    degraded: bool,
    sync_every: u64,
    since_sync: u64,
    pings_sent: u64,
    pongs_seen: u64,
    /// How many times this shard came back from a crash.
    recoveries: u64,

    // A record that started going to disk and has not finished.
    //
    // Without this the writer would start a *new* record after a failed one,
    // leaving orphaned bytes mid-stream. Recovery stops at the first thing that
    // does not verify, so everything after the orphan becomes unreachable, and
    // an acked watermark past it is a lie. The simulator found exactly that on
    // the first hostile run.
    pending_seq: u64,
    pending_buf: [u8; RECORD_LEN],
    pending_done: usize,
}

impl Shard {
    pub fn open<C, R, I, B>(
        id: ShardId,
        sync_every: u64,
        p: &mut Parts<'_, C, R, I, B>,
    ) -> Result<Self, IoError>
    where
        C: Clock,
        R: Rng,
        I: Io,
        B: Bus<Msg>,
    {
        let name = format!("shard-{}.journal", id.0);
        let file = p.io.create(&name)?;
        let mut s = Self {
            id,
            file,
            written: 0,
            acked: 0,
            degraded: false,
            sync_every,
            since_sync: 0,
            pings_sent: 0,
            pongs_seen: 0,
            recoveries: 0,
            pending_seq: 0,
            pending_buf: [0u8; RECORD_LEN],
            pending_done: 0,
        };
        let r = s.recover(p)?;
        trace!(
            p.trace,
            "open",
            "{} file={} recovered={} max_seq={} discarded={}",
            id,
            name,
            r.count,
            r.max_seq,
            r.discarded_bytes
        );
        Ok(s)
    }

    /// Read the journal back and adopt the longest valid prefix.
    pub fn recover<C, R, I, B>(
        &mut self,
        p: &mut Parts<'_, C, R, I, B>,
    ) -> Result<Recovered, IoError>
    where
        C: Clock,
        R: Rng,
        I: Io,
        B: Bus<Msg>,
    {
        let bytes = p.io.read_all(self.file)?;
        let r = record::recover(&bytes);

        invariant!(
            !r.out_of_order,
            "{} journal has a sequence gap: the writer is wrong, not the disk",
            self.id
        );

        // Cut off the tail we just refused to trust. Appending after bytes that
        // do not verify would break the stream for good: every later recovery
        // would stop at the same place, no matter how much was written after.
        if r.discarded_bytes > 0 {
            let good = r.count * RECORD_LEN as u64;
            p.io.truncate(self.file, good)?;
            trace!(
                p.trace,
                "truncate", "{} to={} discarded={}", self.id, good, r.discarded_bytes
            );
        }

        self.written = r.max_seq;
        self.acked = self.acked.min(r.max_seq);
        self.since_sync = 0;
        self.degraded = false;
        self.pending_seq = 0;
        self.pending_done = 0;
        Ok(r)
    }

    /// Push the outstanding record towards the disk. Returns whether it landed
    /// in full.
    ///
    /// Short writes are normal and retried straight away. A refusal (no space)
    /// is not an error to report upwards: the record stays outstanding and the
    /// next tick continues it from exactly where it stopped. What must never
    /// happen is starting a different record while this one is half written.
    fn push_pending<C, R, I, B>(&mut self, p: &mut Parts<'_, C, R, I, B>) -> Result<bool, IoError>
    where
        C: Clock,
        R: Rng,
        I: Io,
        B: Bus<Msg>,
    {
        invariant!(self.pending_seq > 0, "{} has no record to push", self.id);

        let mut stalled = false;
        while self.pending_done < RECORD_LEN && !stalled {
            match p
                .io
                .append(self.file, &self.pending_buf[self.pending_done..])
            {
                // Zero bytes accepted is progress-free, not an error: stop and
                // come back next tick rather than spinning.
                Ok(0) => stalled = true,
                Ok(n) => self.pending_done += n,
                Err(IoError::NoSpace) => {
                    trace!(
                        p.trace,
                        "nospace",
                        "{} seq={} at byte {}",
                        self.id,
                        self.pending_seq,
                        self.pending_done
                    );
                    self.degraded = true;
                    stalled = true;
                }
                Err(e) => return Err(e),
            }
        }

        if self.pending_done < RECORD_LEN {
            return Ok(false);
        }

        self.written = self.pending_seq;
        self.since_sync += 1;
        self.degraded = false;
        trace!(p.trace, "write", "{} seq={}", self.id, self.written);
        self.pending_seq = 0;
        self.pending_done = 0;
        Ok(true)
    }

    /// One unit of work: write a record, sync if due, occasionally ping a peer.
    pub fn tick<C, R, I, B>(
        &mut self,
        peers: &[ShardId],
        p: &mut Parts<'_, C, R, I, B>,
    ) -> Result<(), IoError>
    where
        C: Clock,
        R: Rng,
        I: Io,
        B: Bus<Msg>,
    {
        // Finish what is outstanding before starting anything new.
        if self.pending_seq == 0 {
            let seq = self.written + 1;
            self.pending_seq = seq;
            self.pending_buf = record::encode(seq);
            self.pending_done = 0;
        }
        self.push_pending(p)?;

        if self.since_sync >= self.sync_every {
            match p.io.fsync(self.file) {
                Ok(()) => {
                    let before = self.acked;
                    self.acked = self.written;
                    self.since_sync = 0;
                    self.degraded = false;
                    invariant!(
                        self.acked >= before,
                        "{} acked watermark went backwards: {} -> {}",
                        self.id,
                        before,
                        self.acked
                    );
                    trace!(p.trace, "sync", "{} acked={}", self.id, self.acked);
                }
                Err(e) => {
                    // A failed sync promises nothing. Keep the watermark put.
                    self.degraded = true;
                    trace!(p.trace, "syncfail", "{} err={}", self.id, e);
                }
            }
        }

        if !peers.is_empty() && p.rng.next_u64() % 4 == 0 {
            let idx = (p.rng.next_u64() % peers.len() as u64) as usize;
            let to = peers[idx];
            let nonce = self.written;
            p.bus.send(self.id, to, Msg::Ping { nonce });
            self.pings_sent += 1;
            trace!(p.trace, "ping", "{} -> {} nonce={}", self.id, to, nonce);
        }

        Ok(())
    }

    pub fn on_msg<C, R, I, B>(&mut self, from: ShardId, msg: Msg, p: &mut Parts<'_, C, R, I, B>)
    where
        C: Clock,
        R: Rng,
        I: Io,
        B: Bus<Msg>,
    {
        match msg {
            Msg::Ping { nonce } => {
                p.bus.send(self.id, from, Msg::Pong { nonce });
                trace!(p.trace, "pong", "{} -> {} nonce={}", self.id, from, nonce);
            }
            Msg::Pong { nonce } => {
                self.pongs_seen += 1;
                trace!(
                    p.trace,
                    "pongrx", "{} from={} nonce={}", self.id, from, nonce
                );
            }
        }
    }

    pub fn acked(&self) -> u64 {
        self.acked
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    pub fn degraded(&self) -> bool {
        self.degraded
    }

    pub fn recoveries(&self) -> u64 {
        self.recoveries
    }

    pub fn note_recovery(&mut self) {
        self.recoveries += 1;
    }

    pub fn pongs_seen(&self) -> u64 {
        self.pongs_seen
    }

    /// Bytes this shard believes it has on disk.
    pub fn expected_bytes(&self) -> u64 {
        self.written * RECORD_LEN as u64
    }
}
