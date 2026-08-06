//! One shard's write path, from what a source handed over to a sealed segment.
//!
//! # What a segment's life looks like here
//!
//! A journal file per segment, named for the shard and the segment number, and a
//! manifest file beside it when that segment is sealed. **The manifest write is
//! the commit point**, which is the same rule `trailryx-publish` follows in an
//! object store and it is not a coincidence: a segment is sealed if and only if
//! its manifest is there, so a crash between the two leaves a journal that the
//! next process simply keeps appending to, and never a manifest describing
//! records nobody can read.
//!
//! Rolling to the next segment happens immediately after that write, with
//! [`ChainStart::After`] carrying the head the sealed segment ended on. That is
//! what makes a shard one chain across as many files as it takes: dropping a
//! whole file leaves a pair that no longer meets, rather than leaving every
//! remaining file perfectly valid on its own.
//!
//! # The one thing this process re-promises at startup
//!
//! `Journal::open` recovers what is on the file and sets the acked watermark to
//! zero, deliberately: what a previous process wrote may have been in the page
//! cache when it died, and this process has not made anything durable yet. So a
//! plane that inherits records **syncs once before it promises anything about
//! them**, and only then are they eligible to be sealed. Sealing takes the acked
//! prefix, so without that sync a restart would seal nothing and the records
//! would sit in an open segment for ever.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use trailryx_assemble::Assembler;
use trailryx_contracts::ingest::{Ingest, MetaDraft};
use trailryx_index::SegmentManifest;
use trailryx_journal::journal::{Appended, ChainStart, Journal, JournalError, Recovered};
use trailryx_record::{
    AgentId, Basis, ErrorCode, EventType, Hash, MapperVersion, Record, RunId, SegmentId, Severity,
    ShardIx, TenantId, Timestamp, Untrusted, Verdict,
};
use trailryx_sim::clock::{Clock, SystemClock};
use trailryx_sim::io::StdIo;
use trailryx_sim::rng::SimRng;
use trailryx_store::evidence::{decode_manifest, encode_manifest};
use trailryx_store::seal::{SealOutcome, StoreError, seal_segment};

/// How many times one record is offered to a device that took only part of it.
///
/// A bound rather than a `loop`, because the frame stays outstanding and no other
/// record may start while it does: an unbounded retry here is a store that stops
/// accepting anything and says nothing. On exhaustion the gap is counted, which
/// is what `docs/durability.md` §5 asks for.
const MAX_APPEND_ATTEMPTS: u32 = 1_000;

/// When a segment is sealed, and how often the journal is made durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealPolicy {
    /// Records after which the open segment is sealed.
    pub seal_after_records: u64,
    /// Nanoseconds after the oldest unsealed record, after which the open segment
    /// is sealed however short it is.
    ///
    /// Both bounds exist because either alone is wrong. A busy shard that only
    /// sealed on a timer would put a day of records in one segment; a quiet one
    /// that only sealed on a count would hold its records unsealed for ever, and
    /// an unsealed record is one no proof covers.
    pub seal_after_nanos: u64,
    /// Records after which the journal is synced.
    pub sync_every: u64,
}

impl Default for SealPolicy {
    fn default() -> Self {
        Self {
            seal_after_records: 4_096,
            seal_after_nanos: 60 * 1_000_000_000,
            sync_every: 64,
        }
    }
}

/// What opening a data directory found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The segment this process will write into.
    pub segment: SegmentId,
    /// How many sealed segments the directory already holds.
    pub sealed_segments: u64,
    /// What recovery made of the open segment's journal.
    pub recovered: Recovered,
}

/// What one batch did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Accepted {
    /// Records appended, including the ones the store wrote about itself.
    pub written: u64,
    /// Records the journal had already seen, at this position, and absorbed.
    pub duplicates: u64,
    /// Payload parts this process declined to keep. See [`Plane::accept`].
    pub declined_payload_parts: u64,
}

/// A segment that is now sealed, and the file that says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub segment: SegmentId,
    pub records: u64,
    /// The head the next segment starts from.
    pub chain_after: Hash,
    pub manifest_path: PathBuf,
}

#[derive(Debug)]
pub enum PlaneError {
    Io(String),
    Journal(JournalError),
    Store(StoreError),
    /// A configuration or a directory this process will not work from.
    Refused(String),
    /// A record the device would not take, after every attempt.
    Stalled {
        after: u32,
    },
}

impl std::fmt::Display for PlaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Journal(e) => write!(f, "journal: {e}"),
            Self::Store(e) => write!(f, "store: {e}"),
            Self::Refused(what) => f.write_str(what),
            Self::Stalled { after } => write!(
                f,
                "the device took only part of a record after {after} attempts, \
                 so the record is outstanding and the gap is counted"
            ),
        }
    }
}

impl std::error::Error for PlaneError {}

impl From<JournalError> for PlaneError {
    fn from(e: JournalError) -> Self {
        Self::Journal(e)
    }
}

impl From<StoreError> for PlaneError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// One shard: a journal, an assembler, and a sealing schedule.
#[derive(Debug)]
pub struct Plane {
    dir: PathBuf,
    io: StdIo,
    clock: SystemClock,
    shard: ShardIx,
    tenant: TenantId,
    /// The identity the store speaks under when it writes about itself.
    ///
    /// Parsed once, at startup, so a trust domain that cannot form an agent id
    /// fails when the process starts rather than at three in the morning when
    /// something is finally lost and there is nothing to write it down with.
    own_agent: AgentId,
    policy: SealPolicy,
    journal: Journal,
    segment: SegmentId,
    chain_before: Hash,
    assembler: Assembler<SimRng>,
    sealed_segments: u64,
    /// When the oldest record in the open segment was recorded.
    ///
    /// The clock the time-based half of the policy is measured against, and it is
    /// the record's time rather than the process's: what matters is how long a
    /// record has gone unsealed, not how long this process has been up.
    oldest_unsealed: Option<Timestamp>,
    /// Payload parts declined since the last seal, by the run that lost them.
    ///
    /// Held rather than written at once, so the note lands in the segment that
    /// holds the records it is about. Bounded by the runs in one segment, which is
    /// bounded by the sealing policy, so it cannot grow the way an unbounded map
    /// of every run ever seen would.
    declined_in_segment: BTreeMap<RunId, u64>,
    declined_payload_parts: u64,
}

impl Plane {
    /// Open a data directory, recovering whatever a previous process left.
    ///
    /// `seed` seeds the identity minter. It is a parameter rather than a constant
    /// because a test pins it and a deployment must not: two processes minting
    /// from one seed in the same millisecond would mint one identity twice, and
    /// the journal's deduplication would then drop the second record as a
    /// duplicate. [`seed_from_process`] is what the binary passes.
    pub fn open(
        dir: &Path,
        shard: ShardIx,
        tenant: TenantId,
        trust_domain: &str,
        policy: SealPolicy,
        seed: u64,
    ) -> Result<(Self, Opened), PlaneError> {
        let own_agent = AgentId::parse_strict(format!("agent://{trust_domain}/trailryx.node"))
            .map_err(|e| {
                PlaneError::Refused(format!(
                    "--trust-domain {trust_domain} does not form an agent identifier: {e}"
                ))
            })?;
        let mut io = StdIo::new(dir).map_err(|e| PlaneError::Io(e.to_string()))?;
        let clock = SystemClock::new();

        // The highest manifest names the last segment that was sealed, and the
        // head the next one continues from. A directory with none is a new store.
        let sealed = sealed_manifests(dir, shard)?;
        let (segment, start) = match sealed.last() {
            Some((last, manifest)) => (
                SegmentId(last.0 + 1),
                ChainStart::After(manifest.chain_after),
            ),
            None => (SegmentId(1), ChainStart::First),
        };

        let (mut journal, recovered) = Journal::open(
            shard,
            segment,
            &journal_name(shard, segment),
            policy.sync_every,
            start,
            &mut io,
            &clock,
        )?;
        // See the note at the top of this file: recovery sets the acked watermark
        // to zero, and this is where records inherited from a previous process are
        // re-promised. Without it a restart would seal nothing.
        if recovered.records > 0 {
            journal.sync(&mut io)?;
        }
        let chain_before = journal.genesis_head();
        // A recovered record is unsealed and its age is unknown to this process,
        // so the timer starts now rather than pretending to know when the record
        // arrived. The record-count half of the policy is unaffected, because the
        // journal knows how many it recovered.
        let oldest_unsealed = (recovered.records > 0).then(|| Timestamp(clock.wall_nanos()));

        let plane = Self {
            dir: dir.to_path_buf(),
            io,
            clock,
            shard,
            tenant,
            own_agent,
            policy,
            journal,
            segment,
            chain_before,
            assembler: Assembler::new(shard, SimRng::new(seed)),
            sealed_segments: sealed.len() as u64,
            oldest_unsealed,
            declined_in_segment: BTreeMap::new(),
            declined_payload_parts: 0,
        };
        let opened = Opened {
            segment,
            sealed_segments: sealed.len() as u64,
            recovered,
        };
        Ok((plane, opened))
    }

    /// Take a batch from a source and put it in the journal.
    ///
    /// `adopt_batch` rather than `adopt` per unit, because a batch of spans
    /// arrives children first and resolving in arrival order finds no parent at
    /// all: the assembler's own documentation records that measurement.
    ///
    /// # Payload parts are declined, and the decline is a record
    ///
    /// This process has no key custodian, so it seals no payloads. Dropping them
    /// silently would be the one behaviour `docs/durability.md` §5 names as
    /// making the product dishonest, so the count of what was declined becomes a
    /// `StoreEvent` record **in the run it belongs to**. `run_id` is one of the
    /// five provable dimensions, so a reconstruction of that run finds the note
    /// without a new field, a new index or a format version. The shape is the one
    /// `Assembler::lost_edge_events` already uses for a lost causal edge,
    /// including the count riding in `tokens_in`, and the reason it rides there is
    /// that the record schema is frozen and has no counter of its own.
    ///
    /// The note is written at [`Plane::seal`] rather than here, one per run per
    /// segment, which is both cheaper and more useful: a note per batch doubled
    /// the record count on a stream where every span carries an unmapped
    /// attribute, and a note in the segment that holds the records it is about is
    /// found by anybody reading that segment.
    pub fn accept(&mut self, batch: Vec<Ingest>, now: Timestamp) -> Result<Accepted, PlaneError> {
        let mut out = Accepted::default();
        let assembled = self.assembler.adopt_batch(batch, now);

        for unit in assembled {
            let parts = unit.payload.len() as u64;
            if parts > 0 {
                let run = unit.record.run_id.clone();
                *self.declined_in_segment.entry(run).or_default() += parts;
                self.declined_payload_parts = self.declined_payload_parts.saturating_add(parts);
                out.declined_payload_parts += parts;
            }
            self.append(&unit.record, now, &mut out)?;
        }

        Ok(out)
    }

    /// Everything the store owes about the open segment, as records in it.
    ///
    /// Two kinds, and both exist because a counter in memory cannot reach a
    /// reader. An edge the assembler could not resolve produces no hop at all, so
    /// a reconstruction over those records would report itself complete; a payload
    /// part this process declined leaves a record whose payload reference is
    /// absent, which is indistinguishable from a record that never had one.
    fn flush_notes(&mut self, now: Timestamp) -> Result<Accepted, PlaneError> {
        let mut out = Accepted::default();
        let draft = self.store_draft(now);
        for lost in self.assembler.lost_edge_events(now, &draft) {
            self.append(&lost.record, now, &mut out)?;
        }
        for (run, parts) in std::mem::take(&mut self.declined_in_segment) {
            let mut meta = draft.clone();
            meta.run_id = run;
            meta.tokens_in = Some(u32::try_from(parts).unwrap_or(u32::MAX));
            let note = self.assembler.record(meta, now, Vec::new(), Vec::new());
            // Its own payload is dropped and not counted: the detail is the
            // count, the count is already in the metadata plane, and counting it
            // would produce a note about a note for ever.
            self.append(&note.record, now, &mut out)?;
        }
        Ok(out)
    }

    /// Put one record on the file, continuing it if the device took only part.
    fn append(
        &mut self,
        record: &Record,
        now: Timestamp,
        out: &mut Accepted,
    ) -> Result<(), PlaneError> {
        for attempt in 1..=MAX_APPEND_ATTEMPTS {
            match self.journal.append(record, &mut self.io)? {
                Appended::Written { .. } => {
                    out.written += 1;
                    self.oldest_unsealed.get_or_insert(now);
                    return Ok(());
                }
                Appended::Duplicate { .. } => {
                    out.duplicates += 1;
                    return Ok(());
                }
                // The frame stays outstanding and the next call continues it from
                // exactly where it stopped, which is the journal's contract.
                Appended::Stalled { .. } => {
                    if attempt == MAX_APPEND_ATTEMPTS {
                        self.journal.note_gap();
                        return Err(PlaneError::Stalled { after: attempt });
                    }
                }
                // One owner appends here, so nothing else can be outstanding. If
                // this ever fires, the assumption is wrong and saying so is better
                // than looping until the other record finishes.
                Appended::Busy { pending_seq } => {
                    return Err(PlaneError::Refused(format!(
                        "record {pending_seq} is still going to disk, so this plane has \
                         two writers"
                    )));
                }
            }
        }
        Err(PlaneError::Stalled {
            after: MAX_APPEND_ATTEMPTS,
        })
    }

    /// Make everything written so far durable.
    pub fn sync(&mut self) -> Result<u64, PlaneError> {
        Ok(self.journal.sync(&mut self.io)?)
    }

    /// Whether the schedule says the open segment should be sealed now.
    pub fn seal_due(&self, now: Timestamp) -> bool {
        if self.journal.written() == 0 {
            return false;
        }
        if self.journal.written() >= self.policy.seal_after_records {
            return true;
        }
        match self.oldest_unsealed {
            Some(since) => {
                now.as_nanos().saturating_sub(since.as_nanos()) >= self.policy.seal_after_nanos
            }
            None => false,
        }
    }

    /// Seal the open segment, write its manifest, and roll to the next one.
    ///
    /// The sync is part of sealing rather than something a caller has to
    /// remember: sealing commits to the **acked** prefix, so a seal without a
    /// sync would commit to a shorter segment than the file holds and leave the
    /// remainder in a file nothing appends to again.
    pub fn seal(&mut self, now: Timestamp) -> Result<Option<Sealed>, PlaneError> {
        // What the store owes about this segment goes in before it is closed, so
        // a note lands beside the records it is about rather than in whichever
        // segment happened to be open when somebody noticed.
        self.flush_notes(now)?;
        if self.journal.written() == 0 {
            return Ok(None);
        }
        self.sync()?;
        let sealed = match seal_segment(&self.journal, self.segment, self.shard, &mut self.io)? {
            SealOutcome::Sealed(sealed) => sealed,
            // An idle shard is normal, and an empty segment is not a harmless
            // thing to publish: the core review found a zero-record segment used
            // as a splice point for fabricated records.
            SealOutcome::NothingDurable => return Ok(None),
        };

        let path = self.dir.join(manifest_name(self.shard, self.segment));
        write_committing(&path, &encode_manifest(sealed.manifest()))
            .map_err(|e| PlaneError::Io(format!("{}: {e}", path.display())))?;

        let next = SegmentId(self.segment.0 + 1);
        let (journal, recovered) = Journal::open(
            self.shard,
            next,
            &journal_name(self.shard, next),
            self.policy.sync_every,
            ChainStart::After(sealed.chain_after),
            &mut self.io,
            &self.clock,
        )?;
        if recovered.records != 0 {
            return Err(PlaneError::Refused(format!(
                "{next} already holds {} records, so this shard has two writers",
                recovered.records
            )));
        }

        let _ = now;
        self.journal = journal;
        self.segment = next;
        self.chain_before = sealed.chain_after;
        self.oldest_unsealed = None;
        self.sealed_segments += 1;
        Ok(Some(Sealed {
            segment: sealed.manifest().segment,
            records: sealed.records,
            chain_after: sealed.chain_after,
            manifest_path: path,
        }))
    }

    /// Sync if the journal asks for it, then seal if the schedule says so.
    ///
    /// The whole schedule in one call, so a caller's loop is a sleep and a tick
    /// rather than a policy of its own.
    pub fn tick(&mut self, now: Timestamp) -> Result<Option<Sealed>, PlaneError> {
        if self.journal.sync_due() {
            self.sync()?;
        }
        if self.seal_due(now) {
            self.seal(now)
        } else {
            Ok(None)
        }
    }

    /// The envelope the store speaks about itself in.
    fn store_draft(&self, now: Timestamp) -> MetaDraft {
        MetaDraft {
            // Not the first version of the GenAI mapper: no mapper touched a
            // record the store wrote about itself.
            mapper: MapperVersion::UNMAPPED,
            tenant: self.tenant.clone(),
            agent_id: self.own_agent.clone(),
            // Replaced by every caller with the run the note is about. This value
            // is what a note about no particular run would carry, and nothing
            // writes one today.
            run_id: RunId::parse(format!("node-{}", self.segment.0))
                .unwrap_or_else(|_| RunId::parse("node").expect("a constant run parses")),
            parent_run_id: None,
            on_behalf_of: Vec::new(),
            // The store speaking about itself, so the clock is ours for once and
            // the wrapper is a formality the type system still insists on.
            occurred_at: Untrusted::new(now),
            decided_at: None,
            event_type: EventType::StoreEvent,
            severity: Severity::Warning,
            basis: Basis::default(),
            verdict: Some(Verdict::Failed),
            error: Some(ErrorCode::Internal),
            latency_micros: None,
            tokens_in: None,
            tokens_out: None,
            cost_micros: None,
        }
    }

    pub fn segment(&self) -> SegmentId {
        self.segment
    }

    pub fn acked(&self) -> u64 {
        self.journal.acked()
    }

    pub fn written(&self) -> u64 {
        self.journal.written()
    }

    pub fn gaps(&self) -> u64 {
        self.journal.gaps()
    }

    pub fn sealed_segments(&self) -> u64 {
        self.sealed_segments
    }

    pub fn declined_payload_parts(&self) -> u64 {
        self.declined_payload_parts
    }

    pub fn unresolved_parents(&self) -> u64 {
        self.assembler.unresolved_parents()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn shard(&self) -> ShardIx {
        self.shard
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The head the open segment's chain starts from.
    pub fn chain_before(&self) -> Hash {
        self.chain_before
    }

    /// The store's own clock, which is the only clock a record's `recorded_at`
    /// may come from.
    pub fn now(&self) -> Timestamp {
        Timestamp(self.clock.wall_nanos())
    }
}

/// The journal file for one segment of one shard.
pub fn journal_name(shard: ShardIx, segment: SegmentId) -> String {
    format!("{shard}-{:06}.trlx", segment.0)
}

/// The manifest that says a segment is sealed.
pub fn manifest_name(shard: ShardIx, segment: SegmentId) -> String {
    format!("{shard}-{:06}.mf", segment.0)
}

/// The segment number a manifest file name carries, if it is one of this shard's.
pub fn segment_of(shard: ShardIx, file_name: &str) -> Option<SegmentId> {
    let rest = file_name.strip_prefix(&format!("{shard}-"))?;
    let digits = rest.strip_suffix(".mf")?;
    digits.parse::<u64>().ok().map(SegmentId)
}

/// Every sealed segment of one shard, in order, as the directory records them.
///
/// Public because the reader needs exactly this list and two implementations of
/// "which segments are sealed" would be two answers to one question.
pub fn sealed_manifests(
    dir: &Path,
    shard: ShardIx,
) -> Result<Vec<(SegmentId, SegmentManifest)>, PlaneError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // A directory that does not exist yet holds no sealed segments, which is
        // a fact rather than a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PlaneError::Io(format!("{}: {e}", dir.display()))),
    };

    let mut found: Vec<(SegmentId, SegmentManifest)> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| PlaneError::Io(format!("{}: {e}", dir.display())))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(segment) = segment_of(shard, name) else {
            continue;
        };
        let path = entry.path();
        let bytes =
            std::fs::read(&path).map_err(|e| PlaneError::Io(format!("{}: {e}", path.display())))?;
        let manifest = decode_manifest(&bytes).ok_or_else(|| {
            PlaneError::Refused(format!(
                "{}: this is not a segment manifest",
                path.display()
            ))
        })?;
        // The name says which segment this is and so does the manifest. If they
        // disagree, a file has been moved, and adopting it under the name it now
        // has would put one segment's records under another's number.
        if manifest.segment != segment || manifest.shard != shard {
            return Err(PlaneError::Refused(format!(
                "{}: the manifest inside describes {} of {}",
                path.display(),
                manifest.segment,
                manifest.shard
            )));
        }
        found.push((segment, manifest));
    }
    found.sort_by_key(|(segment, _)| segment.0);
    Ok(found)
}

/// Write a file so that a reader sees all of it or none of it.
///
/// A temporary beside it, flushed, then renamed, then the directory flushed.
/// `rename` within one directory is the atomic step every publication protocol
/// here rests on, and it is the local spelling of the conditional write the
/// object-store path uses. Without it a crash mid-write leaves a half manifest,
/// which reads as a corrupt segment rather than as an unsealed one.
fn write_committing(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("mf.part");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent()
        && let Ok(handle) = std::fs::File::open(dir)
    {
        // Best effort, and stated as such: without it the rename is durable on
        // every filesystem this has been run on and guaranteed by none of them.
        let _ = handle.sync_all();
    }
    Ok(())
}

/// A seed no two processes on one machine share.
///
/// The identity minter's low bits come from here. Two planes minting from one
/// seed in the same millisecond would mint one identity twice, and the journal
/// would absorb the second record as a duplicate: silent loss, from the one
/// field that must not collide. Not a cryptographic source and it does not need
/// to be: `trailryx_sim::Rng` documents itself as unfit for keys, and a record
/// identity is not a key.
pub fn seed_from_process() -> u64 {
    let pid = u64::from(std::process::id());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos.rotate_left(17) ^ pid.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}
