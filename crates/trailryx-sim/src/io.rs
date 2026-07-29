//! Storage as a capability, with a crash model.
//!
//! This is where the durability contract lives. The simulated backend keeps two
//! buffers per file:
//!
//! - `durable`: survived an `fsync`, survives a crash;
//! - `dirty`: appended but not yet synced, **may or may not** survive a crash.
//!
//! A crash keeps a random prefix of `dirty`, covering the whole range from
//! "nothing landed" to "everything landed". Code that assumes either extreme
//! fails here rather than in production.
//!
//! The interface is append-only on purpose: that is the shape of the journal,
//! and a trait that cannot overwrite cannot be misused into overwriting.

use crate::rng::{RngExt, SimRng};
use std::collections::BTreeMap;

pub type FileId = u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoError {
    NotFound,
    NoSpace,
    /// The device reported a failure on flush. Data may or may not be durable.
    SyncFailed,
    Other(String),
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::NoSpace => write!(f, "no space"),
            Self::SyncFailed => write!(f, "sync failed"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for IoError {}

pub type IoResult<T> = Result<T, IoError>;

/// Append-only file storage.
pub trait Io {
    fn create(&mut self, name: &str) -> IoResult<FileId>;

    /// Append `data`. Returns how many bytes were accepted, which may be fewer
    /// than requested: a short write is a normal outcome, not an error.
    fn append(&mut self, file: FileId, data: &[u8]) -> IoResult<usize>;

    /// Make everything appended so far durable.
    fn fsync(&mut self, file: FileId) -> IoResult<()>;

    /// Cut the file back to `len` bytes and make the cut durable.
    ///
    /// Every real write-ahead log needs this: after a crash the tail is torn,
    /// and appending after torn bytes would break the stream permanently. It is
    /// the only operation here that removes data, and it exists solely so that
    /// recovery can discard a tail it has already refused to trust.
    fn truncate(&mut self, file: FileId, len: u64) -> IoResult<()>;

    /// Read the whole file as the current process sees it.
    fn read_all(&mut self, file: FileId) -> IoResult<Vec<u8>>;

    /// Bytes visible to this process, durable or not.
    fn size(&self, file: FileId) -> IoResult<u64>;
}

/// Probabilities in parts per million.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IoFaults {
    /// Append accepts only part of the buffer.
    pub short_write_ppm: u32,
    /// `fsync` returns `Ok` without making anything durable. The write hole.
    pub lying_fsync_ppm: u32,
    /// `fsync` returns an error.
    pub fsync_error_ppm: u32,
    /// Append fails with `NoSpace`.
    pub no_space_ppm: u32,
}

impl IoFaults {
    /// Everything off. The happy path.
    pub const NONE: Self = Self {
        short_write_ppm: 0,
        lying_fsync_ppm: 0,
        fsync_error_ppm: 0,
        no_space_ppm: 0,
    };

    /// A deliberately nasty disk.
    pub const HOSTILE: Self = Self {
        short_write_ppm: 120_000,
        lying_fsync_ppm: 40_000,
        fsync_error_ppm: 20_000,
        no_space_ppm: 10_000,
    };
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IoStats {
    pub appends: u64,
    pub short_writes: u64,
    pub fsyncs: u64,
    pub lying_fsyncs: u64,
    pub fsync_errors: u64,
    pub no_space: u64,
    pub crashes: u64,
    pub bytes_lost_to_crash: u64,
}

#[derive(Debug, Clone)]
struct SimFile {
    name: String,
    durable: Vec<u8>,
    dirty: Vec<u8>,
}

/// In-memory storage with a crash model and fault injection.
#[derive(Debug)]
pub struct SimIo {
    files: Vec<SimFile>,
    /// `BTreeMap`, not `HashMap`: hash iteration order is randomised per process
    /// and would leak non-determinism straight into the trace.
    by_name: BTreeMap<String, FileId>,
    rng: SimRng,
    pub faults: IoFaults,
    pub stats: IoStats,
}

impl SimIo {
    pub fn new(seed: u64, faults: IoFaults) -> Self {
        Self {
            files: Vec::new(),
            by_name: BTreeMap::new(),
            rng: SimRng::new(seed),
            faults,
            stats: IoStats::default(),
        }
    }

    /// Simulate a power cut. Durable bytes stay; a random prefix of the
    /// unsynced tail survives, the rest is gone.
    pub fn crash(&mut self) {
        self.stats.crashes += 1;
        let mut lost = 0u64;
        for f in &mut self.files {
            if f.dirty.is_empty() {
                continue;
            }
            let keep = self.rng.below(f.dirty.len() as u64 + 1) as usize;
            lost += (f.dirty.len() - keep) as u64;
            f.durable.extend_from_slice(&f.dirty[..keep]);
            f.dirty.clear();
        }
        self.stats.bytes_lost_to_crash += lost;
    }

    /// Bytes guaranteed to survive a crash right now.
    pub fn durable_len(&self, file: FileId) -> IoResult<u64> {
        self.file(file).map(|f| f.durable.len() as u64)
    }

    pub fn file_names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }

    /// Name of a file, for traces and panic messages.
    pub fn name_of(&self, file: FileId) -> Option<&str> {
        self.file(file).ok().map(|f| f.name.as_str())
    }

    fn file(&self, id: FileId) -> IoResult<&SimFile> {
        self.files.get(id as usize).ok_or(IoError::NotFound)
    }

    fn file_mut(&mut self, id: FileId) -> IoResult<&mut SimFile> {
        self.files.get_mut(id as usize).ok_or(IoError::NotFound)
    }
}

impl Io for SimIo {
    fn create(&mut self, name: &str) -> IoResult<FileId> {
        if let Some(&id) = self.by_name.get(name) {
            return Ok(id);
        }
        let id = u32::try_from(self.files.len()).map_err(|_| IoError::NoSpace)?;
        self.files.push(SimFile {
            name: name.to_owned(),
            durable: Vec::new(),
            dirty: Vec::new(),
        });
        self.by_name.insert(name.to_owned(), id);
        Ok(id)
    }

    fn append(&mut self, file: FileId, data: &[u8]) -> IoResult<usize> {
        let no_space = self.rng.chance_ppm(self.faults.no_space_ppm);
        let short = self.rng.chance_ppm(self.faults.short_write_ppm);
        let cut = if short && data.len() > 1 {
            self.rng.below(data.len() as u64) as usize
        } else {
            data.len()
        };

        if no_space {
            self.stats.no_space += 1;
            return Err(IoError::NoSpace);
        }

        let f = self.file_mut(file)?;
        f.dirty.extend_from_slice(&data[..cut]);

        self.stats.appends += 1;
        if cut < data.len() {
            self.stats.short_writes += 1;
        }
        Ok(cut)
    }

    fn fsync(&mut self, file: FileId) -> IoResult<()> {
        let lying = self.rng.chance_ppm(self.faults.lying_fsync_ppm);
        let failing = self.rng.chance_ppm(self.faults.fsync_error_ppm);

        self.stats.fsyncs += 1;

        if failing {
            self.stats.fsync_errors += 1;
            return Err(IoError::SyncFailed);
        }
        if lying {
            // The dangerous one: success is reported, nothing becomes durable.
            self.stats.lying_fsyncs += 1;
            return Ok(());
        }

        let f = self.file_mut(file)?;
        let dirty = std::mem::take(&mut f.dirty);
        f.durable.extend_from_slice(&dirty);
        Ok(())
    }

    fn truncate(&mut self, file: FileId, len: u64) -> IoResult<()> {
        let f = self.file_mut(file)?;
        let len = usize::try_from(len).map_err(|_| IoError::NoSpace)?;
        if len <= f.durable.len() {
            f.durable.truncate(len);
            f.dirty.clear();
        } else {
            let keep = len - f.durable.len();
            if keep < f.dirty.len() {
                f.dirty.truncate(keep);
            }
        }
        Ok(())
    }

    fn read_all(&mut self, file: FileId) -> IoResult<Vec<u8>> {
        let f = self.file(file)?;
        let mut out = Vec::with_capacity(f.durable.len() + f.dirty.len());
        out.extend_from_slice(&f.durable);
        out.extend_from_slice(&f.dirty);
        Ok(out)
    }

    fn size(&self, file: FileId) -> IoResult<u64> {
        self.file(file)
            .map(|f| (f.durable.len() + f.dirty.len()) as u64)
    }
}

/// Real filesystem backend. Not used by the simulator; it exists so the trait
/// is proven against a real implementation from day one.
#[derive(Debug)]
pub struct StdIo {
    dir: std::path::PathBuf,
    files: Vec<std::fs::File>,
    by_name: BTreeMap<String, FileId>,
}

impl StdIo {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            files: Vec::new(),
            by_name: BTreeMap::new(),
        })
    }
}

fn other(e: impl std::fmt::Display) -> IoError {
    IoError::Other(e.to_string())
}

impl Io for StdIo {
    fn create(&mut self, name: &str) -> IoResult<FileId> {
        if let Some(&id) = self.by_name.get(name) {
            return Ok(id);
        }
        let path = self.dir.join(name);
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .map_err(other)?;
        let id = u32::try_from(self.files.len()).map_err(other)?;
        self.files.push(f);
        self.by_name.insert(name.to_owned(), id);
        Ok(id)
    }

    fn append(&mut self, file: FileId, data: &[u8]) -> IoResult<usize> {
        use std::io::Write as _;
        let f = self.files.get_mut(file as usize).ok_or(IoError::NotFound)?;
        f.write(data).map_err(other)
    }

    fn fsync(&mut self, file: FileId) -> IoResult<()> {
        let f = self.files.get_mut(file as usize).ok_or(IoError::NotFound)?;
        f.sync_data().map_err(other)
    }

    fn truncate(&mut self, file: FileId, len: u64) -> IoResult<()> {
        let f = self.files.get_mut(file as usize).ok_or(IoError::NotFound)?;
        f.set_len(len).map_err(other)?;
        f.sync_all().map_err(other)
    }

    fn read_all(&mut self, file: FileId) -> IoResult<Vec<u8>> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let f = self.files.get_mut(file as usize).ok_or(IoError::NotFound)?;
        let pos = f.stream_position().map_err(other)?;
        f.seek(SeekFrom::Start(0)).map_err(other)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(other)?;
        f.seek(SeekFrom::Start(pos)).map_err(other)?;
        Ok(buf)
    }

    fn size(&self, file: FileId) -> IoResult<u64> {
        let f = self.files.get(file as usize).ok_or(IoError::NotFound)?;
        f.metadata().map(|m| m.len()).map_err(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsync_makes_data_survive_a_crash() {
        let mut io = SimIo::new(1, IoFaults::NONE);
        let f = io.create("j").unwrap();
        io.append(f, b"hello").unwrap();
        io.fsync(f).unwrap();
        io.crash();
        assert_eq!(io.read_all(f).unwrap(), b"hello");
    }

    #[test]
    fn unsynced_tail_may_be_lost_but_never_grows() {
        // Over many seeds the surviving tail is always a prefix of what was
        // written, never something else.
        for seed in 0..200u64 {
            let mut io = SimIo::new(seed, IoFaults::NONE);
            let f = io.create("j").unwrap();
            io.append(f, b"AAAA").unwrap();
            io.fsync(f).unwrap();
            io.append(f, b"BBBB").unwrap();
            io.crash();
            let got = io.read_all(f).unwrap();
            assert!(got.starts_with(b"AAAA"), "acked data lost, seed {seed}");
            assert!(got.len() <= 8);
            assert!(
                b"AAAABBBB".starts_with(&got[..]),
                "invented bytes, seed {seed}"
            );
        }
    }

    #[test]
    fn lying_fsync_is_observable() {
        let faults = IoFaults {
            lying_fsync_ppm: 1_000_000,
            ..IoFaults::NONE
        };
        let mut io = SimIo::new(3, faults);
        let f = io.create("j").unwrap();
        io.append(f, b"data").unwrap();
        io.fsync(f).unwrap(); // reports success
        assert_eq!(io.durable_len(f).unwrap(), 0);
        assert_eq!(io.stats.lying_fsyncs, 1);
    }

    #[test]
    fn same_seed_same_io_behaviour() {
        let run = |seed: u64| {
            let mut io = SimIo::new(seed, IoFaults::HOSTILE);
            let f = io.create("j").unwrap();
            let mut log = Vec::new();
            for i in 0..200u32 {
                log.push(format!("{:?}", io.append(f, &i.to_le_bytes())));
                log.push(format!("{:?}", io.fsync(f)));
            }
            log
        };
        assert_eq!(run(99), run(99));
    }
}
