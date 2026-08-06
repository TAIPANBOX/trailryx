//! Where a reader stopped in a file, so the next run resumes rather than restarts.
//!
//! # The defect this exists for
//!
//! `trailryx-node events --file` read the whole file every time. Records are
//! minted with a fresh identity per run, so a second import of an unchanged file
//! produced a second copy of every record and the journal's own deduplication
//! never fired. Measured on 6 August 2026: three imports of a two-line file
//! produced nine records in three segments, `0 duplicate(s)` reported each time.
//! A scheduled ship would therefore have duplicated the whole trail on every run,
//! and a duplicated audit trail is worse than an absent one, because its counts
//! are wrong and nothing says so.
//!
//! # What a cursor is keyed on, and why not the obvious things
//!
//! A path alone is wrong the moment a file is rotated: the name stays and the
//! bytes change. An inode is not portable and is reused. A byte offset alone is
//! wrong if the file is truncated or rewritten. So a cursor here is two things,
//! and only the second one decides anything:
//!
//! - **a name**, the absolute path, which is how an operator refers to the file
//!   and how this module finds the cursor to read. It is written into the file in
//!   full, so a digest collision in the file's own name is detected rather than
//!   silently resumed from;
//! - **a position with its evidence**: how many bytes were consumed, and the
//!   hash of exactly those bytes. Resuming happens only when that prefix is still
//!   the head of the file that is there now.
//!
//! That makes the four cases mechanical. The file is unchanged: the prefix
//! matches and there is nothing after it. The file has grown: the prefix matches
//! and only what follows is read. The file was truncated: it is shorter than the
//! prefix, so it is not the file that was read. The file was replaced under the
//! same name: the prefix does not match, so it is not that file either. The last
//! two are read from the beginning and **say so**, because a rotated journal is a
//! new stream and reading it whole is right, while resuming into it blindly would
//! skip whatever the new file's first bytes were.
//!
//! # Every failure here points the same way
//!
//! An absent cursor, a torn one, one that fails its own digest, one naming
//! another path: all of them are read as "nothing is remembered", which imports
//! the file whole. That direction is chosen rather than fallen into. Reading a
//! damaged cursor as a position would **skip lines that were never stored**, which
//! is silent loss; reading it as absent re-imports lines that already are, which
//! is duplication, and duplication is loud, because the run reports the records it
//! wrote. `docs/durability.md` §5 is the same rule one layer down.
//!
//! # When it is written
//!
//! **After the segment holding its records is sealed, never before.** A cursor
//! that is behind the evidence re-imports; a cursor ahead of it loses. So the
//! commit point of the data is the commit point of the cursor's right to move,
//! and the remaining window, between the manifest's rename and the cursor's, can
//! only ever duplicate one run's worth of lines. This is the journal watermark's
//! discipline in [`trailryx_journal::journal::Journal::sync`], with the same
//! answer to the same question: under-promise.

use std::path::{Path, PathBuf};

use trailryx_crypto::{Digest, Sha384};
use trailryx_record::{Hash, ShardIx, Timestamp};

/// The first line of a cursor file, and the only version this build reads.
const MAGIC: &str = "trailryx-cursor v1";

/// How much of the path digest names the file. Sixty-four bits, and a collision
/// is caught rather than trusted: the path is written inside and compared.
const NAME_HEX: usize = 16;

/// Where a reader stopped in one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// The file this cursor is about, absolute and with symlinks resolved.
    pub path: String,
    /// Bytes of that file already read into records.
    ///
    /// Always just past a line terminator: an unterminated final line may still
    /// be being written, so it is never counted as consumed.
    pub bytes: u64,
    /// Complete lines in that prefix, blank ones included, so a line number in a
    /// report is the line number an operator sees in an editor.
    pub lines: u64,
    /// Records those lines produced, across every run.
    pub records: u64,
    /// The hash of exactly the first `bytes` bytes.
    pub prefix: Hash,
    /// When this position was committed.
    pub at: Timestamp,
}

/// What was found beside a data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remembered {
    /// Nothing here: a first run, or a directory that never saw this file.
    Nothing,
    Cursor(Cursor),
    /// A cursor file that did not read back whole.
    ///
    /// Its own name, so an operator can look at it. Treated as nothing by
    /// [`decide`], for the reason in this module's header.
    Unreadable(String),
}

/// Why a file is being read from the beginning rather than resumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Whole {
    /// No cursor in this data directory names this file.
    NothingRemembered,
    /// A cursor file is there and did not read back.
    CursorUnreadable(String),
    /// A cursor file is there, under the same name, about a different path.
    AnotherPath { remembered: String },
    /// The file is shorter than the prefix the cursor remembers, so it cannot be
    /// the file that prefix came from.
    FileShorter { remembered: u64, now: u64 },
    /// The file is long enough and its first `remembered` bytes are not the ones
    /// that were read.
    PrefixDiffers { remembered: u64 },
}

impl std::fmt::Display for Whole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NothingRemembered => {
                f.write_str("nothing is remembered about this file, so all of it is new")
            }
            Self::CursorUnreadable(path) => write!(
                f,
                "the cursor at {path} did not read back, so it is treated as absent and \
                 the file is read whole"
            ),
            Self::AnotherPath { remembered } => write!(
                f,
                "the cursor under this name is about {remembered}, so it says nothing \
                 about this file"
            ),
            Self::FileShorter { remembered, now } => write!(
                f,
                "the cursor remembers {remembered} byte(s) and the file is {now}, so this \
                 is not the file that was read"
            ),
            Self::PrefixDiffers { remembered } => write!(
                f,
                "the first {remembered} byte(s) are not the ones that were read, so the \
                 file under this name was replaced rather than appended to"
            ),
        }
    }
}

/// What to do with a file, given what is remembered about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resume {
    /// Read it from byte zero, for this reason.
    Whole(Whole),
    /// Read it from where the cursor stopped.
    After(Cursor),
}

impl Resume {
    /// The first byte of the file this run should read.
    pub fn from(&self) -> u64 {
        match self {
            Self::Whole(_) => 0,
            Self::After(cursor) => cursor.bytes,
        }
    }

    /// Lines already accounted for, so this run's line numbers continue theirs.
    pub fn lines_before(&self) -> u64 {
        match self {
            Self::Whole(_) => 0,
            Self::After(cursor) => cursor.lines,
        }
    }

    /// Records already accounted for.
    pub fn records_before(&self) -> u64 {
        match self {
            Self::Whole(_) => 0,
            Self::After(cursor) => cursor.records,
        }
    }
}

/// Offset just past the last complete line, and the bytes held back after it.
///
/// A line is complete when its terminator has landed. That is the framer's own
/// rule and it is the only one a reader of a live file may use: a producer that
/// flushes on a timer leaves its last line unterminated most of the time, and
/// recording half a line as a record would put a truncated event in an audit
/// trail. So the tail is left where it is and the run says how many bytes it left,
/// which is a complaint that repeats until the producer finishes the line.
pub fn complete_prefix(bytes: &[u8]) -> u64 {
    match bytes.iter().rposition(|b| *b == b'\n') {
        Some(at) => at as u64 + 1,
        None => 0,
    }
}

/// The hash of a byte range, in the same function every caller uses.
pub fn digest(bytes: &[u8]) -> Hash {
    let mut h = Sha384::new();
    Digest::update(&mut h, b"trailryx/source-cursor/v1\0");
    Digest::update(&mut h, bytes);
    Digest::finish(h)
}

/// The cursor file for one source file in one shard's data directory.
///
/// Named for a digest of the path rather than the path, because a path holds
/// separators and has no length anybody controls. The path itself goes inside.
pub fn cursor_name(shard: ShardIx, path: &Path) -> String {
    let hex = digest(path.as_os_str().as_encoded_bytes()).to_hex();
    format!("{shard}-{}.cur", &hex[..NAME_HEX])
}

/// The path this file is remembered under, absolute where the filesystem allows.
///
/// Canonical, so the same file reached through a symlink or a relative path is
/// one source rather than two. A path that will not canonicalise is used as
/// given, which is the honest fallback: it names something this process could not
/// resolve, and refusing the whole import over that would be worse.
pub fn source_name(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

/// Read what is remembered about one file.
pub fn load(dir: &Path, shard: ShardIx, source: &Path) -> Remembered {
    let path = dir.join(cursor_name(shard, source));
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Remembered::Nothing;
    };
    match parse(&text) {
        Some(cursor) => Remembered::Cursor(cursor),
        None => Remembered::Unreadable(path.display().to_string()),
    }
}

/// Where the cursor for one source file lives.
pub fn path_of(dir: &Path, shard: ShardIx, source: &Path) -> PathBuf {
    dir.join(cursor_name(shard, source))
}

/// Write a position down, so that all of it lands or none of it does.
///
/// The same temporary-then-rename the manifest uses, for the same reason: a half
/// written cursor read as a position would skip lines. It could not be, because
/// the digest below would refuse it, and writing it this way means the digest
/// never has to be the thing that saves us.
pub fn save(
    dir: &Path,
    shard: ShardIx,
    source: &Path,
    cursor: &Cursor,
) -> std::io::Result<PathBuf> {
    let path = path_of(dir, shard, source);
    crate::plane::write_committing(&path, encode(cursor).as_bytes())?;
    Ok(path)
}

/// Decide what to read, given what is remembered and what is on disk now.
pub fn decide(remembered: Remembered, file: &[u8], source: &str) -> Resume {
    let cursor = match remembered {
        Remembered::Nothing => return Resume::Whole(Whole::NothingRemembered),
        Remembered::Unreadable(at) => return Resume::Whole(Whole::CursorUnreadable(at)),
        Remembered::Cursor(cursor) => cursor,
    };
    // A digest of a path is sixty-four bits here, so two paths can land on one
    // cursor file. Comparing the path the cursor carries turns that from a silent
    // resume into a file read whole, which is the same direction every other
    // failure in this module takes.
    if cursor.path != source {
        return Resume::Whole(Whole::AnotherPath {
            remembered: cursor.path,
        });
    }
    let now = file.len() as u64;
    if now < cursor.bytes {
        return Resume::Whole(Whole::FileShorter {
            remembered: cursor.bytes,
            now,
        });
    }
    let head = &file[..usize::try_from(cursor.bytes).unwrap_or(usize::MAX)];
    if digest(head) != cursor.prefix {
        return Resume::Whole(Whole::PrefixDiffers {
            remembered: cursor.bytes,
        });
    }
    Resume::After(cursor)
}

/// The bytes of a cursor file, digest included.
fn encode(cursor: &Cursor) -> String {
    let body = body(cursor);
    let digest = digest(body.as_bytes()).to_hex();
    format!("{body}digest {digest}\n")
}

/// Everything the digest covers.
fn body(cursor: &Cursor) -> String {
    format!(
        "{MAGIC}\npath {}\nbytes {}\nlines {}\nrecords {}\nat {}\nprefix {}\n",
        cursor.path,
        cursor.bytes,
        cursor.lines,
        cursor.records,
        cursor.at.as_nanos(),
        cursor.prefix.to_hex()
    )
}

/// Read a cursor file back, or refuse it whole.
///
/// Every refusal is the same answer to the caller, `None`, because every one of
/// them means the same thing: nothing here may be resumed from.
fn parse(text: &str) -> Option<Cursor> {
    // The last byte is a terminator, and a file that has lost it is refused
    // rather than trimmed into shape. The digest would have caught every other
    // missing byte and not this one, because trimming a newline and having none
    // to trim are the same operation: a cursor cut one byte short read back
    // perfectly until this line existed. Strictness is free here, since
    // `write_committing` renames a whole file into place and nothing else writes
    // one.
    let text = text.strip_suffix('\n')?;
    let (body_text, digest_hex) = text.rsplit_once("digest ")?;
    let stated = Hash::from_hex(digest_hex)?;
    if digest(body_text.as_bytes()) != stated {
        return None;
    }

    let mut lines = body_text.lines();
    if lines.next()? != MAGIC {
        return None;
    }
    let mut path = None;
    let mut bytes = None;
    let mut line_count = None;
    let mut records = None;
    let mut at = None;
    let mut prefix = None;
    for line in lines {
        let (name, value) = line.split_once(' ')?;
        match name {
            "path" => path = Some(value.to_owned()),
            "bytes" => bytes = Some(value.parse().ok()?),
            "lines" => line_count = Some(value.parse().ok()?),
            "records" => records = Some(value.parse().ok()?),
            "at" => at = Some(Timestamp(value.parse().ok()?)),
            "prefix" => prefix = Some(Hash::from_hex(value)?),
            // A field a later version added. Refused rather than skipped: this
            // build cannot know whether it changes what the others mean.
            _ => return None,
        }
    }
    Some(Cursor {
        path: path?,
        bytes: bytes?,
        lines: line_count?,
        records: records?,
        prefix: prefix?,
        at: at?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor() -> Cursor {
        Cursor {
            path: "/tmp/sent.ndjson".to_owned(),
            bytes: 42,
            lines: 2,
            records: 3,
            prefix: digest(b"whatever"),
            at: Timestamp(1_785_000_000_000_000_000),
        }
    }

    #[test]
    fn a_cursor_written_down_reads_back_exactly() {
        assert_eq!(parse(&encode(&cursor())), Some(cursor()));
    }

    #[test]
    fn a_cursor_with_a_byte_changed_reads_as_nothing_at_all() {
        // The direction the whole module takes: a damaged position is absent, so
        // the file is read again, rather than a position, which would skip lines
        // nobody stored.
        let text = encode(&cursor()).replace("bytes 42", "bytes 43");
        assert_eq!(parse(&text), None);
    }

    #[test]
    fn a_cursor_cut_short_reads_as_nothing_at_all() {
        let text = encode(&cursor());
        for cut in [0, 4, 20, text.len() - 4, text.len() - 1] {
            assert_eq!(parse(&text[..cut]), None, "a cursor cut at {cut} parsed");
        }
    }

    #[test]
    fn a_field_this_build_does_not_know_is_refused_rather_than_skipped() {
        // A later version's field may change what the fields beside it mean, and
        // a reader that ignored it would resume from a position it misread.
        let with_extra = format!(
            "{MAGIC}\npath /tmp/sent.ndjson\nbytes 42\nlines 2\nrecords 3\nat 1\nprefix {}\nwindow 7\n",
            digest(b"whatever").to_hex()
        );
        let text = format!(
            "{with_extra}digest {}\n",
            digest(with_extra.as_bytes()).to_hex()
        );
        assert_eq!(parse(&text), None);
    }

    #[test]
    fn a_complete_prefix_ends_at_the_last_terminator() {
        assert_eq!(complete_prefix(b""), 0);
        assert_eq!(complete_prefix(b"{}"), 0, "one unterminated line");
        assert_eq!(complete_prefix(b"{}\n"), 3);
        assert_eq!(complete_prefix(b"{}\n{}"), 3, "the tail is held back");
        assert_eq!(complete_prefix(b"{}\n{}\n"), 6);
    }
}
