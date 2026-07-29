//! The evidence pack format, and a reader for it.
//!
//! Deliberately dull. Fixed-width big-endian integers, explicit lengths, no
//! varints, no compression, no schema negotiation. A format is only auditable
//! if somebody can read the parser without trusting it, and every clever
//! encoding trick costs a reader ten minutes of doubt.
//!
//! # What a pack contains
//!
//! Enough to check the store's arithmetic, and nothing that would let the pack
//! itself be the thing believed. Every root in it is recomputed from the
//! records underneath it, so a pack that states a convenient root and no
//! matching records fails on its own contents.
//!
//! Payloads are **not** in it. A pack travels to an auditor, and the audit
//! trail is metadata: the prompts stay in the store behind a separate
//! authorisation, and a pack that carried them would make every audit a data
//! export.

use crate::sha384::{HASH_BYTES, Hash};

pub const MAGIC: &[u8; 7] = b"TRXEVID";
pub const VERSION: u8 = 2;

pub const SECTION_END: u8 = 0;
pub const SECTION_HEADER: u8 = 1;
pub const SECTION_SHARD: u8 = 2;
pub const SECTION_SEGMENT: u8 = 3;
pub const SECTION_RECORDS: u8 = 4;
pub const SECTION_SIGNATURE: u8 = 5;
pub const SECTION_WITNESS: u8 = 6;

/// A ceiling on anything the pack asks us to allocate.
///
/// The pack comes from the party being audited. A length field is an
/// instruction from them, and an unbounded one is an instruction to run out of
/// memory.
const MAX_ITEMS: u64 = 100_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    BadMagic,
    UnknownVersion(u8),
    Truncated(&'static str),
    UnknownSection(u8),
    TooMany(&'static str),
    NotUtf8(&'static str),
    SectionOverrun(&'static str),
    Missing(&'static str),
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a Trailryx evidence pack"),
            Self::UnknownVersion(v) => write!(f, "pack version {v} is newer than this verifier"),
            Self::Truncated(what) => write!(f, "the pack ends inside {what}"),
            Self::UnknownSection(k) => write!(f, "section kind {k} is not one this version knows"),
            Self::TooMany(what) => write!(f, "{what} declares an implausible count"),
            Self::NotUtf8(what) => write!(f, "{what} is not valid UTF-8"),
            Self::SectionOverrun(what) => write!(f, "{what} reads past its own section"),
            Self::Missing(what) => write!(f, "the pack has no {what}"),
        }
    }
}

impl std::error::Error for PackError {}

#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], PackError> {
        let end = self.pos.checked_add(n).ok_or(PackError::Truncated(what))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(PackError::Truncated(what))?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8, PackError> {
        Ok(self.take(1, what)?[0])
    }

    pub fn u16(&mut self, what: &'static str) -> Result<u16, PackError> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self, what: &'static str) -> Result<u32, PackError> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self, what: &'static str) -> Result<u64, PackError> {
        let b = self.take(8, what)?;
        let mut v = [0u8; 8];
        v.copy_from_slice(b);
        Ok(u64::from_be_bytes(v))
    }

    pub fn hash(&mut self, what: &'static str) -> Result<Hash, PackError> {
        let b = self.take(HASH_BYTES, what)?;
        let mut h = [0u8; HASH_BYTES];
        h.copy_from_slice(b);
        Ok(h)
    }

    pub fn bytes(&mut self, what: &'static str) -> Result<&'a [u8], PackError> {
        let len = self.u32(what)? as usize;
        self.take(len, what)
    }

    pub fn string(&mut self, what: &'static str) -> Result<String, PackError> {
        let b = self.bytes(what)?;
        std::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|_| PackError::NotUtf8(what))
    }

    pub fn count(&mut self, what: &'static str) -> Result<usize, PackError> {
        let n = self.u64(what)?;
        if n > MAX_ITEMS {
            return Err(PackError::TooMany(what));
        }
        Ok(n as usize)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub tenant: String,
    pub generated_at: u64,
    pub store_root: Hash,
    pub shard_count: u32,
    /// One byte per algorithm slot, as the store writes them.
    pub algorithms: [u8; 3],
}

/// The publisher's commitment to a root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Somebody else's assertion that the root existed at a time.
///
/// The part a signature cannot give. A publisher chooses the timestamp they
/// sign, so their own signature rules out nothing about when the history was
/// written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub witness: String,
    pub seen_at: u64,
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    pub shard: u16,
    pub segment_count: u32,
    pub root: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub format_version: u16,
    pub segment: u64,
    pub shard: u16,
    pub records: u64,
    pub history_root: Hash,
    /// Dimension name and root, in the order the store wrote them. Order is
    /// part of what the manifest commits to, so it is preserved rather than
    /// sorted.
    pub index_roots: Vec<(String, Hash)>,
    pub chain_before: Hash,
    pub chain_after: Hash,
    pub first_recorded_at: u64,
    pub last_recorded_at: u64,
    pub algorithms: [u8; 3],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSet {
    pub shard: u16,
    pub segment: u64,
    /// Each record exactly as the journal wrote it, and nothing else.
    ///
    /// No sequence number beside it, no chain link, no extracted keys. Every
    /// one of those is derivable, and a field the pack declares is a field the
    /// pack can lie about. What is derived cannot disagree with itself.
    pub records: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pack {
    pub header: Header,
    pub signature: Option<Signature>,
    pub witnesses: Vec<Witness>,
    pub shards: Vec<Shard>,
    pub segments: Vec<Segment>,
    pub record_sets: Vec<RecordSet>,
}

impl Pack {
    pub fn parse(bytes: &[u8]) -> Result<Self, PackError> {
        let mut r = Reader::new(bytes);
        if r.take(MAGIC.len(), "the magic")? != MAGIC {
            return Err(PackError::BadMagic);
        }
        let version = r.u8("the version")?;
        if version != VERSION {
            return Err(PackError::UnknownVersion(version));
        }

        let mut header = None;
        let mut signature = None;
        let mut witnesses = Vec::new();
        let mut shards = Vec::new();
        let mut segments = Vec::new();
        let mut record_sets = Vec::new();

        loop {
            let kind = r.u8("a section kind")?;
            if kind == SECTION_END {
                break;
            }
            let len = r.count("a section length")?;
            let body = r.take(len, "a section body")?;
            let mut s = Reader::new(body);

            match kind {
                SECTION_HEADER => header = Some(parse_header(&mut s)?),
                SECTION_SHARD => shards.push(parse_shard(&mut s)?),
                SECTION_SEGMENT => segments.push(parse_segment(&mut s)?),
                SECTION_RECORDS => record_sets.push(parse_records(&mut s)?),
                SECTION_SIGNATURE => signature = Some(parse_signature(&mut s)?),
                SECTION_WITNESS => witnesses.push(parse_witness(&mut s)?),
                // Not skipped. A verifier that ignored a section it did not
                // understand would report success on a pack whose meaning it
                // only partly read.
                other => return Err(PackError::UnknownSection(other)),
            }
            if !s.is_empty() {
                return Err(PackError::SectionOverrun("a section"));
            }
        }

        Ok(Self {
            header: header.ok_or(PackError::Missing("header"))?,
            signature,
            witnesses,
            shards,
            segments,
            record_sets,
        })
    }

    pub fn records_for(&self, shard: u16, segment: u64) -> Option<&RecordSet> {
        self.record_sets
            .iter()
            .find(|s| s.shard == shard && s.segment == segment)
    }
}

fn parse_header(r: &mut Reader<'_>) -> Result<Header, PackError> {
    Ok(Header {
        tenant: r.string("the tenant")?,
        generated_at: r.u64("the timestamp")?,
        store_root: r.hash("the store root")?,
        shard_count: r.u32("the shard count")?,
        algorithms: [
            r.u8("the hash algorithm")?,
            r.u8("the signature algorithm")?,
            r.u8("the KEM algorithm")?,
        ],
    })
}

fn parse_signature(r: &mut Reader<'_>) -> Result<Signature, PackError> {
    Ok(Signature {
        algorithm: r.string("a signature algorithm")?,
        public_key: r.bytes("a public key")?.to_vec(),
        signature: r.bytes("a signature")?.to_vec(),
    })
}

fn parse_witness(r: &mut Reader<'_>) -> Result<Witness, PackError> {
    Ok(Witness {
        witness: r.string("a witness name")?,
        seen_at: r.u64("a witness timestamp")?,
        algorithm: r.string("a signature algorithm")?,
        public_key: r.bytes("a public key")?.to_vec(),
        signature: r.bytes("a signature")?.to_vec(),
    })
}

fn parse_shard(r: &mut Reader<'_>) -> Result<Shard, PackError> {
    Ok(Shard {
        shard: r.u16("a shard index")?,
        segment_count: r.u32("a segment count")?,
        root: r.hash("a shard root")?,
    })
}

fn parse_segment(r: &mut Reader<'_>) -> Result<Segment, PackError> {
    let format_version = r.u16("a format version")?;
    let segment = r.u64("a segment id")?;
    let shard = r.u16("a shard index")?;
    let records = r.u64("a record count")?;
    let history_root = r.hash("a history root")?;
    let chain_before = r.hash("a chain head")?;
    let chain_after = r.hash("a chain head")?;
    let n = r.count("an index-root count")?;
    let mut index_roots = Vec::with_capacity(n.min(64));
    for _ in 0..n {
        index_roots.push((r.string("a dimension name")?, r.hash("an index root")?));
    }
    Ok(Segment {
        format_version,
        segment,
        shard,
        records,
        history_root,
        index_roots,
        chain_before,
        chain_after,
        first_recorded_at: r.u64("a first timestamp")?,
        last_recorded_at: r.u64("a last timestamp")?,
        algorithms: [
            r.u8("the hash algorithm")?,
            r.u8("the signature algorithm")?,
            r.u8("the KEM algorithm")?,
        ],
    })
}

fn parse_records(r: &mut Reader<'_>) -> Result<RecordSet, PackError> {
    let shard = r.u16("a shard index")?;
    let segment = r.u64("a segment id")?;
    let n = r.count("a record count")?;
    let mut records = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        records.push(r.bytes("a record body")?.to_vec());
    }
    Ok(RecordSet {
        shard,
        segment,
        records,
    })
}
