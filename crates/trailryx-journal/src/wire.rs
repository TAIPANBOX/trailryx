//! The on-disk encoding.
//!
//! # Canonical, because the chain hashes these bytes
//!
//! One record must always produce exactly one byte sequence. If the encoder had
//! any freedom, two honest writers could produce different bytes for the same
//! record and their chains would disagree with no one having done anything
//! wrong. So: fixed field order, explicit enum discriminants that are part of
//! the format rather than whatever the compiler assigned, no maps, no floats.
//!
//! # Validated on the way in
//!
//! Decoding re-parses every identifier through its constructor rather than
//! trusting the bytes. The disk is not a trusted input: a corrupted token that
//! decoded straight into an `AgentId` would carry a value the type system
//! promises is impossible, and everything downstream is written against that
//! promise.
//!
//! # Framing
//!
//! ```text
//! frame := magic:u8 version:u8 len:varint body:len chain_link:48 crc32:u32
//! ```
//!
//! The CRC catches the torn tail a crash leaves behind, cheaply. The chain link
//! is the tamper-evidence, and storing it per record is deliberate: it makes
//! every record verifiable on its own, without replaying the file from the top.

use trailryx_record::{AgentId, ids::IdError};
use trailryx_record::{
    Algorithms, Basis, DelegationProof, ErrorCode, EventType, HASH_BYTES, Hash, HashAlg, IssuerId,
    KemAlg, KeyThumbprint, MapperVersion, ModelId, Outcome, PayloadClass, PayloadRef,
    PolicyVersion, PrincipalId, Record, RecordId, RunId, SegmentId, Severity, ShardIx, SigAlg,
    TenantId, Timestamp, TokenId, ToolName, Untrusted, Verdict,
};

pub const FRAME_MAGIC: u8 = 0xA7;
/// The frame version this writer emits.
///
/// Moved to 2 on 2026-08-27, when `basis.delegation_proof` was added
/// (agent-passport SPEC 5.2). Records already on disk are NOT rewritten: a
/// store whose whole claim is tamper-evidence cannot rewrite its own history to
/// add a field, and a migration that did would be indistinguishable from the
/// tampering the chain exists to catch. So the migration lives in the reader.
pub const FRAME_VERSION: u8 = 2;

/// The oldest frame this reader accepts.
///
/// A v1 frame decodes into a record whose `delegation_proof` is `None`, which
/// SPEC 5.2 already defines as NOT PROVEN rather than unknown. So the only
/// thing that changes about an old record is that a field it never had reads as
/// absent, which is what its absence always meant.
pub const OLDEST_FRAME_VERSION: u8 = 1;
pub const SEGMENT_MAGIC: &[u8; 4] = b"TRLX";
pub const FORMAT_VERSION: u16 = 1;

/// Nothing sane is this large; the bound stops a corrupt length from asking for
/// a gigabyte allocation before the CRC ever gets a chance to reject it.
pub const MAX_BODY_BYTES: usize = 4 << 20;

/// The longest segment header this format can produce.
///
/// Four magic bytes, then four varints (format version, shard, segment,
/// created_at) at their widest, then four CRC bytes. Written down because
/// recovery needs to answer a question the header alone cannot: is this file
/// short enough that a header which failed to decode is the *only* thing in it?
/// A file longer than this has records behind the header, and a header that
/// fails to decode is then corruption rather than a crash.
pub const MAX_SEGMENT_HEADER_LEN: usize = 4 + 3 + 3 + 10 + 10 + 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    BadMagic,
    UnknownVersion(u8),
    BadCrc,
    BadDiscriminant {
        field: &'static str,
        got: u8,
    },
    TooLarge(usize),
    BadId(&'static str, IdError),
    /// The bytes decode, but they are not the bytes an encoder would produce.
    NonCanonical(&'static str),
    Trailing(usize),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated"),
            Self::BadMagic => write!(f, "bad magic"),
            Self::UnknownVersion(v) => write!(f, "unknown frame version {v}"),
            Self::BadCrc => write!(f, "checksum mismatch"),
            Self::BadDiscriminant { field, got } => {
                write!(f, "unknown discriminant {got} for {field}")
            }
            Self::TooLarge(n) => write!(f, "declared length {n} exceeds the maximum"),
            Self::BadId(field, e) => write!(f, "invalid {field}: {e}"),
            Self::NonCanonical(why) => write!(f, "non-canonical encoding: {why}"),
            Self::Trailing(n) => write!(f, "{n} bytes left over after decoding"),
        }
    }
}

impl std::error::Error for WireError {}

pub type WireResult<T> = Result<T, WireError>;

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// LEB128. Small numbers cost one byte, which most of ours are.
    pub fn varint(&mut self, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(byte);
                return;
            }
            self.buf.push(byte | 0x80);
        }
    }

    /// Zigzag, so small negatives stay small.
    pub fn varint_i64(&mut self, v: i64) {
        self.varint(((v << 1) ^ (v >> 63)) as u64);
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.varint(b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    pub fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    pub fn hash(&mut self, h: &Hash) {
        self.buf.extend_from_slice(h.as_bytes());
    }

    pub fn u128(&mut self, v: u128) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn opt<T>(&mut self, v: Option<&T>, mut f: impl FnMut(&mut Self, &T)) {
        match v {
            Some(x) => {
                self.u8(1);
                f(self, x);
            }
            None => self.u8(0),
        }
    }

    pub fn seq<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Self, &T)) {
        self.varint(items.len() as u64);
        for it in items {
            f(self, it);
        }
    }
}

#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn finish(self) -> WireResult<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(WireError::Trailing(self.remaining()))
        }
    }

    pub fn u8(&mut self) -> WireResult<u8> {
        let b = *self.buf.get(self.pos).ok_or(WireError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    /// LEB128, **canonical only**.
    ///
    /// An overlong encoding such as `[0x81, 0x00]` also means 1, so accepting
    /// it would give one record several valid byte forms. The chain hashes
    /// those bytes: an offline verifier that decodes a record and re-encodes it
    /// to recompute a link would then disagree with the disk, and the module
    /// promises exactly one byte sequence per record. Cheap to enforce now, a
    /// format break later.
    pub fn varint(&mut self) -> WireResult<u64> {
        let mut out = 0u64;
        let mut shift = 0u32;
        let mut groups = 0u32;
        loop {
            let b = self.u8()?;
            groups += 1;
            // Ten groups of seven bits is the most a u64 can hold, and the
            // tenth may only carry the single remaining bit.
            if groups > 10 || (groups == 10 && b & 0x7e != 0) {
                return Err(WireError::NonCanonical("varint overflows u64"));
            }
            out |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                // A continuation byte that contributed nothing means the value
                // was padded rather than encoded.
                if groups > 1 && b == 0 {
                    return Err(WireError::NonCanonical("overlong varint"));
                }
                return Ok(out);
            }
            shift += 7;
        }
    }

    pub fn varint_i64(&mut self) -> WireResult<i64> {
        let u = self.varint()?;
        Ok(((u >> 1) as i64) ^ -((u & 1) as i64))
    }

    pub fn bytes(&mut self) -> WireResult<&'a [u8]> {
        let len = usize::try_from(self.varint()?).map_err(|_| WireError::Truncated)?;
        if len > MAX_BODY_BYTES {
            return Err(WireError::TooLarge(len));
        }
        let end = self.pos.checked_add(len).ok_or(WireError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    pub fn str(&mut self) -> WireResult<&'a str> {
        std::str::from_utf8(self.bytes()?).map_err(|_| WireError::Truncated)
    }

    pub fn hash(&mut self) -> WireResult<Hash> {
        let end = self.pos + HASH_BYTES;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        let mut out = [0u8; HASH_BYTES];
        out.copy_from_slice(slice);
        self.pos = end;
        Ok(Hash(out))
    }

    pub fn u128(&mut self) -> WireResult<u128> {
        let end = self.pos + 16;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(slice);
        self.pos = end;
        Ok(u128::from_be_bytes(out))
    }

    pub fn opt<T>(
        &mut self,
        mut f: impl FnMut(&mut Self) -> WireResult<T>,
    ) -> WireResult<Option<T>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(f(self)?)),
            got => Err(WireError::BadDiscriminant {
                field: "option",
                got,
            }),
        }
    }

    pub fn seq<T>(&mut self, mut f: impl FnMut(&mut Self) -> WireResult<T>) -> WireResult<Vec<T>> {
        let n = usize::try_from(self.varint()?).map_err(|_| WireError::Truncated)?;
        // A corrupt count must not reserve memory before it is proven.
        if n > MAX_BODY_BYTES {
            return Err(WireError::TooLarge(n));
        }
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(f(self)?);
        }
        Ok(out)
    }
}

/// CRC-32 (IEEE), bitwise. Detects a torn tail, nothing more: integrity against
/// an adversary is the chain's job.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// Enum discriminants: part of the format, not the compiler's business
// ---------------------------------------------------------------------------

macro_rules! disc {
    ($name:ident, $ty:ty, $field:expr, $( $variant:path => $code:expr ),+ $(,)?) => {
        mod $name {
            use super::*;
            pub fn put(w: &mut Writer, v: $ty) {
                w.u8(match v { $( $variant => $code ),+ });
            }
            pub fn get(r: &mut Reader<'_>) -> WireResult<$ty> {
                let got = r.u8()?;
                Ok(match got {
                    $( $code => $variant, )+
                    _ => return Err(WireError::BadDiscriminant { field: $field, got }),
                })
            }
        }
    };
}

// A code is assigned once and never moved. A new variant takes the next unused
// number and nothing above it changes, which is why `SigAlg::Es384` is 4 rather
// than sitting beside `Es256`, and why `NotificationDispatched` is 11 rather than
// beside the decisions it is not one of. Renumbering would redefine a field in
// place, which invariant 7 forbids; appending leaves every record ever written
// decoding to exactly what it was written as, and leaves a build that predates
// the new code refusing it by name rather than reading it as something else.
disc!(event_type, EventType, "event_type",
    EventType::RequestReceived => 1, EventType::ModelCall => 2, EventType::ToolCall => 3,
    EventType::PolicyDecision => 4, EventType::BudgetCheck => 5, EventType::MemoryAccess => 6,
    EventType::Delegation => 7, EventType::RunCompleted => 8, EventType::Erasure => 9,
    EventType::StoreEvent => 10, EventType::NotificationDispatched => 11,
    EventType::IdentityFinding => 12,
);

disc!(severity, Severity, "severity",
    Severity::Debug => 1, Severity::Info => 2, Severity::Notice => 3,
    Severity::Warning => 4, Severity::Error => 5, Severity::Critical => 6,
);

disc!(verdict, Verdict, "verdict",
    Verdict::Allowed => 1, Verdict::Denied => 2, Verdict::Held => 3,
    Verdict::Failed => 4, Verdict::NotApplicable => 5,
);

disc!(error_code, ErrorCode, "error",
    ErrorCode::None => 1, ErrorCode::Timeout => 2, ErrorCode::RateLimited => 3,
    ErrorCode::Unauthorized => 4, ErrorCode::BudgetExceeded => 5, ErrorCode::PolicyDenied => 6,
    ErrorCode::UpstreamError => 7, ErrorCode::Malformed => 8, ErrorCode::Internal => 9,
);

disc!(payload_class, PayloadClass, "payload.class",
    PayloadClass::Prompt => 1, PayloadClass::Completion => 2, PayloadClass::ToolArguments => 3,
    PayloadClass::ToolResult => 4, PayloadClass::Document => 5, PayloadClass::Diagnostic => 6,
);

disc!(hash_alg, HashAlg, "algorithms.hash", HashAlg::Sha384 => 1);

disc!(sig_alg, SigAlg, "algorithms.signature",
    SigAlg::Es256 => 1, SigAlg::MlDsa65 => 2, SigAlg::SlhDsa => 3, SigAlg::Es384 => 4,
);

disc!(kem_alg, KemAlg, "algorithms.kem", KemAlg::X25519MlKem768 => 1);

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

pub fn encode_record(rec: &Record) -> Vec<u8> {
    let mut w = Writer::new();

    w.u128(rec.id.0);
    w.str(rec.tenant.as_str());
    w.varint(u64::from(rec.shard.0));

    w.str(rec.agent_id.as_str());
    w.str(rec.run_id.as_str());
    w.opt(rec.parent_run_id.as_ref(), |w, v| w.str(v.as_str()));
    w.seq(&rec.on_behalf_of, |w, v| w.str(v.as_str()));

    w.varint(rec.occurred_at.as_untrusted().as_nanos());
    w.opt(rec.decided_at.as_ref(), |w, v| {
        w.varint(v.as_untrusted().as_nanos())
    });
    w.varint(rec.recorded_at.as_nanos());
    w.opt(rec.knowledge_as_of.as_ref(), |w, v| w.varint(v.as_nanos()));
    w.opt(rec.clock_skew_nanos.as_ref(), |w, v| w.varint(*v));

    event_type::put(&mut w, rec.event_type);
    severity::put(&mut w, rec.severity);

    let b = &rec.basis;
    w.opt(b.policy_version.as_ref(), |w, v| w.str(v.as_str()));
    w.opt(b.budget_remaining_micros.as_ref(), |w, v| w.varint_i64(*v));
    w.opt(b.memory_ref.as_ref(), |w, v| w.hash(v));
    w.opt(b.model.as_ref(), |w, v| w.str(v.as_str()));
    w.opt(b.temperature_milli.as_ref(), |w, v| w.varint(u64::from(*v)));
    w.opt(b.max_tokens.as_ref(), |w, v| w.varint(u64::from(*v)));
    w.opt(b.prompt_hash.as_ref(), |w, v| w.hash(v));
    w.seq(&b.tool_manifest, |w, v| w.str(v.as_str()));
    w.seq(&b.identity_chain, |w, v| w.str(v.as_str()));

    w.seq(&rec.caused_by, |w, v| w.u128(v.0));

    let o = &rec.outcome;
    w.opt(o.verdict.as_ref(), |w, v| verdict::put(w, *v));
    w.opt(o.error.as_ref(), |w, v| error_code::put(w, *v));
    w.opt(o.latency_micros.as_ref(), |w, v| w.varint(*v));
    w.opt(o.tokens_in.as_ref(), |w, v| w.varint(u64::from(*v)));
    w.opt(o.tokens_out.as_ref(), |w, v| w.varint(u64::from(*v)));
    w.opt(o.cost_micros.as_ref(), |w, v| w.varint_i64(*v));

    w.opt(rec.payload.as_ref(), |w, p| {
        w.hash(&p.hash);
        w.varint(p.size_bytes);
        payload_class::put(w, p.class);
        w.hash(&p.key_id);
    });

    w.varint(rec.seq);
    w.hash(&rec.prev_hash);
    w.varint(rec.segment_id.0);
    hash_alg::put(&mut w, rec.algorithms.hash);
    sig_alg::put(&mut w, rec.algorithms.signature);
    kem_alg::put(&mut w, rec.algorithms.kem);
    w.varint(u64::from(rec.mapper.0));

    // v2 adds `basis.delegation_proof`, and it is written LAST rather than
    // beside the rest of the basis. The body is a fixed field order with no
    // tags, so a v1 decoder reads positionally: putting this in the middle
    // would move every field after it and make a v1 body undecodable by any
    // reader that knew only v1. Appended, a v2 body IS a v1 body with more
    // after it, and the version says whether to read the more.
    w.opt(rec.basis.delegation_proof.as_ref(), |w, p| {
        w.str(p.jti.as_str());
        w.str(p.jkt.as_str());
        w.str(p.iss.as_str());
        w.varint(p.exp.as_nanos());
    });

    w.into_bytes()
}

fn id<T>(field: &'static str, r: Result<T, IdError>) -> WireResult<T> {
    r.map_err(|e| WireError::BadId(field, e))
}

pub fn decode_record(bytes: &[u8]) -> WireResult<Record> {
    decode_record_at(bytes, FRAME_VERSION)
}

/// Decode a body written under `version`.
///
/// The version is a parameter and not a guess, because the body carries no
/// tags: what fields are present is a fact about the frame that wrapped it.
/// Reading a v1 body as v2 would run off the end; reading a v2 body as v1 would
/// leave bytes over, which `finish` refuses.
pub fn decode_record_at(bytes: &[u8], version: u8) -> WireResult<Record> {
    let mut r = Reader::new(bytes);

    let rec_id = RecordId(r.u128()?);
    let tenant = id("tenant", TenantId::parse(r.str()?))?;
    let shard = ShardIx(u16::try_from(r.varint()?).map_err(|_| WireError::Truncated)?);

    let agent_id = id("agent_id", AgentId::parse(r.str()?))?;
    let run_id = id("run_id", RunId::parse(r.str()?))?;
    let parent_run_id = r.opt(|r| id("parent_run_id", RunId::parse(r.str()?)))?;
    let on_behalf_of = r.seq(|r| id("on_behalf_of", PrincipalId::parse(r.str()?)))?;

    let occurred_at = Untrusted::new(Timestamp(r.varint()?));
    let decided_at = r.opt(|r| Ok(Untrusted::new(Timestamp(r.varint()?))))?;
    let recorded_at = Timestamp(r.varint()?);
    let knowledge_as_of = r.opt(|r| Ok(Timestamp(r.varint()?)))?;
    let clock_skew_nanos = r.opt(Reader::varint)?;

    let event_type = event_type::get(&mut r)?;
    let severity = severity::get(&mut r)?;

    let mut basis = Basis {
        policy_version: r.opt(|r| id("basis.policy_version", PolicyVersion::parse(r.str()?)))?,
        budget_remaining_micros: r.opt(Reader::varint_i64)?,
        memory_ref: r.opt(Reader::hash)?,
        model: r.opt(|r| id("basis.model", ModelId::parse(r.str()?)))?,
        temperature_milli: r
            .opt(|r| u16::try_from(r.varint()?).map_err(|_| WireError::Truncated))?,
        max_tokens: r.opt(|r| u32::try_from(r.varint()?).map_err(|_| WireError::Truncated))?,
        prompt_hash: r.opt(Reader::hash)?,
        tool_manifest: r.seq(|r| id("basis.tool_manifest", ToolName::parse(r.str()?)))?,
        identity_chain: r.seq(|r| id("basis.identity_chain", PrincipalId::parse(r.str()?)))?,
        // v2 fills this below, after the fields v1 also has. A v1 body leaves
        // it None, which SPEC 5.2 defines as NOT proven.
        delegation_proof: None,
    };

    let caused_by = r.seq(|r| Ok(RecordId(r.u128()?)))?;

    let outcome = Outcome {
        verdict: r.opt(verdict::get)?,
        error: r.opt(error_code::get)?,
        latency_micros: r.opt(Reader::varint)?,
        tokens_in: r.opt(|r| u32::try_from(r.varint()?).map_err(|_| WireError::Truncated))?,
        tokens_out: r.opt(|r| u32::try_from(r.varint()?).map_err(|_| WireError::Truncated))?,
        cost_micros: r.opt(Reader::varint_i64)?,
    };

    let payload = r.opt(|r| {
        Ok(PayloadRef {
            hash: r.hash()?,
            size_bytes: r.varint()?,
            class: payload_class::get(r)?,
            key_id: r.hash()?,
        })
    })?;

    let seq = r.varint()?;
    let prev_hash = r.hash()?;
    let segment_id = SegmentId(r.varint()?);
    let algorithms = Algorithms {
        hash: hash_alg::get(&mut r)?,
        signature: sig_alg::get(&mut r)?,
        kem: kem_alg::get(&mut r)?,
    };
    let mapper = MapperVersion(u16::try_from(r.varint()?).map_err(|_| WireError::Truncated)?);

    // v2's trailing field. A v1 body simply has nothing here, and `finish`
    // below is what turns "read as the wrong version" into an error rather
    // than into a record with the wrong shape.
    if version >= 2 {
        basis.delegation_proof = r.opt(|r| {
            Ok(DelegationProof {
                jti: id("basis.delegation_proof.jti", TokenId::parse(r.str()?))?,
                jkt: id("basis.delegation_proof.jkt", KeyThumbprint::parse(r.str()?))?,
                iss: id("basis.delegation_proof.iss", IssuerId::parse(r.str()?))?,
                exp: Timestamp(r.varint()?),
            })
        })?;
    }

    r.finish()?;

    Ok(Record {
        id: rec_id,
        tenant,
        shard,
        agent_id,
        run_id,
        parent_run_id,
        on_behalf_of,
        occurred_at,
        decided_at,
        recorded_at,
        knowledge_as_of,
        clock_skew_nanos,
        event_type,
        severity,
        basis,
        caused_by,
        outcome,
        payload,
        seq,
        prev_hash,
        segment_id,
        algorithms,
        mapper,
    })
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// The bytes of one journal entry.
pub fn encode_frame(body: &[u8], chain_link: &Hash) -> Vec<u8> {
    encode_frame_at(body, chain_link, FRAME_VERSION)
}

/// Frame a body under an EXPLICIT version.
///
/// The version is inside the CRC, so a v1 frame cannot be made by writing a
/// v2 one and patching the byte: the frame catches that, correctly, as a bad
/// CRC. Building an older frame honestly is what a migration test needs, and
/// there is no way to do it from outside without this.
pub fn encode_frame_at(body: &[u8], chain_link: &Hash, version: u8) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(FRAME_MAGIC);
    w.u8(version);
    w.varint(body.len() as u64);
    let mut out = w.into_bytes();
    out.extend_from_slice(body);
    out.extend_from_slice(chain_link.as_bytes());
    let crc = crc32(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub body: &'a [u8],
    pub chain_link: Hash,
    pub total_len: usize,
    /// Which frame version this was written under. `decode_record` needs it:
    /// the body is a fixed field order with no tags, so what fields are present
    /// is a fact about the version and cannot be read off the bytes.
    pub version: u8,
}

/// Read one frame from the front of `buf`.
///
/// Returns `Truncated` when the buffer simply ends mid-frame, which is the
/// ordinary shape of a crash and not an error the caller should panic on.
pub fn decode_frame(buf: &[u8]) -> WireResult<Frame<'_>> {
    let mut r = Reader::new(buf);
    if r.u8()? != FRAME_MAGIC {
        return Err(WireError::BadMagic);
    }
    let version = r.u8()?;
    if !(OLDEST_FRAME_VERSION..=FRAME_VERSION).contains(&version) {
        return Err(WireError::UnknownVersion(version));
    }
    let len = usize::try_from(r.varint()?).map_err(|_| WireError::Truncated)?;
    if len > MAX_BODY_BYTES {
        return Err(WireError::TooLarge(len));
    }
    let header_len = buf.len() - r.remaining();
    let body_end = header_len + len;
    let link_end = body_end + HASH_BYTES;
    let crc_end = link_end + 4;
    if buf.len() < crc_end {
        return Err(WireError::Truncated);
    }

    let want = u32::from_le_bytes([
        buf[link_end],
        buf[link_end + 1],
        buf[link_end + 2],
        buf[link_end + 3],
    ]);
    if crc32(&buf[..link_end]) != want {
        return Err(WireError::BadCrc);
    }

    let mut link = [0u8; HASH_BYTES];
    link.copy_from_slice(&buf[body_end..link_end]);

    Ok(Frame {
        body: &buf[header_len..body_end],
        chain_link: Hash(link),
        total_len: crc_end,
        version,
    })
}

/// The header every segment file starts with. Carries its own format version,
/// so a file found on its own can still say what it is.
pub fn encode_segment_header(shard: ShardIx, segment: SegmentId, created_at: Timestamp) -> Vec<u8> {
    let mut w = Writer::new();
    let mut out = SEGMENT_MAGIC.to_vec();
    w.varint(u64::from(FORMAT_VERSION));
    w.varint(u64::from(shard.0));
    w.varint(segment.0);
    w.varint(created_at.as_nanos());
    out.extend_from_slice(&w.into_bytes());
    let crc = crc32(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    pub format_version: u16,
    pub shard: ShardIx,
    pub segment: SegmentId,
    pub created_at: Timestamp,
    pub len: usize,
}

pub fn decode_segment_header(buf: &[u8]) -> WireResult<SegmentHeader> {
    // Too short to judge is not the same as belonging to somebody else, and
    // the caller decides very different things about the two.
    if buf.len() < 4 {
        return Err(WireError::Truncated);
    }
    if &buf[..4] != SEGMENT_MAGIC {
        return Err(WireError::BadMagic);
    }
    let mut r = Reader::new(&buf[4..]);
    let format_version = u16::try_from(r.varint()?).map_err(|_| WireError::Truncated)?;
    if format_version != FORMAT_VERSION {
        return Err(WireError::UnknownVersion(
            u8::try_from(format_version).unwrap_or(u8::MAX),
        ));
    }
    let shard = ShardIx(u16::try_from(r.varint()?).map_err(|_| WireError::Truncated)?);
    let segment = SegmentId(r.varint()?);
    let created_at = Timestamp(r.varint()?);
    let consumed = 4 + (buf.len() - 4 - r.remaining());
    let crc_end = consumed + 4;
    if buf.len() < crc_end {
        return Err(WireError::Truncated);
    }
    let want = u32::from_le_bytes([
        buf[consumed],
        buf[consumed + 1],
        buf[consumed + 2],
        buf[consumed + 3],
    ]);
    if crc32(&buf[..consumed]) != want {
        return Err(WireError::BadCrc);
    }
    Ok(SegmentHeader {
        format_version,
        shard,
        segment,
        created_at,
        len: crc_end,
    })
}
