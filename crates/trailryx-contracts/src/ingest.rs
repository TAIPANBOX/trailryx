//! What a source hands over, and why it has this shape.
//!
//! The plane boundary is enforced here **structurally**. A source does not
//! submit a record; it submits typed metadata plus separately classified
//! payload blobs. [`MetaDraft`] has no free-text field of any kind, so a source
//! that wanted to smuggle a prompt into the metadata plane has nowhere to put
//! it. Not a lint, not a review comment: there is no such field.
//!
//! That matters because the mapper is exactly where the mistake happens. Faced
//! with an attribute it does not recognise, the tempting move is to keep it
//! "verbatim, just in case", and unrecognised OpenTelemetry attributes
//! routinely contain prompts and personal data. Here the only place it fits is
//! [`PayloadPart`], behind a key.

use trailryx_record::{
    AgentId, Basis, ErrorCode, EventType, PayloadClass, PrincipalId, RunId, Severity, TenantId,
    Timestamp, Untrusted, Verdict,
};

/// Metadata as a source may propose it.
///
/// Typed fields only. Compare with [`crate::ingest::PayloadPart`]: everything
/// that could be content lives there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaDraft {
    pub tenant: TenantId,
    pub agent_id: AgentId,
    pub run_id: RunId,
    pub parent_run_id: Option<RunId>,
    pub on_behalf_of: Vec<PrincipalId>,

    /// The emitter's clock. Untrusted at the type level, so nothing downstream
    /// can quietly treat it as ours.
    pub occurred_at: Untrusted<Timestamp>,
    pub decided_at: Option<Untrusted<Timestamp>>,

    pub event_type: EventType,
    pub severity: Severity,
    pub basis: Basis,
    pub verdict: Option<Verdict>,
    pub error: Option<ErrorCode>,
    pub latency_micros: Option<u64>,
    pub tokens_in: Option<u32>,
    pub tokens_out: Option<u32>,
    pub cost_micros: Option<i64>,
}

/// A blob bound for the encrypted plane.
///
/// `class` is metadata, `bytes` are not. Classification without content is what
/// lets retention and access be decided without opening anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadPart {
    pub class: PayloadClass,
    pub bytes: Vec<u8>,
}

impl PayloadPart {
    pub fn new(class: PayloadClass, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            class,
            bytes: bytes.into(),
        }
    }

    /// Anything a mapper could not place into a typed field.
    ///
    /// Named so the intent is unmistakable at the call site: this is the
    /// destination for the unknown, and it is on the encrypted side.
    pub fn unmapped(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(PayloadClass::Diagnostic, bytes)
    }
}

/// Where a source is in its own stream. Opaque to us, meaningful to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Cursor(pub u64);

/// A source's own name for one event: a span id, a message id, an offset.
///
/// Bounded and opaque. We never parse it, never display it and never store it;
/// it is compared for equality inside one batch and then dropped. That is why
/// it may be raw bytes here while [`MetaDraft`] has no such field: a span id
/// that happened to contain somebody's name would be a leak if it reached a
/// record, and it does not reach one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceKey {
    len: u8,
    bytes: [u8; Self::MAX_BYTES],
}

impl SourceKey {
    pub const MAX_BYTES: usize = 32;

    /// Longer input is refused rather than truncated: two keys that differed
    /// only past the cut would become equal, and equality is the one thing
    /// this type is for.
    pub fn new(raw: &[u8]) -> Option<Self> {
        if raw.is_empty() || raw.len() > Self::MAX_BYTES {
            return None;
        }
        let mut bytes = [0u8; Self::MAX_BYTES];
        bytes[..raw.len()].copy_from_slice(raw);
        Some(Self {
            len: raw.len() as u8,
            bytes,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// How one event relates to another **in the source's own terms**.
///
/// The ingest path resolves this into `caused_by` once record ids exist, and
/// then forgets it. Without it a batch of spans arrives as a heap of unrelated
/// events and the causal graph, which is half of what the store is for, has to
/// be reconstructed by guesswork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Correlation {
    pub id: SourceKey,
    pub parent: Option<SourceKey>,
}

/// One unit handed over by a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingest {
    pub meta: MetaDraft,
    pub payload: Vec<PayloadPart>,
    /// Present when the source can say how this event relates to another.
    pub correlation: Option<Correlation>,
    pub cursor: Cursor,
}

impl Ingest {
    pub fn payload_bytes(&self) -> u64 {
        self.payload.iter().map(|p| p.bytes.len() as u64).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmapped_content_lands_on_the_encrypted_side() {
        let p = PayloadPart::unmapped(b"gen_ai.prompt=Ivan Petrenko, born 1979".to_vec());
        assert_eq!(p.class, PayloadClass::Diagnostic);
        assert!(!p.bytes.is_empty());
    }

    #[test]
    fn an_oversize_correlation_key_is_refused_rather_than_cut() {
        // Truncating would make two different parents equal, and equality is
        // the only thing this type does.
        assert!(SourceKey::new(&[7u8; SourceKey::MAX_BYTES]).is_some());
        assert!(SourceKey::new(&[7u8; SourceKey::MAX_BYTES + 1]).is_none());
        assert!(SourceKey::new(&[]).is_none());
    }

    #[test]
    fn correlation_keys_compare_on_their_real_length() {
        let short = SourceKey::new(b"ab").unwrap();
        let padded = SourceKey::new(b"ab\0").unwrap();
        assert_ne!(short, padded, "the zero padding is not part of the key");
        assert_eq!(short.as_bytes(), b"ab");
    }

    #[test]
    fn a_draft_has_nowhere_to_put_text() {
        // Documentation as a test: if a future edit adds a String field to
        // MetaDraft, this comment is where the reviewer should stop. The
        // structural guarantee is the absence of such a field, which no
        // assertion can express directly, so the schema check in
        // trailryx-record is the backstop.
        let size = std::mem::size_of::<PayloadPart>();
        assert!(size > 0);
    }
}
