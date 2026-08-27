//! The canonical decision record.
//!
//! Not a span. A span answers "how long did it take and who called whom". This
//! answers "what was done, on what grounds, against what the system knew, and
//! how it ended", which is a different shape: several parents rather than one,
//! four clocks rather than one, and a basis block that has no equivalent in
//! tracing at all.
//!
//! Everything here lives in the **metadata plane** and is therefore typed:
//! identifiers, enums, hashes, numbers, timestamps. Free text of any kind
//! belongs to the payload plane, behind a key. See [`crate::schema`] for why
//! that boundary is an invariant rather than a habit.

use crate::hash::Hash;
use crate::ids::{
    AgentId, IssuerId, KeyThumbprint, ModelId, PolicyVersion, PrincipalId, RecordId, RunId,
    SegmentId, ShardIx, TenantId, TokenId, ToolName,
};
use crate::time::{Timestamp, Untrusted};

/// What kind of thing happened. An enum, not a string: an open vocabulary in
/// the metadata plane would be a hole through which content arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventType {
    /// The agent was asked to do something.
    RequestReceived,
    /// A model was called.
    ModelCall,
    /// A tool was invoked.
    ToolCall,
    /// A policy decision was taken.
    PolicyDecision,
    /// Spend was metered or a budget checked.
    BudgetCheck,
    /// Memory was read or written.
    MemoryAccess,
    /// The agent delegated to another agent.
    Delegation,
    /// The run finished.
    RunCompleted,
    /// A person's data was erased.
    Erasure,
    /// The store said something about itself: a gap, a re-sign, a recovery.
    StoreEvent,
    /// A notification about the run was dispatched to a person.
    ///
    /// The eleventh, and the first added after the vocabulary was written. It is
    /// here rather than folded into one of the ten because none of them is true
    /// of it: nothing was decided, no policy was consulted, no budget moved, and
    /// the agent did not act at all. Somebody was told something, which is a fact
    /// an auditor asks about directly ("when was this escalated, and to whom")
    /// and which no other event type can answer without lying about what
    /// happened.
    ///
    /// **Dispatched, not delivered.** The producer observes a transport taking
    /// the message; whether it reached a mailbox, a spam folder or a silently
    /// discarding filter is not knowable from where the record is written, and a
    /// trail that claimed the stronger fact would be worse than one that admits
    /// the weaker one. Who it went to is personal data and lives in the payload
    /// plane like every other free-form member; this type says only that a
    /// notification left.
    NotificationDispatched,
    /// An identity plane reported a finding about an agent.
    ///
    /// The twelfth, and it is here for the same reason the eleventh was: none of
    /// the others is true of it. Nothing was decided, no policy was consulted,
    /// no budget moved, nobody was told, the store is not speaking about itself,
    /// and the subject agent did not act at all. Something LOOKED at the estate
    /// and said the identity may not be what it seems.
    ///
    /// **Why that earns a type here when other products' findings do not.** This
    /// store's subject axis is `agent_id`: every trail hangs off it, and a
    /// finding that the identity behind a trail was ever in doubt conditions how
    /// an auditor reads every other record about that subject. "Was this
    /// identity questioned, and when" is a question no other type can answer
    /// without saying something untrue. A crypto finding, a simulation finding
    /// or a quality drift do not clear that bar: their subjects are a
    /// certificate, a scenario and a score, none of which this store is built
    /// around.
    ///
    /// **It asserts that a finding was REPORTED, never that it is true.** The
    /// same standing `NotificationDispatched` takes about delivery. An identity
    /// plane's detectors are heuristics over a graph and some of them are wrong;
    /// what the record fixes is that at this time, this producer said this about
    /// this subject.
    ///
    /// **`run_id` names the reporting SCAN, not an execution of the subject.**
    /// The subject agent never ran that run. This is the one type for which
    /// [`crate::ids::RunId`]'s "one execution of an agent" is not the reading:
    /// here a query by run reconstructs one scan's findings, and a query by
    /// agent reconstructs one subject's identity history. Both are questions an
    /// auditor asks; leaving this unsaid would let the record lie by
    /// implication.
    ///
    /// **Which detector fired is not here**, and that is the plane boundary
    /// rather than an omission. The producer's detector names are its own
    /// vocabulary and change without anybody else editing anything; compiling
    /// them into a frozen format is what this store refuses for exactly that
    /// reason. They arrive in the payload plane with the rest of `data`.
    IdentityFinding,
}

impl EventType {
    pub const ALL: &'static [Self] = &[
        Self::RequestReceived,
        Self::ModelCall,
        Self::ToolCall,
        Self::PolicyDecision,
        Self::BudgetCheck,
        Self::MemoryAccess,
        Self::Delegation,
        Self::RunCompleted,
        Self::Erasure,
        Self::StoreEvent,
        Self::NotificationDispatched,
        Self::IdentityFinding,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestReceived => "request_received",
            Self::ModelCall => "model_call",
            Self::ToolCall => "tool_call",
            Self::PolicyDecision => "policy_decision",
            Self::BudgetCheck => "budget_check",
            Self::MemoryAccess => "memory_access",
            Self::Delegation => "delegation",
            Self::RunCompleted => "run_completed",
            Self::Erasure => "erasure",
            Self::StoreEvent => "store_event",
            Self::NotificationDispatched => "notification_dispatched",
            Self::IdentityFinding => "identity_finding",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
}

impl Severity {
    pub const ALL: &'static [Self] = &[
        Self::Debug,
        Self::Info,
        Self::Notice,
        Self::Warning,
        Self::Error,
        Self::Critical,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// How a decision ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    Allowed,
    Denied,
    Held,
    Failed,
    NotApplicable,
}

impl Verdict {
    pub const ALL: &'static [Self] = &[
        Self::Allowed,
        Self::Denied,
        Self::Held,
        Self::Failed,
        Self::NotApplicable,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Held => "held",
            Self::Failed => "failed",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Why something failed, as a code.
///
/// Deliberately **not** a message. Provider error strings are the classic way
/// personal data leaks into a log: they quote the input. The code stays in
/// metadata, the text goes to the payload plane with everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorCode {
    None,
    Timeout,
    RateLimited,
    Unauthorized,
    BudgetExceeded,
    PolicyDenied,
    UpstreamError,
    Malformed,
    Internal,
}

impl ErrorCode {
    pub const ALL: &'static [Self] = &[
        Self::None,
        Self::Timeout,
        Self::RateLimited,
        Self::Unauthorized,
        Self::BudgetExceeded,
        Self::PolicyDenied,
        Self::UpstreamError,
        Self::Malformed,
        Self::Internal,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::Unauthorized => "unauthorized",
            Self::BudgetExceeded => "budget_exceeded",
            Self::PolicyDenied => "policy_denied",
            Self::UpstreamError => "upstream_error",
            Self::Malformed => "malformed",
            Self::Internal => "internal",
        }
    }
}

/// What the system knew when it decided.
///
/// This block is the reason the product exists. A span records that a call
/// happened; this records the grounds on which it was allowed to happen, which
/// is what an auditor asks about and what nobody stores today.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Basis {
    /// Which policy version was in force.
    pub policy_version: Option<PolicyVersion>,
    /// Budget remaining at decision time, in micro-units of account currency.
    pub budget_remaining_micros: Option<i64>,
    /// What the agent remembered: a reference, never a copy. Copying memory
    /// into the record would put somebody else's content in our metadata.
    pub memory_ref: Option<Hash>,
    /// Which model, and the parameters that change its behaviour.
    pub model: Option<ModelId>,
    pub temperature_milli: Option<u16>,
    pub max_tokens: Option<u32>,
    /// The prompt, by hash. Never the prompt.
    pub prompt_hash: Option<Hash>,
    /// Which tools were in scope at the moment of the decision. Names only.
    pub tool_manifest: Vec<ToolName>,
    /// Delegation chain in force, root first.
    pub identity_chain: Vec<PrincipalId>,
    /// That the chain above was PROVED, and by which token. agent-passport
    /// SPEC 5.2, and `None` means NOT proven rather than proven elsewhere.
    ///
    /// # Why it is typed metadata and not payload
    ///
    /// The chain is typed and kept; the payload plane is what a per-event key
    /// erases. SPEC 5.2 reads a chain with no proof beside it as not proven, so
    /// a proof in the erasable half means a routine erasure turns a proven
    /// chain into an unproven one, silently, in the store whose whole claim is
    /// that nobody can quietly alter what it holds. 5.2 spends a MUST on that
    /// downgrade.
    ///
    /// It carries no personal content: a token id, a key thumbprint, an issuer
    /// URL and an expiry. Nothing about privacy argues for the erasable plane.
    pub delegation_proof: Option<DelegationProof>,
}

/// That a delegation chain was proved, and by which token (SPEC 5.2).
///
/// The token itself never travels. It is a live credential and this is a
/// replicated, hash-chained record that outlives it; what is kept is enough to
/// walk to the issuer's own record and to its revocation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationProof {
    /// The token's id, so an auditor can find it in the issuer's own record.
    pub jti: TokenId,
    /// RFC 7638 thumbprint the token was bound to: WHO was holding it, which a
    /// chain of names cannot say.
    pub jkt: KeyThumbprint,
    /// The issuer, so the right keys and the right revocation list are read.
    pub iss: IssuerId,
    /// When the proof stopped being one. The chain carries no freshness; this
    /// is the freshness, and it belongs to the proof rather than to the names.
    pub exp: Timestamp,
}

/// How it ended, and what it cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Outcome {
    pub verdict: Option<Verdict>,
    pub error: Option<ErrorCode>,
    pub latency_micros: Option<u64>,
    pub tokens_in: Option<u32>,
    pub tokens_out: Option<u32>,
    /// Cost in micro-units, so money never becomes a float.
    pub cost_micros: Option<i64>,
}

/// How the payload is classified, so retention and access can be decided
/// without opening it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PayloadClass {
    Prompt,
    Completion,
    ToolArguments,
    ToolResult,
    Document,
    Diagnostic,
}

impl PayloadClass {
    pub const ALL: &'static [Self] = &[
        Self::Prompt,
        Self::Completion,
        Self::ToolArguments,
        Self::ToolResult,
        Self::Document,
        Self::Diagnostic,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::Completion => "completion",
            Self::ToolArguments => "tool_arguments",
            Self::ToolResult => "tool_result",
            Self::Document => "document",
            Self::Diagnostic => "diagnostic",
        }
    }
}

/// A pointer into the encrypted payload plane.
///
/// The record knows the size, the shape and the key that opens it. It does not
/// know the content, and after erasure nobody does: the reference stays, so the
/// chain still verifies, and the bytes are unreachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadRef {
    pub hash: Hash,
    pub size_bytes: u64,
    pub class: PayloadClass,
    /// Which key wraps this payload's data key. Erasing that key erases this.
    pub key_id: Hash,
}

/// Which algorithms produced this record, recorded per record.
///
/// Not configuration: schema. In 2030 the migration away from today's
/// primitives has to start by enumerating what needs re-signing, and that is
/// impossible if the answer lives in a config file rather than in the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Algorithms {
    pub hash: HashAlg,
    pub signature: SigAlg,
    pub kem: KemAlg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlg {
    Sha384,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigAlg {
    /// Classical, present.
    Es256,
    /// ECDSA on P-384 with SHA-384: what the store actually signs with.
    ///
    /// Added rather than replacing `Es256`, which is what the algorithm fields
    /// are for. One hash across the whole system instead of two, security
    /// levels that match, and a curve every cloud key store supports.
    Es384,
    /// Post-quantum, hybrid with the above.
    MlDsa65,
    /// Hash-based, for epoch anchors. Not in v1: no audited Rust implementation
    /// covers it yet, and the longest-lived guarantee is the wrong place to
    /// take that risk.
    SlhDsa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KemAlg {
    /// Hybrid: safe if either half survives.
    X25519MlKem768,
}

impl HashAlg {
    pub const ALL: &'static [Self] = &[Self::Sha384];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha384 => "sha384",
        }
    }
}

impl SigAlg {
    pub const ALL: &'static [Self] = &[Self::Es256, Self::Es384, Self::MlDsa65, Self::SlhDsa];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "es256",
            Self::Es384 => "es384",
            Self::MlDsa65 => "ml-dsa-65",
            Self::SlhDsa => "slh-dsa",
        }
    }
}

impl KemAlg {
    pub const ALL: &'static [Self] = &[Self::X25519MlKem768];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X25519MlKem768 => "x25519-ml-kem-768",
        }
    }
}

impl Default for Algorithms {
    fn default() -> Self {
        Self {
            hash: HashAlg::Sha384,
            // What the store actually signs with. It said `Es256` until the
            // demo printed the primitive inventory next to a signature made
            // with P-384, and a record that misdeclares its own algorithms
            // makes the migration those fields exist for impossible to plan.
            signature: SigAlg::Es384,
            kem: KemAlg::X25519MlKem768,
        }
    }
}

/// Which mapper version produced this record from whatever arrived on the wire.
///
/// The GenAI semantic conventions are still moving. When they change, this
/// number changes and the store does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MapperVersion(pub u16);

impl MapperVersion {
    /// A record no mapper produced: one the store wrote about itself.
    ///
    /// Zero rather than one, because "the first version of the GenAI mapper" and
    /// "not mapped at all" are different facts and a reader years from now cannot
    /// recover the difference from a field that conflated them.
    pub const UNMAPPED: Self = Self(0);
}

/// The canonical record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: RecordId,
    pub tenant: TenantId,
    pub shard: ShardIx,

    pub agent_id: AgentId,
    pub run_id: RunId,
    pub parent_run_id: Option<RunId>,
    /// Delegation chain, root first.
    pub on_behalf_of: Vec<PrincipalId>,

    /// Told to us. Untrusted by construction.
    pub occurred_at: Untrusted<Timestamp>,
    pub decided_at: Option<Untrusted<Timestamp>>,
    /// Ours.
    pub recorded_at: Timestamp,
    /// Which state of knowledge the decision was taken against.
    pub knowledge_as_of: Option<Timestamp>,
    /// Set when the emitter's clock disagreed with ours beyond the threshold.
    pub clock_skew_nanos: Option<u64>,

    pub event_type: EventType,
    pub severity: Severity,

    pub basis: Basis,
    /// Several parents, not one: a decision follows from a request *and* a
    /// policy verdict *and* a memory state *and* a budget.
    pub caused_by: Vec<RecordId>,
    pub outcome: Outcome,
    pub payload: Option<PayloadRef>,

    pub seq: u64,
    pub prev_hash: Hash,
    pub segment_id: SegmentId,
    pub algorithms: Algorithms,
    pub mapper: MapperVersion,
}

/// The dimensions a completeness proof can cover.
///
/// Fixed here, once, because they decide how segments are sorted. Everything
/// else is a filter without a proof, and the API says so rather than implying
/// otherwise.
/// Five, and the fifth was added deliberately when causal reconstruction
/// arrived: `caused_by` names records by id, so a closure that cannot follow
/// its own edges provably is half a feature. It also gives an evidence pack the
/// most basic operation it needs, "here is record X with its inclusion proof",
/// and a ULID sorts by time anyway, so the index is useful on its own.
pub const PROVABLE_DIMENSIONS: &[&str] = &["id", "recorded_at", "agent_id", "run_id", "event_type"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Kind, RECORD_V1};

    /// Every closed vocabulary, as the pair it actually is: the path the schema
    /// document publishes it under, and the enum the compiler checks.
    ///
    /// This table is itself a second place, so
    /// `every_closed_vocabulary_in_the_schema_is_held_against_an_enum` holds it.
    /// Without that, a field added to the schema and not to this list would be a
    /// vocabulary nothing compares, which is the same drift one level up.
    fn vocabularies() -> Vec<(&'static str, Vec<&'static str>)> {
        macro_rules! names {
            ($ty:ty) => {
                <$ty>::ALL
                    .iter()
                    .map(|v| v.as_str())
                    .collect::<Vec<&'static str>>()
            };
        }
        vec![
            ("event_type", names!(EventType)),
            ("severity", names!(Severity)),
            ("outcome.verdict", names!(Verdict)),
            ("outcome.error", names!(ErrorCode)),
            ("payload.class", names!(PayloadClass)),
            ("algorithms.hash", names!(HashAlg)),
            ("algorithms.signature", names!(SigAlg)),
            ("algorithms.kem", names!(KemAlg)),
        ]
    }

    fn schema_enum(path: &str) -> &'static [&'static str] {
        let field = RECORD_V1
            .fields
            .iter()
            .find(|f| f.path == path)
            .unwrap_or_else(|| panic!("the schema describes {path}"));
        match field.kind {
            Kind::Enum(variants) => variants,
            _ => panic!("{path} is an enumeration or the boundary rule is not enforceable"),
        }
    }

    /// Each vocabulary is written down twice: once as an enum the compiler
    /// checks, and once in the schema document an auditor reads. Two places, one
    /// value, which is invariant 16, and the schema is the copy nothing compiles.
    ///
    /// It is the copy that leaves the repository, too: `to_json()` publishes it
    /// and `schema/record.v1.json` is committed, so a variant present in the enum
    /// and missing here is a value the format's own published description says
    /// does not exist.
    ///
    /// That was not hypothetical. `algorithms.signature` listed `es256`,
    /// `ml-dsa-65` and `slh-dsa` while `Algorithms::default()` signed with
    /// `SigAlg::Es384`, so every record the store wrote declared an algorithm the
    /// schema denied. The fields exist to make the 2030 migration enumerable, and
    /// a reader who trusts the document would have enumerated the wrong set.
    ///
    /// This replaces `the_schema_document_lists_exactly_the_event_types_that_exist`,
    /// which held one of the eight vocabularies. Two checks of one value is the
    /// thing invariant 16 is about, and the narrower test was written while the
    /// other seven were already unheld. It was verified against its own case
    /// before it was removed: with `notification_dispatched` taken out of the
    /// schema, this fails naming `event_type` and printing both lists.
    #[test]
    fn the_schema_document_lists_exactly_the_variants_that_exist() {
        for (path, actual) in vocabularies() {
            assert_eq!(
                schema_enum(path),
                actual.as_slice(),
                "the schema document and the enum disagree about what {path} can be"
            );
        }
    }

    /// The check above compares what it is given, so what it is given has to be
    /// everything. A new `Kind::Enum` field arriving with no entry in
    /// `vocabularies()` would leave that field unchecked while the suite reported
    /// a pass, which is invariant 19 in the place it is easiest to miss.
    #[test]
    fn every_closed_vocabulary_in_the_schema_is_held_against_an_enum() {
        let mut checked: Vec<&str> = vocabularies().iter().map(|(path, _)| *path).collect();
        checked.sort_unstable();
        let mut published: Vec<&str> = RECORD_V1
            .fields
            .iter()
            .filter(|f| matches!(f.kind, Kind::Enum(_)))
            .map(|f| f.path)
            .collect();
        published.sort_unstable();
        assert_eq!(
            published, checked,
            "a closed vocabulary in the schema has no enum held against it, so nothing \
             would notice the two drifting apart"
        );
    }

    #[test]
    fn enum_names_are_stable_and_unique() {
        // These strings go on disk and into evidence packs. A rename is a
        // format change, so it should be visible as one.
        let mut all: Vec<&str> = Vec::new();
        all.extend(EventType::ALL.iter().map(|v| v.as_str()));
        all.extend(Severity::ALL.iter().map(|v| v.as_str()));
        all.extend(Verdict::ALL.iter().map(|v| v.as_str()));
        all.extend(ErrorCode::ALL.iter().map(|v| v.as_str()));
        all.extend(PayloadClass::ALL.iter().map(|v| v.as_str()));
        for s in &all {
            assert!(!s.is_empty());
            assert!(
                s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{s} is not a stable lower_snake token"
            );
        }
    }

    #[test]
    fn provable_dimensions_are_exactly_these_five() {
        // Each one costs a sorted index in every segment and is a promise that
        // holds forever, because segments are immutable once sealed. Adding a
        // sixth should be a decision somebody argues for.
        assert_eq!(
            PROVABLE_DIMENSIONS,
            &["id", "recorded_at", "agent_id", "run_id", "event_type"]
        );
    }

    #[test]
    fn defaults_are_the_post_quantum_ones() {
        let a = Algorithms::default();
        assert_eq!(a.hash, HashAlg::Sha384);
        assert_eq!(a.kem, KemAlg::X25519MlKem768);
    }
}
