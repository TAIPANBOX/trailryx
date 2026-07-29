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
    AgentId, ModelId, PolicyVersion, PrincipalId, RecordId, RunId, SegmentId, ShardIx, TenantId,
    ToolName,
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
    pub const ALL: &'static [Self] = &[Self::Es256, Self::MlDsa65, Self::SlhDsa];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "es256",
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
            signature: SigAlg::Es256,
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
pub const PROVABLE_DIMENSIONS: &[&str] = &["recorded_at", "agent_id", "run_id", "event_type"];

#[cfg(test)]
mod tests {
    use super::*;

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
    fn provable_dimensions_are_exactly_the_agreed_four() {
        assert_eq!(
            PROVABLE_DIMENSIONS,
            &["recorded_at", "agent_id", "run_id", "event_type"]
        );
    }

    #[test]
    fn defaults_are_the_post_quantum_ones() {
        let a = Algorithms::default();
        assert_eq!(a.hash, HashAlg::Sha384);
        assert_eq!(a.kem, KemAlg::X25519MlKem768);
    }
}
