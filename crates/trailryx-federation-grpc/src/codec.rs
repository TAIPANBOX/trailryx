//! Records to the wire and back.
//!
//! The direction that matters is *back*. Encoding our own record is
//! bookkeeping; decoding one that arrived from another environment is the point
//! where somebody else's bytes try to become our metadata, and every identifier
//! goes back through the constructor that guards local ingest rather than
//! straight into the struct.

use crate::pb;
use trailryx_record::{
    AgentId, Algorithms, Basis, ErrorCode, EventType, HASH_BYTES, Hash, HashAlg, KemAlg,
    MapperVersion, ModelId, Outcome, PayloadClass, PayloadRef, PolicyVersion, PrincipalId, Record,
    RecordId, RunId, SegmentId, Severity, ShardIx, SigAlg, TenantId, Timestamp, ToolName,
    Untrusted, Verdict,
};

/// Why a message that arrived could not become a record.
///
/// Carries the field name so a rejected peer produces a diagnosable log line,
/// and never carries the offending value: quoting it back is how the content we
/// refused to store ends up in a log file instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// A constrained identifier did not survive its own parser.
    BadIdentifier { field: &'static str },
    /// A fixed-width field arrived with the wrong number of bytes.
    BadLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    /// An enum arrived as `UNSPECIFIED`, or as a number this version has no
    /// variant for. Refused rather than defaulted: proto3 cannot tell absent
    /// from the first variant, and a record whose event type changed in transit
    /// is worse than one that failed to arrive.
    UnknownEnum { field: &'static str },
    /// A message the schema requires was not present.
    MissingField { field: &'static str },
    /// A number did not fit the width the record declares for it.
    OutOfRange { field: &'static str },
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadIdentifier { field } => {
                write!(f, "{field}: not a legal identifier")
            }
            Self::BadLength {
                field,
                expected,
                got,
            } => write!(f, "{field}: expected {expected} bytes, got {got}"),
            Self::UnknownEnum { field } => write!(f, "{field}: unknown or unspecified variant"),
            Self::MissingField { field } => write!(f, "{field}: required and absent"),
            Self::OutOfRange { field } => write!(f, "{field}: out of range"),
        }
    }
}

impl std::error::Error for WireError {}

/// Length of a record id on the wire: a ULID's 128 bits, big-endian.
const ID_BYTES: usize = 16;

fn hash_to_wire(h: &Hash) -> Vec<u8> {
    h.as_bytes().to_vec()
}

fn hash_from_wire(field: &'static str, bytes: &[u8]) -> Result<Hash, WireError> {
    let array: [u8; HASH_BYTES] = bytes.try_into().map_err(|_| WireError::BadLength {
        field,
        expected: HASH_BYTES,
        got: bytes.len(),
    })?;
    Ok(Hash(array))
}

fn id_to_wire(id: RecordId) -> Vec<u8> {
    id.0.to_be_bytes().to_vec()
}

fn id_from_wire(field: &'static str, bytes: &[u8]) -> Result<RecordId, WireError> {
    let array: [u8; ID_BYTES] = bytes.try_into().map_err(|_| WireError::BadLength {
        field,
        expected: ID_BYTES,
        got: bytes.len(),
    })?;
    Ok(RecordId(u128::from_be_bytes(array)))
}

/// Parse a constrained identifier, discarding the parser's own message.
///
/// The message is dropped on purpose: `IdError::BadChar` names the character it
/// refused, and that character came from another environment. A log line
/// quoting it is the same leak we refused to store.
fn ident<T, E>(field: &'static str, parsed: Result<T, E>) -> Result<T, WireError> {
    parsed.map_err(|_| WireError::BadIdentifier { field })
}

fn narrow_u16(field: &'static str, value: u32) -> Result<u16, WireError> {
    u16::try_from(value).map_err(|_| WireError::OutOfRange { field })
}

// --- enums -----------------------------------------------------------------
//
// Written out rather than derived. A macro would be shorter and would also make
// it possible to add a variant on one side only, which is exactly the change
// these `match`es are here to make impossible to compile.

fn event_type_to_wire(v: EventType) -> pb::EventType {
    match v {
        EventType::RequestReceived => pb::EventType::RequestReceived,
        EventType::ModelCall => pb::EventType::ModelCall,
        EventType::ToolCall => pb::EventType::ToolCall,
        EventType::PolicyDecision => pb::EventType::PolicyDecision,
        EventType::BudgetCheck => pb::EventType::BudgetCheck,
        EventType::MemoryAccess => pb::EventType::MemoryAccess,
        EventType::Delegation => pb::EventType::Delegation,
        EventType::RunCompleted => pb::EventType::RunCompleted,
        EventType::Erasure => pb::EventType::Erasure,
        EventType::StoreEvent => pb::EventType::StoreEvent,
        EventType::NotificationDispatched => pb::EventType::NotificationDispatched,
        EventType::IdentityFinding => pb::EventType::IdentityFinding,
    }
}

fn event_type_from_wire(raw: i32) -> Result<EventType, WireError> {
    const FIELD: &str = "event_type";
    match pb::EventType::try_from(raw) {
        Ok(pb::EventType::RequestReceived) => Ok(EventType::RequestReceived),
        Ok(pb::EventType::ModelCall) => Ok(EventType::ModelCall),
        Ok(pb::EventType::ToolCall) => Ok(EventType::ToolCall),
        Ok(pb::EventType::PolicyDecision) => Ok(EventType::PolicyDecision),
        Ok(pb::EventType::BudgetCheck) => Ok(EventType::BudgetCheck),
        Ok(pb::EventType::MemoryAccess) => Ok(EventType::MemoryAccess),
        Ok(pb::EventType::Delegation) => Ok(EventType::Delegation),
        Ok(pb::EventType::RunCompleted) => Ok(EventType::RunCompleted),
        Ok(pb::EventType::Erasure) => Ok(EventType::Erasure),
        Ok(pb::EventType::StoreEvent) => Ok(EventType::StoreEvent),
        Ok(pb::EventType::NotificationDispatched) => Ok(EventType::NotificationDispatched),
        Ok(pb::EventType::IdentityFinding) => Ok(EventType::IdentityFinding),
        Ok(pb::EventType::Unspecified) | Err(_) => Err(WireError::UnknownEnum { field: FIELD }),
    }
}

fn severity_to_wire(v: Severity) -> pb::Severity {
    match v {
        Severity::Debug => pb::Severity::Debug,
        Severity::Info => pb::Severity::Info,
        Severity::Notice => pb::Severity::Notice,
        Severity::Warning => pb::Severity::Warning,
        Severity::Error => pb::Severity::Error,
        Severity::Critical => pb::Severity::Critical,
    }
}

fn severity_from_wire(raw: i32) -> Result<Severity, WireError> {
    const FIELD: &str = "severity";
    match pb::Severity::try_from(raw) {
        Ok(pb::Severity::Debug) => Ok(Severity::Debug),
        Ok(pb::Severity::Info) => Ok(Severity::Info),
        Ok(pb::Severity::Notice) => Ok(Severity::Notice),
        Ok(pb::Severity::Warning) => Ok(Severity::Warning),
        Ok(pb::Severity::Error) => Ok(Severity::Error),
        Ok(pb::Severity::Critical) => Ok(Severity::Critical),
        Ok(pb::Severity::Unspecified) | Err(_) => Err(WireError::UnknownEnum { field: FIELD }),
    }
}

fn verdict_to_wire(v: Verdict) -> pb::Verdict {
    match v {
        Verdict::Allowed => pb::Verdict::Allowed,
        Verdict::Denied => pb::Verdict::Denied,
        Verdict::Held => pb::Verdict::Held,
        Verdict::Failed => pb::Verdict::Failed,
        Verdict::NotApplicable => pb::Verdict::NotApplicable,
    }
}

fn verdict_from_wire(raw: i32) -> Result<Verdict, WireError> {
    const FIELD: &str = "outcome.verdict";
    match pb::Verdict::try_from(raw) {
        Ok(pb::Verdict::Allowed) => Ok(Verdict::Allowed),
        Ok(pb::Verdict::Denied) => Ok(Verdict::Denied),
        Ok(pb::Verdict::Held) => Ok(Verdict::Held),
        Ok(pb::Verdict::Failed) => Ok(Verdict::Failed),
        Ok(pb::Verdict::NotApplicable) => Ok(Verdict::NotApplicable),
        Ok(pb::Verdict::Unspecified) | Err(_) => Err(WireError::UnknownEnum { field: FIELD }),
    }
}

fn error_code_to_wire(v: ErrorCode) -> pb::ErrorCode {
    match v {
        ErrorCode::None => pb::ErrorCode::None,
        ErrorCode::Timeout => pb::ErrorCode::Timeout,
        ErrorCode::RateLimited => pb::ErrorCode::RateLimited,
        ErrorCode::Unauthorized => pb::ErrorCode::Unauthorized,
        ErrorCode::BudgetExceeded => pb::ErrorCode::BudgetExceeded,
        ErrorCode::PolicyDenied => pb::ErrorCode::PolicyDenied,
        ErrorCode::UpstreamError => pb::ErrorCode::UpstreamError,
        ErrorCode::Malformed => pb::ErrorCode::Malformed,
        ErrorCode::Internal => pb::ErrorCode::Internal,
    }
}

fn error_code_from_wire(raw: i32) -> Result<ErrorCode, WireError> {
    const FIELD: &str = "outcome.error";
    match pb::ErrorCode::try_from(raw) {
        Ok(pb::ErrorCode::None) => Ok(ErrorCode::None),
        Ok(pb::ErrorCode::Timeout) => Ok(ErrorCode::Timeout),
        Ok(pb::ErrorCode::RateLimited) => Ok(ErrorCode::RateLimited),
        Ok(pb::ErrorCode::Unauthorized) => Ok(ErrorCode::Unauthorized),
        Ok(pb::ErrorCode::BudgetExceeded) => Ok(ErrorCode::BudgetExceeded),
        Ok(pb::ErrorCode::PolicyDenied) => Ok(ErrorCode::PolicyDenied),
        Ok(pb::ErrorCode::UpstreamError) => Ok(ErrorCode::UpstreamError),
        Ok(pb::ErrorCode::Malformed) => Ok(ErrorCode::Malformed),
        Ok(pb::ErrorCode::Internal) => Ok(ErrorCode::Internal),
        Ok(pb::ErrorCode::Unspecified) | Err(_) => Err(WireError::UnknownEnum { field: FIELD }),
    }
}

fn payload_class_to_wire(v: PayloadClass) -> pb::PayloadClass {
    match v {
        PayloadClass::Prompt => pb::PayloadClass::Prompt,
        PayloadClass::Completion => pb::PayloadClass::Completion,
        PayloadClass::ToolArguments => pb::PayloadClass::ToolArguments,
        PayloadClass::ToolResult => pb::PayloadClass::ToolResult,
        PayloadClass::Document => pb::PayloadClass::Document,
        PayloadClass::Diagnostic => pb::PayloadClass::Diagnostic,
    }
}

fn payload_class_from_wire(raw: i32) -> Result<PayloadClass, WireError> {
    const FIELD: &str = "payload.class";
    match pb::PayloadClass::try_from(raw) {
        Ok(pb::PayloadClass::Prompt) => Ok(PayloadClass::Prompt),
        Ok(pb::PayloadClass::Completion) => Ok(PayloadClass::Completion),
        Ok(pb::PayloadClass::ToolArguments) => Ok(PayloadClass::ToolArguments),
        Ok(pb::PayloadClass::ToolResult) => Ok(PayloadClass::ToolResult),
        Ok(pb::PayloadClass::Document) => Ok(PayloadClass::Document),
        Ok(pb::PayloadClass::Diagnostic) => Ok(PayloadClass::Diagnostic),
        Ok(pb::PayloadClass::Unspecified) | Err(_) => Err(WireError::UnknownEnum { field: FIELD }),
    }
}

fn hash_alg_to_wire(v: HashAlg) -> pb::HashAlg {
    match v {
        HashAlg::Sha384 => pb::HashAlg::Sha384,
    }
}

fn hash_alg_from_wire(raw: i32) -> Result<HashAlg, WireError> {
    const FIELD: &str = "algorithms.hash";
    match pb::HashAlg::try_from(raw) {
        Ok(pb::HashAlg::Sha384) => Ok(HashAlg::Sha384),
        Ok(pb::HashAlg::Unspecified) | Err(_) => Err(WireError::UnknownEnum { field: FIELD }),
    }
}

fn sig_alg_to_wire(v: SigAlg) -> pb::SigAlg {
    match v {
        SigAlg::Es256 => pb::SigAlg::Es256,
        SigAlg::Es384 => pb::SigAlg::Es384,
        SigAlg::MlDsa65 => pb::SigAlg::MlDsa65,
        SigAlg::SlhDsa => pb::SigAlg::SlhDsa,
    }
}

fn sig_alg_from_wire(raw: i32) -> Result<SigAlg, WireError> {
    const FIELD: &str = "algorithms.signature";
    match pb::SigAlg::try_from(raw) {
        Ok(pb::SigAlg::Es256) => Ok(SigAlg::Es256),
        Ok(pb::SigAlg::Es384) => Ok(SigAlg::Es384),
        Ok(pb::SigAlg::MlDsa65) => Ok(SigAlg::MlDsa65),
        Ok(pb::SigAlg::SlhDsa) => Ok(SigAlg::SlhDsa),
        Ok(pb::SigAlg::Unspecified) | Err(_) => Err(WireError::UnknownEnum { field: FIELD }),
    }
}

fn kem_alg_to_wire(v: KemAlg) -> pb::KemAlg {
    match v {
        KemAlg::X25519MlKem768 => pb::KemAlg::X25519MlKem768,
    }
}

fn kem_alg_from_wire(raw: i32) -> Result<KemAlg, WireError> {
    const FIELD: &str = "algorithms.kem";
    match pb::KemAlg::try_from(raw) {
        Ok(pb::KemAlg::X25519MlKem768) => Ok(KemAlg::X25519MlKem768),
        Ok(pb::KemAlg::Unspecified) | Err(_) => Err(WireError::UnknownEnum { field: FIELD }),
    }
}

// --- records ---------------------------------------------------------------

/// Our record, as it goes out.
pub fn to_wire(record: &Record) -> pb::Record {
    pb::Record {
        id: id_to_wire(record.id),
        tenant: record.tenant.as_str().to_owned(),
        shard: u32::from(record.shard.0),
        agent_id: record.agent_id.as_str().to_owned(),
        run_id: record.run_id.as_str().to_owned(),
        parent_run_id: record.parent_run_id.as_ref().map(|r| r.as_str().to_owned()),
        on_behalf_of: record
            .on_behalf_of
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect(),
        occurred_at: record.occurred_at.as_untrusted().as_nanos(),
        decided_at: record.decided_at.map(|t| t.into_untrusted().as_nanos()),
        recorded_at: record.recorded_at.as_nanos(),
        knowledge_as_of: record.knowledge_as_of.map(Timestamp::as_nanos),
        clock_skew_nanos: record.clock_skew_nanos,
        event_type: event_type_to_wire(record.event_type).into(),
        severity: severity_to_wire(record.severity).into(),
        basis: Some(pb::Basis {
            policy_version: record
                .basis
                .policy_version
                .as_ref()
                .map(|v| v.as_str().to_owned()),
            budget_remaining_micros: record.basis.budget_remaining_micros,
            memory_ref: record.basis.memory_ref.as_ref().map(hash_to_wire),
            model: record.basis.model.as_ref().map(|m| m.as_str().to_owned()),
            temperature_milli: record.basis.temperature_milli.map(u32::from),
            max_tokens: record.basis.max_tokens,
            prompt_hash: record.basis.prompt_hash.as_ref().map(hash_to_wire),
            tool_manifest: record
                .basis
                .tool_manifest
                .iter()
                .map(|t| t.as_str().to_owned())
                .collect(),
            identity_chain: record
                .basis
                .identity_chain
                .iter()
                .map(|p| p.as_str().to_owned())
                .collect(),
        }),
        caused_by: record.caused_by.iter().copied().map(id_to_wire).collect(),
        outcome: Some(pb::Outcome {
            verdict: record.outcome.verdict.map(|v| verdict_to_wire(v).into()),
            error: record.outcome.error.map(|e| error_code_to_wire(e).into()),
            latency_micros: record.outcome.latency_micros,
            tokens_in: record.outcome.tokens_in,
            tokens_out: record.outcome.tokens_out,
            cost_micros: record.outcome.cost_micros,
        }),
        payload: record.payload.as_ref().map(|p| pb::PayloadRef {
            hash: hash_to_wire(&p.hash),
            size_bytes: p.size_bytes,
            class: payload_class_to_wire(p.class).into(),
            key_id: hash_to_wire(&p.key_id),
        }),
        seq: record.seq,
        prev_hash: hash_to_wire(&record.prev_hash),
        segment_id: record.segment_id.0,
        algorithms: Some(pb::Algorithms {
            hash: hash_alg_to_wire(record.algorithms.hash).into(),
            signature: sig_alg_to_wire(record.algorithms.signature).into(),
            kem: kem_alg_to_wire(record.algorithms.kem).into(),
        }),
        mapper: u32::from(record.mapper.0),
    }
}

/// Somebody else's bytes, as they try to become a record.
///
/// Every identifier goes back through the constructor that guards local ingest.
/// That is the whole reason this is a `Result`: the alternative is a struct
/// literal, and a struct literal would let a peer put a paragraph of somebody's
/// medical history where a run id belongs.
pub fn from_wire(wire: pb::Record) -> Result<Record, WireError> {
    let basis = wire
        .basis
        .ok_or(WireError::MissingField { field: "basis" })?;
    let outcome = wire
        .outcome
        .ok_or(WireError::MissingField { field: "outcome" })?;
    let algorithms = wire.algorithms.ok_or(WireError::MissingField {
        field: "algorithms",
    })?;

    Ok(Record {
        id: id_from_wire("id", &wire.id)?,
        tenant: ident("tenant", TenantId::parse(wire.tenant))?,
        shard: ShardIx(narrow_u16("shard", wire.shard)?),
        // `parse_strict`, not `parse`, and the difference is the whole point of
        // this line. The journal reads its own records back with the lax
        // constructor because it wrote them; `trailryx-otlp` uses the strict one
        // at the door because those records came from outside. A peer is
        // outside.
        agent_id: ident("agent_id", AgentId::parse_strict(wire.agent_id))?,
        run_id: ident("run_id", RunId::parse(wire.run_id))?,
        parent_run_id: wire
            .parent_run_id
            .map(|r| ident("parent_run_id", RunId::parse(r)))
            .transpose()?,
        on_behalf_of: wire
            .on_behalf_of
            .into_iter()
            .map(|p| ident("on_behalf_of", PrincipalId::parse(p)))
            .collect::<Result<_, _>>()?,
        occurred_at: Untrusted::new(Timestamp(wire.occurred_at)),
        decided_at: wire.decided_at.map(|t| Untrusted::new(Timestamp(t))),
        recorded_at: Timestamp(wire.recorded_at),
        knowledge_as_of: wire.knowledge_as_of.map(Timestamp),
        clock_skew_nanos: wire.clock_skew_nanos,
        event_type: event_type_from_wire(wire.event_type)?,
        severity: severity_from_wire(wire.severity)?,
        basis: Basis {
            policy_version: basis
                .policy_version
                .map(|v| ident("basis.policy_version", PolicyVersion::parse(v)))
                .transpose()?,
            budget_remaining_micros: basis.budget_remaining_micros,
            memory_ref: basis
                .memory_ref
                .map(|h| hash_from_wire("basis.memory_ref", &h))
                .transpose()?,
            model: basis
                .model
                .map(|m| ident("basis.model", ModelId::parse(m)))
                .transpose()?,
            temperature_milli: basis
                .temperature_milli
                .map(|t| narrow_u16("basis.temperature_milli", t))
                .transpose()?,
            max_tokens: basis.max_tokens,
            prompt_hash: basis
                .prompt_hash
                .map(|h| hash_from_wire("basis.prompt_hash", &h))
                .transpose()?,
            tool_manifest: basis
                .tool_manifest
                .into_iter()
                .map(|t| ident("basis.tool_manifest", ToolName::parse(t)))
                .collect::<Result<_, _>>()?,
            identity_chain: basis
                .identity_chain
                .into_iter()
                .map(|p| ident("basis.identity_chain", PrincipalId::parse(p)))
                .collect::<Result<_, _>>()?,
        },
        caused_by: wire
            .caused_by
            .iter()
            .map(|b| id_from_wire("caused_by", b))
            .collect::<Result<_, _>>()?,
        outcome: Outcome {
            verdict: outcome.verdict.map(verdict_from_wire).transpose()?,
            error: outcome.error.map(error_code_from_wire).transpose()?,
            latency_micros: outcome.latency_micros,
            tokens_in: outcome.tokens_in,
            tokens_out: outcome.tokens_out,
            cost_micros: outcome.cost_micros,
        },
        payload: wire
            .payload
            .map(|p| {
                Ok(PayloadRef {
                    hash: hash_from_wire("payload.hash", &p.hash)?,
                    size_bytes: p.size_bytes,
                    class: payload_class_from_wire(p.class)?,
                    key_id: hash_from_wire("payload.key_id", &p.key_id)?,
                })
            })
            .transpose()?,
        seq: wire.seq,
        prev_hash: hash_from_wire("prev_hash", &wire.prev_hash)?,
        segment_id: SegmentId(wire.segment_id),
        algorithms: Algorithms {
            hash: hash_alg_from_wire(algorithms.hash)?,
            signature: sig_alg_from_wire(algorithms.signature)?,
            kem: kem_alg_from_wire(algorithms.kem)?,
        },
        mapper: MapperVersion(narrow_u16("mapper", wire.mapper)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_record::{
        AgentId, Algorithms, Basis, ErrorCode, EventType, Hash, HashAlg, KemAlg, MapperVersion,
        ModelId, Outcome, PayloadClass, PayloadRef, PolicyVersion, PrincipalId, RecordId, RunId,
        SegmentId, Severity, ShardIx, SigAlg, TenantId, Timestamp, ToolName, Untrusted, Verdict,
    };

    /// A record with **every** field set to something distinctive.
    ///
    /// Deliberately not the minimal record the other suites build. A round trip
    /// over a struct left mostly at its defaults proves the defaults survive,
    /// which is the one thing that would still hold if half the encoder were
    /// deleted.
    fn a_fully_populated_record() -> Record {
        Record {
            id: RecordId(0x0123_4567_89ab_cdef_fedc_ba98_7654_3210),
            tenant: TenantId::parse("acme-bank").expect("a tenant"),
            shard: ShardIx(7),
            agent_id: AgentId::parse_strict("agent://acme-bank.example/support/tier1")
                .expect("an agent"),
            run_id: RunId::parse("run-2026-08-04-abc").expect("a run"),
            parent_run_id: Some(RunId::parse("run-parent").expect("a parent run")),
            on_behalf_of: vec![
                PrincipalId::parse("user://acme-bank.example/ivan").expect("a principal"),
                PrincipalId::parse("agent://acme-bank.example/orchestrator").expect("a principal"),
            ],
            occurred_at: Untrusted::new(Timestamp(1_754_300_000_000_000_001)),
            decided_at: Some(Untrusted::new(Timestamp(1_754_300_000_000_000_002))),
            recorded_at: Timestamp(1_754_300_000_000_000_003),
            knowledge_as_of: Some(Timestamp(1_754_300_000_000_000_004)),
            clock_skew_nanos: Some(4_200_000_000),
            event_type: EventType::PolicyDecision,
            severity: Severity::Critical,
            basis: Basis {
                policy_version: Some(PolicyVersion::parse("v17.3").expect("a policy version")),
                budget_remaining_micros: Some(-12_345_678),
                memory_ref: Some(Hash([0x11; 48])),
                model: Some(ModelId::parse("anthropic/claude-opus-5").expect("a model")),
                temperature_milli: Some(700),
                max_tokens: Some(4096),
                prompt_hash: Some(Hash([0x22; 48])),
                tool_manifest: vec![
                    ToolName::parse("ledger.read").expect("a tool"),
                    ToolName::parse("ledger.write").expect("a tool"),
                ],
                identity_chain: vec![
                    PrincipalId::parse("user://acme-bank.example/ivan").expect("a principal"),
                ],
            },
            caused_by: vec![RecordId(1), RecordId(u128::MAX)],
            outcome: Outcome {
                verdict: Some(Verdict::Held),
                error: Some(ErrorCode::BudgetExceeded),
                latency_micros: Some(98_765),
                tokens_in: Some(1_024),
                tokens_out: Some(2_048),
                cost_micros: Some(-99),
            },
            payload: Some(PayloadRef {
                hash: Hash([0x33; 48]),
                size_bytes: 65_536,
                class: PayloadClass::ToolArguments,
                key_id: Hash([0x44; 48]),
            }),
            seq: 9_876_543_210,
            prev_hash: Hash([0x55; 48]),
            segment_id: SegmentId(4_242),
            algorithms: Algorithms {
                hash: HashAlg::Sha384,
                signature: SigAlg::MlDsa65,
                kem: KemAlg::X25519MlKem768,
            },
            mapper: MapperVersion(9),
        }
    }

    /// The whole record, not the parts of it somebody remembered to encode.
    #[test]
    fn a_record_survives_the_wire_unchanged() {
        let original = a_fully_populated_record();
        let decoded = from_wire(to_wire(&original)).expect("a record we encoded ourselves decodes");
        assert_eq!(decoded, original);
    }

    /// Every event type, both ways, from the list rather than from a copy of it.
    ///
    /// What the compiler already holds is that both matches name every variant:
    /// the decoder's last arm spells `Unspecified` and `Err(_)` rather than using
    /// a wildcard, so a variant missing from either side is a build failure, and
    /// removing this test's own subject from the decoder was checked to be one.
    ///
    /// What it does not hold, and what this test is for, is that the two names on
    /// each line are the same name. `EventType::NotificationDispatched =>
    /// pb::EventType::StoreEvent` compiles perfectly, and a record would arrive
    /// at a peer as a different kind of event: a wrong event type, believed,
    /// which is the failure the whole mapping vocabulary is arranged against.
    #[test]
    fn every_event_type_this_build_writes_is_one_it_can_read_back() {
        for event_type in EventType::ALL {
            let mut record = a_fully_populated_record();
            record.event_type = *event_type;
            let decoded = from_wire(to_wire(&record)).unwrap_or_else(|e| {
                panic!("{} did not survive the wire: {e:?}", event_type.as_str())
            });
            assert_eq!(decoded.event_type, *event_type);
        }
    }

    /// The federation port is an outside door, so it owes the same check the
    /// other outside door owes.
    ///
    /// `trailryx-otlp` parses an arriving agent id with `parse_strict`;
    /// `trailryx-journal` uses the lax `parse` because it is reading back what
    /// we ourselves wrote. A peer is the first case wearing the second's
    /// clothes: the bytes look like a record we stored, and they came from
    /// somebody else's machine.
    #[test]
    fn an_agent_id_that_is_not_a_uri_is_refused_the_way_the_ingest_door_refuses_it() {
        let mut wire = to_wire(&a_fully_populated_record());
        wire.agent_id = "support-tier1".to_owned();

        assert_eq!(
            from_wire(wire),
            Err(WireError::BadIdentifier { field: "agent_id" }),
            "a bare token is not an agent://<domain>/<path> and the ingest path already says so"
        );
    }

    /// The plane boundary, at the one door that had not been built yet.
    ///
    /// This passes by construction rather than by a check somebody remembered:
    /// the identifier types keep their `String` private, so `parse` is the only
    /// way to build one and there is no unchecked path for a decoder to take by
    /// mistake. The test is here to make that structural fact visible, and it
    /// would start failing the day somebody adds a `from_unchecked`.
    #[test]
    fn a_prompt_cannot_arrive_from_a_peer_in_place_of_an_identifier() {
        let mut wire = to_wire(&a_fully_populated_record());
        wire.run_id = "Please summarise Ivan Petrenko's medical report".to_owned();

        assert_eq!(
            from_wire(wire),
            Err(WireError::BadIdentifier { field: "run_id" })
        );
    }

    /// Proto3 cannot distinguish "absent" from "the first variant", so a record
    /// whose event type did not survive encoding would arrive as a different
    /// kind of event rather than as a failure.
    #[test]
    fn an_unspecified_enum_is_refused_rather_than_read_as_the_first_variant() {
        let mut wire = to_wire(&a_fully_populated_record());
        wire.event_type = 0;

        assert_eq!(
            from_wire(wire),
            Err(WireError::UnknownEnum {
                field: "event_type"
            })
        );
    }

    /// A variant this build has no name for. Refused, because the alternative is
    /// to guess, and a guessed severity is a record that means something else.
    #[test]
    fn an_enum_from_a_newer_peer_is_refused_rather_than_guessed() {
        let mut wire = to_wire(&a_fully_populated_record());
        wire.severity = 9_999;

        assert_eq!(
            from_wire(wire),
            Err(WireError::UnknownEnum { field: "severity" })
        );
    }

    /// A truncated hash that silently became a different hash would break every
    /// chain check downstream, and would do it quietly.
    #[test]
    fn a_hash_of_the_wrong_length_is_refused() {
        let mut wire = to_wire(&a_fully_populated_record());
        wire.prev_hash = vec![0x55; 47];

        assert_eq!(
            from_wire(wire),
            Err(WireError::BadLength {
                field: "prev_hash",
                expected: 48,
                got: 47
            })
        );
    }
}
