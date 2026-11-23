//! The OpenTelemetry GenAI semantic-convention mapper.
//!
//! # What this buys, and what it does not
//!
//! An agent instrumented with a stock OpenTelemetry SDK writes here without a
//! line of change in it. That is the whole point of stage 6 and it is worth
//! having. It is also worth being precise about what arrives, because the
//! honest answer sells the product better than the flattering one.
//!
//! A span says a model was called, how long it took and what it cost. It does
//! **not** say on what grounds the call was allowed: no policy version, no
//! budget state, no memory reference. Those fields exist in
//! [`trailryx_record::Basis`] because they are what an auditor asks about, and
//! OTLP has no attribute for any of them. So an OTLP-sourced record has a
//! partial basis, always, and the gap is not a defect in this mapper: it is the
//! difference between telemetry and evidence, and it is the reason the store
//! has an envelope of its own.
//!
//! # The rule that decides every hard case
//!
//! An attribute goes into a typed metadata field only if it parses into one.
//! Everything else goes to the payload plane. Not "mostly", not "unless it
//! looks harmless": a mapper that does not recognise something must never
//! decide it is safe, because unrecognised OpenTelemetry attributes routinely
//! contain prompts and personal data.
//!
//! The consequence is stated as an invariant and tested as one: **every
//! attribute lands in exactly one plane.** Never both, which would leave a copy
//! of content in metadata that erasure cannot reach; never neither, which would
//! be a silent loss.
//!
//! # Nothing is repaired
//!
//! A value that does not fit its field is not coerced, lowercased or rounded.
//! It stays where it can do no harm, in the payload, and the typed field stays
//! empty. Repairing an identifier would merge two agents; rounding a number
//! would change what was recorded. Both are worse than an absent field.
//!
//! # Source
//!
//! Attribute names follow the OpenTelemetry GenAI semantic conventions, which
//! moved to their own repository in semconv v1.42.0 (12 June 2026) and remain
//! Development status: the `gen_ai.*` names can still change. That is why
//! [`MAPPER_VERSION`] is recorded on every record. When the conventions move,
//! old records keep saying which reading produced them, and nobody has to guess
//! whether a 2026 record used `gen_ai.system` or `gen_ai.provider.name`.

use crate::otlp::{Attr, Span, StatusCode, Value};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use trailryx_contracts::ingest::{Correlation, Cursor, Ingest, MetaDraft, PayloadPart, SourceKey};
use trailryx_crypto::Sha384;
use trailryx_record::{
    AgentId, Basis, ErrorCode, EventType, MapperVersion, ModelId, PayloadClass, RunId, Severity,
    TenantId, Timestamp, ToolName, Untrusted, Verdict,
};

/// Which reading of the conventions produced a record.
///
/// Bumped whenever a mapping decision changes, never silently. The value lives
/// on the record so a future reader can tell what a field meant when it was
/// written, which matters most for conventions that are still moving.
///
/// Version 2 stopped treating an all-zero `span_id` or `parent_span_id` as a
/// name. OTLP defines those as invalid and emitters do write them out rather than
/// omitting the field, so version 1 manufactured causal edges from them and
/// reclassified unrelated roots as delegations. A record stamped 1 may carry an
/// edge that was never named.
///
/// Version 3 lets a span that names no agent take the agent its trace names
/// (see [`TraceAgents`]). Version 2 filed such a span under the resource's
/// `service.name`, so one run of one agent appeared under two agent ids when an
/// SDK put `gen_ai.agent.name` on some spans and not on the root (issue #80). A
/// record stamped 2 whose agent came from `service.name` may name the service
/// rather than the agent the rest of its run names.
pub const MAPPER_VERSION: MapperVersion = MapperVersion(3);

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// What the operator asserts, because the wire cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapperConfig {
    tenant: TenantId,
    trust_domain: String,
    default_agent: AgentId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    BadTrustDomain,
    BadDefaultAgent,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadTrustDomain => write!(f, "trust domain is not a valid identifier segment"),
            Self::BadDefaultAgent => write!(f, "default agent is not a valid agent URI"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl MapperConfig {
    /// Both the tenant and the trust domain are configuration, never wire data.
    ///
    /// A source that could name its own tenant could write into somebody
    /// else's records, and a source that could name its own trust domain could
    /// impersonate any agent in the estate. Neither is a field a receiver reads
    /// from the network, which is why neither is a parameter of [`map_span`].
    ///
    /// Validated here so a misconfiguration fails when the receiver starts, not
    /// at three in the morning against live traffic.
    pub fn new(tenant: TenantId, trust_domain: &str) -> Result<Self, ConfigError> {
        let default_agent = AgentId::parse_strict(format!("agent://{trust_domain}/unattributed"))
            .map_err(|_| ConfigError::BadTrustDomain)?;
        Ok(Self {
            tenant,
            trust_domain: trust_domain.to_owned(),
            default_agent,
        })
    }

    /// Where spans go when nothing in them names an agent we can index.
    ///
    /// Setting this is what turns "some spans are rejected" into "no spans are
    /// lost". A deployment that leaves it at the default still records
    /// everything; it just attributes it to one bucket, visibly.
    pub fn with_default_agent(mut self, agent: AgentId) -> Self {
        self.default_agent = agent;
        self
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// Why a span produced no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// No `gen_ai.operation.name`. An ordinary HTTP or database span, which
    /// this store has no business turning into an agent decision record.
    NotGenAi,
    /// A GenAI span naming an operation this mapper version does not know.
    /// Deliberately not mapped to something adjacent: a wrong event type is
    /// worse than a missing record, because it is believed.
    UnknownOperation,
    /// No trace id, so nothing to call the run.
    NoRunId,
    /// Nothing in the span or its resource parses as an agent identifier, and
    /// the deployment set no default.
    NoAgent,
    /// The span names an agent other than the one whose own verified token
    /// carried the batch. Never produced by [`map_span`], which does not know
    /// who is calling: [`crate::OtlpSource::accept_as`] does, and refuses here.
    NotTheCaller,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotGenAi => write!(f, "not a GenAI span"),
            Self::UnknownOperation => write!(f, "unknown gen_ai.operation.name"),
            Self::NoRunId => write!(f, "no trace id"),
            Self::NoAgent => write!(f, "no usable agent identifier"),
            Self::NotTheCaller => write!(f, "names an agent other than the caller"),
        }
    }
}

/// What a batch cost, in records that do not exist.
///
/// Kept as counts rather than logged and forgotten: an operator who cannot see
/// what was dropped will assume nothing was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Report {
    pub mapped: u32,
    pub not_genai: u32,
    pub unknown_operation: u32,
    pub no_run_id: u32,
    pub no_agent: u32,
    /// Spans refused because they named an agent other than the authenticated
    /// caller. A loss like the three above it, and written down twice: here,
    /// with every other loss, and as a record under the caller's own name.
    pub not_the_caller: u32,
    /// Spans whose own clock disagreed with ours by more than
    /// [`trailryx_record::CLOCK_SKEW_THRESHOLD_NANOS`].
    ///
    /// Not a loss: the record is written either way, with both times. It is an
    /// anomaly, and one worth surfacing, because a fleet whose clocks have
    /// drifted produces an audit trail whose ordering cannot be defended.
    pub excessive_skew: u32,
}

impl Report {
    pub fn note(&mut self, rejection: Rejection) {
        let slot = match rejection {
            Rejection::NotGenAi => &mut self.not_genai,
            Rejection::UnknownOperation => &mut self.unknown_operation,
            Rejection::NoRunId => &mut self.no_run_id,
            Rejection::NoAgent => &mut self.no_agent,
            Rejection::NotTheCaller => &mut self.not_the_caller,
        };
        *slot = slot.saturating_add(1);
    }

    /// Spans that arrived and produced nothing.
    ///
    /// `not_genai` is excluded: a database span in the same stream is not a
    /// loss, it is traffic that was never ours.
    pub fn lost(&self) -> u32 {
        self.unknown_operation
            .saturating_add(self.no_run_id)
            .saturating_add(self.no_agent)
            .saturating_add(self.not_the_caller)
    }
}

// ---------------------------------------------------------------------------
// The convention
// ---------------------------------------------------------------------------

const OPERATION: &str = "gen_ai.operation.name";

/// Attributes whose values are content, and the class each one is.
///
/// This table is the plane boundary in its most literal form. Anything named
/// here is content by definition and never reaches the metadata plane, however
/// harmless a particular value looks.
const CONTENT: &[(&str, PayloadClass)] = &[
    ("gen_ai.input.messages", PayloadClass::Prompt),
    ("gen_ai.system_instructions", PayloadClass::Prompt),
    ("gen_ai.prompt.variable", PayloadClass::Prompt),
    ("gen_ai.output.messages", PayloadClass::Completion),
    ("gen_ai.tool.call.arguments", PayloadClass::ToolArguments),
    ("gen_ai.tool.definitions", PayloadClass::ToolArguments),
    ("gen_ai.tool.call.result", PayloadClass::ToolResult),
    ("gen_ai.retrieval.documents", PayloadClass::Document),
    ("gen_ai.memory.records", PayloadClass::Document),
    ("gen_ai.retrieval.query.text", PayloadClass::Prompt),
    ("gen_ai.memory.query.text", PayloadClass::Prompt),
];

fn event_type_for(operation: &str, has_parent: bool) -> Option<EventType> {
    Some(match operation {
        // Inference, in all the shapes the conventions give it.
        "chat" | "generate_content" | "text_completion" | "embeddings" => EventType::ModelCall,
        "execute_tool" => EventType::ToolCall,
        // An agent invoked from nothing is a request arriving. The same
        // operation nested inside another span is one agent handing work to
        // another, which is the delegation an auditor follows.
        "invoke_agent" | "invoke_workflow" | "create_agent" | "plan" => {
            if has_parent {
                EventType::Delegation
            } else {
                EventType::RequestReceived
            }
        }
        // Reading or writing a knowledge store, whatever it is called.
        // Retrieval belongs here rather than in a category of its own: what
        // matters to an auditor is that the agent consulted something outside
        // itself before deciding.
        "retrieval"
        | "search_memory"
        | "create_memory"
        | "update_memory"
        | "upsert_memory"
        | "delete_memory"
        | "create_memory_store"
        | "delete_memory_store" => EventType::MemoryAccess,
        _ => return None,
    })
}

/// `error.type` is a free-text field in practice: SDKs put exception class
/// names in it. Only the shapes we recognise become codes; the string itself
/// goes to the payload plane with everything else unrecognised.
///
/// Separators are stripped before matching, because the same condition arrives
/// as `RateLimitError`, `rate_limit_exceeded` and `RATE-LIMITED` depending on
/// whose library is talking. Matching the letters and not the punctuation is
/// the difference between a code and an `UpstreamError` shrug.
fn error_code_for(raw: &str) -> ErrorCode {
    let flat: String = raw
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let has = |needle: &str| flat.contains(needle);

    if has("timeout") || has("timedout") || has("deadlineexceeded") {
        ErrorCode::Timeout
    } else if has("429") || has("ratelimit") || has("toomanyrequests") {
        ErrorCode::RateLimited
    } else if has("401")
        || has("403")
        || has("unauthor")
        || has("authenticat")
        || has("forbidden")
        || has("permissiondenied")
    {
        ErrorCode::Unauthorized
    } else if has("quota") || has("budget") || has("insufficient") {
        ErrorCode::BudgetExceeded
    } else if has("400") || has("invalidrequest") || has("validation") {
        ErrorCode::Malformed
    } else {
        ErrorCode::UpstreamError
    }
}

// ---------------------------------------------------------------------------
// The mapping
// ---------------------------------------------------------------------------

/// Map one span into one ingest unit.
///
/// One span in, at most one record out. Nothing is synthesised: a root span
/// does not also produce a "run completed" record, because inventing records is
/// how a store stops being evidence.
///
/// A pure function of the span, deliberately. It does not take `recorded_at`
/// and could not use one: that timestamp is the store's own, assigned when the
/// record is written, and the gap between it and the emitter's clock is
/// assessed where both are known. A mapper that stamped a time would be a
/// mapper that could get it wrong.
///
/// `trace_agent` is the one agent the span's trace names elsewhere, from
/// [`TraceAgents::agent_for`], or `None`. It is used only when the span names no
/// agent of its own, and it ranks above the resource's `service.name`.
pub fn map_span(
    cfg: &MapperConfig,
    resource: &[Attr],
    scope_name: &str,
    span: &Span,
    trace_agent: Option<&AgentId>,
    cursor: Cursor,
) -> Result<Ingest, Rejection> {
    let operation = span
        .attr(OPERATION)
        .and_then(Value::as_str)
        .ok_or(Rejection::NotGenAi)?
        .to_owned();
    let event_type = event_type_for(&operation, span.has_parent()).ok_or(
        // The operation is named and we do not know it. Refusing costs one
        // record; guessing costs the credibility of every record like it.
        Rejection::UnknownOperation,
    )?;

    let run_id = run_id_from(&span.trace_id).ok_or(Rejection::NoRunId)?;

    // Keys consumed by a typed field or a classified payload part. What is left
    // over at the end is, by definition, what this version did not understand.
    let mut consumed: BTreeSet<&str> = BTreeSet::new();
    consumed.insert(OPERATION);

    let agent_id = agent_from(cfg, resource, span, trace_agent, &mut consumed);

    let basis = basis_from(span, &mut consumed);
    let (verdict, error) = outcome_from(span, &mut consumed);
    let (tokens_in, tokens_out) = tokens_from(span, &mut consumed);

    let meta = MetaDraft {
        mapper: MAPPER_VERSION,
        tenant: cfg.tenant.clone(),
        agent_id,
        run_id,
        // OTLP has no notion of one run being the child of another. A trace is
        // a trace. `gen_ai.conversation.id` is not this either: a conversation
        // outlives a run and contains many. Left empty rather than filled with
        // something that would read as a delegation and is not one.
        parent_run_id: None,
        // Nor does OTLP carry a delegation chain, so there is no principal to
        // record and no chain to verify.
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(span.start_time_unix_nano)),
        decided_at: end_time(span).map(Untrusted::new),
        event_type,
        severity: if span.status_code == StatusCode::Error {
            Severity::Error
        } else {
            Severity::Info
        },
        basis,
        verdict,
        error,
        latency_micros: latency_micros(span),
        tokens_in,
        tokens_out,
        // No convention carries money. Cost is computed from tokens and a price
        // list, and a price list is not telemetry.
        cost_micros: None,
    };

    let payload = payload_from(span, scope_name, &consumed);

    Ok(Ingest {
        meta,
        payload,
        correlation: correlation_from(span),
        cursor,
    })
}

/// A trace id, lowercase hex, as the run identifier.
///
/// Hex rather than the raw bytes because a run id is indexed and compared as a
/// token, and because the same value in a log line and in a record should be
/// recognisably the same value.
fn run_id_from(trace_id: &[u8]) -> Option<RunId> {
    if trace_id.is_empty() || trace_id.iter().all(|b| *b == 0) {
        return None;
    }
    let mut hex = String::with_capacity(trace_id.len() * 2);
    for byte in trace_id {
        hex.push(char::from_digit((byte >> 4) as u32, 16)?);
        hex.push(char::from_digit((byte & 0x0f) as u32, 16)?);
    }
    RunId::parse(hex).ok()
}

/// The first candidate that parses as an agent identifier, else the default.
///
/// Order matters: an explicit agent id beats a human-readable agent name, which
/// beats the one agent the rest of the span's trace names, which beats the
/// service that emitted the span. A candidate that does not parse is **not**
/// repaired into one, and the attribute it came from stays unconsumed, so its
/// value reaches the payload plane instead of being dropped. The trace's agent
/// consumes nothing: it is not an attribute of this span.
fn agent_from(
    cfg: &MapperConfig,
    resource: &[Attr],
    span: &Span,
    trace_agent: Option<&AgentId>,
    consumed: &mut BTreeSet<&'static str>,
) -> AgentId {
    if let Some((key, id)) = own_agent(cfg, span) {
        consumed.insert(key);
        return id;
    }
    if let Some(id) = trace_agent {
        return id.clone();
    }
    if let Some(name) = resource
        .iter()
        .find(|a| a.key == "service.name")
        .and_then(|a| a.value.as_str())
        && let Ok(id) = AgentId::parse_strict(format!("agent://{}/{}", cfg.trust_domain, name))
    {
        return id;
    }
    cfg.default_agent.clone()
}

/// The agent a span names itself, and the attribute that named it.
fn own_agent(cfg: &MapperConfig, span: &Span) -> Option<(&'static str, AgentId)> {
    for key in ["gen_ai.agent.id", "gen_ai.agent.name"] {
        if let Some(name) = span.attr(key).and_then(Value::as_str)
            && let Ok(id) = AgentId::parse_strict(format!("agent://{}/{}", cfg.trust_domain, name))
        {
            return Some((key, id));
        }
    }
    None
}

/// How many traces [`TraceAgents`] remembers before it forgets the oldest.
pub const TRACE_AGENTS_REMEMBERED: usize = 4096;

/// The agent each recent trace names, so a span that names none can take it.
///
/// An SDK can put `gen_ai.agent.name` on the model and `invoke_agent` spans and
/// not on the root span of the same run (issue #80, measured with Google ADK
/// 2.7.0). Mapped one span at a time, the root fell through to the resource's
/// `service.name`, and when that was spelled differently from the agent name the
/// one run was filed under two agent ids. A reader asking for the agent then
/// missed the request that started each run.
///
/// A source learns every span of a batch before it maps any of them, so a root
/// that arrives in the same batch as a named child takes the child's agent, and
/// it keeps what it learned across batches, so a root exported after its
/// children (the usual order, since a root ends last) takes it too.
///
/// What is lent, and to whom, is the narrow reading on purpose:
/// - Only within one trace AND one emitting service (the resource's
///   `service.name`) AND, at the agent-token door, one caller. A trace id
///   travels across services in `traceparent`, so a trace can hold the spans of
///   several agents on several services; lending across them would file one
///   service's unnamed spans under another service's agent, and at the door
///   would turn one caller's span into a refusal of another's.
/// - Only a trace that names exactly ONE agent within that scope lends it. Two
///   names (a supervisor and a sub-agent) leave an unnamed span ambiguous, so it
///   keeps `service.name`, as before.
/// - A span that arrives in an earlier batch than every named span of its trace
///   has nothing to take yet and keeps `service.name`.
/// - The memory is bounded and in process: the oldest of
///   [`TRACE_AGENTS_REMEMBERED`] scopes is forgotten first, and a restart starts
///   empty.
#[derive(Debug, Default)]
pub struct TraceAgents {
    named: HashMap<Vec<u8>, Named>,
    order: VecDeque<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Named {
    One(AgentId),
    Several,
}

impl TraceAgents {
    pub fn new() -> Self {
        Self::default()
    }

    /// Note the agent `span` names, if it names one. `caller` is the agent the
    /// transport proved is sending, or `None` at the fleet door.
    pub fn learn(
        &mut self,
        cfg: &MapperConfig,
        resource: &[Attr],
        span: &Span,
        caller: Option<&AgentId>,
    ) {
        let Some((_, id)) = own_agent(cfg, span) else {
            return;
        };
        let Some(key) = scope_key(resource, span, caller) else {
            return;
        };
        if let Some(entry) = self.named.get_mut(&key) {
            if matches!(entry, Named::One(known) if *known != id) {
                *entry = Named::Several;
            }
            return;
        }
        if self.order.len() >= TRACE_AGENTS_REMEMBERED
            && let Some(oldest) = self.order.pop_front()
        {
            self.named.remove(&oldest);
        }
        self.order.push_back(key.clone());
        self.named.insert(key, Named::One(id));
    }

    /// The one agent named in `span`'s trace, from the same service and caller,
    /// or `None` when that scope names none or several.
    pub fn agent_for(
        &self,
        resource: &[Attr],
        span: &Span,
        caller: Option<&AgentId>,
    ) -> Option<&AgentId> {
        match self.named.get(&scope_key(resource, span, caller)?) {
            Some(Named::One(id)) => Some(id),
            _ => None,
        }
    }
}

/// Trace id, `service.name` and caller, each length-prefixed so no two
/// different triples share a key. `None` for a span with no usable trace id.
fn scope_key(resource: &[Attr], span: &Span, caller: Option<&AgentId>) -> Option<Vec<u8>> {
    if span.trace_id.is_empty() || span.trace_id.iter().all(|b| *b == 0) {
        return None;
    }
    let service = resource
        .iter()
        .find(|a| a.key == "service.name")
        .and_then(|a| a.value.as_str())
        .unwrap_or("");
    let caller = caller.map(AgentId::as_str).unwrap_or("");
    let mut key = Vec::new();
    for part in [
        span.trace_id.as_slice(),
        service.as_bytes(),
        caller.as_bytes(),
    ] {
        key.extend_from_slice(&(part.len() as u64).to_be_bytes());
        key.extend_from_slice(part);
    }
    Some(key)
}

fn basis_from(span: &Span, consumed: &mut BTreeSet<&'static str>) -> Basis {
    let mut basis = Basis::default();

    for key in ["gen_ai.request.model", "gen_ai.response.model"] {
        if let Some(raw) = span.attr(key).and_then(Value::as_str)
            && let Ok(model) = ModelId::parse(raw)
        {
            basis.model = Some(model);
            consumed.insert(key);
            break;
        }
    }

    if let Some(t) = span
        .attr("gen_ai.request.temperature")
        .and_then(Value::as_f64)
    {
        let milli = t * 1000.0;
        // Out of range is left empty rather than clamped. A clamped temperature
        // reads as a fact about the call and would not be one.
        if milli.is_finite() && milli >= 0.0 && milli <= f64::from(u16::MAX) {
            basis.temperature_milli = Some(milli.round() as u16);
            consumed.insert("gen_ai.request.temperature");
        }
    }

    if let Some(max) = span
        .attr("gen_ai.request.max_tokens")
        .and_then(Value::as_i64)
        && let Ok(max) = u32::try_from(max)
    {
        basis.max_tokens = Some(max);
        consumed.insert("gen_ai.request.max_tokens");
    }

    // The prompt by hash, never the prompt. The content itself is already bound
    // for the payload plane; this is what survives its erasure, and it is what
    // lets two records be shown to be about the same prompt afterwards.
    //
    // `Value::Empty` is refused, and that is the point of the check. It means the
    // field arrived carrying nothing: an emitter wrote `{}`, or the value was over
    // `Limits::max_value_bytes` and the decoder dropped it. Hashing that gave every
    // such record `SHA-384("null")`, measured and identical across unrelated
    // prompts, in a metadata field that survives erasure and is committed into a
    // published Merkle root. An auditor comparing two of those hashes would
    // conclude the records were about the same prompt. We never saw the content, so
    // we do not commit to a hash of it. An empty string or an empty array is a
    // different matter and still hashed: those are what the emitter said.
    if let Some(value) = span.attr("gen_ai.input.messages")
        && !holds_nothing(value)
    {
        basis.prompt_hash = Some(Sha384::digest(render(value).as_bytes()));
    }

    // Names only. Everything else about a tool definition is content and is
    // already classified as such above.
    if let Some(Value::Array(items)) = span.attr("gen_ai.tool.definitions") {
        for item in items {
            if let Value::Map(fields) = item
                && let Some(name) = fields
                    .iter()
                    .find(|f| f.key == "name")
                    .and_then(|f| f.value.as_str())
                && let Ok(tool) = ToolName::parse(name)
                && !basis.tool_manifest.contains(&tool)
            {
                basis.tool_manifest.push(tool);
            }
        }
    }

    basis
}

/// What the span says about how it ended.
///
/// A successful span does **not** become `Verdict::Allowed`. Nothing in OTLP
/// says a policy allowed anything, and an auditor reading `allowed` would
/// reasonably believe one did. Only failure is asserted, because only failure
/// is what the status actually reports.
fn outcome_from(
    span: &Span,
    consumed: &mut BTreeSet<&'static str>,
) -> (Option<Verdict>, Option<ErrorCode>) {
    if span.status_code != StatusCode::Error {
        return (None, None);
    }
    let code = span
        .attr("error.type")
        .and_then(Value::as_str)
        .map(error_code_for)
        .unwrap_or(ErrorCode::UpstreamError);
    // The attribute is classified, not consumed: `error.type` carries exception
    // class names and provider messages, so the raw string still belongs in the
    // payload plane even though a code was derived from it.
    let _ = consumed;
    (Some(Verdict::Failed), Some(code))
}

fn tokens_from(span: &Span, consumed: &mut BTreeSet<&'static str>) -> (Option<u32>, Option<u32>) {
    let mut read = |key: &'static str| {
        let value = span.attr(key).and_then(Value::as_i64)?;
        let value = u32::try_from(value).ok()?;
        consumed.insert(key);
        Some(value)
    };
    (
        read("gen_ai.usage.input_tokens"),
        read("gen_ai.usage.output_tokens"),
    )
}

fn end_time(span: &Span) -> Option<Timestamp> {
    (span.end_time_unix_nano != 0).then_some(Timestamp(span.end_time_unix_nano))
}

fn latency_micros(span: &Span) -> Option<u64> {
    if span.start_time_unix_nano == 0 {
        return None;
    }
    // A span that ends before it starts is a broken clock, not a negative
    // duration. `checked_sub` rather than a comparison guard: the guarded form
    // reads correctly and is not, because the value of a `then_some` is
    // computed before the condition is looked at.
    span.end_time_unix_nano
        .checked_sub(span.start_time_unix_nano)
        .map(|nanos| nanos / 1_000)
}

fn correlation_from(span: &Span) -> Option<Correlation> {
    // An invalid id is not a name. `run_id_from` has always applied this rule to
    // the trace id and these two fields did not, so eight zero bytes were a
    // perfectly good correlation key: unrelated spans that wrote the invalid
    // parent id as zeros were handed a parent they never named, and were
    // reclassified as delegations because of it.
    Some(Correlation {
        id: SourceKey::new(span.own_id()?)?,
        parent: span
            .has_parent()
            .then(|| SourceKey::new(&span.parent_span_id))
            .flatten(),
    })
}

/// Everything that is content, classified, plus everything left over.
///
/// The leftover part is what makes the invariant hold: an attribute this
/// version has never seen is not dropped and not promoted, it is written down
/// on the encrypted side where it can be read later by somebody entitled to and
/// erased along with everything else about that person.
fn payload_from(span: &Span, scope_name: &str, consumed: &BTreeSet<&str>) -> Vec<PayloadPart> {
    let mut parts = Vec::new();

    // Every occurrence, not the first. OTLP does not forbid a repeated attribute
    // key and emitters do produce them, and a repeat of a content key is content
    // as much as the first one is: it cannot go to the leftover text below, which
    // is `Diagnostic`, without changing what class the store thinks it is.
    for (key, class) in CONTENT {
        for attr in span.attributes.iter().filter(|a| a.key == *key) {
            parts.push(PayloadPart::new(
                *class,
                format!("{key}\n{}", render(&attr.value)).into_bytes(),
            ));
        }
    }

    let mut rest = String::new();
    // Structural free text: a span name is templated from attributes and a
    // status message quotes provider errors. Both read as harmless and both
    // have been seen to carry inputs.
    push_line(&mut rest, "span.name", &span.name);
    push_line(&mut rest, "otel.scope.name", scope_name);
    if !span.status_message.is_empty() {
        push_line(&mut rest, "span.status.message", &span.status_message);
    }

    let content_keys: BTreeSet<&str> = CONTENT.iter().map(|(k, _)| *k).collect();
    // Only the FIRST occurrence of a recognised key is accounted for elsewhere,
    // because `Span::attr` finds the first and the typed extraction above read
    // exactly that one. Filtering the key rather than the occurrence lost every
    // later value to neither plane: not to metadata, which holds one, and not to
    // the payload, which skipped them all. Measured on a span carrying
    // `gen_ai.request.model` twice, the second model name appeared nowhere at all.
    //
    // A repeat of a metadata key is a value nothing mapped, which is precisely
    // what the leftover text is for. A repeat of a content key went into a content
    // part of its own above and is skipped here, because the leftover part is
    // `Diagnostic` and content may not be reclassified on its way through.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut leftovers: Vec<&Attr> = Vec::new();
    for attr in &span.attributes {
        let key = attr.key.as_str();
        let first = seen.insert(key);
        let accounted = if first {
            consumed.contains(key) || content_keys.contains(key)
        } else {
            content_keys.contains(key)
        };
        if !accounted {
            leftovers.push(attr);
        }
    }
    // Sorted, so the same span always renders the same bytes: the payload is
    // hashed, and a hash that depends on map iteration order is not a hash. Stable,
    // so two values under one key keep the order the emitter sent them in, which is
    // the only order that means anything.
    leftovers.sort_by(|a, b| a.key.cmp(&b.key));
    for attr in leftovers {
        push_line(&mut rest, &attr.key, &render(&attr.value));
    }

    for (i, event) in span.events.iter().enumerate() {
        push_line(&mut rest, &format!("event.{i}.name"), &event.name);
        let mut attrs: Vec<&Attr> = event.attributes.iter().collect();
        attrs.sort_by(|a, b| a.key.cmp(&b.key));
        for attr in attrs {
            push_line(
                &mut rest,
                &format!("event.{i}.{}", attr.key),
                &render(&attr.value),
            );
        }
    }

    parts.push(PayloadPart::unmapped(rest.into_bytes()));
    parts
}

fn push_line(into: &mut String, key: &str, value: &str) {
    // Both sides, and the key was the one that was missed. Newlines and tabs make
    // a field indistinguishable from the next one, which is how an emitter forges
    // an entry that was never sent, and an attribute key is as much the emitter's
    // free text as its value is: `{"key":"a\nb\tc","value":..}` is a legal
    // attribute. These bytes are hashed and the record commits to the hash, so a
    // forged line is a forged payload.
    escape_field(into, key);
    into.push('\t');
    escape_field(into, value);
    into.push('\n');
}

/// One field of a tab-separated line, with every byte that could act as a
/// separator turned into something inert.
fn escape_field(into: &mut String, field: &str) {
    for ch in field.chars() {
        match ch {
            '\\' => into.push_str("\\\\"),
            '\n' => into.push_str("\\n"),
            '\r' => into.push_str("\\r"),
            '\t' => into.push_str("\\t"),
            other => into.push(other),
        }
    }
}

/// Whether any part of this value arrived carrying nothing.
///
/// Recursive, and the recursion is the point. Refusing a top-level `Value::Empty`
/// closed half of this: a skeptic measured the collision still live one level
/// down, in the shape the GenAI conventions actually use, because
/// `gen_ai.input.messages` is an array of maps and it is a *part* of it that a
/// value bound drops. Two different prompts whose oversize part was dropped
/// render identically and hash identically, in a metadata field that survives
/// erasure and is committed into a published root.
///
/// Conservative on purpose. An emitter that genuinely sends an empty `AnyValue`
/// inside its messages also gets no hash, and that is the right way round: the
/// field's whole claim is that two records carrying one hash were about one
/// prompt, so under-claiming costs a comparison and over-claiming asserts
/// something false about a person's data.
fn holds_nothing(value: &Value) -> bool {
    match value {
        Value::Empty => true,
        Value::Array(items) => items.iter().any(holds_nothing),
        Value::Map(fields) => fields.iter().any(|f| holds_nothing(&f.value)),
        _ => false,
    }
}

/// A deterministic rendering of an OTLP value.
///
/// Deterministic because it is hashed. Two decodes of the same bytes must give
/// the same string, or `prompt_hash` means nothing and two copies of one record
/// stop being comparable.
pub fn render(value: &Value) -> String {
    let mut out = String::new();
    render_into(value, &mut out);
    out
}

fn render_into(value: &Value, out: &mut String) {
    match value {
        Value::Empty => out.push_str("null"),
        Value::Str(s) => {
            out.push('"');
            for ch in s.chars() {
                // Every control character that could act as a separator
                // downstream, not just the newline. A rendered value has to be
                // inert wherever it is later embedded.
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    other => out.push(other),
                }
            }
            out.push('"');
        }
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => out.push_str(&i.to_string()),
        // Shortest representation that reads back to the same bits, so the
        // rendering is stable across platforms.
        Value::Double(d) => out.push_str(&format!("{d:?}")),
        Value::Bytes(b) => {
            out.push_str("0x");
            for byte in b {
                out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
                out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
            }
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                render_into(item, out);
            }
            out.push(']');
        }
        Value::Map(fields) => {
            // Sorted by key: a map is unordered on the wire, and an unordered
            // input must not produce an order-dependent hash.
            let mut sorted: Vec<&Attr> = fields.iter().collect();
            sorted.sort_by(|a, b| a.key.cmp(&b.key));
            out.push('{');
            for (i, field) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                render_into(&Value::Str(field.key.clone()), out);
                out.push(':');
                render_into(&field.value, out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod error_codes {
    use super::*;

    #[test]
    fn the_shapes_real_sdks_actually_emit() {
        // Written from what the libraries name their exceptions, not from what
        // a specification says they should.
        for (raw, expected) in [
            ("RateLimitError", ErrorCode::RateLimited),
            ("rate_limit_exceeded", ErrorCode::RateLimited),
            ("429", ErrorCode::RateLimited),
            ("APITimeoutError", ErrorCode::Timeout),
            ("DEADLINE_EXCEEDED", ErrorCode::Timeout),
            ("AuthenticationError", ErrorCode::Unauthorized),
            ("PermissionDeniedError", ErrorCode::Unauthorized),
            ("insufficient_quota", ErrorCode::BudgetExceeded),
            (
                "BadRequestError: invalid_request_error",
                ErrorCode::Malformed,
            ),
            ("SomethingNobodyHasSeen", ErrorCode::UpstreamError),
        ] {
            assert_eq!(error_code_for(raw), expected, "{raw}");
        }
    }
}
