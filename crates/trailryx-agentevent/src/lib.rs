//! The estate's shared agent-event envelope, mapped into records.
//!
//! One JSON object per event, NDJSON when batched, `taipanbox.dev/agent-event`
//! v0.1 or v0.2. It is the format the other products in this estate already emit,
//! and the reason it needs no format change here is that the two were designed
//! against the same identity grammar: an `agent://<trust-domain>/<path>` URI, a
//! run, a delegation chain in `on_behalf_of`, and an event type. A record already
//! carries every one of those.
//!
//! This is a mapper and nothing else. It sits beside `trailryx_otlp::map_span`,
//! obeys the same two rules, and shares its shape deliberately so that a reviewer
//! can read them together.
//!
//! # Rule one: the plane boundary
//!
//! A member goes into a typed metadata field **only if it parses into one**.
//! Everything else goes to the payload plane: `data` is free-form by
//! specification and routinely carries prompts and personal data, `source` and
//! `prev_hash` have no typed home in a frozen record, and a member this version
//! has never seen is by definition something this version cannot classify. None
//! of them is dropped and none of them is promoted.
//!
//! # Rule two: strict at the ingest door
//!
//! Invariant 23. `trailryx-journal` reads identifiers back with the lax
//! constructor because it wrote them; anything arriving from outside is parsed
//! with the strict one. An envelope is outside, so `agent_id` goes through
//! [`trailryx_record::AgentId::parse_strict`] and every principal in
//! `on_behalf_of` through [`trailryx_record::PrincipalId::parse_strict`]. A
//! producer that sent `billing` where `agent://acme.example/billing` was meant is
//! refused here and would have been stored by the journal's own constructor.
//!
//! The trust domain is the operator's, never the wire's, which is the same rule
//! `trailryx_otlp::MapperConfig` enforces by construction. It cannot be enforced
//! that way here, because the identifier arrives whole rather than being built
//! from a name, so it is enforced by comparison: an `agent://` in somebody else's
//! trust domain is refused rather than recorded. One valid producer could
//! otherwise write records about every agent in the estate.
//!
//! # What is mapped, and what is refused by name
//!
//! An event type becomes a [`trailryx_record::EventType`] only where the record
//! vocabulary has a true home for it. The rest are refused and counted, for the
//! reason `map_span` gives about an unknown operation: **a wrong event type is
//! worse than a missing record, because it is believed.** The registry in
//! `agent-passport/SPEC.md` §6.2 grows within a source without a schema bump, so
//! this table is a reading of it on a date rather than a closed set, and
//! [`MAPPER_VERSION`] says which reading produced a record.
//!
//! Refused today, each because the record vocabulary has no honest home for it
//! rather than because nobody got to it: `mcp_drift`, `sustained_loop`,
//! `fanout_explosion`, `crypto_finding`, `crypto_drift`, `policy_violation`,
//! `evidence_signed`, `eval_run`, `quality_score`, `quality_drift`, `slo_burn`,
//! `sim_run`, `sim_finding`, `blast_radius_measured` and `console_command`. Each
//! is a finding or an observation about infrastructure rather than a decision an
//! agent took, and ten of the twelve event types are decisions.
//!
//! # The two that got types of their own, and what that cost
//!
//! `alert_sent` is heraldyx saying it mailed a person about a run. It is not a
//! decision either, and it was refused here until 6 August 2026 for exactly that
//! reason. What made it different from the fifteen above is that it is not a
//! finding about infrastructure: it is an event in the run's own history, with a
//! subject, a time and an auditor's question attached to it ("when was this
//! escalated, and to whom"), and no other event type can answer that question
//! without saying something untrue about what happened. So the owner took the
//! other way out of the two this paragraph used to name, and the record
//! vocabulary grew an eleventh type,
//! [`trailryx_record::EventType::NotificationDispatched`].
//!
//! That paragraph also used to say the new type would be a format version under
//! invariant 7. It is not, and the difference was worth measuring rather than
//! assuming: invariant 7 forbids **redefining a field in place**, and an appended
//! discriminant redefines nothing. Every code ever written still decodes to the
//! name it was written as, and a build older than the eleventh code refuses it by
//! name instead of reading it as something else. The reasoning and the runs are in
//! the pull request that added it.
//!
//! `identity_finding` earned the twelfth type on 10 August 2026 on the same
//! argument, sharpened. None of the eleven was true of it either, and what
//! separated it from `crypto_finding` and `sim_finding`, which are still refused,
//! is that this store's subject axis is `agent_id`: a doubt about the identity
//! behind a trail conditions how an auditor reads every other record about that
//! subject, and no other type answers "was this identity questioned, and when"
//! without saying something untrue. The reasoning is on
//! [`trailryx_record::EventType::IdentityFinding`] itself.
//!
//! Extending the table further still means one of the same two things, and the
//! second is still refused here: a new event type, which is the owner's decision,
//! or mapping a finding onto a decision, which is not.
//!
//! # A measurement over a population is not an event in a run
//!
//! `slo_burn` is verdryx computing an error budget over one of four service level
//! indicators: a target, the observed ratio of good runs over eligible ones in a
//! window, a Wilson interval around it, how much budget is left and how fast it is
//! going. It is refused, and it is the entry on that list whose refusal has to be
//! argued rather than asserted, because the two types this vocabulary has grown
//! were both grown for a plane in this estate reporting about an agent, which is
//! what verdryx is doing here. "It came from another product's plane" stopped
//! being an answer on 6 August 2026.
//!
//! Neither was grown because a finding deserved a record. Each is an event in ONE
//! RUN'S OWN HISTORY, carrying a subject this store is built around, a time, and
//! an auditor's question no other type answers without saying something untrue. A
//! burn has neither half. It is computed after the fact, by a third party, over a
//! POPULATION of runs across a window, and the answer belongs to the population
//! rather than to any run in it. A record has to name one run and one subject, so
//! recording a burn would fasten a ratio measured over a fleet to whichever
//! `agent_id` and `run_id` the line happened to carry, and assert about that agent
//! something the measurement does not support. The producer says as much itself:
//! the event carries the identifier the ratio was grouped on, `agent_id` or
//! `key_id`, which is a grouping choice rather than a property of any one run.
//!
//! There is no adjacent type to fall back on, and each candidate says more than
//! happened. `BudgetCheck` is money and would assert that spend was metered, when
//! what was measured is a rate of good outcomes. `StoreEvent` is this store
//! speaking about itself, and a burn is arithmetic somebody else did.
//! `PolicyDecision` is the worst of the three, because it would read as an
//! enforcement and **nothing is enforced**: verdryx computes the budget and says
//! so, it writes no policy, demotes nobody, and what to do about a spent budget is
//! a person's decision taken somewhere this record plane does not reach. A record
//! implying otherwise would be this store asserting a consequence that does not
//! exist.
//!
//! One thing about the counter, since the refusals here are meant to be read.
//! Only two triggers reach the bus at all, `exhausted` and `fast_burn`. Severity
//! is fixed per type across this estate, so one type is one paging band, and a
//! slow burn (the budget will be gone by Friday) is deliberately not an alert: it
//! stays in verdryx's own report and its JSON, where a dashboard reads it. So a
//! run of this stream that turns away N lines of this type turned away N budgets
//! already gone or going fast rather than N windows computed, and a quiet
//! `unknown_type` counter is not the same fact as a healthy fleet.

pub mod time;

use std::collections::BTreeSet;
use std::fmt;

use trailryx_contracts::ingest::{Cursor, Ingest, MetaDraft, PayloadPart};
use trailryx_json::{Event, Limits, Reader};
use trailryx_record::{
    AgentId, Basis, ErrorCode, EventType, MapperVersion, PayloadClass, PrincipalId, RunId,
    Severity, TenantId, Untrusted, Verdict,
};

/// Which reading of the registry produced a record.
///
/// It moves when the table below does. The registry is documented as growing
/// within a source without a schema bump, so a record has to say which reading of
/// it was in force when the record was written, exactly as an OTLP-sourced record
/// says which reading of the GenAI conventions was.
///
/// 102 is the reading that maps `alert_sent`. Records written by 101 are not
/// wrong and are not migrated: they were produced by a reader that had no event
/// type for a dispatched notification, so a line it refused stayed a counted
/// refusal rather than becoming a record, and this field is how somebody reading
/// the store years from now can tell that apart from a run in which nothing was
/// dispatched.
///
/// 103 is the reading that maps `identity_finding` and refuses a claimed subject
/// by name. The same reasoning applies twice over here, because the cursor
/// commits past refused lines: every identity finding written before this
/// reading deployed stayed a counted refusal and will not be re-read. The trail
/// of identity findings starts at 103, and this field is what says so rather
/// than leaving a reader to conclude the identity plane was quiet.
///
/// 104 is the reading that maps `dependency_failed`, and it is the first entry in
/// the table that is about the box rather than about the agent. The 103 argument
/// applies again and it bites harder here, because of what the type is: a
/// dependency failure written before this reading deployed stayed a counted
/// refusal, the cursor committed past the line, and it will not be re-read. So the
/// trail of the estate's own outages starts at 104, and a reader who finds nothing
/// before it is looking at a reader that could not map them rather than at a period
/// in which nothing broke. That distinction is the whole reason this field exists,
/// and it matters more for an outage than for anything else in the table: silence
/// is what an outage looks like from the outside anyway.
pub const MAPPER_VERSION: MapperVersion = MapperVersion(104);

/// The schema values this reader accepts.
///
/// v0.1 and v0.2 because the specification says a consumer MUST accept either
/// and an emitter on v0.1 is under no obligation to move. They differ only in
/// whether `source` is a closed enum, and `source` is not a field this mapper
/// decides anything from.
///
/// **v0.3 is here so a claim can be REFUSED BY NAME rather than by encoding.**
/// It is the version an observer stamps when `agent_id` carries a subject a
/// process asserted about itself (SPEC 3.3, 6.4), and accepting it is not a
/// MUST. Refusing it at [`Rejection::UnknownSchema`] would have been defensible
/// and was rejected: that counter is shared with typos, a future v0.4 and
/// foreign formats, so an operator reading it diagnoses producer drift, and the
/// one fact worth surfacing, that N processes claimed identities, would be
/// invisible.
///
/// Accepting a version is not a promise to record its traffic. It is the
/// statement that this reader knows what the version means, and this one now
/// does: see [`Rejection::ClaimedSubject`].
pub const SCHEMAS: &[&str] = &[
    "taipanbox.dev/agent-event/v0.1",
    "taipanbox.dev/agent-event/v0.2",
    "taipanbox.dev/agent-event/v0.3",
];

/// What the operator asserts, because the wire cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeConfig {
    tenant: TenantId,
    trust_domain: String,
    /// `agent://<trust-domain>/`, built once so every line is compared against a
    /// value that was validated at startup rather than formatted per line.
    prefix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    BadTrustDomain,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("trust domain does not form an agent identifier")
    }
}

impl std::error::Error for ConfigError {}

impl EnvelopeConfig {
    pub fn new(tenant: TenantId, trust_domain: &str) -> Result<Self, ConfigError> {
        // Validated by building one, so a misconfiguration fails when the
        // receiver starts rather than against live traffic.
        AgentId::parse_strict(format!("agent://{trust_domain}/probe"))
            .map_err(|_| ConfigError::BadTrustDomain)?;
        Ok(Self {
            tenant,
            trust_domain: trust_domain.to_owned(),
            prefix: format!("agent://{trust_domain}/"),
        })
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
}

/// Why a line produced no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Not a JSON object, or not JSON at all.
    NotAnEnvelope,
    /// A `schema` this reader does not accept, or none at all.
    UnknownSchema,
    /// No `agent_id`, or one that is not an `agent://` URI. Strict, because this
    /// is the ingest door: invariant 23.
    NoAgent,
    /// An `agent://` in a trust domain this receiver does not serve.
    ForeignTrustDomain,
    /// An `agent_id` a PROCESS asserted about itself: `claimed:agent://...`,
    /// read out of AGENT_PASSPORT_ID by an observer (SPEC 3.3).
    ///
    /// **Refused because `agent_id` is the one field this store cannot take
    /// back.** It is mandatory, provable, committed into the immutable index
    /// roots and one of the nine unerasable fields, and its promise to hold no
    /// personal data is, in the schema's own words, contractual rather than
    /// technical: an operator asserts that the value space holds machine names,
    /// "not a natural person". Every party that authors an established
    /// identifier is under that contract. A claimed one is authored by the only
    /// party that is not: a process writes its own environment, and inside the
    /// permitted characters it can write a person's name, another
    /// organisation's agent, or an unbounded stream of fresh identifiers, every
    /// byte of which would land where erasure can never reach.
    ///
    /// There is no other home for it either. Fabricating a stand-in `agent_id`
    /// is what SPEC 6.1 forbids in as many words, and the payload plane cannot
    /// carry the subject because `agent_id` is not optional. `AgentId` is capped
    /// at 255 bytes while v0.3 allows 263, so a maximal claim cannot even be
    /// constructed as one: the type was never shaped for this.
    ///
    /// **The tenant comparison deliberately never runs on one.** Folding a
    /// foreign-domain claim into [`Rejection::ForeignTrustDomain`] would say a
    /// producer of ours is misconfigured and send somebody to check
    /// configuration, when the domain is whatever the process typed. And
    /// comparing the inner identifier would bound nothing: an attacker claims
    /// to be YOUR agent precisely when impersonating you.
    ///
    /// Nothing is lost silently. The finding stays in the producer's own
    /// journal, in Slack and in OTLP, and this counter says how many were turned
    /// away and why.
    ClaimedSubject,
    /// A `type` this reading of the registry does not map. Deliberately not
    /// mapped to something adjacent.
    UnknownType,
    /// No `run_id`, or one that is not a run identifier. A record names a run,
    /// and inventing one would put unrelated events in a single run.
    NoRunId,
    /// A `ts` that is not an RFC 3339 instant.
    BadTime,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnEnvelope => f.write_str("not an agent-event object"),
            Self::UnknownSchema => f.write_str("a schema this reader does not accept"),
            Self::NoAgent => f.write_str("no usable agent identifier"),
            Self::ForeignTrustDomain => f.write_str("an agent in another trust domain"),
            Self::ClaimedSubject => f.write_str(
                "a subject the process asserted about itself, not one the estate issued",
            ),
            Self::UnknownType => f.write_str("an event type this reading does not map"),
            Self::NoRunId => f.write_str("no run identifier"),
            Self::BadTime => f.write_str("no usable timestamp"),
        }
    }
}

/// What a stream cost, in records that do not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Report {
    pub mapped: u32,
    pub not_an_envelope: u32,
    pub unknown_schema: u32,
    pub no_agent: u32,
    pub foreign_trust_domain: u32,
    pub claimed_subject: u32,
    pub unknown_type: u32,
    pub no_run_id: u32,
    pub bad_time: u32,
}

impl Report {
    pub fn note(&mut self, rejection: Rejection) {
        let slot = match rejection {
            Rejection::NotAnEnvelope => &mut self.not_an_envelope,
            Rejection::UnknownSchema => &mut self.unknown_schema,
            Rejection::NoAgent => &mut self.no_agent,
            Rejection::ForeignTrustDomain => &mut self.foreign_trust_domain,
            Rejection::ClaimedSubject => &mut self.claimed_subject,
            Rejection::UnknownType => &mut self.unknown_type,
            Rejection::NoRunId => &mut self.no_run_id,
            Rejection::BadTime => &mut self.bad_time,
        };
        *slot = slot.saturating_add(1);
    }

    /// Lines that arrived and produced nothing.
    ///
    /// All of them, unlike the OTLP mapper's, and the difference is the stream: a
    /// database span in an OTLP batch is traffic that was never ours, while every
    /// line here is addressed to this envelope by its own `schema` member.
    pub fn lost(&self) -> u32 {
        self.not_an_envelope
            .saturating_add(self.unknown_schema)
            .saturating_add(self.no_agent)
            .saturating_add(self.foreign_trust_domain)
            .saturating_add(self.unknown_type)
            .saturating_add(self.no_run_id)
            .saturating_add(self.bad_time)
    }
}

/// What one event type means in the record vocabulary.
///
/// The severity is the registry's own band for that type, and it is a fallback
/// rather than an override: an envelope that carries `severity` is believed. It
/// exists because `severity` is optional in the schema and a record's is not, so
/// something has to answer, and the registry's documented band is an answer
/// somebody else wrote down rather than one invented here.
struct Mapping {
    event_type: EventType,
    verdict: Option<Verdict>,
    error: Option<ErrorCode>,
    severity: Severity,
}

/// The reading of `agent-passport/SPEC.md` §6.2 this version carries.
fn mapping_for(kind: &str) -> Option<Mapping> {
    let m = |event_type, verdict, error, severity| {
        Some(Mapping {
            event_type,
            verdict,
            error,
            severity,
        })
    };
    match kind {
        // Money. A threshold is a warning about a budget and not a refusal, and
        // it sits one band below the exhaustion it precedes for the same reason
        // the producer puts it there.
        "budget_exhausted" => m(
            EventType::BudgetCheck,
            Some(Verdict::Denied),
            Some(ErrorCode::BudgetExceeded),
            Severity::Critical,
        ),
        "unit_cap_exceeded" => m(
            EventType::BudgetCheck,
            Some(Verdict::Denied),
            Some(ErrorCode::BudgetExceeded),
            Severity::Error,
        ),
        "budget_threshold" => m(EventType::BudgetCheck, None, None, Severity::Warning),
        "spend_spike" => m(EventType::BudgetCheck, None, None, Severity::Warning),
        // Policy. `policy_allow` may assert `Allowed`, which the OTLP mapper
        // refuses to do, and the difference is the source: a span says a call
        // happened, while this event is a policy engine saying it allowed one.
        "policy_allow" => m(
            EventType::PolicyDecision,
            Some(Verdict::Allowed),
            None,
            Severity::Info,
        ),
        "policy_deny" => m(
            EventType::PolicyDecision,
            Some(Verdict::Denied),
            Some(ErrorCode::PolicyDenied),
            Severity::Error,
        ),
        "breaker_tripped" => m(
            EventType::PolicyDecision,
            Some(Verdict::Denied),
            Some(ErrorCode::PolicyDenied),
            Severity::Warning,
        ),
        "dlp_block" | "taint_block" => m(
            EventType::PolicyDecision,
            Some(Verdict::Denied),
            Some(ErrorCode::PolicyDenied),
            Severity::Error,
        ),
        "identity_mismatch" => m(
            EventType::PolicyDecision,
            Some(Verdict::Denied),
            Some(ErrorCode::Unauthorized),
            Severity::Error,
        ),
        // Approvals. `Held` is in the record vocabulary already, for an erasure
        // a custodian promised and has not performed, and it means the same thing
        // here: decided by nobody yet.
        "approval_requested" => m(
            EventType::PolicyDecision,
            Some(Verdict::Held),
            None,
            Severity::Warning,
        ),
        "approval_granted" => m(
            EventType::PolicyDecision,
            Some(Verdict::Allowed),
            None,
            Severity::Info,
        ),
        "approval_denied" => m(
            EventType::PolicyDecision,
            Some(Verdict::Denied),
            Some(ErrorCode::PolicyDenied),
            Severity::Error,
        ),
        "approval_timeout" | "approval_unanswered" => m(
            EventType::PolicyDecision,
            Some(Verdict::Failed),
            Some(ErrorCode::Timeout),
            Severity::Error,
        ),
        "tool_call" => m(EventType::ToolCall, None, None, Severity::Info),
        "run_killed" => m(
            EventType::RunCompleted,
            Some(Verdict::Failed),
            Some(ErrorCode::PolicyDenied),
            Severity::Error,
        ),
        // Memory. All four are a memory being read or written, which is what the
        // record's own event type says, and none of them is an erasure: a
        // forgotten memory and a person exercising a right are different facts and
        // `EventType::Erasure` is the second one.
        "memory_written" | "memory_forgotten" | "reflection_run" | "contradiction_found" => {
            m(EventType::MemoryAccess, None, None, Severity::Info)
        }
        // An identity plane reporting a finding about an agent. No verdict and no
        // error: a finding decides nothing, and asserting a verdict would make
        // the record say the estate concluded something when what happened is
        // that a detector spoke.
        //
        // `Warning` is the fallback band only. The producer sends a severity on
        // every line and `severity_for` prefers it; this is what a later producer
        // of this type would get, and it agrees with the producer's own unknown
        // band, which is medium. A finding is by nature a signal, which is why it
        // is not `Info` the way a dispatched notification is: that one is a thing
        // that happened, this one is somebody saying look.
        "identity_finding" => m(EventType::IdentityFinding, None, None, Severity::Warning),
        // A notification left for a person. No verdict and no error, and both are
        // deliberate rather than unfinished: heraldyx's `data` carries an
        // `outcome` member reading "accepted" or "refused", and reading either
        // into a typed field would be this store asserting a producer's free-form
        // member as a decision it stands behind. `data` is not read here, by the
        // rule at the top of this file, and the recipients in `data.to` are the
        // reason that rule is not negotiable: they are personal data, and the
        // metadata plane is the one erasure cannot reach.
        //
        // Info rather than a warning band. A notification is a thing that
        // happened, not a signal about anything; the severity of what it was
        // about belongs to the event it was about, which is already in the store
        // under its own type.
        // Web egress. A governed fetch IS a tool call: `fetch_url` and `browse`
        // are tools an agent invoked, and the record vocabulary already has the
        // word for that. No verdict, because it happened.
        "web_fetch" => m(EventType::ToolCall, None, None, Severity::Notice),
        // A fetch this plane refused. `Denied` is true of every one of them,
        // and the ERROR CODE is deliberately absent, which is the same
        // reasoning `alert_sent` uses just below.
        //
        // `web_blocked` covers refusals of several different kinds: a policy
        // that said no, an address inside the deployment, a scheme that is not
        // http, a per-hour cap that was spent, and a policy plane that could
        // not be asked at all. `ErrorCode::PolicyDenied` would assert that a
        // policy denied it, which is false for the address case, where the
        // refusal happens before any policy runs and no policy language
        // contemplates the address anyway.
        //
        // The producer's `data.verdict` member tells the two apart. Reading it
        // into a typed field here would be this store asserting a producer's
        // free-form member as a decision it stands behind, which is exactly
        // what the rule at the top of this file forbids. The member is not
        // lost: it reaches the payload plane like every other unconsumed
        // member, where a reader can see it and this store claims nothing
        // about it.
        "web_blocked" => m(
            EventType::PolicyDecision,
            Some(Verdict::Denied),
            None,
            Severity::Error,
        ),
        "alert_sent" => m(
            EventType::NotificationDispatched,
            None,
            None,
            Severity::Info,
        ),
        // The box's own dependency died. Every other entry in this table is an
        // agent misbehaving or a plane refusing it; this one is tokenfuse saying
        // that its provider, or the policy plane it asks before every call, could
        // not be reached. Until 25 August 2026 that left a `502` on the wire and
        // nothing in any store, which is the gap the type was cut for.
        //
        // It needs no new record type, and that is the difference from
        // `alert_sent`. `EventType::ModelCall` is true of it and asserts nothing
        // beyond what happened: a call was made and it did not complete.
        // `Verdict::Failed` says the second half of that, and
        // `ErrorCode::UpstreamError` says what failed was somebody else's service
        // rather than ours. `trailryx_otlp::semconv` already falls back to exactly
        // that trio for the same real-world fact when a span reports an error it
        // cannot name more precisely, so the estate's two ingest doors agree about
        // an upstream failure rather than each inventing a reading of it. Adding a
        // twelfth event type for a fact the vocabulary already holds would make the
        // same failure look like two different things depending on which door it
        // came through, and invariant 36 would then have to carry a discriminant
        // that bought nothing.
        //
        // The three tempting alternatives are each worse, and each in the same way:
        // they say more than happened, which is the one thing this mapper may never
        // do. `PolicyDecision` would assert that a policy decided something, and the
        // entire content of the event is that nothing did. `BudgetCheck` would
        // assert that spend was metered or a budget consulted, and a call that never
        // reached a provider moved no money. `StoreEvent` is the store speaking
        // about itself, reserved for a gap, a re-sign or a recovery, and this is not
        // the store: it is a component upstream of the store reporting its own
        // weather, and borrowing that type would put somebody else's outage in the
        // one place a reader trusts to be ours.
        //
        // One arm covers both dependencies, and the policy plane is the case that
        // tempts a second one. When the dependency that failed is the policy plane
        // rather than the provider, a model call still happened, ungoverned, under
        // the default `failmode=open`, or was still stopped under `failmode=closed`;
        // either way the agent's call is what the event is about, and `ModelCall`
        // stays true of it. Splitting the arm would also require reading
        // `data.dependency`, which the rule at the top of this file forbids: a
        // producer's free-form member must not become a typed field this store
        // stands behind. So which dependency died, how far the call had got, what
        // the failure did to the call and the transport-error text all travel in the
        // payload plane, where a reader can see them and this store claims nothing
        // about them. Nothing is lost, and nothing is asserted.
        //
        // `Severity::Error` is the fallback band and not an override, the same way
        // every other band in this table is: `severity_for` prefers the producer's
        // value on every line that carries one, and tokenfuse fixes this type at
        // `high` inside its own code rather than letting a call site choose. `high`
        // is `Severity::Error`, so the two agree, and a line that arrived without the
        // optional member produces the same record shape as one that carried it. It
        // is set to the value they agree on deliberately rather than left at
        // whatever looked reasonable, because a fallback that disagreed with the one
        // producer of the type would mean two records of one outage reading at two
        // volumes, for a reason no reader of the store could recover. It is not the
        // `Critical` band `budget_exhausted` takes: a dependency that failed is
        // recoverable and usually already recovering, while a budget that is gone
        // stays gone until somebody acts.
        "dependency_failed" => m(
            EventType::ModelCall,
            Some(Verdict::Failed),
            Some(ErrorCode::UpstreamError),
            Severity::Error,
        ),
        _ => None,
    }
}

/// The five bands of the envelope onto the six of a record.
fn severity_for(raw: &str) -> Option<Severity> {
    Some(match raw {
        "info" => Severity::Info,
        "low" => Severity::Notice,
        "medium" => Severity::Warning,
        "high" => Severity::Error,
        "critical" => Severity::Critical,
        _ => return None,
    })
}

/// Members this mapper reads into a typed field, and therefore does not repeat in
/// the payload plane.
const CONSUMED: &[&str] = &[
    "schema",
    "ts",
    "type",
    "severity",
    "agent_id",
    "run_id",
    "on_behalf_of",
];

/// Map one NDJSON line into one ingest unit.
///
/// A pure function of the line, deliberately, and for the reason `map_span` gives
/// about the same shape: `recorded_at` is the store's own clock, assigned where
/// the record is written, and a mapper that stamped a time would be a mapper that
/// could get it wrong.
pub fn map_line(cfg: &EnvelopeConfig, line: &[u8], cursor: Cursor) -> Result<Ingest, Rejection> {
    let parsed = Parsed::read(line)?;

    if !parsed
        .schema
        .as_deref()
        .is_some_and(|s| SCHEMAS.contains(&s))
    {
        return Err(Rejection::UnknownSchema);
    }

    // The claim is tested on the RAW string, before anything tries to build an
    // AgentId out of it, and the order is the whole of it: `parse_strict`
    // refuses the claimed form as a bad shape, so without this branch a claim
    // would be counted as `NoAgent`, which is not true of it and would send an
    // operator looking for a producer that forgot a field.
    //
    // The wire form is pinned here verbatim rather than through a shared
    // validator, because the producer's is Go and this is Rust and nothing
    // crosses that boundary. The tests carry the same literal for that reason.
    if let Some(raw) = parsed.agent_id.as_deref() {
        if let Some(inner) = raw.strip_prefix("claimed:") {
            if AgentId::parse_strict(inner).is_ok() {
                return Err(Rejection::ClaimedSubject);
            }
            // A `claimed:` wrapper around something that is not an identifier at
            // all is not a claim this door has to reason about; it is garbage,
            // and `NoAgent` is true of it.
        }
    }

    // Strict, because this is the ingest door and not the journal reading back
    // something it wrote. Invariant 23.
    let agent_id = parsed
        .agent_id
        .as_deref()
        .and_then(|raw| AgentId::parse_strict(raw).ok())
        .ok_or(Rejection::NoAgent)?;
    if !agent_id.as_str().starts_with(&cfg.prefix) {
        return Err(Rejection::ForeignTrustDomain);
    }

    let kind = parsed.kind.as_deref().ok_or(Rejection::UnknownType)?;
    let mapping = mapping_for(kind).ok_or(Rejection::UnknownType)?;

    let run_id = parsed
        .run_id
        .as_deref()
        .and_then(|raw| RunId::parse(raw).ok())
        .ok_or(Rejection::NoRunId)?;

    let occurred_at = parsed
        .ts
        .as_deref()
        .and_then(time::parse_rfc3339)
        .ok_or(Rejection::BadTime)?;

    // Every principal or none. A chain with one link dropped is a different
    // chain, and a delegation chain is exactly the thing an auditor follows, so a
    // link this reader cannot parse takes the whole member to the payload plane
    // rather than shortening the chain in the metadata plane.
    let mut on_behalf_of = Vec::new();
    let mut chain_kept = true;
    for raw in &parsed.on_behalf_of {
        match PrincipalId::parse_strict(raw) {
            Ok(principal) => on_behalf_of.push(principal),
            Err(_) => {
                chain_kept = false;
                break;
            }
        }
    }
    if !chain_kept {
        on_behalf_of.clear();
    }

    let severity = parsed
        .severity
        .as_deref()
        .and_then(severity_for)
        .unwrap_or(mapping.severity);

    let meta = MetaDraft {
        mapper: MAPPER_VERSION,
        // The operator's, never the wire's: a producer that could name its own
        // tenant could write into somebody else's records.
        tenant: cfg.tenant.clone(),
        agent_id,
        run_id,
        // The envelope has no member for one. `run_id` names one execution and
        // nothing in this format links two of them, so the field stays empty
        // rather than being filled with something that would read as a delegation.
        parent_run_id: None,
        on_behalf_of,
        occurred_at: Untrusted::new(occurred_at),
        // The envelope carries one time, and it is when the event happened rather
        // than when a decision was taken. Claiming both from one value would make
        // a latency out of nothing.
        decided_at: None,
        event_type: mapping.event_type,
        severity,
        // Nothing in this envelope is a basis. `data` is free-form by
        // specification, so a policy version read out of it would be a policy
        // version this store asserted on a producer's behalf.
        basis: Basis::default(),
        verdict: mapping.verdict,
        error: mapping.error,
        latency_micros: None,
        tokens_in: None,
        tokens_out: None,
        cost_micros: None,
    };

    Ok(Ingest {
        meta,
        payload: parsed.payload(chain_kept),
        // The envelope has no per-event name to correlate on. `prev_hash` names
        // the previous event in the producer's own chain and not this one, so it
        // cannot serve as this event's identity, and a correlation key that is
        // somebody else's identity is how a causal graph invents an edge.
        correlation: None,
        cursor,
    })
}

/// One line, read into strings, before anything is parsed into a typed field.
#[derive(Debug, Default)]
struct Parsed {
    schema: Option<String>,
    ts: Option<String>,
    kind: Option<String>,
    severity: Option<String>,
    agent_id: Option<String>,
    run_id: Option<String>,
    on_behalf_of: Vec<String>,
    /// Everything bound for the payload plane, as `(member, rendered)`.
    rest: Vec<(String, String)>,
}

impl Parsed {
    fn read(line: &[u8]) -> Result<Self, Rejection> {
        let mut reader = Reader::new(line, Limits::default(), 0);
        match reader.value() {
            Ok(Event::ObjectStart) => {}
            _ => return Err(Rejection::NotAnEnvelope),
        }

        let mut out = Self::default();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        loop {
            let name = match reader.next_name() {
                Ok(Some(name)) => name.into_owned(),
                Ok(None) => break,
                Err(_) => return Err(Rejection::NotAnEnvelope),
            };

            // A member repeated is refused by the reader itself, so what arrives
            // here is a member this mapper has already handled only if the
            // grammar allowed it. Kept as a guard rather than an assumption.
            let first = seen.insert(name.clone());
            let slot = match name.as_str() {
                "schema" if first => Some(&mut out.schema),
                "ts" if first => Some(&mut out.ts),
                "type" if first => Some(&mut out.kind),
                "severity" if first => Some(&mut out.severity),
                "agent_id" if first => Some(&mut out.agent_id),
                "run_id" if first => Some(&mut out.run_id),
                _ => None,
            };

            if let Some(slot) = slot {
                match reader.value() {
                    Ok(Event::Str(text)) => *slot = Some(text.into_owned()),
                    // A member of the wrong JSON type is not repaired into the
                    // right one. The typed field stays empty and the value goes
                    // to the payload plane with everything else unrecognised.
                    Ok(other) => {
                        let rendered = canonical(&mut reader, other)?;
                        out.rest.push((name, rendered));
                    }
                    Err(_) => return Err(Rejection::NotAnEnvelope),
                }
                continue;
            }

            if name == "on_behalf_of" && first {
                match reader.value() {
                    Ok(Event::ArrayStart) => loop {
                        match reader.next_element() {
                            Ok(true) => match reader.value() {
                                Ok(Event::Str(text)) => out.on_behalf_of.push(text.into_owned()),
                                Ok(other) => {
                                    // A link that is not a string is a link that
                                    // cannot be parsed, and the whole chain is
                                    // then kept out of the metadata plane.
                                    out.on_behalf_of.push(canonical(&mut reader, other)?);
                                }
                                Err(_) => return Err(Rejection::NotAnEnvelope),
                            },
                            Ok(false) => break,
                            Err(_) => return Err(Rejection::NotAnEnvelope),
                        }
                    },
                    Ok(other) => {
                        let rendered = canonical(&mut reader, other)?;
                        out.rest.push((name, rendered));
                    }
                    Err(_) => return Err(Rejection::NotAnEnvelope),
                }
                continue;
            }

            // Everything else, including `data`, `source`, `prev_hash` and any
            // member a later schema adds.
            let value = reader.value().map_err(|_| Rejection::NotAnEnvelope)?;
            let rendered = canonical(&mut reader, value)?;
            out.rest.push((name, rendered));
        }

        Ok(out)
    }

    /// The payload plane: everything this mapper did not put in a typed field.
    ///
    /// One part, `Diagnostic`, because nothing in this envelope is classified as
    /// content by the producer. `data` is where a prompt would be and the
    /// specification says only that it is free-form, so the store cannot say
    /// whether it holds a prompt, a completion or a document, and a class it
    /// guessed would be a class somebody makes a retention decision from.
    fn payload(&self, chain_kept: bool) -> Vec<PayloadPart> {
        let mut text = String::new();
        let mut lines: Vec<(&str, &str)> = self
            .rest
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        // Sorted, so the same event always renders the same bytes: this is
        // hashed, and a hash that depends on member order is not a hash.
        lines.sort_by(|a, b| a.0.cmp(b.0));
        for (key, value) in lines {
            push_line(&mut text, key, value);
        }
        if !chain_kept {
            for link in &self.on_behalf_of {
                push_line(&mut text, "on_behalf_of", link);
            }
        }
        if text.is_empty() {
            return Vec::new();
        }
        vec![PayloadPart::new(
            PayloadClass::Diagnostic,
            text.into_bytes(),
        )]
    }
}

/// A value, rendered so that two spellings of one event produce one string.
///
/// Deterministic because it is hashed, which is the reason
/// `trailryx_otlp::semconv::render` is deterministic: an object is unordered on
/// the wire and a producer's whitespace is its own business, so a payload whose
/// bytes depended on either would give two copies of one event two different
/// payload hashes. Keys are sorted, whitespace is dropped, and a number is
/// emitted as the digits the producer wrote, so nothing passes through a float on
/// the way through.
///
/// The recursion is bounded by the reader's own depth limit rather than by a
/// count kept here: the reader refuses a value deeper than
/// `trailryx_json::Limits::max_depth` before this function is ever handed one.
fn canonical(reader: &mut Reader<'_>, value: Event<'_>) -> Result<String, Rejection> {
    let mut out = String::new();
    render_into(reader, value, &mut out)?;
    Ok(out)
}

fn render_into(
    reader: &mut Reader<'_>,
    value: Event<'_>,
    out: &mut String,
) -> Result<(), Rejection> {
    match value {
        Event::Null => out.push_str("null"),
        Event::Bool(b) => out.push_str(if b { "true" } else { "false" }),
        Event::Number(n) => {
            out.push_str(std::str::from_utf8(n.raw()).map_err(|_| Rejection::NotAnEnvelope)?)
        }
        Event::Str(s) => quote(&s, out),
        Event::ArrayStart => {
            out.push('[');
            let mut first = true;
            loop {
                match reader.next_element() {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => return Err(Rejection::NotAnEnvelope),
                }
                if !first {
                    out.push(',');
                }
                first = false;
                let element = reader.value().map_err(|_| Rejection::NotAnEnvelope)?;
                render_into(reader, element, out)?;
            }
            out.push(']');
        }
        Event::ObjectStart => {
            let mut members: Vec<(String, String)> = Vec::new();
            loop {
                match reader.next_name() {
                    Ok(Some(name)) => {
                        let member = reader.value().map_err(|_| Rejection::NotAnEnvelope)?;
                        let mut rendered = String::new();
                        render_into(reader, member, &mut rendered)?;
                        members.push((name.into_owned(), rendered));
                    }
                    Ok(None) => break,
                    Err(_) => return Err(Rejection::NotAnEnvelope),
                }
            }
            members.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (key, rendered)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                quote(key, out);
                out.push(':');
                out.push_str(rendered);
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A string, with every control character that could act as a separator
/// downstream turned into something inert.
fn quote(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
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

/// One field of a tab-separated line, with every byte that could act as a
/// separator turned into something inert.
///
/// The same rule `trailryx_otlp::semconv` applies to an attribute, and it is
/// spelled again here rather than shared because these are two formats with two
/// vocabularies. What must not differ is the property, and that is a test rather
/// than a comment: a member whose name or value carries a tab or a newline cannot
/// forge a second line.
fn push_line(into: &mut String, key: &str, value: &str) {
    escape_field(into, key);
    into.push('\t');
    escape_field(into, value);
    into.push('\n');
}

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

/// The members this mapper reads into typed fields.
///
/// Exported so a test can assert the partition rather than restate it: a member
/// is consumed or it is in the payload, never both and never neither.
pub fn consumed_members() -> &'static [&'static str] {
    CONSUMED
}
