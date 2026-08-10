//! The shared envelope, against the estate's own examples and against a
//! producer that is trying it on.
//!
//! Two things are kept honest here and they are different questions. The fixture
//! at the bottom is `agent-passport/examples/events.ndjson` **verbatim**, six
//! lines written by whoever wrote the specification and not by whoever wrote this
//! reader, so a shape either side drifts on shows up as a failure rather than as
//! two documents agreeing with each other. The rest is the ingest door: what a
//! producer can and cannot get into the metadata plane.

use trailryx_agentevent::{EnvelopeConfig, MAPPER_VERSION, Rejection, map_line};
use trailryx_contracts::ingest::Cursor;
use trailryx_record::{
    AgentId, ErrorCode, EventType, PrincipalId, Severity, TenantId, Timestamp, Verdict,
};

/// The trust domain the specification's own examples are written in.
const SPEC_DOMAIN: &str = "acme-bank.example";
const OURS: &str = "acme.example";

fn config(domain: &str) -> EnvelopeConfig {
    EnvelopeConfig::new(
        TenantId::parse("acme").expect("a constant tenant parses"),
        domain,
    )
    .expect("a constant trust domain is usable")
}

fn map(domain: &str, line: &str) -> Result<trailryx_contracts::ingest::Ingest, Rejection> {
    map_line(&config(domain), line.as_bytes(), Cursor(1))
}

/// One line in our own trust domain, with the members a caller wants to vary.
fn line(kind: &str, extra: &str) -> String {
    format!(
        r#"{{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:44.100Z",
            "source":"tokenfuse","type":"{kind}","severity":"critical",
            "agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842"{extra}}}"#
    )
    .replace('\n', "")
}

fn payload_text(unit: &trailryx_contracts::ingest::Ingest) -> String {
    unit.payload
        .iter()
        .map(|part| String::from_utf8_lossy(&part.bytes).into_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// The specification's own file
// ---------------------------------------------------------------------------

/// Every line of `agent-passport/examples/events.ndjson`, and what this reading
/// of the registry does with it. Two map and four are refused **by name**, which
/// is the part worth pinning: a refusal that is counted and named is a decision,
/// and a refusal nobody wrote down is a hole.
///
/// The fourth line is the one to read twice. `wardryx`'s `policy_deny` maps
/// perfectly and carries no `run_id`, which the envelope allows and a record does
/// not: a record names a run and inventing one would put unrelated events in a
/// single run. So a producer that wants its events in this store has to send one,
/// and that is a finding about the two formats rather than a defect in either.
#[test]
fn the_specs_own_examples_map_or_are_refused_by_name() {
    let expected: [Result<(EventType, Severity), Rejection>; 6] = [
        Ok((EventType::BudgetCheck, Severity::Critical)),
        Ok((EventType::MemoryAccess, Severity::Warning)),
        // qryx's `evidence_signed`: a fact about infrastructure rather than a
        // decision an agent took, and there is no event type for one.
        Err(Rejection::UnknownType),
        Err(Rejection::NoRunId),
        Err(Rejection::UnknownType),
        Err(Rejection::UnknownType),
    ];

    for (raw, want) in SPEC_EXAMPLES.lines().zip(expected) {
        match (map(SPEC_DOMAIN, raw), want) {
            (Ok(unit), Ok((event_type, severity))) => {
                assert_eq!(unit.meta.event_type, event_type, "{raw}");
                assert_eq!(unit.meta.severity, severity, "{raw}");
                assert_eq!(unit.meta.mapper, MAPPER_VERSION);
            }
            (Err(got), Err(want)) => assert_eq!(got, want, "{raw}"),
            (got, want) => panic!("{raw}\n  got {got:?}\n  want {want:?}"),
        }
    }
}

/// The delegation chain crosses, whole, and it is the reason the two formats fit
/// each other at all: `on_behalf_of` is the same thing in both.
///
/// The line is the specification's fourth example with a `run_id` added, because
/// its own has none. That is the one change, and it is called out rather than
/// smuggled in: without it this test would be about the missing member instead.
#[test]
fn a_delegation_chain_crosses_into_the_metadata_plane() {
    let wardryx = SPEC_EXAMPLES
        .lines()
        .nth(3)
        .expect("the wardryx example")
        .replace(
            r#""severity": "high""#,
            r#""severity": "high", "run_id": "run-9001""#,
        );
    let unit = map(SPEC_DOMAIN, &wardryx).expect("it maps");
    assert_eq!(
        unit.meta.on_behalf_of,
        vec![
            PrincipalId::parse_strict("agent://acme-bank.example/eng/ci-orchestrator")
                .expect("a constant principal parses")
        ]
    );
    assert_eq!(unit.meta.verdict, Some(Verdict::Denied));
    assert_eq!(unit.meta.error, Some(ErrorCode::PolicyDenied));
    assert_eq!(
        unit.meta.agent_id,
        AgentId::parse_strict("agent://acme-bank.example/eng/ci-fixer/instance-7")
            .expect("a constant agent parses")
    );

    // A chain with one unusable link is not shortened: the whole member goes to
    // the payload plane, because a delegation chain missing a link is a different
    // chain and it is exactly the thing an auditor follows.
    let broken = wardryx.replace(
        r#""agent://acme-bank.example/eng/ci-orchestrator""#,
        r#""agent://acme-bank.example/eng/ci-orchestrator", "the ops team""#,
    );
    let unit = map(SPEC_DOMAIN, &broken).expect("it maps");
    assert!(unit.meta.on_behalf_of.is_empty());
    assert!(payload_text(&unit).contains("ci-orchestrator"));
}

// ---------------------------------------------------------------------------
// The ingest door
// ---------------------------------------------------------------------------

/// Invariant 23, on this door. The journal's own constructor takes every one of
/// these, because the journal wrote them; a peer, a file and an envelope are
/// outside wearing the journal's clothes.
#[test]
fn an_agent_id_that_is_not_a_uri_is_refused_the_way_the_ingest_door_refuses_it() {
    for raw in [
        "support/tier1-bot",
        "agent://acme.example",
        "agent:///support",
        "spiffe://acme.example/agent/support",
    ] {
        assert!(
            AgentId::parse(raw).is_ok(),
            "{raw} is what the journal's lax constructor takes"
        );
        let event = line("budget_exhausted", "").replace(
            r#""agent_id":"agent://acme.example/support/tier1-bot""#,
            &format!(r#""agent_id":"{raw}""#),
        );
        assert_eq!(map(OURS, &event), Err(Rejection::NoAgent), "{raw}");
    }
}

/// A trust domain is the operator's, never the wire's. The OTLP mapper enforces
/// that by building the identifier out of its own configuration; an envelope
/// carries the identifier whole, so here it is a comparison, and without it one
/// valid producer could write records about every agent in the estate.
#[test]
fn an_agent_from_another_trust_domain_is_refused_rather_than_recorded() {
    let event = line("budget_exhausted", "").replace(
        r#""agent_id":"agent://acme.example/support/tier1-bot""#,
        r#""agent_id":"agent://other.example/support/tier1-bot""#,
    );
    assert_eq!(map(OURS, &event), Err(Rejection::ForeignTrustDomain));
    // And a domain that merely starts the same way is another domain.
    let lookalike = line("budget_exhausted", "").replace(
        r#""agent_id":"agent://acme.example/support/tier1-bot""#,
        r#""agent_id":"agent://acme.example.attacker.test/support""#,
    );
    assert_eq!(map(OURS, &lookalike), Err(Rejection::ForeignTrustDomain));
}

/// A run identifier is not invented. An event with none produces no record,
/// because a fabricated run would put unrelated events in one run and a
/// reconstruction of that run would report them as related.
#[test]
fn an_event_with_no_run_is_refused_rather_than_given_one() {
    let no_run = line("budget_exhausted", "").replace(r#","run_id":"run-8842""#, "");
    assert_eq!(map(OURS, &no_run), Err(Rejection::NoRunId));
    let unusable = line("budget_exhausted", "").replace(
        r#""run_id":"run-8842""#,
        r#""run_id":"Please summarise the attached report""#,
    );
    assert_eq!(map(OURS, &unusable), Err(Rejection::NoRunId));
}

#[test]
fn a_schema_this_reader_does_not_accept_is_refused() {
    for schema in [
        "taipanbox.dev/agent-event/v0.4",
        "taipanbox.dev/agent-passport/v0.1",
        "",
    ] {
        let event = line("budget_exhausted", "").replace("taipanbox.dev/agent-event/v0.2", schema);
        assert_eq!(map(OURS, &event), Err(Rejection::UnknownSchema), "{schema}");
    }
    // And both of the two it must accept.
    for schema in [
        "taipanbox.dev/agent-event/v0.1",
        "taipanbox.dev/agent-event/v0.2",
        // v0.3 moved from the refused list to this one when this reader learned
        // what a claimed subject is. Accepting a version is not a promise to
        // record its traffic: a claim under it is refused one layer down, by
        // name. See `a_claimed_subject_is_refused_by_name_rather_than_by_encoding`.
        "taipanbox.dev/agent-event/v0.3",
    ] {
        let event = line("budget_exhausted", "").replace("taipanbox.dev/agent-event/v0.2", schema);
        assert!(map(OURS, &event).is_ok(), "{schema}");
    }
}

/// A dispatch journal line, at the door, with the members heraldyx actually
/// writes.
///
/// The shape is `heraldyx/internal/record/record.go`: one agent-event per message
/// sent, `type` is `alert_sent`, and `data` carries the dedup key, the transport,
/// the outcome word and **the operator addresses that were written to**. The
/// addresses are the reason this test exists rather than being a line in the one
/// above it.
const HERALDYX_DISPATCH: &str = concat!(
    r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-08-06T03:14:00Z","#,
    r#""source":"heraldyx","type":"alert_sent","#,
    r#""agent_id":"agent://acme.example/support/tier1-bot","run_id":"run-8842","#,
    r#""severity":"info","#,
    r#""data":{"kind":"alert","about":"budget_exhausted:agent://acme.example/support/tier1-bot","#,
    r#""to":["ops@acme.example","oncall@acme.example"],"transport":"smtp","outcome":"accepted"},"#,
    r#""prev_hash":"sha256:2e81d20e76391693864bc8b7c0963b6aa87ef867c36bc80a0678166dcfb3168e"}"#,
);

/// A notification that was dispatched is a record, and the person it was
/// dispatched to is not in the metadata plane.
///
/// Two claims, and the second is the one that could go wrong quietly. `data.to`
/// holds operator email addresses, which are personal data by anybody's reading,
/// and the only thing keeping them out of the plane that survives erasure is that
/// this mapper reads **nothing** out of `data`. So the assertion is not that some
/// particular member was skipped, it is that the whole of `data` is in the payload
/// and none of it is in the metadata: `to`, and the transport beside it, and the
/// outcome word beside that.
///
/// The verdict is the tempting mistake and it is asserted empty on purpose.
/// `data.outcome` says "accepted", and reading that into `Verdict::Allowed` would
/// put a producer's free-form member into a typed field that an auditor reads as
/// a decision this store stands behind. A dispatch is not a decision with a
/// verdict; it is a thing that happened.
#[test]
fn a_dispatched_notification_is_a_record_and_the_operator_written_to_is_not() {
    let unit = map(OURS, HERALDYX_DISPATCH).expect("a dispatch journal line maps");
    assert_eq!(
        unit.meta.event_type.as_str(),
        "notification_dispatched",
        "a notification was dispatched to a human, which is not one of the ten decisions"
    );
    assert_eq!(unit.meta.severity, Severity::Info);
    assert_eq!(unit.meta.mapper, MAPPER_VERSION);
    assert_eq!(unit.meta.verdict, None, "a dispatch decides nothing");
    assert_eq!(unit.meta.error, None);
    assert_eq!(
        unit.meta.run_id.as_str(),
        "run-8842",
        "the run the notification was about, carried whole"
    );

    let metadata = format!("{:?}", unit.meta);
    let payload = payload_text(&unit);
    for from_data in [
        "ops@acme.example",
        "oncall@acme.example",
        "smtp",
        "accepted",
        "budget_exhausted",
    ] {
        assert!(
            !metadata.contains(from_data),
            "{from_data} came out of `data` and reached the metadata plane:\n{metadata}"
        );
        assert!(
            payload.contains(from_data),
            "{from_data} reached neither plane:\n{payload}"
        );
    }
}

/// The severity band, when the producer sends none.
///
/// heraldyx stamps `info` on every dispatch, so this is about the other producers
/// that will write this type later: a notification is a thing that happened and
/// not a warning about anything, so the fallback is the quietest band that is not
/// debug.
#[test]
fn a_dispatch_with_no_severity_is_information_rather_than_a_warning() {
    let no_severity = HERALDYX_DISPATCH.replace(r#""severity":"info","#, "");
    let unit = map(OURS, &no_severity).expect("a dispatch with no severity maps");
    assert_eq!(unit.meta.severity, Severity::Info);
}

/// A type this reading does not map is refused rather than mapped to something
/// adjacent, which is the rule `map_span` states for an unknown operation.
#[test]
fn an_unmapped_type_is_refused_rather_than_mapped_to_something_adjacent() {
    for kind in ["mcp_drift", "crypto_finding", "console_command", "sim_run"] {
        assert_eq!(
            map(OURS, &line(kind, "")),
            Err(Rejection::UnknownType),
            "{kind}"
        );
    }
}

// ---------------------------------------------------------------------------
// The plane boundary
// ---------------------------------------------------------------------------

/// Every member lands in exactly one plane: never both, which would leave a copy
/// of content where erasure cannot reach it, and never neither, which is a silent
/// loss. The partition is asserted rather than described.
#[test]
fn every_member_lands_in_exactly_one_plane() {
    let event = line(
        "budget_exhausted",
        r#","data":{"budget_usd":2.0,"note":"for ivan.petrenko@example.com"},
           "prev_hash":"sha256:2e81d20e76391693864bc8b7c0963b6aa87ef867c36bc80a0678166dcfb3168e",
           "something_a_later_schema_added":[1,2,3]"#,
    )
    .replace('\n', "")
    .replace("           ", "");
    let unit = map(OURS, &event).expect("it maps");
    let payload = payload_text(&unit);

    // In the payload, because no typed field holds them.
    for member in [
        "source",
        "data",
        "prev_hash",
        "something_a_later_schema_added",
    ] {
        assert!(
            payload.contains(member),
            "{member} reached neither plane:\n{payload}"
        );
    }
    // And in the metadata plane, which means they are not repeated below.
    for member in trailryx_agentevent::consumed_members() {
        assert!(
            !payload.contains(&format!("{member}\t")),
            "{member} is in both planes:\n{payload}"
        );
    }
    assert_eq!(unit.meta.severity, Severity::Critical);
    assert_eq!(
        unit.meta.occurred_at.as_untrusted(),
        &Timestamp(1_783_566_764_100_000_000)
    );
}

/// The rule that decides every hard case, stated as the test invariant 5 states
/// it: prose does not reach the plane that survives erasure.
#[test]
fn no_prompt_text_reaches_the_metadata_plane() {
    let event = line(
        "policy_deny",
        r#","data":{"prompt":"settle the balance for Ivan Petrenko, born 1979"}"#,
    );
    let unit = map(OURS, &event).expect("it maps");
    let metadata = format!("{:?}", unit.meta);
    assert!(
        !metadata.contains("Ivan Petrenko"),
        "the metadata plane carries content:\n{metadata}"
    );
    assert!(payload_text(&unit).contains("Ivan Petrenko"));
}

/// A member's own name and value are the producer's free text, and these bytes
/// are hashed and committed to. A tab or a newline in either must not be able to
/// forge a line, or a field, that was never sent.
#[test]
fn a_member_cannot_forge_a_second_line_of_payload() {
    let event = line(
        "policy_deny",
        r#","data":"tokenfuse\ndata\tforged","weird\tkey":"x""#,
    );
    let unit = map(OURS, &event).expect("it maps");
    let payload = payload_text(&unit);
    let lines: Vec<&str> = payload.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "three members reached the payload, so there are three lines:\n{payload}"
    );
    for rendered in &lines {
        assert_eq!(
            rendered.matches('\t').count(),
            1,
            "a member forged a second field: {rendered:?}"
        );
    }
    assert!(payload.contains("weird"), "{payload}");
}

// ---------------------------------------------------------------------------
// Two spellings, one meaning
// ---------------------------------------------------------------------------

/// The differential this format allows. There is one decoder rather than two, so
/// what has to be held is that the record does not depend on how the producer
/// happened to serialise the object: member order, whitespace and escaping are
/// choices a JSON writer makes freely, and two of them must not become two
/// different records.
#[test]
fn two_spellings_of_one_event_produce_one_record() {
    let compact = concat!(
        r#"{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-07-09T03:12:44.100Z","#,
        r#""source":"wardryx","type":"policy_deny","severity":"high","#,
        r#""agent_id":"agent://acme.example/eng/ci-fixer","run_id":"run-8842","#,
        r#""data":{"policy":"prod-deploy","reason":"café"}}"#
    );
    let reordered = concat!(
        "{\n  \"data\" : { \"reason\" : \"café\", \"policy\" : \"prod-deploy\" },\n",
        "  \"run_id\":\"run-8842\",  \"agent_id\" : \"agent://acme.example/eng/ci-fixer\",\n",
        "  \"severity\":\"high\", \"type\":\"policy_deny\", \"source\":\"wardryx\",\n",
        "  \"ts\":\"2026-07-09T03:12:44.100Z\",\n",
        "  \"schema\":\"taipanbox.dev/agent-event/v0.2\"\n}"
    );

    let a = map(OURS, compact).expect("the compact spelling maps");
    let b = map(OURS, reordered).expect("the reordered spelling maps");
    assert_eq!(a.meta, b.meta, "two spellings produced two records");
    // The payload is sorted by member, so the bytes match as well, which is what
    // makes the payload's hash a property of the event rather than of the writer.
    assert_eq!(
        payload_text(&a).lines().collect::<Vec<_>>(),
        payload_text(&b).lines().collect::<Vec<_>>()
    );
}

/// `severity` is optional in the schema and a record's is not, so something has
/// to answer. The answer is the registry's own band for that type, which is
/// somebody else's decision written down, rather than a value invented here.
#[test]
fn a_missing_severity_comes_from_the_registry_rather_than_from_nowhere() {
    let no_severity = line("approval_requested", "").replace(r#""severity":"critical","#, "");
    let unit = map(OURS, &no_severity).expect("it maps");
    assert_eq!(unit.meta.severity, Severity::Warning);
    assert_eq!(unit.meta.verdict, Some(Verdict::Held));
    // And a severity that is present is believed, whatever the registry says.
    let unit = map(OURS, &line("approval_requested", "")).expect("it maps");
    assert_eq!(unit.meta.severity, Severity::Critical);
}

#[test]
fn a_line_that_is_not_an_object_is_refused_rather_than_half_read() {
    for raw in [
        "",
        "not json",
        "[]",
        "\"a string\"",
        r#"{"schema":"taipanbox.dev/agent-event/v0.2""#,
        // A duplicate member is fatal to the reader this crate goes through, and
        // that is the point of going through it: which of two values wins is an
        // implementation detail, and a detail must not be baked into evidence.
        r#"{"schema":"taipanbox.dev/agent-event/v0.2","schema":"x"}"#,
    ] {
        assert_eq!(map(OURS, raw), Err(Rejection::NotAnEnvelope), "{raw:?}");
    }
}

/// `agent-passport/examples/events.ndjson`, verbatim, read on 6 August 2026.
///
/// Copied rather than read from the other repository at test time: a fixture that
/// reaches outside its own tree is a fixture that fails for reasons that have
/// nothing to do with the code. What it costs is that somebody has to come back
/// when the specification's examples change, and this comment is where they will
/// look.
const SPEC_EXAMPLES: &str = concat!(
    r#"{"schema": "taipanbox.dev/agent-event/v0.1", "ts": "2026-07-09T03:12:44.100Z", "source": "tokenfuse", "type": "budget_exhausted", "severity": "critical", "agent_id": "agent://acme-bank.example/support/tier1-bot", "run_id": "run-8842", "on_behalf_of": ["user://acme-bank.example/j.doe"], "data": {"budget_usd": 2.00, "spent_usd": 2.00, "action": "blocked_402"}, "prev_hash": "sha256:2e81d20e76391693864bc8b7c0963b6aa87ef867c36bc80a0678166dcfb3168e"}"#,
    "\n",
    r#"{"schema": "taipanbox.dev/agent-event/v0.1", "ts": "2026-07-09T03:15:02.500Z", "source": "engram", "type": "contradiction_found", "severity": "medium", "agent_id": "agent://acme-bank.example/support/tier1-bot", "run_id": "run-8843", "data": {"memory_id": "mem-3391", "conflicting_memory_id": "mem-2207", "topic": "customer_refund_policy"}}"#,
    "\n",
    r#"{"schema": "taipanbox.dev/agent-event/v0.1", "ts": "2026-07-09T03:21:11.900Z", "source": "qryx", "type": "evidence_signed", "severity": "info", "agent_id": "agent://acme-bank.example/support/tier1-bot", "data": {"evidence_id": "ev-55210", "algorithm": "ed25519", "subject": "agent://acme-bank.example/support/tier1-bot"}, "prev_hash": "sha256:18685d1af6bf73830978dfc5145c333129c0c82825a5605e7c05d03b361c56c8"}"#,
    "\n",
    r#"{"schema": "taipanbox.dev/agent-event/v0.2", "ts": "2026-07-09T03:25:47.200Z", "source": "wardryx", "type": "policy_deny", "severity": "high", "agent_id": "agent://acme-bank.example/eng/ci-fixer/instance-7", "on_behalf_of": ["agent://acme-bank.example/eng/ci-orchestrator"], "data": {"policy": "prod-deploy-requires-approval", "reason": "no approval on file for deploy:prod scope"}}"#,
    "\n",
    r#"{"schema": "taipanbox.dev/agent-event/v0.2", "ts": "2026-07-09T03:28:15.400Z", "source": "verdryx", "type": "quality_drift", "severity": "high", "agent_id": "agent://acme-bank.example/support/tier1-bot", "data": {"eval_suite": "refund-policy-qa", "baseline_score": 0.94, "current_score": 0.81, "delta": -0.13}}"#,
    "\n",
    r#"{"schema": "taipanbox.dev/agent-event/v0.2", "ts": "2026-07-09T03:31:52.700Z", "source": "mockryx", "type": "blast_radius_measured", "severity": "medium", "agent_id": "agent://acme-bank.example/eng/ci-fixer/instance-7", "on_behalf_of": ["agent://acme-bank.example/eng/ci-orchestrator"], "data": {"scenario": "prod-deploy-rehearsal", "blast_radius_score": 0.62, "affected_resources": 14}}"#,
);

// ---------------------------------------------------------------------------
// Web egress (scopyx), SPEC 6.2
// ---------------------------------------------------------------------------

/// A governed fetch is a tool call, and its severity comes from the registry
/// band rather than from anything this store invents.
#[test]
fn a_governed_fetch_becomes_a_tool_call_at_the_registry_band() {
    let event = line(
        "web_fetch",
        r#","data":{"origin":"https://vendor.example"}"#,
    )
    .replace(r#""source":"tokenfuse""#, r#""source":"scopyx""#)
    .replace(r#""severity":"critical""#, r#""severity":"low""#);
    let unit = map(OURS, &event).expect("a web_fetch maps");
    assert_eq!(unit.meta.event_type, EventType::ToolCall);
    assert_eq!(
        unit.meta.verdict, None,
        "it happened; there is nothing to decide"
    );
    assert_eq!(unit.meta.error, None);
    assert_eq!(
        unit.meta.severity,
        Severity::Notice,
        "`low` is Notice, per severity_for"
    );
}

/// A refused fetch is a denial, and it carries NO error code on purpose.
///
/// `web_blocked` covers a policy that said no, an address inside the
/// deployment, an unsupported scheme, a spent per-hour cap, and a policy plane
/// that could not be asked. `PolicyDenied` is false for the address case, where
/// the refusal happens before any policy runs, so the typed field stays empty
/// and the producer's own `verdict` member reaches the payload plane instead.
#[test]
fn a_refused_fetch_is_denied_without_this_store_naming_the_rule() {
    let event = line(
        "web_blocked",
        r#","data":{"origin":"http://169.254.169.254","verdict":"deny_address"}"#,
    )
    .replace(r#""source":"tokenfuse""#, r#""source":"scopyx""#)
    .replace(r#""severity":"critical""#, r#""severity":"high""#);
    let unit = map(OURS, &event).expect("a web_blocked maps");
    assert_eq!(unit.meta.event_type, EventType::PolicyDecision);
    assert_eq!(unit.meta.verdict, Some(Verdict::Denied));
    assert_eq!(
        unit.meta.error, None,
        "an address refusal is not a policy denial, and this store must not say it was"
    );
    assert_eq!(unit.meta.severity, Severity::Error, "`high` is Error");

    // The distinction is not lost, it is somewhere this store makes no claim
    // about it.
    assert!(
        payload_text(&unit).contains("deny_address"),
        "the producer's own verdict must reach the payload plane"
    );
}

/// Invariant 35, for the new source. A producer this store accepts by name is
/// still refused when it writes about an agent in somebody else's trust domain:
/// without the comparison, one valid producer could record every agent in the
/// estate under one receiver's tenant.
#[test]
fn a_scopyx_event_about_another_trust_domain_is_refused_rather_than_recorded() {
    let foreign = line("web_fetch", "")
        .replace(r#""source":"tokenfuse""#, r#""source":"scopyx""#)
        .replace(
            r#""agent_id":"agent://acme.example/support/tier1-bot""#,
            r#""agent_id":"agent://other.example/support/tier1-bot""#,
        );
    assert_eq!(map(OURS, &foreign), Err(Rejection::ForeignTrustDomain));

    // And a domain that merely starts the same way is another domain.
    let lookalike = line("web_blocked", "")
        .replace(r#""source":"tokenfuse""#, r#""source":"scopyx""#)
        .replace(
            r#""agent_id":"agent://acme.example/support/tier1-bot""#,
            r#""agent_id":"agent://acme.example.attacker.test/support""#,
        );
    assert_eq!(map(OURS, &lookalike), Err(Rejection::ForeignTrustDomain));
}

/// A URL never reaches a typed metadata field, because this mapper does not
/// read `data` and scopyx never wrote one there in the first place.
///
/// Both halves matter. The producer keeps the path and query out of the event,
/// and this store keeps `data` out of metadata; either alone would leave a URL
/// somewhere erasure cannot reach the day the other changed.
#[test]
fn a_fetched_url_stays_out_of_the_metadata_plane() {
    let event = line(
        "web_fetch",
        r#","data":{"origin":"https://crm.example","url_sha384":"sha384:abc"}"#,
    )
    .replace(r#""source":"tokenfuse""#, r#""source":"scopyx""#)
    .replace(r#""severity":"critical""#, r#""severity":"low""#);
    let unit = map(OURS, &event).expect("maps");

    let meta = format!("{:?}", unit.meta);
    for leaked in ["crm.example", "sha384:abc", "origin"] {
        assert!(
            !meta.contains(leaked),
            "the metadata plane carries {leaked:?}: {meta}"
        );
    }
}

// The identity plane: a finding becomes a record, a claim does not.
// ---------------------------------------------------------------------------

/// A finding from the identity plane maps, and it decides nothing.
///
/// No verdict and no error code, because a finding is a detector speaking and
/// not the estate concluding. The record fixes that at this time this producer
/// said this about this subject, which is the same standing
/// `notification_dispatched` takes about delivery.
#[test]
fn an_identity_finding_maps_and_asserts_no_verdict() {
    let event = line(
        "identity_finding",
        r#","data":{"detector":"unrouted_egress"}"#,
    )
    .replace("\"source\":\"tokenfuse\"", "\"source\":\"idryx\"");
    let unit = map(OURS, &event).expect("an identity finding must map");
    assert_eq!(unit.meta.event_type, EventType::IdentityFinding);
    assert_eq!(unit.meta.verdict, None, "a finding decides nothing");
    assert_eq!(unit.meta.error, None, "a finding names no error code");
    assert_eq!(unit.meta.mapper, MAPPER_VERSION);
}

/// Which detector fired never reaches the metadata plane.
///
/// The producer's detector names are its own vocabulary and change without
/// anybody else editing anything. Compiling them into a frozen format is what
/// this store refuses, so `data` travels to the payload plane whole and the
/// typed side carries the subject, the type and the time.
#[test]
fn the_detector_name_stays_in_the_payload_plane() {
    let event = line(
        "identity_finding",
        r#","data":{"detector":"claimed_agent_drift"}"#,
    )
    .replace("\"source\":\"tokenfuse\"", "\"source\":\"idryx\"");
    let unit = map(OURS, &event).expect("an identity finding must map");
    assert!(
        payload_text(&unit).contains("claimed_agent_drift"),
        "the detector must reach the payload plane, which is where an operator finds it"
    );
    let metadata = format!("{:?}", unit.meta);
    assert!(
        !metadata.contains("claimed_agent_drift"),
        "a producer's own vocabulary reached the metadata plane:\n{metadata}"
    );
}

/// A subject a process asserted about itself is refused BY NAME, and never
/// recorded.
///
/// `agent_id` is mandatory, provable, committed into the immutable index roots
/// and one of the nine unerasable fields, and its promise to hold no personal
/// data is contractual: an operator asserts the value space holds machine names.
/// Every party that authors an established identifier is under that contract,
/// and the party that authors a claimed one is not. A process writes its own
/// environment, so within the permitted characters it can write a person's name
/// into a field erasure can never reach.
#[test]
fn a_claimed_subject_is_refused_by_name_rather_than_by_encoding() {
    let claimed = line("identity_finding", "")
        .replace("\"source\":\"tokenfuse\"", "\"source\":\"idryx\"")
        .replace("agent-event/v0.2", "agent-event/v0.3")
        .replace(
            "\"agent_id\":\"agent://acme.example/support/tier1-bot\"",
            "\"agent_id\":\"claimed:agent://acme.example/support/tier1-bot\"",
        );
    assert_eq!(
        map(OURS, &claimed),
        Err(Rejection::ClaimedSubject),
        "a claim must be refused under its own name, not blended into another count"
    );
}

/// And the refusal is about the CLAIM, not about the domain.
///
/// A claimed subject naming another organisation's agent is still
/// `ClaimedSubject`. Counting it as a foreign trust domain would say a producer
/// of ours is misconfigured and send somebody to check configuration, when the
/// domain is whatever the process typed. The tenant comparison deliberately
/// never runs on one.
#[test]
fn a_claimed_subject_from_another_domain_is_still_a_claim_and_not_a_tenant_finding() {
    let claimed = line("identity_finding", "")
        .replace("\"source\":\"tokenfuse\"", "\"source\":\"idryx\"")
        .replace("agent-event/v0.2", "agent-event/v0.3")
        .replace(
            "\"agent_id\":\"agent://acme.example/support/tier1-bot\"",
            "\"agent_id\":\"claimed:agent://other-bank.example/support/tier1-bot\"",
        );
    assert_eq!(map(OURS, &claimed), Err(Rejection::ClaimedSubject));
}

/// A `claimed:` wrapper around something that is not an identifier is not a
/// claim this door has to reason about. It is garbage, and `NoAgent` is true of
/// it.
#[test]
fn a_claimed_wrapper_around_garbage_is_no_agent_rather_than_a_claim() {
    let junk = line("identity_finding", "")
        .replace("\"source\":\"tokenfuse\"", "\"source\":\"idryx\"")
        .replace("agent-event/v0.2", "agent-event/v0.3")
        .replace(
            "\"agent_id\":\"agent://acme.example/support/tier1-bot\"",
            "\"agent_id\":\"claimed:not-a-uri\"",
        );
    assert_eq!(map(OURS, &junk), Err(Rejection::NoAgent));
}

/// An ESTABLISHED subject under v0.3 still maps.
///
/// The producer is not supposed to stamp v0.3 on an established subject, and
/// that MUST NOT is the producer's rule. A consumer that refused the line would
/// be punishing a reader for a writer's mistake, and the event is safe and
/// honest to record either way.
#[test]
fn an_established_subject_under_v0_3_still_maps() {
    let event = line("identity_finding", "")
        .replace("\"source\":\"tokenfuse\"", "\"source\":\"idryx\"")
        .replace("agent-event/v0.2", "agent-event/v0.3");
    let unit = map(OURS, &event).expect("an established subject maps under any accepted version");
    assert_eq!(unit.meta.event_type, EventType::IdentityFinding);
}
