//! Written from the other side: what somebody sending us bytes would try.
//!
//! An ingest endpoint is the one place in the store where an attacker chooses
//! the input. Everything here is a thing a hostile or simply broken emitter can
//! do, and the assertion is always the same shape: the store keeps working, the
//! lie does not land, and whatever was lost is counted.

mod common;

use common::*;
use trailryx_contracts::contracts::Source;
use trailryx_contracts::ingest::Cursor;
use trailryx_otlp::{Limits, MapperConfig, OtlpSource};
use trailryx_record::{EventType, PayloadClass, TenantId, Timestamp};

const NOW: Timestamp = Timestamp(1_700_000_000_400_000_000);

fn source() -> OtlpSource {
    OtlpSource::new(MapperConfig::new(TenantId::parse("acme").unwrap(), "acme.example").unwrap())
}

fn diagnostic(ingest: &trailryx_contracts::ingest::Ingest) -> String {
    ingest
        .payload
        .iter()
        .filter(|p| p.class == PayloadClass::Diagnostic)
        .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
        .collect()
}

#[test]
fn a_sender_cannot_choose_its_own_tenant() {
    // The one that would matter most: a tenant read from the wire is a tenant
    // an emitter can write into. It is configuration, so there is no attribute
    // that reaches it, however the attribute is spelled.
    let span = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("tenant", "victim")
        .str_attr("trailryx.tenant", "victim")
        .str_attr("gen_ai.tenant", "victim");

    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[span]), NOW);
    let items = src.poll(1).unwrap();

    assert_eq!(items[0].meta.tenant.as_str(), "acme");
    // The attempt is not obeyed and not hidden: it is written down where any
    // other unrecognised attribute goes.
    assert!(diagnostic(&items[0]).contains("victim"));
}

#[test]
fn a_sender_cannot_forge_a_trust_domain() {
    // An agent name is attacker-chosen text pasted into an identifier, which is
    // the classic shape of an injection. The trust domain comes from
    // configuration and is always the prefix, whatever the name tries.
    for name in [
        "../evil.example/agent",
        "evil.example/agent",
        "..",
        "agent://evil.example/agent",
    ] {
        let span = SpanBuilder::new("chat")
            .str_attr("gen_ai.operation.name", "chat")
            .str_attr("gen_ai.agent.name", name);
        let mut src = source();
        src.accept(&request(&service("a"), "scope", &[span]), NOW);
        let items = src.poll(1).unwrap();
        assert!(
            items[0]
                .meta
                .agent_id
                .as_str()
                .starts_with("agent://acme.example/"),
            "{name} produced {}",
            items[0].meta.agent_id
        );
    }
}

#[test]
fn an_attribute_value_cannot_forge_a_line_in_the_payload() {
    // The diagnostic payload is line-oriented, so a value containing a newline
    // and a tab is an attempt to write an entry nobody sent.
    let span = SpanBuilder::new("the real name")
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("acme.evil", "harmless\nspan.name\tsomething else entirely");

    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[span]), NOW);
    let items = src.poll(1).unwrap();
    let text = diagnostic(&items[0]);

    // The property, not a particular spelling of it: exactly one line claims
    // to be the span name, and no value contributed a line of its own.
    let names: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("span.name\t"))
        .collect();
    assert_eq!(names, vec!["span.name\tthe real name"], "{text}");
    assert_eq!(text.lines().count(), 3, "one line per attribute: {text}");
    for line in text.lines() {
        assert_eq!(
            line.matches('\t').count(),
            1,
            "a value smuggled a separator: {line}"
        );
    }
    // Nothing was lost in the escaping either.
    assert!(text.contains("harmless"), "{text}");
    assert!(text.contains("something else entirely"), "{text}");
}

#[test]
fn a_value_nested_past_the_limit_does_not_take_the_process_down() {
    // Cheap to send, and without a depth limit it is a way to abort the store
    // from outside: a recursive parser meeting this overflows the stack, and a
    // stack overflow in Rust is not an error anybody can catch.
    let mut value = any_string("bottom");
    for _ in 0..64 {
        value = any_array(&[value]);
    }
    let span = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .attr("acme.deep", value);

    let mut src = source();
    assert_eq!(
        src.accept(&request(&service("a"), "scope", &[span]), NOW),
        0
    );
    assert_eq!(src.wire_report().malformed_batches, 1);
    assert!(src.has_unreported_anomaly());
}

#[test]
fn a_truncated_batch_is_counted_rather_than_fatal() {
    // Half a message arrives whenever a connection drops. It must not stop the
    // receiver, and it must not pass unnoticed either.
    let batch = request(&service("a"), "scope", &[chat()]);
    let mut src = source();
    assert_eq!(src.accept(&batch[..batch.len() / 2], NOW), 0);
    assert_eq!(src.wire_report().malformed_batches, 1);

    // And the next, whole batch still works: one bad message does not poison
    // the receiver.
    assert_eq!(src.accept(&batch, NOW), 1);
}

#[test]
fn an_oversize_value_is_dropped_and_the_rest_of_the_span_survives() {
    let huge = "x".repeat(400 * 1024);
    let span = chat().str_attr("acme.blob", &huge);

    let mut src = source();
    assert_eq!(
        src.accept(&request(&service("a"), "scope", &[span]), NOW),
        1
    );
    assert_eq!(src.dropped().oversize_values, 1);

    let items = src.poll(1).unwrap();
    assert_eq!(
        items[0].meta.event_type,
        EventType::ModelCall,
        "still a record"
    );
}

#[test]
fn a_flood_of_spans_is_bounded_and_the_excess_is_counted() {
    let spans: Vec<SpanBuilder> = (0..40).map(|_| chat()).collect();
    let mut src = OtlpSource::with_limits(
        MapperConfig::new(TenantId::parse("acme").unwrap(), "acme.example").unwrap(),
        Limits {
            max_spans: 10,
            ..Limits::default()
        },
    );
    assert_eq!(
        src.accept(&request(&service("a"), "scope", &spans), NOW),
        10
    );
    assert_eq!(src.dropped().spans, 30);
    assert!(src.has_unreported_anomaly(), "a silent cap is a lie");
}

#[test]
fn a_span_with_no_trace_id_is_refused() {
    let span = chat().trace_id(Vec::new());
    let mut src = source();
    assert_eq!(
        src.accept(&request(&service("a"), "scope", &[span]), NOW),
        0
    );
    assert_eq!(src.report().no_run_id, 1);

    // All-zero is the same thing wearing a hat: it is what an SDK emits when
    // it has no context, and it is not an identifier.
    let span = chat().trace_id(vec![0u8; 16]);
    let mut src = source();
    assert_eq!(
        src.accept(&request(&service("a"), "scope", &[span]), NOW),
        0
    );
    assert_eq!(src.report().no_run_id, 1);
}

#[test]
fn a_span_nobody_can_attribute_falls_to_the_configured_default() {
    // `service.name` with capitals is not an identifier we can index. Rather
    // than lose the span, it goes to the bucket the operator configured, and
    // the attribution is visibly a fallback rather than a guess.
    let span = chat();
    let mut src = source();
    let batch = request(
        &[("service.name", any_string("Billing Assistant"))],
        "scope",
        &[span],
    );
    assert_eq!(src.accept(&batch, NOW), 1);
    let items = src.poll(1).unwrap();
    assert_eq!(
        items[0].meta.agent_id.as_str(),
        "agent://acme.example/unattributed"
    );
}

#[test]
fn an_excessive_clock_skew_is_noticed_and_the_record_is_kept() {
    // An emitter an hour out of step is still evidence. What must not happen is
    // the store treating its time as ours, or noticing and saying nothing.
    let span = chat().times(1_700_000_000_000_000_000, 1_700_000_000_250_000_000);
    let mut src = source();
    let hour_later = Timestamp(1_700_000_000_000_000_000 + 3_600_000_000_000);
    assert_eq!(
        src.accept(&request(&service("a"), "scope", &[span]), hour_later),
        1
    );
    assert_eq!(src.report().excessive_skew, 1);
    assert!(src.has_unreported_anomaly());
}

#[test]
fn a_loss_becomes_a_record() {
    // The rule the whole store follows: a gap that nobody wrote down is worse
    // than a gap, because the trail looks complete.
    let unknown = SpanBuilder::new("x").str_attr("gen_ai.operation.name", "not_a_real_operation");
    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[unknown]), NOW);

    let event = src.anomaly_event(NOW).expect("something was lost");
    assert_eq!(event.meta.event_type, EventType::StoreEvent);
    assert_eq!(event.meta.severity, trailryx_record::Severity::Warning);
    assert_eq!(event.meta.tenant.as_str(), "acme");

    // The fact is metadata and survives erasure; the breakdown is payload,
    // because it counts things that were about somebody.
    let detail = diagnostic(&event);
    assert!(detail.contains("unknown_operation\t1"), "{detail}");
    // Version 2: version 1 treated an all-zero span id as a real correlation
    // name, which manufactured causal edges out of the value OTLP defines as
    // invalid. A record stamped 1 may carry an edge nobody named.
    assert!(detail.contains("mapper_version\t2"), "{detail}");

    // Reporting is not repeating: nothing new means no second record.
    assert!(src.anomaly_event(NOW).is_none());
}

#[test]
fn an_ack_never_rewinds() {
    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[chat()]), NOW);
    src.ack(Cursor(5)).unwrap();
    src.ack(Cursor(2)).unwrap();
    src.ack(Cursor(5)).unwrap();
    // Idempotent and monotonic, as the contract requires: an older cursor is a
    // repeat of something settled, never an instruction to reopen it.
}

#[test]
fn a_span_with_no_span_id_still_becomes_a_record() {
    // Correlation is a bonus, not a precondition. A span the emitter could not
    // name is still an event that happened.
    let span = chat().span_id(Vec::new());
    let mut src = source();
    assert_eq!(
        src.accept(&request(&service("a"), "scope", &[span]), NOW),
        1
    );
    let items = src.poll(1).unwrap();
    assert!(items[0].correlation.is_none());
}

#[test]
fn an_empty_batch_is_not_an_error() {
    let mut src = source();
    assert_eq!(src.accept(&[], NOW), 0);
    assert_eq!(src.wire_report().malformed_batches, 0);
    assert!(!src.has_unreported_anomaly());
}

fn chat() -> SpanBuilder {
    SpanBuilder::new("chat gpt-4o-mini")
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("gen_ai.request.model", "gpt-4o-mini")
}
