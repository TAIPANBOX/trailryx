//! A source told who is calling: `OtlpSource::accept_as`.
//!
//! The ingest door can now know which agent sent a batch, from that agent's own
//! verified token, and a span's agent comes from attributes the sender chose.
//! When the two disagree the span is refused, because writing it would put a
//! record in the name of an agent that never sent it. The refusal is not
//! silent: it is counted with every other loss, and it becomes a record of its
//! own, under the name of the agent that made the attempt, in the run its span
//! named. That is invariant 34's rule for a plane that will not keep
//! something, applied to the newest thing it will not keep.

use crate::common;

use common::*;
use trailryx_contracts::contracts::Source;
use trailryx_otlp::{MapperConfig, OtlpSource};
use trailryx_record::{AgentId, EventType, PayloadClass, Severity, TenantId, Timestamp, Verdict};

const NOW: Timestamp = Timestamp(1_700_000_000_400_000_000);

fn source() -> OtlpSource {
    OtlpSource::new(MapperConfig::new(TenantId::parse("acme").unwrap(), "acme.example").unwrap())
}

fn agent(name: &str) -> AgentId {
    AgentId::parse_strict(format!("agent://acme.example/{name}")).unwrap()
}

fn chat(trace: u8) -> SpanBuilder {
    SpanBuilder::new("chat")
        .trace_id(vec![trace; 16])
        .str_attr("gen_ai.operation.name", "chat")
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
fn with_no_caller_the_source_writes_what_it_always_wrote() {
    let batch = request(&service("a"), "scope", &[chat(1), chat(2)]);
    let mut plain = source();
    let mut unbound = source();
    assert_eq!(plain.accept(&batch, NOW), 2);
    assert_eq!(unbound.accept_as(&batch, NOW, None), 2);
    assert_eq!(plain.poll(10).unwrap(), unbound.poll(10).unwrap());
    assert_eq!(unbound.report().not_the_caller, 0);
}

#[test]
fn a_span_naming_the_caller_is_kept() {
    let mut src = source();
    let produced = src.accept_as(
        &request(&service("a"), "scope", &[chat(1)]),
        NOW,
        Some(&agent("a")),
    );
    assert_eq!(produced, 1);
    let items = src.poll(10).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].meta.agent_id, agent("a"));
    assert_eq!(items[0].meta.event_type, EventType::ModelCall);
    assert_eq!(src.report().not_the_caller, 0);
}

#[test]
fn a_span_naming_another_agent_is_refused_and_written_down_under_the_caller() {
    let mut src = source();
    let produced = src.accept_as(
        &request(&service("b"), "scope", &[chat(0x5e)]),
        NOW,
        Some(&agent("a")),
    );
    assert_eq!(produced, 0, "no record of b's was produced");
    assert_eq!(src.report().not_the_caller, 1);
    assert_eq!(
        src.report().lost(),
        1,
        "a refusal is a loss and is counted as one"
    );

    let items = src.poll(10).unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    let note = &items[0];
    assert_eq!(note.meta.agent_id, agent("a"), "under the caller's name");
    assert_eq!(note.meta.event_type, EventType::StoreEvent);
    assert_eq!(note.meta.severity, Severity::Warning);
    assert_eq!(note.meta.verdict, Some(Verdict::Denied));
    assert_eq!(
        note.meta.run_id.as_str(),
        "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e",
        "in the run the refused span named"
    );
    assert_eq!(note.meta.tenant.as_str(), "acme");
    // The names are claims the caller made, and identifiers or not they are
    // kept where everything a sender chose is kept: the payload plane.
    let detail = diagnostic(note);
    assert!(detail.contains("spans_refused\t1\n"), "{detail}");
    assert!(detail.contains("agent://acme.example/b"), "{detail}");
    assert!(detail.contains("reason\tnot_the_caller\n"), "{detail}");
}

/// A span that names nobody falls to the deployment's default agent, and the
/// default is not the caller either. Otherwise leaving the attribute off would
/// be the way to write under a name nobody verified.
#[test]
fn the_default_agent_is_not_a_way_around_the_caller() {
    let mut src = source();
    let produced = src.accept_as(&request(&[], "scope", &[chat(7)]), NOW, Some(&agent("a")));
    assert_eq!(produced, 0);
    assert_eq!(src.report().not_the_caller, 1);
}

/// One note per batch, however many spans it refused. A note per span would let
/// one authenticated agent turn every batch it sends into as many store
/// records as it has spans, in somebody else's run.
#[test]
fn one_note_per_batch_however_many_spans_were_refused() {
    let mut src = source();
    let spans: Vec<SpanBuilder> = (1..=5).map(chat).collect();
    let produced = src.accept_as(
        &request(&service("b"), "scope", &spans),
        NOW,
        Some(&agent("a")),
    );
    assert_eq!(produced, 0);
    assert_eq!(src.report().not_the_caller, 5);
    let items = src.poll(10).unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(diagnostic(&items[0]).contains("spans_refused\t5\n"));
}

/// Kept and refused side by side, in the order they arrived, with the note
/// after the batch it is about.
#[test]
fn a_mixed_batch_keeps_the_callers_spans_and_refuses_the_rest() {
    let mut src = source();
    let spans = [
        chat(1),
        chat(2).str_attr("gen_ai.agent.id", "b"),
        chat(3).str_attr("gen_ai.agent.id", "a"),
    ];
    let produced = src.accept_as(
        &request(&service("a"), "scope", &spans),
        NOW,
        Some(&agent("a")),
    );
    assert_eq!(produced, 2);
    let kinds: Vec<(String, EventType)> = src
        .poll(10)
        .unwrap()
        .iter()
        .map(|i| (i.meta.agent_id.as_str().to_owned(), i.meta.event_type))
        .collect();
    assert_eq!(
        kinds,
        vec![
            ("agent://acme.example/a".to_owned(), EventType::ModelCall),
            ("agent://acme.example/a".to_owned(), EventType::ModelCall),
            ("agent://acme.example/a".to_owned(), EventType::StoreEvent),
        ]
    );
}

/// And the counters the store already writes down carry it by name.
#[test]
fn the_anomaly_record_counts_the_refusal() {
    let mut src = source();
    src.accept_as(
        &request(&service("b"), "scope", &[chat(1)]),
        NOW,
        Some(&agent("a")),
    );
    assert!(src.has_unreported_anomaly());
    let anomaly = src.anomaly_event(NOW).expect("an anomaly");
    assert!(
        diagnostic(&anomaly).contains("not_the_caller\t1\n"),
        "{}",
        diagnostic(&anomaly)
    );
}
