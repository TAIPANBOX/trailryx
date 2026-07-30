//! Written from the other side: what somebody writing us a file would try.
//!
//! A file is a slower trust boundary than a socket and not a smaller one. It is
//! read later, by a process with more privilege than the producer had, and
//! usually with nobody watching. So the assertion here is always the same shape
//! as `hostile.rs` next door: the reader keeps working, the lie does not land,
//! and whatever was lost is counted.
//!
//! The counter tests at the end are about the reporting itself. A store whose
//! anomaly total has silently lost a term is a store that reports "nothing to
//! report" over a hole, which is the one failure mode worse than the hole.

mod common;

use common::jsonenc;
use common::jsonenc::IntForm;
use std::collections::BTreeSet;
use trailryx_contracts::contracts::Source;
use trailryx_contracts::ingest::{Cursor, Ingest};
use trailryx_otlp::MapperConfig;
use trailryx_otlp::jsonl::{Class, Counters, JsonlSource};
use trailryx_record::{AgentId, EventType, MapperVersion, PayloadClass, TenantId, Timestamp};

const NOW: Timestamp = Timestamp(1_700_000_000_400_000_000);
const START: u64 = 1_700_000_000_000_000_000;
const TRACE: [u8; 16] = [0xab; 16];

fn cfg() -> MapperConfig {
    MapperConfig::new(TenantId::parse("acme").unwrap(), "acme.example").unwrap()
}

fn source() -> JsonlSource {
    JsonlSource::replay(cfg())
}

fn chat_span() -> jsonenc::SpanBuilder {
    jsonenc::SpanBuilder::new("chat gpt-4o-mini")
        .trace_id(TRACE.to_vec())
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("gen_ai.request.model", "gpt-4o-mini")
}

/// A span naming an operation this mapper version does not know.
///
/// Built from scratch rather than from [`chat_span`] with the operation
/// overwritten: two attributes with the same key are legal OTLP and the mapper
/// reads the first, so an "overwritten" operation would still be `chat` and the
/// test would be asserting nothing.
fn unknown_operation_span() -> jsonenc::SpanBuilder {
    jsonenc::SpanBuilder::new("summarise")
        .trace_id(TRACE.to_vec())
        .span_id(vec![0x44; 8])
        .str_attr("gen_ai.operation.name", "summarise_thread")
}

fn line(spans: &[jsonenc::SpanBuilder]) -> Vec<u8> {
    let mut out = jsonenc::request(&jsonenc::service("billing"), "scope", "", spans);
    out.push('\n');
    out.into_bytes()
}

/// An envelope around span objects written by hand.
///
/// A `SpanBuilder` hex-encodes every id, so the fixtures that are wrong on
/// purpose cannot come from one: an id that is *almost* right is exactly the case
/// this transport has and the wire path does not.
fn envelope(spans: &[String]) -> Vec<u8> {
    let resource = jsonenc::object(&[(
        "attributes",
        jsonenc::array(&[jsonenc::kv("service.name", jsonenc::any_string("billing"))]),
    )]);
    let scope_spans = jsonenc::object(&[
        (
            "scope",
            jsonenc::object(&[("name", jsonenc::string("scope"))]),
        ),
        ("spans", jsonenc::array(spans)),
    ]);
    let mut out = jsonenc::object(&[(
        "resourceSpans",
        jsonenc::array(&[jsonenc::object(&[
            ("resource", resource),
            ("scopeSpans", jsonenc::array(&[scope_spans])),
        ])]),
    )]);
    out.push('\n');
    out.into_bytes()
}

/// One span object, with the ids exactly as given rather than as encoded.
fn raw_span(name: &str, span_id: &str, parent: Option<&str>, operation: &str) -> String {
    let mut members = vec![
        ("traceId", jsonenc::string(&jsonenc::hex(&TRACE))),
        ("spanId", jsonenc::string(span_id)),
    ];
    if let Some(parent) = parent {
        members.push(("parentSpanId", jsonenc::string(parent)));
    }
    members.push(("name", jsonenc::string(name)));
    members.push(("kind", "3".to_owned()));
    members.push((
        "startTimeUnixNano",
        jsonenc::uint64(START, IntForm::DecimalString),
    ));
    members.push((
        "attributes",
        jsonenc::array(&[jsonenc::kv(
            "gen_ai.operation.name",
            jsonenc::any_string(operation),
        )]),
    ));
    jsonenc::object(&members)
}

fn diagnostic(ingest: &Ingest) -> String {
    ingest
        .payload
        .iter()
        .filter(|p| p.class == PayloadClass::Diagnostic)
        .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// What a line may not decide
// ---------------------------------------------------------------------------

#[test]
fn a_line_cannot_choose_its_own_tenant() {
    // The one that would matter most: a tenant read from a file is a tenant
    // whoever can write the file can write into. It is configuration, so no
    // attribute reaches it, however the attribute is spelled.
    let span = chat_span()
        .str_attr("tenant", "victim")
        .str_attr("trailryx.tenant", "victim")
        .str_attr("gen_ai.tenant", "victim");

    let mut src = source();
    assert_eq!(src.accept_chunk(&line(&[span]), NOW), 1);
    let items = src.poll(1).unwrap();

    assert_eq!(items[0].meta.tenant.as_str(), "acme");
    // Not obeyed and not hidden: the attempt is written down where any other
    // unrecognised attribute goes, on the encrypted side.
    let text = diagnostic(&items[0]);
    assert_eq!(text.matches("victim").count(), 3, "{text}");
}

#[test]
fn a_line_cannot_forge_a_trust_domain() {
    // An agent name is producer-chosen text pasted into an identifier, which is
    // the classic shape of an injection. The trust domain comes from
    // configuration and is always the prefix, whatever the name tries.
    for name in [
        "../evil.example/agent",
        "evil.example/agent",
        "..",
        "agent://evil.example/x",
    ] {
        let mut src = source();
        assert_eq!(
            src.accept_chunk(
                &line(&[chat_span().str_attr("gen_ai.agent.name", name)]),
                NOW
            ),
            1
        );
        let items = src.poll(1).unwrap();
        // The prefix is the whole guarantee, and it is enough. Two of these
        // spellings do parse as an identifier once our domain is in front of
        // them, and then they are a path *under* our trust domain: an odd agent
        // name, not another estate's agent.
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
    // and a tab is an attempt to write an entry nobody sent. In this transport
    // the newline has to arrive escaped, because a raw one would have ended the
    // line, which is the same defence one layer down.
    let span = jsonenc::SpanBuilder::new("the real name")
        .trace_id(TRACE.to_vec())
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("acme.evil", "harmless\nspan.name\tsomething else entirely");

    let mut src = source();
    assert_eq!(src.accept_chunk(&line(&[span]), NOW), 1);
    let items = src.poll(1).unwrap();
    let text = diagnostic(&items[0]);

    let names: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("span.name\t"))
        .collect();
    assert_eq!(names, vec!["span.name\tthe real name"], "{text}");
    assert_eq!(text.lines().count(), 3, "one line per attribute: {text}");
    for l in text.lines() {
        assert_eq!(
            l.matches('\t').count(),
            1,
            "a value smuggled a separator: {l}"
        );
    }
    assert!(text.contains("harmless"), "{text}");
    assert!(text.contains("something else entirely"), "{text}");
}

#[test]
fn an_all_zero_parent_span_id_is_not_a_parent() {
    // OTLP defines an all-zero span id as invalid, and emitters write the field
    // out as zeros rather than omitting it. Treating those eight bytes as a name
    // manufactured edges: two unrelated roots, each naming the invalid parent,
    // became children of whichever span had claimed the all-zero id, and
    // `event_type` flipped from a request arriving to one agent delegating to
    // another, which is the edge an auditor follows. That is what MAPPER_VERSION
    // 2 was cut for, and it must not come back through a second transport.
    let zeros = jsonenc::hex(&[0u8; 8]);
    let bytes = envelope(&[
        raw_span("zero-named", &zeros, None, "invoke_agent"),
        raw_span(
            "root-a",
            &jsonenc::hex(&[0x55; 8]),
            Some(&zeros),
            "invoke_agent",
        ),
        raw_span(
            "root-b",
            &jsonenc::hex(&[0x66; 8]),
            Some(&zeros),
            "invoke_agent",
        ),
    ]);

    let mut src = source();
    assert_eq!(src.accept_chunk(&bytes, NOW), 3);
    let batch = src.poll(16).unwrap();

    assert!(
        batch[0].correlation.is_none(),
        "an invalid id is not a name"
    );
    for unit in &batch[1..] {
        assert!(
            unit.correlation.is_some_and(|c| c.parent.is_none()),
            "an all-zero parent id became a parent"
        );
        assert_eq!(
            unit.meta.event_type,
            EventType::RequestReceived,
            "an invalid parent id reclassified a root as a delegation"
        );
    }
    // Read, not refused: an id of the right length that happens to be zeros is a
    // real emitter's output and costs nothing.
    assert_eq!(src.shape().bad_ids, 0);
    assert_eq!(src.dropped().spans, 0);
}

#[test]
fn a_misspelled_parent_span_id_drops_the_span_rather_than_making_it_a_root() {
    // The one place this transport refuses rather than defaults, and the reason
    // is that a defaulted parent is a *claim*: `Span::has_parent` would then say
    // the span is a root and the mapper would turn a Delegation into a
    // RequestReceived. `otel-cli server json` writes exactly this, a span id in
    // base64, twelve characters where OTLP fixes sixteen.
    for spelling in [
        "APBnqgupArc=",        // base64, not hex
        "1111111111111111111", // hex, too long
        "111111111111111",     // hex, one short
        "0x1111111111111111",  // prefixed
        "gggggggggggggggg",    // not hex at all
    ] {
        let mut src = source();
        let bytes = envelope(&[
            raw_span(
                "delegate",
                &jsonenc::hex(&[0x22; 8]),
                Some(spelling),
                "invoke_agent",
            ),
            // A sibling in the same line, to show the refusal costs one span and
            // not the batch it arrived in.
            raw_span("root", &jsonenc::hex(&[0x11; 8]), None, "invoke_agent"),
        ]);
        assert_eq!(src.accept_chunk(&bytes, NOW), 1, "{spelling}");

        assert_eq!(src.shape().bad_ids, 1, "{spelling}");
        assert_eq!(src.dropped().spans, 1, "{spelling}");
        let batch = src.poll(16).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(
            batch[0].meta.event_type,
            EventType::RequestReceived,
            "the survivor is the root, and the delegation is gone rather than \
             reclassified: {spelling}"
        );
        assert!(src.has_unreported_anomaly(), "a dropped span is a loss");
    }
}

// ---------------------------------------------------------------------------
// The reporting itself
// ---------------------------------------------------------------------------

/// One counter's name and a way to bump exactly that counter.
type Bump = (&'static str, fn(&mut Counters));

#[test]
fn every_counter_is_either_a_loss_or_declared_not_one() {
    // `OtlpSource::anomaly_total` is a hand-written sum of seven terms and the
    // struct it sums has eight, so a batch whose only fault is invalid UTF-8
    // produces no anomaly record at all. Here the total is a sum over the
    // classified list, and this test is what holds the classification up: every
    // counter is bumped in turn and has to move the total or be declared a
    // diagnostic.
    //
    // The table names the counters independently of the list, so a counter added
    // to any of the four reports fails here until somebody has said which it is.
    let bumps: &[Bump] = &[
        ("mapped", |c| c.mapping.mapped += 1),
        ("not_genai", |c| c.mapping.not_genai += 1),
        ("unknown_operation", |c| c.mapping.unknown_operation += 1),
        ("no_run_id", |c| c.mapping.no_run_id += 1),
        ("no_agent", |c| c.mapping.no_agent += 1),
        ("excessive_clock_skew", |c| c.mapping.excessive_skew += 1),
        ("malformed_lines", |c| c.lines.malformed_lines += 1),
        ("oversize_lines", |c| c.lines.oversize_lines += 1),
        ("too_deep", |c| c.lines.too_deep += 1),
        ("duplicate_members", |c| c.lines.duplicate_members += 1),
        ("lone_surrogates", |c| c.lines.lone_surrogates += 1),
        ("bad_encoding", |c| c.lines.bad_encoding += 1),
        ("concatenated_values", |c| c.lines.concatenated_values += 1),
        ("incomplete_interior_lines", |c| {
            c.lines.incomplete_interior_lines += 1
        }),
        ("unterminated_final_line", |c| {
            c.lines.unterminated_final_line += 1
        }),
        ("blank_lines", |c| c.lines.blank_lines += 1),
        ("leading_bom", |c| c.lines.leading_bom = true),
        ("queue_full_stops", |c| c.lines.queue_full_stops += 1),
        ("skew_not_assessed", |c| c.lines.skew_not_assessed += 1),
        ("dropped_spans", |c| c.dropped.spans += 1),
        ("dropped_attributes", |c| c.dropped.attributes += 1),
        ("dropped_events", |c| c.dropped.events += 1),
        ("oversize_values", |c| c.dropped.oversize_values += 1),
        // Named here even though this transport can never charge it: the reader
        // refuses a bad byte before a decoder sees it. It is the term
        // `OtlpSource` forgot, and a counter nobody can reach today is exactly
        // the counter a later edit reaches.
        ("invalid_utf8", |c| c.dropped.invalid_utf8 += 1),
        ("unknown_members", |c| c.shape.unknown_members += 1),
        ("snake_case_keys", |c| c.shape.snake_case_keys += 1),
        ("not_traces_data", |c| c.shape.not_traces_data += 1),
        ("wrong_signal", |c| c.shape.wrong_signal += 1),
        ("bare_resource_spans", |c| c.shape.bare_resource_spans += 1),
        ("empty_batches", |c| c.shape.empty_batches += 1),
        ("bad_ids", |c| c.shape.bad_ids += 1),
        ("bad_types", |c| c.shape.bad_types += 1),
        ("bad_numbers", |c| c.shape.bad_numbers += 1),
        ("double_overflow", |c| c.shape.double_overflow += 1),
        ("nonfinite_doubles", |c| c.shape.nonfinite_doubles += 1),
        ("bad_base64", |c| c.shape.bad_base64 += 1),
        ("multi_valued_anyvalue", |c| {
            c.shape.multi_valued_anyvalue += 1
        }),
    ];

    let listed: BTreeSet<&str> = Counters::default().list().iter().map(|c| c.name).collect();
    let tabled: BTreeSet<&str> = bumps.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        listed, tabled,
        "the counter list and this table have drifted apart"
    );

    let mut losses = 0usize;
    for (name, bump) in bumps {
        let mut counters = Counters::default();
        bump(&mut counters);
        let entry = counters
            .list()
            .into_iter()
            .find(|c| c.name == *name)
            .expect("the sets are equal");
        assert_eq!(entry.value, 1, "{name} bumped some other counter");
        let total = counters.anomaly_total();
        match entry.class {
            Class::Loss => {
                losses += 1;
                assert_eq!(total, 1, "{name} is a loss and did not reach the total");
            }
            Class::Diagnostic => assert_eq!(
                total, 0,
                "{name} is declared a diagnostic and moved the total anyway"
            ),
        }
    }
    assert!(losses > 7, "the sum {losses} terms wide replaces one of 7");
}

#[test]
fn an_anomaly_never_moves_the_resume_point() {
    // `OtlpSource` mints the anomaly a cursor above every pending record, so
    // acknowledging the anomaly acknowledges records nobody has drained and a
    // resume starts after them. An anomaly is not a position in a file.
    let mut src = source();
    assert_eq!(src.accept_chunk(&line(&[chat_span()]), NOW), 1);
    assert_eq!(src.accept_chunk(&line(&[unknown_operation_span()]), NOW), 0);

    let event = src.anomaly_event(NOW).expect("a span was refused");
    assert_eq!(event.cursor, Cursor(0));

    // And the sequence is untouched: the next record continues from 1, so the
    // anomaly consumed no position either.
    assert_eq!(
        src.accept_chunk(&line(&[chat_span().span_id(vec![0x55; 8])]), NOW),
        1
    );
    let cursors: Vec<Cursor> = src.poll(16).unwrap().iter().map(|i| i.cursor).collect();
    assert_eq!(cursors, vec![Cursor(1), Cursor(2)]);

    // The record the store wrote about itself was written by no mapper, and says
    // so. `MetaDraft::mapper` states that rule and `source.rs` breaks it, which
    // makes every anomaly record in the OTLP path claim a reading of the GenAI
    // conventions was applied to a row of counters.
    assert_eq!(event.meta.mapper, MapperVersion::UNMAPPED);
    // The version the *records* were mapped under is in the breakdown, where it
    // is a fact about them rather than a claim about this one.
    let detail = diagnostic(&event);
    assert!(detail.contains("mapper_version\t2"), "{detail}");
    assert!(detail.contains("mode\treplay"), "{detail}");
    assert!(detail.contains("unknown_operation\t1"), "{detail}");
    assert!(detail.contains("anomalies_since_last\t1"), "{detail}");
    assert_eq!(
        event.meta.agent_id.as_str(),
        "agent://acme.example/trailryx.jsonl",
        "the trust domain comes from configuration and never from a line"
    );
    // Reporting is not repeating: nothing new means no second record.
    assert!(src.anomaly_event(NOW).is_none());
}

#[test]
fn an_anomaly_record_is_not_lost_when_an_identifier_fails() {
    // `OtlpSource` advances the reported watermark and then `?`s on constructing
    // the identifiers, so a construction failure throws the report away *and*
    // marks it reported: the loss is then invisible forever. Here both
    // identifiers are built first.
    //
    // The failure is reachable, which is the point. An agent id is capped at 255
    // bytes, `MapperConfig::new` validates the shorter `/unattributed` path, and
    // the anomaly agent's path is two bytes longer.
    let domain = "a".repeat(233);
    assert!(
        AgentId::parse_strict(format!("agent://{domain}/unattributed")).is_ok(),
        "the configuration itself has to be valid, or this proves nothing"
    );
    assert!(AgentId::parse_strict(format!("agent://{domain}/trailryx.jsonl")).is_err());

    let cfg = MapperConfig::new(TenantId::parse("acme").unwrap(), &domain).unwrap();
    let mut src = JsonlSource::replay(cfg);
    assert_eq!(src.accept_chunk(&line(&[unknown_operation_span()]), NOW), 0);
    assert_eq!(src.report().unknown_operation, 1);

    assert!(src.has_unreported_anomaly());
    assert!(
        src.anomaly_event(NOW).is_none(),
        "the identifier cannot be built, so there is no record to hand over"
    );
    assert!(
        src.has_unreported_anomaly(),
        "the report was discarded and marked reported: the loss is now invisible"
    );
    assert_eq!(src.report().unknown_operation, 1, "and the counters remain");
}

#[test]
fn a_rejected_span_consumes_no_cursor() {
    // A cursor is a position a resume trusts. A refused span that took one leaves
    // a hole, and an acknowledgement of the hole settles a record that never
    // existed while looking like it settled one that did.
    let bytes = envelope(&[
        raw_span("nope", &jsonenc::hex(&[0x11; 8]), None, "summarise_thread"),
        raw_span("chat", &jsonenc::hex(&[0x22; 8]), None, "chat"),
        raw_span(
            "also nope",
            &jsonenc::hex(&[0x33; 8]),
            None,
            "not_an_operation",
        ),
        raw_span("tool", &jsonenc::hex(&[0x44; 8]), None, "execute_tool"),
    ]);
    let mut src = source();
    assert_eq!(src.accept_chunk(&bytes, NOW), 2);
    assert_eq!(src.report().unknown_operation, 2);

    let cursors: Vec<Cursor> = src.poll(16).unwrap().iter().map(|i| i.cursor).collect();
    assert_eq!(cursors, vec![Cursor(1), Cursor(2)]);
}

#[test]
fn a_full_queue_stops_reading_rather_than_growing() {
    // A reader that keeps reading into a queue nobody drains is a slow OOM. The
    // bytes it has not read are still on the disk; the records it has already
    // made are not, so the answer is to stop reading rather than to keep the
    // records.
    let first = line(&[chat_span()]);
    let second = line(&[chat_span().span_id(vec![0x22; 8])]);
    let third = line(&[chat_span().span_id(vec![0x33; 8])]);

    let mut src = JsonlSource::replay(cfg()).with_max_pending(2);
    assert_eq!(src.accept_chunk(&first, NOW), 1);
    assert_eq!(src.accept_chunk(&second, NOW), 1);
    assert_eq!(src.pending(), 2);

    // At the bound: the chunk is not read at all.
    assert_eq!(src.accept_chunk(&third, NOW), 0);
    assert_eq!(src.line_report().queue_full_stops, 1);
    assert_eq!(src.pending(), 2, "the queue did not grow");

    // The counter says how many times the reader STOPPED, not how many calls were
    // refused while it was stopped. Re-feeding is the documented recovery, so a
    // caller doing exactly the right thing five times must not be reported as five
    // stalls: that would make the figure a property of the caller's retry loop
    // rather than of the store, and a caller retrying every millisecond would
    // report a thousand times what one retrying every second reports for identical
    // conditions.
    for _ in 0..5 {
        assert_eq!(src.accept_chunk(&third, NOW), 0);
    }
    assert_eq!(
        src.line_report().queue_full_stops,
        1,
        "one stall is one stall however patiently it is retried"
    );

    // And a stall does not fabricate an anomaly record, because nothing was lost:
    // the bytes were never read, so they are still the caller's. This assertion
    // used to be the opposite, on the argument that a stall an operator cannot see
    // becomes a loss they cannot see either. The argument is sound and the place
    // was wrong. A stall is an operational condition and belongs in the reader's
    // own report, which is what `line_report` is and what the binary prints; the
    // record stream is evidence, and a record announcing a loss that did not happen
    // teaches an operator to distrust the one that did. The HTTP surface already
    // draws the line in the same place: backpressure there is a 503 to the client,
    // not a record in the store.
    assert!(
        !src.has_unreported_anomaly(),
        "a stall is not a loss and must not manufacture a record saying it was"
    );

    // Nothing was lost: the same bytes were never consumed, so handing them over
    // again after a drain produces the record.
    assert_eq!(src.poll(16).unwrap().len(), 2);
    assert_eq!(src.accept_chunk(&third, NOW), 1);
    assert_eq!(src.poll(16).unwrap().len(), 1);
    assert_eq!(
        src.line_report().queue_full_stops,
        1,
        "and the stall is still counted once after the recovery"
    );

    // Visible where it belongs: once an anomaly exists for a real reason, the stall
    // is in its breakdown rather than being the reason.
    let mut with_loss = JsonlSource::replay(cfg()).with_max_pending(1);
    with_loss.accept_chunk(&first, NOW);
    with_loss.accept_chunk(&second, NOW);
    with_loss.accept_chunk(b"{\"resourceSpans\":[}\n", NOW);
    assert_eq!(with_loss.line_report().queue_full_stops, 1);
    let _ = with_loss.poll(16);
    with_loss.accept_chunk(b"{\"resourceSpans\":[}\n", NOW);
    assert!(
        with_loss.has_unreported_anomaly(),
        "a malformed line is a real loss and does produce a record"
    );
    let event = with_loss
        .anomaly_event(NOW)
        .expect("the malformed line earned an anomaly record");
    let detail = String::from_utf8(
        event
            .payload
            .iter()
            .find(|p| p.class == PayloadClass::Diagnostic)
            .expect("the breakdown is a diagnostic part")
            .bytes
            .clone(),
    )
    .expect("text");
    assert!(
        detail.contains("queue_full_stops\t1"),
        "the stall belongs in the breakdown: {detail}"
    );
}

#[test]
fn an_ack_never_rewinds() {
    let mut src = source();
    assert_eq!(src.accept_chunk(&line(&[chat_span()]), NOW), 1);
    src.ack(Cursor(5)).unwrap();
    src.ack(Cursor(2)).unwrap();
    src.ack(Cursor(5)).unwrap();
    // Idempotent and monotonic, as the contract requires: an older cursor is a
    // repeat of something already settled, never an instruction to reopen it.
    // Acknowledging an anomaly's Cursor(0) is the same no-op for the same reason.
    src.ack(Cursor(0)).unwrap();
}

#[test]
fn a_line_of_another_encoding_is_named_rather_than_half_read() {
    // A UTF-16 file half-read as ASCII looks like a truncated ASCII document
    // rather than the wrong encoding, so it is named and refused. A stream-level
    // refusal produced no records, so it reaches the total as well as its own
    // counter, or a file that produced nothing would report nothing wrong.
    let mut src = source();
    assert_eq!(src.accept_chunk(b"\xFF\xFE{\x00", NOW), 0);
    assert_eq!(src.line_report().bad_encoding, 1);
    assert_eq!(src.line_report().malformed_lines, 1);
    assert!(src.has_unreported_anomaly());

    // And a line whose bytes are not UTF-8 at all is one line, not the file.
    let mut src = source();
    let mut bytes = line(&[chat_span()]);
    bytes.extend_from_slice(b"{\"resourceSpans\":[\"\xC3\x28\"]}\n");
    assert_eq!(src.accept_chunk(&bytes, NOW), 1);
    assert_eq!(src.line_report().bad_encoding, 1);
    assert_eq!(src.line_report().malformed_lines, 1);
}

#[test]
fn two_values_on_one_line_are_the_producer_they_identify() {
    // otel-java's `OtlpStdout*` exporters wrote two JSON values on a line before
    // roughly 1.44. Random corruption and a known exporter bug want different
    // answers from an operator, so they get different counters.
    let mut doubled = jsonenc::request(&jsonenc::service("billing"), "scope", "", &[chat_span()]);
    doubled.push_str(&jsonenc::request(
        &jsonenc::service("billing"),
        "scope",
        "",
        &[chat_span()],
    ));
    doubled.push('\n');

    let mut src = source();
    assert_eq!(src.accept_chunk(doubled.as_bytes(), NOW), 0);
    assert_eq!(src.line_report().concatenated_values, 1);
    assert_eq!(src.line_report().malformed_lines, 1);
    // The rest of the file still reads: one producer's bug is not an outage.
    assert_eq!(src.accept_chunk(&line(&[chat_span()]), NOW), 1);
}

#[test]
fn a_line_past_the_length_bound_is_refused_and_the_next_one_is_read() {
    // The bound is on bytes read rather than on the assembled line, because the
    // alternative is a multi-gigabyte file with no newline in it and a reader
    // that assembles first has already lost.
    const CAP: usize = 512;
    let json = trailryx_json::Limits {
        max_line_bytes: CAP,
        ..trailryx_json::Limits::default()
    };
    let mut src = JsonlSource::with_limits(
        cfg(),
        trailryx_otlp::Limits::default(),
        json,
        trailryx_otlp::Mode::Replay,
    );
    let long = line(&[chat_span().str_attr("acme.blob", &"x".repeat(4096))]);
    assert!(long.len() > CAP);
    assert_eq!(src.accept_chunk(&long, NOW), 0);
    assert_eq!(src.line_report().oversize_lines, 1);
    assert_eq!(src.line_report().malformed_lines, 1);

    let short = envelope(&[raw_span("chat", &jsonenc::hex(&[0x22; 8]), None, "chat")]);
    assert!(short.len() <= CAP, "{} bytes", short.len());
    assert_eq!(src.accept_chunk(&short, NOW), 1);
    assert_eq!(
        src.line_report().oversize_lines,
        1,
        "one refusal, not one per line after it"
    );
}
