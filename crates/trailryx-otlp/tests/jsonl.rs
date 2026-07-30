//! A file of OTLP/JSON lines, read the way a collector writes one.
//!
//! The decoder has its own tests next door in `shapes.rs` and the mapper has
//! `mapping.rs` and `planes.rs`. What is left for this file is everything that
//! only exists because the transport is a file: a last line the producer has not
//! finished writing, a batch whose children were exported before their parents,
//! and the requirement that the same bytes produce the same records twice.

mod common;

use common::jsonenc;
use std::collections::BTreeSet;
use trailryx_assemble::Assembler;
use trailryx_contracts::contracts::{Delivery, Ordering, Source, Trust};
use trailryx_contracts::ingest::{Cursor, Ingest};
use trailryx_otlp::MapperConfig;
use trailryx_otlp::jsonl::{JsonlSource, Mode};
use trailryx_record::{PayloadClass, ShardIx, TenantId, Timestamp};
use trailryx_sim::rng::SimRng;

/// Four hundred milliseconds after the fixture spans start, so a `tail` reader
/// finds no skew and the tests that are not about skew are not about skew.
const NOW: Timestamp = Timestamp(1_700_000_000_400_000_000);
const SCOPE: &str = "opentelemetry.instrumentation.openai";
const TRACE: [u8; 16] = [0xab; 16];

fn cfg() -> MapperConfig {
    MapperConfig::new(TenantId::parse("acme").unwrap(), "acme.example").unwrap()
}

/// The span an instrumented chat call actually emits, in OTLP/JSON.
fn chat_span() -> jsonenc::SpanBuilder {
    jsonenc::SpanBuilder::new("chat gpt-4o-mini")
        .trace_id(TRACE.to_vec())
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("gen_ai.request.model", "gpt-4o-mini")
        .int_attr("gen_ai.usage.input_tokens", 1_204)
        .int_attr("gen_ai.usage.output_tokens", 87)
}

fn line(spans: &[jsonenc::SpanBuilder]) -> String {
    jsonenc::request(
        &jsonenc::service("billing-assistant"),
        SCOPE,
        "0.42.1",
        spans,
    )
}

/// One line and its terminator, which is what a file holds.
fn file(lines: &[String]) -> Vec<u8> {
    let mut out = String::new();
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out.into_bytes()
}

#[test]
fn the_jsonl_source_conforms() {
    // Freshly constructed, with nothing pending, and that is not incidental: the
    // suite is side-effecting. It polls 3, then acknowledges Cursor(10) twice and
    // Cursor(1). Our cursors are a dense sequence from 1, so acknowledging 10
    // against a source that had been fed would settle ten real records that
    // nobody had drained, and the test would be quietly asserting that a resume
    // may skip them.
    //
    // This is the first adapter in the tree that is not a fake to be run against
    // the suite at all. What it checks is the descriptor and the acknowledgement
    // discipline, and neither needs a record to exist.
    for mode in [Mode::Replay, Mode::Tail] {
        let mut src = match mode {
            Mode::Replay => JsonlSource::replay(cfg()),
            Mode::Tail => JsonlSource::tail(cfg()),
        };
        assert_eq!(src.pending(), 0);
        let report = trailryx_contracts::conformance::source(&mut src);
        assert!(!report.checks.is_empty(), "a suite with no checks passes");
        for check in &report.checks {
            assert!(check.passed, "{mode}: {}: {}", check.name, check.detail);
        }
        assert!(report.passed(), "{}", report.summary());
    }

    let d = JsonlSource::replay(cfg()).descriptor();
    assert_eq!(d.name, "otlp/traces+jsonl");
    // The times are the producer's and the identity comes from `service.name`,
    // an attribute the producer chose. Neither is a formality.
    assert_eq!(d.clock_trust, Trust::Untrusted);
    assert_eq!(d.identity_trust, Trust::Untrusted);
    assert_eq!(d.delivery, Delivery::AtLeastOnce);
    assert_eq!(d.ordering, Ordering::Unordered);
}

#[test]
fn a_line_a_collector_wrote_becomes_a_record() {
    let mut src = JsonlSource::replay(cfg());
    assert_eq!(src.accept_chunk(&file(&[line(&[chat_span()])]), NOW), 1);
    assert_eq!(src.finish(NOW), 0);

    let items = src.poll(10).unwrap();
    assert_eq!(items.len(), 1);
    let meta = &items[0].meta;
    assert_eq!(meta.tenant.as_str(), "acme");
    assert_eq!(
        meta.agent_id.as_str(),
        "agent://acme.example/billing-assistant"
    );
    assert_eq!(meta.tokens_in, Some(1_204));
    assert_eq!(items[0].cursor, Cursor(1), "dense from 1");

    // Nothing went wrong, so there is nothing to write down. The skew that was
    // not assessed is not a fault: an archive's clock is not supposed to agree
    // with ours, and the counter says the comparison was skipped.
    assert!(!src.has_unreported_anomaly());
    assert_eq!(src.line_report().skew_not_assessed, 1);
    assert_eq!(src.line_report().malformed_lines, 0);
    assert_eq!(src.report().excessive_skew, 0);
}

#[test]
fn a_live_file_is_assessed_against_our_clock_and_an_archive_is_not() {
    // The whole reason the two constructors exist. Last week's archive replayed
    // today would otherwise mark every record excessively skewed and then write
    // an anomaly record saying the fleet's clocks have drifted, which is true of
    // the reader and false of the fleet.
    let bytes = file(&[line(&[chat_span()])]);
    let an_hour_later = Timestamp(1_700_000_000_000_000_000 + 3_600_000_000_000);

    let mut tail = JsonlSource::tail(cfg());
    assert_eq!(tail.accept_chunk(&bytes, an_hour_later), 1);
    assert_eq!(tail.report().excessive_skew, 1);
    assert_eq!(tail.line_report().skew_not_assessed, 0);
    assert!(tail.has_unreported_anomaly());

    let mut replay = JsonlSource::replay(cfg());
    assert_eq!(replay.accept_chunk(&bytes, an_hour_later), 1);
    assert_eq!(replay.report().excessive_skew, 0);
    assert_eq!(replay.line_report().skew_not_assessed, 1);
    assert!(
        !replay.has_unreported_anomaly(),
        "an archive's age is not an incident"
    );
}

#[test]
fn a_partial_tail_is_not_corruption() {
    // A collector that flushes on a timer leaves a partial line most of the time.
    // Counting that as malformed would make every tail read look like an
    // incident, and an operator who has learned to ignore the counter is an
    // operator who will ignore it when a producer really is broken.
    let whole = file(&[line(&[chat_span()])]);
    let cut = whole.len() / 2;

    let mut src = JsonlSource::tail(cfg());
    assert_eq!(src.accept_chunk(&whole[..cut], NOW), 0);
    assert_eq!(src.line_report().unterminated_final_line, 1);
    assert_eq!(src.line_report().malformed_lines, 0);
    assert_eq!(src.line_report().incomplete_interior_lines, 0);
    assert!(!src.has_unreported_anomaly(), "nothing has been lost yet");

    // The producer finishes the line. The record arrives, once.
    assert_eq!(src.accept_chunk(&whole[cut..], NOW), 1);
    assert_eq!(src.finish(NOW), 0);
    assert_eq!(src.poll(10).unwrap().len(), 1);
    assert_eq!(src.line_report().malformed_lines, 0);
    assert_eq!(
        src.line_report().unterminated_final_line,
        1,
        "one partial line, counted once however many reads saw it"
    );
}

#[test]
fn a_pretty_printed_file_is_named_rather_than_read() {
    // The other half of the previous test, and the reason the two counters are
    // separate. Somebody ran a formatter over a JSON Lines file, so one record is
    // now four lines and not one of them is a record. An interior line that ends
    // mid-value is a real fault with a producer to fix; the same shape on the last
    // line is a collector mid-flush, and the two must not share a counter.
    let pretty = b"{\n  \"resourceSpans\": []\n}\n{}\n";
    let mut src = JsonlSource::replay(cfg());
    assert_eq!(src.accept_chunk(pretty, NOW), 0);
    assert_eq!(src.finish(NOW), 0);

    let lines = src.line_report();
    assert_eq!(lines.incomplete_interior_lines, 1, "the bare `{{`");
    assert_eq!(
        lines.concatenated_values, 1,
        "`  \"resourceSpans\": []` is a string with a value after it"
    );
    assert_eq!(
        lines.malformed_lines, 3,
        "those two and the `}}` that closes nothing"
    );
    assert_eq!(lines.unterminated_final_line, 0, "the file ends on an LF");
    // The `{}` is not one of them: a collector with an empty queue sends exactly
    // that, and it is a traces batch with nothing in it rather than a fault.
    assert_eq!(src.shape().empty_batches, 1);
    assert!(src.has_unreported_anomaly());
}

#[test]
fn a_file_exported_children_first_still_produces_the_causal_edges() {
    // The same defect the wire path has a test for, over the file path. A span is
    // exported when it *ends*, and a child ends inside the parent that contains
    // it, so a `BatchSpanProcessor` writes the child's line first. Resolution in
    // arrival order therefore found no parents at all, and the causal graph, which
    // the contracts crate calls half of what the store is for, was empty for
    // every trace read from a file.
    let child = jsonenc::SpanBuilder::new("delegate")
        .trace_id(TRACE.to_vec())
        .span_id(vec![0x22; 8])
        .parent(vec![0x11; 8])
        .str_attr("gen_ai.operation.name", "invoke_agent");
    let parent = jsonenc::SpanBuilder::new("root")
        .trace_id(TRACE.to_vec())
        .span_id(vec![0x11; 8])
        .str_attr("gen_ai.operation.name", "invoke_agent");

    let mut src = JsonlSource::replay(cfg());
    assert_eq!(src.accept_chunk(&file(&[line(&[child, parent])]), NOW), 2);
    let batch = src.poll(16).unwrap();
    assert_eq!(batch.len(), 2);

    let mut assembler = Assembler::new(ShardIx(0), SimRng::new(1));
    let records = assembler.adopt_batch(batch, NOW);
    let kid = &records[0].record;
    let root = &records[1].record;
    assert_eq!(
        kid.caused_by,
        vec![root.id],
        "the child was written first and lost its edge"
    );
    assert!(root.caused_by.is_empty());
    assert_eq!(assembler.unresolved_parents(), 0);
}

#[test]
fn the_same_file_produces_the_same_bytes_twice() {
    // The payload is hashed and the hash reaches a Merkle root, so a rendering
    // that depended on map iteration order would make two reads of one file into
    // two different stores. Compared as whole `Ingest` values, byte for byte,
    // rather than field by field, because the field somebody forgets to compare
    // is the field that drifts.
    let bytes = file(&[
        line(&[chat_span()]),
        line(&[chat_span()
            .span_id(vec![0x33; 8])
            .attr(
                "gen_ai.input.messages",
                jsonenc::any_map(&[
                    ("role", jsonenc::any_string("user")),
                    (
                        "content",
                        jsonenc::any_string("what is the balance for Ivan Petrenko"),
                    ),
                ]),
            )
            .str_attr("acme.internal.note", "asked twice")]),
    ]);

    let first = drain(&bytes, &[bytes.len()]);
    let second = drain(&bytes, &[bytes.len()]);
    assert_eq!(first, second);

    // And the same again at a chunk size that lands inside every token, because
    // a reader that reassembled a line differently would produce different bytes
    // from the same file.
    for size in [1usize, 7, 64] {
        assert_eq!(drain(&bytes, &[size]), first, "chunk size {size}");
    }
}

/// Read `bytes` in pieces of the given sizes and hand back every record.
fn drain(bytes: &[u8], sizes: &[usize]) -> Vec<Ingest> {
    let mut src = JsonlSource::replay(cfg());
    for size in sizes {
        for chunk in bytes.chunks((*size).max(1)) {
            src.accept_chunk(chunk, NOW);
        }
    }
    src.finish(NOW);
    src.poll(usize::MAX).unwrap()
}

/// Where an attribute is expected to end up. The same three planes the wire
/// path's `planes.rs` asserts over, restated here so the JSON path cannot drift
/// away from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plane {
    Metadata,
    Content,
    Diagnostic,
}

#[test]
fn every_attribute_lands_in_exactly_one_plane() {
    // Never both, which would leave a copy of content in metadata that erasure
    // cannot reach. Never neither, which would be a silent loss. The table is
    // the mapping restated independently of the code, so a change on one side
    // alone fails here.
    let expected = [
        ("gen_ai.operation.name", Plane::Metadata),
        ("gen_ai.request.model", Plane::Metadata),
        ("gen_ai.request.max_tokens", Plane::Metadata),
        ("gen_ai.usage.input_tokens", Plane::Metadata),
        ("gen_ai.usage.output_tokens", Plane::Metadata),
        ("gen_ai.input.messages", Plane::Content),
        ("gen_ai.output.messages", Plane::Content),
        ("gen_ai.provider.name", Plane::Diagnostic),
        ("gen_ai.response.id", Plane::Diagnostic),
        ("acme.internal.customer_note", Plane::Diagnostic),
        ("gen_ai.something.invented.in.2027", Plane::Diagnostic),
    ];

    let span = jsonenc::SpanBuilder::new("chat gpt-4o-mini")
        .trace_id(TRACE.to_vec())
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("gen_ai.request.model", "gpt-4o-mini")
        .int_attr("gen_ai.request.max_tokens", 512)
        .int_attr("gen_ai.usage.input_tokens", 100)
        .int_attr("gen_ai.usage.output_tokens", 20)
        .str_attr("gen_ai.provider.name", "openai")
        .str_attr("gen_ai.response.id", "chatcmpl-1")
        .str_attr("acme.internal.customer_note", "Ivan asked twice")
        .str_attr("gen_ai.something.invented.in.2027", "who knows")
        .attr(
            "gen_ai.input.messages",
            jsonenc::any_string("what is my balance"),
        )
        .attr(
            "gen_ai.output.messages",
            jsonenc::any_string("it is 12 UAH"),
        );

    let mut src = JsonlSource::replay(cfg());
    assert_eq!(src.accept_chunk(&file(&[line(&[span])]), NOW), 1);
    let items = src.poll(1).unwrap();
    let ingest = &items[0];

    let diagnostic = String::from_utf8(
        ingest
            .payload
            .iter()
            .find(|p| p.class == PayloadClass::Diagnostic)
            .expect("there is always a diagnostic part")
            .bytes
            .clone(),
    )
    .unwrap();

    let mut seen = BTreeSet::new();
    for (key, plane) in expected {
        seen.insert(key);
        let in_diagnostic = diagnostic
            .lines()
            .any(|l| l.starts_with(&format!("{key}\t")));
        let has_own_part = ingest.payload.iter().any(|p| {
            p.class != PayloadClass::Diagnostic
                && String::from_utf8_lossy(&p.bytes).starts_with(&format!("{key}\n"))
        });
        match plane {
            Plane::Metadata => {
                assert!(
                    !in_diagnostic,
                    "{key} is in a typed field and in the payload"
                );
                assert!(!has_own_part, "{key} is in a typed field and classified");
            }
            Plane::Content => {
                assert!(has_own_part, "{key} is content and has no payload part");
                assert!(!in_diagnostic, "{key} is classified and also unclassified");
            }
            Plane::Diagnostic => {
                assert!(in_diagnostic, "{key} was understood by nobody and vanished");
                assert!(!has_own_part, "{key} has a part it should not have");
            }
        }
    }

    // No prompt text in the metadata plane, checked against its debug rendering
    // rather than field by field, so a future field that quietly carries text
    // fails here too.
    let rendered = format!("{:?}", ingest.meta);
    assert!(!rendered.contains("Ivan"), "{rendered}");
    assert_eq!(seen.len(), expected.len(), "the table lists a key twice");
}

#[test]
fn a_utf16_mark_refuses_the_stream_the_same_way_at_every_read_size() {
    // The worst defect the adversarial review found in this transport. The
    // framer refused a byte-order mark from inside its opening path, before the
    // chunk had been framed or its bytes accounted for, so `push` dropped that
    // whole chunk and the caller carried on with the next one. Measured: the same
    // forty-kilobyte file behind a UTF-16 mark admitted 0 records at a 64 KiB
    // read, 118 at 16 KiB, 179 at 4 KiB and 199 at a two-byte read, and every one
    // of those runs reported one or two lost lines. How much of a file reaches an
    // audit store must not be a function of the read size.
    let lines: Vec<String> = (1..=40u32)
        .map(|n| line(&[chat_span().span_id(vec![n as u8; 8])]))
        .collect();
    let mut marked = vec![0xFF, 0xFE];
    marked.extend_from_slice(&file(&lines));

    for chunk in [marked.len(), 65536, 8192, 1024, 64, 2] {
        let mut src = JsonlSource::replay(cfg());
        for part in marked.chunks(chunk) {
            src.accept_chunk(part, NOW);
        }
        src.finish(NOW);
        assert_eq!(
            src.poll(usize::MAX).unwrap().len(),
            0,
            "chunk {chunk}: a stream that is UTF-16 is not a stream with a bad first line"
        );
        let report = src.line_report();
        assert_eq!(report.bad_encoding, 1, "chunk {chunk}: charged once");
        assert_eq!(report.malformed_lines, 1, "chunk {chunk}");
    }

    // The control: the same lines without the mark all arrive, at the read size a
    // caller actually uses.
    let clean = file(&lines);
    let mut src = JsonlSource::replay(cfg());
    for part in clean.chunks(65536) {
        src.accept_chunk(part, NOW);
    }
    src.finish(NOW);
    assert_eq!(src.poll(usize::MAX).unwrap().len(), 40);
    assert_eq!(src.line_report().bad_encoding, 0);
}

#[test]
fn a_flush_inside_a_multibyte_character_is_not_corruption() {
    // A collector flushes on a timer and stops wherever it stops, which is as
    // likely to be inside a character as between two members. Both were reported
    // as a malformed line, so a tail read produced a `Verdict::Failed` warning
    // record claiming loss where nothing had been lost. Measured over every
    // truncation point of one Ukrainian-language line: 19 of 299 were charged, and
    // every one of the 19 ended on the lead byte of a two-byte character.
    let one = line(&[chat_span().str_attr("gen_ai.input.messages", "який баланс на рахунку")]);
    let bytes = one.as_bytes();
    for cut in 1..bytes.len() {
        let mut src = JsonlSource::tail(cfg());
        src.accept_chunk(&bytes[..cut], NOW);
        src.finish(NOW);
        let report = src.line_report();
        assert_eq!(
            report.malformed_lines,
            0,
            "a flush at byte {cut} of {} was charged as corruption",
            bytes.len()
        );
        assert_eq!(report.bad_encoding, 0, "at byte {cut}");
        let _ = src.poll(usize::MAX);
    }

    // And genuinely invalid UTF-8 is still corruption, on the last line as much as
    // anywhere: the exemption is for bytes that have not arrived, not for bytes
    // that cannot be right.
    let mut broken = bytes[..bytes.len() - 1].to_vec();
    broken.extend_from_slice(&[0xC0, 0xAF]);
    let mut src = JsonlSource::tail(cfg());
    src.accept_chunk(&broken, NOW);
    src.finish(NOW);
    assert_eq!(src.line_report().malformed_lines, 1);
    assert_eq!(src.line_report().bad_encoding, 1);
}
