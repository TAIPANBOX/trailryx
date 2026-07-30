//! The plane boundary, checked attribute by attribute.
//!
//! The rule the mapper is built on: every attribute lands in **exactly one**
//! plane. Both would leave a copy of content in metadata that erasure cannot
//! reach. Neither would be a silent loss. So the tests here are not about
//! individual fields, they are about the accounting.

mod common;

use common::*;
use trailryx_contracts::contracts::Source;
use trailryx_otlp::{Limits, MapperConfig, OtlpSource};
use trailryx_record::{PayloadClass, TenantId, Timestamp};

const NOW: Timestamp = Timestamp(1_700_000_000_400_000_000);

fn source() -> OtlpSource {
    OtlpSource::new(MapperConfig::new(TenantId::parse("acme").unwrap(), "acme.example").unwrap())
}

/// Where an attribute is expected to end up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plane {
    /// Parsed into a typed field. Its key must not appear in the diagnostic
    /// payload, or there would be two copies.
    Metadata,
    /// Content, classified. Its key names a payload part of its own.
    Content,
    /// Not understood by this version, written down verbatim on the encrypted
    /// side.
    Diagnostic,
}

/// One mapped ingest from one span, at the default limits.
fn mapped(spans: &[SpanBuilder]) -> trailryx_contracts::ingest::Ingest {
    mapped_with(spans, trailryx_otlp::Limits::default())
}

/// The same, at chosen limits, so a test can make a value oversize.
fn mapped_with(
    spans: &[SpanBuilder],
    limits: trailryx_otlp::Limits,
) -> trailryx_contracts::ingest::Ingest {
    let mut src = OtlpSource::with_limits(
        MapperConfig::new(TenantId::parse("acme").unwrap(), "acme.example").unwrap(),
        limits,
    );
    src.accept(&request(&service("billing"), "scope", spans), NOW);
    src.poll(1).unwrap().remove(0)
}

/// The diagnostic part: every attribute this version did not understand.
fn unmapped(ingest: &trailryx_contracts::ingest::Ingest) -> String {
    String::from_utf8(
        ingest
            .payload
            .iter()
            .find(|p| p.class == PayloadClass::Diagnostic)
            .expect("there is always a diagnostic part")
            .bytes
            .clone(),
    )
    .expect("the diagnostic part is text")
}

#[test]
fn every_attribute_lands_in_exactly_one_plane() {
    // A span mixing all three categories, including two attributes no version
    // of this mapper has ever seen. The table below is the mapping restated
    // independently of the code, so a change on one side alone fails here.
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

    let mut span = SpanBuilder::new("chat gpt-4o-mini")
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("gen_ai.request.model", "gpt-4o-mini")
        .int_attr("gen_ai.request.max_tokens", 512)
        .int_attr("gen_ai.usage.input_tokens", 100)
        .int_attr("gen_ai.usage.output_tokens", 20)
        .str_attr("gen_ai.provider.name", "openai")
        .str_attr("gen_ai.response.id", "chatcmpl-1")
        .str_attr("acme.internal.customer_note", "Ivan asked twice")
        .str_attr("gen_ai.something.invented.in.2027", "who knows");
    span = span
        .attr("gen_ai.input.messages", any_string("what is my balance"))
        .attr("gen_ai.output.messages", any_string("it is 12 UAH"));

    let mut src = source();
    src.accept(&request(&service("billing"), "scope", &[span]), NOW);
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

    for (key, plane) in expected {
        let in_diagnostic = diagnostic
            .lines()
            .any(|line| line.starts_with(&format!("{key}\t")));
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
}

#[test]
fn no_prompt_text_reaches_the_metadata_plane() {
    // The one failure this whole design exists to prevent. Checked against the
    // debug rendering of the metadata rather than field by field, so a future
    // field that quietly carries text fails here too.
    let secret = "Ivan Petrenko, born 1979, account UA123456";
    let span = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("gen_ai.input.messages", secret)
        .str_attr("acme.unknown.field", secret);

    let mut src = source();
    src.accept(&request(&service("billing"), "scope", &[span]), NOW);
    let items = src.poll(1).unwrap();

    let rendered = format!("{:?}", items[0].meta);
    assert!(
        !rendered.contains("Petrenko"),
        "content reached the metadata plane: {rendered}"
    );
    // And it is not lost either: it is on the encrypted side, twice, because
    // it was sent twice.
    let payload = items[0]
        .payload
        .iter()
        .map(|p| String::from_utf8_lossy(&p.bytes).into_owned())
        .collect::<String>();
    assert_eq!(payload.matches("Petrenko").count(), 2);
}

#[test]
fn a_value_that_does_not_fit_its_field_is_not_repaired() {
    // A model name with capitals cannot be a `ModelId`. Lowercasing it would
    // merge two models that a provider distinguishes; dropping it would lose
    // what was said. So the typed field stays empty and the value goes to the
    // payload like anything else this mapper could not place.
    let span = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("gen_ai.request.model", "Claude-Opus-5");

    let mut src = source();
    src.accept(&request(&service("billing"), "scope", &[span]), NOW);
    let items = src.poll(1).unwrap();

    assert_eq!(items[0].meta.basis.model, None, "not repaired into a fit");
    let diagnostic = String::from_utf8_lossy(&items[0].payload.last().unwrap().bytes).into_owned();
    assert!(
        diagnostic.contains("Claude-Opus-5"),
        "and not lost either: {diagnostic}"
    );
}

#[test]
fn a_temperature_outside_the_field_is_left_empty_rather_than_clamped() {
    let span = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .attr("gen_ai.request.temperature", any_double(-1.0));

    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[span]), NOW);
    let items = src.poll(1).unwrap();
    assert_eq!(
        items[0].meta.basis.temperature_milli, None,
        "a clamped temperature would read as a fact about the call"
    );
}

#[test]
fn the_prompt_hash_outlives_the_prompt() {
    // Erasure destroys the payload. The hash stays in the record, so two
    // records can still be shown to be about the same prompt afterwards, and
    // that is the whole reason the field exists.
    let span = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("gen_ai.input.messages", "what is my balance");
    let other = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .span_id(vec![0x99; 8])
        .str_attr("gen_ai.input.messages", "what is my balance");
    let different = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .span_id(vec![0x98; 8])
        .str_attr("gen_ai.input.messages", "what is my balance?");

    let mut src = source();
    src.accept(
        &request(&service("a"), "scope", &[span, other, different]),
        NOW,
    );
    let items = src.poll(3).unwrap();

    assert_eq!(
        items[0].meta.basis.prompt_hash,
        items[1].meta.basis.prompt_hash
    );
    assert_ne!(
        items[0].meta.basis.prompt_hash,
        items[2].meta.basis.prompt_hash
    );
}

#[test]
fn a_map_hashes_the_same_whatever_order_its_keys_arrive_in() {
    // Attributes are unordered on the wire. If the rendering followed arrival
    // order, the same prompt sent twice would hash to two different values and
    // `prompt_hash` would mean nothing.
    let one = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .attr(
            "gen_ai.input.messages",
            any_map(&[
                ("role", any_string("user")),
                ("content", any_string("hello")),
            ]),
        );
    let other = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .span_id(vec![0x77; 8])
        .attr(
            "gen_ai.input.messages",
            any_map(&[
                ("content", any_string("hello")),
                ("role", any_string("user")),
            ]),
        );

    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[one, other]), NOW);
    let items = src.poll(2).unwrap();
    assert_eq!(
        items[0].meta.basis.prompt_hash,
        items[1].meta.basis.prompt_hash
    );
}

#[test]
fn a_tool_manifest_keeps_names_and_nothing_else() {
    // Tool definitions carry descriptions and JSON schemas, which are content.
    // Only the names are indexable, and only the names are kept in metadata.
    let span = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .attr(
            "gen_ai.tool.definitions",
            any_array(&[
                any_map(&[
                    ("name", any_string("lookup_balance")),
                    (
                        "description",
                        any_string("looks up the balance for a customer"),
                    ),
                ]),
                any_map(&[("name", any_string("send_email"))]),
            ]),
        );

    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[span]), NOW);
    let items = src.poll(1).unwrap();

    let names: Vec<&str> = items[0]
        .meta
        .basis
        .tool_manifest
        .iter()
        .map(|t| t.as_str())
        .collect();
    assert_eq!(names, vec!["lookup_balance", "send_email"]);

    let rendered = format!("{:?}", items[0].meta);
    assert!(!rendered.contains("looks up the balance"), "{rendered}");
}

#[test]
fn a_derived_code_is_not_a_second_copy_of_the_content() {
    // This looks like an exception to the one-plane rule and is not. The
    // metadata gets a closed-vocabulary *code*; the payload keeps the string it
    // was derived from. Nothing about the person survives in metadata, which is
    // the same trade `prompt_hash` makes.
    let span = SpanBuilder::new("chat")
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr(
            "error.type",
            "RateLimitError: user ivan@example.com over quota",
        )
        .status(2, "");

    let mut src = source();
    src.accept(&request(&service("a"), "scope", &[span]), NOW);
    let items = src.poll(1).unwrap();

    assert_eq!(
        items[0].meta.error,
        Some(trailryx_record::ErrorCode::RateLimited)
    );
    let rendered = format!("{:?}", items[0].meta);
    assert!(!rendered.contains("ivan@example.com"), "{rendered}");
    assert!(
        String::from_utf8_lossy(&items[0].payload.last().unwrap().bytes)
            .contains("ivan@example.com")
    );
}

#[test]
fn an_attribute_key_cannot_forge_a_line_in_the_payload() {
    // `push_line` escaped the value and wrote the key raw, so a key holding a
    // newline wrote an extra field into the leftover payload. An attribute key is
    // the emitter's free text exactly as much as its value is, and these bytes are
    // hashed with the record committing to the hash, so a forged line is a forged
    // payload. The comment above `push_line` claimed to prevent this and prevented
    // half of it.
    let hostile = "forged\ngen_ai.request.model\tclaude-opus-5";
    let span = SpanBuilder::new("chat")
        .trace_id(vec![0xab; 16])
        .span_id(vec![0x11; 8])
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr(hostile, "x");
    let ingest = mapped(&[span]);
    let leftover = unmapped(&ingest);

    // One line per attribute the mapper did not recognise, and the hostile key is
    // one attribute however many newlines it contains.
    let forged: Vec<&str> = leftover
        .lines()
        .filter(|l| l.starts_with("gen_ai.request.model\t"))
        .collect();
    assert!(forged.is_empty(), "a key forged a field: {leftover:?}");
    assert!(
        leftover.contains("forged\\ngen_ai.request.model\\tclaude-opus-5\t"),
        "the key must arrive escaped and whole: {leftover:?}"
    );
}

#[test]
fn a_prompt_nobody_saw_gets_no_hash_rather_than_the_hash_of_nothing() {
    // `prompt_hash` is metadata, so it survives erasure and is committed into a
    // published root, and its whole purpose is that two records carrying the same
    // hash were about the same prompt. An `AnyValue` that arrived empty, whether
    // because the emitter wrote `{}` or because the decoder dropped it for size,
    // rendered as `null` and hashed to one value shared by every such record.
    // Measured before the fix: two unrelated oversize prompts and an empty value
    // all gave the same sixteen leading hex digits.
    let tight = Limits {
        max_value_bytes: 32,
        ..Limits::default()
    };
    let oversize = |text: &str| {
        let span = SpanBuilder::new("chat")
            .trace_id(vec![0xab; 16])
            .span_id(vec![0x11; 8])
            .str_attr("gen_ai.operation.name", "chat")
            .str_attr("gen_ai.input.messages", text);
        mapped_with(&[span], tight).meta.basis.prompt_hash
    };
    assert_eq!(oversize(&"secret alpha ".repeat(20)), None);
    assert_eq!(oversize(&"different beta ".repeat(20)), None);

    // A prompt we did see is still hashed, and an empty string is a thing the
    // emitter said rather than a thing we failed to read, so it is hashed too and
    // differs from a real one.
    let seen = |text: &str| {
        let span = SpanBuilder::new("chat")
            .trace_id(vec![0xab; 16])
            .span_id(vec![0x11; 8])
            .str_attr("gen_ai.operation.name", "chat")
            .str_attr("gen_ai.input.messages", text);
        mapped(&[span]).meta.basis.prompt_hash
    };
    let real = seen("who am i").expect("a prompt we read is hashed");
    let empty_string = seen("").expect("an empty string is what the emitter said");
    assert_ne!(real, empty_string);
}

#[test]
fn a_repeated_attribute_key_keeps_every_value_it_sent() {
    // OTLP does not forbid a repeated key and emitters produce them. The mapper
    // filtered the KEY rather than the occurrence, so `Span::attr` read the first
    // value into metadata and the payload skipped all of them: every later value
    // went to neither plane, with nothing counting it. Measured on a span carrying
    // `gen_ai.request.model` twice, the second model name appeared nowhere at all.
    let span = SpanBuilder::new("chat")
        .trace_id(vec![0xab; 16])
        .span_id(vec![0x11; 8])
        .str_attr("gen_ai.operation.name", "chat")
        .str_attr("gen_ai.request.model", "gpt-4o-mini")
        .str_attr("gen_ai.request.model", "claude-opus-5")
        .str_attr("acme.note", "first")
        .str_attr("acme.note", "second");
    let ingest = mapped(&[span]);

    // The typed field still takes the first, which is the mapper's documented rule
    // and not what changed.
    assert_eq!(
        ingest.meta.basis.model.as_ref().map(|m| m.as_str()),
        Some("gpt-4o-mini")
    );

    // And every value the mapper did not use is written down.
    let leftover = unmapped(&ingest);
    assert!(
        leftover.contains("gen_ai.request.model\t\"claude-opus-5\"\n"),
        "the second model name went nowhere: {leftover:?}"
    );
    // Quoted, because the leftover renders each value the way everything hashed in
    // this store is rendered, and a string is rendered with its quotes.
    assert!(leftover.contains("acme.note\t\"first\"\n"), "{leftover:?}");
    assert!(leftover.contains("acme.note\t\"second\"\n"), "{leftover:?}");
}

#[test]
fn a_repeated_content_key_stays_content_rather_than_becoming_a_diagnostic() {
    // A repeat of a content key is content as much as the first one is, so it gets
    // a part of its own with the same class. Writing it into the leftover text
    // would put a prompt into a `Diagnostic` part, which is the plane boundary
    // moving under a repeated key.
    let span = SpanBuilder::new("chat")
        .trace_id(vec![0xab; 16])
        .span_id(vec![0x11; 8])
        .str_attr("gen_ai.operation.name", "chat")
        .attr("gen_ai.input.messages", any_string("what is my balance"))
        .attr("gen_ai.input.messages", any_string("and my overdraft"));
    let ingest = mapped(&[span]);

    let prompts: Vec<String> = ingest
        .payload
        .iter()
        .filter(|p| p.class == PayloadClass::Prompt)
        .map(|p| String::from_utf8(p.bytes.clone()).expect("text"))
        .collect();
    assert_eq!(prompts.len(), 2, "both prompts must survive: {prompts:?}");
    assert!(prompts[0].contains("what is my balance"));
    assert!(prompts[1].contains("and my overdraft"));

    let leftover = unmapped(&ingest);
    assert!(
        !leftover.contains("overdraft"),
        "content reached the diagnostic part: {leftover:?}"
    );
}
