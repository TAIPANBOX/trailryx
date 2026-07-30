//! What arrives on the traces endpoint, dialect by dialect and rule by rule.
//!
//! The differential test next door proves the two decoders agree about a batch
//! that is spelled correctly. This one is about everything else that turns up on
//! a real endpoint, and the property it asserts over and over is the same:
//! **exactly one thing goes wrong, it is counted by name, and the line is still a
//! line**. A store that refuses a batch because one emitter spelled one member
//! wrongly has turned an emitter's bug into an outage, and a store that guesses
//! has put a value nobody sent into evidence.
//!
//! So every test below asserts the whole counter list, not the one counter it
//! cares about. Asserting one counter passes just as happily when a second thing
//! also went wrong, and the second thing is the one nobody is looking at.
//!
//! Each test is named for the producer it pins or the rule it pins. The
//! producers are real: the reference collector configured for
//! `application/json`, otel-java's `OtlpJsonLoggingSpanExporter`, and
//! `otel-cli server json`.

mod common;

use common::{jsonenc, spec};
use trailryx_json::{Bound, Kind, Limits as JsonLimits, Syntax};
use trailryx_otlp::otlp::{Span, SpanKind, StatusCode};
use trailryx_otlp::{Decoded, Limits, Value, decode_traces_data};

const LINE: u64 = 42;
const SCOPE: &str = "opentelemetry.instrumentation.openai";

// ---------------------------------------------------------------------------
// The three dialects
// ---------------------------------------------------------------------------

#[test]
fn the_canonical_envelope_a_collector_sends_becomes_records() {
    let line = jsonenc::request(
        &jsonenc::service("payments-agent"),
        SCOPE,
        "0.42.1",
        &[jsonenc::SpanBuilder::new("chat gpt-4o-mini")
            .trace_id(spec::TRACE_ID.to_vec())
            .span_id(spec::ROOT_SPAN_ID.to_vec())],
    );
    let decoded = decode(&line);
    only(&decoded, &[]);
    assert_eq!(decoded.request.span_count(), 1);
    let span = only_span(&decoded);
    assert_eq!(span.trace_id, spec::TRACE_ID.to_vec());
    assert_eq!(span.own_id(), Some(spec::ROOT_SPAN_ID.as_slice()));
    assert_eq!(
        decoded.request.resource_spans[0].scopes[0].scope_version,
        "0.42.1"
    );
}

#[test]
fn a_bare_resource_spans_from_the_otel_java_logging_exporter_is_accepted_and_counted() {
    // `OtlpJsonLoggingSpanExporter` writes one `ResourceSpans` per line with no
    // envelope around it. Deliberate, documented, and a decoder that insisted on
    // `resourceSpans` would read a whole file of these as nothing.
    let span = jsonenc::SpanBuilder::new("chat gpt-4o-mini")
        .trace_id(spec::TRACE_ID.to_vec())
        .span_id(spec::ROOT_SPAN_ID.to_vec());
    let bare = jsonenc::object(&[
        ("resource", resource_object()),
        ("scopeSpans", jsonenc::array(&[scope_spans_object(&span)])),
    ]);
    let decoded = decode(&bare);
    only(&decoded, &[("bare_resource_spans", 1)]);
    assert_eq!(decoded.request.span_count(), 1);

    // And it says the same thing the envelope says. The counter is the only
    // difference between the two dialects, which is what makes it worth counting
    // rather than worth refusing.
    let enveloped = decode(&jsonenc::object(&[(
        "resourceSpans",
        jsonenc::array(&[jsonenc::object(&[
            ("resource", resource_object()),
            ("scopeSpans", jsonenc::array(&[scope_spans_object(&span)])),
        ])]),
    )]));
    assert_eq!(
        decoded.request.resource_spans,
        enveloped.request.resource_spans
    );
    only(&enveloped, &[]);
}

#[test]
fn an_otel_cli_snake_case_line_is_read_and_understood_as_nothing() {
    // `otel-cli server json` writes the `.proto` field names and base64 ids. It
    // is not a newer OTLP and it is not OTLP/JSON: it is a different encoding
    // that happens to have the same shape, and half-reading it produces records
    // with no trace id, which is worse than producing none. One member is
    // skipped at the top and the whole subtree goes with it.
    let line = concat!(
        r#"{"resource_spans":[{"resource":{"attributes":[{"key":"service.name","#,
        r#""value":{"string_value":"payments-agent"}}]},"scope_spans":[{"spans":[{"#,
        r#""trace_id":"S/kvNXezTaajzpKdDg5HNg==","span_id":"APBnqgupArc=","#,
        r#""name":"chat","kind":3,"start_time_unix_nano":"1700000000000000000"}]}]}]}"#
    );
    let decoded = decode(line);
    only(
        &decoded,
        &[
            ("unknown_members", 1),
            ("snake_case_keys", 1),
            ("not_traces_data", 1),
        ],
    );
    assert_eq!(decoded.request.span_count(), 0);
    assert!(decoded.request.resource_spans.is_empty());
    assert!(!decoded.request.dropped.any());
}

#[test]
fn a_snake_case_member_inside_a_camel_case_envelope_is_skipped_and_named() {
    // The dangerous middle case: the envelope is right, so a decoder gets far
    // enough to look confident, and the spans are behind a name it does not know.
    // The batch is empty and the counters say which producer to fix.
    let line = concat!(
        r#"{"resourceSpans":[{"resource":{"attributes":[]},"#,
        r#""scope_spans":[{"spans":[{"name":"chat"}]}]}]}"#
    );
    let decoded = decode(line);
    only(
        &decoded,
        &[
            ("unknown_members", 1),
            ("snake_case_keys", 1),
            ("empty_batches", 1),
        ],
    );
    assert_eq!(decoded.request.span_count(), 0);
    assert_eq!(decoded.request.resource_spans.len(), 1);
}

// ---------------------------------------------------------------------------
// The top-level shapes
// ---------------------------------------------------------------------------

#[test]
fn a_metrics_or_logs_envelope_is_the_wrong_signal_and_not_a_malformed_line() {
    // An exporter pointed at the wrong endpoint. Naming it is the difference
    // between an operator fixing one line of configuration and an operator
    // reading a decoder's source.
    for line in [
        r#"{"resourceMetrics":[{"resource":{"attributes":[]}}]}"#,
        r#"{"resourceLogs":[{"resource":{"attributes":[]}}]}"#,
    ] {
        let decoded = decode(line);
        only(&decoded, &[("unknown_members", 1), ("wrong_signal", 1)]);
        assert_eq!(decoded.request.span_count(), 0);
    }
}

#[test]
fn valid_json_that_is_not_traces_data_is_still_not_a_malformed_line() {
    // Anything at all can be posted to an endpoint. None of these is a parse
    // error, because they parse.
    for (line, unknown) in [
        (r#"{"foo":1}"#, 1),
        (r#"{"resourceSpansX":[]}"#, 1),
        (r#"{"a":1,"b":2}"#, 2),
        ("[]", 0),
        ("[1,2,3]", 0),
        (r#""text""#, 0),
        ("42", 0),
        ("true", 0),
        ("null", 0),
    ] {
        let decoded = decode(line);
        only(
            &decoded,
            &[("unknown_members", unknown), ("not_traces_data", 1)],
        );
        assert_eq!(decoded.request.span_count(), 0, "{line}");
    }
}

#[test]
fn an_empty_object_and_an_empty_batch_are_both_empty_and_neither_is_a_fault() {
    // A collector with an empty queue sends these, and a receiver that logged a
    // fault for each one would drown the real ones.
    for line in [
        "{}",
        r#"{"resourceSpans":[]}"#,
        r#"{"resourceSpans":[{"resource":{"attributes":[]}}]}"#,
        r#"{"resourceSpans":[{"scopeSpans":[{"scope":{"name":"s"},"spans":[]}]}]}"#,
    ] {
        let decoded = decode(line);
        only(&decoded, &[("empty_batches", 1)]);
        assert_eq!(decoded.request.span_count(), 0, "{line}");
        assert!(!decoded.request.dropped.any(), "{line}");
    }
    // A bare `ResourceSpans` with nothing in it is empty and bare at once.
    let decoded = decode(r#"{"resource":{"attributes":[]}}"#);
    only(
        &decoded,
        &[("bare_resource_spans", 1), ("empty_batches", 1)],
    );
}

#[test]
fn only_the_grammar_refuses_a_line() {
    // The four classes the reader has, each reached through this decoder, so that
    // "nothing an emitter can write refuses a line" is a claim about what is
    // left: bytes that are not JSON.
    let truncated = refusal(r#"{"resourceSpans":[{"scopeSpans":"#);
    assert_eq!(truncated.kind, Kind::Syntax(Syntax::UnexpectedEof));
    assert_eq!(
        truncated.line, LINE,
        "the line has to travel into the error"
    );

    // The same member twice in one object. Refused rather than resolved, because
    // which copy wins is an implementation detail and CVE-2017-12635 is that
    // detail becoming a privilege escalation.
    let duplicated = refusal(r#"{"resourceSpans":[],"resourceSpans":[]}"#);
    assert_eq!(duplicated.kind, Kind::Syntax(Syntax::DuplicateName));

    // A bare non-JSON float, which is how a producer that formats its own JSON
    // writes an infinity it should have quoted.
    let bare_nan = refusal(&one_attr(r#"{"doubleValue":NaN}"#));
    assert_eq!(bare_nan.kind, Kind::Syntax(Syntax::BadNumber));

    // Past the container backstop. Built from the bound rather than typed out,
    // because the backstop is a backstop and may move: what the grammar refuses is
    // nesting past it, not nesting past a particular number. The parity with the
    // wire is a different bound in a different place, counted in OTLP message
    // levels, and `tests/differential.rs` is where that is pinned.
    let bound = JsonLimits::default().max_depth;
    let too_deep = format!("{}1{}", "[".repeat(bound + 1), "]".repeat(bound + 1));
    let deep = decode_traces_data(
        too_deep.as_bytes(),
        Limits::default(),
        JsonLimits::default(),
        LINE,
    )
    .expect_err("one container past the backstop");
    assert_eq!(deep.kind, Kind::Limit(Bound::Depth));
}

// ---------------------------------------------------------------------------
// Ids: the one fault that costs a span
// ---------------------------------------------------------------------------

#[test]
fn a_base64_trace_id_drops_the_span_rather_than_storing_a_wrong_trace() {
    // The 24 characters `otel-cli` writes for 16 bytes. Sixteen bytes come out of
    // it if you decode it as base64, and they are not the id the emitter sent,
    // so every span in the batch would point at a trace nobody can find.
    let line = one_span(r#""traceId":"S/kvNXezTaajzpKdDg5HNg==","spanId":"00f067aa0ba902b7""#);
    let decoded = decode(&line);
    only(&decoded, &[("bad_ids", 1), ("empty_batches", 1)]);
    assert_eq!(decoded.request.span_count(), 0);
    assert_eq!(decoded.request.dropped.spans, 1);
}

#[test]
fn an_unreadable_parent_span_id_drops_the_span_because_absent_would_be_a_claim() {
    // Treating this as absent turns a Delegation into a RequestReceived, which is
    // the defect MAPPER_VERSION 2 was cut for. The span goes instead: a record
    // that is missing is a hole an auditor can see, and a record whose parent was
    // invented is not.
    for id in [
        r#""0f067aa0ba902b7""#,   // fifteen characters
        r#""00f067aa0ba902b70""#, // seventeen
        r#""00f067aa0ba902bg""#,  // not hex
        r#""APBnqgupArc=""#,      // base64
        r#""0x00f067aa0ba902b7""#,
    ] {
        let line = one_span(&format!(
            r#""traceId":"{}","spanId":"{}","parentSpanId":{id}"#,
            jsonenc::hex(&spec::TRACE_ID),
            jsonenc::hex(&spec::CHILD_SPAN_ID)
        ));
        let decoded = decode(&line);
        only(&decoded, &[("bad_ids", 1), ("empty_batches", 1)]);
        assert_eq!(decoded.request.span_count(), 0, "{id}");
        assert_eq!(decoded.request.dropped.spans, 1, "{id}");
    }
}

#[test]
fn an_id_that_is_not_a_string_at_all_drops_the_span_and_names_the_type() {
    // A hand-rolled emitter that wrote the id as a number. The type is the fault
    // and the span still goes, because the consequence of reading an unreadable
    // id as absent does not depend on how it was unreadable.
    for member in [
        r#""traceId":123"#,
        r#""spanId":null"#,
        r#""parentSpanId":["00f067aa0ba902b7"]"#,
        r#""traceId":{"value":"4bf92f3577b34da6a3ce929d0e0e4736"}"#,
    ] {
        let decoded = decode(&one_span(member));
        only(&decoded, &[("bad_types", 1), ("empty_batches", 1)]);
        assert_eq!(decoded.request.span_count(), 0, "{member}");
        assert_eq!(decoded.request.dropped.spans, 1, "{member}");
    }
}

#[test]
fn absent_an_empty_string_and_all_zeros_all_mean_no_parent() {
    // Three emitters, three spellings, one meaning. The empty string is what
    // proto3's "always print fields" mode writes, the zeros are what OTLP calls
    // an invalid id and emitters send anyway, and the decoder keeps the bytes it
    // was given rather than re-deriving the answer: `Span::has_parent` is the one
    // place that decides.
    let spans = [
        format!(r#""spanId":"{}""#, jsonenc::hex(&spec::ROOT_SPAN_ID)),
        format!(
            r#""spanId":"{}","parentSpanId":"""#,
            jsonenc::hex(&spec::CHILD_SPAN_ID)
        ),
        format!(
            r#""spanId":"{}","parentSpanId":"0000000000000000""#,
            jsonenc::hex(&spec::ORPHAN_SPAN_ID)
        ),
    ];
    let line = format!(
        r#"{{"resourceSpans":[{{"scopeSpans":[{{"spans":[{{{}}},{{{}}},{{{}}}]}}]}}]}}"#,
        spans[0], spans[1], spans[2]
    );
    let decoded = decode(&line);
    only(&decoded, &[]);
    let spans = &decoded.request.resource_spans[0].scopes[0].spans;
    assert_eq!(spans.len(), 3);
    assert!(spans.iter().all(|s| !s.has_parent()));
    assert!(spans[0].parent_span_id.is_empty());
    assert!(spans[1].parent_span_id.is_empty());
    assert_eq!(spans[2].parent_span_id, vec![0u8; 8]);
}

#[test]
fn a_hex_id_is_case_insensitive_because_the_encoding_says_so() {
    // The specification's own example is uppercase and every collector emits
    // lowercase, so a decoder that accepted one of them would refuse real
    // traffic. The bytes are the same bytes either way.
    let upper =
        one_span(r#""traceId":"4BF92F3577B34DA6A3CE929D0E0E4736","spanId":"00F067AA0BA902B7""#);
    let decoded = decode(&upper);
    only(&decoded, &[]);
    let span = only_span(&decoded);
    assert_eq!(span.trace_id, spec::TRACE_ID.to_vec());
    assert_eq!(span.span_id, spec::ROOT_SPAN_ID.to_vec());
}

// ---------------------------------------------------------------------------
// A known member of the wrong type: one field lost, never a line
// ---------------------------------------------------------------------------

#[test]
fn an_enum_written_as_its_name_is_a_bad_type_and_the_field_keeps_its_default() {
    // Proto3 JSON permits the name and this decoder does not, because accepting
    // it means a second table of names beside the numbers, and the day the two
    // disagree a Server span becomes an Internal one with nothing to say so.
    let decoded = decode(&one_span(r#""kind":"SPAN_KIND_SERVER""#));
    only(&decoded, &[("bad_types", 1)]);
    assert_eq!(only_span(&decoded).kind, SpanKind::Unspecified);

    let decoded = decode(&one_span(r#""status":{"code":"STATUS_CODE_ERROR"}"#));
    only(&decoded, &[("bad_types", 1)]);
    assert_eq!(only_span(&decoded).status_code, StatusCode::Unset);

    // The integers go through the same `from_wire` the wire reader uses, so an
    // enum neither transport knows lands on the same default.
    let decoded = decode(&one_span(
        r#""kind":2,"status":{"code":2,"message":"boom"}"#,
    ));
    only(&decoded, &[]);
    let span = only_span(&decoded);
    assert_eq!(span.kind, SpanKind::Server);
    assert_eq!(span.status_code, StatusCode::Error);
    assert_eq!(span.status_message, "boom");

    let decoded = decode(&one_span(r#""kind":99,"status":{"code":99}"#));
    only(&decoded, &[]);
    assert_eq!(only_span(&decoded).kind, SpanKind::Unspecified);
    assert_eq!(only_span(&decoded).status_code, StatusCode::Unset);
}

#[test]
fn a_repeated_field_written_as_an_object_costs_the_member_and_not_the_line() {
    // `"attributes":{}` is what an emitter that thought a map was a map writes.
    // The span survives with no attributes, which is a visible loss, and every
    // other span in the batch survives too. The `kind` beside the bad member is
    // there to prove the walk carried on reading rather than abandoning the span.
    for member in [
        r#""attributes":{}"#,
        r#""attributes":"none""#,
        r#""events":{}"#,
        r#""status":[]"#,
        r#""name":42"#,
    ] {
        let decoded = decode(&one_span(&format!(r#""kind":3,{member}"#)));
        only(&decoded, &[("bad_types", 1)]);
        let span = only_span(&decoded);
        assert_eq!(span.kind, SpanKind::Client, "{member}");
        assert!(span.attributes.is_empty(), "{member}");
        assert!(span.events.is_empty(), "{member}");
    }
}

#[test]
fn one_bad_element_of_an_array_does_not_cost_the_others() {
    let line = one_span(
        r#""attributes":[{"key":"a","value":{"stringValue":"1"}},7,{"key":"b","value":{"stringValue":"2"}}]"#,
    );
    let decoded = decode(&line);
    only(&decoded, &[("bad_types", 1)]);
    let attrs = &only_span(&decoded).attributes;
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].key, "a");
    assert_eq!(attrs[1].key, "b");
}

#[test]
fn an_absent_field_is_proto3s_default_and_never_an_error() {
    // A span that says nothing at all. Every field is its default and the line is
    // clean: proto3 does not distinguish absent from default, and a decoder that
    // required a member would refuse a conforming emitter.
    let decoded = decode(&one_span(""));
    only(&decoded, &[]);
    let span = only_span(&decoded);
    assert_eq!(span.name, "");
    assert_eq!(span.kind, SpanKind::Unspecified);
    assert_eq!(span.start_time_unix_nano, 0);
    assert_eq!(span.end_time_unix_nano, 0);
    assert_eq!(span.status_code, StatusCode::Unset);
    assert!(span.trace_id.is_empty());
    assert!(!span.has_parent());
    assert_eq!(span.own_id(), None);
}

#[test]
fn an_unknown_member_is_skipped_and_counted_at_every_level_it_can_appear() {
    // A newer OTLP, or a collector with an extension. Six members this version
    // has never heard of, one at each level, and the span still decodes.
    let line = concat!(
        r#"{"newAtTheTop":{"deep":[1,2]},"resourceSpans":[{"newInResourceSpans":1,"#,
        r#""schemaUrl":"https://example.invalid/schema","#,
        r#""scopeSpans":[{"newInScopeSpans":null,"scope":{"name":"s","newInScope":[]},"#,
        r#""spans":[{"newInSpan":"x","traceState":"vendor=1","droppedLinksCount":2,"#,
        r#""name":"chat","attributes":[{"key":"k","newInKeyValue":1,"#,
        r#""value":{"stringValue":"v","newInAnyValue":{}}}]}]}]}]}"#
    );
    let decoded = decode(line);
    only(&decoded, &[("unknown_members", 10)]);
    let span = only_span(&decoded);
    assert_eq!(span.name, "chat");
    assert_eq!(span.attributes.len(), 1);
    assert_eq!(span.attributes[0].value, Value::Str("v".to_owned()));
    // The count travels in the request too, where the wire reader puts its own.
    assert_eq!(decoded.request.unknown_fields, 10);
    assert_eq!(decoded.request.padded_varints, 0);
}

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

#[test]
fn a_64_bit_field_takes_a_decimal_string_or_a_json_number_and_nothing_else() {
    // Both spellings are legal and real emitters send both. The value here needs
    // 61 bits: a decoder that routed it through a double would give back
    // 1700000000123456768, which is a timestamp nobody sent.
    let at = 1_700_000_000_123_456_789u64;
    for spelling in [format!(r#""{at}""#), at.to_string()] {
        let line = one_span(&format!(
            r#""startTimeUnixNano":{spelling},"endTimeUnixNano":{spelling}"#
        ));
        let decoded = decode(&line);
        only(&decoded, &[]);
        assert_eq!(only_span(&decoded).start_time_unix_nano, at, "{spelling}");
        assert_eq!(only_span(&decoded).end_time_unix_nano, at, "{spelling}");
    }
    // The edges of the type, and the exponent form, which is the same number.
    for (spelling, want) in [
        (r#""18446744073709551615""#, u64::MAX),
        (r#""0""#, 0),
        ("18446744073709551615", u64::MAX),
        ("1e3", 1000),
        ("1.0", 1),
    ] {
        let decoded = decode(&one_span(&format!(r#""startTimeUnixNano":{spelling}"#)));
        only(&decoded, &[]);
        assert_eq!(only_span(&decoded).start_time_unix_nano, want, "{spelling}");
    }
}

#[test]
fn a_64_bit_field_that_cannot_be_read_keeps_its_default_and_says_so() {
    // Out of range, not a whole number, not a number at all, or spelled in a way
    // that is not a JSON number. `"+1"` and `"01"` matter more than they look:
    // `str::parse` accepts both as 1, so a decoder built on it would take as a
    // string exactly what the grammar refuses as a number.
    for spelling in [
        "true",
        "null",
        "{}",
        "[]",
        r#""""#,
        r#""+1""#,
        r#""01""#,
        r#""1.5""#,
        r#""1e3""#,
        r#"" 1""#,
        r#""-1""#,
        r#""18446744073709551616""#,
        r#""0x10""#,
        "-1",
        "1.5",
        "18446744073709551616",
        "1e999",
    ] {
        let decoded = decode(&one_span(&format!(r#""startTimeUnixNano":{spelling}"#)));
        only(&decoded, &[("bad_numbers", 1)]);
        assert_eq!(
            only_span(&decoded).start_time_unix_nano,
            0,
            "{spelling} must leave the default"
        );
    }
}

#[test]
fn an_int_value_takes_both_spellings_and_the_edges_of_the_type() {
    for (spelling, want) in [
        (r#""1024""#, 1024),
        ("1204", 1204),
        (r#""-9223372036854775808""#, i64::MIN),
        (r#""9223372036854775807""#, i64::MAX),
        ("-1", -1),
        (r#""-0""#, 0),
    ] {
        let decoded = decode(&one_attr(&format!(r#"{{"intValue":{spelling}}}"#)));
        only(&decoded, &[]);
        assert_eq!(*only_value(&decoded), Value::Int(want), "{spelling}");
    }
    // Past the type in both directions. The value stays absent rather than
    // saturating: `9223372036854775808u64 as i64` is `i64::MIN`, which is a wrong
    // answer that looks like a right one.
    for spelling in [
        r#""9223372036854775808""#,
        r#""-9223372036854775809""#,
        "9223372036854775808",
    ] {
        let decoded = decode(&one_attr(&format!(r#"{{"intValue":{spelling}}}"#)));
        only(&decoded, &[("bad_numbers", 1)]);
        assert_eq!(*only_value(&decoded), Value::Empty, "{spelling}");
    }
}

#[test]
fn a_finite_double_that_overflows_is_refused_and_infinity_is_not() {
    // The asymmetry is deliberate. An emitter that means infinity has a word for
    // it; an emitter that wrote 1e999 wrote a finite number this type cannot
    // hold, and storing infinity for it would be a repair.
    let decoded = decode(&one_attr(r#"{"doubleValue":1e999}"#));
    only(&decoded, &[("double_overflow", 1)]);
    assert_eq!(*only_value(&decoded), Value::Empty);

    // Underflow is not overflow: a number too small to tell from zero is zero.
    let decoded = decode(&one_attr(r#"{"doubleValue":1e-999}"#));
    only(&decoded, &[]);
    assert_eq!(*only_value(&decoded), Value::Double(0.0));

    for (word, want) in [
        ("Infinity", f64::INFINITY),
        ("-Infinity", f64::NEG_INFINITY),
    ] {
        let decoded = decode(&one_attr(&format!(r#"{{"doubleValue":"{word}"}}"#)));
        only(&decoded, &[("nonfinite_doubles", 1)]);
        assert_eq!(*only_value(&decoded), Value::Double(want), "{word}");
    }
    let decoded = decode(&one_attr(r#"{"doubleValue":"NaN"}"#));
    only(&decoded, &[("nonfinite_doubles", 1)]);
    assert!(matches!(only_value(&decoded), Value::Double(d) if d.is_nan()));

    // Those three words and no others. A number written as a string is legal for
    // a 64-bit integer and not for a double, and reading it anyway would be
    // inventing a dialect for one producer.
    for text in ["1.5", "inf", "INFINITY", "+Infinity", "nan", ""] {
        let decoded = decode(&one_attr(&format!(r#"{{"doubleValue":"{text}"}}"#)));
        only(&decoded, &[("bad_types", 1)]);
        assert_eq!(*only_value(&decoded), Value::Empty, "{text}");
    }
}

// ---------------------------------------------------------------------------
// AnyValue
// ---------------------------------------------------------------------------

#[test]
fn an_empty_anyvalue_is_present_and_empty_and_not_absent() {
    // An SDK configured with a key and given no value writes `{}`. The attribute
    // exists and its value does not, and folding the two together loses the
    // difference between a cleared field and one nobody wrote.
    for value in ["{}", r#"{"unknownValue":1}"#] {
        let decoded = decode(&one_attr(value));
        let attrs = &only_span(&decoded).attributes;
        assert_eq!(attrs.len(), 1, "{value}");
        assert_eq!(attrs[0].key, "k", "{value}");
        assert_eq!(attrs[0].value, Value::Empty, "{value}");
    }
    // A `KeyValue` with no `value` member at all is the same value and still an
    // attribute.
    let decoded = decode(&one_span(r#""attributes":[{"key":"k"}]"#));
    only(&decoded, &[]);
    assert_eq!(only_span(&decoded).attributes[0].value, Value::Empty);
}

#[test]
fn two_members_in_one_anyvalue_let_the_last_win_and_say_so() {
    // A oneof cannot have two members set and this document says it does. Last
    // wins, because that is what the wire reader's match arms do, and the two
    // transports must not disagree about a message neither of them should have
    // been sent.
    let decoded = decode(&one_attr(r#"{"stringValue":"first","intValue":"5"}"#));
    only(&decoded, &[("multi_valued_anyvalue", 1)]);
    assert_eq!(*only_value(&decoded), Value::Int(5));

    let decoded = decode(&one_attr(r#"{"intValue":"5","stringValue":"last"}"#));
    only(&decoded, &[("multi_valued_anyvalue", 1)]);
    assert_eq!(*only_value(&decoded), Value::Str("last".to_owned()));

    // A member that could not be read sets nothing, so it is not a second value.
    let decoded = decode(&one_attr(r#"{"stringValue":"kept","intValue":true}"#));
    only(&decoded, &[("bad_numbers", 1)]);
    assert_eq!(*only_value(&decoded), Value::Str("kept".to_owned()));
}

#[test]
fn a_bytes_value_is_base64_in_either_alphabet_and_padding_is_optional() {
    // Proto3 says `bytes` are base64 and does not say which alphabet, so both
    // are accepted. This is also the only place a decoder can be tempted to try
    // hex, and the ids are the only place it can be tempted to try base64.
    for text in ["3q2+7wB//w==", "3q2-7wB__w==", "3q2+7wB//w", "3q2-7wB__w"] {
        let decoded = decode(&one_attr(&format!(r#"{{"bytesValue":"{text}"}}"#)));
        only(&decoded, &[]);
        assert_eq!(
            *only_value(&decoded),
            Value::Bytes(spec::FINGERPRINT.to_vec()),
            "{text}"
        );
    }
    let decoded = decode(&one_attr(r#"{"bytesValue":""}"#));
    only(&decoded, &[]);
    assert_eq!(*only_value(&decoded), Value::Bytes(Vec::new()));
}

#[test]
fn a_bytes_value_that_is_not_base64_leaves_the_value_empty_and_counts_it() {
    for text in [
        "!!!!",         // outside the alphabet
        "A",            // one character, which no group can be
        "3q2+7wB//w=x", // a character after the padding
        "/x==",         // a second spelling of the byte /w== already spells
        "3q2 7wB//w==", // a space, which some encoders wrap lines with
        "deadbeef00",   // hex, which is what a decoder confusing the two writes
    ] {
        let decoded = decode(&one_attr(&format!(r#"{{"bytesValue":"{text}"}}"#)));
        only(&decoded, &[("bad_base64", 1)]);
        assert_eq!(*only_value(&decoded), Value::Empty, "{text}");
    }
    // Not a string at all.
    let decoded = decode(&one_attr(r#"{"bytesValue":[222,173]}"#));
    only(&decoded, &[("bad_types", 1)]);
    assert_eq!(*only_value(&decoded), Value::Empty);
}

#[test]
fn an_array_and_a_kvlist_need_their_values_wrapper() {
    // `ArrayValue` is a message with one field, so the wrapper is not decoration.
    // An emitter that writes the array directly loses the values, and the count
    // is what tells it so.
    let decoded = decode(&one_attr(r#"{"arrayValue":{"values":[{"intValue":"1"}]}}"#));
    only(&decoded, &[]);
    assert_eq!(*only_value(&decoded), Value::Array(vec![Value::Int(1)]));

    let decoded = decode(&one_attr(r#"{"arrayValue":[{"intValue":"1"}]}"#));
    only(&decoded, &[("bad_types", 1)]);
    assert_eq!(*only_value(&decoded), Value::Empty);

    let decoded = decode(&one_attr(
        r#"{"kvlistValue":{"values":[{"key":"a","value":{"boolValue":true}}]}}"#,
    ));
    only(&decoded, &[]);
    let Value::Map(pairs) = only_value(&decoded) else {
        panic!("a kvlist must decode to a map");
    };
    assert_eq!(pairs[0].key, "a");
    assert_eq!(pairs[0].value, Value::Bool(true));

    // A kvlist is not a JSON object, however much it looks like one should be.
    let decoded = decode(&one_attr(r#"{"kvlistValue":{"a":{"boolValue":true}}}"#));
    only(&decoded, &[("unknown_members", 1)]);
    assert_eq!(*only_value(&decoded), Value::Map(Vec::new()));
}

// ---------------------------------------------------------------------------
// The bounds, charged where the wire path charges them
// ---------------------------------------------------------------------------

#[test]
fn the_attribute_bound_drops_the_overflow_and_charges_the_wire_paths_counter() {
    let limits = Limits {
        max_attributes: 2,
        ..Limits::default()
    };
    let line = one_span(
        r#""attributes":[{"key":"a","value":{"intValue":"1"}},{"key":"b","value":{"intValue":"2"}},{"key":"c","value":{"intValue":"3"}},{"key":"d","value":{"intValue":"4"}}]"#,
    );
    let decoded = decode_with(&line, limits);
    only(&decoded, &[]);
    let attrs = &only_span(&decoded).attributes;
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[1].key, "b");
    assert_eq!(decoded.request.dropped.attributes, 2);
}

#[test]
fn a_key_longer_than_the_bound_is_cut_where_the_wire_path_cuts_it() {
    // Cut by bytes and through the same function, so a key that straddles the cut
    // gets the same U+FFFD in both stores. Two spellings of one key would mean
    // two columns in a projection.
    let limits = Limits {
        max_key_bytes: 4,
        ..Limits::default()
    };
    let decoded = decode_with(&one_span(r#""attributes":[{"key":"abcdefgh"}]"#), limits);
    assert_eq!(only_span(&decoded).attributes[0].key, "abcd");

    // A three-byte character straddling the boundary. The tail is replaced, not
    // dropped and not repaired.
    let decoded = decode_with(&one_span(r#""attributes":[{"key":"ab€"}]"#), limits);
    assert_eq!(only_span(&decoded).attributes[0].key, "ab\u{fffd}");
}

#[test]
fn an_oversize_value_is_charged_to_the_wire_paths_counter_and_leaves_no_value() {
    let limits = Limits {
        max_value_bytes: 8,
        ..Limits::default()
    };
    let decoded = decode_with(&one_attr(r#"{"stringValue":"far too many bytes"}"#), limits);
    only(&decoded, &[]);
    // Empty and not truncated: a value cut in half is a value that says something
    // the emitter did not.
    assert_eq!(*only_value(&decoded), Value::Empty);
    assert_eq!(decoded.request.dropped.oversize_values, 1);

    // The bound is on the decoded bytes and not on the base64, which is a third
    // longer: nine bytes are over an eight-byte bound however they were spelled.
    let nine = jsonenc::base64(&[0xab; 9]);
    let decoded = decode_with(&one_attr(&format!(r#"{{"bytesValue":"{nine}"}}"#)), limits);
    only(&decoded, &[]);
    assert_eq!(*only_value(&decoded), Value::Empty);
    assert_eq!(decoded.request.dropped.oversize_values, 1);

    // And eight of them are not over it, so the bound is the boundary and not an
    // estimate made from the encoded length.
    let eight = jsonenc::base64(&[0xab; 8]);
    let decoded = decode_with(&one_attr(&format!(r#"{{"bytesValue":"{eight}"}}"#)), limits);
    only(&decoded, &[]);
    assert_eq!(*only_value(&decoded), Value::Bytes(vec![0xab; 8]));
    assert_eq!(decoded.request.dropped.oversize_values, 0);
}

#[test]
fn the_array_item_bound_charges_the_attribute_counter_as_the_wire_path_does() {
    let limits = Limits {
        max_array_items: 2,
        ..Limits::default()
    };
    let line = one_attr(
        r#"{"arrayValue":{"values":[{"intValue":"1"},{"intValue":"2"},{"intValue":"3"}]}}"#,
    );
    let decoded = decode_with(&line, limits);
    only(&decoded, &[]);
    assert_eq!(
        *only_value(&decoded),
        Value::Array(vec![Value::Int(1), Value::Int(2)])
    );
    assert_eq!(decoded.request.dropped.attributes, 1);
}

#[test]
fn the_span_and_event_bounds_drop_the_overflow_without_calling_it_unknown() {
    // A span past the bound is one this decoder understood perfectly and declined
    // to store. Counting it as an unknown member would report a hundred thousand
    // fields we did not understand about a batch we understood entirely.
    let limits = Limits {
        max_spans: 1,
        max_events: 1,
        ..Limits::default()
    };
    let event = r#"{"timeUnixNano":"1","name":"e"}"#;
    let line = format!(
        r#"{{"resourceSpans":[{{"scopeSpans":[{{"spans":[{{"name":"kept","events":[{event},{event}]}},{{"name":"dropped"}}]}}]}}]}}"#
    );
    let decoded = decode_with(&line, limits);
    only(&decoded, &[]);
    let span = only_span(&decoded);
    assert_eq!(span.name, "kept");
    assert_eq!(span.events.len(), 1);
    assert_eq!(decoded.request.dropped.spans, 1);
    assert_eq!(decoded.request.dropped.events, 1);
    assert_eq!(decoded.request.unknown_fields, 0);
}

#[test]
fn the_span_bound_counts_the_whole_batch_and_not_one_scope() {
    // As on the wire: the bound is on what one line can put in the store, so two
    // scopes of one span each are two spans.
    let limits = Limits {
        max_spans: 1,
        ..Limits::default()
    };
    let scope = r#"{"spans":[{"name":"s"}]}"#;
    let line = format!(r#"{{"resourceSpans":[{{"scopeSpans":[{scope},{scope}]}}]}}"#);
    let decoded = decode_with(&line, limits);
    assert_eq!(decoded.request.span_count(), 1);
    assert_eq!(decoded.request.dropped.spans, 1);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn decode(line: &str) -> Decoded {
    decode_with(line, Limits::default())
}

fn decode_with(line: &str, limits: Limits) -> Decoded {
    decode_traces_data(line.as_bytes(), limits, JsonLimits::default(), LINE)
        .unwrap_or_else(|e| panic!("{line}\nmust decode, and did not: {e}"))
}

fn refusal(line: &str) -> trailryx_json::JsonError {
    decode_traces_data(
        line.as_bytes(),
        Limits::default(),
        JsonLimits::default(),
        LINE,
    )
    .map(|_| ())
    .expect_err("these bytes must be refused")
}

/// Assert the counters named, and that every counter not named is zero.
///
/// Asserting one counter passes just as happily when a second thing also went
/// wrong, and the second thing is the one nobody is looking at.
fn only(decoded: &Decoded, want: &[(&str, u32)]) {
    for (name, value) in decoded.shape.counters() {
        let expected = want
            .iter()
            .find(|(wanted, _)| *wanted == name)
            .map_or(0, |(_, v)| *v);
        assert_eq!(value, expected, "the {name} counter");
    }
    for (name, _) in want {
        assert!(
            decoded.shape.counters().iter().any(|(n, _)| n == name),
            "there is no counter named {name}, so this expectation asserts nothing"
        );
    }
}

/// The canonical envelope around one span, whose members are written verbatim.
fn one_span(members: &str) -> String {
    format!(r#"{{"resourceSpans":[{{"scopeSpans":[{{"spans":[{{{members}}}]}}]}}]}}"#)
}

/// The same, around one attribute whose `AnyValue` is written verbatim.
fn one_attr(value: &str) -> String {
    one_span(&format!(r#""attributes":[{{"key":"k","value":{value}}}]"#))
}

fn only_span(decoded: &Decoded) -> &Span {
    let spans = &decoded.request.resource_spans[0].scopes[0].spans;
    assert_eq!(spans.len(), 1, "exactly one span was expected");
    &spans[0]
}

fn only_value(decoded: &Decoded) -> &Value {
    let attrs = &only_span(decoded).attributes;
    assert_eq!(attrs.len(), 1, "exactly one attribute was expected");
    &attrs[0].value
}

fn resource_object() -> String {
    jsonenc::object(&[(
        "attributes",
        jsonenc::array(&[jsonenc::kv(
            "service.name",
            jsonenc::any_string("payments-agent"),
        )]),
    )])
}

fn scope_spans_object(span: &jsonenc::SpanBuilder) -> String {
    jsonenc::object(&[
        (
            "scope",
            jsonenc::object(&[("name", jsonenc::string(SCOPE))]),
        ),
        ("spans", jsonenc::array(&[span.encode()])),
    ])
}
