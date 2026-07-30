//! One batch, two encodings, two decoders, and one answer.
//!
//! The claim this file exists to hold up is the one in the crate doc: there are
//! two transports and one mapper, so nothing downstream of a decode can tell
//! which content type the collector was configured for. That claim is cheap to
//! state and it fails quietly, because each decoder's own tests pass while the
//! two of them disagree about the same run.
//!
//! So the fixture in `common/spec.rs` is described once as data and written twice
//! by encoders that share no code, and the two decoded
//! [`trailryx_otlp::TraceRequest`] values are compared as whole structs. Not
//! field by field: a comparison that names the fields it checks is a comparison
//! that stops covering the field somebody adds next.
//!
//! # Why the sweep below the fixture
//!
//! The fixture is one document and cannot be every document. The tests after it
//! take the awkward parts one at a time, so that a failure names the value that
//! broke rather than saying two large structs differ:
//!
//! - every `AnyValue` variant, including the empty one, which is present and
//!   empty and not the same as absent;
//! - a 64-bit integer written as a decimal string on one side and a varint on the
//!   other, which is the case that loses whole fields when a decoder reads only
//!   one of the two legal spellings;
//! - `NaN`, compared through a rendered form rather than by equality, because
//!   `NaN != NaN` would fail this test for a reason that has nothing to do with
//!   decoding;
//! - a span carrying events, an error status, the same attribute key twice, and a
//!   `parentSpanId` of eight zero bytes.
//!
//! # And why the nesting test
//!
//! `trailryx_json::Limits::max_depth` is 25 and [`trailryx_otlp::protobuf::MAX_DEPTH`]
//! is 16, and those two numbers have to admit exactly the same OTLP nesting: an
//! `AnyValue` starts at container depth 10 in JSON and at message depth 5 on the
//! wire, and each further level costs 3 or 4 in JSON against 2 or 3 on the wire.
//! Nobody can check that by looking. The last test encodes the boundary both
//! ways and fails loudly if either constant moves, because a transport that
//! admits deeper payloads than its twin is a way to choose which reader sees your
//! batch.

mod common;

use common::{jsonenc, spec};
use trailryx_json::Limits as JsonLimits;
use trailryx_otlp::otlp::TraceRequest;
use trailryx_otlp::protobuf::MAX_DEPTH;
use trailryx_otlp::{Decoded, Limits, Value, decode_trace_request, decode_traces_data};

/// The line number every JSON decode here is told it is at. Any number but zero:
/// the point is that it travels into an error, and these lines do not fail.
const LINE: u64 = 7;

const SCOPE: &str = "opentelemetry.instrumentation.openai";
const KEY: &str = "app.value";

// ---------------------------------------------------------------------------
// The headline
// ---------------------------------------------------------------------------

#[test]
fn the_two_decoders_agree_on_every_byte() {
    let f = spec::fixture();
    let wire = decode_trace_request(&spec::encode_protobuf(&f), Limits::default())
        .expect("the fixture's protobuf side must decode");
    let json = spec::encode_json(&f);
    let text = decode_traces_data(
        json.as_bytes(),
        Limits::default(),
        JsonLimits::default(),
        LINE,
    )
    .expect("the fixture's JSON side must decode");

    // Whole structs, including the counters. Everything the fixture is built out
    // of is in here: the empty AnyValue, the all-zero parent, both spellings of a
    // 64-bit integer, the nanosecond clocks that are not representable as
    // doubles, the escaped and the raw spelling of one string, the base64 bytes,
    // the non-finite double, the repeated attribute key, the event, the status.
    assert_eq!(text.request, wire);

    // And what the JSON side had to say that the wire side has no way to say. The
    // list is exhaustive by construction, so a counter added later shows up here
    // as a compile error rather than as an untested field.
    assert_eq!(
        text.shape.counters(),
        [
            // `droppedAttributesCount`, the one member the fixture writes that
            // neither decoder models. The wire side counts the same one.
            ("unknown_members", 1),
            ("snake_case_keys", 0),
            ("not_traces_data", 0),
            ("wrong_signal", 0),
            ("bare_resource_spans", 0),
            ("empty_batches", 0),
            ("bad_ids", 0),
            ("bad_types", 0),
            ("bad_numbers", 0),
            ("double_overflow", 0),
            // `app.score`, written `"Infinity"` because JSON has no literal.
            ("nonfinite_doubles", 1),
            ("bad_base64", 0),
            ("multi_valued_anyvalue", 0),
        ]
    );
    assert_eq!(
        wire.unknown_fields, 1,
        "the two tallies must be the one tally"
    );
    assert_eq!(text.request.span_count(), 3);
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

#[test]
fn every_anyvalue_variant_decodes_to_the_same_value_from_either_transport() {
    let cases: Vec<(&str, Vec<u8>, String)> = vec![
        (
            "a string",
            common::any_string("payments-agent"),
            jsonenc::any_string("payments-agent"),
        ),
        (
            "the same string spelled with escapes on the JSON side",
            common::any_string(spec::CONTROL_ZOO),
            jsonenc::any_string_escaped(spec::CONTROL_ZOO),
        ),
        (
            "the empty string",
            common::any_string(""),
            jsonenc::any_string(""),
        ),
        ("true", common::any_bool(true), jsonenc::any_bool(true)),
        ("false", common::any_bool(false), jsonenc::any_bool(false)),
        (
            "an integer as a decimal string in JSON and a varint on the wire",
            common::any_int(1024),
            jsonenc::any_int(1024, jsonenc::IntForm::DecimalString),
        ),
        (
            "an integer as a JSON number",
            common::any_int(1204),
            jsonenc::any_int(1204, jsonenc::IntForm::Number),
        ),
        (
            "a negative integer",
            common::any_int(-1),
            jsonenc::any_int(-1, jsonenc::IntForm::DecimalString),
        ),
        (
            "the integer with no positive counterpart",
            common::any_int(i64::MIN),
            jsonenc::any_int(i64::MIN, jsonenc::IntForm::DecimalString),
        ),
        (
            "an integer past what a double holds exactly",
            common::any_int(9_007_199_254_740_993),
            jsonenc::any_int(9_007_199_254_740_993, jsonenc::IntForm::Number),
        ),
        (
            "a double",
            common::any_double(0.2),
            jsonenc::any_double(0.2),
        ),
        (
            "negative zero",
            common::any_double(-0.0),
            jsonenc::any_double(-0.0),
        ),
        (
            "the largest finite double",
            common::any_double(f64::MAX),
            jsonenc::any_double(f64::MAX),
        ),
        (
            "positive infinity, which JSON has to spell as a word",
            common::any_double(f64::INFINITY),
            jsonenc::any_double(f64::INFINITY),
        ),
        (
            "negative infinity",
            common::any_double(f64::NEG_INFINITY),
            jsonenc::any_double(f64::NEG_INFINITY),
        ),
        (
            "bytes, base64 on one side and length-delimited on the other",
            common::len_delim(7, spec::FINGERPRINT),
            jsonenc::any_bytes(spec::FINGERPRINT),
        ),
        (
            "no bytes at all",
            common::len_delim(7, b""),
            jsonenc::any_bytes(b""),
        ),
        (
            "an empty AnyValue, which is present and empty",
            Vec::new(),
            jsonenc::any_empty(),
        ),
        (
            "an empty array",
            common::any_array(&[]),
            jsonenc::any_array(&[]),
        ),
        (
            "an array of every scalar",
            common::any_array(&[
                common::any_string("text"),
                common::any_bool(false),
                common::any_int(7),
                common::any_double(1.5),
                Vec::new(),
            ]),
            jsonenc::any_array(&[
                jsonenc::any_string("text"),
                jsonenc::any_bool(false),
                jsonenc::any_int(7, jsonenc::IntForm::DecimalString),
                jsonenc::any_double(1.5),
                jsonenc::any_empty(),
            ]),
        ),
        (
            "an empty kvlist",
            common::any_map(&[]),
            jsonenc::any_map(&[]),
        ),
        (
            "an array of kvlist, which is the GenAI messages shape",
            common::any_array(&[common::any_map(&[
                ("role", common::any_string("user")),
                (
                    "parts",
                    common::any_array(&[common::any_map(&[(
                        "content",
                        common::any_string("Résume la partition \u{1d11e}"),
                    )])]),
                ),
            ])]),
            jsonenc::any_array(&[jsonenc::any_map(&[
                ("role", jsonenc::any_string("user")),
                (
                    "parts",
                    jsonenc::any_array(&[jsonenc::any_map(&[(
                        "content",
                        jsonenc::any_string_escaped("Résume la partition \u{1d11e}"),
                    )])]),
                ),
            ])]),
        ),
    ];

    for (what, pb, js) in cases {
        let (wire, text) = both_ways(pb, js);
        assert_eq!(text.request, wire, "{what}");
        // A silent no-op would satisfy the line above, so the value has to have
        // arrived at all.
        assert_eq!(text.request.span_count(), 1, "{what}");
    }
}

#[test]
fn nan_arrives_from_both_transports_and_is_compared_by_what_it_renders_as() {
    // `NaN != NaN`, so an equality assertion on the whole struct would fail here
    // for a reason that has nothing to do with either decoder. The rendered form
    // is the comparison this deserves, and it still fails if one side produced a
    // number or nothing at all.
    let (wire, text) = both_ways(common::any_double(f64::NAN), jsonenc::any_double(f64::NAN));
    assert_eq!(format!("{:?}", text.request), format!("{wire:?}"));
    let value = only_attr(&text);
    assert!(
        matches!(value, Value::Double(d) if d.is_nan()),
        "the JSON side produced {value:?}"
    );
    assert_eq!(text.shape.counters()[10], ("nonfinite_doubles", 1));
    // And the struct comparison really is the thing that cannot be used, rather
    // than something this test is avoiding out of caution.
    assert_ne!(text.request, wire);
}

#[test]
fn a_span_with_events_a_status_a_repeated_key_and_a_zero_parent_agrees_too() {
    let at = 1_700_000_000_500_000_000;
    let message = "429 Too Many Requests";
    let pb = common::request(
        &common::service("payments-agent"),
        SCOPE,
        &[common::SpanBuilder::new("chat gpt-4o-mini")
            // Eight zero bytes: OTLP calls this id invalid and emitters send it
            // rather than omitting the field.
            .parent(spec::INVALID_PARENT.to_vec())
            .attr("app.retry", common::any_int(1))
            .attr("app.retry", common::any_string("after the second attempt"))
            .event(
                at,
                "exception",
                &[
                    ("exception.type", common::any_string("RateLimitError")),
                    ("exception.escaped", common::any_bool(true)),
                    ("retry.after_ms", common::any_int(3_000)),
                ],
            )
            .status(2, message)],
    );
    let js = jsonenc::request(
        &jsonenc::service("payments-agent"),
        SCOPE,
        "",
        &[jsonenc::SpanBuilder::new("chat gpt-4o-mini")
            .parent(spec::INVALID_PARENT.to_vec())
            .attr("app.retry", jsonenc::any_int(1, jsonenc::IntForm::Number))
            .attr("app.retry", jsonenc::any_string("after the second attempt"))
            .event(
                at,
                "exception",
                &[
                    ("exception.type", jsonenc::any_string("RateLimitError")),
                    ("exception.escaped", jsonenc::any_bool(true)),
                    (
                        "retry.after_ms",
                        jsonenc::any_int(3_000, jsonenc::IntForm::DecimalString),
                    ),
                ],
            )
            .status(2, message)],
    );

    let wire = decode_trace_request(&pb, Limits::default()).expect("the protobuf side must decode");
    let text = decode_traces_data(
        js.as_bytes(),
        Limits::default(),
        JsonLimits::default(),
        LINE,
    )
    .expect("the JSON side must decode");
    assert_eq!(text.request, wire);

    let span = &text.request.resource_spans[0].scopes[0].spans[0];
    // The eight zero bytes are here, and they still name no parent. Deriving
    // "absent" at decode time instead would have thrown the bytes away.
    assert_eq!(span.parent_span_id, spec::INVALID_PARENT.to_vec());
    assert!(!span.has_parent());
    assert_eq!(span.status_message, message);
    assert_eq!(span.events.len(), 1);
    assert_eq!(span.events[0].time_unix_nano, at);
    assert_eq!(span.events[0].attributes.len(), 3);
    // The repeated key arrives twice, in order, from both.
    let retries: Vec<&Value> = span
        .attributes
        .iter()
        .filter(|a| a.key == "app.retry")
        .map(|a| &a.value)
        .collect();
    assert_eq!(
        retries,
        vec![
            &Value::Int(1),
            &Value::Str("after the second attempt".to_owned())
        ]
    );
}

// ---------------------------------------------------------------------------
// The two depth limits, pinned against each other
// ---------------------------------------------------------------------------

#[test]
fn nesting_is_bounded_the_same_way_on_both_transports() {
    // What is pinned here is that the two transports agree about which lines
    // become records, over every position an `AnyValue` can occupy and every mix
    // of the two nesting shapes. It used to be a pair of constants and a pure
    // chain at one position, and that missed a divergence in BOTH directions: a
    // resource attribute nested two array and three map levels was refused on the
    // wire and accepted in JSON, and a span attribute nested four array and one
    // map level was accepted on the wire and refused in JSON. The derivation
    // behind it cannot work, because the wire charges 2 and 3 per level and the
    // JSON spelling charges 3 and 4, and no single container bound matches a
    // message bound at two different ratios.
    //
    // The parity is now counted in OTLP message levels, in `otlpjson::Ctx`, so it
    // is exact by construction. This grid is what keeps it honest.
    assert_eq!(
        MAX_DEPTH, 16,
        "the wire depth bound moved; the JSON side reads this same constant, so \
         only this message and the headroom note on JsonLimits::max_depth need it"
    );

    let mut agreed = 0usize;
    let mut deepest_accepted = 0usize;
    for position in [Position::Resource, Position::Span, Position::Event] {
        for arrays in 0..=7 {
            for maps in 0..=5 {
                let (pb, js) = at_position(position, arrays, maps);
                let wire = decode_trace_request(&pb, Limits::default());
                let text =
                    decode_traces_data(js.as_bytes(), Limits::default(), JsonLimits::default(), 1);
                assert_eq!(
                    wire.is_ok(),
                    text.is_ok(),
                    "{position:?} with {arrays} array and {maps} map levels: \
                     wire {:?}, json {:?}",
                    wire.as_ref()
                        .map(|r| r.span_count())
                        .map_err(|e| format!("{e:?}")),
                    text.as_ref()
                        .map(|d| d.request.span_count())
                        .map_err(|e| format!("{:?}", e.kind)),
                );
                if let (Ok(w), Ok(t)) = (&wire, &text) {
                    assert_eq!(&t.request, w, "{position:?} {arrays}/{maps}");
                    // The container depth the JSON spelling of this shape reached,
                    // which is what `JsonLimits::max_depth` has to stay clear of.
                    let containers = position.json_base() + 3 * arrays + 4 * maps;
                    deepest_accepted = deepest_accepted.max(containers);
                }
                agreed += 1;
            }
        }
    }
    assert_eq!(agreed, 3 * 8 * 6);
    // The measurement behind the headroom on `JsonLimits::max_depth`. If this
    // grows past the bound, the container backstop has become the binding
    // constraint and is refusing OTLP the wire accepts.
    assert_eq!(
        deepest_accepted, 27,
        "the deepest wire-legal container nesting"
    );
    assert!(
        deepest_accepted < JsonLimits::default().max_depth,
        "the container backstop is now the binding constraint, which is the defect \
         this test was rewritten to catch"
    );
}

#[test]
fn the_deepest_shape_the_conventions_actually_produce_still_parses() {
    // A depth bound that refuses a legitimate structured-message attribute is a
    // data-loss bug wearing a security argument. The GenAI conventions put
    // messages in an array of maps whose `parts` is another array of maps, which
    // is two array levels and two map levels.
    let (pb, js) = at_position(Position::Span, 2, 2);
    let wire = decode_trace_request(&pb, Limits::default()).expect("the wire must take it");
    let text = decode_traces_data(js.as_bytes(), Limits::default(), JsonLimits::default(), 1)
        .expect("and so must the JSON");
    assert_eq!(text.request, wire);
    assert_eq!(wire.span_count(), 1);
}

/// Where an `AnyValue` sits, which decides how deep it starts on each transport.
#[derive(Debug, Clone, Copy)]
enum Position {
    Resource,
    Span,
    Event,
}

impl Position {
    /// The container depth of the first `AnyValue` in the JSON spelling.
    fn json_base(self) -> usize {
        match self {
            // {} resourceSpans[] {} resource{} attributes[] KeyValue{} AnyValue{}
            Self::Resource => 7,
            // ... scopeSpans[] {} spans[] {} attributes[] KeyValue{} AnyValue{}
            Self::Span => 10,
            // ... spans[] {} events[] {} attributes[] KeyValue{} AnyValue{}
            Self::Event => 12,
        }
    }
}

/// One batch carrying one deeply nested attribute at `position`, encoded twice.
fn at_position(position: Position, arrays: usize, maps: usize) -> (Vec<u8>, String) {
    let pb_value = nested_pb(arrays, maps);
    let js_value = nested_json(arrays, maps);

    let mut span = common::SpanBuilder::new("chat gpt-4o-mini");
    let mut js_span = jsonenc::SpanBuilder::new("chat gpt-4o-mini");
    let mut resource_pb: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut resource_js: Vec<(&str, String)> = Vec::new();
    match position {
        Position::Resource => {
            resource_pb.push((KEY, pb_value));
            resource_js.push((KEY, js_value));
        }
        Position::Span => {
            span = span.attr(KEY, pb_value);
            js_span = js_span.attr(KEY, js_value);
        }
        Position::Event => {
            span = span.event(7, "boom", &[(KEY, pb_value)]);
            js_span = js_span.event(7, "boom", &[(KEY, js_value)]);
        }
    }
    let pb = common::request(&resource_pb, SCOPE, &[span]);
    let js = jsonenc::request(&resource_js, SCOPE, "", &[js_span]);
    (pb, js)
}

fn nested_pb(arrays: usize, maps: usize) -> Vec<u8> {
    let mut value = common::any_string("leaf");
    for _ in 0..maps {
        value = common::any_map(&[("k", value)]);
    }
    for _ in 0..arrays {
        value = common::any_array(&[value]);
    }
    value
}

fn nested_json(arrays: usize, maps: usize) -> String {
    let mut value = String::from("{\"stringValue\":\"leaf\"}");
    for _ in 0..maps {
        value = format!("{{\"kvlistValue\":{{\"values\":[{{\"key\":\"k\",\"value\":{value}}}]}}}}");
    }
    for _ in 0..arrays {
        value = format!("{{\"arrayValue\":{{\"values\":[{value}]}}}}");
    }
    value
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// One `AnyValue`, as the single attribute of one span, decoded from both
/// encodings of the same batch.
fn both_ways(value_pb: Vec<u8>, value_json: String) -> (TraceRequest, Decoded) {
    let (pb, js) = encode_both(value_pb, value_json);
    let wire = decode_trace_request(&pb, Limits::default()).expect("the protobuf side must decode");
    let text = decode_traces_data(
        js.as_bytes(),
        Limits::default(),
        JsonLimits::default(),
        LINE,
    )
    .expect("the JSON side must decode");
    (wire, text)
}

fn encode_both(value_pb: Vec<u8>, value_json: String) -> (Vec<u8>, String) {
    let pb = common::request(
        &common::service("payments-agent"),
        SCOPE,
        &[common::SpanBuilder::new("chat gpt-4o-mini").attr(KEY, value_pb)],
    );
    // The scope version is empty on both sides: `common::request` writes the
    // scope name only, and the JSON writer omits the member for an empty version
    // rather than writing `""`, which is a different document.
    let js = jsonenc::request(
        &jsonenc::service("payments-agent"),
        SCOPE,
        "",
        &[jsonenc::SpanBuilder::new("chat gpt-4o-mini").attr(KEY, value_json)],
    );
    (pb, js)
}

/// The value of the one attribute the sweep writes.
fn only_attr(decoded: &Decoded) -> &Value {
    decoded.request.resource_spans[0].scopes[0].spans[0]
        .attr(KEY)
        .expect("the attribute must have arrived")
}
