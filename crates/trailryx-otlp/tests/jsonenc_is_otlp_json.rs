//! Oracle 6: the fixture really is OTLP/JSON, according to something else.
//!
//! Every other check on the JSON side compares our writer against our own idea
//! of the encoding, which cannot catch the failure that matters: a fixture that
//! drifts out of the specification and takes the decoder written against it
//! along. So the document goes to a JSON parser nobody here wrote, and the
//! properties that make it OTLP/JSON rather than merely valid JSON are asserted
//! one at a time:
//!
//! - it parses at all;
//! - every member name is lowerCamelCase and one the encoding defines, because
//!   `trace_id` would parse perfectly and be ignored by every real collector;
//! - trace and span ids are hex of exactly 32 and 16 characters, not base64,
//!   which is the one place OTLP overrides proto3's mapping for `bytes`. The
//!   check insists on lowercase because that is what this writer emits, not
//!   because the wire format requires it: the encoding is case-insensitive and a
//!   decoder has to accept either;
//! - a `bytesValue` is standard base64 and survives a round trip through an
//!   implementation that is not ours;
//! - no object names the same member twice, which a hand-rolled writer with a
//!   copy-pasted push would do and no compiler would notice;
//! - enums are integers;
//! - no byte below 0x20 appears raw, and the characters that had to be escaped
//!   come back out of the parser unchanged.
//!
//! It needs a `python3` on the path and nothing else: the standard library's
//! `json` and `base64` are the whole dependency. A machine without one loses the
//! check and says so, which is the same bargain `trailryx-projection`'s pyarrow
//! oracle makes. Override the interpreter with `TRAILRYX_PYTHON`.
//!
//! Nothing here reads the document back with our own JSON decoder, and that is
//! deliberate rather than pending: an oracle that used the code under test would
//! be checking it against itself. `tests/differential.rs` is where the two
//! decoders are compared. The last test below reads the fixture's *protobuf* twin
//! back instead, which writes down what the fixture means field by field, so the
//! JSON decoder meets a stated expectation rather than whichever structure it
//! happens to produce.

mod common;

use common::{jsonenc, spec};
use std::io::ErrorKind;
use std::process::Command;
use trailryx_otlp::{Limits, Value, decode_trace_request};

/// The checks, dispatched by name so each Rust test asserts one property and
/// fails with the message for that property alone.
const ORACLE: &str = r#"
import base64, json, re, sys

compact_path, pretty_path, check = sys.argv[1], sys.argv[2], sys.argv[3]
with open(compact_path, encoding="utf-8") as f:
    compact = f.read()
with open(pretty_path, encoding="utf-8") as f:
    pretty = f.read()

# Every member name the OTLP/JSON encoding of a trace request is allowed to use.
# A name that is not here is either snake_case, which is the mistake this oracle
# exists to catch, or something the fixture invented.
ALLOWED = {
    "resourceSpans", "resource", "scopeSpans", "scope", "spans", "schemaUrl",
    "name", "version", "attributes", "droppedAttributesCount",
    "key", "value",
    "stringValue", "boolValue", "intValue", "doubleValue", "bytesValue",
    "arrayValue", "kvlistValue", "values",
    "traceId", "spanId", "parentSpanId", "traceState", "flags",
    "kind", "startTimeUnixNano", "endTimeUnixNano", "timeUnixNano",
    "events", "droppedEventsCount", "links", "droppedLinksCount",
    "status", "code", "message",
}

def fail(why):
    print("FAIL: " + why)
    sys.exit(1)

def parse(text, where):
    def pairs(items):
        seen = set()
        for key, _ in items:
            if key in seen:
                fail("%s names the member %r twice in one object" % (where, key))
            seen.add(key)
        return dict(items)
    try:
        return json.loads(text, object_pairs_hook=pairs)
    except ValueError as e:
        fail("%s is not JSON: %s" % (where, e))

def walk(node, path="$"):
    if isinstance(node, dict):
        for key, value in node.items():
            yield (path, key, value)
            yield from walk(value, path + "." + key)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from walk(value, "%s[%d]" % (path, i))

doc = parse(compact, "the document")
try:
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
except (KeyError, IndexError, TypeError) as e:
    fail("the envelope is not resourceSpans/scopeSpans/spans: %s" % e)

if check == "parses":
    if not isinstance(spans, list) or not spans:
        fail("no spans came back")
    print("ok: parsed, %d bytes, %d spans" % (len(compact.encode("utf-8")), len(spans)))

elif check == "members":
    names = set()
    for path, key, _ in walk(doc):
        if not re.fullmatch(r"[a-z][A-Za-z0-9]*", key):
            fail("member %r at %s is not lowerCamelCase" % (key, path))
        if key not in ALLOWED:
            fail("member %r at %s is not a name the encoding defines" % (key, path))
        names.add(key)
    # The members the fixture is meant to exercise. A fixture that quietly lost
    # one of these would still pass every check above.
    required = {
        "resourceSpans", "resource", "scopeSpans", "scope", "spans", "version",
        "traceId", "spanId", "parentSpanId", "name", "kind",
        "startTimeUnixNano", "endTimeUnixNano", "attributes",
        "droppedAttributesCount", "status", "code", "message",
        "events", "timeUnixNano", "key", "value",
        "stringValue", "intValue", "doubleValue", "boolValue", "bytesValue",
        "arrayValue", "kvlistValue", "values",
    }
    missing = sorted(required - names)
    if missing:
        fail("the fixture no longer exercises: %s" % ", ".join(missing))
    print("ok: %d distinct member names, all defined" % len(names))

elif check == "ids":
    seen = 0
    for path, key, value in walk(doc):
        if key not in ("traceId", "spanId", "parentSpanId"):
            continue
        want = 32 if key == "traceId" else 16
        if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{%d}" % want, value):
            fail("%s at %s is not %d lowercase hex characters: %r"
                 % (key, path, want, value))
        seen += 1
    if seen < 7:
        fail("only %d ids found, so the fixture stopped covering them" % seen)
    parents = [v for _, k, v in walk(doc) if k == "parentSpanId"]
    if "0" * 16 not in parents:
        fail("no all-zero parentSpanId, which is the invalid id emitters do send")
    print("ok: %d ids, hex, right lengths" % seen)

elif check == "base64":
    seen = 0
    for path, key, value in walk(doc):
        if key != "bytesValue":
            continue
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
            fail("bytesValue at %s is not standard base64: %r" % (path, value))
        raw = base64.b64decode(value, validate=True)
        if base64.b64encode(raw).decode("ascii") != value:
            fail("bytesValue at %s does not round trip" % path)
        seen += 1
    if seen == 0:
        fail("no bytesValue in the fixture, so base64 is untested")
    print("ok: %d bytesValue, standard base64, round tripped" % seen)

elif check == "duplicates":
    # `parse` already refuses a duplicate member. What is left to prove is that
    # the repeated *attribute key* the fixture carries reached the document: it
    # is a repeated element of an array, which is legal JSON and which a writer
    # that spelled attributes as an object rather than a list would silently
    # collapse into one.
    repeated = False
    for span in spans:
        keys = [a["key"] for a in span.get("attributes", [])]
        if len(keys) != len(set(keys)):
            repeated = True
    if not repeated:
        fail("no span repeats an attribute key, so the case is untested")
    print("ok: no duplicate members, and a repeated attribute key survived")

elif check == "enums":
    for span in spans:
        kind = span["kind"]
        if isinstance(kind, bool) or not isinstance(kind, int):
            fail("kind is %r, not an integer" % (kind,))
        status = span.get("status")
        if status is not None:
            code = status.get("code")
            if isinstance(code, bool) or not isinstance(code, int):
                fail("status.code is %r, not an integer" % (code,))
    print("ok: kind and status.code are integers")

elif check == "escaping":
    raw = re.search(r"[\x00-\x1f]", compact)
    if raw:
        fail("byte 0x%02x appears raw at offset %d" % (ord(raw.group()), raw.start()))
    strings = [v for _, _, v in walk(doc) if isinstance(v, str)]
    for needed, what in [
        ("\t", "a tab"),
        ("\n", "a newline"),
        ("\x7f", "DEL"),
        ("\u2028", "U+2028"),
        ("\U0001d11e", "an astral character"),
        ("\ufffe", "a non-character"),
    ]:
        if not any(needed in s for s in strings):
            fail("no string came back carrying %s" % what)
    # The escaped spelling and the raw spelling have to be the same text. The
    # fixture writes the astral character both ways.
    both = [s for s in strings if "\U0001d11e" in s]
    if len(both) < 2:
        fail("the astral character appears in %d strings, so only one spelling "
             "of it is being tested" % len(both))
    print("ok: nothing raw below 0x20, and every awkward character survived")

elif check == "pretty":
    other = parse(pretty, "the pretty-printed copy")
    if other != doc:
        fail("pretty printing changed the document")
    if "\n" not in pretty:
        fail("pretty printing produced one line")
    print("ok: %d lines, same document" % pretty.count("\n"))

else:
    fail("unknown check %r" % check)
"#;

/// Run one check, or say why it could not run.
///
/// Returns `None` when there is no interpreter, which is the only reason a check
/// is allowed to be skipped. Anything else the interpreter says is a failure.
fn oracle(check: &str) -> Option<String> {
    let json = spec::encode_json(&spec::fixture());
    let dir = std::env::temp_dir().join("trailryx-otlp-json-oracle");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    // Per check and per process, because `cargo test` runs these in parallel and
    // two of them writing one path would race.
    let stem = format!("{check}-{}", std::process::id());
    let compact = dir.join(format!("{stem}.json"));
    let pretty = dir.join(format!("{stem}.pretty.json"));
    std::fs::write(&compact, &json).expect("the fixture should be writable");
    std::fs::write(&pretty, jsonenc::pretty(&json)).expect("the fixture should be writable");

    let python = std::env::var("TRAILRYX_PYTHON").unwrap_or_else(|_| "python3".to_owned());
    let output = match Command::new(&python)
        .arg("-c")
        .arg(ORACLE)
        .arg(&compact)
        .arg(&pretty)
        .arg(check)
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            println!(
                "skipped: no {python} on this machine, so the OTLP/JSON fixture was not \
                 checked against a parser we did not write. Set TRAILRYX_PYTHON to one."
            );
            return None;
        }
        Err(e) => panic!("{python} would not run: {e}"),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the {check} check failed against {}:\n{stdout}\n{stderr}",
        compact.display()
    );
    Some(stdout.into_owned())
}

#[test]
fn the_fixture_parses_in_an_implementation_we_did_not_write() {
    if let Some(out) = oracle("parses") {
        print!("{out}");
    }
}

#[test]
fn every_member_name_is_lowercamelcase_and_one_the_encoding_defines() {
    if let Some(out) = oracle("members") {
        print!("{out}");
    }
}

#[test]
fn trace_and_span_ids_are_lowercase_hex_of_the_length_otlp_fixes() {
    if let Some(out) = oracle("ids") {
        print!("{out}");
    }
}

#[test]
fn a_bytes_value_is_standard_base64_and_round_trips() {
    if let Some(out) = oracle("base64") {
        print!("{out}");
    }
}

#[test]
fn no_object_names_the_same_member_twice() {
    if let Some(out) = oracle("duplicates") {
        print!("{out}");
    }
}

#[test]
fn an_enum_is_an_integer_and_never_its_name() {
    if let Some(out) = oracle("enums") {
        print!("{out}");
    }
}

#[test]
fn every_awkward_character_survives_and_none_of_them_travels_raw() {
    if let Some(out) = oracle("escaping") {
        print!("{out}");
    }
}

#[test]
fn pretty_printing_changes_the_layout_and_nothing_else() {
    if let Some(out) = oracle("pretty") {
        print!("{out}");
    }
}

// The rest are about the writer rather than the document, so they need no
// interpreter: they assert the two legal spellings are both present, which is
// the only reason the fixture is worth feeding to a differential test.

#[test]
fn a_64_bit_integer_is_written_both_as_a_number_and_as_a_decimal_string() {
    let json = spec::encode_json(&spec::fixture());
    // max_tokens quoted, input_tokens bare. A decoder that reads one form and
    // not the other loses a field silently, which is why one fixture carries
    // both rather than two fixtures carrying one each.
    assert!(
        json.contains(r#""intValue":"1024""#),
        "the decimal-string form is missing"
    );
    assert!(
        json.contains(r#""intValue":1204"#),
        "the JSON-number form is missing"
    );
    // And the same for the nanosecond clocks, where the number form is the
    // dangerous one: 1700000000123456789 needs 61 bits and a reader that goes
    // through a double gives back 1700000000123456768.
    assert!(
        json.contains(r#""startTimeUnixNano":"1700000000000000000""#),
        "the quoted clock form is missing"
    );
    assert!(
        json.contains(r#""startTimeUnixNano":1700000000123456789"#),
        "the bare clock form is missing"
    );
}

#[test]
fn a_non_finite_double_is_a_quoted_word_because_json_has_no_literal_for_it() {
    assert_eq!(jsonenc::double(f64::INFINITY), "\"Infinity\"");
    assert_eq!(jsonenc::double(f64::NEG_INFINITY), "\"-Infinity\"");
    assert_eq!(jsonenc::double(f64::NAN), "\"NaN\"");
    // A finite one stays a number, including the ones that tempt a formatter
    // into scientific notation or into dropping the fraction.
    assert_eq!(jsonenc::double(0.2), "0.2");
    assert_eq!(jsonenc::double(-0.0), "-0.0");
    assert_eq!(jsonenc::double(1.0), "1.0");
}

#[test]
fn base64_pads_by_the_length_of_the_input() {
    // The three residues, and the two characters that separate standard base64
    // from the URL-safe alphabet a decoder might assume.
    assert_eq!(jsonenc::base64(b""), "");
    assert_eq!(jsonenc::base64(&[0xff]), "/w==");
    assert_eq!(jsonenc::base64(&[0xff, 0xef]), "/+8=");
    assert_eq!(jsonenc::base64(&[0xff, 0xef, 0xbe]), "/+++");
    assert_eq!(jsonenc::base64(spec::FINGERPRINT), "3q2+7wB//w==");
}

#[test]
fn an_id_is_hex_and_is_never_padded_to_a_length_it_did_not_have() {
    assert_eq!(
        jsonenc::hex(&spec::TRACE_ID),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(jsonenc::hex(&spec::ROOT_SPAN_ID), "00f067aa0ba902b7");
    assert_eq!(jsonenc::hex(&spec::INVALID_PARENT), "0000000000000000");
    // A short id stays short. The decoder's job is to refuse it, and it cannot
    // if the encoder repairs it first.
    assert_eq!(jsonenc::hex(&[0x0a]), "0a");
}

#[test]
fn the_protobuf_twin_of_the_fixture_decodes_into_what_the_fixture_describes() {
    let f = spec::fixture();
    let decoded = decode_trace_request(&spec::encode_protobuf(&f), Limits::default())
        .expect("the fixture's protobuf side should decode");

    assert_eq!(decoded.span_count(), 3);
    let rs = &decoded.resource_spans[0];
    assert_eq!(
        rs.attr("service.name"),
        Some(&Value::Str("payments-agent".to_owned()))
    );
    // Present and empty, which is the case a JSON decoder will meet as `{}`.
    assert_eq!(rs.attr("deployment.environment"), Some(&Value::Empty));

    let scope = &rs.scopes[0];
    assert_eq!(scope.scope_name, f.scope.name);
    assert_eq!(scope.scope_version, f.scope.version);

    let (root, chat, orphan) = (&scope.spans[0], &scope.spans[1], &scope.spans[2]);
    assert!(!root.has_parent());
    assert_eq!(chat.parent_span_id, spec::ROOT_SPAN_ID.to_vec());
    // Eight zero bytes are on the wire and still name no parent.
    assert_eq!(orphan.parent_span_id, spec::INVALID_PARENT.to_vec());
    assert!(!orphan.has_parent());
    assert_eq!(orphan.start_time_unix_nano, 1_700_000_000_123_456_789);

    assert_eq!(
        chat.attr("gen_ai.request.max_tokens"),
        Some(&Value::Int(1024))
    );
    assert_eq!(
        chat.attr("gen_ai.usage.input_tokens"),
        Some(&Value::Int(1_204))
    );
    assert_eq!(
        chat.attr("app.request.fingerprint"),
        Some(&Value::Bytes(spec::FINGERPRINT.to_vec()))
    );
    assert_eq!(
        chat.attr("app.note"),
        Some(&Value::Str(spec::CONTROL_ZOO.to_owned()))
    );
    assert_eq!(chat.attr("app.score"), Some(&Value::Double(f64::INFINITY)));
    // The repeated key arrives twice, in order, and `attr` keeps answering with
    // the first.
    let retries: Vec<&Value> = chat
        .attributes
        .iter()
        .filter(|a| a.key == "app.retry")
        .map(|a| &a.value)
        .collect();
    assert_eq!(retries.len(), 2);
    assert_eq!(retries[0], &Value::Int(1));
    assert_eq!(chat.attr("app.retry"), Some(&Value::Int(1)));

    // Three levels below the attribute, with the escaped text.
    let Some(Value::Array(messages)) = chat.attr("gen_ai.input.messages") else {
        panic!("the messages attribute is not an array");
    };
    let Value::Map(message) = &messages[0] else {
        panic!("a message is not a map");
    };
    let Some(Value::Array(parts)) = message.iter().find(|a| a.key == "parts").map(|a| &a.value)
    else {
        panic!("the parts are not an array");
    };
    let Value::Map(part) = &parts[0] else {
        panic!("a part is not a map");
    };
    assert_eq!(
        part.iter().find(|a| a.key == "content").map(|a| &a.value),
        Some(&Value::Str("Résume la partition \u{1d11e}".to_owned()))
    );

    assert_eq!(chat.events.len(), 1);
    assert_eq!(chat.events[0].attributes.len(), 3);
    assert_eq!(
        chat.status_message,
        "429 Too Many Requests\n\tupstream said: slow down"
    );

    // The one field the fixture writes that this decoder does not model:
    // `dropped_attributes_count`. It is skipped and counted, and a JSON decoder
    // will have to walk past `droppedAttributesCount` for the same reason.
    assert_eq!(decoded.unknown_fields, 1);
    assert_eq!(decoded.padded_varints, 0);
    assert!(!decoded.dropped.any());
}

#[test]
fn the_escaped_and_the_raw_spelling_of_one_string_are_the_same_text() {
    let clef = "clef \u{1d11e}";
    assert_eq!(jsonenc::string(clef), "\"clef \u{1d11e}\"");
    assert_eq!(jsonenc::string_escaped(clef), "\"clef \\ud834\\udd1e\"");
    // Below the BMP there is no pair to get wrong, and above it there is.
    assert_eq!(jsonenc::string_escaped("é"), "\"\\u00e9\"");
    // Control characters are escaped in both spellings, or the document would
    // not be JSON at all.
    assert_eq!(jsonenc::string("a\tb\nc"), "\"a\\tb\\nc\"");
    assert_eq!(jsonenc::string("\u{1}"), "\"\\u0001\"");
    assert_eq!(jsonenc::string("\u{7f}"), "\"\u{7f}\"");
}
