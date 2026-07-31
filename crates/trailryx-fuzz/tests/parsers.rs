//! The suite: every parser in the workspace that reads bytes somebody else wrote.
//!
//! A parser here is not a convenience. Each one is a place where the process takes
//! input from outside its own trust boundary: an agent's telemetry, a timestamp
//! authority's answer, an object fetched from a bucket, a pack handed to a verifier.
//! Somebody who wants this store to lose records will send it bytes, and the first
//! thing those bytes reach is one of these functions.
//!
//! The property is the same for every one of them and deliberately weak: **whatever
//! the input, return.** No panic, no hang. A parser that refuses everything would
//! pass this suite and fail the oracle tests, which is the right division of labour.

use trailryx_fuzz::{Report, Target, run};
use trailryx_record::{
    AgentId, Algorithms, Basis, EventType, Hash, MapperVersion, Outcome, Record, RecordId, RunId,
    SegmentId, Severity, ShardIx, TenantId, Timestamp, Untrusted,
};

/// A real record, so the corpus for the wire format is something the wire format
/// accepts. Five targets started out with corpora made of zero bytes, and the
/// acceptance counter caught it: they were exercising the first rejection and
/// nothing else.
fn record() -> Record {
    Record {
        id: RecordId(1),
        tenant: TenantId::parse("acme").expect("a tenant"),
        shard: ShardIx(0),
        agent_id: AgentId::parse("agent://acme.example/support").expect("an agent"),
        run_id: RunId::parse("run-1").expect("a run"),
        parent_run_id: None,
        on_behalf_of: Vec::new(),
        occurred_at: Untrusted::new(Timestamp(1_000)),
        decided_at: None,
        recorded_at: Timestamp(1_000),
        knowledge_as_of: None,
        clock_skew_nanos: None,
        event_type: EventType::ModelCall,
        severity: Severity::Info,
        basis: Basis::default(),
        caused_by: Vec::new(),
        outcome: Outcome::default(),
        payload: None,
        seq: 0,
        prev_hash: Hash::ZERO,
        segment_id: SegmentId(1),
        algorithms: Algorithms::default(),
        mapper: MapperVersion(1),
    }
}

fn manifest() -> trailryx_index::SegmentManifest {
    use trailryx_index::completeness::Dimension;
    trailryx_index::SegmentManifest {
        format_version: 1,
        segment: SegmentId(1),
        shard: ShardIx(0),
        records: 2,
        history_root: Hash([7u8; 48]),
        index_roots: Dimension::ALL
            .iter()
            .map(|d| (*d, Hash([9u8; 48])))
            .collect(),
        chain_before: Hash::ZERO,
        chain_after: Hash([2u8; 48]),
        first_recorded_at: Timestamp(1),
        last_recorded_at: Timestamp(9),
        algorithms: Algorithms::default(),
    }
}

/// Enough cases to be worth running in the gate on every push. The long run is the
/// same suite with a bigger number, which is what `TRAILRYX_FUZZ_CASES` is for.
fn cases() -> u64 {
    std::env::var("TRAILRYX_FUZZ_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

fn targets() -> Vec<Target> {
    vec![
        Target {
            name: "json::validate",
            corpus: vec![
                br#"{"a":1,"b":[true,null,"x"],"c":{"d":1.5e3}}"#.to_vec(),
                br#"[1,2,3]"#.to_vec(),
                br#""a string with A escapes""#.to_vec(),
            ],
            run: |bytes| {
                trailryx_json::validate(bytes, trailryx_json::Limits::default(), 1).is_ok()
            },
        },
        Target {
            name: "json::Framer",
            corpus: vec![b"{\"a\":1}\n{\"b\":2}\n".to_vec(), b"{}\n".to_vec()],
            run: |bytes| {
                let mut framer = trailryx_json::Framer::new(trailryx_json::Limits::default());
                framer.push(bytes, |_line| Ok(())).is_ok()
            },
        },
        Target {
            name: "otlp::decode_trace_request",
            corpus: vec![Vec::new(), vec![0x0a, 0x02, 0x08, 0x01], vec![0x0a, 0x00]],
            run: |bytes| {
                trailryx_otlp::otlp::decode_trace_request(
                    bytes,
                    trailryx_otlp::otlp::Limits::default(),
                )
                .is_ok()
            },
        },
        Target {
            name: "asn1::Reader",
            corpus: vec![
                vec![0x30, 0x03, 0x02, 0x01, 0x2a],
                vec![0x02, 0x01, 0x01],
                vec![0x30, 0x80],
            ],
            run: |bytes| {
                let mut der = trailryx_asn1::Der::new(bytes);
                // Walked the way a real caller does, until it refuses.
                let mut any = false;
                while der.take_any().is_ok() {
                    any = true;
                }
                any
            },
        },
        Target {
            name: "verify::tsp::read",
            corpus: vec![der_token()],
            run: |bytes| trailryx_verify::tsp::read(bytes).is_ok(),
        },
        Target {
            name: "http::parse_response",
            corpus: vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec(),
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
                    .to_vec(),
                b"HTTP/1.1 404 Not Found\r\n\r\n".to_vec(),
            ],
            run: |bytes| trailryx_http::parse_response(bytes, 1 << 16).is_ok(),
        },
        Target {
            name: "journal::wire::decode_record",
            corpus: vec![trailryx_journal::wire::encode_record(&record())],
            run: |bytes| trailryx_journal::wire::decode_record(bytes).is_ok(),
        },
        Target {
            name: "store::cold::decode_body",
            corpus: vec![
                trailryx_store::cold::encode_body(&[b"one".to_vec(), b"two".to_vec()]),
                trailryx_store::cold::encode_body(&[]),
            ],
            run: |bytes| trailryx_store::cold::decode_body(bytes).is_ok(),
        },
        Target {
            name: "store::cold::decode_envelope",
            corpus: vec![trailryx_store::cold::encode_envelope(
                &Hash([3u8; 48]),
                &manifest(),
            )],
            run: |bytes| trailryx_store::cold::decode_envelope(bytes).is_ok(),
        },
        Target {
            name: "store::evidence::decode_manifest",
            corpus: vec![trailryx_store::evidence::encode_manifest(&manifest())],
            run: |bytes| trailryx_store::evidence::decode_manifest(bytes).is_some(),
        },
        Target {
            name: "verify::Pack",
            corpus: vec![b"TRAILRYX".to_vec(), vec![0; 64]],
            run: |bytes| trailryx_verify::Pack::parse(bytes).is_ok(),
        },
        Target {
            name: "azure::base64_decode",
            corpus: vec![b"Zm9vYmFy".to_vec(), b"Zm8=".to_vec(), b"====".to_vec()],
            run: |bytes| {
                std::str::from_utf8(bytes)
                    .ok()
                    .and_then(trailryx_azure::sharedkey::base64_decode)
                    .is_some()
            },
        },
        Target {
            name: "s3::xml",
            corpus: vec![
                b"<ListBucketResult><Contents><Key>a</Key></Contents></ListBucketResult>".to_vec(),
                b"<Error><Code>NoSuchKey</Code></Error>".to_vec(),
            ],
            run: |bytes| {
                let Ok(text) = std::str::from_utf8(bytes) else {
                    return false;
                };
                let mut found = trailryx_s3::xml::text_of(text, "Key").is_some();
                for block in trailryx_s3::xml::blocks(text, "Contents") {
                    found |= trailryx_s3::xml::text_of(block, "Key").is_some();
                }
                found
            },
        },
    ]
}

/// The suite, at the size the gate runs it.
///
/// A failure prints the seed and the case, so reproducing it is a command rather
/// than an archaeology exercise.
#[test]
fn no_parser_panics_on_anything() {
    let report: Report = run(&targets(), 20260731, cases());
    assert!(
        report.failures.is_empty(),
        "{} of {} cases panicked:\n{}",
        report.failures.len(),
        report.cases,
        report
            .failures
            .iter()
            .map(|f| format!("  {}", f.reproduce()))
            .collect::<Vec<_>>()
            .join("\n")
    );
    // A suite that ran nothing passes vacuously, which is the failure mode of every
    // test harness that stops finding its own inputs.
    assert!(report.targets >= 13, "targets: {}", report.targets);
    assert!(report.cases >= 13 * 300, "cases: {}", report.cases);

    // The measurement that keeps this suite honest. Random bytes die at byte one,
    // so if nothing is accepted anywhere, the mutations are not reaching past the
    // first check and the run proves only that a rejection does not panic.
    let reaching: Vec<&(&str, u64)> = report.accepted.iter().filter(|(_, n)| *n > 0).collect();
    println!("accepted per target: {:?}", report.accepted);
    // Eleven of the thirteen reach past the first check. The two that do not are
    // `verify::tsp::read` and `verify::Pack`, whose valid inputs are a real CMS
    // token and a real evidence pack: one needs an authority and the other needs
    // the trees that only exist at sealing time. Both are exercised for their
    // rejection path, which is worth something and is not the same thing, and this
    // number is here so that fact stays visible rather than being discovered later.
    assert!(
        reaching.len() >= 11,
        "only {} of {} targets ever accepted an input, so this suite is testing \
         first rejections rather than parsers: {:?}",
        reaching.len(),
        report.targets,
        report.accepted
    );
}

/// A second seed, because one seed is one path through the generator and the point
/// of seeding is that another is a different path rather than a different day.
#[test]
fn a_second_seed_finds_nothing_either() {
    let report = run(&targets(), 7, cases() / 2);
    assert!(
        report.failures.is_empty(),
        "{}",
        report
            .failures
            .iter()
            .map(Failure::reproduce)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

use trailryx_fuzz::Failure;

/// A DER structure shaped like a timestamp token: nested sequences, an integer, an
/// octet string. Not a token any authority would issue, and that is the point: it
/// has to be valid enough that the reader walks into it rather than refusing at the
/// first tag, which is where the interesting failures live.
fn der_token() -> Vec<u8> {
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() < 128 {
            out.push(contents.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(contents);
        out
    }
    let imprint = tlv(0x04, &[7u8; 48]);
    let algorithm = tlv(
        0x30,
        &tlv(
            0x06,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
        ),
    );
    let message = tlv(0x30, &[algorithm.clone(), imprint].concat());
    let info = tlv(
        0x30,
        &[
            tlv(0x02, &[1]),
            tlv(0x06, &[0x2a, 0x03]),
            message,
            tlv(0x02, &[42]),
            tlv(0x18, b"20260731120000Z"),
        ]
        .concat(),
    );
    tlv(0x30, &[tlv(0x06, &[0x2a, 0x04]), tlv(0xa0, &info)].concat())
}
