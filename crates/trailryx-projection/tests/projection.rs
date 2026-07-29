//! What a projection is, and what it must never become.

mod common;

use common::segment;
use trailryx_projection::{project, project_columns};

#[test]
fn a_projection_is_never_evidence() {
    // The single most important line in this crate. A Parquet file is fast,
    // convenient and shaped exactly like the records it came from, and treating
    // it as proof would retire the only thing this store sells.
    let s = segment();
    let p = project(&[&s]).unwrap();
    assert!(!p.provable());
    assert!(p.why_not_provable().contains("ask the segment"));
}

#[test]
fn the_same_segments_always_give_the_same_bytes() {
    // "Delete it and rebuild it" is only safe if the rebuild is identical.
    let s = segment();
    let a = project(&[&s]).unwrap();
    let b = project(&[&s]).unwrap();
    assert_eq!(a.bytes(), b.bytes());

    // And rebuilt from a freshly sealed copy of the same records, not just from
    // the same object in memory.
    let c = project(&[&segment()]).unwrap();
    assert_eq!(a.bytes(), c.bytes());
}

#[test]
fn every_row_carries_its_chain_link() {
    // Without it a projection row connects to nothing and cannot be checked
    // against the journal it claims to summarise.
    let s = segment();
    let columns = project_columns(&[&s]);
    let links = columns.iter().find(|c| c.name == "chain_link").unwrap();
    let real: Vec<String> = s.links().iter().map(|l| l.to_hex()).collect();
    for (i, expected) in real.iter().enumerate() {
        assert_eq!(links.values.cell(i).as_ref(), Some(expected));
    }
}

#[test]
fn no_column_can_hold_a_sentence() {
    // The rule that keeps a projection erasable. It lands in object storage,
    // gets copied into a lake, gets backed up: exactly the surface a key
    // destruction cannot reach. So every string in it is a validated token, an
    // enum name, a hash or a comma-joined list of those, and a value with a
    // space or a capital in it means somebody added a column that can carry
    // content.
    let s = segment();
    let columns = project_columns(&[&s]);
    for column in &columns {
        for i in 0..s.records().len() {
            let Some(value) = column.values.cell(i) else {
                continue;
            };
            if column.name.ends_with("_nanos")
                || column.name.ends_with("_micros")
                || matches!(
                    column.name.as_str(),
                    "shard"
                        | "seq"
                        | "segment_id"
                        | "max_tokens"
                        | "temperature_milli"
                        | "mapper_version"
                        | "payload_size_bytes"
                        | "tokens_in"
                        | "tokens_out"
                )
            {
                continue;
            }
            assert!(
                value.chars().all(|c| {
                    c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || matches!(c, '.' | '_' | '-' | '/' | ':' | ',')
                }),
                "column {} row {i} holds {value:?}, which is not a token",
                column.name
            );
        }
    }
}

#[test]
fn the_payload_is_referenced_and_never_carried() {
    let s = segment();
    let columns = project_columns(&[&s]);
    let names: Vec<&str> = columns.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"payload_hash"));
    assert!(names.contains(&"payload_key_id"));
    assert!(
        !names
            .iter()
            .any(|n| n.contains("payload_bytes") || *n == "payload"),
        "{names:?}"
    );
}

#[test]
fn an_absent_optional_field_is_a_null_rather_than_a_zero() {
    // Row two has every optional field empty. A zero there would read as a
    // fact: a budget of nothing, a latency of nothing.
    let s = segment();
    let columns = project_columns(&[&s]);
    for name in [
        "model",
        "budget_remaining_micros",
        "payload_hash",
        "verdict",
    ] {
        let column = columns.iter().find(|c| c.name == name).unwrap();
        assert!(column.optional, "{name} should be nullable");
        assert!(column.values.cell(0).is_some(), "{name} row 0");
        assert!(
            column.values.cell(1).is_none(),
            "{name} row 1 should be null"
        );
    }
}

#[test]
fn a_repeated_field_joins_on_a_separator_its_values_cannot_contain() {
    let s = segment();
    let columns = project_columns(&[&s]);
    let tools = columns.iter().find(|c| c.name == "tool_manifest").unwrap();
    assert_eq!(
        tools.values.cell(0),
        Some("lookup_balance,send_email".to_owned())
    );
    assert_eq!(
        tools.values.cell(1),
        None,
        "an empty list is absent, not empty"
    );
}
