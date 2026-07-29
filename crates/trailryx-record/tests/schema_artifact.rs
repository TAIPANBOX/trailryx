//! The schema is also a committed artifact.
//!
//! Emitting it from the types is convenient; committing the result is what makes
//! a schema change **visible in a diff**. A record format that can drift without
//! anyone noticing is a record format nobody can vouch for later.
//!
//! Regenerate deliberately:
//!
//! ```text
//! UPDATE_SCHEMA=1 cargo test -p trailryx-record --test schema_artifact
//! ```

use std::path::PathBuf;
use trailryx_record::RECORD_V1;

fn artifact_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("schema")
        .join("record.v1.json")
}

#[test]
fn committed_schema_matches_the_types() {
    let want = RECORD_V1.to_json();
    let path = artifact_path();

    if std::env::var_os("UPDATE_SCHEMA").is_some() {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, &want).expect("write schema");
        return;
    }

    let got = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}\nrun: UPDATE_SCHEMA=1 cargo test -p trailryx-record",
            path.display()
        )
    });

    assert_eq!(
        got, want,
        "the committed schema no longer matches the types.\n\
         If the change is intended, regenerate it so the diff is reviewable:\n  \
         UPDATE_SCHEMA=1 cargo test -p trailryx-record --test schema_artifact"
    );
}

#[test]
fn the_artifact_states_the_boundary_for_a_reader() {
    // An auditor reading the JSON should be able to see the rule without
    // reading Rust.
    let j = std::fs::read_to_string(artifact_path()).expect("schema present");
    assert!(j.contains("Metadata plane holds typed fields only"));
    assert!(j.contains("\"x-plane\": \"payload\""));
    assert!(j.contains("\"x-provable-dimensions\""));
}
