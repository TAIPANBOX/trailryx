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
use trailryx_record::{RECORD_V1, RECORD_V2, Schema};

fn artifact_path() -> PathBuf {
    path_for(&RECORD_V1)
}

/// Where a schema's published artifact lives, named by the version it IS.
fn path_for(schema: &Schema) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("schema")
        .join(format!("record.v{}.json", schema.version))
}

/// v1's artifact must not move, ever.
///
/// This is the whole claim the migration rests on: v1 is a PREFIX of v2, so
/// every record already on disk is described by exactly the fields it was
/// written under. Insert a field above the v2 block and this goes red, which
/// is the point of it being a separate test from v2's.
#[test]
fn the_v1_artifact_is_frozen_and_did_not_move() {
    let want = RECORD_V1.to_json();
    let path = path_for(&RECORD_V1);
    let got = std::fs::read_to_string(&path).expect("v1 artifact present");
    assert_eq!(
        got, want,
        "v1's published schema changed. Records already on disk were written \
         under it, so it describes history and history does not move. If a \
         field was added, it belongs at the END, after the v2 block."
    );
}

#[test]
fn committed_v2_schema_matches_the_types() {
    let want = RECORD_V2.to_json();
    let path = path_for(&RECORD_V2);
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
    assert_eq!(got, want, "v2's published schema disagrees with the types");
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
