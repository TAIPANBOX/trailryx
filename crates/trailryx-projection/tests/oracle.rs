//! The check that the file really is Parquet.
//!
//! Everything else in this crate compares our writer against our own idea of
//! what it should produce, which is worth something and is not worth what this
//! is worth. Here the file goes to pyarrow, a reader written by other people,
//! and every cell comes back and is compared.
//!
//! It needs a Python with pyarrow, which not every machine has, so the test
//! reads a path from `TRAILRYX_PARQUET_ORACLE` and reports that it was skipped
//! when there is none. A skipped check that says so is honest; one that quietly
//! passes is the thing this whole project is against.
//!
//! ```text
//! python3 -m venv /tmp/oracle && /tmp/oracle/bin/pip install pyarrow
//! TRAILRYX_PARQUET_ORACLE=/tmp/oracle/bin/python cargo test -p trailryx-projection
//! ```

mod common;

use common::segment;
use std::process::Command;
use trailryx_projection::parquet::{Column, Values};
use trailryx_projection::{project, project_columns};

const NULL: &str = "\\0NULL";
/// A list cell is marked, so the oracle can insist the reader hands back a list
/// rather than a string that happens to render the same.
const LIST: &str = "\\0LIST";

#[test]
fn somebody_elses_reader_agrees_with_every_cell() {
    let Ok(python) = std::env::var("TRAILRYX_PARQUET_ORACLE") else {
        println!(
            "skipped: set TRAILRYX_PARQUET_ORACLE to a python with pyarrow to check the file \
             against a reader we did not write"
        );
        return;
    };

    let s = segment();
    let projection = project(&[&s]).unwrap();
    let columns = project_columns(&[&s]);

    let dir = std::env::temp_dir().join(format!("trailryx-oracle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let parquet = dir.join("projection.parquet");
    let expected = dir.join("expected.tsv");
    std::fs::write(&parquet, projection.bytes()).unwrap();

    let mut table = String::new();
    for column in &columns {
        for row in 0..projection.rows() {
            let cell = match column.values.cell(row) {
                Some(rendered) if column.values.is_list_column() => format!("{LIST}{rendered}"),
                Some(rendered) => rendered,
                None => NULL.to_owned(),
            };
            table.push_str(&format!("{}\t{row}\t{cell}\n", column.name));
        }
    }
    std::fs::write(&expected, table).unwrap();

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oracle.py");
    let output = Command::new(python)
        .arg(script)
        .arg(&parquet)
        .arg(&expected)
        .output()
        .expect("the oracle should run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "pyarrow disagreed with the writer:\n{stdout}\n{stderr}"
    );
    println!("{stdout}");
    // The sibling test below always wiped its directory and this one never did, which
    // cost one stale directory while the path was a constant. With a process id in it,
    // it costs one on every run, so the two now behave the same way.
    let _ = std::fs::remove_dir_all(&dir);
}

/// The encoding hazard that lists exist to get wrong, put to an outside reader.
///
/// An empty list writes a level pair and **no value**. Get that wrong and every
/// later row's values shift by one, which produces a file that parses cleanly and
/// says something else. The pattern below is chosen so a shift of one cannot look
/// right anywhere: empty lists at the start, in the middle and at the end, next to
/// lists of one, two and three elements, with a scalar column beside them whose
/// values would visibly misalign.
#[test]
fn pyarrow_agrees_about_lists_with_empties_at_every_position() {
    let Ok(python) = std::env::var("TRAILRYX_PARQUET_ORACLE") else {
        println!("skipped: TRAILRYX_PARQUET_ORACLE is not set, so no outside reader saw the lists");
        return;
    };

    let lists: Vec<Vec<String>> = vec![
        vec![],
        vec!["a".into()],
        vec![],
        vec!["b".into(), "c".into()],
        vec!["d".into(), "e".into(), "f".into()],
        vec![],
        vec!["g".into()],
        vec![],
    ];
    let rows = lists.len();
    let columns = vec![
        Column::required(
            "n",
            Values::Int64((0..rows).map(|i| Some(i as i64 * 100)).collect()),
        ),
        Column::required("items", Values::StringList(lists.clone())),
        // A second list column after the first, because a mistake in the first
        // column's value count can also corrupt the offsets of the next one.
        Column::required(
            "again",
            Values::StringList(lists.iter().rev().cloned().collect()),
        ),
        Column::optional(
            "tail",
            Values::String((0..rows).map(|i| Some(format!("row-{i}"))).collect()),
        ),
    ];

    let bytes = trailryx_projection::parquet::write(&columns).expect("the file writes");
    let dir = std::env::temp_dir().join(format!("trailryx-oracle-lists-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let parquet = dir.join("lists.parquet");
    let expected = dir.join("expected.tsv");
    std::fs::write(&parquet, &bytes).unwrap();

    let mut table = String::new();
    for column in &columns {
        for row in 0..rows {
            let cell = match column.values.cell(row) {
                Some(rendered) if column.values.is_list_column() => format!("{LIST}{rendered}"),
                Some(rendered) => rendered,
                None => NULL.to_owned(),
            };
            table.push_str(&format!("{}\t{row}\t{cell}\n", column.name));
        }
    }
    std::fs::write(&expected, table).unwrap();

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oracle.py");
    let output = Command::new(python)
        .arg(script)
        .arg(&parquet)
        .arg(&expected)
        .output()
        .expect("the oracle should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "pyarrow disagreed about a list with empties:\n{stdout}\n{stderr}"
    );
    println!("{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}
