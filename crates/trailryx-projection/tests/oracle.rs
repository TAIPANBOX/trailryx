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
use trailryx_projection::{project, project_columns};

const NULL: &str = "\\0NULL";

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

    let dir = std::env::temp_dir().join("trailryx-oracle");
    std::fs::create_dir_all(&dir).unwrap();
    let parquet = dir.join("projection.parquet");
    let expected = dir.join("expected.tsv");
    std::fs::write(&parquet, projection.bytes()).unwrap();

    let mut table = String::new();
    for column in &columns {
        for row in 0..projection.rows() {
            let cell = column.values.cell(row).unwrap_or_else(|| NULL.to_owned());
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
}
