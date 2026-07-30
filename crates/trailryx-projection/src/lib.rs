//! Columnar projections of the journal.
//!
//! Stage 9 exists because stage 10 needs it: a SQL engine wants columns, and
//! the journal is a chain of records. What matters is the relationship between
//! the two, and it is asymmetric in a way that is easy to lose.
//!
//! The journal is the truth and can prove it. A projection is a **copy in a
//! convenient shape**: rebuildable, disposable, and never evidence. Every
//! answer computed from one comes back without a completeness proof, and
//! [`Projection::provable`] returns false as a method rather than as a note in
//! a document.
//!
//! # Zero dependencies, including for Parquet
//!
//! [`parquet`] is a restricted writer: PLAIN encoding, no compression, one row
//! group, data pages of version one. Hand-writing it would be a poor trade if
//! the result were only Parquet-shaped, so correctness is delegated to somebody
//! else's reader: the test suite writes a file and has pyarrow read every value
//! back. See `tests/oracle.rs` for how to run it.

pub mod parquet;
pub mod projection;
pub mod thrift;

pub use parquet::{Column, ColumnType, Values, WriteError};
pub use projection::{Projection, SCHEMA_VERSION, columns_from_records, project, project_columns};
