//! Every integration test of `trailryx-otlp`, linked into one binary.
//!
//! Each file under `tests/` used to be a test target of its own, and each one
//! linked the whole dependency tree again. One binary per crate is what
//! `scripts/one-test-binary-per-crate.sh` holds. A module here is what a
//! file was, with its tests under the same names, so a run of one file is
//! `cargo test -p trailryx-otlp --test it <module>::`.

mod common;

mod differential;
mod hostile;
mod hostile_jsonl;
mod jsonenc_is_otlp_json;
mod jsonl;
mod mapping;
mod planes;
mod shapes;
