//! OTLP ingest, and the mapper from OpenTelemetry GenAI semantics to records.
//!
//! This is the first crate that reads bytes written by somebody else. Every
//! other crate in the store consumes data it produced itself, under invariants
//! it enforced. Here the input is chosen by whoever is talking to us, and the
//! whole crate is arranged around that difference:
//!
//! - [`protobuf`] is a wire reader with a depth limit, because a small message
//!   can describe a structure deep enough to overflow the stack, and a stack
//!   overflow in Rust aborts the process;
//! - [`otlp`] bounds every repeated field, because each one is a length chosen
//!   by the sender;
//! - [`semconv`] puts anything it does not recognise into the encrypted plane,
//!   because unrecognised OpenTelemetry attributes routinely contain prompts;
//! - [`source`] never fails a batch, and never loses one quietly either.
//!
//! # The point of the exercise
//!
//! An agent instrumented with a stock OpenTelemetry SDK writes here with no
//! change to it. That is worth a great deal and it is not the whole product: a
//! span carries what happened, not the grounds on which it was allowed to
//! happen. See [`semconv`] for exactly which fields stay empty and why.
//!
//! # Zero dependencies, here too
//!
//! Protobuf is decoded by hand. That is more work than adding a crate and it
//! buys the same thing the rest of the core buys: the parser at the trust
//! boundary is one we can read end to end, its limits are ours to choose, and
//! there is no build-time code generation between the specification and what
//! actually runs.

pub mod otlp;
pub mod protobuf;
pub mod semconv;
pub mod source;

pub use otlp::{Limits, Span, TraceRequest, Value, decode_trace_request};
pub use protobuf::{Reader, Stats, WireError};
pub use semconv::{MAPPER_VERSION, MapperConfig, Rejection, Report, map_span};
pub use source::{OtlpSource, WireReport};
