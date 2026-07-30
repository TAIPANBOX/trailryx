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
//! - [`otlpjson`] reads the same messages out of OTLP/JSON, and declines to
//!   half-read the dialects that only look like it;
//! - [`semconv`] puts anything it does not recognise into the encrypted plane,
//!   because unrecognised OpenTelemetry attributes routinely contain prompts;
//! - [`source`] never fails a batch, and never loses one quietly either;
//! - [`jsonl`] reads a file of those lines rather than a socket, and keeps the
//!   two things a file has and a socket does not: a partial last line, which is
//!   not corruption, and an age, which is why skew is only assessed on a live
//!   one.
//!
//! # The point of the exercise
//!
//! An agent instrumented with a stock OpenTelemetry SDK writes here with no
//! change to it. That is worth a great deal and it is not the whole product: a
//! span carries what happened, not the grounds on which it was allowed to
//! happen. See [`semconv`] for exactly which fields stay empty and why.
//!
//! # Two transports and one mapper
//!
//! There are now two readers and there is still one meaning. [`otlp`] decodes
//! the protobuf encoding, [`otlpjson`] decodes OTLP/JSON, and both hand back the
//! same [`otlp::TraceRequest`]. Nothing downstream of that type can tell which
//! content type the emitter was configured for.
//!
//! That is the design and it is not tidiness. [`semconv`] is where the
//! judgements live: which attributes are payload and which are metadata, what a
//! missing parent does to `event_type`, which spans are refused outright. A
//! second copy of those judgements behind the JSON reader would drift from the
//! first, and two stores would then describe the same run differently because
//! one collector was sending `application/json` and the other
//! `application/x-protobuf`. Mapping is hard and worth doing once; decoding is
//! mechanical and worth doing twice.
//!
//! `tests/differential.rs` is what holds the claim up: one fixture, two
//! independent encoders, and an assertion that the two decoders return equal
//! structs. It also pins the two depth limits against each other, because
//! `trailryx_json::Limits::max_depth` and [`protobuf::MAX_DEPTH`] are different
//! numbers that have to admit exactly the same nesting.
//!
//! # Zero dependencies, here too
//!
//! Protobuf is decoded by hand. That is more work than adding a crate and it
//! buys the same thing the rest of the core buys: the parser at the trust
//! boundary is one we can read end to end, its limits are ours to choose, and
//! there is no build-time code generation between the specification and what
//! actually runs.
//!
//! JSON is read through [`trailryx_json`], which is a crate in this tree that
//! itself depends on nothing, so the same claim survives: still no third-party
//! code between a stranger's bytes and a record. It is a dependency and not a
//! copy on purpose, because a bound raised for JSON Lines ingest has to be the
//! same bound OTLP/JSON gets.

pub mod jsonl;
pub mod otlp;
pub mod otlpjson;
pub mod protobuf;
pub mod semconv;
pub mod source;

pub use jsonl::{Class, Counter, Counters, JsonlSource, LineReport, Mode};
pub use otlp::{Limits, Span, TraceRequest, Value, decode_trace_request};
pub use otlpjson::{Decoded, ShapeReport, decode_traces_data};
pub use protobuf::{Reader, Stats, WireError};
pub use semconv::{MAPPER_VERSION, MapperConfig, Rejection, Report, map_span};
pub use source::{OtlpSource, WireReport};
