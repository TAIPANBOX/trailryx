//! The OTLP/HTTP ingest server.
//!
//! An agent instrumented with a stock OpenTelemetry SDK, or a collector
//! forwarding on its behalf, posts to this and the records land in the store.
//! Everything above this crate consumed data it had produced itself under
//! invariants it enforced. This is where a stranger chooses the bytes.
//!
//! # What it is not, and will not become
//!
//! Said here rather than left to be inferred, because the first item is the one
//! that matters:
//!
//! - **No TLS.** The standard library has none and adding one is a dependency
//!   this workspace does not take. The default bind is loopback for that reason,
//!   and a routable bind announces itself at startup.
//! - **No authentication.** Anything that can reach the port can write records
//!   into an audit store. There is an `AuthProvider` contract and an
//!   `Action::Ingest` for it to authorise, and this server does not call either
//!   yet: until it does, reaching the port *is* the authorisation.
//! - **No HTTP/2, no h2c, and so no OTLP over gRPC.** HTTP/2 is HPACK, frames
//!   and flow control, a larger surface than the rest of this crate put
//!   together. OTLP over HTTP is the specification's default protocol and is
//!   what an SDK uses unless told otherwise.
//! - **No chunked bodies.** `Transfer-Encoding` in any form is 501, which
//!   deletes the request-smuggling family rather than defending against it. No
//!   chunk parser, no chunk extensions, no trailer section.
//! - **No JSON.** `application/json` is 415, still, and the reason has changed.
//!   It used to be that serving JSON would mean a second OTLP decoder, and a
//!   second decoder at a trust boundary is a second thing that can be wrong
//!   differently from the first. That decoder now exists: `trailryx_otlp::jsonl`
//!   reads a collector's exported file. What has not changed is the decision to
//!   keep it off *this* surface, which is the one exposed to the network, and the
//!   two decoders are pinned to agree by `trailryx-otlp/tests/differential.rs`
//!   rather than by hoping. A file an operator hands over is a different
//!   transport, not a wider network surface.
//! - **No metrics and no logs.** `/v1/metrics` and `/v1/logs` are 404. This
//!   store records what agents did.
//! - **No pipelining and no response compression.**
//!
//! A deployment that needs the network puts a reverse proxy in front to
//! terminate TLS and authenticate. That has a consequence worth saying in the
//! same breath: a proxy means two HTTP parsers in a row, and any disagreement
//! between them about where a message ends is request smuggling. It is exactly
//! why [`request`] refuses to have an opinion about anything ambiguous instead
//! of resolving it.
//!
//! # What it does not do to the store
//!
//! It calls [`trailryx_otlp::OtlpSource::accept`] and nothing else. It never
//! polls, never acks and never turns loss into a record: draining the source and
//! calling `anomaly_event` are the embedding store's job. A store that forgets
//! will accumulate records nobody collects and losses nobody wrote down, so the
//! binary beside this file shows the shape.
//!
//! It also never reads a clock. `recorded_at` comes from a closure the store
//! supplies, because a server that stamped its own time would be one process
//! away from a source that stamps its own time, and the difference between those
//! two is the whole trust model.
//!
//! # Where the strictness comes from
//!
//! Not taste. Each module names the failure its rules exist to prevent:
//! [`request`] for smuggling and header injection, [`inflate`] for
//! decompression bombs, [`response`] for response splitting, [`server`] for
//! resource exhaustion, [`handler`] for the difference between an answer a
//! client retries and one it throws away.

pub mod config;
pub mod handler;
pub mod inflate;
pub mod request;
pub mod response;
pub mod server;

pub use config::Config;
pub use handler::{Ingest, Verdict};
pub use request::{Head, Method, Wire};
pub use response::{Response, Status};
pub use server::{Event, EventKind, Server, Stopper};
