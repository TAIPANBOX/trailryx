//! What the answers mean.
//!
//! Separated from the socket on purpose: every decision here can be tested by
//! calling a function, and the tests that matter most are about which status
//! code an emitter gets, not about whether a byte stream parsed.
//!
//! # The one place the answer differs from what the store does
//!
//! `OtlpSource::accept` is fail-open by design: it never returns an error, it
//! counts what it could not use, and a later `anomaly_event` turns the loss into
//! a record. That is right for the store and it is not right for the wire. A
//! batch that could not be decoded at all gets a 400, because 400 is
//! non-retryable and the emitter needs to stop resending bytes that will never
//! decode and go and fix its instrumentation. Answering 200 would be the silent
//! half of fail-open, which the store's own documentation rejects.
//!
//! # Retryable versus not is the whole game
//!
//! An OTLP client keeps a batch and comes back on 429, 502, 503 and 504, and
//! drops it on everything else. So backpressure is 503 and never 500: a
//! five-second blip answered with 500 becomes permanent, fleet-wide holes in
//! the evidence. And a malformed batch is 400 and never 503, or the emitter
//! spends the rest of its life resending it.
//!
//! # Shedding happens before the handoff
//!
//! `accept` never fails, so once bytes go in they are ours to keep. The queue
//! check therefore happens before the lock and before the call, not after.

use crate::config::Config;
use crate::inflate::{self, gunzip};
use crate::request::{Head, Method};
use crate::response::{ContentType, Response, Status, encode_export_response};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use trailryx_otlp::OtlpSource;
use trailryx_record::Timestamp;

/// What the head alone decided.
#[derive(Debug)]
pub enum Verdict {
    /// Read this many bytes, decompress if asked, then submit.
    ReadBody { length: u64, gzip: bool },
    /// Answer now. The body, if any, is never read: draining an oversized or
    /// rejected body to keep a connection alive is how a cap becomes free.
    Answer(Response),
}

/// The ingest endpoint: the source, its lock, and the clock it is stamped from.
pub struct Ingest {
    source: Mutex<OtlpSource>,
    /// Supplied by the embedding store. This crate never reads a wall clock:
    /// `recorded_at` is the store's own time, and a server that stamped it
    /// would be one process away from a source that stamps it.
    clock: Box<dyn Fn() -> Timestamp + Send + Sync>,
    config: Config,
    /// Set once if the lock is ever poisoned. From then on every request is
    /// answered 503 rather than panicking a thread at a time.
    degraded: AtomicBool,
}

impl std::fmt::Debug for Ingest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ingest")
            .field("degraded", &self.degraded.load(Ordering::Relaxed))
            .field("bind", &self.config.bind)
            .finish_non_exhaustive()
    }
}

impl Ingest {
    pub fn new(
        source: OtlpSource,
        config: Config,
        clock: Box<dyn Fn() -> Timestamp + Send + Sync>,
    ) -> Self {
        Self {
            source: Mutex::new(source),
            clock,
            config,
            degraded: AtomicBool::new(false),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// Take a look at anything the source will report.
    ///
    /// The server never drains the source or turns loss into a record: that is
    /// the embedding store's job, and this accessor is how it reaches in.
    pub fn with_source<T>(&self, f: impl FnOnce(&mut OtlpSource) -> T) -> Option<T> {
        match self.source.lock() {
            Ok(mut guard) => Some(f(&mut guard)),
            Err(_) => {
                self.degraded.store(true, Ordering::Relaxed);
                None
            }
        }
    }

    fn unavailable(&self, why: &str) -> Response {
        // Retry-After in seconds, not as a date: some exporters clamp a
        // negative date delta to zero, which turns throttling into a storm.
        Response::error(Status::ServiceUnavailable, why)
            .retry_after(self.config.retry_after_seconds)
    }

    /// Everything that can be decided without reading a body.
    pub fn inspect(&self, head: &Head) -> Verdict {
        let prefix = self.config.path_prefix.as_str();
        let Some(rest) = head.path.strip_prefix(prefix) else {
            return Verdict::Answer(Response::error(
                Status::NotFound,
                "no endpoint is served at that path",
            ));
        };

        // The traces path, and the base endpoint itself: an SDK configured with
        // OTEL_EXPORTER_OTLP_ENDPOINT rather than the traces-specific variable
        // appends nothing, and refusing it would be refusing a correct client.
        let is_traces = matches!(rest, "/v1/traces" | "/" | "");
        let is_other_signal =
            matches!(rest, "/v1/metrics" | "/v1/logs" | "/v1development/profiles");

        if !is_traces {
            let why = if is_other_signal {
                "this store records traces; metrics and logs are not accepted here"
            } else {
                "no endpoint is served at that path"
            };
            return Verdict::Answer(Response::error(Status::NotFound, why));
        }
        if head.method != Method::Post {
            return Verdict::Answer(
                Response::error(Status::MethodNotAllowed, "traces are POSTed").allow("POST"),
            );
        }

        if self.is_degraded() {
            return Verdict::Answer(self.unavailable("the ingest path is degraded"));
        }

        // Three cases, and they are three because collapsing the first two
        // told an SDK posting a legitimate empty export that its length was
        // missing.
        match head.declared_length {
            // It said zero. An empty export, whatever else it declared. The
            // specification says it should succeed and `accept` produces
            // exactly that.
            Some(0) => {
                return Verdict::ReadBody {
                    length: 0,
                    gzip: false,
                };
            }
            // It said nothing at all and described no content either, so there
            // is nothing to read and nothing was meant.
            None if head.content_type.is_none() => {
                return Verdict::ReadBody {
                    length: 0,
                    gzip: false,
                };
            }
            // It described a body and did not say how long. There is no
            // transfer coding here to find out with.
            None => {
                return Verdict::Answer(Response::error(
                    Status::LengthRequired,
                    "a body needs a Content-Length; this server does not implement transfer codings",
                ));
            }
            Some(_) => {}
        }

        match media_type(head.content_type.as_deref()) {
            Some(Media::Protobuf) => {}
            Some(Media::Json) => {
                return Verdict::Answer(Response::error(
                    Status::UnsupportedMediaType,
                    "this server accepts application/x-protobuf only; set OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf",
                ));
            }
            None => {
                return Verdict::Answer(Response::error(
                    Status::UnsupportedMediaType,
                    "this server accepts application/x-protobuf only",
                ));
            }
        }

        let gzip = match coding(head.content_encoding.as_deref()) {
            Some(Coding::Identity) => false,
            Some(Coding::Gzip) => true,
            None => {
                // 415 and never 400: this is a feature we do not have, not a
                // message we could not read, and 415 is the non-retryable code
                // that says so.
                return Verdict::Answer(Response::error(
                    Status::UnsupportedMediaType,
                    "the only content coding this server decodes is a single gzip",
                ));
            }
        };

        if head.body_length() > self.config.max_body as u64 {
            return Verdict::Answer(Response::error(
                Status::PayloadTooLarge,
                "the declared body length exceeds this server's limit",
            ));
        }

        // Shed before the handoff, because after it the batch is ours.
        match self.with_source(|source| source.pending()) {
            Some(pending) if pending >= self.config.max_pending => {
                return Verdict::Answer(
                    self.unavailable("the ingest queue is full; the batch is still yours"),
                );
            }
            None => {
                return Verdict::Answer(self.unavailable("the ingest path is degraded"));
            }
            Some(_) => {}
        }

        Verdict::ReadBody {
            length: head.body_length(),
            gzip,
        }
    }

    /// Decompress if needed, hand the bytes to the source, and answer.
    pub fn submit(&self, body: Vec<u8>, gzip: bool) -> Response {
        let body = if gzip {
            let bounds = inflate::Bounds {
                max_output: self.config.max_body,
                max_ratio: self.config.gzip_max_ratio,
                ..inflate::Bounds::default()
            };
            match gunzip(&body, bounds) {
                Ok(bytes) => bytes,
                Err(inflate::InflateError::OutputTooLarge)
                | Err(inflate::InflateError::RatioTooHigh) => {
                    return Response::error(
                        Status::PayloadTooLarge,
                        "the body decompresses to more than this server accepts",
                    );
                }
                Err(_) => {
                    // The stream is broken, which is the emitter's bug and will
                    // not be fixed by sending it again.
                    return Response::error(
                        Status::BadRequest,
                        "the gzip body could not be decoded",
                    );
                }
            }
        } else {
            body
        };

        let recorded_at = (self.clock)();
        // The counters the source already keeps are the only per-request truth
        // available without re-implementing its decoder, and reading a delta is
        // not re-implementing anything.
        let outcome = self.with_source(|source| {
            let malformed_before = source.wire_report().malformed_batches;
            let lost_before = source.report().lost();
            source.accept(&body, recorded_at);
            (
                source.wire_report().malformed_batches - malformed_before,
                source.report().lost() - lost_before,
            )
        });

        let Some((malformed, lost)) = outcome else {
            return self.unavailable("the ingest path is degraded");
        };

        if malformed > 0 {
            // The batch has still been counted by the source, and
            // `anomaly_event` will still turn it into a record. What differs
            // here is only what the emitter is told, and it is told to stop.
            return Response::error(
                Status::BadRequest,
                "the batch could not be decoded as an ExportTraceServiceRequest",
            );
        }

        if lost > 0 {
            return Response::new(Status::Ok).body(
                ContentType::Protobuf,
                encode_export_response(
                    u64::from(lost),
                    "some spans could not be mapped; see the store's ingest counters",
                ),
            );
        }

        // Nothing extra. A present-but-empty partial success makes some client
        // versions log an error for every export of data that arrived intact.
        Response::new(Status::Ok).body(ContentType::Protobuf, Vec::new())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Media {
    Protobuf,
    Json,
}

/// Compare type and subtype, ignore parameters.
///
/// `application/x-protobuf; charset=utf-8` is the same media type as the bare
/// form, and a client that adds a parameter is not a client to refuse.
fn media_type(value: Option<&[u8]>) -> Option<Media> {
    let value = value?;
    let essence = match value.iter().position(|b| *b == b';') {
        Some(at) => &value[..at],
        None => value,
    };
    let essence = trim_ascii(essence);
    if essence.eq_ignore_ascii_case(b"application/x-protobuf") {
        Some(Media::Protobuf)
    } else if essence.eq_ignore_ascii_case(b"application/json") {
        Some(Media::Json)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coding {
    Identity,
    Gzip,
}

/// Exactly one coding, and only one of two.
///
/// `gzip, gzip` is refused as well as `deflate`: nested codings are how a
/// decompression bomb multiplies its ratio, and there is no legitimate emitter
/// that sends one.
fn coding(value: Option<&[u8]>) -> Option<Coding> {
    let Some(value) = value else {
        return Some(Coding::Identity);
    };
    let value = trim_ascii(value);
    if value.is_empty() {
        return Some(Coding::Identity);
    }
    if value.contains(&b',') {
        return None;
    }
    if value.eq_ignore_ascii_case(b"identity") {
        Some(Coding::Identity)
    } else if value.eq_ignore_ascii_case(b"gzip") {
        Some(Coding::Gzip)
    } else {
        None
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if *first == b' ' || *first == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if *last == b' ' || *last == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_media_type_ignores_its_parameters_and_nothing_else() {
        assert_eq!(
            media_type(Some(b"application/x-protobuf")),
            Some(Media::Protobuf)
        );
        assert_eq!(
            media_type(Some(b"application/x-protobuf; charset=utf-8")),
            Some(Media::Protobuf)
        );
        assert_eq!(
            media_type(Some(b"APPLICATION/X-PROTOBUF")),
            Some(Media::Protobuf)
        );
        assert_eq!(media_type(Some(b"application/json")), Some(Media::Json));
        assert_eq!(media_type(Some(b"application/protobuf")), None);
        assert_eq!(media_type(Some(b"")), None);
        assert_eq!(media_type(None), None);
    }

    #[test]
    fn one_coding_or_none_and_never_two() {
        assert_eq!(coding(None), Some(Coding::Identity));
        assert_eq!(coding(Some(b"")), Some(Coding::Identity));
        assert_eq!(coding(Some(b"identity")), Some(Coding::Identity));
        assert_eq!(coding(Some(b"gzip")), Some(Coding::Gzip));
        assert_eq!(coding(Some(b"GZIP")), Some(Coding::Gzip));
        // Nesting is how a bomb multiplies its ratio.
        assert_eq!(coding(Some(b"gzip, gzip")), None);
        assert_eq!(coding(Some(b"identity, gzip")), None);
        for other in [
            b"deflate".as_slice(),
            b"br",
            b"zstd",
            b"compress",
            b"gzip;q=1",
        ] {
            assert_eq!(coding(Some(other)), None, "{:?}", other);
        }
    }
}
