//! The OTLP receiver as a [`Source`].
//!
//! # Fail-open, but never silent
//!
//! A malformed batch does not stop the receiver and does not fail the emitter's
//! next attempt. An agent whose telemetry library has a bug must not be turned
//! into an agent that cannot work. But every batch that could not be read, and
//! every span that produced no record, is counted, and the counts become a
//! record of their own through [`OtlpSource::anomaly_event`].
//!
//! That is the shape the whole store uses for loss: the *fact* of it lives in
//! the metadata plane, where erasure cannot reach it, and the *detail* lives in
//! the payload plane with everything else that might name a person. An operator
//! who erases a person still knows how many spans were dropped that day.
//!
//! # No clock of its own
//!
//! `recorded_at` is supplied by the caller, because it must come from the
//! store's clock. A receiver that stamped its own time would be one process
//! away from a source that stamps its own time, and the difference between
//! those two is the entire trust model.

use crate::otlp::{Dropped, Limits, decode_trace_request};
use crate::semconv::{MAPPER_VERSION, MapperConfig, Report, map_span};
use std::collections::VecDeque;
use trailryx_contracts::contracts::{
    AdapterResult, Delivery, Ordering, Source, SourceDescriptor, Trust,
};
use trailryx_contracts::ingest::{Cursor, Ingest, MetaDraft, PayloadPart};
use trailryx_record::{
    AgentId, Basis, EventType, PayloadClass, RunId, Severity, Timestamp, Untrusted, Verdict,
    assess_skew,
};

/// What the wire itself said, as opposed to what the spans said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WireReport {
    /// Batches that could not be decoded at all.
    pub malformed_batches: u32,
    /// Fields this version does not know. Expected to be non-zero against a
    /// newer collector, and worth watching all the same: it is the measure of
    /// how much of each message we understood.
    pub unknown_fields: u32,
    /// Varints encoded in more bytes than the value needs. No ordinary encoder
    /// produces one.
    pub padded_varints: u32,
}

#[derive(Debug)]
pub struct OtlpSource {
    cfg: MapperConfig,
    limits: Limits,
    pending: VecDeque<Ingest>,
    next_cursor: u64,
    acked: Cursor,
    report: Report,
    dropped: Dropped,
    wire: WireReport,
    anomalies_reported: u64,
}

impl OtlpSource {
    pub fn new(cfg: MapperConfig) -> Self {
        Self::with_limits(cfg, Limits::default())
    }

    pub fn with_limits(cfg: MapperConfig, limits: Limits) -> Self {
        Self {
            cfg,
            limits,
            pending: VecDeque::new(),
            next_cursor: 1,
            acked: Cursor(0),
            report: Report::default(),
            dropped: Dropped::default(),
            wire: WireReport::default(),
            anomalies_reported: 0,
        }
    }

    /// Take one encoded `ExportTraceServiceRequest`.
    ///
    /// Returns how many records it produced. Never returns an error: the
    /// emitter is told its batch was accepted whatever we made of it, and what
    /// we made of it is in the counters.
    pub fn accept(&mut self, encoded: &[u8], recorded_at: Timestamp) -> usize {
        let Ok(request) = decode_trace_request(encoded, self.limits) else {
            self.wire.malformed_batches = self.wire.malformed_batches.saturating_add(1);
            return 0;
        };

        self.wire.unknown_fields = self
            .wire
            .unknown_fields
            .saturating_add(request.unknown_fields);
        self.wire.padded_varints = self
            .wire
            .padded_varints
            .saturating_add(request.padded_varints);
        self.merge_dropped(request.dropped);

        let mut produced = 0;
        for resource_spans in &request.resource_spans {
            for scope in &resource_spans.scopes {
                for span in &scope.spans {
                    let cursor = Cursor(self.next_cursor);
                    match map_span(
                        &self.cfg,
                        &resource_spans.resource,
                        &scope.scope_name,
                        span,
                        cursor,
                    ) {
                        Ok(ingest) => {
                            self.next_cursor += 1;
                            self.report.mapped = self.report.mapped.saturating_add(1);
                            // Both clocks are known here and nowhere else, so
                            // this is where disagreement gets noticed. The
                            // record is kept either way: an event with a bad
                            // clock is still evidence, as long as nobody is
                            // told the clock was fine.
                            if assess_skew(ingest.meta.occurred_at, recorded_at).is_excessive() {
                                self.report.excessive_skew =
                                    self.report.excessive_skew.saturating_add(1);
                            }
                            self.pending.push_back(ingest);
                            produced += 1;
                        }
                        Err(rejection) => self.report.note(rejection),
                    }
                }
            }
        }
        produced
    }

    fn merge_dropped(&mut self, other: Dropped) {
        self.dropped.spans = self.dropped.spans.saturating_add(other.spans);
        self.dropped.attributes = self.dropped.attributes.saturating_add(other.attributes);
        self.dropped.events = self.dropped.events.saturating_add(other.events);
        self.dropped.oversize_values = self
            .dropped
            .oversize_values
            .saturating_add(other.oversize_values);
        self.dropped.invalid_utf8 = self.dropped.invalid_utf8.saturating_add(other.invalid_utf8);
    }

    pub fn report(&self) -> Report {
        self.report
    }

    pub fn wire_report(&self) -> WireReport {
        self.wire
    }

    pub fn dropped(&self) -> Dropped {
        self.dropped
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Whether anything went wrong that has not yet been written down.
    pub fn has_unreported_anomaly(&self) -> bool {
        self.anomaly_total() > self.anomalies_reported
    }

    fn anomaly_total(&self) -> u64 {
        u64::from(self.report.lost())
            + u64::from(self.report.excessive_skew)
            + u64::from(self.wire.malformed_batches)
            + u64::from(self.dropped.spans)
            + u64::from(self.dropped.attributes)
            + u64::from(self.dropped.events)
            + u64::from(self.dropped.oversize_values)
    }

    /// Turn everything that went wrong so far into a record.
    ///
    /// The loss becomes a record because an audit trail with a hole in it and
    /// no note about the hole is worse than one that admits it: the first looks
    /// complete. `Severity::Warning` and the event type are the part that
    /// survives erasure; the breakdown is payload, because it counts things
    /// that were about somebody.
    ///
    /// Returns `None` when nothing has gone wrong since the last call.
    pub fn anomaly_event(&mut self, recorded_at: Timestamp) -> Option<Ingest> {
        if !self.has_unreported_anomaly() {
            return None;
        }
        let total = self.anomaly_total();
        let since = total - self.anomalies_reported;
        self.anomalies_reported = total;

        let run_id = RunId::parse(format!("otlp-anomalies-{}", self.anomalies_reported)).ok()?;
        let agent_id =
            AgentId::parse_strict(format!("agent://{}/trailryx.otlp", self.cfg.trust_domain()))
                .ok()?;

        let detail = format!(
            "anomalies_since_last\t{since}\n\
             unknown_operation\t{}\n\
             no_run_id\t{}\n\
             no_agent\t{}\n\
             excessive_clock_skew\t{}\n\
             malformed_batches\t{}\n\
             dropped_spans\t{}\n\
             dropped_attributes\t{}\n\
             dropped_events\t{}\n\
             oversize_values\t{}\n\
             invalid_utf8\t{}\n\
             unknown_protobuf_fields\t{}\n\
             padded_varints\t{}\n\
             mapper_version\t{}\n",
            self.report.unknown_operation,
            self.report.no_run_id,
            self.report.no_agent,
            self.report.excessive_skew,
            self.wire.malformed_batches,
            self.dropped.spans,
            self.dropped.attributes,
            self.dropped.events,
            self.dropped.oversize_values,
            self.dropped.invalid_utf8,
            self.wire.unknown_fields,
            self.wire.padded_varints,
            MAPPER_VERSION.0,
        );

        let cursor = Cursor(self.next_cursor);
        self.next_cursor += 1;

        Some(Ingest {
            meta: MetaDraft {
                mapper: crate::semconv::MAPPER_VERSION,
                tenant: self.cfg.tenant().clone(),
                agent_id,
                run_id,
                parent_run_id: None,
                on_behalf_of: Vec::new(),
                // The store speaking about itself, so for once the clock is
                // ours and the "untrusted" wrapper is a formality the type
                // system still insists on. Better a wrapper we do not need than
                // a field that can be filled from the wire.
                occurred_at: Untrusted::new(recorded_at),
                decided_at: None,
                event_type: EventType::StoreEvent,
                severity: Severity::Warning,
                basis: Basis::default(),
                verdict: Some(Verdict::Failed),
                error: None,
                latency_micros: None,
                tokens_in: None,
                tokens_out: None,
                cost_micros: None,
            },
            payload: vec![PayloadPart::new(
                PayloadClass::Diagnostic,
                detail.into_bytes(),
            )],
            correlation: None,
            cursor,
        })
    }
}

impl Source for OtlpSource {
    fn descriptor(&self) -> SourceDescriptor {
        SourceDescriptor {
            name: "otlp/traces",
            // Both untrusted, and neither is a formality. The timestamps come
            // from the emitter's clock, and the identity comes from an
            // attribute the emitter chose. The trust domain is ours; nothing
            // else here is.
            clock_trust: Trust::Untrusted,
            identity_trust: Trust::Untrusted,
            // OTLP exporters retry on failure without deduplicating.
            delivery: Delivery::AtLeastOnce,
            // A span is exported when it ends, so a child arrives before its
            // parent as a matter of course.
            ordering: Ordering::Unordered,
        }
    }

    fn poll(&mut self, budget: usize) -> AdapterResult<Vec<Ingest>> {
        let take = budget.min(self.pending.len());
        Ok(self.pending.drain(..take).collect())
    }

    fn ack(&mut self, cursor: Cursor) -> AdapterResult<()> {
        // Idempotent, and never a rewind: an older cursor is a repeat of
        // something already settled, not an instruction to reopen it.
        if cursor > self.acked {
            self.acked = cursor;
        }
        Ok(())
    }
}
