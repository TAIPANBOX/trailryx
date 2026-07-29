//! The listener, and what bounds it.
//!
//! # Thread per connection, and why that is defensible
//!
//! The standard library has no readiness interface, so a worker pool cannot
//! multiplex requests: a pooled worker would have to hold a whole *connection*,
//! which makes a pool strictly worse than a thread each under a slow-sender
//! attack. Sixteen workers means sixteen slow peers is total starvation;
//! two hundred and fifty-six threads means two hundred and fifty-six slow peers,
//! and every one of them still dies on a phase deadline.
//!
//! What bounds this design is the cap and the deadlines, not the threading
//! model. A thread costs 128 KiB of stack once the default two megabytes is
//! overridden, which it is, because nothing on the request path recurses.
//!
//! # At the cap, answer rather than vanish
//!
//! Refusing to call `accept` would leave completed handshakes in the kernel's
//! queue to be dropped silently, and a client would see an unexplained timeout.
//! So the socket is accepted, told 503 with a `Retry-After`, and closed. 503 is
//! retryable, so the batch stays where it is.
//!
//! # There is no TLS here and there never will be
//!
//! The standard library has none and adding one is a dependency this workspace
//! does not take. So the default bind is loopback, a routable bind says so at
//! startup, and the documentation states plainly that anything which can reach
//! this port can write records into an audit store. A deployment that needs the
//! network must terminate TLS and authenticate in front of it.
//!
//! And the second half, which matters just as much: putting a proxy in front
//! means two HTTP parsers in a row, which is exactly why [`crate::request`] is
//! as strict as it is.

use crate::handler::{Ingest, Verdict};
use crate::request::{BodyError, Incoming, Wire};
use crate::response::{Response, Status};
use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Something worth telling an operator, with no room for anything a client
/// chose.
///
/// Typed rather than a formatted string, so a request's bytes cannot reach a log
/// line by accident. Bodies carry telemetry that routinely contains prompts,
/// which is the whole reason the mapper puts unrecognised attributes in the
/// encrypted plane, and a log file is outside every plane the store maintains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub kind: EventKind,
    pub status: Option<u16>,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Listening,
    /// A bind the network can reach. Said out loud once, at startup.
    RoutableBind,
    Accepted,
    /// A request was answered.
    Served,
    /// A request was refused, with the status in `status`.
    Refused,
    /// Over the connection cap or the in-flight budget.
    Shed,
    /// The peer went away mid-message. Nothing was handed onward.
    Truncated,
    /// The accept loop itself failed.
    AcceptFailed,
    /// A thread could not be spawned.
    SpawnFailed,
    Closed,
}

type Sink = Arc<dyn Fn(Event) + Send + Sync>;

/// Decrements the live-connection count however the handler leaves.
///
/// A guard rather than a line at the end of the function: a `return` on an
/// error path is exactly how a counter leaks until the cap is reached and the
/// server refuses everything forever.
struct Live(Arc<AtomicUsize>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Reserves body bytes against a global budget, and gives them back.
struct Budget {
    total: Arc<AtomicUsize>,
    taken: usize,
}

impl Budget {
    /// `None` when the reservation would cross the ceiling.
    fn reserve(total: &Arc<AtomicUsize>, want: usize, ceiling: usize) -> Option<Self> {
        total
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let next = current.checked_add(want)?;
                (next <= ceiling).then_some(next)
            })
            .ok()
            .map(|_| Self {
                total: Arc::clone(total),
                taken: want,
            })
    }
}

impl Drop for Budget {
    fn drop(&mut self) {
        self.total.fetch_sub(self.taken, Ordering::AcqRel);
    }
}

#[derive(Debug)]
pub struct Server {
    ingest: Arc<Ingest>,
    listener: TcpListener,
    live: Arc<AtomicUsize>,
    inflight: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
    address: SocketAddr,
}

/// Stops a running server from another thread.
#[derive(Debug, Clone)]
pub struct Stopper {
    stopping: Arc<AtomicBool>,
    address: SocketAddr,
}

impl Stopper {
    /// Set the flag, then connect once to wake the blocked accept.
    ///
    /// The alternative is a non-blocking listener polled on a timer, which adds
    /// latency to every connection to make shutdown convenient. One throwaway
    /// connection costs nothing and only happens when stopping.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
    }
}

impl Server {
    pub fn bind(ingest: Arc<Ingest>) -> io::Result<Self> {
        let listener = TcpListener::bind(ingest.config().bind)?;
        let address = listener.local_addr()?;
        Ok(Self {
            ingest,
            listener,
            live: Arc::new(AtomicUsize::new(0)),
            inflight: Arc::new(AtomicUsize::new(0)),
            stopping: Arc::new(AtomicBool::new(false)),
            address,
        })
    }

    /// The address actually bound, which is what a test needs when it asked for
    /// port zero.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn stopper(&self) -> Stopper {
        Stopper {
            stopping: Arc::clone(&self.stopping),
            address: self.address,
        }
    }

    pub fn live_connections(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// Serve until stopped. Never panics and never returns on one bad accept.
    pub fn serve(&self, log: Sink) {
        log(Event {
            kind: EventKind::Listening,
            status: None,
            bytes: 0,
        });
        if self.ingest.config().is_routable() {
            // Said once, loudly, because the consequence is an unauthenticated
            // plaintext write path into an audit store.
            log(Event {
                kind: EventKind::RoutableBind,
                status: None,
                bytes: 0,
            });
        }

        loop {
            if self.stopping.load(Ordering::Acquire) {
                return;
            }
            let (stream, _peer) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => continue,
                Err(_) => {
                    // Out of file descriptors is the case that matters: a tight
                    // retry loop would spin a core and never recover, so the
                    // loop pauses and tries again rather than exiting.
                    log(Event {
                        kind: EventKind::AcceptFailed,
                        status: None,
                        bytes: 0,
                    });
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            if self.stopping.load(Ordering::Acquire) {
                return;
            }

            let config = self.ingest.config();
            let taken = self.live.fetch_add(1, Ordering::AcqRel) + 1;
            let guard = Live(Arc::clone(&self.live));
            if taken > config.max_connections {
                log(Event {
                    kind: EventKind::Shed,
                    status: Some(Status::ServiceUnavailable.code()),
                    bytes: 0,
                });
                shed(stream, config.retry_after_seconds, config.write_timeout);
                drop(guard);
                continue;
            }

            let ingest = Arc::clone(&self.ingest);
            let inflight = Arc::clone(&self.inflight);
            let log_for_thread = Arc::clone(&log);
            let spawned = std::thread::Builder::new()
                .stack_size(config.thread_stack_bytes)
                .name("trailryx-ingest".to_owned())
                .spawn(move || {
                    let _guard = guard;
                    serve_connection(stream, &ingest, &inflight, &log_for_thread);
                });
            if spawned.is_err() {
                // The guard and the socket both moved into the closure, and a
                // failed spawn drops the closure, so the count is given back
                // and the connection closes. No status, because nothing was
                // written: the peer sees a closed connection, which is the one
                // thing we can still tell it once there is no thread to write
                // from.
                log(Event {
                    kind: EventKind::SpawnFailed,
                    status: None,
                    bytes: 0,
                });
            }
        }
    }
}

/// Tell a connection we cannot take it, then close.
fn shed(mut stream: TcpStream, retry_after: u32, write_timeout: Duration) {
    let _ = stream.set_write_timeout(Some(write_timeout));
    let response = Response::error(
        Status::ServiceUnavailable,
        "this server is at its connection limit; the batch is still yours",
    )
    .retry_after(retry_after);
    let _ = response.write_to(&mut stream);
    let _ = stream.shutdown(Shutdown::Both);
}

fn serve_connection(
    stream: TcpStream,
    ingest: &Arc<Ingest>,
    inflight: &Arc<AtomicUsize>,
    log: &Sink,
) {
    let config = ingest.config();
    log(Event {
        kind: EventKind::Accepted,
        status: None,
        bytes: 0,
    });

    // Before any read, both ways. A socket read with no timeout is a thread a
    // stranger can hold for as long as they like.
    if stream.set_read_timeout(Some(config.read_timeout)).is_err()
        || stream
            .set_write_timeout(Some(config.write_timeout))
            .is_err()
    {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }
    // Two handles on one socket: the parser reads through one and responses go
    // out through the other, so a response can be written without borrowing the
    // reader's buffer.
    let Ok(mut writer) = stream.try_clone() else {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    };
    let mut wire = Wire::new(stream, config);

    // `checked_add` because the lifetime comes from configuration, and
    // `Instant + Duration` panics on overflow rather than saturating.
    let Some(connection_deadline) = Instant::now().checked_add(config.connection_lifetime) else {
        let _ = writer.shutdown(Shutdown::Both);
        return;
    };
    let mut served = 0u32;

    loop {
        if served >= config.max_requests_per_connection || Instant::now() >= connection_deadline {
            break;
        }
        // The first request gets the header budget; a later one on the same
        // connection gets the idle budget first, then the header budget once
        // bytes start arriving. Both are clamped by the connection's lifetime.
        let head_budget = if served == 0 {
            config.header_timeout
        } else {
            config.idle_timeout + config.header_timeout
        };
        let head_deadline = Instant::now()
            .checked_add(head_budget)
            .unwrap_or(connection_deadline)
            .min(connection_deadline);

        match wire.read_head(config, head_deadline) {
            Incoming::Eof => break,
            Incoming::Refused(reject) => {
                let response = Response::error(reject.status, reject.why);
                log(Event {
                    kind: EventKind::Refused,
                    status: Some(reject.status.code()),
                    bytes: 0,
                });
                let _ = response.write_to(&mut writer);
                break;
            }
            Incoming::Head(head) => {
                let close_after = head.close_requested;
                let response = match ingest.inspect(&head) {
                    Verdict::Answer(response) => response,
                    Verdict::ReadBody { length, gzip } => {
                        // What may actually be held, not what was declared. A
                        // compressed body is charged the ceiling it can inflate
                        // to: charging the declared length let two hundred and
                        // fifty-six connections of fifteen kilobytes each hold
                        // four gigabytes against a budget that had counted four
                        // megabytes.
                        let declared = usize::try_from(length).unwrap_or(usize::MAX);
                        let want = if gzip { config.max_body } else { declared };
                        let Some(_budget) =
                            Budget::reserve(inflight, want, config.max_inflight_body)
                        else {
                            log(Event {
                                kind: EventKind::Shed,
                                status: Some(Status::ServiceUnavailable.code()),
                                bytes: length,
                            });
                            let response = Response::error(
                                Status::ServiceUnavailable,
                                "this server is at its in-flight body limit; the batch is still yours",
                            )
                            .retry_after(config.retry_after_seconds);
                            let _ = response.write_to(&mut writer);
                            break;
                        };

                        if head.expect_continue && Response::write_continue(&mut writer).is_err() {
                            break;
                        }
                        let body_deadline = Instant::now()
                            .checked_add(config.body_timeout)
                            .unwrap_or(connection_deadline)
                            .min(connection_deadline);
                        match wire.read_body(length, config, body_deadline) {
                            Ok(body) => ingest.submit(body, gzip),
                            Err(BodyError::Truncated) => {
                                // Nothing is handed onward and nothing is
                                // answered: there is no message to answer.
                                log(Event {
                                    kind: EventKind::Truncated,
                                    status: None,
                                    bytes: length,
                                });
                                break;
                            }
                            Err(BodyError::Refused(reject)) => {
                                let response = Response::error(reject.status, reject.why);
                                log(Event {
                                    kind: EventKind::Refused,
                                    status: Some(reject.status.code()),
                                    bytes: length,
                                });
                                let _ = response.write_to(&mut writer);
                                break;
                            }
                        }
                    }
                };

                let status = response.status();
                let closing = response.will_close();
                if response.write_to(&mut writer).is_err() {
                    break;
                }
                log(Event {
                    kind: if status == Status::Ok {
                        EventKind::Served
                    } else {
                        EventKind::Refused
                    },
                    status: Some(status.code()),
                    bytes: head.body_length(),
                });
                served += 1;

                // Leftover bytes at this point are, by construction, either a
                // broken client or somebody's next request arriving before we
                // said anything about this one. Refusing to pipeline costs a
                // real exporter nothing and removes the response-ordering
                // class entirely.
                if closing || close_after || wire.buffered() > 0 {
                    break;
                }
            }
        }
    }

    // In stages. An immediate close on a socket with unread client data makes
    // the kernel send RST, which can erase the 413 we just wrote from the
    // client's receive buffer and turn a documented limit into a mystery.
    let _ = writer.flush();
    let _ = writer.shutdown(Shutdown::Write);
    if let Some(until) = Instant::now().checked_add(Duration::from_secs(5)) {
        wire.drain_briefly(64 * 1024, until);
    }
    let _ = writer.shutdown(Shutdown::Both);
    log(Event {
        kind: EventKind::Closed,
        status: None,
        bytes: u64::from(served),
    });
}

/// A log sink that writes one line per event to standard error.
///
/// Typed events only, so nothing a client sent can appear here.
pub fn stderr_log() -> Sink {
    Arc::new(|event: Event| {
        eprintln!(
            "trailryx-ingest {:?} status={} n={}",
            event.kind,
            event
                .status
                .map_or_else(|| "-".to_owned(), |s| s.to_string()),
            event.bytes
        );
    })
}

/// A sink that discards, for tests and for an operator who routes elsewhere.
pub fn silent_log() -> Sink {
    Arc::new(|_| {})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_refuses_rather_than_overshooting() {
        let total = Arc::new(AtomicUsize::new(0));
        let a = Budget::reserve(&total, 60, 100).expect("60 of 100");
        assert!(Budget::reserve(&total, 60, 100).is_none(), "120 of 100");
        let b = Budget::reserve(&total, 40, 100).expect("exactly 100");
        assert_eq!(total.load(Ordering::Acquire), 100);
        drop(a);
        drop(b);
        assert_eq!(total.load(Ordering::Acquire), 0, "the guards gave it back");
    }

    #[test]
    fn a_budget_cannot_be_overflowed_into_success() {
        let total = Arc::new(AtomicUsize::new(1));
        assert!(
            Budget::reserve(&total, usize::MAX, usize::MAX).is_none(),
            "the addition wrapping would have looked like room"
        );
    }

    #[test]
    fn a_live_count_returns_however_the_handler_leaves() {
        let live = Arc::new(AtomicUsize::new(0));
        live.fetch_add(1, Ordering::AcqRel);
        {
            let _guard = Live(Arc::clone(&live));
            assert_eq!(live.load(Ordering::Acquire), 1);
        }
        assert_eq!(live.load(Ordering::Acquire), 0);
    }
}
