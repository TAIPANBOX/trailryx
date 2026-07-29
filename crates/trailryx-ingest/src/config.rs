//! Every limit, in one place, with the reason next to the number.
//!
//! Limits scattered as literals through a request path drift apart, and the
//! one that was forgotten is the one an attacker finds. Having them here is
//! also what lets the hostile tests set a 512-byte cap and prove the check
//! fires rather than asserting it exists.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    /// Loopback, and this is the most important default in the crate.
    ///
    /// There is no TLS here and no authentication, so anything that can reach
    /// the port can write records into an audit store. Loopback removes the
    /// untrusted network from the threat model rather than mitigating it, which
    /// is the only honest thing a plaintext listener can do. A routable bind is
    /// a deliberate act and says so at startup.
    pub bind: SocketAddr,

    /// Served in front of the OTLP paths, for a deployment behind a proxy that
    /// mounts us somewhere. Empty by default.
    pub path_prefix: String,

    /// Live connections. Each costs a thread.
    ///
    /// 256 threads at 128 KiB of stack is 32 MiB, which is affordable, and 256
    /// simultaneous exporters is far more than one store fronts. At the cap the
    /// socket is still accepted and answered 503: refusing to accept would make
    /// the kernel drop completed handshakes silently, and a client would see an
    /// unexplained timeout instead of a reason.
    pub max_connections: usize,

    /// The default 2 MiB per thread is what makes thread-per-connection look
    /// expensive. Nothing on the request path recurses, so 128 KiB is generous.
    pub thread_stack_bytes: usize,

    pub max_request_line: usize,
    pub max_header_line: usize,
    pub max_header_count: usize,
    /// Counted incrementally while reading, including the request line, so a
    /// header section that never ends is bounded rather than measured.
    pub max_header_section: usize,

    /// The cap on the body **after** decompression.
    pub max_body: usize,

    /// Across all connections at once, so 256 threads cannot each hold the
    /// per-request maximum.
    ///
    /// Divide it by [`Config::max_body`] to get how many gzip requests may be in
    /// flight, because a compressed request is charged the worst case it can
    /// inflate to rather than the length it declared. It was charged the declared
    /// length until an adversarial review measured what that allows: 256
    /// connections of fifteen kilobytes each, holding four gigabytes of
    /// decompressed bodies, against a sixty-four megabyte ceiling that never
    /// noticed because it had counted four megabytes.
    pub max_inflight_body: usize,

    /// Decompressed bytes per compressed byte. A real payload never approaches
    /// this; a bomb exists to exceed it.
    pub gzip_max_ratio: usize,

    /// Records waiting to be drained before the server sheds load.
    pub max_pending: usize,

    /// After this many, the connection closes. Without a cap, every per-phase
    /// deadline can be satisfied forever by a client that keeps being polite.
    pub max_requests_per_connection: u32,

    pub connection_lifetime: Duration,
    /// Between requests on a kept-alive connection.
    pub idle_timeout: Duration,
    pub header_timeout: Duration,
    pub body_timeout: Duration,
    pub write_timeout: Duration,
    /// The per-syscall timeout. The phase deadlines above are what actually
    /// bound a connection; this one stops a single read from blocking forever.
    pub read_timeout: Duration,

    /// Bytes per second a body must arrive at, once enough has arrived to
    /// judge. This is what makes a slow-body attack terminate early rather
    /// than at the body deadline.
    pub min_body_rate: usize,

    /// Sent with every 503. Seconds, not an HTTP date: some exporters clamp a
    /// negative date delta to zero, which turns throttling into a retry storm.
    pub retry_after_seconds: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4318),
            path_prefix: String::new(),
            max_connections: 256,
            thread_stack_bytes: 128 * 1024,
            max_request_line: 8 * 1024,
            max_header_line: 8 * 1024,
            max_header_count: 64,
            max_header_section: 16 * 1024,
            max_body: 16 * 1024 * 1024,
            max_inflight_body: 256 * 1024 * 1024,
            gzip_max_ratio: 200,
            max_pending: 65_536,
            max_requests_per_connection: 100,
            connection_lifetime: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(5),
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            min_body_rate: 1024,
            retry_after_seconds: 1,
        }
    }
}

impl Config {
    /// Whether this configuration puts the port somewhere the network can see.
    ///
    /// Asked at startup so the answer can be said out loud rather than
    /// discovered by whoever finds the port.
    pub fn is_routable(&self) -> bool {
        !self.bind.ip().is_loopback()
    }
}
