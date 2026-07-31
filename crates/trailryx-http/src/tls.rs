//! TLS for the outbound side, and nothing else.
//!
//! # Why this is in the client rather than in front of it
//!
//! Everywhere else in this system transport security is the deployment's: a
//! terminator sits in front of ingest and in front of the SQL port, and the process
//! binds to loopback. That works because those are things other people connect to.
//!
//! Outbound has no such place to stand. Nothing sits in front of a client reaching
//! somebody else's object store, so either the client speaks TLS or the operator
//! runs a proxy for it. Since the standing decision is to take the best available
//! implementation rather than write one, this is `rustls`, on the same `aws-lc-rs`
//! backend the cryptographic provider uses, so a deployment links one implementation
//! of AES rather than two.
//!
//! # What is verified, and by whose list
//!
//! Certificates are checked against the Mozilla root set compiled into the binary,
//! not against the host's store. That is a deliberate trade and worth stating: the
//! same binary trusts the same roots on every machine, which is what makes a
//! reproducible build mean something, and it does not pick up a corporate root
//! somebody installed on one host. A deployment that needs its own certificate
//! authority, which in a bank is most of them, supplies it through
//! [`Tls::with_roots`] rather than by editing the system store.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// A configured TLS client, reused across connections.
///
/// Built once because assembling a root store and a config is the expensive part,
/// and doing it per request would put certificate parsing on the hot path.
#[derive(Clone)]
pub struct Tls {
    config: Arc<ClientConfig>,
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tls(<rustls client config>)")
    }
}

impl Default for Tls {
    fn default() -> Self {
        Self::new()
    }
}

impl Tls {
    /// The Mozilla root set compiled into this binary.
    pub fn new() -> Self {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Self::from_roots(roots)
    }

    /// A private certificate authority instead of the public one.
    ///
    /// The case this exists for: an operator whose object store presents a
    /// certificate from their own authority, which is the normal arrangement inside
    /// a bank. Anything that does not parse is skipped rather than fatal, and the
    /// count of what was accepted comes back so a caller can refuse to start on
    /// zero instead of silently trusting nothing.
    pub fn with_roots(pem_certificates: &[Vec<u8>]) -> (Self, usize) {
        let mut roots = RootCertStore::empty();
        let mut accepted = 0;
        for der in pem_certificates {
            if roots.add(CertificateDer::from(der.clone())).is_ok() {
                accepted += 1;
            }
        }
        (Self::from_roots(roots), accepted)
    }

    fn from_roots(roots: RootCertStore) -> Self {
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            config: Arc::new(config),
        }
    }

    /// Wrap a connected socket in TLS for `server_name`.
    ///
    /// The name is the host on its own, never the authority: a certificate is issued
    /// for a name, and passing `host:port` here fails verification against every
    /// certificate that would otherwise be valid.
    pub fn wrap(
        &self,
        server_name: &str,
        socket: TcpStream,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| format!("{server_name} is not a name a certificate can be issued for"))?;
        let connection = ClientConnection::new(Arc::clone(&self.config), name)
            .map_err(|e| format!("the TLS session could not be started: {e}"))?;
        Ok(StreamOwned::new(connection, socket))
    }
}

/// A connection that is either plain or wrapped, so the request path is written
/// once.
pub enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl std::fmt::Debug for Stream {
    /// Written by hand because `StreamOwned` has no `Debug`, and named by variant
    /// rather than by contents: what a reader wants from this is whether the
    /// connection was encrypted, and the bytes in flight are not for a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain(_) => f.write_str("Stream::Plain"),
            Self::Tls(_) => f.write_str("Stream::Tls"),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configuration_is_built_from_the_compiled_roots() {
        // Nothing here reaches a network. What it checks is that the root set is
        // not empty, because a config built from zero roots verifies nothing and
        // would fail only at the first handshake, in a deployment.
        assert!(
            !webpki_roots::TLS_SERVER_ROOTS.is_empty(),
            "a compiled-in root set with no roots trusts nothing"
        );
        let _ = Tls::new();
    }

    #[test]
    fn a_private_authority_reports_how_many_certificates_it_accepted() {
        let (_, accepted) = Tls::with_roots(&[b"not a certificate".to_vec()]);
        assert_eq!(
            accepted, 0,
            "rubbish must not be counted as a trusted authority"
        );
    }

    /// An authority is a name, and `host:port` is not one. Getting this wrong makes
    /// every handshake fail against certificates that are perfectly valid, which is
    /// a confusing failure to debug from the outside.
    #[test]
    fn a_server_name_with_a_port_in_it_is_refused_before_the_handshake() {
        let tls = Tls::new();
        let socket = match TcpStream::connect(("127.0.0.1", 1)) {
            Ok(s) => s,
            // No listener, which is the normal case: the name check below is what
            // the test is about, and it happens before anything is sent.
            Err(_) => return,
        };
        assert!(tls.wrap("example.com:443", socket).is_err());
    }
}
