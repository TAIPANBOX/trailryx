//! The Postgres wire surface, and the two things the convenient path gets wrong.
//!
//! # Why `datafusion_postgres::serve` is not used
//!
//! Two reasons, both measured against the library rather than assumed:
//!
//! 1. **It does no authentication.** `HandlerFactory::new` installs
//!    `SimpleStartupHandler`, whose own doc comment says "does no authentication",
//!    and `AuthManager::new` seeds a `postgres` superuser with an empty password,
//!    `can_login: true` and `Permission::All`. Anything that can reach the port is
//!    in, as a superuser.
//! 2. **It forwards arbitrary SQL**, which is arbitrary local file read. See
//!    [`crate::gate`], where the statement that reads `/etc/passwd` is the first
//!    test.
//!
//! Neither is a criticism of the library: a general-purpose adapter that made those
//! choices for you would be worse. They are the choices a store serving an audit
//! trail has to make itself, and this module makes them.
//!
//! # The doctrine, the same one the ingest side already follows
//!
//! - **Loopback by default.** There is no TLS here, so anything that can reach the
//!   port can read the trail, and loopback removes the untrusted network from the
//!   threat model rather than mitigating it.
//! - **A routable bind with no authentication refuses to start**, before the socket
//!   opens. `trailryx-ingest` learned this the same way: it used to log a warning,
//!   which meant the operator who most needed to notice was reading the least,
//!   because the line arrives after the port is already open.
//! - **Read authorisation is its own action.** [`Action::Query`] rather than a
//!   general "logged in": the contract splits `ReadMetadata`, `ReadPayload` and
//!   `Query` because they are different permissions, and a surface that collapsed
//!   them would hand payload access to anybody allowed to count rows.
//!
//! # Why the credential is the password and the username is not an identity
//!
//! `AuthProvider::authenticate` takes a credential and returns a principal, which is
//! the right way round: the server does not hold the secret and does not decide who
//! somebody is. pgwire's own `AuthSource` asks the server for the *expected*
//! password, which is the other model and a weaker one, so this module implements
//! [`StartupHandler`] directly instead of using it.
//!
//! The username a client sends is recorded and **never trusted**: the principal comes
//! from the provider. A surface that took the username as the identity would let a
//! client choose who it was.

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{Sink, SinkExt};
use pgwire::api::auth::{
    ServerParameterProvider, StartupHandler, finish_authentication,
    save_startup_parameters_to_metadata,
};
use pgwire::api::{ClientInfo, PgWireServerHandlers};
use pgwire::error::{ErrorInfo, PgWireError, PgWireResult};
use pgwire::messages::startup::Authentication;
use pgwire::messages::{PgWireBackendMessage, PgWireFrontendMessage};
use tokio::io::AsyncWriteExt;

use trailryx_contracts::contracts::{Action, AdapterError, AuthProvider, Decision};

/// Where the facade listens.
#[derive(Debug, Clone)]
pub struct Config {
    /// Loopback and port 5432, so a client's default connection string works and the
    /// untrusted network is out of the threat model rather than mitigated.
    pub bind: SocketAddr,
    /// Live connections. Each is a tokio task rather than a thread, so this is a
    /// memory bound rather than a thread bound, but it is still a bound: a read
    /// surface with none is a read surface that can be exhausted.
    ///
    /// Kept by [`serve_on`], which is where a bound has to be kept and not here: this
    /// field was documented as a bound and read by nothing for the first four days it
    /// existed, which is worse than not having it, because a deployer lowering it
    /// reads it as a mitigation they have applied.
    pub max_connections: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:5432".parse().expect("a literal address parses"),
            max_connections: 64,
        }
    }
}

impl Config {
    /// Whether this configuration puts the port somewhere the network can see.
    pub fn is_routable(&self) -> bool {
        !self.bind.ip().is_loopback()
    }
}

/// Gives a connection's slot back however its task ends.
///
/// A guard rather than a line at the end of the task, for the reason the ingest side
/// wrote next to the same type: an early return on one error path is how a count leaks
/// until the cap is reached and the server refuses everything for ever, looking
/// healthy the whole time.
struct Live(Arc<AtomicUsize>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How long the refusal below may take to leave.
///
/// Bounded because everything done on a socket a stranger controls is bounded. Sixty
/// bytes fit in any send buffer, so a write still unfinished after this is a peer that
/// is not reading, and holding a task for it is the exhaustion the cap exists to stop.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(1);

/// Tell a connection past the cap why, then close.
///
/// **Answer rather than vanish**, which is the same choice `trailryx-ingest` made at
/// its own cap and for the same reason: a socket that simply closes leaves a client
/// with "connection closed", which is what it also sees on a crash, a firewall, a
/// wrong protocol and a half-written startup handler. 53300 is `too_many_connections`,
/// the code a driver's own retry logic reads, and this is the one condition here that
/// is worth retrying.
///
/// On its own task rather than on the accept loop: a peer that never reads would
/// otherwise hold the listener, and a listener held is every other client refused.
async fn refuse(mut socket: tokio::net::TcpStream) {
    let refusal = at_the_connection_limit();
    let _ = tokio::time::timeout(REFUSAL_TIMEOUT, async move {
        if socket.write_all(&refusal).await.is_ok() {
            // A close alone would be the vanishing this function exists to avoid: the
            // bytes are only an answer once they have left.
            let _ = socket.flush().await;
        }
        let _ = socket.shutdown().await;
    })
    .await;
}

/// A Postgres `ErrorResponse` saying the server is at its connection limit.
///
/// Encoded here rather than taken from pgwire because pgwire's encoder writes into a
/// `bytes::BytesMut`, and that is a dependency this crate would be taking for one
/// forty-byte message whose layout the protocol froze. What establishes the bytes are
/// right is not this comment but a real driver reading them: the test asserts on the
/// SQLSTATE `tokio-postgres` parsed out, which it cannot report unless every field
/// landed where the protocol says.
///
/// `S`, `C` and `M` because a client refuses to parse an error missing any of the
/// three; `V` beside `S` because every server since 9.6 sends the unlocalised
/// severity, and a fake that skipped it would be teaching clients a shape no real
/// server has.
fn at_the_connection_limit() -> Vec<u8> {
    let mut fields = Vec::new();
    for (tag, value) in [
        (b'S', "FATAL"),
        (b'V', "FATAL"),
        (b'C', "53300"),
        (b'M', "this server is at its connection limit"),
    ] {
        fields.push(tag);
        fields.extend_from_slice(value.as_bytes());
        fields.push(0);
    }
    // Ends the field list, and is not the same zero as the one ending the last field.
    fields.push(0);

    let mut out = vec![b'E'];
    // The length counts itself and the fields, and never the type byte. Derived from
    // the bytes rather than written out, so the two cannot disagree.
    let length = i32::try_from(fields.len() + 4).expect("four short constant fields");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&fields);
    out
}

/// What a refused connection was refused for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusals {
    pub no_credential: u64,
    pub rejected: u64,
    pub denied: u64,
    pub unavailable: u64,
    pub poisoned: bool,
}

/// The gate in front of a session.
///
/// Named separately from the ingest gate because the action is different and the
/// difference matters: this one asks [`Action::Query`], and a principal allowed to
/// write records is not thereby allowed to read them.
///
/// # What this gate is, and what a deployer must not read into it
///
/// It is a **door**, asked once, at connect time: authenticate the credential, then
/// `authorize(principal, Action::Query, scope)` where `scope` is the string fixed
/// when this gate was constructed. It admits the connection or it refuses it.
///
/// It is **not a row filter, and there is no row filter behind it**. Past the door
/// every authenticated client reads every record in every segment registered on the
/// server, whatever the `tenant` field on those records says. Nothing on the read
/// path takes a principal or a tenant: not `RecordTable::scan`, not
/// [`crate::pushdown::plan`], not `records_as_of`, `causal_closure` or `journal`. A
/// `WHERE tenant = ...` is a predicate the client chose and can leave out.
///
/// **So the deployment model is one server per scope.** The segments a server
/// registers are the segments its clients may read, and separating two tenants means
/// two servers, two ports and two sets of segments, not two principals on this one.
/// The unit tests below show two gates with different scopes refusing each other's
/// principals, which is exactly that model and is not multi-tenancy: they are two
/// servers in one test, not one server keeping two tenants apart.
///
/// Per-principal or per-tenant row filtering is a design decision with its own
/// questions (where the tenant of a request comes from, what a partial proof means
/// once rows are withheld, what an index range proves about a filtered answer) and it
/// is scheduled separately. Until it exists, a deployment that puts two tenants'
/// segments behind one of these has no isolation between them.
pub struct ReadGate {
    provider: Mutex<Box<dyn AuthProvider + Send>>,
    scope: String,
    no_credential: AtomicU64,
    rejected: AtomicU64,
    denied: AtomicU64,
    unavailable: AtomicU64,
    poisoned: std::sync::atomic::AtomicBool,
}

impl Debug for ReadGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadGate")
            .field("scope", &self.scope)
            .field("refusals", &self.refusals())
            .finish_non_exhaustive()
    }
}

impl ReadGate {
    /// `scope` is the whole server's scope and it never varies per client: it is the
    /// string every `Action::Query` decision is asked about, fixed here, for every
    /// connection this gate will ever admit. See the type's documentation for why
    /// that makes the deployment one server per scope.
    pub fn new(provider: Box<dyn AuthProvider + Send>, scope: impl Into<String>) -> Self {
        Self {
            provider: Mutex::new(provider),
            scope: scope.into(),
            no_credential: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            unavailable: AtomicU64::new(0),
            poisoned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn refusals(&self) -> Refusals {
        Refusals {
            no_credential: self.no_credential.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            unavailable: self.unavailable.load(Ordering::Relaxed),
            poisoned: self.poisoned.load(Ordering::Relaxed),
        }
    }

    /// Authenticate a password, then authorise [`Action::Query`].
    ///
    /// The error is a short reason for the wire. It never quotes the credential: a
    /// Postgres error goes into the client's log and often into the server's.
    fn decide(&self, credential: &[u8]) -> Result<(), &'static str> {
        if credential.is_empty() {
            self.no_credential.fetch_add(1, Ordering::Relaxed);
            return Err("this server requires a password");
        }
        let Ok(mut provider) = self.provider.lock() else {
            // Deny by default, for ever. A provider that panicked must not become an
            // open door, which is the one failure mode that turns a crash in
            // authentication into unauthenticated access to the whole trail.
            self.poisoned.store(true, Ordering::Relaxed);
            self.unavailable.fetch_add(1, Ordering::Relaxed);
            return Err("the authentication provider failed");
        };
        let principal = match provider.authenticate(credential) {
            Ok(principal) => principal,
            Err(AdapterError::Unavailable(_)) => {
                self.unavailable.fetch_add(1, Ordering::Relaxed);
                return Err("the authentication provider is unavailable");
            }
            // Refused and unsupported answer alike, so a client cannot tell which
            // schemes a deployment accepts by watching the error change.
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                return Err("password authentication failed");
            }
        };
        match provider.authorize(&principal, Action::Query, &self.scope) {
            Decision::Allow => Ok(()),
            Decision::Deny => {
                self.denied.fetch_add(1, Ordering::Relaxed);
                Err("this principal may not query this scope")
            }
        }
    }
}

/// The startup flow: ask for a password, hand it to the provider, and finish.
#[derive(Debug)]
struct Startup {
    gate: Arc<ReadGate>,
}

/// The parameters a client is told about the server.
///
/// Deliberately spare. `server_version` is what drivers branch on, and everything
/// else a client learns it should learn by asking.
#[derive(Debug, Clone)]
struct Parameters;

impl ServerParameterProvider for Parameters {
    fn server_parameters<C>(&self, _client: &C) -> Option<std::collections::HashMap<String, String>>
    where
        C: ClientInfo,
    {
        let mut out = std::collections::HashMap::new();
        // A version drivers accept. Claiming a version is not claiming to be
        // Postgres: what is served is a read-only view with one table in it, and the
        // statement gate refuses the rest.
        out.insert("server_version".to_owned(), "16.0".to_owned());
        out.insert("client_encoding".to_owned(), "UTF8".to_owned());
        out.insert("DateStyle".to_owned(), "ISO".to_owned());
        Some(out)
    }
}

#[async_trait::async_trait]
impl StartupHandler for Startup {
    async fn on_startup<C>(
        &self,
        client: &mut C,
        message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        match message {
            PgWireFrontendMessage::Startup(startup) => {
                // Both of these are easy to leave out and the symptom is the same
                // either way: every client sees "connection closed" and nothing says
                // why. `protocol_negotiation` answers the version and SSL question the
                // client asks first, and without the state change pgwire does not
                // route the password message to this handler at all, so the handshake
                // stops half finished. Learned by leaving them out.
                pgwire::api::auth::protocol_negotiation(client, &startup).await?;
                save_startup_parameters_to_metadata(client, &startup);
                client.set_state(pgwire::api::PgWireConnectionState::AuthenticationInProgress);
                // Cleartext, and the honesty about it is in the module docs: there is
                // no TLS here, so on a routable bind the password is readable on the
                // wire. That is why a routable bind without a provider refuses to
                // start and why the answer to a routable bind is a terminating proxy.
                client
                    .send(PgWireBackendMessage::Authentication(
                        Authentication::CleartextPassword,
                    ))
                    .await?;
                Ok(())
            }
            PgWireFrontendMessage::PasswordMessageFamily(password) => {
                let password = password.into_password()?;
                match self.gate.decide(password.password.as_bytes()) {
                    Ok(()) => finish_authentication(client, &Parameters).await,
                    // 28P01 is `invalid_password`, which is what a client expects and
                    // what its retry logic reads. Returned as an error rather than
                    // hand-written onto the socket, so pgwire closes the connection the
                    // way it closes every other failed startup: one path out, not two.
                    Err(reason) => Err(PgWireError::UserError(Box::new(ErrorInfo::new(
                        "FATAL".to_owned(),
                        "28P01".to_owned(),
                        reason.to_owned(),
                    )))),
                }
            }
            _ => Ok(()),
        }
    }
}

/// Why a server would not start.
#[derive(Debug)]
pub enum StartError {
    /// The bind is reachable from the network and no provider was supplied.
    ///
    /// Refused **before** the socket opens, so the port never exists for the moment
    /// between opening it and objecting.
    RoutableWithoutAuth(SocketAddr),
    Io(std::io::Error),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoutableWithoutAuth(addr) => write!(
                f,
                "{addr} is reachable from the network and no AuthProvider was supplied; \
                 this port serves the audit trail, so it will not open. Supply one, or bind \
                 loopback"
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StartError {}

/// Check a configuration without opening anything.
///
/// Separated from serving so the refusal is testable without a socket, and so a
/// caller can validate a configuration at startup rather than at first connection.
pub fn check(config: &Config, gate: Option<&ReadGate>) -> Result<(), StartError> {
    if config.is_routable() && gate.is_none() {
        return Err(StartError::RoutableWithoutAuth(config.bind));
    }
    Ok(())
}

/// The handler factory: our startup handler, and the gated session as the query path.
pub struct Handlers {
    startup: Arc<Startup>,
    service: Arc<datafusion_postgres::DfSessionService>,
}

impl Debug for Handlers {
    /// Hand-written: neither the service nor the startup handler has a `Debug`, and
    /// the workspace lint warns on a type without one. Prints nothing about either,
    /// because there is nothing a reader would want from them that is not a secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handlers").finish_non_exhaustive()
    }
}

impl Handlers {
    /// The startup handler is ours, the query service is the library's **with our
    /// gate installed as its first hook**.
    ///
    /// The split is the honest one: what may run is ours to be right about, and
    /// encoding forty-two columns including four lists into Postgres wire format is
    /// not a thing to reimplement for the sake of owning it.
    ///
    /// **One of these per connection**, over a session of that connection's own. It
    /// used to be one per server, Arc-cloned into every task, which made the proof
    /// slot behind `trailryx_proof()` process-wide. Passing a session that another
    /// connection also holds puts that back: see [`crate::Session::for_connection`].
    pub fn new(session: &crate::Session, gate: Arc<ReadGate>) -> Self {
        Self {
            startup: Arc::new(Startup { gate }),
            service: session.pg_service(),
        }
    }
}

impl PgWireServerHandlers for Handlers {
    fn simple_query_handler(&self) -> Arc<impl pgwire::api::query::SimpleQueryHandler> {
        Arc::clone(&self.service)
    }

    fn extended_query_handler(&self) -> Arc<impl pgwire::api::query::ExtendedQueryHandler> {
        Arc::clone(&self.service)
    }

    fn startup_handler(&self) -> Arc<impl StartupHandler> {
        Arc::clone(&self.startup)
    }
}

/// Serve until the process ends.
///
/// `check` first, always, so a misconfigured bind is refused before a socket exists.
/// The listener and every connection live on the caller's tokio runtime, which
/// §3.2a requires to be **its own threads**: a facade sharing a core's thread would
/// cost that shard its determinism, and with it the way rare bugs are found here.
pub async fn serve(
    config: Config,
    session: Arc<crate::Session>,
    gate: Option<Arc<ReadGate>>,
) -> Result<(), StartError> {
    check(&config, gate.as_deref())?;
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(StartError::Io)?;
    serve_on(listener, config, session, gate).await
}

/// Serve on a listener somebody else bound.
///
/// Exists so a test can take port zero and learn the address, and so a deployment can
/// hand over a socket it opened under different privileges. The policy check has
/// already happened by then, which is why this one does not repeat it: a listener is
/// past the point where refusing helps.
///
/// The configuration is still taken, and [`Config::bind`] in it is the one field this
/// function ignores, because the socket is already open. [`Config::max_connections`]
/// is kept here and nowhere else.
///
/// # One session per connection
///
/// The `session` handed in is the **template**: it names the sealed segments and
/// whether raw journal access is registered, and each accepted socket gets a session
/// of its own forked from it. That is not tidiness. `trailryx_proof()` reports how
/// provable the last answer on this session was, and until 5 August 2026 one session,
/// one `SessionContext` and one proof slot served every connection in the process, so
/// a client asking about its own partial answer could be told about a stranger's
/// proved one. A reader who believed it would take an unproved answer as proved,
/// through the one function whose entire purpose is to stop exactly that.
///
/// A session forked per connection is also what makes the cap above a memory bound
/// worth having rather than an abstraction: each admitted connection now costs a
/// catalog of its own, so the number of them is a number somebody has to keep.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    config: Config,
    session: Arc<crate::Session>,
    gate: Option<Arc<ReadGate>>,
) -> Result<(), StartError> {
    // With no gate the port is loopback, which `check` has already established. The
    // permissive provider is only reachable in that case and it says so in its name.
    let gate = gate.unwrap_or_else(|| Arc::new(ReadGate::loopback_only()));
    let live = Arc::new(AtomicUsize::new(0));
    loop {
        let (socket, _peer) = listener.accept().await.map_err(StartError::Io)?;

        // Taken before the decision and given back by the guard, so one number answers
        // the question on both sides of it. `>` and not `>=` because this connection is
        // already counted: at a cap of one, the first connection is the one allowed.
        //
        // Decided here rather than inside the task, because a task is the thing being
        // bounded: counting after spawning would bound nothing that had not already
        // happened.
        let taken = live.fetch_add(1, Ordering::AcqRel) + 1;
        let guard = Live(Arc::clone(&live));
        if taken > config.max_connections {
            // The slot goes back before the refusal is written, because a connection
            // being turned away is not occupying one.
            drop(guard);
            tokio::spawn(refuse(socket));
            continue;
        }

        let session = Arc::clone(&session);
        let gate = Arc::clone(&gate);
        tokio::spawn(async move {
            let _guard = guard;
            // Forked inside the task rather than on the accept loop, so a slow
            // registration cannot hold up the next client, and bound to a name rather
            // than left as a temporary, so what keeps this connection's catalog alive
            // is something a reader can see.
            let connection = session.for_connection();
            let handlers = Arc::new(Handlers::new(&connection, gate));
            // One connection failing is one connection failing. A read surface that
            // took the listener down with a client would be a denial of service
            // anybody could perform.
            let _ = pgwire::tokio::process_socket(socket, None, handlers).await;
        });
    }
}

impl ReadGate {
    /// A gate that admits any password, for a loopback bind with no provider.
    ///
    /// Named for what it is rather than called `permissive` or `none`: it is only
    /// reachable when [`check`] has established the bind is loopback, where the port
    /// is the trust boundary. On a routable bind the server refuses to start rather
    /// than reaching for this.
    fn loopback_only() -> Self {
        struct AnyPassword;
        impl AuthProvider for AnyPassword {
            fn authenticate(
                &mut self,
                _credential: &[u8],
            ) -> trailryx_contracts::contracts::AdapterResult<
                trailryx_contracts::contracts::Principal,
            > {
                Ok(trailryx_contracts::contracts::Principal {
                    id: trailryx_record::PrincipalId::parse("user://localhost/loopback")
                        .expect("a constant the identifier grammar accepts"),
                    via: "loopback",
                })
            }
            fn authorize(
                &mut self,
                _p: &trailryx_contracts::contracts::Principal,
                action: Action,
                _scope: &str,
            ) -> Decision {
                // Even here, only querying. A loopback bind is not a reason to hand
                // out every action in the enum.
                if action == Action::Query {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        }
        Self::new(Box::new(AnyPassword), "loopback")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_contracts::contracts::{AdapterResult, Principal};
    use trailryx_record::PrincipalId;

    struct OneReader {
        secret: &'static str,
        scope: &'static str,
    }

    impl AuthProvider for OneReader {
        fn authenticate(&mut self, credential: &[u8]) -> AdapterResult<Principal> {
            if credential == self.secret.as_bytes() {
                Ok(Principal {
                    id: PrincipalId::parse("user://acme.example/reader")
                        .map_err(|_| AdapterError::Rejected("bad id"))?,
                    via: "password",
                })
            } else {
                Err(AdapterError::Rejected("wrong password"))
            }
        }

        fn authorize(&mut self, _p: &Principal, action: Action, scope: &str) -> Decision {
            if action == Action::Query && scope == self.scope {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
    }

    fn gate(scope: &'static str) -> ReadGate {
        ReadGate::new(
            Box::new(OneReader {
                secret: "s3cret",
                scope: "acme",
            }),
            scope,
        )
    }

    #[test]
    fn the_right_password_on_the_right_scope_is_admitted() {
        let g = gate("acme");
        assert_eq!(g.decide(b"s3cret"), Ok(()));
        assert_eq!(g.refusals().rejected, 0);
    }

    #[test]
    fn an_empty_password_never_reaches_the_provider() {
        let g = gate("acme");
        assert!(g.decide(b"").is_err());
        assert_eq!(g.refusals().no_credential, 1);
        assert_eq!(g.refusals().rejected, 0);
    }

    #[test]
    fn a_wrong_password_and_a_wrong_scope_are_both_refused_and_counted_apart() {
        let wrong_password = gate("acme");
        assert!(wrong_password.decide(b"guess").is_err());
        assert_eq!(wrong_password.refusals().rejected, 1);
        assert_eq!(wrong_password.refusals().denied, 0);

        // The right password, and this gate is a DIFFERENT SERVER, standing in front
        // of somebody else's segments. A principal who may read one scope is not
        // thereby admitted to another one's door.
        //
        // Read no further into it than that. Two gates here are two servers, and what
        // is being shown is that each door decides for itself. It is not a server
        // keeping two tenants apart, because no such thing exists on this surface:
        // past either door, every record that server registered is readable. The
        // type's documentation says so at length, because this test is the thing most
        // likely to be mistaken for the feature.
        let wrong_scope = gate("other-tenant");
        assert!(wrong_scope.decide(b"s3cret").is_err());
        assert_eq!(wrong_scope.refusals().denied, 1);
        assert_eq!(wrong_scope.refusals().rejected, 0);
    }

    /// Reading is its own permission. A provider that allows writing must not thereby
    /// allow querying, which is why the gate asks `Action::Query` by name.
    #[test]
    fn permission_to_write_is_not_permission_to_read() {
        struct WriterOnly;
        impl AuthProvider for WriterOnly {
            fn authenticate(&mut self, _c: &[u8]) -> AdapterResult<Principal> {
                Ok(Principal {
                    id: PrincipalId::parse("agent://acme.example/writer").unwrap(),
                    via: "password",
                })
            }
            fn authorize(&mut self, _p: &Principal, action: Action, _s: &str) -> Decision {
                if action == Action::Ingest {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        }
        let g = ReadGate::new(Box::new(WriterOnly), "acme");
        assert!(g.decide(b"anything").is_err());
        assert_eq!(g.refusals().denied, 1);
    }

    /// The failure mode that would turn a crash in authentication into unauthenticated
    /// access to the whole trail. Poisoned on purpose and measured, not asserted.
    #[test]
    fn a_poisoned_provider_denies_every_later_connection() {
        let g = gate("acme");
        let _ = std::panic::catch_unwind(|| {
            let _guard = g.provider.lock().expect("first lock");
            panic!("a provider panicked while holding the lock");
        });
        assert!(g.provider.is_poisoned());
        for _ in 0..3 {
            assert!(
                g.decide(b"s3cret").is_err(),
                "a poisoned gate must never admit"
            );
        }
        assert!(g.refusals().poisoned);
        assert_eq!(g.refusals().unavailable, 3);
    }

    /// No refusal may quote the credential: a Postgres error lands in the client's
    /// log and usually in the server's.
    #[test]
    fn no_refusal_echoes_the_password() {
        let g = gate("other-tenant");
        for password in [b"s3cret".as_slice(), b"leaked-value".as_slice()] {
            if let Err(reason) = g.decide(password) {
                assert!(!reason.contains("s3cret"), "{reason}");
                assert!(!reason.contains("leaked"), "{reason}");
            }
        }
    }

    /// A routable bind with no provider must not open a port. The check runs before
    /// the socket, so the port never exists for the moment between opening it and
    /// objecting, which is what the ingest side had to learn.
    #[test]
    fn a_routable_bind_without_a_provider_refuses_before_the_socket() {
        let routable = Config {
            bind: "192.0.2.1:5432".parse().unwrap(),
            ..Config::default()
        };
        let error = check(&routable, None).expect_err("must refuse");
        assert!(matches!(error, StartError::RoutableWithoutAuth(_)));
        assert!(error.to_string().contains("audit trail"), "{error}");

        // With a provider it passes the policy check. Whether the address binds is a
        // separate question and a later one.
        let g = gate("acme");
        assert!(check(&routable, Some(&g)).is_ok());

        // Loopback with no provider is tolerated, because the port is the boundary.
        assert!(check(&Config::default(), None).is_ok());
    }
}
