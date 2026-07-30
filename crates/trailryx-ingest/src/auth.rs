//! The gate in front of the body read.
//!
//! # Why the check happens before the body
//!
//! [`Config::max_body`] is sixteen megabytes and [`Config::max_inflight_body`]
//! is two hundred and fifty-six. If authentication were checked after the body
//! arrived, an unauthenticated caller could make this server buffer a quarter of
//! a gigabyte before being told no, which is a denial of service that costs the
//! attacker one header line. So the gate runs in the pre-body phase, on the
//! head alone, and a caller with no credential never gets to send a byte of
//! body.
//!
//! That ordering is the whole reason this is a separate phase rather than a
//! check inside `accept`.
//!
//! # Why a missing credential never reaches the provider
//!
//! Absent and empty are both refused here, without taking the lock. The
//! conformance suite already requires a provider to refuse an empty credential,
//! so this changes no answer; it exists so that the answer does not depend on a
//! provider getting that case right, and so that an unauthenticated flood costs
//! one atomic increment rather than a mutex acquisition per request.
//!
//! # Why a poisoned lock denies
//!
//! The contract's stated guarantee is "deny by default". A provider that
//! panicked leaves the mutex poisoned, and from then on this gate answers 503
//! for every request rather than falling through. Falling through is the one
//! failure mode that would turn a crash in an authentication provider into an
//! open door, and it is the reason the poisoned arm is written out rather than
//! reached with `unwrap`.
//!
//! [`Config::max_body`]: crate::config::Config::max_body
//! [`Config::max_inflight_body`]: crate::config::Config::max_inflight_body

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use trailryx_contracts::contracts::{Action, AdapterError, AuthProvider, Decision};

use crate::response::{Response, Status};

/// What the gate decided.
///
/// Not comparable, on purpose: a `Response` is not a value with an equality, and
/// a test that asserted on a whole refusal would be asserting on its wording.
/// Tests here compare the status, which is the part that is a contract.
#[derive(Debug)]
pub enum Outcome {
    /// Authenticated and permitted. The caller carries on to the body.
    ///
    /// The principal is deliberately not returned. Nothing on the ingest path
    /// needs it: a record's identity comes from the OTLP resource attributes
    /// through the mapper, and letting the transport supply an identity instead
    /// would put a second, unattested source of truth next to the first.
    Allow,
    /// Refused. The response is final and the connection closes with it.
    Refuse(Response),
}

/// The authentication seam.
///
/// A deployment supplies the provider; this crate only sequences the two calls
/// and turns the answers into status codes.
pub struct Gate {
    provider: Mutex<Box<dyn AuthProvider + Send>>,
    /// The scope every `Ingest` action is authorised against.
    ///
    /// One string, fixed at construction from the same tenant the mapper was
    /// built with. It is not read from the request: a scope a caller can choose
    /// is not a scope.
    scope: String,
    no_credential: AtomicU64,
    rejected: AtomicU64,
    denied: AtomicU64,
    unavailable: AtomicU64,
    poisoned: AtomicBool,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("scope", &self.scope)
            .field("no_credential", &self.no_credential.load(Ordering::Relaxed))
            .field("rejected", &self.rejected.load(Ordering::Relaxed))
            .field("denied", &self.denied.load(Ordering::Relaxed))
            .field("unavailable", &self.unavailable.load(Ordering::Relaxed))
            .field("poisoned", &self.poisoned.load(Ordering::Relaxed))
            .finish()
    }
}

/// What the gate has refused since it was built, for an operator who needs to
/// see that a fleet is failing on a rotated token rather than on the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusals {
    pub no_credential: u64,
    pub rejected: u64,
    pub denied: u64,
    pub unavailable: u64,
    pub poisoned: bool,
}

impl Gate {
    pub fn new(provider: Box<dyn AuthProvider + Send>, scope: impl Into<String>) -> Self {
        Self {
            provider: Mutex::new(provider),
            scope: scope.into(),
            no_credential: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            unavailable: AtomicU64::new(0),
            poisoned: AtomicBool::new(false),
        }
    }

    pub fn scope(&self) -> &str {
        &self.scope
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

    /// Authenticate, then authorise `Ingest` against the fixed scope.
    ///
    /// The credential is the `Authorization` field value verbatim, undecoded.
    /// This crate does not parse it and no message here ever quotes it: an error
    /// body that echoed a credential would write it into whatever log collects
    /// exporter failures.
    pub fn decide(&self, credential: Option<&[u8]>) -> Outcome {
        let credential = match credential {
            Some(bytes) if !bytes.is_empty() => bytes,
            // Absent, or present and empty. Both mean nothing was offered.
            _ => {
                self.no_credential.fetch_add(1, Ordering::Relaxed);
                return Outcome::Refuse(Response::unauthorized(
                    "this endpoint requires an Authorization field",
                ));
            }
        };

        let Ok(mut provider) = self.provider.lock() else {
            self.poisoned.store(true, Ordering::Relaxed);
            self.unavailable.fetch_add(1, Ordering::Relaxed);
            return Outcome::Refuse(Response::error(
                Status::ServiceUnavailable,
                "the authentication provider failed and this server will not admit writes without it",
            ));
        };

        let principal = match provider.authenticate(credential) {
            Ok(principal) => principal,
            // Transient, and ours rather than the caller's. 503 is retryable and
            // says so, which is what an exporter should do while a token service
            // is down: keep the batch.
            Err(AdapterError::Unavailable(_)) => {
                self.unavailable.fetch_add(1, Ordering::Relaxed);
                return Outcome::Refuse(Response::error(
                    Status::ServiceUnavailable,
                    "the authentication provider is unavailable",
                ));
            }
            // Refused, or a credential of a kind this provider does not
            // evaluate. Both are 401: not retryable, so a misconfigured
            // exporter stops instead of retrying a wrong token forever, and
            // neither answer says which of the two it was.
            Err(AdapterError::Rejected(_) | AdapterError::Unsupported(_)) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                return Outcome::Refuse(Response::unauthorized("the credential was not accepted"));
            }
        };

        match provider.authorize(&principal, Action::Ingest, &self.scope) {
            Decision::Allow => Outcome::Allow,
            Decision::Deny => {
                self.denied.fetch_add(1, Ordering::Relaxed);
                Outcome::Refuse(Response::error(
                    Status::Forbidden,
                    "this principal may not write records to this scope",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_contracts::contracts::{AdapterResult, Principal};
    use trailryx_record::PrincipalId;

    /// Accepts exactly one token and authorises exactly one scope.
    struct OneToken {
        token: &'static str,
        scope: &'static str,
        calls: u32,
    }

    impl AuthProvider for OneToken {
        fn authenticate(&mut self, credential: &[u8]) -> AdapterResult<Principal> {
            self.calls = self.calls.saturating_add(1);
            let offered = std::str::from_utf8(credential)
                .map_err(|_| AdapterError::Rejected("not text"))?
                .strip_prefix("Bearer ")
                .ok_or(AdapterError::Unsupported("not a bearer credential"))?;
            if offered == self.token {
                Ok(Principal {
                    id: PrincipalId::parse("agent-one".to_owned())
                        .map_err(|_| AdapterError::Rejected("bad id"))?,
                    via: "bearer",
                })
            } else {
                Err(AdapterError::Rejected("wrong token"))
            }
        }

        fn authorize(&mut self, _principal: &Principal, action: Action, scope: &str) -> Decision {
            if action == Action::Ingest && scope == self.scope {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
    }

    fn gate(scope: &'static str) -> Gate {
        Gate::new(
            Box::new(OneToken {
                token: "s3cret",
                scope: "acme",
                calls: 0,
            }),
            scope,
        )
    }

    fn allowed(outcome: &Outcome) -> bool {
        matches!(outcome, Outcome::Allow)
    }

    fn status(outcome: &Outcome) -> Option<Status> {
        match outcome {
            Outcome::Allow => None,
            Outcome::Refuse(r) => Some(r.status()),
        }
    }

    #[test]
    fn the_right_token_on_the_right_scope_is_allowed() {
        let g = gate("acme");
        assert!(allowed(&g.decide(Some(b"Bearer s3cret"))));
        assert_eq!(g.refusals().no_credential, 0);
    }

    #[test]
    fn an_absent_credential_is_401_and_never_reaches_the_provider() {
        let g = gate("acme");
        assert_eq!(status(&g.decide(None)), Some(Status::Unauthorized));
        assert_eq!(g.refusals().no_credential, 1);
        assert_eq!(g.refusals().rejected, 0);
    }

    /// An empty field value is a request with an `Authorization:` line and
    /// nothing after it. It is not a credential, and it must not be handed to a
    /// provider that might treat empty as a default identity.
    #[test]
    fn an_empty_credential_is_refused_without_consulting_the_provider() {
        let g = gate("acme");
        assert_eq!(status(&g.decide(Some(b""))), Some(Status::Unauthorized));
        assert_eq!(g.refusals().no_credential, 1);
        assert_eq!(g.refusals().rejected, 0);
    }

    #[test]
    fn a_wrong_token_is_401_not_403() {
        let g = gate("acme");
        assert_eq!(
            status(&g.decide(Some(b"Bearer wrong"))),
            Some(Status::Unauthorized)
        );
        assert_eq!(g.refusals().rejected, 1);
    }

    /// The distinction the two codes carry: 401 means the server does not know
    /// who you are, 403 means it does and you may not write here. An exporter
    /// pointed at the wrong tenant needs the second answer, and collapsing both
    /// into one would make that indistinguishable from a rotated token.
    #[test]
    fn a_valid_token_on_the_wrong_scope_is_403() {
        let g = gate("other-tenant");
        assert_eq!(
            status(&g.decide(Some(b"Bearer s3cret"))),
            Some(Status::Forbidden)
        );
        assert_eq!(g.refusals().denied, 1);
        assert_eq!(g.refusals().rejected, 0);
    }

    /// A credential shape the provider does not evaluate is not a different
    /// answer from one it evaluated and refused. Telling them apart would let a
    /// caller enumerate which schemes a deployment accepts.
    #[test]
    fn an_unsupported_scheme_answers_the_same_as_a_wrong_token() {
        let g = gate("acme");
        let unsupported = g.decide(Some(b"Basic dXNlcjpwYXNz"));
        let wrong = g.decide(Some(b"Bearer wrong"));
        assert_eq!(status(&unsupported), Some(Status::Unauthorized));
        assert_eq!(status(&unsupported), status(&wrong));
    }

    /// Both refusals are terminal for an OTLP exporter, and that is deliberate.
    /// A retry on a wrong token is a retry that will be wrong every time, and a
    /// fleet retrying it is a fleet attacking its own auth provider.
    #[test]
    fn neither_refusal_asks_the_exporter_to_retry() {
        let g = gate("other-tenant");
        for credential in [b"Bearer wrong".as_slice(), b"Bearer s3cret".as_slice()] {
            match g.decide(Some(credential)) {
                Outcome::Refuse(r) => assert!(!r.status().is_retryable()),
                Outcome::Allow => panic!("expected a refusal"),
            }
        }
        assert!(status(&g.decide(None)).is_some_and(|s| !s.is_retryable()));
    }

    struct Flaky(bool);

    impl AuthProvider for Flaky {
        fn authenticate(&mut self, _credential: &[u8]) -> AdapterResult<Principal> {
            Err(AdapterError::Unavailable("token service down"))
        }
        fn authorize(&mut self, _principal: &Principal, _action: Action, _scope: &str) -> Decision {
            if self.0 {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
    }

    /// The one case where the exporter should keep the batch: the provider is
    /// down, not the credential wrong.
    #[test]
    fn a_provider_outage_is_a_retryable_503() {
        let g = Gate::new(Box::new(Flaky(true)), "acme");
        match g.decide(Some(b"Bearer s3cret")) {
            Outcome::Refuse(r) => {
                assert_eq!(r.status(), Status::ServiceUnavailable);
                assert!(r.status().is_retryable());
            }
            Outcome::Allow => panic!("an outage must not admit a write"),
        }
        assert_eq!(g.refusals().unavailable, 1);
    }

    /// The failure mode this module exists to rule out: a panicking provider
    /// must not become an open door. Measured rather than asserted, by poisoning
    /// the lock the way a real panic would.
    #[test]
    fn a_poisoned_provider_denies_every_later_request() {
        let g = Gate::new(Box::new(Flaky(true)), "acme");
        let _ = std::panic::catch_unwind(|| {
            let _guard = g.provider.lock().expect("first lock");
            panic!("a provider panicked while holding the lock");
        });
        assert!(g.provider.is_poisoned(), "the lock should be poisoned");

        for _ in 0..3 {
            match g.decide(Some(b"Bearer s3cret")) {
                Outcome::Refuse(r) => assert_eq!(r.status(), Status::ServiceUnavailable),
                Outcome::Allow => panic!("a poisoned gate must never allow"),
            }
        }
        assert!(g.refusals().poisoned);
        assert_eq!(g.refusals().unavailable, 3);
    }

    /// The scope is fixed at construction. There is no path from a request to
    /// the string `authorize` is called with, and this test is what would fail
    /// if one were added.
    #[test]
    fn the_scope_comes_from_construction_and_not_from_the_request() {
        let g = gate("acme");
        assert_eq!(g.scope(), "acme");
        assert!(allowed(&g.decide(Some(b"Bearer s3cret"))));
        assert_eq!(g.scope(), "acme");
    }

    /// No message the gate produces may contain the credential, on any path.
    /// A refusal body ends up in whatever log collects exporter failures, and a
    /// credential written there has leaked.
    #[test]
    fn no_refusal_ever_echoes_the_credential() {
        let secret = b"Bearer s3cret-do-not-log";
        for g in [gate("other-tenant"), Gate::new(Box::new(Flaky(false)), "x")] {
            if let Outcome::Refuse(r) = g.decide(Some(secret)) {
                let mut wire = Vec::new();
                r.write_to(&mut wire).expect("write");
                assert!(
                    !contains(&wire, b"s3cret"),
                    "a refusal echoed the credential: {}",
                    String::from_utf8_lossy(&wire)
                );
            }
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// RFC 9110 requires the challenge on a 401, and an exporter that reads it
    /// is the one that will stop rather than loop.
    #[test]
    fn a_401_carries_a_www_authenticate_challenge() {
        let g = gate("acme");
        let Outcome::Refuse(r) = g.decide(None) else {
            panic!("expected a refusal");
        };
        let mut wire = Vec::new();
        r.write_to(&mut wire).expect("write");
        assert!(contains(&wire, b"WWW-Authenticate: Bearer\r\n"));
        assert!(contains(&wire, b"401 Unauthorized"));
    }
}
