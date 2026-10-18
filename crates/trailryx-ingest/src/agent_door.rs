//! The agent-token door: an [`AuthProvider`] that knows which agent is calling.
//!
//! # What it replaces, and why
//!
//! [`crate::bearer::SharedSecret`] authenticates a fleet. Every exporter that
//! holds the secret is one principal, and the agent a record is about comes
//! from attributes the exporter wrote, so any holder of the secret can write
//! records in any agent's name. That is the shape of a credential, not a bug in
//! one, and no amount of care with the secret changes it.
//!
//! This door takes each agent's own access token, issued by vouchryx and bound
//! to a key only that agent holds, with a proof of possession made for this
//! request. It verifies both offline against the issuer's public keys,
//! exactly as tokenfuse and agent-stack-go do (see [`crate::agent_token`]), and
//! the principal is the token's `sub`. The gate it builds then binds every
//! record in the request to that agent: a span naming anybody else is refused,
//! and the refusal is itself a record under the caller's name.
//!
//! @decided 2026-10-18: the record plane's ingest door learns which agent is
//! calling from that agent's own access token, issued by vouchryx and verified
//! offline at the door, and it refuses to write a record that names a different
//! agent. Opt-in: without the flags the door is what it was.
//!
//! # What is configured, and what is refused at startup
//!
//! The issuer, the audience, the issuer's key set, the origin this door is
//! reached at, and the operator's trust domain. Each is refused when it could
//! not do its job: an empty issuer or audience (an empty audience would accept
//! a token minted for any resource), a key set with no EC P-256 key or with a
//! private member in it, an origin that is anything but a scheme and an
//! authority, and a trust domain that is not one. A door that started anyway
//! would refuse every agent or, worse, admit some it should not.
//!
//! # The origin, and why it is configured rather than read
//!
//! A proof is signed over the URL the agent addressed. Behind the terminating
//! proxy this server requires on a routable bind, that URL's scheme and
//! authority are the proxy's, and the `Host` field is something the request
//! says about itself. So the origin is configuration and the path is what the
//! request line carried, still encoded.
//!
//! # What it does not do
//!
//! No revocation list: the shared table's hook is wired to one that answers
//! false, and a token is good for its five minutes once issued. No server
//! nonce (RFC 9449 section 8). The replay cache is per process and in memory,
//! which [`crate::agent_token`] says plainly where it is defined.

use trailryx_contracts::contracts::{
    Action, AdapterError, AdapterResult, AuthProvider, Decision, Principal, RequestContext,
};
use trailryx_record::{AgentId, PrincipalId};

use crate::agent_token::{self, JwksError, KeySet, Policy, Refusal, ReplayCache, Request};
use crate::auth::Gate;

/// The challenge a 401 carries at this door (RFC 9449 section 7.1).
pub const DPOP_CHALLENGE: &str = "DPoP algs=\"ES256\"";

/// Proofs remembered per generation of the replay cache. Two generations of
/// two minutes each, so a door holds at most twice this many: about seventy
/// proofs a second sustained for a whole generation before it refuses, which
/// is a fleet of hundreds of agents each exporting every few seconds. A full
/// cache answers 503, which an exporter retries.
pub const DEFAULT_REPLAY_CAP: usize = 16_384;

const SCHEME: &str = "dpop ";

/// What an operator configures. Every field is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorConfig {
    /// The exact `iss` an agent's token must carry.
    pub issuer: String,
    /// The exact `aud` an agent's token must name: this door's resource.
    pub audience: String,
    /// `scheme://authority`, as agents address this door. The request path is
    /// joined to it to make the URL a proof must name.
    pub origin: String,
    /// The operator's trust domain. A token for an agent outside it is a valid
    /// token for an agent this store does not write for.
    pub trust_domain: String,
    /// The tenant scope `Ingest` is authorised against.
    pub scope: String,
    /// Proofs remembered per generation; see [`DEFAULT_REPLAY_CAP`].
    pub replay_cap: usize,
}

/// Why a door was not built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoorError {
    NoIssuer,
    NoAudience,
    Origin,
    TrustDomain,
    ReplayCap,
    Jwks(JwksError),
}

impl std::fmt::Display for DoorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoIssuer => f.write_str("the issuer is empty"),
            Self::NoAudience => f.write_str(
                "the audience is empty, and a door with none would accept a token minted for any resource",
            ),
            Self::Origin => f.write_str(
                "the origin must be scheme://authority and nothing else, as agents address this door",
            ),
            Self::TrustDomain => f.write_str("the trust domain is not a usable identifier segment"),
            Self::ReplayCap => f.write_str("the replay cache cannot hold zero proofs"),
            Self::Jwks(e) => write!(f, "the issuer's key set: {e}"),
        }
    }
}

impl std::error::Error for DoorError {}

/// The provider. Held behind the gate's lock, like any other.
pub struct AgentTokenDoor {
    policy: Policy,
    origin: String,
    /// `agent://<trust domain>/`, the prefix every principal admitted here has.
    domain_prefix: String,
    scope: String,
    replay: ReplayCache,
    /// Whole seconds, supplied by the embedding binary: this crate never reads
    /// a clock.
    clock: Box<dyn Fn() -> i64 + Send>,
}

impl std::fmt::Debug for AgentTokenDoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentTokenDoor")
            .field("issuer", &self.policy.issuer)
            .field("audience", &self.policy.audience)
            .field("keys", &self.policy.keys.usable())
            .field("origin", &self.origin)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl AgentTokenDoor {
    /// `jwks` is the issuer's key set as the file holds it.
    pub fn new(
        config: DoorConfig,
        jwks: &[u8],
        clock: Box<dyn Fn() -> i64 + Send>,
    ) -> Result<Self, DoorError> {
        if config.issuer.is_empty() {
            return Err(DoorError::NoIssuer);
        }
        if config.audience.is_empty() {
            return Err(DoorError::NoAudience);
        }
        if !is_origin(&config.origin) {
            return Err(DoorError::Origin);
        }
        // The same construction the mapper validates its trust domain with, so
        // the two cannot disagree about what a domain is.
        let domain_prefix = format!("agent://{}/", config.trust_domain);
        if AgentId::parse_strict(format!("{domain_prefix}x")).is_err()
            || config.trust_domain.contains('/')
        {
            return Err(DoorError::TrustDomain);
        }
        if config.replay_cap == 0 {
            return Err(DoorError::ReplayCap);
        }
        let keys = KeySet::from_jwks(jwks).map_err(DoorError::Jwks)?;
        Ok(Self {
            policy: Policy {
                keys,
                issuer: config.issuer,
                audience: config.audience,
            },
            origin: config.origin,
            domain_prefix,
            scope: config.scope,
            replay: ReplayCache::new(config.replay_cap),
            clock,
        })
    }

    /// The gate this door belongs behind: it binds every record in a request to
    /// the agent that sent it, and its 401 names the DPoP scheme.
    pub fn into_gate(self) -> Gate {
        let scope = self.scope.clone();
        Gate::new(Box::new(self), scope)
            .binding_records_to_the_caller()
            .with_challenge(DPOP_CHALLENGE)
    }
}

/// `scheme://authority`: a scheme, then an authority with no userinfo, and
/// nothing after it, not even a slash.
fn is_origin(origin: &str) -> bool {
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    let mut scheme_chars = scheme.bytes();
    scheme_chars.next().is_some_and(|b| b.is_ascii_alphabetic())
        && scheme_chars.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        && !authority.is_empty()
        && !authority
            .bytes()
            .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@') || b <= b' ' || b >= 0x7f)
}

/// Case-insensitive on the scheme, byte-exact on the token, as
/// [`crate::bearer`] reads its own.
fn strip_scheme(credential: &[u8]) -> Option<&[u8]> {
    let (head, rest) = credential.split_at_checked(SCHEME.len())?;
    head.eq_ignore_ascii_case(SCHEME.as_bytes()).then_some(rest)
}

impl AuthProvider for AgentTokenDoor {
    /// Never: a proof is signed over the request, so a credential alone cannot
    /// be checked. The gate asks [`Self::authenticate_request`].
    fn authenticate(&mut self, _credential: &[u8]) -> AdapterResult<Principal> {
        Err(AdapterError::Unsupported(
            "an agent's token is verified against the request it arrived on",
        ))
    }

    fn authenticate_request(&mut self, request: &RequestContext<'_>) -> AdapterResult<Principal> {
        let credential = request
            .header("authorization")
            .ok_or(AdapterError::Rejected("no credential"))?;
        // RFC 9449 section 7.2: a bound token presented as a bearer token is
        // refused, or the proof is optional and the binding is decoration.
        let token = strip_scheme(credential).ok_or(AdapterError::Unsupported(
            "this door takes the DPoP scheme only",
        ))?;
        let token = std::str::from_utf8(token)
            .map_err(|_| AdapterError::Rejected(Refusal::Malformed.as_str()))?;
        let proof = match request.header("dpop") {
            Some(bytes) => Some(
                std::str::from_utf8(bytes)
                    .map_err(|_| AdapterError::Rejected(Refusal::WrongKey.as_str()))?,
            ),
            None => None,
        };
        let url = format!("{}{}", self.origin, request.path);
        let presented = Request {
            token,
            proof,
            method: request.method,
            url: &url,
            now: (self.clock)(),
        };
        // No revocation list at this door: the hook the shared rules ask for is
        // answered here, out loud, rather than left out.
        let no_revocation_list = |_: &str, _: &str, _: i64| false;
        let verified = agent_token::verify(
            &self.policy,
            &presented,
            &mut self.replay,
            &no_revocation_list,
        )
        .map_err(|refusal| match refusal {
            // The one refusal that will not be the same on retry.
            Refusal::ReplayCacheFull => AdapterError::Unavailable(refusal.as_str()),
            other => AdapterError::Rejected(other.as_str()),
        })?;
        let id = PrincipalId::parse_strict(verified.subject).map_err(|_| {
            AdapterError::Rejected("the token's subject is not an identifier this store can hold")
        })?;
        Ok(Principal {
            id,
            via: "agent-token",
        })
    }

    /// `Ingest` on the configured scope, for an agent in the configured trust
    /// domain, and nothing else. Invariant 35 at this door: the issuer may
    /// vouch for agents of many domains, and this store writes for one.
    fn authorize(&mut self, principal: &Principal, action: Action, scope: &str) -> Decision {
        match action {
            Action::Ingest
                if scope == self.scope
                    && principal.id.as_str().starts_with(&self.domain_prefix) =>
            {
                Decision::Allow
            }
            _ => Decision::Deny,
        }
    }
}

/// The four flags, as a binary received them.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentTokenFlags<'a> {
    pub issuer: Option<&'a str>,
    pub audience: Option<&'a str>,
    /// A path: the key set is read from a file.
    pub jwks: Option<&'a str>,
    pub origin: Option<&'a str>,
}

impl AgentTokenFlags<'_> {
    pub fn any(&self) -> bool {
        self.issuer.is_some()
            || self.audience.is_some()
            || self.jwks.is_some()
            || self.origin.is_some()
    }
}

/// The help text both binaries print for the flags, written once.
pub const FLAGS_HELP: &str = "\
--agent-token-issuer URL     the exact iss an agent's own access token carries
--agent-token-audience AUD   the exact aud it must name: this door's resource
--agent-token-jwks PATH      the issuer's public keys, as a JWK Set file
--agent-token-origin URL     scheme://authority, as agents address this door
                             The four go together. Each agent then presents
                             `Authorization: DPoP <token>` and a `DPoP` proof,
                             both verified offline, and a span naming any other
                             agent is refused and written down as a refusal.";

/// Build the gate from the flags: `Ok(None)` when none was given, an error that
/// names the flag when only some were, or when the door would not start.
///
/// Both `trailryx-ingest` and `trailryx-node run` call this, so the two cannot
/// drift on what the flags mean or what is refused.
pub fn gate_from_flags(
    flags: AgentTokenFlags<'_>,
    scope: &str,
    trust_domain: &str,
    clock: Box<dyn Fn() -> i64 + Send>,
) -> Result<Option<Gate>, String> {
    if !flags.any() {
        return Ok(None);
    }
    let issuer = required(flags.issuer, "--agent-token-issuer")?;
    let audience = required(flags.audience, "--agent-token-audience")?;
    let path = required(flags.jwks, "--agent-token-jwks")?;
    let origin = required(flags.origin, "--agent-token-origin")?;
    let jwks =
        std::fs::read(path).map_err(|e| format!("cannot read --agent-token-jwks {path}: {e}"))?;
    let door = AgentTokenDoor::new(
        DoorConfig {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            origin: origin.to_owned(),
            trust_domain: trust_domain.to_owned(),
            scope: scope.to_owned(),
            replay_cap: DEFAULT_REPLAY_CAP,
        },
        &jwks,
        clock,
    )
    .map_err(|e| format!("the agent-token door will not start: {e}"))?;
    Ok(Some(door.into_gate()))
}

fn required<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("{name} is required with the other --agent-token-* flags"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scheme_is_case_insensitive_and_the_token_is_exact() {
        for prefix in ["DPoP ", "dpop ", "DPOP "] {
            assert_eq!(
                strip_scheme(format!("{prefix}abc").as_bytes()),
                Some(&b"abc"[..])
            );
        }
        assert_eq!(strip_scheme(b"DPoP  abc"), Some(&b" abc"[..]));
        assert_eq!(strip_scheme(b"Bearer abc"), None);
        assert_eq!(strip_scheme(b"DPo"), None);
    }

    #[test]
    fn an_origin_is_a_scheme_and_an_authority() {
        for good in [
            "https://ingest.acme.example",
            "http://127.0.0.1:4318",
            "https://[::1]:4318",
        ] {
            assert!(is_origin(good), "{good}");
        }
        for bad in [
            "https://ingest.acme.example/",
            "ingest.acme.example",
            "://x",
            "1https://x",
            "https://a b",
        ] {
            assert!(!is_origin(bad), "{bad}");
        }
    }

    #[test]
    fn some_flags_without_the_rest_name_what_is_missing() {
        let clock = || -> Box<dyn Fn() -> i64 + Send> { Box::new(|| 0) };
        assert!(matches!(
            gate_from_flags(AgentTokenFlags::default(), "acme", "acme.example", clock()),
            Ok(None)
        ));
        let partial = AgentTokenFlags {
            issuer: Some("https://vouchryx.acme.example"),
            audience: Some("https://ingest.acme.example"),
            ..AgentTokenFlags::default()
        };
        let Err(why) = gate_from_flags(partial, "acme", "acme.example", clock()) else {
            panic!("a partial set of flags built a door");
        };
        assert!(why.contains("--agent-token-jwks"), "{why}");
    }
}
