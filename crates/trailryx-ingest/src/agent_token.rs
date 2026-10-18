//! An agent's own access token, and the proof presented with it, verified
//! offline.
//!
//! vouchryx issues each agent a five-minute access token: a JWS typed `at+jwt`
//! (RFC 9068), signed ES256, and bound by `cnf.jkt` to a key only the agent
//! holds (RFC 9449). The agent presents it with a fresh proof of possession,
//! a second JWS it signs per request over the method, the URL and the token's
//! own hash. Every door in the estate checks the pair locally, from the
//! issuer's key set, with no call to anybody.
//!
//! # The same rules as the other two doors, and how that is known
//!
//! tokenfuse (Rust) and agent-stack-go (Go) already verify these tokens. This
//! is a third verifier, and a third verifier is only worth having if it agrees
//! with the other two on every case somebody thought to write down. The
//! estate's shared table, vendored byte for byte under `tests/vectors/`, is
//! that list, and `tests/it/agent_token_vectors.rs` requires every case's
//! stated answer. The order of the checks below is the order the Go verifier
//! makes them in, because the order decides which refusal a malformed
//! presentation gets, and the table pins refusals rather than only refusing.
//!
//! # What a refusal tells the caller
//!
//! Nothing. [`Refusal`] is for an operator's counters and for the table; the
//! door turns every one of them into the same 401, because a verifier that
//! narrates which check failed is an oracle for whoever is probing it.
//!
//! # Where it says nothing
//!
//! The replay cache is per process and in memory, as it is in the other two:
//! two doors behind one balancer each remember their own, so a proof used at
//! one can be presented once at the other inside its sixty seconds, and a
//! restart forgets everything for one generation. Closing that needs shared
//! state, which is a deployment decision rather than a type.

use std::collections::BTreeSet;

use crate::jose::{Compact, EcKey, Json, access_token_hash, has_private_member};

/// The JWS `typ` of an agent's own access token, checked exactly: not `JWT`,
/// and not the long form `application/at+jwt`.
pub const AGENT_TOKEN_TYP: &str = "at+jwt";
/// The JWS `typ` of a proof of possession.
pub const PROOF_TYP: &str = "dpop+jwt";
/// How far past `exp` a token still verifies, and how far ahead of this clock
/// its `iat` may be. A tenth of a five-minute life.
pub const LEEWAY_SECS: i64 = 30;
/// How far a proof's `iat` may sit from this clock, either way.
pub const PROOF_WINDOW_SECS: i64 = 60;
/// The longest proof `jti` a door will remember. The caller chooses it, and
/// the replay cache stores it.
pub const MAX_PROOF_JTI_BYTES: usize = 256;
/// One generation of the replay cache: two proof windows, because a proof's
/// `iat` may be a window ahead of now and now a window past its `iat`.
pub const REPLAY_GENERATION_SECS: i64 = 2 * PROOF_WINDOW_SECS;

/// Why a presentation was refused, in the shared table's vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not this kind of token: the wrong `typ`, no `kid`, a subject that is not
    /// an agent or is not its own client, no `jti`, an `act` claim, or a claim
    /// of the wrong type.
    Malformed,
    /// No key in the set verifies it: an unknown `kid`, another key's
    /// signature, or an algorithm the key does not permit.
    BadSignature,
    Issuer,
    /// `aud` does not name this door, or this door names no audience.
    Audience,
    Expired,
    NotYetValid,
    /// No `cnf.jkt`: a bearer token, which this door does not take.
    NotBound,
    /// A bound token with no proof.
    NoProof,
    /// The proof fails, is by another key, or names another token.
    WrongKey,
    Revoked,
    /// This proof was presented before, inside its window.
    Replayed,
    /// The replay cache is at its cap, so single use cannot be promised.
    /// Transient, unlike every other refusal here.
    ReplayCacheFull,
}

impl Refusal {
    /// The table's name for it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::NotBound => "not_bound",
            Self::NoProof => "no_proof",
            Self::WrongKey => "wrong_key",
            Self::Revoked => "revoked",
            Self::Replayed => "replay",
            Self::ReplayCacheFull => "replay_cache_full",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// The issuer's keys
// ---------------------------------------------------------------------------

/// Why a key set could not be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwksError {
    NotJson,
    /// Not `{"keys": [...]}`.
    NotAKeySet,
    /// A key carries a member only its holder should have.
    PrivateMember,
    /// Two keys share a `kid`, so a token naming it could be checked against
    /// either, depending on the order of a file.
    DuplicateKid,
    /// No key a token could be verified with: no EC P-256 key with a `kid`.
    NoUsableKey,
}

impl std::fmt::Display for JwksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotJson => "the key set is not JSON",
            Self::NotAKeySet => "the key set is not an object with a keys array",
            Self::PrivateMember => "a key in the set carries a private member",
            Self::DuplicateKid => "two keys in the set share a kid",
            Self::NoUsableKey => "the set holds no EC P-256 key with a kid",
        })
    }
}

impl std::error::Error for JwksError {}

#[derive(Debug, Clone)]
struct IssuerKey {
    kid: String,
    /// `None` for a key of any other kind: kept, so a token naming it is
    /// refused as unverifiable rather than as unknown, which is the answer the
    /// other doors give.
    ec: Option<EcKey>,
}

/// The issuer's public keys, held locally. More than one during a rotation;
/// a token's `kid` names the one that verifies it.
#[derive(Debug, Clone)]
pub struct KeySet {
    keys: Vec<IssuerKey>,
}

impl KeySet {
    /// A JWK Set (RFC 7517 section 5).
    ///
    /// Refused outright, rather than loaded with the bad part left out: a key
    /// carrying a private member, two keys with one `kid`, and a set with no
    /// key this door can verify with. Each is a configuration somebody should
    /// hear about before the port opens.
    pub fn from_jwks(bytes: &[u8]) -> Result<Self, JwksError> {
        let doc = Json::parse(bytes).ok_or(JwksError::NotJson)?;
        let Some(Json::Arr(items)) = doc.get("keys") else {
            return Err(JwksError::NotAKeySet);
        };
        let mut keys: Vec<IssuerKey> = Vec::new();
        for item in items {
            if !item.is_object() {
                return Err(JwksError::NotAKeySet);
            }
            if has_private_member(item) {
                return Err(JwksError::PrivateMember);
            }
            // A key with no kid can never be named, so it can never verify.
            let Some(kid) = item
                .get("kid")
                .and_then(Json::as_str)
                .filter(|k| !k.is_empty())
            else {
                continue;
            };
            if keys.iter().any(|k| k.kid == kid) {
                return Err(JwksError::DuplicateKid);
            }
            keys.push(IssuerKey {
                kid: kid.to_owned(),
                ec: EcKey::from_jwk(item),
            });
        }
        if !keys.iter().any(|k| k.ec.is_some()) {
            return Err(JwksError::NoUsableKey);
        }
        Ok(Self { keys })
    }

    /// How many keys a token could be verified with.
    pub fn usable(&self) -> usize {
        self.keys.iter().filter(|k| k.ec.is_some()).count()
    }

    /// By `kid` and never by trying each key in turn: trying them all would make
    /// one compromised key a skeleton key for every other.
    fn find(&self, kid: &str) -> Option<&IssuerKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// What a door holds before any token arrives.
#[derive(Debug, Clone)]
pub struct Policy {
    pub keys: KeySet,
    /// The exact `iss` required.
    pub issuer: String,
    /// The exact `aud` required, and required: an empty audience refuses every
    /// token rather than accepting any.
    pub audience: String,
}

/// One presentation: what the caller sent, and what this server received.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub token: &'a str,
    pub proof: Option<&'a str>,
    /// What THIS server received, never what the proof says: comparing a proof
    /// with itself is no check at all.
    pub method: &'a str,
    /// The URL this door is reached at, as the agent addressed it.
    pub url: &'a str,
    /// This door's clock, in whole seconds.
    pub now: i64,
}

/// What a door may rely on once a token and its proof verified. Every field
/// is signed by the issuer, or by the agent's bound key, or derived from one
/// of those.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAgent {
    /// `sub`: an `agent://` URI, equal to the token's `client_id`.
    pub subject: String,
    pub unit: String,
    pub org: String,
    pub jti: String,
    pub jkt: String,
    /// The proof's `jti`, already recorded as used. Empty when relayed.
    pub proof_jti: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// The revocation hook: asked last, with the token's `jti`, its agent and its
/// `iat`. A door with no revocation list says so with one that answers false.
pub type Revoked<'a> = &'a dyn Fn(&str, &str, i64) -> bool;

/// Verify an agent's token and its proof, at a door, and record the proof as
/// used.
///
/// The token's checks first; then the proof, which must verify for this
/// request at this moment, carry a `jti` short enough to remember, be signed
/// by the key the token is bound to, and name THIS token in its `ath`; then the
/// revocation hook; and only then the replay cache, so a proof spent on a
/// refused presentation is not spent at all and nobody who cannot sign for a
/// bound key can fill the cache.
pub fn verify(
    policy: &Policy,
    request: &Request<'_>,
    replay: &mut ReplayCache,
    revoked: Revoked<'_>,
) -> Result<VerifiedAgent, Refusal> {
    let claims = token_claims(policy, request.token, request.now)?;
    let Some(proof) = request.proof.filter(|p| !p.is_empty()) else {
        return Err(Refusal::NoProof);
    };
    if request.method.is_empty() || request.url.is_empty() {
        return Err(Refusal::NoProof);
    }
    let proof =
        verify_proof(proof, request.method, request.url, request.now).ok_or(Refusal::WrongKey)?;
    if proof.jti.len() > MAX_PROOF_JTI_BYTES {
        return Err(Refusal::WrongKey);
    }
    if proof.thumbprint != claims.jkt {
        return Err(Refusal::WrongKey);
    }
    if proof.ath != access_token_hash(request.token) {
        return Err(Refusal::WrongKey);
    }
    if revoked(&claims.jti, &claims.sub, claims.iat) {
        return Err(Refusal::Revoked);
    }
    replay
        .check_and_record(&proof.jti, request.now)
        .map_err(|r| match r {
            Replay::Seen => Refusal::Replayed,
            Replay::Full => Refusal::ReplayCacheFull,
        })?;
    Ok(claims.verified(proof.jti))
}

/// Every check [`verify`] makes except the proof.
///
/// No door in this repository calls it: nothing here relays a token another
/// door verified. It exists so the shared table's relayed cases hold the
/// token's half of the rules on their own, which is the half every other case
/// reaches only through a proof.
pub fn verify_relayed(
    policy: &Policy,
    token: &str,
    now: i64,
    revoked: Revoked<'_>,
) -> Result<VerifiedAgent, Refusal> {
    let claims = token_claims(policy, token, now)?;
    if revoked(&claims.jti, &claims.sub, claims.iat) {
        return Err(Refusal::Revoked);
    }
    Ok(claims.verified(String::new()))
}

struct Claims {
    sub: String,
    jti: String,
    jkt: String,
    unit: String,
    org: String,
    iat: i64,
    exp: i64,
}

impl Claims {
    fn verified(self, proof_jti: String) -> VerifiedAgent {
        VerifiedAgent {
            subject: self.sub,
            unit: self.unit,
            org: self.org,
            jti: self.jti,
            jkt: self.jkt,
            proof_jti,
            issued_at: self.iat,
            expires_at: self.exp,
        }
    }
}

/// A string claim, read the way the other doors read one they require: absent
/// or of another type is the empty string, which the check that needs it then
/// refuses.
fn string_claim<'a>(claims: &'a Json, name: &str) -> &'a str {
    claims.get(name).and_then(Json::as_str).unwrap_or("")
}

/// An optional string claim: absent is empty, a string is itself, and anything
/// else, null included, is a token that cannot be read.
fn optional_string(claims: &Json, name: &str) -> Result<String, Refusal> {
    match claims.get(name) {
        None => Ok(String::new()),
        Some(Json::Str(s)) => Ok(s.clone()),
        Some(_) => Err(Refusal::Malformed),
    }
}

fn token_claims(policy: &Policy, token: &str, now: i64) -> Result<Claims, Refusal> {
    // The type, before anything else is believed or computed.
    let compact = Compact::split(token).ok_or(Refusal::Malformed)?;
    let header = compact.header_json().ok_or(Refusal::Malformed)?;
    if !header.is_object() || header.get("typ").and_then(Json::as_str) != Some(AGENT_TOKEN_TYP) {
        return Err(Refusal::Malformed);
    }
    // Required, not defaulted to "any": a door nobody told its own resource
    // would otherwise accept a token minted for every other one.
    if policy.audience.is_empty() {
        return Err(Refusal::Audience);
    }

    // The signature. The algorithm comes from the key, not from the header:
    // the header is written by whoever presents the token, and an issuer key
    // read as an HMAC secret is the classic downgrade.
    let kid = match header.get("kid") {
        None => return Err(Refusal::Malformed),
        Some(Json::Str(kid)) if kid.is_empty() => return Err(Refusal::Malformed),
        Some(Json::Str(kid)) => kid,
        Some(_) => return Err(Refusal::BadSignature),
    };
    let key = policy.keys.find(kid).ok_or(Refusal::BadSignature)?;
    let ec = key.ec.as_ref().ok_or(Refusal::BadSignature)?;
    if header.get("alg").and_then(Json::as_str) != Some("ES256") || !compact.verify_es256(ec) {
        return Err(Refusal::BadSignature);
    }
    let claims = compact
        .payload_json()
        .filter(Json::is_object)
        .ok_or(Refusal::BadSignature)?;

    if policy.issuer.is_empty() || string_claim(&claims, "iss") != policy.issuer {
        return Err(Refusal::Issuer);
    }
    // Present, and naming this resource exactly. A token with no `aud` was
    // minted for no resource, which is not this one.
    let audience_named = match claims.get("aud") {
        Some(Json::Str(aud)) => *aud == policy.audience,
        Some(Json::Arr(auds)) => auds.iter().any(|a| a.as_str() == Some(&policy.audience)),
        _ => false,
    };
    if !audience_named {
        return Err(Refusal::Audience);
    }
    let exp = match claims.get("exp") {
        Some(Json::Int(exp)) => *exp,
        _ => return Err(Refusal::Expired),
    };
    if now >= exp.saturating_add(LEEWAY_SECS) {
        return Err(Refusal::Expired);
    }
    // Absent is zero, as the other doors default it; present and not a whole
    // second is a token that cannot be read.
    let iat = match claims.get("iat") {
        None => 0,
        Some(Json::Int(iat)) => *iat,
        Some(_) => return Err(Refusal::Malformed),
    };
    if iat > now.saturating_add(LEEWAY_SECS) {
        return Err(Refusal::NotYetValid);
    }

    let sub = string_claim(&claims, "sub");
    let names_an_agent = sub.strip_prefix("agent://").is_some_and(|a| !a.is_empty());
    // A JSON null `act` is no act; any other value names a chain, and an agent's
    // own token acts for nobody.
    let acts = !matches!(claims.get("act"), None | Some(Json::Null));
    if !names_an_agent
        || string_claim(&claims, "client_id") != sub
        || string_claim(&claims, "jti").is_empty()
        || acts
    {
        return Err(Refusal::Malformed);
    }
    let jkt = claims
        .get("cnf")
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(Json::as_str)
        .unwrap_or("");
    if jkt.is_empty() {
        return Err(Refusal::NotBound);
    }
    let unit = optional_string(&claims, "unit")?;
    let org = optional_string(&claims, "org")?;
    Ok(Claims {
        sub: sub.to_owned(),
        jti: string_claim(&claims, "jti").to_owned(),
        jkt: jkt.to_owned(),
        unit,
        org,
        iat,
        exp,
    })
}

/// What a proof establishes before anything remembers it.
struct Proof {
    thumbprint: String,
    jti: String,
    ath: String,
}

/// Every check a proof is held to, in RFC 9449 section 4.3's spirit and the
/// other doors' order. `None` for any failure: the caller turns all of them
/// into one refusal.
fn verify_proof(proof: &str, method: &str, url: &str, now: i64) -> Option<Proof> {
    let compact = Compact::split(proof)?;
    let header = compact.header_json()?;
    // The type is what stops a proof being a token and a token being a proof.
    if header.get("typ").and_then(Json::as_str) != Some(PROOF_TYP) {
        return None;
    }
    let jwk = header.get("jwk")?;
    // RFC 9449 requires the public key. A private member there is a client
    // leaking its own signing key, and a door that took it would be a place
    // private keys collect.
    if !jwk.is_object() || has_private_member(jwk) {
        return None;
    }
    let key = EcKey::from_jwk(jwk)?;
    // Verified against the key the proof carries: the step the scheme rests on.
    // Without it anybody staples somebody else's public key to their own proof.
    if header.get("alg").and_then(Json::as_str) != Some("ES256") || !compact.verify_es256(&key) {
        return None;
    }
    let claims = compact.payload_json().filter(Json::is_object)?;

    // RFC 9110: methods are case-sensitive.
    if string_claim(&claims, "htm") != method {
        return None;
    }
    if !same_url(string_claim(&claims, "htu"), url) {
        return None;
    }
    let Some(Json::Int(iat)) = claims.get("iat") else {
        return None;
    };
    if now.saturating_sub(*iat).saturating_abs() > PROOF_WINDOW_SECS {
        return None;
    }
    // Without a `jti` there is nothing to remember, so the proof could be
    // replayed freely inside its window.
    let jti = string_claim(&claims, "jti");
    if jti.is_empty() {
        return None;
    }
    Some(Proof {
        thumbprint: key.thumbprint(),
        jti: jti.to_owned(),
        // Read, never judged here: only the caller holds the token it names.
        ath: string_claim(&claims, "ath").to_owned(),
    })
}

/// Whether a proof's `htu` and the URL this door was reached at name the same
/// request: RFC 9449 section 4.3, with RFC 3986 section 6.2.2.1's case rule for
/// the scheme and the authority, and the path compared exactly, still encoded.
///
/// The path is not normalised: `/v1%2Ftraces` is not `/v1/traces`, and
/// `/v1/TRACES` is not either. The query and fragment are not compared, since
/// `htu` is the URI without them and a client may add a cache-buster. A URL
/// with no scheme, no authority, or userinfo in the authority is not one this
/// compares at all, so two empty strings never match.
pub fn same_url(a: &str, b: &str) -> bool {
    match (url_parts(a), url_parts(b)) {
        (Some((sa, aa, pa)), Some((sb, ab, pb))) => {
            sa.eq_ignore_ascii_case(sb) && aa.eq_ignore_ascii_case(ab) && pa == pb
        }
        _ => false,
    }
}

/// `(scheme, authority, path)`, or `None` for anything that is not an absolute
/// URL this door could have been reached at.
fn url_parts(url: &str) -> Option<(&str, &str, &str)> {
    let url = match url.find(['?', '#']) {
        Some(at) => &url[..at],
        None => url,
    };
    let (scheme, rest) = url.split_once("://")?;
    let mut scheme_chars = scheme.bytes();
    if !scheme_chars.next()?.is_ascii_alphabetic()
        || !scheme_chars.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(at) => rest.split_at(at),
        None => (rest, ""),
    };
    if authority.is_empty()
        || authority.contains('@')
        || url.bytes().any(|b| b <= b' ' || b >= 0x7f)
    {
        return None;
    }
    Some((scheme, authority, path))
}

// ---------------------------------------------------------------------------
// Single use
// ---------------------------------------------------------------------------

/// Why a proof `jti` could not be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// Used before, inside the window.
    Seen,
    /// The current generation is at its cap, and nothing is forgotten to make
    /// room: forgetting under pressure is a replay guard that stops guarding
    /// exactly when somebody is pushing on it.
    Full,
}

/// Which proof `jti` values have been seen, so a proof is single use.
///
/// Two generations, as the other doors keep them. When the current one is a
/// generation old it becomes the previous one and a fresh one starts; a
/// lookup consults both, so nothing is forgotten while a proof carrying it
/// could still be fresh, and memory is bounded by `cap` per generation.
///
/// Ordered sets rather than hashed ones: no seed to read from the operating
/// system, and no seed for a caller choosing identifiers to attack.
#[derive(Debug, Clone)]
pub struct ReplayCache {
    cap: usize,
    begun: bool,
    /// Moves forward only. A clock that steps backwards must not rotate the
    /// generations, or whoever can nudge it forwards and back gets two
    /// rotations and an empty cache.
    started: i64,
    current: BTreeSet<String>,
    previous: BTreeSet<String>,
}

impl ReplayCache {
    /// `cap` bounds one generation, so at most twice that many identifiers are
    /// held at once.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            begun: false,
            started: 0,
            current: BTreeSet::new(),
            previous: BTreeSet::new(),
        }
    }

    /// Record `jti` as used at `now`, in whole seconds, or say why not.
    pub fn check_and_record(&mut self, jti: &str, now: i64) -> Result<(), Replay> {
        let elapsed = now.saturating_sub(self.started);
        if !self.begun || elapsed >= REPLAY_GENERATION_SECS {
            self.previous = if !self.begun || elapsed >= 2 * REPLAY_GENERATION_SECS {
                // Two generations or more since the last rotation: everything
                // held is older than any proof that could still be fresh.
                BTreeSet::new()
            } else {
                std::mem::take(&mut self.current)
            };
            self.current = BTreeSet::new();
            self.started = now;
            self.begun = true;
        }
        if self.current.contains(jti) || self.previous.contains(jti) {
            return Err(Replay::Seen);
        }
        if self.current.len() >= self.cap {
            return Err(Replay::Full);
        }
        self.current.insert(jti.to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_request_is_the_same_whatever_the_case_of_scheme_and_host() {
        assert!(same_url(
            "HTTPS://Ingest.Acme.Example/v1/traces",
            "https://ingest.acme.example/v1/traces?trace=1"
        ));
        assert!(same_url(
            "https://ingest.acme.example:8443/v1/traces#x",
            "https://ingest.acme.example:8443/v1/traces"
        ));
    }

    #[test]
    fn a_different_path_port_scheme_or_spelling_is_a_different_request() {
        let here = "https://ingest.acme.example/v1/traces";
        for other in [
            "https://ingest.acme.example/v1/TRACES",
            "https://ingest.acme.example/v1%2Ftraces",
            "https://ingest.acme.example/v1/traces/",
            "https://ingest.acme.example:443/v1/traces",
            "http://ingest.acme.example/v1/traces",
            "https://ingest.acme.example.evil/v1/traces",
            "https://user@ingest.acme.example/v1/traces",
            "/v1/traces",
            "ingest.acme.example/v1/traces",
            "https:///v1/traces",
            "",
        ] {
            assert!(!same_url(other, here), "{other:?} matched");
        }
        assert!(!same_url("", ""), "two nothings are not one request");
    }

    #[test]
    fn a_full_cache_refuses_and_a_rotation_frees_it() {
        let mut cache = ReplayCache::new(1);
        assert_eq!(cache.check_and_record("a", 100), Ok(()));
        assert_eq!(cache.check_and_record("b", 100), Err(Replay::Full));
        assert_eq!(
            cache.check_and_record("b", 100 + REPLAY_GENERATION_SECS),
            Ok(())
        );
        assert_eq!(
            cache.check_and_record("a", 100 + REPLAY_GENERATION_SECS),
            Err(Replay::Seen),
            "the previous generation is still consulted"
        );
        // Two generations on, both are gone.
        assert_eq!(
            cache.check_and_record("a", 100 + 3 * REPLAY_GENERATION_SECS),
            Ok(())
        );
    }

    #[test]
    fn a_key_set_that_cannot_be_used_is_refused_by_name() {
        let ec = r#""kty":"EC","crv":"P-256","x":"gMC-krcdA4Sf3PAKbQmV7932Yz-ld_OaQOFkiJjoMD8","y":"iLBNXvD8azso5GnNU_MKdpOyxYxLkJ0yzgkCME9Ijzk""#;
        let ok = format!(r#"{{"keys":[{{"kid":"v-1",{ec}}}]}}"#);
        assert_eq!(KeySet::from_jwks(ok.as_bytes()).map(|k| k.usable()), Ok(1));
        for (doc, why) in [
            ("not json".to_owned(), JwksError::NotJson),
            (r#"{"key":[]}"#.to_owned(), JwksError::NotAKeySet),
            (r#"{"keys":[1]}"#.to_owned(), JwksError::NotAKeySet),
            (r#"{"keys":[]}"#.to_owned(), JwksError::NoUsableKey),
            (format!(r#"{{"keys":[{{{ec}}}]}}"#), JwksError::NoUsableKey),
            (
                r#"{"keys":[{"kid":"r","kty":"RSA","n":"AQAB","e":"AQAB"}]}"#.to_owned(),
                JwksError::NoUsableKey,
            ),
            (
                format!(r#"{{"keys":[{{"kid":"v-1",{ec}}},{{"kid":"v-1",{ec}}}]}}"#),
                JwksError::DuplicateKid,
            ),
            (
                format!(r#"{{"keys":[{{"kid":"v-1","d":"AA",{ec}}}]}}"#),
                JwksError::PrivateMember,
            ),
        ] {
            assert_eq!(KeySet::from_jwks(doc.as_bytes()).err(), Some(why), "{doc}");
        }
    }
}
