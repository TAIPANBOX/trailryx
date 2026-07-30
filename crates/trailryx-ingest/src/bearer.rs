//! A reference [`AuthProvider`]: one shared secret, presented as `Bearer`.
//!
//! # What this is, and what it is not
//!
//! It authenticates a **fleet**, not an agent. Every exporter that holds the
//! secret is the same principal, so it answers "may anything write to this
//! tenant" and nothing finer. That is enough for the deployment this crate was
//! written for, an exporter and a store on the same private network behind a
//! terminating proxy, and it is not an identity system. A deployment that needs
//! to know which agent wrote a record gets that from the OTLP resource
//! attributes through the mapper, which is where record identity has always come
//! from; a deployment that needs per-agent *authorisation* supplies its own
//! provider behind the same seam.
//!
//! It is here rather than in a test because a seam with no implementation is a
//! seam nobody has run. The same argument as the in-tree AEAD, with one
//! difference: this one is honest for what it does, so it is not marked as
//! unvalidated. The thing to be careful about is not the comparison, it is the
//! plaintext transport, and `Server::bind` already refuses the worst
//! configuration outright.
//!
//! # Why the secret is stored as a digest
//!
//! The configured secret is hashed once at construction and the plaintext is
//! dropped. Two properties follow that a stored string does not have:
//!
//! - Comparison is over two fixed-length digests through
//!   [`digests_equal`], so it takes the same time for a wrong first byte as for
//!   a wrong last one and leaks nothing about the secret's length. A `==` on the
//!   strings would leak both.
//! - A core dump, a crash report or a debugger attached to this process yields a
//!   digest and not a usable token.
//!
//! It costs one SHA-384 of a short string per request, which is nothing next to
//! parsing the export that follows.
//!
//! # Why the secret is read from a file
//!
//! Never from `argv`: on a shared host `ps` shows another user's command line.
//! Never from the environment either, which is inherited by every child and
//! printed by most crash handlers. A file has an owner and a mode, and those are
//! the two things an operator can actually check.

use trailryx_contracts::contracts::{
    Action, AdapterError, AdapterResult, AuthProvider, Decision, Principal,
};
use trailryx_crypto::{Sha384, digests_equal};
use trailryx_record::{Hash, PrincipalId};

/// The scheme name, compared case-insensitively as RFC 9110 requires, with the
/// single space RFC 6750 specifies after it.
const SCHEME: &str = "bearer ";

#[derive(Debug)]
pub enum SecretError {
    /// An empty file, or one that is only whitespace. Refused at construction
    /// rather than becoming a server that accepts the empty credential.
    Empty,
    /// Long enough to be a paste accident rather than a token. The bound is
    /// generous; the point is that a file of arbitrary size is not a secret.
    TooLong,
    /// Contains a byte that cannot appear in an HTTP field value, so it could
    /// never be presented and the mistake is worth catching at startup.
    NotAFieldValue,
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("the secret is empty"),
            Self::TooLong => f.write_str("the secret is longer than 4096 bytes"),
            Self::NotAFieldValue => {
                f.write_str("the secret contains a byte that cannot appear in an HTTP field")
            }
        }
    }
}

impl std::error::Error for SecretError {}

const MAX_SECRET: usize = 4096;

/// One shared secret, held as a digest.
pub struct SharedSecret {
    digest: Hash,
    principal: PrincipalId,
    scope: String,
}

impl std::fmt::Debug for SharedSecret {
    /// Prints the scope and the principal and never the digest. A digest is not
    /// the secret, but it is an offline-guessable commitment to a short one, and
    /// a `Debug` that printed it would put that in a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("principal", &self.principal.as_str())
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl SharedSecret {
    /// `secret` is the raw bytes as read from the file. Surrounding ASCII
    /// whitespace is trimmed, because a secret file written by an editor ends
    /// with a newline and refusing that would be refusing the normal case.
    pub fn new(secret: &[u8], scope: impl Into<String>) -> Result<Self, SecretError> {
        let secret = trim_ascii(secret);
        if secret.is_empty() {
            return Err(SecretError::Empty);
        }
        if secret.len() > MAX_SECRET {
            return Err(SecretError::TooLong);
        }
        // Exactly the field-value grammar of RFC 9112: visible ASCII, plus
        // horizontal whitespace, plus the obs-text range. A secret containing a
        // CR could not be sent and must not be silently accepted here.
        if !secret
            .iter()
            .all(|b| matches!(b, 0x21..=0x7E | b'\t' | b' ' | 0x80..=0xFF))
        {
            return Err(SecretError::NotAFieldValue);
        }
        Ok(Self {
            digest: Sha384::digest(secret),
            // Fixed and true: this credential names a fleet holding a secret.
            // Inventing a per-request identity here would put an unattested
            // identity next to the attested one the mapper derives.
            principal: PrincipalId::parse("agent://shared-secret/fleet")
                .expect("a constant that the identifier grammar accepts"),
            scope: scope.into(),
        })
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }
}

impl AuthProvider for SharedSecret {
    fn authenticate(&mut self, credential: &[u8]) -> AdapterResult<Principal> {
        // The scheme is compared case-insensitively and the token is taken as
        // the exact remainder. No trimming after the scheme: a token is bytes,
        // and quietly accepting `Bearer  x` as `x` would make two different
        // credentials the same one.
        let Some(token) = strip_scheme(credential) else {
            return Err(AdapterError::Unsupported(
                "this provider understands the Bearer scheme only",
            ));
        };
        if token.is_empty() {
            return Err(AdapterError::Rejected("the bearer token is empty"));
        }
        if digests_equal(&Sha384::digest(token), &self.digest) {
            Ok(Principal {
                id: self.principal.clone(),
                via: "shared-secret",
            })
        } else {
            Err(AdapterError::Rejected("the bearer token does not match"))
        }
    }

    fn authorize(&mut self, _principal: &Principal, action: Action, scope: &str) -> Decision {
        // Deny by default, in the shape the word means: one action and one
        // scope are named, everything else falls through to `Deny`. Holding the
        // ingest secret is not permission to read, query, erase or administer.
        match action {
            Action::Ingest if scope == self.scope => Decision::Allow,
            _ => Decision::Deny,
        }
    }
}

/// Case-insensitive on the scheme, byte-exact on the token.
fn strip_scheme(credential: &[u8]) -> Option<&[u8]> {
    let (head, rest) = credential.split_at_checked(SCHEME.len())?;
    head.eq_ignore_ascii_case(SCHEME.as_bytes()).then_some(rest)
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let [first, tail @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = tail;
        } else {
            break;
        }
    }
    while let [body @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = body;
        } else {
            break;
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> SharedSecret {
        SharedSecret::new(b"correct-horse-battery-staple\n", "acme").expect("a valid secret")
    }

    #[test]
    fn the_configured_secret_authenticates_and_authorises_ingest() {
        let mut p = provider();
        let principal = p
            .authenticate(b"Bearer correct-horse-battery-staple")
            .expect("the right token");
        assert_eq!(principal.via, "shared-secret");
        assert_eq!(
            p.authorize(&principal, Action::Ingest, "acme"),
            Decision::Allow
        );
    }

    /// RFC 9110 says the scheme is case-insensitive, and exporters differ.
    #[test]
    fn the_scheme_is_case_insensitive() {
        let mut p = provider();
        for prefix in ["Bearer ", "bearer ", "BEARER ", "BeArEr "] {
            let credential = format!("{prefix}correct-horse-battery-staple");
            assert!(
                p.authenticate(credential.as_bytes()).is_ok(),
                "{prefix:?} should be accepted"
            );
        }
    }

    /// The token is not: a secret differing only in case is a different secret.
    #[test]
    fn the_token_is_case_sensitive() {
        let mut p = provider();
        assert!(
            p.authenticate(b"Bearer CORRECT-HORSE-BATTERY-STAPLE")
                .is_err()
        );
    }

    /// The trailing newline an editor writes is not part of the secret. Without
    /// this, the operator's token and the file's contents differ by one byte and
    /// the failure gives no clue why.
    #[test]
    fn a_secret_file_may_end_with_a_newline() {
        for written in [
            b"tok\n".as_slice(),
            b"tok\r\n".as_slice(),
            b"  tok  ".as_slice(),
            b"tok".as_slice(),
        ] {
            let mut p = SharedSecret::new(written, "acme").expect("valid");
            assert!(
                p.authenticate(b"Bearer tok").is_ok(),
                "{:?} should hold the secret `tok`",
                String::from_utf8_lossy(written)
            );
        }
    }

    /// Whitespace after the scheme belongs to the token. Trimming it would make
    /// `Bearer  tok` and `Bearer tok` the same credential, which is one more
    /// string that opens the door than the operator configured.
    #[test]
    fn whitespace_after_the_scheme_is_part_of_the_token() {
        let mut p = provider();
        assert!(
            p.authenticate(b"Bearer  correct-horse-battery-staple")
                .is_err()
        );
    }

    #[test]
    fn a_missing_or_unknown_scheme_is_unsupported_and_a_wrong_token_is_rejected() {
        let mut p = provider();
        assert!(matches!(
            p.authenticate(b"correct-horse-battery-staple"),
            Err(AdapterError::Unsupported(_))
        ));
        assert!(matches!(
            p.authenticate(b"Basic Y29ycmVjdA=="),
            Err(AdapterError::Unsupported(_))
        ));
        assert!(matches!(
            p.authenticate(b"Bearer wrong"),
            Err(AdapterError::Rejected(_))
        ));
        assert!(matches!(
            p.authenticate(b"Bearer "),
            Err(AdapterError::Rejected(_))
        ));
        // Shorter than the scheme itself, which is where a naive `split_at`
        // would panic rather than answer.
        assert!(matches!(
            p.authenticate(b"Bea"),
            Err(AdapterError::Unsupported(_))
        ));
        assert!(matches!(
            p.authenticate(b""),
            Err(AdapterError::Unsupported(_))
        ));
    }

    /// Deny by default in the shape the words mean. Holding the write secret is
    /// not permission to read a payload or erase a subject, and a provider that
    /// allowed the whole enum because it recognised the caller would be exactly
    /// the confusion the `Action` split exists to prevent.
    #[test]
    fn no_other_action_is_permitted_by_the_ingest_secret() {
        let mut p = provider();
        let principal = p
            .authenticate(b"Bearer correct-horse-battery-staple")
            .expect("valid");
        for action in [
            Action::ReadMetadata,
            Action::ReadPayload,
            Action::Query,
            Action::ProduceEvidence,
            Action::Erase,
            Action::Administer,
        ] {
            assert_eq!(
                p.authorize(&principal, action, "acme"),
                Decision::Deny,
                "{action:?} must not follow from the ingest secret"
            );
        }
    }

    #[test]
    fn another_scope_is_denied_even_with_the_right_secret() {
        let mut p = provider();
        let principal = p
            .authenticate(b"Bearer correct-horse-battery-staple")
            .expect("valid");
        for scope in ["", "acm", "acme2", "other"] {
            assert_eq!(
                p.authorize(&principal, Action::Ingest, scope),
                Decision::Deny,
                "{scope:?} is not the configured scope"
            );
        }
    }

    #[test]
    fn a_secret_file_that_could_not_hold_a_secret_is_refused_at_construction() {
        assert!(matches!(
            SharedSecret::new(b"", "acme"),
            Err(SecretError::Empty)
        ));
        assert!(matches!(
            SharedSecret::new(b"   \n\t ", "acme"),
            Err(SecretError::Empty)
        ));
        assert!(matches!(
            SharedSecret::new(&vec![b'x'; MAX_SECRET + 1], "acme"),
            Err(SecretError::TooLong)
        ));
        // A secret with an embedded CR could never be presented in a field, so
        // the server would refuse every request and the reason would be nowhere.
        assert!(matches!(
            SharedSecret::new(b"tok\rmore", "acme"),
            Err(SecretError::NotAFieldValue)
        ));
        assert!(matches!(
            SharedSecret::new(b"tok\0more", "acme"),
            Err(SecretError::NotAFieldValue)
        ));
        assert!(SharedSecret::new(&vec![b'x'; MAX_SECRET], "acme").is_ok());
    }

    /// The property the digest is for: nothing that formats this provider, and
    /// nothing it stores, is the secret.
    ///
    /// The limit of this check is stated rather than hidden: it proves the two
    /// stored fields and the `Debug` output do not contain the plaintext. It
    /// cannot prove the allocator no longer holds the caller's buffer, which is
    /// the caller's to zero and not something this type can promise.
    #[test]
    fn neither_debug_nor_the_stored_fields_contain_the_plaintext_secret() {
        let p = provider();
        let printed = format!("{p:?}");
        assert!(!printed.contains("correct-horse"), "{printed}");
        assert!(printed.contains("acme"));
        let stored = format!("{:?}{}", p.digest, p.scope);
        assert!(!stored.contains("correct-horse"), "{stored}");
    }

    /// Two different secrets must not authenticate each other. Trivially true,
    /// and it is the test that would fail if the comparison were ever changed to
    /// one that compares lengths or prefixes.
    #[test]
    fn a_second_secret_does_not_open_the_first() {
        let mut a = SharedSecret::new(b"secret-a", "acme").expect("valid");
        assert!(a.authenticate(b"Bearer secret-b").is_err());
        assert!(a.authenticate(b"Bearer secret-").is_err());
        assert!(a.authenticate(b"Bearer secret-aa").is_err());
        assert!(a.authenticate(b"Bearer secret-a").is_ok());
    }
}
