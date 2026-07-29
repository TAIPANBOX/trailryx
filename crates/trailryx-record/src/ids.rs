//! Identifiers.
//!
//! Every one of these is a string in the wire sense and a **constrained token**
//! in the schema sense: bounded length, fixed character set, validated at the
//! door. That distinction is what makes them safe to keep in the metadata plane
//! while free text is not (see [`crate::schema`]).
//!
//! Values arrive from outside. They are checked once, here, and after that the
//! type carries the guarantee.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    Empty,
    TooLong { max: usize, got: usize },
    BadChar { at: usize, ch: char },
    BadShape(&'static str),
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty"),
            Self::TooLong { max, got } => write!(f, "too long: {got} bytes, max {max}"),
            Self::BadChar { at, ch } => write!(f, "illegal character {ch:?} at byte {at}"),
            Self::BadShape(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for IdError {}

/// `[a-z0-9._-]`, the character set the Agent Passport spec allows per segment.
fn segment_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
}

fn check(s: &str, max: usize, allowed: fn(char) -> bool) -> Result<(), IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    if s.len() > max {
        return Err(IdError::TooLong { max, got: s.len() });
    }
    for (at, ch) in s.char_indices() {
        if !allowed(ch) {
            return Err(IdError::BadChar { at, ch });
        }
    }
    Ok(())
}

macro_rules! token {
    ($name:ident, $max:expr, $allowed:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub const MAX_BYTES: usize = $max;

            pub fn parse(s: impl Into<String>) -> Result<Self, IdError> {
                let s = s.into();
                check(&s, $max, $allowed)?;
                Ok(Self(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

fn uri_char(c: char) -> bool {
    segment_char(c) || matches!(c, '/' | ':')
}

token!(
    AgentId,
    255,
    uri_char,
    "Canonical agent identifier, `agent://<trust-domain>/<path>`.\n\nTreated as an opaque key: parsed for shape, never for meaning."
);

token!(
    PrincipalId,
    255,
    uri_char,
    "One link of a delegation chain: an `agent://` or `user://` URI."
);

token!(
    RunId,
    64,
    segment_char,
    "One execution of an agent. Unbounded in cardinality by nature, which is why the store is sharded and indexed rather than aggregated."
);

token!(
    PolicyVersion,
    64,
    segment_char,
    "Which version of the governing policy was in force at decision time."
);

token!(
    ModelId,
    128,
    |c: char| segment_char(c) || c == '/',
    "Which model was called. A name, never a prompt."
);

token!(
    ToolName,
    64,
    segment_char,
    "A tool that was in scope. The name only: arguments are payload."
);

token!(
    TenantId,
    64,
    segment_char,
    "Isolation boundary. Shard assignment and key hierarchy both hang off it."
);

impl AgentId {
    /// `agent://<trust-domain>/<path>` with a non-empty path.
    pub fn parse_strict(s: impl Into<String>) -> Result<Self, IdError> {
        let id = Self::parse(s)?;
        let rest =
            id.0.strip_prefix("agent://")
                .ok_or(IdError::BadShape("must start with agent://"))?;
        let (domain, path) = rest
            .split_once('/')
            .ok_or(IdError::BadShape("must have a path after the trust domain"))?;
        if domain.is_empty() {
            return Err(IdError::BadShape("empty trust domain"));
        }
        if path.is_empty() {
            return Err(IdError::BadShape("empty path"));
        }
        Ok(id)
    }
}

/// A record's own identity: a ULID, kept as its 128 bits.
///
/// Monotonic within a shard, so it sorts by time without a separate index and
/// carries no meaning that could leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(pub u128);

impl fmt::Display for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

/// Which segment a record landed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegmentId(pub u64);

impl fmt::Display for SegmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seg-{:016x}", self.0)
    }
}

/// Which shard owns a record. Fixed at store creation and never re-split:
/// shard identity is part of a proof path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardIx(pub u16);

impl fmt::Display for ShardIx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_id_shape_is_enforced() {
        assert!(AgentId::parse_strict("agent://acme-bank.example/support/tier1").is_ok());
        assert!(AgentId::parse_strict("acme-bank.example/support").is_err());
        assert!(AgentId::parse_strict("agent://acme-bank.example").is_err());
        assert!(AgentId::parse_strict("agent:///path").is_err());
    }

    #[test]
    fn uppercase_and_spaces_are_refused() {
        assert!(matches!(
            AgentId::parse("agent://Acme/x"),
            Err(IdError::BadChar { .. })
        ));
        assert!(matches!(
            RunId::parse("run 1"),
            Err(IdError::BadChar { .. })
        ));
    }

    #[test]
    fn length_is_bounded() {
        let long = "a".repeat(RunId::MAX_BYTES + 1);
        assert!(matches!(RunId::parse(long), Err(IdError::TooLong { .. })));
    }

    #[test]
    fn empty_is_refused() {
        assert_eq!(RunId::parse(""), Err(IdError::Empty));
    }

    #[test]
    fn a_prompt_cannot_masquerade_as_an_identifier() {
        // The point of the character set: content does not fit through it.
        assert!(RunId::parse("Please summarise the attached medical report").is_err());
        assert!(ModelId::parse("ivan.petrenko@example.com").is_err());
    }
}
