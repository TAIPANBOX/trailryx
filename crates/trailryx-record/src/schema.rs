//! The schema, and the boundary it enforces.
//!
//! This module is the single place that answers, for every field the store
//! keeps: what type is it, **which plane does it live in**, can it ever be
//! personal data, and can a completeness proof cover it.
//!
//! # The plane boundary
//!
//! > The metadata plane holds only typed fields: identifiers, enums, hashes,
//! > numbers, timestamps. **Any free text lives solely in the encrypted payload
//! > plane**, under a subject key.
//!
//! It is stated as an invariant rather than a habit because the failure mode is
//! quiet and legal. OpenTelemetry's GenAI conventions permit capturing prompt
//! and completion content, so a mapper that puts unrecognised attributes into
//! metadata "verbatim, to be safe" ends up storing names, addresses and whole
//! documents outside the encrypted plane. Erasure then destroys the payload key
//! and leaves the personal data sitting in metadata, which turns the product's
//! central promise into a false one.
//!
//! [`Schema::violations`] returns any breach, and the test suite fails the
//! build on a non-empty result. A mapper that does not know where to put an
//! attribute puts it in the payload plane; never here.
//!
//! # This table is also the DPIA
//!
//! Every field carries a `why`, which is the answer to "what is this, and could
//! it be personal data". Filling it in is not paperwork: it is the pass that
//! catches a field like an upstream error message, which looks like diagnostics
//! and is in practice a verbatim quote of the input.

use crate::record::PROVABLE_DIMENSIONS;

/// Which of the two planes a field lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plane {
    /// Queryable, indexable, not encrypted. Typed fields only.
    Metadata,
    /// Encrypted under a subject key, erasable, never indexed as text in v1.
    Payload,
}

/// Whether a field can carry personal data, and if so who decides.
///
/// Three values rather than two, because the middle one is real and pretending
/// otherwise is how the erasure promise quietly becomes false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pii {
    /// Cannot, by construction: an enum, a number, a hash, a timestamp, or an
    /// identifier this store generates itself.
    Never,
    /// The value is supplied by the operator and could contain personal data if
    /// they put it there. It stays in the metadata plane because queries and
    /// proofs need it in the clear, which means **erasure cannot reach it**:
    /// identifiers end up committed inside immutable index roots, and no key
    /// destruction touches a Merkle root that was published years ago.
    ///
    /// The character set stops a sentence but not a name:
    /// `agent://acme.example/ivan.petrenko.1979` passes every check this schema
    /// makes. So the guarantee here is contractual rather than technical, and
    /// saying so is the honest part. See `docs/identifiers.md`.
    OperatorPseudonymous,
    /// Content. Payload plane only, under a subject key, erasable.
    Possible,
}

/// The shape of a value, at the level the boundary rule cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bool,
    U16,
    U32,
    U64,
    I64,
    Timestamp,
    Hash,
    /// A closed vocabulary. Closed is the point: an open one is free text
    /// wearing a costume.
    Enum(&'static [&'static str]),
    /// A bounded, character-set-restricted token. Long enough to be an
    /// identifier, too narrow to be a sentence.
    Token {
        max_bytes: usize,
        charset: &'static str,
    },
    /// Arbitrary text. Legal **only** in the payload plane.
    FreeText,
    /// Arbitrary bytes. Legal only in the payload plane.
    Bytes,
}

impl Kind {
    pub fn json_type(self) -> &'static str {
        match self {
            Self::Bool => "boolean",
            Self::U16 | Self::U32 | Self::U64 | Self::I64 | Self::Timestamp => "integer",
            Self::Hash | Self::Enum(_) | Self::Token { .. } | Self::FreeText | Self::Bytes => {
                "string"
            }
        }
    }

    /// Can this shape hold content rather than an identifier?
    pub fn is_unbounded(self) -> bool {
        matches!(self, Self::FreeText | Self::Bytes)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// Dotted path, e.g. `basis.policy_version`.
    pub path: &'static str,
    pub kind: Kind,
    pub optional: bool,
    pub repeated: bool,
    pub plane: Plane,
    pub pii: Pii,
    /// Whether a completeness proof can cover a predicate on this field.
    pub provable: bool,
    /// What it is, and why it is safe where it sits. The DPIA line.
    pub why: &'static str,
}

/// A breach of the boundary rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub path: &'static str,
    pub reason: &'static str,
}

#[derive(Debug)]
pub struct Schema {
    pub version: u16,
    pub fields: &'static [Field],
}

impl Schema {
    /// Every way this schema breaks its own rules. Empty is the only acceptable
    /// answer, and the test suite enforces that.
    pub fn violations(&self) -> Vec<Violation> {
        let mut out = Vec::new();
        for f in self.fields {
            if f.plane == Plane::Payload && f.pii != Pii::Possible {
                out.push(Violation {
                    path: f.path,
                    reason: "a payload field is content and must be classified as such",
                });
            }
            if f.plane == Plane::Metadata {
                if f.kind.is_unbounded() {
                    out.push(Violation {
                        path: f.path,
                        reason: "unbounded text or bytes in the metadata plane",
                    });
                }
                if f.pii == Pii::Possible {
                    out.push(Violation {
                        path: f.path,
                        reason: "content-bearing field is not in the payload plane",
                    });
                }
                // An operator-supplied token is unerasable by construction, so
                // it may never be the shape that can hold a document.
                if f.pii == Pii::OperatorPseudonymous && !matches!(f.kind, Kind::Token { .. }) {
                    out.push(Violation {
                        path: f.path,
                        reason: "only a bounded token may be operator-supplied in metadata",
                    });
                }
                if let Kind::Token { max_bytes, charset } = f.kind
                    && (max_bytes == 0 || charset.is_empty())
                {
                    out.push(Violation {
                        path: f.path,
                        reason: "token in the metadata plane without a bound and a character set",
                    });
                }
                if let Kind::Enum(variants) = f.kind
                    && variants.is_empty()
                {
                    out.push(Violation {
                        path: f.path,
                        reason: "empty enumeration is an open vocabulary",
                    });
                }
            }
            if f.why.trim().is_empty() {
                out.push(Violation {
                    path: f.path,
                    reason: "no classification note: the DPIA pass skipped this field",
                });
            }
            if f.provable && f.plane != Plane::Metadata {
                out.push(Violation {
                    path: f.path,
                    reason: "a proof cannot cover a field that is not indexed in the clear",
                });
            }
        }
        out
    }

    /// Fields whose values the operator supplies and erasure cannot reach.
    ///
    /// Deliberately enumerable: the list is short, it is pinned by a test, and
    /// adding to it should be a decision somebody makes on purpose.
    pub fn unerasable_fields(&self) -> Vec<&'static str> {
        self.fields
            .iter()
            .filter(|f| f.pii == Pii::OperatorPseudonymous)
            .map(|f| f.path)
            .collect()
    }

    pub fn provable_fields(&self) -> Vec<&'static str> {
        self.fields
            .iter()
            .filter(|f| f.provable)
            .map(|f| f.path)
            .collect()
    }

    pub fn in_plane(&self, plane: Plane) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(move |f| f.plane == plane)
    }

    /// Emit the schema as a JSON document.
    ///
    /// Hand-rolled rather than derived: the crate carries no dependencies, and
    /// the offline verifier that will read this has to stay small enough for an
    /// auditor to read in one sitting.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(8 << 10);
        s.push_str("{\n");
        s.push_str("  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n");
        // The version this schema IS, not a literal. It said `record.v1.json`
        // for every schema, so v2's artifact would have claimed to be v1's:
        // a published document naming the wrong version of itself is the one
        // kind of drift a reader cannot see.
        s.push_str(&format!(
            "  \"$id\": \"https://trailryx.dev/schema/record.v{}.json\",\n",
            self.version
        ));
        s.push_str("  \"title\": \"Trailryx decision record\",\n");
        s.push_str(&format!("  \"x-version\": {},\n", self.version));
        s.push_str("  \"description\": \"Metadata plane holds typed fields only. Any free text lives in the encrypted payload plane.\",\n");
        s.push_str("  \"type\": \"object\",\n");
        s.push_str("  \"fields\": [\n");

        for (i, f) in self.fields.iter().enumerate() {
            s.push_str("    {");
            s.push_str(&format!("\"path\": \"{}\", ", f.path));
            s.push_str(&format!("\"type\": \"{}\", ", f.kind.json_type()));
            match f.kind {
                Kind::Token { max_bytes, charset } => {
                    s.push_str(&format!(
                        "\"maxLength\": {max_bytes}, \"charset\": \"{charset}\", "
                    ));
                }
                Kind::Enum(variants) => {
                    s.push_str("\"enum\": [");
                    for (j, v) in variants.iter().enumerate() {
                        if j > 0 {
                            s.push_str(", ");
                        }
                        s.push_str(&format!("\"{v}\""));
                    }
                    s.push_str("], ");
                }
                Kind::Hash => s.push_str("\"contentEncoding\": \"base16\", \"maxLength\": 96, "),
                _ => {}
            }
            if f.optional {
                s.push_str("\"optional\": true, ");
            }
            if f.repeated {
                s.push_str("\"repeated\": true, ");
            }
            s.push_str(&format!(
                "\"x-plane\": \"{}\", ",
                match f.plane {
                    Plane::Metadata => "metadata",
                    Plane::Payload => "payload",
                }
            ));
            s.push_str(&format!(
                "\"x-pii\": \"{}\", ",
                match f.pii {
                    Pii::Never => "never",
                    Pii::OperatorPseudonymous => "operator-pseudonymous",
                    Pii::Possible => "possible",
                }
            ));
            s.push_str(&format!("\"x-provable\": {}, ", f.provable));
            s.push_str(&format!("\"x-why\": \"{}\"", escape(f.why)));
            s.push('}');
            if i + 1 < self.fields.len() {
                s.push(',');
            }
            s.push('\n');
        }

        s.push_str("  ],\n");
        s.push_str("  \"x-provable-dimensions\": [");
        for (i, d) in PROVABLE_DIMENSIONS.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&format!("\"{d}\""));
        }
        s.push_str("]\n}\n");
        s
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Version 1 of the record schema.
///
/// Frozen at the end of stage 1. A change here is a format change and needs a
/// version bump plus a migration, not an edit, and [`RECORD_V2`] is what that
/// looked like when it came.
///
/// It is a PREFIX of v2 rather than a separate list, which is not a trick to
/// save typing: it is the claim that the migration was ADDITIVE, written where
/// the compiler checks it. Every record ever written under v1 is described by
/// exactly these fields, and if somebody ever changes one of them in place this
/// stops being true and v1's own artifact moves, which `schema_artifact.rs`
/// then refuses.
pub const RECORD_V1: Schema = Schema {
    version: 1,
    fields: FIELDS_V1,
};

/// Version 2: v1 plus `basis.delegation_proof` (agent-passport SPEC 5.2).
///
/// # What the migration is, and what it deliberately is not
///
/// Nothing is rewritten. Records already on disk stay byte for byte as they
/// were written, keep their own hashes, and keep verifying: a store whose whole
/// claim is tamper-evidence cannot rewrite its own history to add a field, and
/// a migration that did would be indistinguishable from the tampering the chain
/// exists to catch.
///
/// So the migration lives in the READER. `wire::FRAME_VERSION` moves to 2 and
/// the decoder accepts 1 and 2; a v1 frame yields `delegation_proof: None`,
/// which SPEC 5.2 already defines as "not proven" rather than "unknown". The
/// only thing that changes about an old record is that a field it never had
/// reads as absent, which is what it always meant.
pub const RECORD_V2: Schema = Schema {
    version: 2,
    fields: FIELDS,
};

/// The v1 fields: every entry of [`FIELDS`] except the ones v2 added.
const FIELDS_V1: &[Field] = FIELDS.split_at(FIELDS.len() - V2_ADDED).0;

/// How many entries v2 appended. Named so the split above reads as an
/// arithmetic fact rather than a magic index.
const V2_ADDED: usize = 4;

const TOKEN_SEGMENT: &str = "[a-z0-9._-]";
const TOKEN_URI: &str = "[a-z0-9._:/-]";

const FIELDS: &[Field] = &[
    Field {
        path: "id",
        kind: Kind::Token {
            max_bytes: 32,
            charset: "[0-9a-f]",
        },
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: true,
        why: "ULID of the record itself, hex. Generated by us, carries no external content.",
    },
    Field {
        path: "tenant",
        kind: Kind::Token {
            max_bytes: 64,
            charset: TOKEN_SEGMENT,
        },
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: false,
        why: "Isolation boundary chosen by the operator. An organisation name at most, never a person.",
    },
    Field {
        path: "shard",
        kind: Kind::U16,
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Which shard owns the record. Part of a proof path, fixed at store creation.",
    },
    Field {
        path: "agent_id",
        kind: Kind::Token {
            max_bytes: 255,
            charset: TOKEN_URI,
        },
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: true,
        why: "agent:// URI naming a machine actor. Not a natural person; a person appears only via on_behalf_of.",
    },
    Field {
        path: "run_id",
        kind: Kind::Token {
            max_bytes: 64,
            charset: TOKEN_SEGMENT,
        },
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: true,
        why: "One execution. High cardinality by nature, which is why this is a sharded store and not a metrics one.",
    },
    Field {
        path: "parent_run_id",
        kind: Kind::Token {
            max_bytes: 64,
            charset: TOKEN_SEGMENT,
        },
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: false,
        why: "The run that spawned this one. Crosses shards, so causal traversal is a cross-shard operation.",
    },
    Field {
        path: "on_behalf_of",
        kind: Kind::Token {
            max_bytes: 255,
            charset: TOKEN_URI,
        },
        optional: true,
        repeated: true,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: false,
        why: "Delegation chain, root first. A user:// URI is a pseudonymous handle chosen by the operator, not a name; operators are told not to put names in it.",
    },
    Field {
        path: "occurred_at",
        kind: Kind::Timestamp,
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "When the emitter says it happened. Untrusted: it is their clock, and it is not the ordering key.",
    },
    Field {
        path: "decided_at",
        kind: Kind::Timestamp,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "When the decision was taken, per the emitter. Untrusted for the same reason.",
    },
    Field {
        path: "recorded_at",
        kind: Kind::Timestamp,
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: true,
        why: "Our clock, the one we can stand behind. The time dimension a proof covers.",
    },
    Field {
        path: "knowledge_as_of",
        kind: Kind::Timestamp,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Which state of knowledge the decision was taken against. The second axis of bitemporality.",
    },
    Field {
        path: "clock_skew_nanos",
        kind: Kind::U64,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Set when the emitter's clock disagreed with ours beyond threshold. Recorded rather than silently corrected.",
    },
    Field {
        path: "event_type",
        kind: Kind::Enum(&[
            "request_received",
            "model_call",
            "tool_call",
            "policy_decision",
            "budget_check",
            "memory_access",
            "delegation",
            "run_completed",
            "erasure",
            "store_event",
            "notification_dispatched",
            "identity_finding",
        ]),
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: true,
        why: "Closed vocabulary. An open one would be a hole through which content arrives.",
    },
    Field {
        path: "severity",
        kind: Kind::Enum(&["debug", "info", "notice", "warning", "error", "critical"]),
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Operator-assigned importance. Closed vocabulary, so it cannot carry a message.",
    },
    Field {
        path: "basis.policy_version",
        kind: Kind::Token {
            max_bytes: 64,
            charset: TOKEN_SEGMENT,
        },
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: false,
        why: "Which policy was in force. A version label produced by the operator's own tooling.",
    },
    Field {
        path: "basis.budget_remaining_micros",
        kind: Kind::I64,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Money as an integer of micro-units, never a float. Commercial, not personal.",
    },
    Field {
        path: "basis.memory_ref",
        kind: Kind::Hash,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "What the agent remembered, by reference. Copying the memory in would move somebody else's content into our metadata.",
    },
    Field {
        path: "basis.model",
        kind: Kind::Token {
            max_bytes: 128,
            charset: "[a-z0-9._/-]",
        },
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: false,
        why: "Model name. The character set refuses anything shaped like an address or a sentence.",
    },
    Field {
        path: "basis.temperature_milli",
        kind: Kind::U16,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Sampling temperature in thousandths, so it is an integer.",
    },
    Field {
        path: "basis.max_tokens",
        kind: Kind::U32,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Requested output ceiling. A knob set by the caller, with no bearing on who they are.",
    },
    Field {
        path: "basis.prompt_hash",
        kind: Kind::Hash,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "The prompt by hash. The prompt itself is a payload, always.",
    },
    Field {
        path: "basis.tool_manifest",
        kind: Kind::Token {
            max_bytes: 64,
            charset: TOKEN_SEGMENT,
        },
        optional: true,
        repeated: true,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: false,
        why: "Which tools were in scope. Names only; arguments are payload.",
    },
    Field {
        path: "basis.identity_chain",
        kind: Kind::Token {
            max_bytes: 255,
            charset: TOKEN_URI,
        },
        optional: true,
        repeated: true,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: false,
        why: "Delegation in force at decision time, root first. Same pseudonymity rule as on_behalf_of.",
    },
    Field {
        path: "caused_by",
        kind: Kind::Token {
            max_bytes: 32,
            charset: "[0-9a-f]",
        },
        optional: true,
        repeated: true,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Parent records. Several, not one: a decision follows from a request and a policy and a memory state and a budget.",
    },
    Field {
        path: "outcome.verdict",
        kind: Kind::Enum(&["allowed", "denied", "held", "failed", "not_applicable"]),
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "How the decision ended. Closed vocabulary; the reasoning behind it, if any, is a payload.",
    },
    Field {
        path: "outcome.error",
        kind: Kind::Enum(&[
            "none",
            "timeout",
            "rate_limited",
            "unauthorized",
            "budget_exceeded",
            "policy_denied",
            "upstream_error",
            "malformed",
            "internal",
        ]),
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "A code, never a message. Upstream error strings quote the input, which is how personal data leaks into logs; the text goes to the payload plane.",
    },
    Field {
        path: "outcome.latency_micros",
        kind: Kind::U64,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "How long the operation took. A measurement of the work, never of its content.",
    },
    Field {
        path: "outcome.tokens_in",
        kind: Kind::U32,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Token count. A number about content, not the content.",
    },
    Field {
        path: "outcome.tokens_out",
        kind: Kind::U32,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Tokens produced. A count about content rather than the content itself.",
    },
    Field {
        path: "outcome.cost_micros",
        kind: Kind::I64,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Cost in micro-units. Integer, so money never becomes a float.",
    },
    Field {
        path: "payload.hash",
        kind: Kind::Hash,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Which payload this record points at. The reference survives erasure so the chain still verifies.",
    },
    Field {
        path: "payload.size_bytes",
        kind: Kind::U64,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Size of the payload. Reveals length, not content; needed for retention and cost.",
    },
    Field {
        path: "payload.class",
        kind: Kind::Enum(&[
            "prompt",
            "completion",
            "tool_arguments",
            "tool_result",
            "document",
            "diagnostic",
        ]),
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "What kind of payload it is, so retention and access can be decided without opening it.",
    },
    Field {
        path: "payload.key_id",
        kind: Kind::Hash,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Which key wraps this payload's data key. Destroying that key is what erasure means.",
    },
    Field {
        path: "payload.content",
        kind: Kind::Bytes,
        optional: true,
        repeated: false,
        plane: Plane::Payload,
        pii: Pii::Possible,
        provable: false,
        why: "The actual prompt, completion, arguments or document. Encrypted under a per-payload data key. This is the only place content is allowed to be.",
    },
    Field {
        path: "payload.unmapped",
        kind: Kind::FreeText,
        optional: true,
        repeated: false,
        plane: Plane::Payload,
        pii: Pii::Possible,
        provable: false,
        why: "Attributes a mapper did not recognise, kept verbatim so nothing is lost. In the payload plane precisely because unrecognised OpenTelemetry attributes routinely contain prompts and personal data.",
    },
    Field {
        path: "seq",
        kind: Kind::U64,
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Position in the shard's chain. Ours.",
    },
    Field {
        path: "prev_hash",
        kind: Kind::Hash,
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "The link that makes the chain tamper-evident.",
    },
    Field {
        path: "segment_id",
        kind: Kind::U64,
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Which segment the record landed in.",
    },
    Field {
        path: "algorithms.hash",
        kind: Kind::Enum(&["sha384"]),
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Recorded per record so the 2030 migration can enumerate what needs re-signing. Agility is schema, not configuration.",
    },
    Field {
        path: "algorithms.signature",
        // In `SigAlg::ALL` order, which is the order the variants were added:
        // `es384` came after `es256` and is what the store actually signs with.
        // It is listed rather than substituted because these fields exist to
        // make the 2030 migration enumerable, and a record that misdeclares its
        // own algorithm cannot be found by the query that plans it.
        kind: Kind::Enum(&["es256", "es384", "ml-dsa-65", "slh-dsa"]),
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Which signature scheme covered the segment this record belongs to.",
    },
    Field {
        path: "algorithms.kem",
        kind: Kind::Enum(&["x25519-ml-kem-768"]),
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Which key encapsulation wrapped the payload key. Crypto-erasure lasts exactly as long as this does.",
    },
    Field {
        path: "mapper",
        kind: Kind::U16,
        optional: false,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Which mapper version produced this record. When the semantic conventions move, this moves and the store does not.",
    },
    // ------------------------------------------------------------- v2 adds
    //
    // These four are `V2_ADDED`, and they sit LAST because `FIELDS_V1` is the
    // prefix before them. Appending is the only edit that keeps v1's own
    // artifact byte-identical, which is what makes the migration additive
    // rather than a rewrite. Anything inserted above this line changes what v1
    // says it was, about records already written.
    Field {
        path: "basis.delegation_proof.jti",
        kind: Kind::Token {
            max_bytes: 128,
            charset: TOKEN_SEGMENT,
        },
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: false,
        why: "Which token proved the chain, so an auditor can find it in the issuer's own record. An identifier, never the token.",
    },
    Field {
        path: "basis.delegation_proof.jkt",
        kind: Kind::Token {
            max_bytes: 128,
            charset: TOKEN_SEGMENT,
        },
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::OperatorPseudonymous,
        provable: false,
        why: "RFC 7638 thumbprint the token was bound to: who was holding it, which a chain of names cannot say. A key digest, not a person.",
    },
    Field {
        path: "basis.delegation_proof.iss",
        kind: Kind::Token {
            max_bytes: 255,
            charset: TOKEN_URI,
        },
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "Which issuer minted it, so the right keys and the right revocation list are consulted. A service URL.",
    },
    Field {
        path: "basis.delegation_proof.exp",
        kind: Kind::Timestamp,
        optional: true,
        repeated: false,
        plane: Plane::Metadata,
        pii: Pii::Never,
        provable: false,
        why: "When the proof stopped being one. SPEC 2 says the chain carries no freshness; this is the freshness, and it belongs to the proof.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plane_boundary_holds() {
        let v = RECORD_V1.violations();
        assert!(v.is_empty(), "schema violates its own boundary: {v:#?}");
    }

    #[test]
    fn nothing_in_metadata_can_hold_content() {
        for f in RECORD_V1.in_plane(Plane::Metadata) {
            assert!(
                !f.kind.is_unbounded(),
                "{} is unbounded and sits in metadata",
                f.path
            );
            assert_ne!(
                f.pii,
                Pii::Possible,
                "{} is content and does not belong in metadata",
                f.path
            );
        }
    }

    #[test]
    fn the_unerasable_fields_are_exactly_these_nine() {
        // Pinned on purpose. Each of these is committed into immutable index
        // roots, so no key destruction will ever reach it, and the guarantee
        // that it holds no personal data is contractual rather than technical.
        // Adding a tenth should be a decision, not a diff nobody reads.
        let mut got = RECORD_V1.unerasable_fields();
        got.sort_unstable();
        assert_eq!(
            got,
            vec![
                "agent_id",
                "basis.identity_chain",
                "basis.model",
                "basis.policy_version",
                "basis.tool_manifest",
                "on_behalf_of",
                "parent_run_id",
                "run_id",
                "tenant",
            ]
        );
    }

    #[test]
    fn every_provable_dimension_is_either_generated_or_declared_unerasable() {
        // A proof needs its dimension in the clear, so a provable field can
        // never be erasable. Saying which of the two it is, for each, is the
        // point.
        for f in RECORD_V1.fields.iter().filter(|f| f.provable) {
            assert!(
                f.pii == Pii::Never || f.pii == Pii::OperatorPseudonymous,
                "{} is provable and must be classified",
                f.path
            );
        }
    }

    #[test]
    fn content_exists_and_is_confined_to_the_payload_plane() {
        // A schema with no payload fields would pass every other test here
        // while being useless, so assert the plane is actually used.
        let payload: Vec<_> = RECORD_V1.in_plane(Plane::Payload).collect();
        assert!(!payload.is_empty());
        assert!(payload.iter().all(|f| f.pii == Pii::Possible));
        assert!(payload.iter().any(|f| f.kind.is_unbounded()));
    }

    #[test]
    fn every_field_has_a_dpia_note() {
        for f in RECORD_V1.fields {
            assert!(f.why.len() > 20, "{} has no real classification", f.path);
        }
    }

    #[test]
    fn provable_fields_match_the_declared_dimensions() {
        let mut got = RECORD_V1.provable_fields();
        got.sort_unstable();
        let mut want: Vec<&str> = PROVABLE_DIMENSIONS.to_vec();
        want.sort_unstable();
        assert_eq!(got, want);
    }

    #[test]
    fn a_violation_is_actually_detected() {
        // The rule is worthless if the check cannot fail. Build a bad schema
        // and confirm it is caught.
        const BAD: &[Field] = &[Field {
            path: "outcome.error_message",
            kind: Kind::FreeText,
            optional: true,
            repeated: false,
            plane: Plane::Metadata,
            pii: Pii::Possible,
            provable: false,
            why: "an upstream error string, which is exactly the trap",
        }];
        let bad = Schema {
            version: 99,
            fields: BAD,
        };
        let v = bad.violations();
        assert_eq!(v.len(), 2, "{v:#?}");
    }

    #[test]
    fn json_is_emitted_and_mentions_the_boundary() {
        let j = RECORD_V1.to_json();
        assert!(j.starts_with('{'));
        assert!(j.ends_with("}\n"));
        assert!(j.contains("x-plane"));
        assert!(j.contains("\"x-pii\": \"possible\""));
        assert!(j.contains("x-provable-dimensions"));
    }
}
