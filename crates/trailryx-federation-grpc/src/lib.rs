//! The federation transport: gRPC over mutual TLS.
//!
//! # What this crate is for, and what it must not become
//!
//! [`trailryx_federation`] holds the rule: an answer composed across
//! environments is complete if and only if the peer set is attested, every peer
//! answered, and every answer was itself complete. That crate has no
//! dependencies and no sockets. This one is the wire underneath it, and it is a
//! separate crate for a reason worth stating: an auditor reading why an answer
//! was called complete should be able to read the rule without reading tonic.
//!
//! # The three things a remote peer must not be able to do
//!
//! A peer is another environment, reached over a network. That makes it the
//! untrusted party in every exchange, and the transport carries the checks that
//! follow from saying so out loud:
//!
//! 1. **Answer under a name it cannot prove.** The peer's identity is the one
//!    in its client certificate, never the one it puts in a field. Otherwise a
//!    node that can reach the port can satisfy the completeness rule by calling
//!    itself whatever is missing, and the signed registry stops meaning
//!    anything.
//! 2. **Have a truncated stream read as a small complete answer.** The proof
//!    status arrives last, and its absence is a downgrade. This is the same
//!    failure the federation rule exists to prevent, one layer down.
//! 3. **Write free text into our metadata plane.** Identifiers are re-parsed on
//!    arrival through the same constructors that guard local ingest, and a
//!    reason for incompleteness is a code rather than a string.
//!
//! Each of those is a test in this crate, and each of them fails loudly if the
//! check is removed.

/// The generated wire types.
///
/// Kept behind its own module so a reader can tell at a glance which types came
/// from the `.proto` and which are ours.
pub mod pb {
    #![allow(clippy::doc_markdown, clippy::large_enum_variant, missing_docs)]
    tonic::include_proto!("trailryx.federation.v1");
}

mod codec;
mod transport;

pub use codec::{WireError, from_wire, to_wire};
pub use transport::{
    ClientIdentity, GrpcPeer, Incompleteness, RunningPeer, ServedProof, ServerIdentity,
    TransportError, fan_out, serve, use_aws_lc_rs,
};
