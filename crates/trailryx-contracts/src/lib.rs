//! The L1 adapter contracts.
//!
//! Trailryx keeps a small core and a wide periphery: clouds, protocols, queues,
//! key stores, SIEMs. That only works if an adapter cannot weaken a guarantee
//! the core makes, so the boundary is drawn here and defended two ways.
//!
//! **By type.** A source hands over [`ingest::MetaDraft`] plus separately
//! classified [`ingest::PayloadPart`]s. `MetaDraft` has no free-text field, so
//! an adapter that wanted to put a prompt in the metadata plane has nowhere to
//! put it. That is stronger than a rule, because there is nothing to break.
//!
//! **By suite.** [`conformance`] states each guarantee as a check an
//! implementation either passes or does not. It is public so adapter authors
//! can run it themselves, and [`fakes`] carries deliberately wrong
//! implementations that the tests confirm it catches.
//!
//! Frozen at the end of stage 1: adding a method later breaks every adapter.

pub mod conformance;
pub mod contracts;
pub mod fakes;
pub mod ingest;

pub use conformance::{Check, Report};
pub use contracts::{
    Action, AdapterError, AdapterResult, Anchor, AnchorReceipt, AuthProvider, Decision, Delivery,
    Destroyed, ForeignColumn, ForeignTable, KeyId, KeyProvider, Lossiness, ObjectStore, Ordering,
    Peer, PeerDescriptor, PeerResponse, Principal, ProofStatus, PutOutcome, Sink, SinkDescriptor,
    Source, SourceDescriptor, Trust,
};
pub use ingest::{Correlation, Cursor, Ingest, MetaDraft, PayloadPart, SourceKey};
