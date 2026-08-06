//! The record plane, assembled: one process that takes records in, writes them
//! down, seals them on a schedule, and hands them back.
//!
//! # Why this crate exists
//!
//! Every piece of the write path was built and tested before anything joined
//! them. `trailryx-journal` takes a record; `trailryx-store` seals a journal into
//! a segment; `trailryx-index` proves an answer; `trailryx-ingest` accepts OTLP
//! over a socket. Until this crate, the only thing that put the four together was
//! `trailryx-demo`, which walks eight acceptance steps once and exits, and
//! `trailryx-ingest`'s own binary, whose drain thread counts what arrives and
//! throws it away with a comment saying so. So the shipped artefact accepted
//! records and stored none, and nothing on the way in said so.
//!
//! This is the missing process. It composes what exists and implements no
//! storage of its own:
//!
//! - [`plane::Plane`] owns one shard's journal and its assembler, appends what a
//!   source hands over, syncs on a policy, and **seals on a schedule**;
//! - a sealed segment's manifest is written beside its journal file, and that
//!   write is the commit point, exactly as it is in object storage;
//! - [`reader`] reopens a data directory in another process, rebuilds every
//!   sealed segment from the journal's own bytes, refuses any that does not
//!   rebuild the manifest that was published for it, and answers a query with a
//!   completeness proof.
//!
//! # What it deliberately does not do, stated here and in the README
//!
//! **There is no payload plane in this process.** A payload is sealed under a key
//! a custodian holds, and this tree has no key-custodian adapter: `trailryx-erasure`
//! has the mechanics and every implementation of [`trailryx_contracts::contracts::KeyProvider`]
//! in the workspace is a fake. A node that sealed prompts under keys it generated
//! itself and forgot on exit would be offering an erasure it cannot perform, which
//! is worse than not offering one. So payload parts a source hands over are
//! **declined and counted**, the record carries no payload reference, and the count
//! becomes a record of its own: see [`plane::Plane::accept`]. The metadata plane,
//! which is the provable one, is kept in full, `prompt_hash` included.
//!
//! **It does not publish to object storage and does not serve SQL.** The adapters
//! exist (`trailryx-store::tier`, `trailryx-s3`, `trailryx-azure`,
//! `trailryx-sql::server`) and nothing in this binary calls them. Sealed segments
//! live in the data directory. That is a smaller claim than "a database", and it
//! is the one this process can keep.

pub mod cursor;
pub mod events;
pub mod plane;
pub mod reader;

pub use cursor::{Cursor, Remembered, Resume};
pub use events::{Ingested, Ship, Shipped, ingest_bytes, ingest_file, ship};
pub use plane::{Accepted, Opened, Plane, PlaneError, SealPolicy, Sealed};
pub use reader::{ReadError, Sealed as SealedSegments};
