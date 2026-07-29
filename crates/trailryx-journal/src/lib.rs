//! The journal: the store's source of truth.
//!
//! Everything above it is derived. Projections, indexes and exports can be
//! thrown away and rebuilt from here; this cannot be rebuilt from them.
//!
//! Three things live in this crate:
//!
//! - [`wire`], a canonical binary encoding, because the chain hashes these
//!   exact bytes and two honest writers must never disagree about them;
//! - the framing that makes a torn tail detectable and every record verifiable
//!   on its own;
//! - [`journal`], the write path and recovery, which together enforce the
//!   durability contract in `docs/durability.md`.

pub mod journal;
pub mod wire;

pub use journal::{
    Appended, DedupWindow, Journal, JournalError, JournalResult, Recovered, StoppedBecause,
};
pub use wire::{
    FORMAT_VERSION, FRAME_VERSION, WireError, decode_frame, decode_record, encode_frame,
    encode_record,
};
