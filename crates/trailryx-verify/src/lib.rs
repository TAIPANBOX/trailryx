//! An offline verifier for a Trailryx evidence pack.
//!
//! # Why this crate depends on nothing
//!
//! It is the answer to the auditor's question, which is not "is your code
//! good" but "who checked it". Nobody has to trust the store to run this: the
//! crate has no dependencies at all, not even on the rest of Trailryx, and it
//! is small enough to read in a sitting. Its own SHA-384 is written here rather
//! than shared with the store, because a shared hash means a bug in it produces
//! a wrong root and a verifier that agrees.
//!
//! Two implementations by one author are not an independent audit and this file
//! does not pretend otherwise. They mean the same mistake has to be made twice
//! and still match the published NIST vectors. A third implementation written
//! from the format notes by somebody else is what closes the argument, and the
//! format notes are here for exactly that.
//!
//! # What it checks
//!
//! Everything the pack says about itself, by recomputing it:
//!
//! - each record decodes, and its sequence number increases;
//! - the hash chain runs from the segment's declared start to its declared end,
//!   through every record's own bytes;
//! - the history root is the Merkle root over those links;
//! - **each index rebuilds from the records and is strictly sorted**, which the
//!   store had assumed about itself and nobody outside it had checked;
//! - the segment's declared time span is the span its records actually have;
//! - shard roots follow from segment manifests, and the store root from shards;
//! - a shard's segments form one chain, so a whole segment cannot be dropped.
//!
//! # What it cannot check
//!
//! That the history is real rather than a consistent invention. That takes a
//! signature over the store root and an external anchor, and the verifier says
//! so plainly when it has neither, rather than reporting a clean bill.

pub mod merkle;
pub mod p384;
pub mod pack;
pub mod record;
pub mod sha384;
pub mod verify;

pub use pack::{Pack, PackError};
pub use verify::{Finding, Level, Report, verify};
