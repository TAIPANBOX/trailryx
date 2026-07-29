//! Trailryx core, stage 0.
//!
//! What exists here is the skeleton the real store grows into: shards that own
//! their data and talk only by messages, a journal shape that is self-delimiting
//! and checksummed, and a durability contract stated plainly enough to be tested:
//!
//! > every sequence number reported as acked survives any crash.
//!
//! The point of stage 0 is not the behaviour, which is trivial. It is that the
//! seam is in place: no ambient clock, no ambient randomness, no ambient disk,
//! no ambient threads. A seed reproduces a run exactly, faults included.

pub mod record;
pub mod shard;
pub mod sim;

pub use record::{Recovered, recover};
pub use shard::{Msg, Shard};
pub use sim::{Report, SimConfig, run};
