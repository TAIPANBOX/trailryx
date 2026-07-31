//! Azure Blob Storage, over the workspace's own HTTP client.
//!
//! The third cloud, and the first that needed a second signer. Google's XML API is
//! the S3 API with four names changed, so that one is a flavour of the S3 adapter.
//! Azure shares nothing with either: its own string to sign, its own
//! canonicalisation, its own key encoding, its own authorization header.
//!
//! What it does share is the shape of the problem, and therefore the answer:
//! publication is atomic because a conditional create is atomic, here spelled
//! `If-None-Match: *` on a Put Blob, and a published object is read back by version
//! rather than by name.

pub mod client;
pub mod sharedkey;

pub use client::{Azure, Failure};
pub use sharedkey::Credentials;
