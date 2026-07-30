//! S3-compatible object storage, over the workspace's own HTTP client.
//!
//! No cloud SDK, because the S3 API is HTTP plus a signature and this workspace
//! already had the HTTP client and both hash functions. What that buys is a storage
//! adapter the size of the rest of the store instead of several hundred crates; what
//! it costs is that the signature has to be right, which is why it is checked
//! against the AWS CLI rather than against itself.

pub mod client;
pub mod sigv4;
pub mod time;
pub mod xml;

pub use client::{Addressing, Clock, Conditional, Failure, FixedClock, S3, SystemClock};
pub use sigv4::Credentials;
