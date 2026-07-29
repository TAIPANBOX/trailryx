//! Payload custody and erasure.
//!
//! The store's promise is that it can erase one person on request and still be
//! evidence afterwards. Those two are usually in tension: an audit trail
//! defends itself by being unchangeable, and erasure means changing it. This
//! crate is where they stop being in tension.
//!
//! The trick is old and the details are where it goes wrong. Payloads are
//! encrypted; a record commits to its payload by hash, size, class and key id
//! rather than containing it; erasure destroys the key. Every chain, root and
//! proof issued before an erasure still verifies after it, because none of the
//! four committed fields changed.
//!
//! # What this crate does not do
//!
//! It does not implement the cipher or the key generator. Those sit behind
//! [`aead::Aead`] and [`aead::KeySource`], and a deployment supplies a
//! FIPS-validated module. The stand-ins here answer `false` to
//! `is_validated()`, and [`Vault::new`] refuses them.
//!
//! # Where the roadmap was wrong
//!
//! It said attribution should re-wrap a payload's key and destroy the old
//! wrapping. It cannot: the old wrapping is in replicated, backed-up, often
//! write-once storage, and "destroy the old wrapping" means deleting an object,
//! which is the thing crypto-erasure exists to avoid needing. See
//! [`subject`] for what replaced it.

pub mod aead;
pub mod envelope;
pub mod subject;
pub mod vault;

pub use aead::{Aead, Dek, KeySource, PredictableKeys, Sha384Ctr};
pub use envelope::{Envelope, EnvelopeError, associated_data};
pub use subject::{KeyLedger, SubjectHandle, kek_for_record, kek_for_subject};
pub use vault::{
    Forgotten, Vault, VaultError, decode_manifest, decode_parts, encode_parts, manifest_entry,
};
