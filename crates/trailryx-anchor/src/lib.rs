//! RFC 3161 anchoring: a root fixed in time by somebody we do not control.
//!
//! # The claim a signature cannot make
//!
//! A signed root says *who* published a history. It cannot say *when*, because
//! the signer chooses the timestamp they sign: nothing stops an operator from
//! signing a convenient history tomorrow and dating it yesterday. That is the
//! forgery an audit trail has to rule out, and the only defence is a third party
//! saying they saw the root when they say they saw it.
//!
//! `trailryx-sign` already carries one answer, a witness attestation, which is an
//! ECDSA signature over a different statement and needs no new machinery. This
//! crate is the other answer, the one an auditor will ask for by name: a
//! timestamp token from a public authority, obtainable today, checkable by anyone
//! with OpenSSL, and issued by an organisation with a published policy and a
//! commercial reason not to backdate.
//!
//! # Why this is not in the offline verifier
//!
//! `trailryx-verify` is small enough for a person to read in an hour, and that is
//! a load-bearing property rather than a nicety: it is the answer to "who checked
//! your code". ASN.1, CMS and RSA in that crate would roughly double it. So they
//! live here, outside it, and the verifier's own conclusions never depend on them.
//!
//! # The trust model is a pinned key, and that is deliberate
//!
//! There is **no certificate chain validation** here. No path building, no
//! revocation, no extended key usage check, no validity windows. Instead the
//! deployment configures the authority's public key, and every token is verified
//! against exactly that key.
//!
//! This is a reduction and it is a favourable one. Chain validation is a large
//! amount of code whose job is to decide, at verification time, which keys to
//! believe; pinning decides that once, out of band, where a human can look at it.
//! It is what transparency logs settled on for witnesses, for the same reason. An
//! authority that rotates its key is a configuration change, which is the honest
//! shape of that event.
//!
//! What it costs: this crate cannot be pointed at an arbitrary authority and
//! asked to work it out. That is stated rather than worked around.
//!
//! # Nothing here ever returns "verified" for an unverified token
//!
//! With no key configured, [`Anchor::verify`] returns
//! [`AdapterError::Unsupported`] and never `Ok(true)`. A receipt whose imprint
//! binds to the right root but whose signature nobody checked proves nothing at
//! all, and the one thing this crate must not do is let that read as an
//! attestation. The type that comes out of the structural check is called
//! [`tsp::Claim`]; the type that comes out of the cryptographic one is called
//! [`tsp::Attested`].

#![forbid(unsafe_code)]

pub mod bignum;
pub mod http;
pub mod oid;
pub mod rsa;
pub mod tsp;

use trailryx_contracts::contracts::{AdapterError, AdapterResult, Anchor, AnchorReceipt};
use trailryx_record::{Hash, Timestamp};

pub use rsa::RsaPublicKey;
pub use tsp::{Attested, Claim, TspError};

/// How a query reaches an authority and a response comes back.
///
/// A seam rather than a hard-coded client, because when a store talks to the
/// outside world is an operational decision and not this crate's to make. A
/// deployment behind an egress proxy, or one that batches anchoring into a
/// nightly job, supplies its own.
pub trait Transport {
    /// POST a DER `TimeStampReq`, return the DER `TimeStampResp`.
    fn exchange(&mut self, query: &[u8]) -> Result<Vec<u8>, String>;
}

/// What this adapter will believe about a token.
#[derive(Debug)]
pub enum Trust {
    /// The authority's public key, pinned. Every token's CMS signature is
    /// verified against it and nothing else is consulted.
    PinnedKey(RsaPublicKey),
    /// No key. Tokens are still obtained and stored, and their binding to a root
    /// is still checked, but `verify` refuses to answer rather than answering
    /// weakly.
    ///
    /// This exists for the deployment that anchors now and checks later, or that
    /// verifies with the authority's own toolchain. It is not a lower setting of
    /// the same dial: with this, `verify` is an error, not a `true`.
    Unchecked,
}

/// An RFC 3161 anchor.
pub struct Rfc3161 {
    transport: Box<dyn Transport + Send>,
    trust: Trust,
    /// Supplied by the embedding store, exactly as the clock is elsewhere in this
    /// workspace. A nonce this crate generated would need a source of randomness
    /// it has no business owning, and a counter it kept in memory would repeat
    /// after a restart.
    nonce: Box<dyn FnMut() -> u64 + Send>,
    /// Every nonce this adapter has sent and not yet seen answered.
    ///
    /// One entry, because `submit` is synchronous. It is here rather than passed
    /// through the call so that `Anchor::submit`, whose signature this crate does
    /// not own, can still check the response it gets against the request it made.
    last_sent: Option<(Hash, u64)>,
}

impl std::fmt::Debug for Rfc3161 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rfc3161")
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

impl Rfc3161 {
    pub fn new(
        transport: Box<dyn Transport + Send>,
        trust: Trust,
        nonce: Box<dyn FnMut() -> u64 + Send>,
    ) -> Self {
        Self {
            transport,
            trust,
            nonce,
            last_sent: None,
        }
    }

    /// Whether a token's signature can be checked here at all.
    ///
    /// Named after `Aead::is_validated`, and for the same reason: a seam that can
    /// be configured weakly has to be able to say so out loud, so a caller can
    /// refuse rather than discover it later.
    pub fn is_attesting(&self) -> bool {
        matches!(self.trust, Trust::PinnedKey(_))
    }

    /// Read a token that arrived some other way: from an older pack, from a
    /// nightly batch, from an operator's own file.
    ///
    /// `nonce` is what was sent when the token was obtained. A caller that no
    /// longer has it cannot show the token answers its request, which is why
    /// there is no version of this that omits it.
    pub fn examine(&self, root: Hash, token: &[u8], nonce: u64) -> Result<Attested, TspError> {
        let imprint = tsp::imprint_of(root.as_bytes());
        match &self.trust {
            Trust::PinnedKey(key) => {
                let attested = tsp::attest(token, key)?;
                tsp::binds_to(&attested.claim, &imprint, nonce)?;
                Ok(attested)
            }
            Trust::Unchecked => {
                // The binding is still checked, so the caller learns whether the
                // token is even about their root. What they do not get is an
                // `Attested`, because nothing attested it.
                let claim = tsp::claim_of(token)?;
                tsp::binds_to(&claim, &imprint, nonce)?;
                Err(TspError::NoPinnedKey)
            }
        }
    }
}

impl Anchor for Rfc3161 {
    fn submit(&mut self, root: Hash) -> AdapterResult<AnchorReceipt> {
        let imprint = tsp::imprint_of(root.as_bytes());
        let nonce = (self.nonce)();
        let query = tsp::request(&imprint, nonce);

        let response = self
            .transport
            .exchange(&query)
            .map_err(|why| AdapterError::Unavailable(leak(format!("the authority: {why}"))))?;

        let token = tsp::token_from_response(&response)
            .map_err(|e| AdapterError::Rejected(leak(e.to_string())))?
            .to_vec();

        // The binding is checked before the receipt exists, so a receipt for
        // somebody else's root is never constructed and never stored. Checked
        // with the structural reader even when a key is pinned, because the
        // question "is this about my root" has an answer that does not depend on
        // whose signature it carries.
        let claim =
            tsp::claim_of(&token).map_err(|e| AdapterError::Rejected(leak(e.to_string())))?;
        tsp::binds_to(&claim, &imprint, nonce)
            .map_err(|e| AdapterError::Rejected(leak(e.to_string())))?;

        if let Trust::PinnedKey(key) = &self.trust {
            tsp::attest(&token, key).map_err(|e| AdapterError::Rejected(leak(e.to_string())))?;
        }

        // A token dated before the epoch is not a clock skew, it is a token this
        // store cannot represent, and silently clamping it to zero would record
        // an anchor at the epoch.
        let at = u64::try_from(claim.at)
            .map_err(|_| AdapterError::Rejected("the token is dated before 1970"))?
            .checked_mul(1_000_000_000)
            .ok_or(AdapterError::Rejected(
                "the token's time does not fit this store's nanosecond stamp",
            ))?;

        self.last_sent = Some((root, nonce));
        Ok(AnchorReceipt {
            root,
            at: Timestamp(at),
            evidence: token,
        })
    }

    /// Whether this receipt is an attestation of this root.
    ///
    /// Returns `Ok(true)` only when a key is pinned **and** the token's signature
    /// verified against it **and** the token commits to this root under the nonce
    /// that was sent. With no key pinned the answer is
    /// [`AdapterError::Unsupported`], because the honest answer is "not here" and
    /// `false` would say the receipt is bad when it may be fine.
    fn verify(&self, root: Hash, receipt: &AnchorReceipt) -> AdapterResult<bool> {
        let Trust::PinnedKey(key) = &self.trust else {
            return Err(AdapterError::Unsupported(
                "no authority key is pinned, so a token's signature cannot be checked here",
            ));
        };
        // The receipt must be about the root being asked about. A receipt whose
        // own field disagrees with the question is not a weak answer, it is a
        // different receipt.
        if receipt.root != root {
            return Ok(false);
        }
        let Some((sent_root, nonce)) = self.last_sent else {
            return Err(AdapterError::Unsupported(
                "this adapter did not obtain that token, so the nonce it answers is unknown; use `examine`",
            ));
        };
        if sent_root != root {
            return Err(AdapterError::Unsupported(
                "the nonce held by this adapter belongs to a different root; use `examine`",
            ));
        }

        let imprint = tsp::imprint_of(root.as_bytes());
        match tsp::attest(&receipt.evidence, key) {
            Ok(attested) => Ok(tsp::binds_to(&attested.claim, &imprint, nonce).is_ok()),
            // A token that does not verify is a `false` and not an error: the
            // caller asked a yes-or-no question and the answer is no.
            Err(_) => Ok(false),
        }
    }
}

/// `AdapterError` carries `&'static str`, and the reasons here are computed.
///
/// Leaking a short string per rejected anchor is the price of that signature.
/// Anchoring happens once per sealed segment and a rejection is an incident, so
/// the total is bounded by how many times an operator points this at a
/// misbehaving authority. Said out loud rather than hidden behind a helper with a
/// neutral name.
fn leak(reason: String) -> &'static str {
    Box::leak(reason.into_boxed_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trailryx_record::HASH_BYTES;

    struct Dead;
    impl Transport for Dead {
        fn exchange(&mut self, _query: &[u8]) -> Result<Vec<u8>, String> {
            Err("connection refused".to_owned())
        }
    }

    struct Fixed(Vec<u8>);
    impl Transport for Fixed {
        fn exchange(&mut self, _query: &[u8]) -> Result<Vec<u8>, String> {
            Ok(self.0.clone())
        }
    }

    fn root() -> Hash {
        Hash([0x33u8; HASH_BYTES])
    }

    #[test]
    fn a_transport_failure_is_unavailable_and_therefore_worth_retrying() {
        let mut anchor = Rfc3161::new(Box::new(Dead), Trust::Unchecked, Box::new(|| 1));
        assert!(matches!(
            anchor.submit(root()),
            Err(AdapterError::Unavailable(_))
        ));
    }

    /// The property this crate exists to protect: with no key pinned, `verify`
    /// must not be able to say yes. Not `false`, which would blame the receipt,
    /// and never `true`.
    #[test]
    fn with_no_key_pinned_verify_refuses_rather_than_answering() {
        let anchor = Rfc3161::new(Box::new(Dead), Trust::Unchecked, Box::new(|| 1));
        assert!(!anchor.is_attesting());
        let receipt = AnchorReceipt {
            root: root(),
            at: Timestamp(0),
            evidence: vec![1, 2, 3],
        };
        assert!(matches!(
            anchor.verify(root(), &receipt),
            Err(AdapterError::Unsupported(_))
        ));
    }

    #[test]
    fn a_refusal_from_the_authority_is_rejected_and_names_the_status() {
        let refusal =
            trailryx_asn1::sequence(&[trailryx_asn1::sequence(&[trailryx_asn1::integer_u64(2)])]);
        let mut anchor = Rfc3161::new(Box::new(Fixed(refusal)), Trust::Unchecked, Box::new(|| 1));
        let Err(AdapterError::Rejected(why)) = anchor.submit(root()) else {
            panic!("a rejection must be Rejected and not Unavailable");
        };
        assert!(why.contains("PKIStatus 2"), "{why}");
    }

    /// A response about a different root must never become a receipt. The check
    /// runs before the receipt is constructed, so there is no window in which a
    /// wrong one exists.
    #[test]
    fn a_token_for_another_root_never_becomes_a_receipt() {
        let other = tsp::imprint_of(&[0x99u8; HASH_BYTES]);
        let token = fake_token(&other, "20260730143000Z", Some(1));
        let mut response = trailryx_asn1::sequence(&[trailryx_asn1::integer_u64(0)]);
        response.extend_from_slice(&token);
        let response = trailryx_asn1::tlv(trailryx_asn1::tag::SEQUENCE, &response);

        let mut anchor = Rfc3161::new(Box::new(Fixed(response)), Trust::Unchecked, Box::new(|| 1));
        let Err(AdapterError::Rejected(why)) = anchor.submit(root()) else {
            panic!("a token for another root must be rejected");
        };
        assert!(why.contains("different value"), "{why}");
    }

    #[test]
    fn a_token_whose_nonce_does_not_match_is_rejected_as_a_possible_replay() {
        let imprint = tsp::imprint_of(root().as_bytes());
        let token = fake_token(&imprint, "20260730143000Z", Some(7));
        let mut response = trailryx_asn1::sequence(&[trailryx_asn1::integer_u64(0)]);
        response.extend_from_slice(&token);
        let response = trailryx_asn1::tlv(trailryx_asn1::tag::SEQUENCE, &response);

        // The adapter sends 1 and the token answers 7.
        let mut anchor = Rfc3161::new(Box::new(Fixed(response)), Trust::Unchecked, Box::new(|| 1));
        let Err(AdapterError::Rejected(why)) = anchor.submit(root()) else {
            panic!("a mismatched nonce must be rejected");
        };
        assert!(why.contains("replay"), "{why}");
    }

    #[test]
    fn a_well_formed_token_becomes_a_receipt_carrying_the_exact_token_bytes() {
        let imprint = tsp::imprint_of(root().as_bytes());
        let token = fake_token(&imprint, "20260730143000Z", Some(1));
        let mut response = trailryx_asn1::sequence(&[trailryx_asn1::integer_u64(0)]);
        response.extend_from_slice(&token);
        let response = trailryx_asn1::tlv(trailryx_asn1::tag::SEQUENCE, &response);

        let mut anchor = Rfc3161::new(Box::new(Fixed(response)), Trust::Unchecked, Box::new(|| 1));
        let receipt = anchor.submit(root()).expect("a granted, bound token");
        assert_eq!(receipt.root, root());
        assert_eq!(receipt.at, Timestamp(1_785_421_800 * 1_000_000_000));
        assert_eq!(
            receipt.evidence, token,
            "the receipt must carry the delivered bytes and not a re-encoding"
        );
    }

    /// A token dated before 1970 cannot be represented by a nanosecond stamp,
    /// and clamping it to the epoch would record an anchor that says nothing.
    #[test]
    fn a_token_dated_before_the_epoch_is_refused_rather_than_clamped() {
        let imprint = tsp::imprint_of(root().as_bytes());
        let token = fake_token(&imprint, "19600101000000Z", Some(1));
        let mut response = trailryx_asn1::sequence(&[trailryx_asn1::integer_u64(0)]);
        response.extend_from_slice(&token);
        let response = trailryx_asn1::tlv(trailryx_asn1::tag::SEQUENCE, &response);

        let mut anchor = Rfc3161::new(Box::new(Fixed(response)), Trust::Unchecked, Box::new(|| 1));
        let Err(AdapterError::Rejected(why)) = anchor.submit(root()) else {
            panic!("a pre-epoch token must be refused");
        };
        assert!(why.contains("before 1970"), "{why}");
    }

    /// A CMS wrapper with no signer, for the paths that do not touch a signature.
    /// Deliberately not a valid token: `Trust::Unchecked` is the only setting
    /// under which anything accepts it, and that is exactly the point being
    /// tested.
    fn fake_token(imprint: &[u8; 48], time: &str, nonce: Option<u64>) -> Vec<u8> {
        let mut info = vec![
            trailryx_asn1::integer_u64(1),
            trailryx_asn1::oid(&[0x2A, 0x03, 0x04]),
            trailryx_asn1::sequence(&[
                trailryx_asn1::sequence(&[trailryx_asn1::oid(oid::SHA384), trailryx_asn1::null()]),
                trailryx_asn1::octet_string(imprint),
            ]),
            trailryx_asn1::integer_u64(1),
            trailryx_asn1::tlv(trailryx_asn1::tag::GENERALIZED_TIME, time.as_bytes()),
        ];
        if let Some(n) = nonce {
            info.push(trailryx_asn1::integer_u64(n));
        }
        let tst = trailryx_asn1::sequence(&info);

        let signed_data = trailryx_asn1::sequence(&[
            trailryx_asn1::integer_u64(3),
            trailryx_asn1::tlv(trailryx_asn1::tag::SET, &[]),
            trailryx_asn1::sequence(&[
                trailryx_asn1::oid(oid::TST_INFO),
                trailryx_asn1::tlv(
                    trailryx_asn1::tag::context_constructed(0),
                    &trailryx_asn1::octet_string(&tst),
                ),
            ]),
            trailryx_asn1::tlv(trailryx_asn1::tag::SET, &[]),
        ]);
        trailryx_asn1::sequence(&[
            trailryx_asn1::oid(oid::SIGNED_DATA),
            trailryx_asn1::tlv(trailryx_asn1::tag::context_constructed(0), &signed_data),
        ])
    }
}
