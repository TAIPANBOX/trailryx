//! RFC 3161: building a request, and reading a token without believing it.
//!
//! # The two questions a token answers, kept apart
//!
//! 1. **Does this token commit to my root?** Structural. It is answered by
//!    comparing the token's `messageImprint` against a hash we computed
//!    ourselves, and it needs no key and no trust in anybody.
//! 2. **Did the authority actually sign it?** Cryptographic. It needs the
//!    authority's key and it is where [`crate::rsa`] comes in.
//!
//! They are separate functions returning separate types, because the failure
//! modes are different and the answers must never be confused. A token that
//! binds but is unsigned proves nothing at all; a token whose signature verifies
//! but whose imprint is somebody else's root proves something about somebody
//! else. Both are refused, separately, by name.
//!
//! # Why the nonce is checked
//!
//! RFC 3161 makes the nonce optional and a lot of clients ignore it. It is the
//! only thing that distinguishes "the authority answered *my* request just now"
//! from "somebody replayed an old response for the same root". Since the root is
//! the same across retries of the same segment, a replay would otherwise be
//! indistinguishable from a fresh answer, and an anchor whose time can be replayed
//! backwards is an anchor that does not fix anything in time. So a nonce is always
//! sent and a response that omits or changes it is refused.

use trailryx_asn1::{Asn1Error, Der, tag};
use trailryx_crypto::{Sha256, Sha384};

use crate::oid;
use crate::rsa::{DigestKind, RsaError, RsaPublicKey, SignatureAlgorithm};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TspError {
    /// The response did not parse.
    Malformed(&'static str, Asn1Error),
    /// The authority refused, with the PKIStatus it returned. 2 and above are
    /// rejections; 1 is "granted with modifications", which this client treats
    /// as a refusal because the modification is exactly what it did not ask for.
    Refused { status: u64 },
    /// A response with a status of granted and no token in it.
    NoToken,
    /// The token's content type is not `id-ct-TSTInfo`, so whatever it holds is
    /// not a timestamp.
    NotATimestamp,
    /// The token names a different hash algorithm than the request did.
    ImprintAlgorithm,
    /// The token commits to a different value than the root asked about. The
    /// answer that matters: this token is about somebody else's data.
    ImprintMismatch,
    /// The nonce is absent or is not the one that was sent, so this response
    /// cannot be shown to be an answer to this request.
    NonceMismatch,
    /// A `TSTInfo` version this client does not know. Version 1 is the only one
    /// RFC 3161 defines.
    UnknownVersion(u64),
    /// The CMS structure is not the single-signer SignedData a timestamp token
    /// is defined to be.
    UnsupportedCms(&'static str),
    /// The signed attributes do not contain the message digest, or contain one
    /// that is not the digest of the content.
    ContentDigestMismatch,
    /// The signed attributes name a content type other than the one they wrap.
    ContentTypeMismatch,
    /// The signature did not verify against the pinned key.
    Signature(RsaError),
    /// A digest or signature algorithm this implementation does not have.
    UnsupportedAlgorithm,
    /// No authority key is configured, so the signature cannot be checked here.
    ///
    /// Its own variant rather than a signature failure, because the token may be
    /// perfectly good: what is missing is on this side.
    NoPinnedKey,
}

impl std::fmt::Display for TspError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(what, e) => write!(f, "{what} did not parse: {e}"),
            Self::Refused { status } => {
                write!(
                    f,
                    "the authority returned PKIStatus {status} rather than granted"
                )
            }
            Self::NoToken => f.write_str("the authority granted the request and sent no token"),
            Self::NotATimestamp => f.write_str("the token does not hold a TSTInfo"),
            Self::ImprintAlgorithm => f.write_str("the token used a different hash algorithm"),
            Self::ImprintMismatch => {
                f.write_str("the token commits to a different value than this root")
            }
            Self::NonceMismatch => {
                f.write_str("the nonce is absent or not the one sent, so this may be a replay")
            }
            Self::UnknownVersion(v) => write!(f, "TSTInfo version {v} is not version 1"),
            Self::UnsupportedCms(what) => write!(f, "the CMS structure is not supported: {what}"),
            Self::ContentDigestMismatch => {
                f.write_str("the signed message digest is not the digest of the content")
            }
            Self::ContentTypeMismatch => {
                f.write_str("the signed content type is not the content's own type")
            }
            Self::Signature(e) => write!(f, "the signature did not verify: {e}"),
            Self::UnsupportedAlgorithm => f.write_str("an algorithm this client does not have"),
            Self::NoPinnedKey => {
                f.write_str("no authority key is pinned, so no signature was checked")
            }
        }
    }
}

impl std::error::Error for TspError {}

/// The whole of a timestamp request, DER encoded, ready to POST.
///
/// `certReq` is **false**: the authority's certificate is not asked for, because
/// this client does not validate certificate chains and a chain it stored but
/// never checked would be evidence-shaped clutter that reads like evidence. The
/// trust anchor is a pinned key, configured out of band.
pub fn request(imprint: &[u8; 48], nonce: u64) -> Vec<u8> {
    trailryx_asn1::sequence(&[
        trailryx_asn1::integer_u64(1),
        // MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }
        trailryx_asn1::sequence(&[
            trailryx_asn1::sequence(&[trailryx_asn1::oid(oid::SHA384), trailryx_asn1::null()]),
            trailryx_asn1::octet_string(imprint),
        ]),
        trailryx_asn1::integer_u64(nonce),
        trailryx_asn1::boolean(false),
    ])
}

/// What a token says about itself, once it has been read but before anybody has
/// been trusted about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The value the authority stamped, which the caller compares against a hash
    /// it computed.
    pub imprint: [u8; 48],
    /// `genTime`, as whole seconds since the Unix epoch.
    pub at: i64,
    /// The authority's serial number for this token. Kept because it is what a
    /// dispute is opened with.
    pub serial: Vec<u8>,
    /// The nonce the token echoed.
    pub nonce: Option<u64>,
}

/// Split a `TimeStampResp` into its status and its token bytes.
///
/// The token is returned as the exact bytes that were delivered, because they are
/// what gets stored and what any other tool will be pointed at. Nothing is
/// re-encoded: a re-encoded token is a different byte string and its signature
/// would no longer verify.
pub fn token_from_response(response: &[u8]) -> Result<&[u8], TspError> {
    let mut outer = Der::new(response);
    let mut resp = outer
        .take_nested(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("TimeStampResp", e))?;

    // PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString OPTIONAL, failInfo OPTIONAL }
    let mut info = resp
        .take_nested(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("PKIStatusInfo", e))?;
    let status = info
        .integer_u64()
        .map_err(|e| TspError::Malformed("PKIStatus", e))?;
    // 0 is granted. 1 is granted with modifications, which is refused: a
    // modification is the authority answering a question that was not asked.
    if status != 0 {
        return Err(TspError::Refused { status });
    }

    // statusString and failInfo are optional and irrelevant to a granted
    // response; skipping the rest of the status is what lets the token be the
    // next value rather than the third.
    if resp.is_empty() {
        return Err(TspError::NoToken);
    }
    // Whole, tag and length included, so the stored bytes are a self-contained
    // DER value and byte-identical to what the authority signed.
    let token = resp
        .take_raw()
        .map_err(|e| TspError::Malformed("TimeStampToken", e))?;
    // A second value after the token is a field this client did not read, inside
    // a message it is about to call complete.
    resp.expect_end()
        .map_err(|e| TspError::Malformed("TimeStampResp", e))?;
    outer
        .expect_end()
        .map_err(|e| TspError::Malformed("TimeStampResp", e))?;
    Ok(token)
}

/// Read the `TSTInfo` out of a token and return what it claims.
///
/// **This checks no signature.** It answers question one only, and the type it
/// returns is called [`Claim`] rather than anything with "verified" in the name
/// for that reason.
pub fn claim_of(token: &[u8]) -> Result<Claim, TspError> {
    let content = tst_info_bytes(token)?;
    parse_tst_info(content)
}

/// Which bytes of a token a verifier's answer actually depends on.
///
/// Offsets into the token, so a caller can see the trust surface rather than
/// assume it is the whole file. It exists because assuming otherwise was wrong:
/// a bit-flip sweep over a real token found seventy-three offsets where a flipped
/// bit changed nothing, and every one of them was in a field CMS does not sign.
///
/// # What is outside these ranges, and why that is not a hole
///
/// - **`digestAlgorithms`**, the SET at the top of `SignedData`. RFC 5652 puts it
///   there for one-pass processing; it is not covered by any signature and this
///   crate never reads it. The digest it uses comes from the `SignerInfo`, which
///   is inside the signed region.
/// - **`certificates`**, the authority's certificate chain. Not covered by the
///   signature either, and deliberately ignored: this crate pins a key, so a
///   chain it stored would be evidence-shaped clutter it never checked.
/// - **Unsigned attributes**, if any. Unsigned, therefore not evidence.
///
/// A token altered in those places still verifies here and would be **rejected**
/// by a chain-validating verifier such as `openssl ts -verify`. That direction is
/// the safe one: this crate is more permissive about what it ignores, never about
/// what it believes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Covered {
    /// The `TSTInfo` bytes, which the signed `messageDigest` attribute commits to.
    pub content: core::ops::Range<usize>,
    /// The signed attribute set, which the signature is computed over.
    pub signed_attrs: core::ops::Range<usize>,
    /// The signature itself.
    pub signature: core::ops::Range<usize>,
}

impl Covered {
    pub fn contains(&self, offset: usize) -> bool {
        self.content.contains(&offset)
            || self.signed_attrs.contains(&offset)
            || self.signature.contains(&offset)
    }

    pub fn total(&self) -> usize {
        self.content.len() + self.signed_attrs.len() + self.signature.len()
    }
}

/// Locate the three ranges a verification depends on.
///
/// Computed by walking the token exactly as [`attest`] does and recording where
/// each borrowed slice sits, so the answer cannot drift from what verification
/// actually reads.
pub fn covered(token: &[u8]) -> Result<Covered, TspError> {
    // Every slice below is a subslice of `token`, so the pointer difference is
    // its offset. Safe Rust, and exact: deriving the offsets by searching for the
    // bytes could match the wrong occurrence, and threading positions through the
    // reader would put arithmetic in the parser to serve a reporting function.
    let base = token.as_ptr() as usize;
    let span = |slice: &[u8]| -> core::ops::Range<usize> {
        let start = slice.as_ptr() as usize - base;
        start..start + slice.len()
    };
    let content = tst_info_bytes(token)?;
    let parts = signer_parts(token)?;
    Ok(Covered {
        content: span(content),
        signed_attrs: span(parts.signed_attrs),
        signature: span(parts.signature),
    })
}

/// Everything about a token that a caller may believe, once the signature has
/// been checked against a key the caller chose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    pub claim: Claim,
    /// Which digest the authority signed with. Recorded because "verified" is
    /// not a fact on its own: it is a fact about an algorithm.
    pub digest: DigestKind,
}

/// Check the token's CMS signature against a pinned key, then return what it
/// says.
///
/// The order is deliberate: the signature is checked over the exact content
/// bytes that were delivered, and only then is the content read. A reader that
/// parsed first and verified afterwards would have already acted on unsigned
/// input.
pub fn attest(token: &[u8], key: &RsaPublicKey) -> Result<Attested, TspError> {
    let signed = verify_signed_data(token, key)?;
    Ok(Attested {
        claim: parse_tst_info(signed.content)?,
        digest: signed.digest,
    })
}

/// Confirm a claim is about this root, and about this request.
///
/// Separate from parsing so that the comparison is a step somebody can see
/// happening, rather than a condition buried in a parser.
pub fn binds_to(claim: &Claim, root_imprint: &[u8; 48], nonce: u64) -> Result<(), TspError> {
    if claim.imprint != *root_imprint {
        return Err(TspError::ImprintMismatch);
    }
    if claim.nonce != Some(nonce) {
        return Err(TspError::NonceMismatch);
    }
    Ok(())
}

/// The imprint a root is stamped as: SHA-384 of the root's bytes.
///
/// Named rather than inlined because both the request and the check must use the
/// same rule, and two call sites computing it separately is how they come to
/// disagree.
pub fn imprint_of(root: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(Sha384::digest(root).as_bytes());
    out
}

// ---------------------------------------------------------------------------
// CMS, the smallest subset a timestamp token is allowed to be
// ---------------------------------------------------------------------------

struct SignedContent<'a> {
    content: &'a [u8],
    digest: DigestKind,
}

/// `ContentInfo { id-signedData, [0] SignedData }` down to the content bytes.
fn tst_info_bytes(token: &[u8]) -> Result<&[u8], TspError> {
    let mut outer = Der::new(token);
    let mut ci = outer
        .take_nested(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("ContentInfo", e))?;
    let content_type = ci
        .oid()
        .map_err(|e| TspError::Malformed("ContentInfo contentType", e))?;
    if content_type.as_bytes() != oid::SIGNED_DATA {
        return Err(TspError::UnsupportedCms(
            "the outer content is not SignedData",
        ));
    }
    let mut explicit = ci
        .take_nested(tag::context_constructed(0))
        .map_err(|e| TspError::Malformed("ContentInfo content", e))?;
    let mut sd = explicit
        .take_nested(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("SignedData", e))?;

    sd.integer_u64()
        .map_err(|e| TspError::Malformed("SignedData version", e))?;
    sd.skip()
        .map_err(|e| TspError::Malformed("digestAlgorithms", e))?;

    // EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, [0] eContent OPTIONAL }
    let mut eci = sd
        .take_nested(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("encapContentInfo", e))?;
    let econtent_type = eci
        .oid()
        .map_err(|e| TspError::Malformed("eContentType", e))?;
    if econtent_type.as_bytes() != oid::TST_INFO {
        return Err(TspError::NotATimestamp);
    }
    let mut wrapper = eci
        .take_nested(tag::context_constructed(0))
        .map_err(|e| TspError::Malformed("eContent", e))?;
    let content = wrapper
        .octet_string()
        .map_err(|e| TspError::Malformed("eContent octets", e))?;
    wrapper
        .expect_end()
        .map_err(|e| TspError::Malformed("eContent", e))?;
    Ok(content)
}

/// The borrowed pieces of the single `SignerInfo`.
struct SignerParts<'a> {
    /// The contents of the `[0] IMPLICIT SET OF Attribute`, without its tag.
    signed_attrs: &'a [u8],
    signature: &'a [u8],
    digest: DigestKind,
}

/// Walk to the one `SignerInfo` and return its pieces.
///
/// One function rather than two so that [`covered`] and [`verify_signed_data`]
/// cannot disagree about which bytes verification reads. A second walk that
/// drifted from the first would report a trust surface that was not the real one,
/// which is worse than reporting none.
///
/// Restrictions, each of which is a shape a timestamp token is defined to have
/// and each of which is refused rather than handled:
///
/// - **Exactly one signer.** RFC 3161 §2.4.2 says a token has one. Several
///   signers would raise the question of how many must verify, and any answer
///   below "all of them" is a token that verifies while a signer disagrees.
/// - **Signed attributes are required**, because they carry the digest of the
///   content. Without them the signature would be over the content directly and
///   the content type would be unbound.
/// - **No unsigned attributes are consulted.** They are not signed, so they are
///   not evidence.
fn signer_parts(token: &[u8]) -> Result<SignerParts<'_>, TspError> {
    let mut outer = Der::new(token);
    let mut ci = outer
        .take_nested(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("ContentInfo", e))?;
    ci.skip()
        .map_err(|e| TspError::Malformed("contentType", e))?;
    let mut explicit = ci
        .take_nested(tag::context_constructed(0))
        .map_err(|e| TspError::Malformed("content", e))?;
    let mut sd = explicit
        .take_nested(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("SignedData", e))?;
    sd.integer_u64()
        .map_err(|e| TspError::Malformed("version", e))?;
    sd.skip()
        .map_err(|e| TspError::Malformed("digestAlgorithms", e))?;
    sd.skip()
        .map_err(|e| TspError::Malformed("encapContentInfo", e))?;
    // certificates [0] and crls [1], both optional and both ignored: this client
    // does not validate chains, so carrying them would be storing something it
    // never looks at.
    sd.skip_if(tag::context_constructed(0))
        .map_err(|e| TspError::Malformed("certificates", e))?;
    sd.skip_if(tag::context_constructed(1))
        .map_err(|e| TspError::Malformed("crls", e))?;

    let mut signers = sd
        .take_nested(tag::SET)
        .map_err(|e| TspError::Malformed("signerInfos", e))?;
    let mut si = signers
        .take_nested(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("SignerInfo", e))?;
    if !signers.is_empty() {
        return Err(TspError::UnsupportedCms("more than one signer"));
    }

    si.integer_u64()
        .map_err(|e| TspError::Malformed("SignerInfo version", e))?;
    // sid: either an IssuerAndSerialNumber (SEQUENCE) or [0] subjectKeyIdentifier.
    si.skip()
        .map_err(|e| TspError::Malformed("signerIdentifier", e))?;
    let (digest_algorithm, _) = si
        .algorithm_identifier()
        .map_err(|e| TspError::Malformed("digestAlgorithm", e))?;
    let digest = DigestKind::from_digest_oid(digest_algorithm.as_bytes())
        .ok_or(TspError::UnsupportedAlgorithm)?;

    if si.peek_tag() != Some(tag::context_constructed(0)) {
        return Err(TspError::UnsupportedCms("no signed attributes"));
    }
    let signed_attrs = si
        .take(tag::context_constructed(0))
        .map_err(|e| TspError::Malformed("signedAttrs", e))?;

    let (signature_algorithm, _) = si
        .algorithm_identifier()
        .map_err(|e| TspError::Malformed("signatureAlgorithm", e))?;
    let signature_kind = SignatureAlgorithm::from_oid(signature_algorithm.as_bytes())
        .ok_or(TspError::UnsupportedAlgorithm)?;
    // `rsaEncryption` names no digest and takes the one above; the
    // `sha256WithRSAEncryption` spelling names it twice and the two must agree. A
    // token where they differ has two half-trusted algorithms in it.
    if !signature_kind.agrees_with(digest) {
        return Err(TspError::UnsupportedCms(
            "the digest and signature algorithms disagree",
        ));
    }
    let signature = si
        .octet_string()
        .map_err(|e| TspError::Malformed("signature", e))?;

    Ok(SignerParts {
        signed_attrs,
        signature,
        digest,
    })
}

/// Check the one `SignerInfo` and return the content it covers.
///
/// The restrictions are all in [`signer_parts`]; this adds the two checks that
/// need the content: that the signed digest is the digest of it, and that the
/// signature verifies over the attributes carrying that digest.
fn verify_signed_data<'a>(
    token: &'a [u8],
    key: &RsaPublicKey,
) -> Result<SignedContent<'a>, TspError> {
    let content = tst_info_bytes(token)?;
    let parts = signer_parts(token)?;
    check_signed_attrs(parts.signed_attrs, content, parts.digest)?;

    // RFC 5652 §5.4: the signature is over the DER of the signed attributes with
    // the IMPLICIT [0] tag replaced by SET OF. Getting this wrong is the single
    // most common way a hand-written CMS verifier fails to verify a valid token,
    // and it fails closed, so it looks like a bad signature.
    let to_be_signed = trailryx_asn1::tlv(tag::SET, parts.signed_attrs);
    let digest = digest_of(parts.digest, &to_be_signed);
    key.verify(parts.digest, &digest, parts.signature)
        .map_err(TspError::Signature)?;

    Ok(SignedContent {
        content,
        digest: parts.digest,
    })
}

/// The two attributes that bind a signature to its content, both required.
///
/// Without `messageDigest` the signature covers the attribute set and says
/// nothing about the timestamp inside. Without `contentType` a signature over one
/// kind of content could be presented as covering another.
fn check_signed_attrs(body: &[u8], content: &[u8], kind: DigestKind) -> Result<(), TspError> {
    let mut attrs = Der::new(body);
    let mut saw_digest = false;
    let mut saw_type = false;

    while !attrs.is_empty() {
        let mut attr = attrs
            .take_nested(tag::SEQUENCE)
            .map_err(|e| TspError::Malformed("Attribute", e))?;
        let attr_type = attr.oid().map_err(|e| TspError::Malformed("attrType", e))?;
        let mut values = attr
            .take_nested(tag::SET)
            .map_err(|e| TspError::Malformed("attrValues", e))?;

        if attr_type.as_bytes() == oid::MESSAGE_DIGEST {
            let claimed = values
                .octet_string()
                .map_err(|e| TspError::Malformed("messageDigest", e))?;
            values
                .expect_end()
                .map_err(|e| TspError::Malformed("messageDigest", e))?;
            if claimed != digest_of(kind, content).as_slice() {
                return Err(TspError::ContentDigestMismatch);
            }
            // A second messageDigest would be a second answer to the same
            // question, and taking the first is how a checker is bypassed.
            if saw_digest {
                return Err(TspError::UnsupportedCms("two messageDigest attributes"));
            }
            saw_digest = true;
        } else if attr_type.as_bytes() == oid::CONTENT_TYPE {
            let claimed = values
                .oid()
                .map_err(|e| TspError::Malformed("contentType", e))?;
            values
                .expect_end()
                .map_err(|e| TspError::Malformed("contentType", e))?;
            if claimed.as_bytes() != oid::TST_INFO {
                return Err(TspError::ContentTypeMismatch);
            }
            if saw_type {
                return Err(TspError::UnsupportedCms("two contentType attributes"));
            }
            saw_type = true;
        }
        // Everything else is signed and irrelevant: a signing-time attribute, a
        // signing certificate reference. They are covered by the signature and
        // this client draws no conclusion from them.
    }

    if !saw_digest {
        return Err(TspError::ContentDigestMismatch);
    }
    if !saw_type {
        return Err(TspError::ContentTypeMismatch);
    }
    Ok(())
}

fn digest_of(kind: DigestKind, data: &[u8]) -> Vec<u8> {
    match kind {
        DigestKind::Sha256 => Sha256::digest(data).to_vec(),
        DigestKind::Sha384 => Sha384::digest(data).as_bytes().to_vec(),
    }
}

/// `TSTInfo`, read field by field in the order the specification lists them.
fn parse_tst_info(content: &[u8]) -> Result<Claim, TspError> {
    let mut outer = Der::new(content);
    let mut info = outer
        .take_nested(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("TSTInfo", e))?;

    let version = info
        .integer_u64()
        .map_err(|e| TspError::Malformed("TSTInfo version", e))?;
    if version != 1 {
        return Err(TspError::UnknownVersion(version));
    }
    info.oid().map_err(|e| TspError::Malformed("policy", e))?;

    let mut mi = info
        .take_nested(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("messageImprint", e))?;
    let (algorithm, _) = mi
        .algorithm_identifier()
        .map_err(|e| TspError::Malformed("hashAlgorithm", e))?;
    if algorithm.as_bytes() != oid::SHA384 {
        return Err(TspError::ImprintAlgorithm);
    }
    let hashed = mi
        .octet_string()
        .map_err(|e| TspError::Malformed("hashedMessage", e))?;
    mi.expect_end()
        .map_err(|e| TspError::Malformed("messageImprint", e))?;
    // The algorithm said SHA-384, so the length is not negotiable. A token
    // naming SHA-384 over a 32-byte value is malformed, not a shorter hash.
    if hashed.len() != 48 {
        return Err(TspError::ImprintAlgorithm);
    }
    let mut imprint = [0u8; 48];
    imprint.copy_from_slice(hashed);

    let serial = info
        .integer_bytes()
        .map_err(|e| TspError::Malformed("serialNumber", e))?
        .to_vec();
    let at = info
        .generalized_time()
        .map_err(|e| TspError::Malformed("genTime", e))?;

    // accuracy, ordering: both optional, both ignored. Accuracy widens the
    // interval and this client records the instant the token names; a caller that
    // needs the interval has the token bytes.
    info.skip_if(tag::SEQUENCE)
        .map_err(|e| TspError::Malformed("accuracy", e))?;
    info.skip_if(tag::BOOLEAN)
        .map_err(|e| TspError::Malformed("ordering", e))?;

    let nonce = if info.peek_tag() == Some(tag::INTEGER) {
        Some(
            info.integer_u64()
                .map_err(|e| TspError::Malformed("nonce", e))?,
        )
    } else {
        None
    };

    Ok(Claim {
        imprint,
        at,
        serial,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_the_structure_rfc_3161_specifies() {
        let imprint = [0x5Au8; 48];
        let encoded = request(&imprint, 0xDEAD_BEEF);
        let mut outer = Der::new(&encoded);
        let mut req = outer.take_nested(tag::SEQUENCE).expect("a SEQUENCE");
        assert_eq!(req.integer_u64(), Ok(1), "version is 1");

        let mut mi = req.take_nested(tag::SEQUENCE).expect("messageImprint");
        let (algorithm, parameters) = mi.algorithm_identifier().expect("hashAlgorithm");
        assert_eq!(algorithm.as_bytes(), oid::SHA384);
        assert_eq!(parameters, Some((tag::NULL, &[][..])));
        assert_eq!(mi.octet_string(), Ok(&imprint[..]));
        assert_eq!(mi.expect_end(), Ok(()));

        assert_eq!(req.integer_u64(), Ok(0xDEAD_BEEF), "the nonce is sent");
        assert_eq!(req.boolean(), Ok(false), "certReq is false");
        assert_eq!(req.expect_end(), Ok(()));
        assert_eq!(outer.expect_end(), Ok(()));
    }

    /// A nonce is what makes a response an answer to this request rather than a
    /// replay of an older one for the same root.
    #[test]
    fn a_request_for_the_same_root_with_a_different_nonce_is_a_different_request() {
        let imprint = [1u8; 48];
        assert_ne!(request(&imprint, 1), request(&imprint, 2));
    }

    #[test]
    fn a_refusal_reports_the_status_rather_than_looking_for_a_token() {
        // PKIStatus 2 is rejection.
        for status in [1u64, 2, 3, 4, 5] {
            let response =
                trailryx_asn1::sequence(&[trailryx_asn1::sequence(&[trailryx_asn1::integer_u64(
                    status,
                )])]);
            assert_eq!(
                token_from_response(&response),
                Err(TspError::Refused { status })
            );
        }
    }

    /// "Granted with modifications" is a refusal here. The modification is the
    /// authority answering a question this client did not ask.
    #[test]
    fn granted_with_modifications_is_treated_as_a_refusal() {
        let response = trailryx_asn1::sequence(&[
            trailryx_asn1::sequence(&[trailryx_asn1::integer_u64(1)]),
            trailryx_asn1::sequence(&[trailryx_asn1::oid(oid::SIGNED_DATA)]),
        ]);
        assert_eq!(
            token_from_response(&response),
            Err(TspError::Refused { status: 1 })
        );
    }

    #[test]
    fn a_granted_response_with_no_token_is_named_rather_than_parsed_as_empty() {
        let response =
            trailryx_asn1::sequence(&[trailryx_asn1::sequence(&[trailryx_asn1::integer_u64(0)])]);
        assert_eq!(token_from_response(&response), Err(TspError::NoToken));
    }

    /// The token must come back as the exact bytes delivered, tag and length
    /// included. Re-encoding would produce a different byte string whose
    /// signature no longer verifies, and the failure would look like a bad
    /// authority.
    #[test]
    fn the_token_is_returned_as_the_exact_bytes_that_arrived() {
        let token = trailryx_asn1::sequence(&[
            trailryx_asn1::oid(oid::SIGNED_DATA),
            trailryx_asn1::tlv(tag::context_constructed(0), &trailryx_asn1::integer_u64(7)),
        ]);
        let mut response = Vec::new();
        response.extend_from_slice(&trailryx_asn1::sequence(&[trailryx_asn1::integer_u64(0)]));
        response.extend_from_slice(&token);
        let response = trailryx_asn1::tlv(tag::SEQUENCE, &response);

        assert_eq!(token_from_response(&response), Ok(&token[..]));
    }

    #[test]
    fn binding_compares_the_imprint_and_the_nonce_and_names_which_failed() {
        let claim = Claim {
            imprint: [7u8; 48],
            at: 1_785_421_800,
            serial: vec![1],
            nonce: Some(42),
        };
        assert_eq!(binds_to(&claim, &[7u8; 48], 42), Ok(()));
        assert_eq!(
            binds_to(&claim, &[8u8; 48], 42),
            Err(TspError::ImprintMismatch)
        );
        assert_eq!(
            binds_to(&claim, &[7u8; 48], 43),
            Err(TspError::NonceMismatch)
        );
        let no_nonce = Claim {
            nonce: None,
            ..claim
        };
        assert_eq!(
            binds_to(&no_nonce, &[7u8; 48], 42),
            Err(TspError::NonceMismatch),
            "a token with no nonce cannot be shown to answer this request"
        );
    }

    #[test]
    fn the_imprint_of_a_root_is_its_sha384_and_both_call_sites_agree() {
        let root = [0xABu8; 48];
        assert_eq!(imprint_of(&root), {
            let mut expected = [0u8; 48];
            expected.copy_from_slice(Sha384::digest(&root).as_bytes());
            expected
        });
    }

    // -----------------------------------------------------------------------
    // TSTInfo, built by hand so the parser is exercised against every optional
    // field being present and absent
    // -----------------------------------------------------------------------

    fn tst_info(
        imprint: &[u8],
        algorithm: &[u8],
        time: &str,
        nonce: Option<u64>,
        accuracy: bool,
        ordering: bool,
    ) -> Vec<u8> {
        let mut parts = vec![
            trailryx_asn1::integer_u64(1),
            trailryx_asn1::oid(&[0x2A, 0x03, 0x04]),
            trailryx_asn1::sequence(&[
                trailryx_asn1::sequence(&[trailryx_asn1::oid(algorithm), trailryx_asn1::null()]),
                trailryx_asn1::octet_string(imprint),
            ]),
            trailryx_asn1::integer_u64(0x0102_0304),
            trailryx_asn1::tlv(tag::GENERALIZED_TIME, time.as_bytes()),
        ];
        if accuracy {
            parts.push(trailryx_asn1::sequence(&[trailryx_asn1::integer_u64(1)]));
        }
        if ordering {
            parts.push(trailryx_asn1::boolean(true));
        }
        if let Some(n) = nonce {
            parts.push(trailryx_asn1::integer_u64(n));
        }
        trailryx_asn1::sequence(&parts)
    }

    #[test]
    fn a_tst_info_reads_with_every_combination_of_its_optional_fields() {
        let imprint = [0x11u8; 48];
        for accuracy in [false, true] {
            for ordering in [false, true] {
                for nonce in [None, Some(99u64)] {
                    let encoded = tst_info(
                        &imprint,
                        oid::SHA384,
                        "20260730143000Z",
                        nonce,
                        accuracy,
                        ordering,
                    );
                    let claim = parse_tst_info(&encoded).unwrap_or_else(|e| {
                        panic!("accuracy={accuracy} ordering={ordering} nonce={nonce:?}: {e}")
                    });
                    assert_eq!(claim.imprint, imprint);
                    assert_eq!(claim.at, 1_785_421_800);
                    assert_eq!(claim.serial, vec![0x01, 0x02, 0x03, 0x04]);
                    assert_eq!(claim.nonce, nonce);
                }
            }
        }
    }

    /// A token naming SHA-384 over 32 bytes is malformed. Accepting it would
    /// mean comparing a 48-byte root imprint against something shorter, and the
    /// only safe answer to that is to refuse.
    #[test]
    fn an_imprint_whose_length_disagrees_with_its_algorithm_is_refused() {
        let encoded = tst_info(
            &[0u8; 32],
            oid::SHA384,
            "20260730143000Z",
            None,
            false,
            false,
        );
        assert_eq!(
            parse_tst_info(&encoded),
            Err(TspError::ImprintAlgorithm),
            "48 bytes were promised and 32 delivered"
        );
    }

    #[test]
    fn a_token_stamped_with_another_algorithm_is_refused_by_name() {
        let encoded = tst_info(
            &[0u8; 32],
            oid::SHA256,
            "20260730143000Z",
            None,
            false,
            false,
        );
        assert_eq!(parse_tst_info(&encoded), Err(TspError::ImprintAlgorithm));
    }

    #[test]
    fn a_tst_info_version_other_than_one_is_refused() {
        let mut parts = vec![
            trailryx_asn1::integer_u64(2),
            trailryx_asn1::oid(&[0x2A, 0x03, 0x04]),
        ];
        parts.push(trailryx_asn1::sequence(&[
            trailryx_asn1::sequence(&[trailryx_asn1::oid(oid::SHA384), trailryx_asn1::null()]),
            trailryx_asn1::octet_string(&[0u8; 48]),
        ]));
        let encoded = trailryx_asn1::sequence(&parts);
        assert_eq!(parse_tst_info(&encoded), Err(TspError::UnknownVersion(2)));
    }

    #[test]
    fn every_truncation_of_a_valid_token_is_an_error_and_never_a_panic() {
        let whole = tst_info(
            &[0x22u8; 48],
            oid::SHA384,
            "20260730143000Z",
            Some(5),
            true,
            true,
        );
        for cut in 0..whole.len() {
            assert!(
                parse_tst_info(&whole[..cut]).is_err(),
                "a prefix of {cut} bytes parsed as a whole TSTInfo"
            );
        }
        assert!(parse_tst_info(&whole).is_ok());
    }
}
