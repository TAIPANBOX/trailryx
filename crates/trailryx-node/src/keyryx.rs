//! Keyryx as the seal's signer, and the witness attestations keyryx writes.
//!
//! Red-first scaffold: every function here answers as today's build does (nothing
//! is signed, nothing is read), so the tests in `tests/it/keyryx.rs` compile and
//! fail on their assertions.

use trailryx_http::Client;
use trailryx_record::{Hash, SigAlg};
use trailryx_sign::{SignError, Signer, WitnessAttestation};

/// The key a seal is signed under, as Keyryx names it.
pub const ROOT_KEY: &str = "trailryx-root";

/// A signer whose private key is held by Keyryx, reached over `trailryx-http`.
pub struct KeyryxSigner {
    client: Client,
    bearer: String,
    public: Vec<u8>,
    kid: Option<String>,
}

impl KeyryxSigner {
    /// A signer for the Keyryx at `origin`, presenting `bearer` on every signature.
    /// Makes no request: the key set is read by [`KeyryxSigner::refresh`].
    pub fn new(origin: &str, bearer: &str) -> Result<Self, SignError> {
        let client = Client::new(origin).map_err(|e| SignError::Unavailable(e.to_string()))?;
        Ok(Self {
            client,
            bearer: bearer.to_owned(),
            public: Vec::new(),
            kid: None,
        })
    }

    /// Read the key set and take its ES384 key as the one this signer signs under.
    pub fn refresh(&mut self) -> Result<(), SignError> {
        let _ = (&self.client, &self.bearer, &self.kid);
        Err(SignError::Unavailable(
            "keyryx signing is not built yet".to_owned(),
        ))
    }
}

impl Signer for KeyryxSigner {
    fn algorithm(&self) -> SigAlg {
        SigAlg::Es384
    }

    fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn is_validated(&self) -> bool {
        false
    }

    fn sign(&mut self, _message: &[u8]) -> Result<Vec<u8>, SignError> {
        Err(SignError::Unavailable(
            "keyryx signing is not built yet".to_owned(),
        ))
    }
}

/// Standard base64 with padding, the form Keyryx's JSON carries statements in.
pub fn encode_base64(_bytes: &[u8]) -> String {
    String::new()
}

/// The inverse of [`encode_base64`]. Strict: padding must be present and canonical.
pub fn decode_base64(_text: &str) -> Option<Vec<u8>> {
    None
}

/// URL-safe base64 without padding, the form Keyryx's witness writes keys and
/// signatures in.
pub fn encode_base64url(_bytes: &[u8]) -> String {
    String::new()
}

/// The inverse of [`encode_base64url`].
pub fn decode_base64url(_text: &str) -> Option<Vec<u8>> {
    None
}

/// One attestation file, read: which tenant and store root it is about, how many
/// segments the witness saw, and the attestation trailryx-verify checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    pub tenant: String,
    pub store_root: Hash,
    pub segments: u64,
    pub attestation: WitnessAttestation,
}

/// Parse a file in the shape Keyryx's witness writes beside a store.
pub fn parse_attestation(_bytes: &[u8]) -> Result<Attested, String> {
    Err("keyryx attestation parsing is not built yet".to_owned())
}
