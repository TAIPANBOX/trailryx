//! Keyryx as the seal's signer, and the witness attestations Keyryx writes beside a store.
//!
//! The root a seal produces is signed under a key Keyryx holds, by a request this process
//! makes over `trailryx-http`. Nothing here holds a private key: the signer keeps the public
//! key Keyryx publishes and the consumer credential that lets it ask for a signature.
//!
//! Keyryx answers in JSON, read strictly through `trailryx-json`, the reader OTLP goes
//! through. Base64 is written here both ways, because Keyryx uses the standard alphabet for
//! statements and signatures and the URL-safe one for keys and attestations.

use std::time::Duration;

use trailryx_http::{Client, Http, Method, Request};
use trailryx_json::{Event, Limits, Reader};
use trailryx_record::{Hash, SigAlg, TenantId, Timestamp};
use trailryx_sign::{SignError, Signer, WitnessAttestation};

/// The key a seal is signed under, as Keyryx names it.
pub const ROOT_KEY: &str = "trailryx-root";

/// The purpose Keyryx records for each seal signature, in its use log.
const PURPOSE: &str = "seal";

/// How long a connection may take before the seal calls Keyryx unreachable. An attempt
/// costs at most these, once, and never once per record.
const CONNECT: Duration = Duration::from_secs(2);
const IO: Duration = Duration::from_secs(5);

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A signer whose private key is held by Keyryx, reached over `trailryx-http`.
///
/// The key is read by [`KeyryxSigner::refresh`], and every signature is checked against
/// it: a key set that changed under the signer is refused, not signed under the old key.
pub struct KeyryxSigner {
    client: Client,
    bearer: String,
    public: Vec<u8>,
    kid: Option<String>,
}

// Written by hand, never derived: `bearer` is the credential that lets this process ask for
// signatures, and a derived Debug would print it into any log line or panic message.
impl std::fmt::Debug for KeyryxSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kid = self.kid.as_deref().unwrap_or("not read yet");
        write!(f, "KeyryxSigner {{ kid: {kid}, bearer set }}")
    }
}

impl KeyryxSigner {
    /// A signer for the Keyryx at `origin`, presenting `bearer` on every signature.
    /// Makes no request: the key set is read by [`KeyryxSigner::refresh`].
    pub fn new(origin: &str, bearer: &str) -> Result<Self, SignError> {
        let client = Client::new(origin)
            .map_err(|e| SignError::Unavailable(e.to_string()))?
            .with_timeouts(CONNECT, IO);
        Ok(Self {
            client,
            bearer: bearer.to_owned(),
            public: Vec::new(),
            kid: None,
        })
    }

    /// Read the key set and take its ES384 key as the one this signer signs under.
    pub fn refresh(&mut self) -> Result<(), SignError> {
        let request = Request::new(Method::Get, format!("/v1/jwks/{ROOT_KEY}"));
        let body = self.exchange(request)?;
        let (kid, public) = es384_key(&body)?;
        self.kid = Some(kid);
        self.public = public;
        Ok(())
    }

    fn exchange(&mut self, request: Request) -> Result<Vec<u8>, SignError> {
        let response = self.client.send(&request).map_err(SignError::Unavailable)?;
        if response.status != 200 {
            return Err(SignError::Unavailable(format!(
                "keyryx answered {}",
                response.status
            )));
        }
        Ok(response.body)
    }

    fn request_signature(&mut self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let Some(kid) = self.kid.clone() else {
            return Err(SignError::Unavailable(
                "keyryx's key is not read yet".to_owned(),
            ));
        };
        let body = format!(
            r#"{{"statement_b64":"{}","purpose":"{PURPOSE}"}}"#,
            encode_base64(message)
        );
        let request = Request::new(Method::Post, format!("/v1/keys/{ROOT_KEY}/sign"))
            .header("Authorization", format!("Bearer {}", self.bearer))
            .header("Content-Type", "application/json")
            .body(body.into_bytes());
        let answer = self.exchange(request)?;
        parse_signature(&answer, &kid, &self.public)
    }
}

impl Signer for KeyryxSigner {
    fn algorithm(&self) -> SigAlg {
        SigAlg::Es384
    }

    fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    /// Keyryx's ES384 is held by a Go process, not by a certified module, so this says no.
    /// The seal signs through `sign_root_unvalidated` for that reason, and says so where it does.
    fn is_validated(&self) -> bool {
        false
    }

    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        self.request_signature(message)
    }
}

fn refused(why: &str) -> SignError {
    SignError::Unavailable(format!("keyryx's key set {why}"))
}

/// The one ES384 key in a key set, as its kid and its uncompressed point `0x04 || X || Y`.
fn es384_key(body: &[u8]) -> Result<(String, Vec<u8>), SignError> {
    let set = parse(body).map_err(|why| refused(&why))?;
    let keys = set
        .field("keys")
        .and_then(Json::items)
        .ok_or_else(|| refused("has no keys array"))?;
    let [key] = keys else {
        return Err(refused(&format!(
            "holds {} keys, and this signer takes exactly one",
            keys.len()
        )));
    };
    if key.str_field("kty") != Some("EC") || key.str_field("crv") != Some("P-384") {
        return Err(refused("holds no P-384 key"));
    }
    let kid = key
        .str_field("kid")
        .ok_or_else(|| refused("has a key with no kid"))?
        .to_owned();
    let x = key
        .str_field("x")
        .and_then(decode_base64url)
        .filter(|x| x.len() == 48)
        .ok_or_else(|| refused("has a key whose x is not 48 bytes"))?;
    let y = key
        .str_field("y")
        .and_then(decode_base64url)
        .filter(|y| y.len() == 48)
        .ok_or_else(|| refused("has a key whose y is not 48 bytes"))?;
    let mut public = Vec::with_capacity(97);
    public.push(0x04);
    public.extend_from_slice(&x);
    public.extend_from_slice(&y);
    Ok((kid, public))
}

/// Keyryx's answer to a signature: the algorithm, the key that made it, the key's point
/// and the signature. Refused unless all four agree with the key this signer read.
fn parse_signature(body: &[u8], kid: &str, public: &[u8]) -> Result<Vec<u8>, SignError> {
    let answer =
        parse(body).map_err(|why| SignError::Unavailable(format!("keyryx's answer: {why}")))?;
    if answer.str_field("alg") != Some("ES384") {
        return Err(SignError::Unavailable(
            "keyryx answered with another algorithm".to_owned(),
        ));
    }
    if answer.str_field("kid") != Some(kid) {
        return Err(SignError::Unavailable(
            "keyryx signed under a key this signer did not read".to_owned(),
        ));
    }
    let answered = answer.str_field("public_key_b64").and_then(decode_base64);
    if answered.as_deref() != Some(public) {
        return Err(SignError::Unavailable(
            "keyryx's key is not the one this signer read".to_owned(),
        ));
    }
    let signature = answer
        .str_field("signature_b64")
        .and_then(decode_base64)
        .ok_or_else(|| SignError::Unavailable("keyryx's signature is not base64".to_owned()))?;
    if signature.len() != 96 {
        return Err(SignError::BadLength {
            expected: 96,
            got: signature.len(),
        });
    }
    Ok(signature)
}

/// Standard base64 with padding, the form Keyryx's JSON carries statements in.
pub fn encode_base64(bytes: &[u8]) -> String {
    encode(bytes, STANDARD, true)
}

/// The inverse of [`encode_base64`]. Strict: padding must be present and canonical.
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    decode(text, STANDARD, true)
}

/// URL-safe base64 without padding, the form Keyryx's witness writes keys and signatures in.
pub fn encode_base64url(bytes: &[u8]) -> String {
    encode(bytes, URL_SAFE, false)
}

/// The inverse of [`encode_base64url`].
pub fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    decode(text, URL_SAFE, false)
}

fn encode(bytes: &[u8], alphabet: &[u8; 64], padded: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or(0));
        let third = u32::from(chunk.get(2).copied().unwrap_or(0));
        let group = (first << 16) | (second << 8) | third;
        // One byte is two symbols, two bytes three, three bytes four.
        let symbols = chunk.len() + 1;
        for i in 0..4 {
            if i < symbols {
                let index = (group >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(alphabet[index as usize]));
            } else if padded {
                out.push('=');
            }
        }
    }
    out
}

/// Strict: the alphabet must match, padding must be present exactly when the alphabet
/// takes it, and the bits after the last whole byte must be zero, so one text decodes to
/// one byte string and no other.
fn decode(text: &str, alphabet: &[u8; 64], padded: bool) -> Option<Vec<u8>> {
    let body = if padded {
        if !text.len().is_multiple_of(4) {
            return None;
        }
        let data = text.trim_end_matches('=');
        if text.len() - data.len() > 2 {
            return None;
        }
        data
    } else {
        if text.contains('=') || text.len() % 4 == 1 {
            return None;
        }
        text
    };
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in body.bytes() {
        let value = alphabet.iter().position(|&a| a == byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if buffer != 0 {
        return None;
    }
    Some(out)
}

/// Lowercase hex, as the store names its roots and Keyryx names its witness files.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The inverse of [`hex_encode`], for either case. Refused on an odd length or a byte
/// that is not a hex digit.
pub(crate) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some((high * 16 + low) as u8)
        })
        .collect()
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

/// The members Keyryx's witness writes, and no others. A file with another member is
/// refused rather than read past, because a reader that ignores what it does not know
/// is a reader that can be told anything.
const ATTESTATION_MEMBERS: [&str; 8] = [
    "witness",
    "tenant",
    "store_root",
    "segments",
    "seen_at",
    "algorithm",
    "public_key",
    "signature",
];

/// Parse a file in the shape Keyryx's witness writes beside a store.
pub fn parse_attestation(bytes: &[u8]) -> Result<Attested, String> {
    let json = parse(bytes)?;
    let Json::Obj(members) = &json else {
        return Err("an attestation is a JSON object".to_owned());
    };
    if let Some((name, _)) = members
        .iter()
        .find(|(name, _)| !ATTESTATION_MEMBERS.contains(&name.as_str()))
    {
        return Err(format!("an attestation has an unknown member {name:?}"));
    }

    let witness = json.str_field("witness").ok_or("no witness name")?;
    if !witness_name_ok(witness) {
        return Err(format!(
            "the witness name {witness:?} is not a bounded token"
        ));
    }
    let tenant = json.str_field("tenant").ok_or("no tenant")?;
    TenantId::parse(tenant).map_err(|_| format!("the tenant {tenant:?} is not an identifier"))?;
    let store_root = json
        .str_field("store_root")
        .and_then(hex_decode)
        .and_then(|bytes| <[u8; 48]>::try_from(bytes).ok())
        .map(Hash)
        .ok_or("the store root is not 48 bytes of hex")?;
    let segments = json.num_field("segments").ok_or("no segment count")?;
    let seen_at = json
        .num_field("seen_at")
        .ok_or("no time the witness saw the root")?;
    let algorithm = json.str_field("algorithm").ok_or("no algorithm")?;
    if algorithm != "es384" {
        return Err(format!(
            "the algorithm {algorithm:?} is not one keyryx witnesses with"
        ));
    }
    let public_key = json
        .str_field("public_key")
        .and_then(decode_base64url)
        .filter(|key| key.len() == 97 && key[0] == 0x04)
        .ok_or("the witness key is not an uncompressed P-384 point")?;
    let signature = json
        .str_field("signature")
        .and_then(decode_base64url)
        .filter(|sig| sig.len() == 96)
        .ok_or("the witness signature is not 96 bytes")?;

    Ok(Attested {
        tenant: tenant.to_owned(),
        store_root,
        segments,
        attestation: WitnessAttestation {
            witness: witness.to_owned(),
            seen_at: Timestamp(seen_at),
            algorithm: SigAlg::Es384,
            public_key,
            signature,
        },
    })
}

/// The same charset trailryx-sign accepts for a witness name: a bounded token.
fn witness_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// A JSON value, as far as this module reads one. Numbers are kept only when they are
/// unsigned integers, which is all a count or a time is.
enum Json {
    Str(String),
    Num(Option<u64>),
    Other,
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn field(&self, name: &str) -> Option<&Json> {
        match self {
            Json::Obj(members) => members
                .iter()
                .find(|(n, _)| n.as_str() == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    fn str_field(&self, name: &str) -> Option<&str> {
        match self.field(name)? {
            Json::Str(text) => Some(text.as_str()),
            _ => None,
        }
    }

    fn num_field(&self, name: &str) -> Option<u64> {
        match self.field(name)? {
            Json::Num(number) => *number,
            _ => None,
        }
    }

    fn items(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(items) => Some(items.as_slice()),
            _ => None,
        }
    }
}

/// One JSON document, strictly: the reader refuses what the grammar refuses, a second
/// value, and nesting past its bound.
fn parse(bytes: &[u8]) -> Result<Json, String> {
    let mut reader = Reader::new(bytes, Limits::default(), 1);
    let value = read_value(&mut reader)?;
    reader.finish().map_err(|e| e.to_string())?;
    Ok(value)
}

fn read_value(reader: &mut Reader<'_>) -> Result<Json, String> {
    match reader.value().map_err(|e| e.to_string())? {
        Event::Null | Event::Bool(_) => Ok(Json::Other),
        Event::Number(number) => Ok(Json::Num(number.as_u64())),
        Event::Str(text) => Ok(Json::Str(text.into_owned())),
        Event::ArrayStart => {
            let mut items = Vec::new();
            while reader.next_element().map_err(|e| e.to_string())? {
                items.push(read_value(reader)?);
            }
            Ok(Json::Arr(items))
        }
        Event::ObjectStart => {
            let mut members = Vec::new();
            while let Some(name) = reader.next_name().map_err(|e| e.to_string())? {
                let name = name.into_owned();
                members.push((name, read_value(reader)?));
            }
            Ok(Json::Obj(members))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_what_is_not_hex() {
        assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex_decode("00ABff"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(hex_decode("0"), None);
        assert_eq!(hex_decode("+f"), None);
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn the_json_reader_refuses_a_second_document_and_an_unknown_escape() {
        assert!(parse(br#"{"a":1} {"b":2}"#).is_err());
        assert!(parse(br#"{"a":"\q"}"#).is_err());
        assert!(matches!(parse(br#"{"a":1}"#), Ok(Json::Obj(_))));
    }
}
