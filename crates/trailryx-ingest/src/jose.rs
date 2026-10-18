//! The parts of JOSE an agent-token door needs, and nothing past them.
//!
//! A compact JWS split into its three parts, the base64url those parts are
//! written in, a small JSON value read through this tree's own strict reader,
//! an EC P-256 public key read out of a JWK, and that key's RFC 7638
//! thumbprint. Signatures are checked by `trailryx_verify::p256`, which is the
//! whole reason this crate can take a token without taking a dependency.
//!
//! # Strict where a lenient reading would make two spellings of one thing
//!
//! - **base64url is canonical or refused.** No padding, nothing outside the
//!   alphabet, and the unused low bits of a final partial group must be zero.
//!   A decoder that ignored those bits would accept four different spellings
//!   of one signature, and a proof is identified by what it says rather than
//!   by its bytes, so a second spelling buys an attacker nothing today and
//!   costs a reader of the log an explanation.
//! - **A member named twice is refused,** by the reader, for the reason
//!   `trailryx_json` gives: which of the two a parser keeps is an
//!   implementation detail, and here it would be a detail deciding who a token
//!   names.
//! - **A number is an integer literal or it is not a date.** `1.0`, `1e3` and
//!   `1800000000.5` are refused where a NumericDate is read, the way the Rust
//!   door in this estate refuses them.

use trailryx_json::{Event, Limits, Reader};
use trailryx_verify::{p256, sha256};

/// Decode unpadded base64url, canonically, or refuse.
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    fn sextet(b: u8) -> Option<u32> {
        Some(u32::from(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        }))
    }
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for b in chunk {
            acc = (acc << 6) | sextet(*b)?;
        }
        match chunk.len() {
            4 => out.extend_from_slice(&acc.to_be_bytes()[1..]),
            // Two characters carry one byte and four bits that must be zero.
            3 => {
                if acc & 0b11 != 0 {
                    return None;
                }
                out.extend_from_slice(&(acc >> 2).to_be_bytes()[2..]);
            }
            2 => {
                if acc & 0b1111 != 0 {
                    return None;
                }
                out.push((acc >> 4) as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Encode as unpadded base64url.
pub fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut acc = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            acc |= u32::from(*b) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            out.push(char::from(
                ALPHABET[((acc >> (18 - 6 * i)) & 0x3f) as usize],
            ));
        }
    }
    out
}

/// A JSON value, as much of one as a token holds.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// An integer literal that fits an `i64`.
    Int(i64),
    /// Any other number. Kept apart so a date written as a fraction is a
    /// value that is not a date, rather than a date rounded.
    OtherNumber,
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Strict JSON, one value, and nothing after it.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes, Limits::default(), 1);
        let value = read(&mut r)?;
        r.finish().ok()?;
        Some(value)
    }

    /// A member of an object. `None` when absent or when this is not an object.
    pub fn get(&self, name: &str) -> Option<&Json> {
        match self {
            Self::Obj(members) => members.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Self::Obj(_))
    }
}

fn read(r: &mut Reader<'_>) -> Option<Json> {
    Some(match r.value().ok()? {
        Event::Null => Json::Null,
        Event::Bool(b) => Json::Bool(b),
        Event::Number(n) => match n.as_i64() {
            Some(v) if n.is_integer_literal() => Json::Int(v),
            _ => Json::OtherNumber,
        },
        Event::Str(s) => Json::Str(s.into_owned()),
        Event::ArrayStart => {
            let mut items = Vec::new();
            while r.next_element().ok()? {
                items.push(read(r)?);
            }
            Json::Arr(items)
        }
        Event::ObjectStart => {
            let mut members = Vec::new();
            while let Some(name) = r.next_name().ok()? {
                let name = name.into_owned();
                members.push((name, read(r)?));
            }
            Json::Obj(members)
        }
    })
}

/// A compact JWS, split and nothing more: no part of it is believed yet.
#[derive(Debug, Clone, Copy)]
pub struct Compact<'a> {
    /// `header.payload`, the bytes the signature is over, as presented.
    pub signing_input: &'a str,
    pub header: &'a str,
    pub payload: &'a str,
    pub signature: &'a str,
}

impl<'a> Compact<'a> {
    /// Exactly three parts. Two dots is not a matter of opinion.
    pub fn split(jws: &'a str) -> Option<Self> {
        let mut parts = jws.split('.');
        let header = parts.next()?;
        let payload = parts.next()?;
        let signature = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            signing_input: &jws[..header.len() + 1 + payload.len()],
            header,
            payload,
            signature,
        })
    }

    /// The protected header, decoded and parsed. Not verified: whatever it says
    /// was written by whoever presented the token.
    pub fn header_json(&self) -> Option<Json> {
        Json::parse(&base64url_decode(self.header)?)
    }

    /// The payload, decoded and parsed, for a caller that has verified the
    /// signature already.
    pub fn payload_json(&self) -> Option<Json> {
        Json::parse(&base64url_decode(self.payload)?)
    }

    /// Whether `key` signed this, as ES256.
    pub fn verify_es256(&self, key: &EcKey) -> bool {
        let Some(signature) = base64url_decode(self.signature) else {
            return false;
        };
        p256::verify(&key.point, self.signing_input.as_bytes(), &signature).is_ok()
    }
}

/// Members only a key's holder should have (RFC 7518 sections 6.2.2, 6.3.2 and
/// 6.4). A JWK carrying one of them is a private key in a public place.
pub const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];

/// Whether a JWK carries any member only its holder should have.
pub fn has_private_member(jwk: &Json) -> bool {
    PRIVATE_MEMBERS.iter().any(|m| jwk.get(m).is_some())
}

/// An EC P-256 public key, as a JWK wrote it and as the curve reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcKey {
    /// The members as written, which is what a thumbprint hashes.
    pub x: String,
    pub y: String,
    /// `0x04 || X || Y`, already checked to be a point on P-256.
    pub point: [u8; p256::PUBLIC_KEY_BYTES],
}

impl EcKey {
    /// `kty` exactly `EC`, `crv` exactly `P-256`, and `x` and `y` each the full
    /// thirty-two bytes RFC 7518 section 6.2.1.2 requires, together a point on
    /// the curve. Anything else is not a key this door verifies with.
    pub fn from_jwk(jwk: &Json) -> Option<Self> {
        if jwk.get("kty")?.as_str()? != "EC" || jwk.get("crv")?.as_str()? != "P-256" {
            return None;
        }
        let x = jwk.get("x")?.as_str()?;
        let y = jwk.get("y")?.as_str()?;
        let (xb, yb) = (base64url_decode(x)?, base64url_decode(y)?);
        if xb.len() != 32 || yb.len() != 32 {
            return None;
        }
        let mut point = [0u8; p256::PUBLIC_KEY_BYTES];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&xb);
        point[33..].copy_from_slice(&yb);
        p256::check_public_key(&point).ok()?;
        Some(Self {
            x: x.to_owned(),
            y: y.to_owned(),
            point,
        })
    }

    /// The RFC 7638 thumbprint: SHA-256 over the required members in
    /// lexicographic order with no whitespace, base64url without padding.
    ///
    /// What a token is bound to through `cnf.jkt`, so this decides whether a
    /// stolen token can be presented by another holder. `kid`, `use` and `alg`
    /// are not in it, which is why renaming a key does not unbind a live token.
    /// The members are base64url by construction, so there is nothing in them
    /// a JSON string would have to escape.
    pub fn thumbprint(&self) -> String {
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            self.x, self.y
        );
        base64url_encode(&sha256::digest(canonical.as_bytes()))
    }
}

/// `ath`, RFC 9449 section 4.2: the base64url SHA-256 of the token's ASCII.
pub fn access_token_hash(token: &str) -> String {
    base64url_encode(&sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips_every_length() {
        for len in 0..80usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = base64url_encode(&bytes);
            assert!(!text.contains('='));
            assert_eq!(base64url_decode(&text), Some(bytes), "length {len}");
        }
    }

    /// RFC 4648 section 10, in the URL alphabet and without padding.
    #[test]
    fn base64url_matches_the_rfc_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url_encode(plain.as_bytes()), encoded);
            assert_eq!(base64url_decode(encoded), Some(plain.as_bytes().to_vec()));
        }
        assert_eq!(base64url_decode("-_8"), Some(vec![0xfb, 0xff]));
    }

    #[test]
    fn base64url_refuses_padding_other_alphabets_and_second_spellings() {
        for bad in [
            "Zg==", "Zm8=", "Zm9v+", "Zm9v/", "Z", "Zm9vY", "Zm 9v", "Zm9v\n",
            // `Zh` and `Zm` both carry "f" with different unused bits; only the
            // one whose unused bits are zero is the byte.
            "Zh", "Zm9", "Zm9vYh",
        ] {
            assert_eq!(base64url_decode(bad), None, "{bad:?}");
        }
        assert_eq!(base64url_decode("Zg"), Some(b"f".to_vec()));
    }

    #[test]
    fn a_compact_jws_has_exactly_three_parts() {
        let c = Compact::split("a.b.c").expect("three parts");
        assert_eq!((c.header, c.payload, c.signature), ("a", "b", "c"));
        assert_eq!(c.signing_input, "a.b");
        assert!(Compact::split("a.b").is_none());
        assert!(Compact::split("a.b.c.d").is_none());
        assert!(Compact::split("").is_none());
        let empty = Compact::split("..").expect("three empty parts split");
        assert_eq!(empty.signing_input, ".");
    }

    #[test]
    fn json_dates_are_integer_literals_and_names_are_unique() {
        assert_eq!(Json::parse(b"1800000000"), Some(Json::Int(1_800_000_000)));
        assert_eq!(Json::parse(b"1.0"), Some(Json::OtherNumber));
        assert_eq!(Json::parse(b"1e3"), Some(Json::OtherNumber));
        assert_eq!(
            Json::parse(b"99999999999999999999"),
            Some(Json::OtherNumber)
        );
        assert_eq!(Json::parse(br#"{"a":1,"a":2}"#), None);
        assert_eq!(Json::parse(b"{} {}"), None);
        let doc =
            Json::parse(br#"{"cnf":{"jkt":"x"},"aud":["a","b"],"act":null}"#).expect("an object");
        assert_eq!(
            doc.get("cnf")
                .and_then(|c| c.get("jkt"))
                .and_then(Json::as_str),
            Some("x")
        );
        assert_eq!(doc.get("act"), Some(&Json::Null));
        assert_eq!(doc.get("absent"), None);
    }

    /// The holder key of the estate's shared table and the thumbprint its tokens
    /// are bound to, as the table states it.
    #[test]
    fn the_thumbprint_is_the_one_the_estate_binds_tokens_to() {
        let jwk = Json::parse(
            br#"{"kty":"EC","crv":"P-256","x":"1TgD9mHtbQofhQeOXTpGN2CREOh4uY9yMgXOYe7TiZU","y":"57jWh8MYOp02MJJT9EyLY1jGD-60qCoYsLClvC7Hi5Y","kid":"ignored","use":"sig"}"#,
        )
        .expect("a jwk");
        let key = EcKey::from_jwk(&jwk).expect("a P-256 key");
        assert_eq!(
            key.thumbprint(),
            "-xSVhqOu5JMoNZpfXV7-SnczXtxflpgSfrwceZeuhUQ"
        );
    }

    #[test]
    fn a_jwk_that_is_not_a_full_p256_point_is_not_a_key() {
        let good = r#""x":"1TgD9mHtbQofhQeOXTpGN2CREOh4uY9yMgXOYe7TiZU","y":"57jWh8MYOp02MJJT9EyLY1jGD-60qCoYsLClvC7Hi5Y""#;
        for jwk in [
            format!(r#"{{"kty":"EC","crv":"P-384",{good}}}"#),
            format!(r#"{{"kty":"ec","crv":"P-256",{good}}}"#),
            format!(r#"{{"kty":"RSA","crv":"P-256",{good}}}"#),
            format!(r#"{{"crv":"P-256",{good}}}"#),
            // Thirty-one bytes of x: a short coordinate is not left-padded here.
            r#"{"kty":"EC","crv":"P-256","x":"OAP2Ye1tCh-FB45dOkY3YJEQ6Hi5j3IyBc5h7tOJlQ","y":"57jWh8MYOp02MJJT9EyLY1jGD-60qCoYsLClvC7Hi5Y"}"#.to_owned(),
            // y flipped in its last bit: not on the curve.
            r#"{"kty":"EC","crv":"P-256","x":"1TgD9mHtbQofhQeOXTpGN2CREOh4uY9yMgXOYe7TiZU","y":"57jWh8MYOp02MJJT9EyLY1jGD-60qCoYsLClvC7Hi5c"}"#.to_owned(),
        ] {
            let parsed = Json::parse(jwk.as_bytes()).expect("json");
            assert!(EcKey::from_jwk(&parsed).is_none(), "{jwk}");
        }
    }

    #[test]
    fn a_private_member_is_noticed_by_name() {
        for member in PRIVATE_MEMBERS {
            let jwk =
                Json::parse(format!(r#"{{"kty":"EC","{member}":"AA"}}"#).as_bytes()).expect("json");
            assert!(has_private_member(&jwk), "{member}");
        }
        let public = Json::parse(br#"{"kty":"EC","x":"AA","y":"AA","kid":"k"}"#).expect("json");
        assert!(!has_private_member(&public));
    }

    /// RFC 9449 section 4.2's own example: the hash of its example token.
    #[test]
    fn ath_matches_rfc_9449() {
        assert_eq!(
            access_token_hash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"),
            "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
        );
    }
}
