#!/usr/bin/env python3
"""Writes tests/vectors/agent-door-fixtures.json: the tokens and proofs the wire
tests in tests/it/agent_door.rs present to a running server.

Run with `python3 -I tests/make_door_fixtures.py` from the crate directory. The
output is byte-for-byte reproducible: every key is derived from a fixed label and
every signature nonce from the key and the message, so a second run writes the
same file, and a diff after a run means something changed.

Pure Python on purpose. The verifier under test is ours, so the signer that makes
its inputs must not be: this file shares no code with it, and when the
`cryptography` package is importable every signature is checked by OpenSSL as
well before anything is written.

Every key here is TEST-ONLY and signs nothing but this file. They are not the keys
in agent-token-vectors.json, which that table reserves for itself.
"""

import base64
import hashlib
import json
import os

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = (3 * a[0] * a[0] - 3) * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def mul(k, point):
    acc = None
    while k:
        if k & 1:
            acc = add(acc, point)
        point = add(point, point)
        k >>= 1
    return acc


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def key(label):
    d = int.from_bytes(hashlib.sha256(b"trailryx test-only " + label.encode()).digest(), "big") % N
    x, y = mul(d, G)
    assert (y * y - (x ** 3 - 3 * x + B)) % P == 0
    return {"d": d, "x": b64(x.to_bytes(32, "big")), "y": b64(y.to_bytes(32, "big"))}


def public_jwk(k):
    return {"kty": "EC", "crv": "P-256", "x": k["x"], "y": k["y"]}


def thumbprint(k):
    canonical = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (k["x"], k["y"])
    return b64(hashlib.sha256(canonical.encode()).digest())


def sign(k, message):
    e = int.from_bytes(hashlib.sha256(message).digest(), "big") % N
    counter = 0
    while True:
        seed = k["d"].to_bytes(32, "big") + hashlib.sha256(message).digest() + bytes([counter])
        nonce = int.from_bytes(hashlib.sha256(seed).digest(), "big") % N
        counter += 1
        if nonce == 0:
            continue
        r = mul(nonce, G)[0] % N
        s = pow(nonce, -1, N) * (e + r * k["d"]) % N
        if r and s:
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def compact(k, header, claims):
    enc = lambda obj: b64(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())
    signing = enc(header) + "." + enc(claims)
    return signing + "." + b64(sign(k, signing.encode())), signing


ISSUER = "https://vouchryx.acme.example"
AUDIENCE = "https://ingest.acme.example"
ORIGIN = "https://ingest.acme.example"
NOW = 1800000000

issuer = key("door issuer")
holder = key("door holder")
stranger = key("door stranger")


def token(sub, jti, holder_key):
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": sub,
        "client_id": sub,
        "jti": jti,
        "iat": NOW,
        "exp": NOW + 300,
        "cnf": {"jkt": thumbprint(holder_key)},
        "unit": "ops",
        "org": "default",
    }
    return compact(issuer, {"alg": "ES256", "kid": "door-1", "typ": "at+jwt"}, claims)


def proof(signer, tok, jti, path="/v1/traces", method="POST"):
    claims = {
        "jti": jti,
        "htm": method,
        "htu": ORIGIN + path,
        "iat": NOW,
        "ath": b64(hashlib.sha256(tok.encode()).digest()),
    }
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk(signer)}
    return compact(signer, header, claims)


checked = []

tokens = {}
for name, sub in [
    ("billing", "agent://acme.example/billing"),
    ("elsewhere", "agent://other.example/billing"),
]:
    tokens[name], signing = token(sub, "tok-" + name, holder)
    checked.append((issuer, signing, tokens[name]))

proofs = {}
for i in range(1, 9):
    proofs["billing-%d" % i], signing = proof(holder, tokens["billing"], "p-%d" % i)
    checked.append((holder, signing, proofs["billing-%d" % i]))
proofs["elsewhere-1"], signing = proof(holder, tokens["elsewhere"], "e-1")
checked.append((holder, signing, proofs["elsewhere-1"]))
proofs["stolen-1"], signing = proof(stranger, tokens["billing"], "s-1")
checked.append((stranger, signing, proofs["stolen-1"]))

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    for k, signing, jws in checked:
        raw = base64.urlsafe_b64decode(jws.rsplit(".", 1)[1] + "==")
        x = int.from_bytes(base64.urlsafe_b64decode(k["x"] + "="), "big")
        y = int.from_bytes(base64.urlsafe_b64decode(k["y"] + "="), "big")
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        pub.verify(der, signing.encode(), ec.ECDSA(hashes.SHA256()))
    note = "every signature checked by the cryptography package"
except ImportError:
    note = "the cryptography package is absent, so nothing checked these signatures"

out = {
    "comment": (
        "TEST-ONLY keys and the tokens and proofs they sign, for tests/it/agent_door.rs. "
        "Generated by tests/make_door_fixtures.py; do not edit by hand."
    ),
    "issuer": ISSUER,
    "audience": AUDIENCE,
    "origin": ORIGIN,
    "trust_domain": "acme.example",
    "now": NOW,
    "jwks": {"keys": [dict(public_jwk(issuer), kid="door-1", use="sig", alg="ES256")]},
    "holder_jkt": thumbprint(holder),
    "tokens": tokens,
    "proofs": proofs,
}
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "vectors", "agent-door-fixtures.json"), "w") as f:
    json.dump(out, f, indent=1, sort_keys=True)
    f.write("\n")
print(note)
