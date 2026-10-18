//! The estate's shared table for an agent's own access token, answered by this
//! repository's verifier.
//!
//! `tests/vectors/agent-token-vectors.json` is vendored byte for byte from
//! agent-stack-go (`delegation/testdata/agent-token-vectors.json`), which is
//! where the canonical copy lives and where the Go verifier answers it. The
//! Rust door in tokenfuse answers the same file. A third verifier that agrees
//! with both on every case is what "the same rules" means here, rather than a
//! sentence in a pull request saying so.
//!
//! The file is not edited here, ever: its `$source` field names the copy that
//! is, and the test below checks the vendored bytes still say so.

use trailryx_ingest::agent_token::{
    self, KeySet, Policy, Refusal, Replay, ReplayCache, Request, VerifiedAgent,
};
use trailryx_json::{Event, Limits, Reader};

const TABLE: &str = include_str!("../vectors/agent-token-vectors.json");

/// A JSON value, just enough of one to read the table with.
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, name: &str) -> Option<&Json> {
        match self {
            Json::Obj(members) => members.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }
    fn str(&self, name: &str) -> Option<&str> {
        match self.get(name)? {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    fn int(&self, name: &str) -> Option<i64> {
        match self.get(name)? {
            Json::Int(n) => Some(*n),
            _ => None,
        }
    }
    fn arr(&self, name: &str) -> &[Json] {
        match self.get(name) {
            Some(Json::Arr(items)) => items,
            _ => &[],
        }
    }
}

fn read(r: &mut Reader<'_>) -> Json {
    match r.value().expect("a value") {
        Event::Null => Json::Null,
        Event::Bool(b) => Json::Bool(b),
        Event::Number(n) => Json::Int(n.as_i64().expect("the table holds whole numbers")),
        Event::Str(s) => Json::Str(s.into_owned()),
        Event::ArrayStart => {
            let mut items = Vec::new();
            while r.next_element().expect("an element") {
                items.push(read(r));
            }
            Json::Arr(items)
        }
        Event::ObjectStart => {
            let mut members = Vec::new();
            while let Some(name) = r.next_name().expect("a member") {
                let name = name.into_owned();
                members.push((name, read(r)));
            }
            Json::Obj(members)
        }
    }
}

fn table() -> Json {
    let mut r = Reader::new(TABLE.as_bytes(), Limits::default(), 1);
    let doc = read(&mut r);
    r.finish().expect("one document");
    doc
}

/// Serialise a value back to JSON, for the one place the table holds a JWKS as an
/// object and the verifier takes it as bytes.
fn to_json(v: &Json) -> String {
    match v {
        Json::Null => "null".to_owned(),
        Json::Bool(b) => b.to_string(),
        Json::Int(n) => n.to_string(),
        Json::Str(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        Json::Arr(items) => format!(
            "[{}]",
            items.iter().map(to_json).collect::<Vec<_>>().join(",")
        ),
        Json::Obj(members) => format!(
            "{{{}}}",
            members
                .iter()
                .map(|(k, v)| format!("\"{k}\":{}", to_json(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// The verifier this case names, against the table's own refusal vocabulary.
fn answer(doc: &Json, case: &Json) -> Result<VerifiedAgent, Refusal> {
    let config = doc.get("config").expect("a config");
    let keys = KeySet::from_jwks(to_json(config.get("jwks").expect("a jwks")).as_bytes())
        .expect("the table's key set loads");
    let policy = Policy {
        keys,
        issuer: config.str("issuer").expect("an issuer").to_owned(),
        audience: case
            .str("audience")
            .or_else(|| config.str("audience"))
            .expect("an audience")
            .to_owned(),
    };
    let revoke_jti = case
        .get("revoke")
        .and_then(|r| r.str("jti"))
        .map(str::to_owned);
    let revoke_subject = case
        .get("revoke")
        .and_then(|r| r.str("subject"))
        .map(str::to_owned);
    let revoked = move |jti: &str, subject: &str, _iat: i64| {
        revoke_jti.as_deref() == Some(jti) || revoke_subject.as_deref() == Some(subject)
    };
    let now = case.int("now").expect("a clock");
    let token = case.str("jws").expect("a token");
    match case.str("verifier").expect("a verifier") {
        "agent" => {
            let request = Request {
                token,
                proof: case.str("dpop"),
                method: case
                    .str("method")
                    .or_else(|| config.str("method"))
                    .expect("a method"),
                url: case
                    .str("url")
                    .or_else(|| config.str("url"))
                    .expect("a url"),
                now,
            };
            // A fresh cache per case, as the table says.
            let mut replay = ReplayCache::new(1024);
            agent_token::verify(&policy, &request, &mut replay, &revoked)
        }
        "relayed" => agent_token::verify_relayed(&policy, token, now, &revoked),
        other => panic!("no verifier here is called {other}"),
    }
}

#[test]
fn the_vendored_table_is_the_canonical_one_unedited() {
    let doc = table();
    assert_eq!(
        doc.str("$source"),
        Some("agent-stack-go/delegation/testdata/agent-token-vectors.json")
    );
    // The same digest as the canonical copy at agent-stack-go 05fc8c7. A
    // refresh changes this line and the file together, and nothing else.
    let digest = trailryx_verify::sha256::digest(TABLE.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "554cae8f8f69fbda83f8a8a66b862eea11dbc70c06476bc19072ee10c23f0774"
    );
    // The constants the table pins are the ones this verifier uses.
    let constants = doc.get("constants").expect("constants");
    assert_eq!(constants.str("typ"), Some(agent_token::AGENT_TOKEN_TYP));
    assert_eq!(constants.int("leeway_secs"), Some(agent_token::LEEWAY_SECS));
    assert_eq!(
        constants.int("proof_window_secs"),
        Some(agent_token::PROOF_WINDOW_SECS)
    );
    assert_eq!(
        constants.int("max_proof_jti_bytes"),
        Some(agent_token::MAX_PROOF_JTI_BYTES as i64)
    );
    assert_eq!(
        constants.int("replay_generation_secs"),
        Some(agent_token::REPLAY_GENERATION_SECS)
    );
}

#[test]
fn every_agent_and_relayed_case_gets_the_answer_the_table_states() {
    let doc = table();
    let cases = doc.arr("cases");
    let mut wrong = Vec::new();
    let mut answered = 0;
    let mut skipped = Vec::new();
    for case in cases {
        let name = case.str("name").expect("a name");
        let verifier = case.str("verifier").expect("a verifier");
        if verifier == "delegation" {
            // The delegation-chain verifier, which this repository does not have.
            skipped.push(name);
            continue;
        }
        let expect = case.str("expect").expect("an expectation");
        let got = answer(&doc, case);
        let said = match &got {
            Ok(_) => "accept",
            Err(refusal) => refusal.as_str(),
        };
        if said != expect {
            wrong.push(format!(
                "{name} ({verifier}): expected {expect}, got {said}"
            ));
            continue;
        }
        if let (Ok(verified), Some(v)) = (&got, case.get("verified")) {
            let fields = [
                ("subject", verified.subject.as_str()),
                ("unit", verified.unit.as_str()),
                ("org", verified.org.as_str()),
                ("jti", verified.jti.as_str()),
                ("jkt", verified.jkt.as_str()),
                ("proof_jti", verified.proof_jti.as_str()),
            ];
            for (field, ours) in fields {
                if v.str(field) != Some(ours) {
                    wrong.push(format!(
                        "{name}: {field} is {ours:?}, the table says {:?}",
                        v.str(field)
                    ));
                }
            }
            if v.int("issued_at") != Some(verified.issued_at)
                || v.int("expires_at") != Some(verified.expires_at)
            {
                wrong.push(format!("{name}: the token's life is not the table's"));
            }
        }
        answered += 1;
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // Fifty-nine cases, three of them the delegation verifier's. Pinned, so a
    // refresh that adds a verifier kind is a decision here rather than a skip.
    assert_eq!(answered, 56, "answered {answered}");
    assert_eq!(skipped.len(), 3, "skipped {skipped:?}");
}

#[test]
fn every_replay_sequence_gets_the_answer_the_table_states() {
    let doc = table();
    let sequences = doc.arr("replay");
    assert_eq!(sequences.len(), 6);
    for sequence in sequences {
        let name = sequence.str("name").expect("a name");
        let cap = usize::try_from(sequence.int("cap").expect("a cap")).expect("a size");
        let mut cache = ReplayCache::new(cap);
        for (i, step) in sequence.arr("steps").iter().enumerate() {
            let got = match cache.check_and_record(
                step.str("jti").expect("a jti"),
                step.int("now").expect("a clock"),
            ) {
                Ok(()) => "ok",
                Err(Replay::Seen) => "seen",
                Err(Replay::Full) => "full",
            };
            assert_eq!(
                Some(got),
                step.str("expect"),
                "{name}, step {i}: the table says {:?}",
                step.str("expect")
            );
        }
    }
}
