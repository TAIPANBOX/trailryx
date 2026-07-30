//! The conformance suite.
//!
//! Written together with the contracts, not after them. An adapter that has not
//! passed this does not ship, and the suite is public so an adapter author can
//! run it against their own implementation before opening a pull request.
//!
//! Each check corresponds to a guarantee stated on the trait it exercises. The
//! suite is deliberately hostile: several checks exist only to catch the
//! plausible wrong implementation, such as an object store that overwrites
//! instead of refusing, or a key provider that can bring a destroyed key back.

use crate::contracts::{
    Action, Anchor, AuthProvider, Decision, Delivery, Destroyed, ForeignTable, KeyId, KeyProvider,
    Lossiness, ObjectStore, Ordering, Peer, ProofStatus, PutOutcome, Sink, Source, Trust,
};
use crate::ingest::Cursor;
use trailryx_record::Hash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub subject: String,
    pub checks: Vec<Check>,
}

impl Report {
    fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            checks: Vec::new(),
        }
    }

    fn check(&mut self, name: &'static str, passed: bool, detail: impl Into<String>) {
        self.checks.push(Check {
            name,
            passed,
            detail: detail.into(),
        });
    }

    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }

    pub fn failures(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|c| !c.passed)
    }

    pub fn summary(&self) -> String {
        let ok = self.checks.iter().filter(|c| c.passed).count();
        let mut s = format!(
            "{}: {}/{} checks passed",
            self.subject,
            ok,
            self.checks.len()
        );
        for f in self.failures() {
            s.push_str(&format!("\n  FAIL {}: {}", f.name, f.detail));
        }
        s
    }
}

/// A source must describe itself honestly and acknowledge idempotently.
pub fn source<S: Source>(s: &mut S) -> Report {
    let d = s.descriptor();
    let mut r = Report::new(format!("Source/{}", d.name));

    r.check(
        "descriptor is stable",
        s.descriptor() == d,
        "two calls returned different descriptors",
    );

    r.check(
        "name is not empty",
        !d.name.is_empty(),
        "an unnamed adapter cannot be audited",
    );

    // Nothing external can vouch for its own clock without proving it, and no
    // source proves it today. A source claiming Trusted is claiming something
    // it cannot deliver, and the store would then skip skew detection for it.
    r.check(
        "does not claim a trusted clock",
        d.clock_trust == Trust::Untrusted,
        "an external source claiming Trusted disables skew detection for itself",
    );

    let budget_respected = s.poll(3).map(|v| v.len() <= 3).unwrap_or(true);
    r.check(
        "poll respects the budget",
        budget_respected,
        "returned more items than asked for",
    );

    let a = s.ack(Cursor(10));
    let b = s.ack(Cursor(10));
    r.check(
        "ack is idempotent",
        a.is_ok() && b.is_ok(),
        "acknowledging the same cursor twice failed",
    );

    let rewind = s.ack(Cursor(1));
    r.check(
        "an older cursor is a no-op, not a rewind",
        rewind.is_ok(),
        "acknowledging an older cursor was treated as an error",
    );

    // Exactly-once is claimed far more often than it is delivered. Rather than
    // forbidding the claim, the check makes it implausible to make casually: it
    // is only allowed alongside ordered delivery, the one shape where it is
    // even arguable.
    r.check(
        "exactly-once is claimed only where it is plausible",
        d.delivery != Delivery::ExactlyOnce || d.ordering == Ordering::Ordered,
        "exactly-once claimed on an unordered stream, which almost nothing delivers",
    );

    r
}

/// A sink must admit what it loses.
pub fn sink<S: Sink>(s: &mut S) -> Report {
    let d = s.descriptor();
    let mut r = Report::new(format!("Sink/{}", d.name));

    r.check(
        "descriptor is stable",
        s.descriptor() == d,
        "two calls returned different descriptors",
    );

    let enumerated = match d.lossiness {
        Lossiness::Lossless => true,
        Lossiness::Lossy { drops } => !drops.is_empty(),
    };
    r.check(
        "a lossy sink enumerates what it drops",
        enumerated,
        "declared lossy without naming a single dropped field",
    );

    r.check(
        "empty batch is accepted",
        s.emit(&[]).is_ok(),
        "an empty batch should be a no-op, not an error",
    );

    r.check("flush succeeds", s.flush().is_ok(), "flush failed");

    r
}

/// The atomic-publish guarantee, which is what removes the need for a
/// coordinator. Every check here exists because the plausible wrong
/// implementation overwrites.
pub fn object_store<S: ObjectStore>(s: &mut S) -> Report {
    let mut r = Report::new("ObjectStore");
    let key = "conformance/segment-0001.manifest";

    let first = s.put_if_absent(key, b"first writer");
    r.check(
        "first write is accepted",
        first == Ok(PutOutcome::Written),
        format!("expected Written, got {first:?}"),
    );

    let second = s.put_if_absent(key, b"second writer");
    r.check(
        "second write is refused",
        second == Ok(PutOutcome::AlreadyExists),
        format!("expected AlreadyExists, got {second:?}: two nodes could publish one segment"),
    );

    let stored = s.get(key).unwrap_or(None);
    r.check(
        "the loser did not overwrite the winner",
        stored.as_deref() == Some(b"first writer".as_slice()),
        "the second writer's bytes are stored, so publication is not atomic",
    );

    let missing = s.get("conformance/never-written").unwrap_or(Some(vec![]));
    r.check(
        "a missing key reads as absent, not as empty",
        missing.is_none(),
        "returned Some for a key that was never written",
    );

    let listed = s.list("conformance/").unwrap_or_default();
    r.check(
        "list finds what was written",
        listed.iter().any(|k| k == key),
        "the key is readable but not listed",
    );

    let unrelated = s.list("somewhere-else/").unwrap_or_default();
    r.check(
        "list respects the prefix",
        !unrelated.iter().any(|k| k == key),
        "the prefix filter is not applied",
    );

    r
}

/// Erasure is only as real as this. Every check is about a key staying dead.
pub fn key_provider<K: KeyProvider>(k: &mut K) -> Report {
    let mut r = Report::new("KeyProvider");
    let kek = KeyId(Hash([7u8; trailryx_record::HASH_BYTES]));
    let dek = b"a data key, 32 bytes long......xx";

    let wrapped = k.wrap(kek, dek);
    r.check(
        "wrap succeeds",
        wrapped.is_ok(),
        format!("{:?}", wrapped.as_ref().err()),
    );
    let Ok(wrapped) = wrapped else {
        return r;
    };

    r.check(
        "wrapping is not the identity",
        wrapped.as_slice() != dek.as_slice(),
        "the wrapped form equals the plaintext key",
    );

    let round = k.unwrap(kek, &wrapped);
    r.check(
        "unwrap returns the original",
        round.as_deref() == Ok(dek.as_slice()),
        "round trip did not preserve the key",
    );

    r.check("the key exists before destruction", k.exists(kek), "");

    let d1 = k.destroy(kek);
    // A provider may destroy now or schedule it. Both are acceptable answers and
    // they are not the same answer, which is the whole point of the third variant:
    // the suite used to demand `Now` and would have failed every real key
    // management service, all of which schedule.
    r.check(
        "destroy reports the key was there",
        matches!(d1, Ok(Destroyed::Now) | Ok(Destroyed::Scheduled { .. })),
        format!("expected Now or Scheduled, got {d1:?}"),
    );
    let scheduled = matches!(d1, Ok(Destroyed::Scheduled { .. }));

    // `exists` answers "can this key still be used", not "has the material been
    // shredded". A scheduled key is unusable now, so both kinds of provider answer
    // the same way and the check does not have to branch.
    r.check(
        "the key is gone",
        !k.exists(kek),
        "the provider still reports the destroyed key as present",
    );

    let after = k.unwrap(kek, &wrapped);
    r.check(
        "unwrap fails from the moment of destruction",
        after.is_err(),
        "a destroyed key still unwraps: erasure would be a lie",
    );

    let d2 = k.destroy(kek);
    if scheduled {
        // A second call must not restart the clock. A provider that pushed the
        // effective time out on every retry would make an erasure job that retries
        // an erasure that never lands, and the retry is the normal case.
        let same = matches!((&d1, &d2), (Ok(a), Ok(b)) if a == b);
        r.check(
            "destroying twice reports the same schedule",
            same,
            format!("first {d1:?}, then {d2:?}: the schedule moved"),
        );
    } else {
        r.check(
            "destroy is idempotent",
            d2 == Ok(Destroyed::Already),
            format!("expected Already, got {d2:?}"),
        );
    }

    // A schedule that a caller cannot place in time is a schedule nobody can act
    // on: the whole point of the variant is that the caller learns when, and
    // whether somebody can still undo it.
    if let Ok(Destroyed::Scheduled { effective_at, .. }) = &d1 {
        r.check(
            "a scheduled destruction names a time",
            effective_at.as_nanos() > 0,
            "the effective time is the epoch, which no custodian means",
        );
    }

    // A provider that lets the same id be wrapped again has effectively
    // resurrected the key, and every payload wrapped under it becomes readable.
    let resurrect = k.wrap(kek, dek);
    r.check(
        "a destroyed key id is never reissued",
        resurrect.is_err(),
        "wrapping under a destroyed key id succeeded",
    );

    r
}

/// A receipt must be specific to its root.
pub fn anchor<A: Anchor>(a: &mut A) -> Report {
    let mut r = Report::new("Anchor");
    let root = Hash([1u8; trailryx_record::HASH_BYTES]);
    let other = Hash([2u8; trailryx_record::HASH_BYTES]);

    let receipt = a.submit(root);
    r.check("submit succeeds", receipt.is_ok(), "");
    let Ok(receipt) = receipt else { return r };

    r.check(
        "the receipt names the root it covers",
        receipt.root == root,
        "receipt is for a different root",
    );

    r.check(
        "it verifies for its own root",
        a.verify(root, &receipt) == Ok(true),
        "a fresh receipt does not verify",
    );

    r.check(
        "it does not verify for another root",
        a.verify(other, &receipt) != Ok(true),
        "the receipt verifies for a root it never covered: it proves nothing",
    );

    r
}

/// Deny by default, and decide the same way twice.
pub fn auth_provider<A: AuthProvider>(a: &mut A) -> Report {
    let mut r = Report::new("AuthProvider");

    let bad = a.authenticate(b"");
    r.check(
        "an empty credential is refused",
        bad.is_err(),
        "authenticated an empty credential",
    );

    let p = a.authenticate(b"valid-credential");
    r.check("a valid credential authenticates", p.is_ok(), "");
    let Ok(p) = p else { return r };

    let d1 = a.authorize(&p, Action::Query, "tenant-a");
    let d2 = a.authorize(&p, Action::Query, "tenant-a");
    r.check(
        "decisions are deterministic",
        d1 == d2,
        "the same question got two answers",
    );

    r.check(
        "an unknown scope is denied",
        a.authorize(&p, Action::Query, "a-tenant-that-does-not-exist") == Decision::Deny,
        "default is allow, which is the wrong default",
    );

    // Reading the audit trail and reading the prompts inside it are different
    // permissions, and a provider that conflates them hands out the payloads to
    // everyone who can see the metadata.
    let meta = a.authorize(&p, Action::ReadMetadata, "tenant-a");
    let payload = a.authorize(&p, Action::ReadPayload, "tenant-a");
    r.check(
        "payload access is decided separately from metadata access",
        !(meta == Decision::Allow && payload == Decision::Allow)
            || a.authorize(&p, Action::Erase, "tenant-a") == Decision::Deny,
        "every action resolves the same way, so the actions are not really distinguished",
    );

    r
}

/// An unattested peer cannot claim a full proof.
pub fn peer<P: Peer>(p: &mut P) -> Report {
    let d = p.descriptor();
    let mut r = Report::new(format!("Peer/{}", d.name));

    let resp = p.query("recorded_at >= 0");
    r.check("query succeeds", resp.is_ok(), "");
    let Ok(resp) = resp else { return r };

    r.check(
        "an unattested peer never claims a full proof",
        d.attested || resp.proof != ProofStatus::Full,
        "claimed Full while outside the signed registry: forgetting a node would shrink the answer silently",
    );

    r
}

/// Foreign rows are never provable.
pub fn foreign_table<T: ForeignTable>(t: &mut T) -> Report {
    let mut r = Report::new("ForeignTable");

    r.check("has a name", !t.name().is_empty(), "");
    r.check("declares columns", !t.columns().is_empty(), "");
    r.check(
        "does not claim to be provable",
        !t.provable(),
        "foreign data did not come from our journal and cannot be covered by a completeness proof",
    );

    r
}
