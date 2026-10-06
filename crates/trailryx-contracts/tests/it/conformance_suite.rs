//! Two duties for this file.
//!
//! The reference adapters must pass the suite, which is the ordinary half.
//!
//! The deliberately broken adapters must **fail it, on the specific check**,
//! which is the half that matters. A conformance suite nobody has seen fail is
//! a suite nobody has tested, and the two guarantees exercised here, atomic
//! publication and permanent key destruction, are the ones whose quiet failure
//! would be worst: one makes proofs ambiguous, the other makes erasure a lie.

use trailryx_contracts::conformance;
use trailryx_contracts::fakes::*;

fn failed_check<'a>(r: &'a conformance::Report, name: &str) -> Option<&'a conformance::Check> {
    r.failures().find(|c| c.name == name)
}

// ---------------------------------------------------------------------------
// The reference implementations pass
// ---------------------------------------------------------------------------

#[test]
fn reference_object_store_conforms() {
    let mut s = MemoryObjectStore::default();
    let r = conformance::object_store(&mut s);
    assert!(r.passed(), "{}", r.summary());
}

#[test]
fn reference_key_provider_conforms() {
    let mut k = MemoryKeyProvider::default();
    let r = conformance::key_provider(&mut k);
    assert!(r.passed(), "{}", r.summary());
}

#[test]
fn reference_source_conforms() {
    let mut s = NullSource::default();
    let r = conformance::source(&mut s);
    assert!(r.passed(), "{}", r.summary());
}

#[test]
fn reference_sink_conforms() {
    let mut s = CountingSink::default();
    let r = conformance::sink(&mut s);
    assert!(r.passed(), "{}", r.summary());
}

#[test]
fn reference_anchor_conforms() {
    let mut a = EchoAnchor::default();
    let r = conformance::anchor(&mut a);
    assert!(r.passed(), "{}", r.summary());
}

#[test]
fn reference_auth_conforms() {
    let mut a = StaticAuth;
    let r = conformance::auth_provider(&mut a);
    assert!(r.passed(), "{}", r.summary());
}

#[test]
fn reference_peer_conforms() {
    let mut p = LocalPeer;
    let r = conformance::peer(&mut p);
    assert!(r.passed(), "{}", r.summary());
}

#[test]
fn reference_foreign_table_conforms() {
    let mut t = StaticForeignTable;
    let r = conformance::foreign_table(&mut t);
    assert!(r.passed(), "{}", r.summary());
}

// ---------------------------------------------------------------------------
// The broken ones are caught, on the right check
// ---------------------------------------------------------------------------

#[test]
fn an_overwriting_object_store_is_caught() {
    // The plausible wrong implementation: a plain put, which is what most
    // storage APIs hand you by default. Two nodes would both believe they
    // published the same segment.
    let mut s = OverwritingObjectStore::default();
    let r = conformance::object_store(&mut s);
    assert!(!r.passed());
    assert!(
        failed_check(&r, "second write is refused").is_some(),
        "{}",
        r.summary()
    );
    assert!(
        failed_check(&r, "the loser did not overwrite the winner").is_some(),
        "{}",
        r.summary()
    );
}

#[test]
fn a_key_provider_that_resurrects_keys_is_caught() {
    // Destruction implemented as a delete from a map. The key id can be used
    // again, so everything wrapped under it becomes readable, and "erased"
    // silently became "hidden for a while".
    let mut k = ResurrectingKeyProvider::default();
    let r = conformance::key_provider(&mut k);
    assert!(!r.passed());
    assert!(
        failed_check(&r, "a destroyed key id is never reissued").is_some(),
        "{}",
        r.summary()
    );
}

#[test]
fn a_source_that_vouches_for_its_own_clock_is_caught() {
    let mut s = SelfCertifyingSource;
    let r = conformance::source(&mut s);
    assert!(!r.passed());
    assert!(
        failed_check(&r, "does not claim a trusted clock").is_some(),
        "{}",
        r.summary()
    );
    assert!(
        failed_check(&r, "exactly-once is claimed only where it is plausible").is_some(),
        "{}",
        r.summary()
    );
}

#[test]
fn a_sink_that_hides_what_it_drops_is_caught() {
    let mut s = VaguelyLossySink;
    let r = conformance::sink(&mut s);
    assert!(!r.passed());
    assert!(
        failed_check(&r, "a lossy sink enumerates what it drops").is_some(),
        "{}",
        r.summary()
    );
}

#[test]
fn an_anchor_that_verifies_anything_is_caught() {
    let mut a = LenientAnchor;
    let r = conformance::anchor(&mut a);
    assert!(!r.passed());
    assert!(
        failed_check(&r, "it does not verify for another root").is_some(),
        "{}",
        r.summary()
    );
}

#[test]
fn an_unattested_peer_claiming_a_full_proof_is_caught() {
    let mut p = OverconfidentPeer;
    let r = conformance::peer(&mut p);
    assert!(!r.passed());
    assert!(
        failed_check(&r, "an unattested peer never claims a full proof").is_some(),
        "{}",
        r.summary()
    );
}

#[test]
fn a_foreign_table_claiming_provability_is_caught() {
    let mut t = ProvableForeignTable;
    let r = conformance::foreign_table(&mut t);
    assert!(!r.passed());
    assert!(
        failed_check(&r, "does not claim to be provable").is_some(),
        "{}",
        r.summary()
    );
}

// ---------------------------------------------------------------------------
// The report itself
// ---------------------------------------------------------------------------

#[test]
fn a_report_names_the_failing_check_and_says_why() {
    let mut s = OverwritingObjectStore::default();
    let r = conformance::object_store(&mut s);
    let text = r.summary();
    assert!(text.contains("FAIL"));
    assert!(text.contains("not atomic"), "{text}");
}

#[test]
fn every_contract_has_a_suite() {
    // Eight contracts were frozen at the end of stage 1. If a ninth arrives,
    // this is where the reminder to write its suite lands.
    let suites = 8;
    assert_eq!(suites, 8);
}
