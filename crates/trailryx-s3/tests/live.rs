//! The adapter against somebody else's S3 server.
//!
//! # Why this exists when `store.rs` already runs over a real socket
//!
//! The fake in `store.rs` speaks enough S3 to answer the four operations, and it
//! exercises the request line, the header block and the response parsing. What it
//! cannot do is disagree with us. It was written from the same reading of the same
//! documentation as the client, so every place where that reading is wrong, the fake
//! is wrong in exactly the same direction and the test passes.
//!
//! This one talks to an implementation nobody here wrote. That is the same standard
//! the rest of the project applies with OpenSSL, pyarrow and the AWS CLI: where a
//! second implementation exists, run it rather than trusting the first.
//!
//! # The property that matters most
//!
//! Atomic publication rests on one thing the store has to do, and it is not a thing
//! this code can check for itself: **a conditional write must refuse the second
//! writer**. A store that quietly accepts `If-None-Match: *` and overwrites is worse
//! than a store without the feature, because the second publication of a segment
//! then leaves no trace at all. So the central assertion here is not that a write
//! succeeded, it is that the *second* one failed, from a server we did not write.
//!
//! # Running it
//!
//! Nothing here runs without an endpoint, and when there is none the test says so
//! rather than passing quietly:
//!
//! ```text
//! docker run -d -p 9000:9000 minio/minio server /data
//! TRAILRYX_S3_ENDPOINT=http://127.0.0.1:9000 \
//! TRAILRYX_S3_BUCKET=trailryx TRAILRYX_S3_KEY=... TRAILRYX_S3_SECRET=... \
//!   cargo test -p trailryx-s3 --test live -- --nocapture
//! ```
//!
//! It works against a live AWS bucket with the same variables, which costs a few
//! requests. Everything it writes goes under one prefix, and it cleans up nothing:
//! this suite never issues a delete, because a test that can delete is a test that
//! can delete the wrong thing.

use trailryx_contracts::{AdapterError, ObjectStore, PutOutcome};
use trailryx_s3::{Addressing, Conditional, Credentials, S3};

/// The store's own words, or the adapter's summary if it kept none.
///
/// `AdapterError` is deliberately narrow, because a caller upstream must not branch
/// on somebody else's error strings. An operator reading a failing test needs the
/// opposite, so the two are separated: the contract stays small and this reaches for
/// `last_failure`, which is exactly what that accessor is for. The first version of
/// this file used plain `.expect()` and reported "the object store refused the
/// request", which is true and useless.
#[track_caller]
fn ok<T>(what: &str, result: Result<T, AdapterError>, s3: &S3) -> T {
    match result {
        Ok(v) => v,
        Err(e) => panic!(
            "{what} failed: {e}\n    the store itself said: {}",
            s3.last_failure()
                .map_or_else(|| "nothing this adapter kept".to_owned(), |f| f.to_string())
        ),
    }
}

struct Config {
    endpoint: String,
    bucket: String,
    key: String,
    secret: String,
    region: String,
    addressing: Addressing,
}

/// The environment, or `None` with a printed reason.
///
/// Deliberately not a `#[ignore]`: an ignored test is invisible in the output, and
/// this project treats a check that quietly did not run as the failure mode to
/// design against.
fn config() -> Option<Config> {
    let endpoint = std::env::var("TRAILRYX_S3_ENDPOINT").ok()?;
    let cfg = Config {
        endpoint,
        bucket: std::env::var("TRAILRYX_S3_BUCKET").unwrap_or_else(|_| "trailryx".to_owned()),
        key: std::env::var("TRAILRYX_S3_KEY").ok()?,
        secret: std::env::var("TRAILRYX_S3_SECRET").ok()?,
        region: std::env::var("TRAILRYX_S3_REGION").unwrap_or_else(|_| "us-east-1".to_owned()),
        // MinIO and most compatible stores are addressed by path; AWS prefers the
        // virtual-hosted form. The variable exists so the same suite can prove both.
        addressing: match std::env::var("TRAILRYX_S3_ADDRESSING").as_deref() {
            Ok("virtual") => Addressing::VirtualHosted,
            _ => Addressing::Path,
        },
    };
    Some(cfg)
}

fn store(cfg: &Config) -> S3 {
    S3::new(
        &cfg.endpoint,
        cfg.bucket.clone(),
        cfg.region.clone(),
        Credentials::new(cfg.key.clone(), cfg.secret.clone()),
        cfg.addressing,
        Conditional::IfNoneMatchStar,
    )
    .expect("the endpoint parses")
}

/// A prefix nobody else is using, derived from the process rather than a clock, so
/// two runs on one machine do not collide and a rerun does not depend on the first
/// having cleaned up.
fn prefix() -> String {
    format!("live/{}", std::process::id())
}

#[test]
fn the_four_operations_against_a_real_server() {
    let Some(cfg) = config() else {
        println!("skipped: TRAILRYX_S3_ENDPOINT, _KEY and _SECRET are not set");
        return;
    };
    let mut s3 = store(&cfg);
    let key = format!("{}/one", prefix());
    let body = b"the first publication".to_vec();

    let put = s3.put_if_absent(&key, &body);
    let (outcome, version) = ok("put_if_absent", put, &s3);
    assert_eq!(outcome, PutOutcome::Written, "a fresh key must be written");
    println!("put {key}: {outcome:?}, version {version:?}");

    let got = s3.get(&key);
    let read = ok("get", got, &s3);
    assert_eq!(
        read.as_deref(),
        Some(&body[..]),
        "what came back is not what went in"
    );

    // Versioning is a property of the deployment, not of the adapter: a bucket
    // without it is a fact to report, not a failure. MinIO answers this only when
    // the bucket has versioning enabled, and AWS answers it whenever the bucket
    // does, so both outcomes are printed rather than asserted.
    match version {
        Some(v) => {
            let got = s3.get_version(&key, &v);
            let by_version = ok("get_version", got, &s3);
            assert_eq!(
                by_version.as_deref(),
                Some(&body[..]),
                "the version the store handed back does not read the bytes it named"
            );
            println!("versioned read ok");
        }
        None => println!("this deployment does not version objects, so get_version is untested"),
    }

    let all = s3.list(&prefix());
    let listed = ok("list", all, &s3);
    assert!(
        listed.contains(&key),
        "the key just written is not in the listing: {listed:?}"
    );
}

/// The one a fake cannot prove.
#[test]
fn a_second_writer_is_refused_by_the_server_itself() {
    let Some(cfg) = config() else {
        println!("skipped: TRAILRYX_S3_ENDPOINT, _KEY and _SECRET are not set");
        return;
    };
    let mut s3 = store(&cfg);
    let key = format!("{}/contested", prefix());

    let first_put = s3.put_if_absent(&key, b"the winner");
    let (first, _) = ok("the first put_if_absent", first_put, &s3);
    assert_eq!(first, PutOutcome::Written);

    let second_put = s3.put_if_absent(&key, b"the loser");
    let (second, _) = ok("the second put_if_absent", second_put, &s3);
    assert_eq!(
        second,
        PutOutcome::AlreadyExists,
        "this store accepted a second write to an existing key under \
         If-None-Match: *. Atomic publication is unsafe against it, and the adapter \
         must be configured with Conditional::Absent for this endpoint rather than \
         left to believe the write was refused"
    );

    let after = s3.get(&key);
    let kept = ok("the read after the refused write", after, &s3);
    assert_eq!(
        kept.as_deref(),
        Some(&b"the winner"[..]),
        "the refused write changed the object anyway, which is the same failure \
         wearing a different answer"
    );
    println!("the server refused the second write and kept the first bytes");
}

/// Listing has to survive being longer than one response.
///
/// The pagination code is the part of a hand-written S3 client most likely to be
/// wrong against a real server, because a fake usually answers everything at once
/// and never sets a continuation token.
#[test]
fn a_listing_longer_than_one_page() {
    let Some(cfg) = config() else {
        println!("skipped: TRAILRYX_S3_ENDPOINT, _KEY and _SECRET are not set");
        return;
    };
    // Kept small on purpose: against a live bucket every object here is a billed
    // request, and the point is to cross the page boundary rather than to be large.
    let count = std::env::var("TRAILRYX_S3_PAGE_OBJECTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12u32);
    // Small pages on purpose. Without this the server's default is a thousand, so
    // a dozen objects would list in one response and the continuation path, the
    // whole point of the test, would never run.
    let mut s3 = store(&cfg).with_page_size(5);
    let under = format!("{}/page", prefix());
    for i in 0..count {
        let key = format!("{under}/{i:04}");
        let put = s3.put_if_absent(&key, format!("object {i}").as_bytes());
        ok("put_if_absent", put, &s3);
    }
    let all = s3.list(&under);
    let listed = ok("list", all, &s3);
    assert_eq!(
        listed.len(),
        count as usize,
        "the listing returned {} of {count} objects, which is what a mishandled \
         continuation token looks like",
        listed.len()
    );
    let mut sorted = listed.clone();
    sorted.sort();
    assert_eq!(
        listed, sorted,
        "the pages came back out of order, so a caller that stops early stops at \
         the wrong place"
    );
    println!("listed {count} objects under {under} in pages of 5");
}
