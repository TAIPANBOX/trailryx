//! The adapter against somebody else's Blob Storage.
//!
//! # Why, given `blob.rs` already runs against a fake over a real socket
//!
//! For the same reason the S3 crate grew a file with this name, and that reason was
//! not theoretical. The S3 adapter had a full green suite against a fake that spoke
//! S3, and the first request it ever sent to a server nobody here wrote was refused:
//! it had been sending two `Host` headers, which RFC 9112 requires a server to
//! reject. The fake had been written from the same reading of the same documentation
//! as the client, so it agreed with the client's mistake.
//!
//! Shared Key signing is a harder version of the same risk than SigV4, because the
//! string to sign is a fixed sequence of lines whose emptiness rules are documented
//! in prose and easy to read one way rather than another. A signature that is wrong
//! in a way our own fake also believes is wrong in the same way is a signature that
//! passes every test here and nothing at Microsoft.
//!
//! # Running it
//!
//! ```text
//! docker run -d -p 10000:10000 mcr.microsoft.com/azure-storage/azurite \
//!   azurite-blob --blobHost 0.0.0.0
//! TRAILRYX_AZURE_ENDPOINT=http://devstoreaccount1.blob.localhost:10000 \
//! TRAILRYX_AZURE_CONTAINER=trailryx \
//! TRAILRYX_AZURE_ACCOUNT=devstoreaccount1 TRAILRYX_AZURE_KEY=... \
//!   cargo test -p trailryx-azure --test live -- --nocapture
//! ```
//!
//! **The endpoint has to be the production-shaped one**, with the account in the host
//! rather than in the path. Azurite accepts both; this adapter only builds the first,
//! because that is what `account.blob.core.windows.net` is, and teaching it a base
//! path so an emulator's default shape works would be shipping a concession to a test
//! tool. `*.localhost` resolves to 127.0.0.1 by RFC 6761, so nothing has to be added
//! to `/etc/hosts`. Aimed at the path-shaped URL the run answers `404
//! ResourceNotFound` after the signature has already been accepted, which is worth
//! knowing before somebody spends an afternoon on the signer.
//!
//! Azurite's well-known development account and key are public and are in Microsoft's
//! own documentation, which is why they are passed in rather than written here: a
//! credential in a source file is a credential somebody copies into production.

use trailryx_azure::{Azure, Credentials};
use trailryx_contracts::{AdapterError, ObjectStore, PutOutcome};

/// The store's own words rather than the contract's summary.
#[track_caller]
fn ok<T>(what: &str, result: Result<T, AdapterError>, azure: &Azure) -> T {
    match result {
        Ok(v) => v,
        Err(e) => panic!(
            "{what} failed: {e}\n    the store itself said: {}",
            azure
                .last_failure()
                .map_or_else(|| "nothing this adapter kept".to_owned(), |f| f.to_string())
        ),
    }
}

struct Config {
    endpoint: String,
    container: String,
    account: String,
    key: String,
}

fn config() -> Option<Config> {
    Some(Config {
        endpoint: std::env::var("TRAILRYX_AZURE_ENDPOINT").ok()?,
        container: std::env::var("TRAILRYX_AZURE_CONTAINER")
            .unwrap_or_else(|_| "trailryx".to_owned()),
        account: std::env::var("TRAILRYX_AZURE_ACCOUNT").ok()?,
        key: std::env::var("TRAILRYX_AZURE_KEY").ok()?,
    })
}

fn store(cfg: &Config) -> Azure {
    Azure::new(
        &cfg.endpoint,
        cfg.container.clone(),
        Credentials::new(cfg.account.clone(), &cfg.key).expect("the key is base64"),
    )
    .expect("the endpoint parses")
}

fn prefix() -> String {
    format!("live/{}", std::process::id())
}

#[test]
fn the_operations_against_a_real_server() {
    let Some(cfg) = config() else {
        println!("skipped: TRAILRYX_AZURE_ENDPOINT, _ACCOUNT and _KEY are not set");
        return;
    };
    let mut azure = store(&cfg);
    let key = format!("{}/one", prefix());
    let body = b"the first publication".to_vec();

    let put = azure.put_if_absent(&key, &body);
    let (outcome, version) = ok("put_if_absent", put, &azure);
    assert_eq!(outcome, PutOutcome::Written, "a fresh blob must be written");
    println!("put {key}: {outcome:?}, version {version:?}");

    let got = azure.get(&key);
    let read = ok("get", got, &azure);
    assert_eq!(
        read.as_deref(),
        Some(&body[..]),
        "what came back is not what went in"
    );

    let all = azure.list(&prefix());
    let listed = ok("list", all, &azure);
    assert!(
        listed.contains(&key),
        "the blob just written is not in the listing: {listed:?}"
    );
}

/// The property atomic publication rests on, asked of a server we did not write.
///
/// On Blob Storage the condition is `If-None-Match: *`, and a refusal is `409
/// BlobAlreadyExists` rather than S3's `412`. Those are different enough that
/// agreeing with our own fake proves nothing about agreeing with Azure.
#[test]
fn a_second_writer_is_refused_by_the_server_itself() {
    let Some(cfg) = config() else {
        println!("skipped: TRAILRYX_AZURE_ENDPOINT, _ACCOUNT and _KEY are not set");
        return;
    };
    let mut azure = store(&cfg);
    let key = format!("{}/contested", prefix());

    let first_put = azure.put_if_absent(&key, b"the winner");
    let (first, _) = ok("the first put_if_absent", first_put, &azure);
    assert_eq!(first, PutOutcome::Written);

    let second_put = azure.put_if_absent(&key, b"the loser");
    let (second, _) = ok("the second put_if_absent", second_put, &azure);
    assert_eq!(
        second,
        PutOutcome::AlreadyExists,
        "this endpoint accepted a second write to an existing blob under \
         If-None-Match: *, so atomic publication is unsafe against it"
    );

    let after = azure.get(&key);
    let kept = ok("the read after the refused write", after, &azure);
    assert_eq!(
        kept.as_deref(),
        Some(&b"the winner"[..]),
        "the refused write changed the blob anyway"
    );
    println!("the server refused the second write and kept the first bytes");
}
