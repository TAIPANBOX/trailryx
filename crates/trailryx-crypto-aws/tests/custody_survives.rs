//! The custodian across a restart, which is the only place this can be tested.
//!
//! Every test here opens a custodian over a directory, drops it, and opens a
//! **second** one over the same directory. That is what a restart is from the
//! outside, and it is the property `HybridKeyProvider` does not have: its module
//! documentation says so and `a_second_custodian_cannot_open_the_first_ones_wrapped_key`
//! in `wrap_path.rs` pins it.
//!
//! The pair of them is deliberate. One custodian keeps nothing and the other keeps
//! everything, and both are correct answers to different deployments; what would be
//! wrong is a custodian whose durability nobody stated.

use std::path::{Path, PathBuf};

use trailryx_contracts::contracts::{AdapterError, Destroyed, KeyId, KeyProvider};
use trailryx_crypto_aws::{CustodyError, CustodyKey, PersistedKeyProvider};
use trailryx_record::Hash;

/// A directory of this process's own, removed when the test ends.
///
/// `std::process::id()` is invariant 29: `$TMPDIR` belongs to the user rather than
/// to the run, and two copies of this binary would otherwise name one directory.
#[derive(Debug)]
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "trailryx-custody-{}-{name}-{}",
            std::process::id(),
            name.len()
        ));
        let _ = std::fs::remove_dir_all(&path);
        Self { path }
    }

    fn dir(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    /// Invariant 31: the file that made a scratch path removes it. This one owns
    /// its directory and has nothing to leave behind, which is the case a `Drop`
    /// is the right tool for.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn root() -> CustodyKey {
    CustodyKey::from_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        .expect("a root key")
}

fn other_root() -> CustodyKey {
    CustodyKey::from_hex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
        .expect("a second root key")
}

fn kek(byte: u8) -> KeyId {
    KeyId(Hash([byte; 48]))
}

fn open(dir: &Path) -> PersistedKeyProvider {
    PersistedKeyProvider::open(dir, root()).expect("the custodian opens")
}

/// The whole point of the branch: a key wrapped by one process opens in the next.
#[test]
fn a_payload_key_wrapped_before_a_restart_unwraps_after_one() {
    let scratch = Scratch::new("restart");
    let dek = [7u8; 32];

    let wrapped = {
        let mut first = open(scratch.dir());
        first.wrap(kek(1), &dek).expect("a wrap")
    };

    let mut second = open(scratch.dir());
    assert_eq!(
        second.unwrap(kek(1), &wrapped).expect("an unwrap"),
        dek,
        "a restart made a payload the previous process wrapped unreadable"
    );
    assert!(second.exists(kek(1)));
}

/// The product feature, across the thing that is meant to undo it.
#[test]
fn a_destroyed_key_is_still_destroyed_after_a_restart() {
    let scratch = Scratch::new("destroy");
    let dek = [7u8; 32];

    let wrapped = {
        let mut first = open(scratch.dir());
        let wrapped = first.wrap(kek(1), &dek).expect("a wrap");
        assert_eq!(first.destroy(kek(1)), Ok(Destroyed::Now));
        wrapped
    };

    let mut second = open(scratch.dir());
    assert!(
        !second.exists(kek(1)),
        "a destroyed key came back on restart"
    );
    assert!(second.unwrap(kek(1), &wrapped).is_err());
    // Not merely absent: refused, so the id cannot be reissued with a fresh key
    // pair that would make `exists` true again.
    assert!(second.wrap(kek(1), &dek).is_err());
    assert_eq!(second.destroy(kek(1)), Ok(Destroyed::Already));
}

/// `exists` and `unwrap` answer the same question, in every state and on both
/// sides of a restart.
#[test]
fn exists_and_unwrap_agree_on_every_state_and_across_a_restart() {
    let scratch = Scratch::new("agree");
    let dek = [7u8; 32];

    let wrapped = {
        let mut first = open(scratch.dir());
        let wrapped = first.wrap(kek(1), &dek).expect("a live key");
        first.wrap(kek(2), &dek).expect("a key to destroy");
        first.destroy(kek(2)).expect("a destruction");

        for id in [1u8, 2, 3] {
            let opens = first.unwrap(kek(id), &wrapped).is_ok();
            assert_eq!(first.exists(kek(id)), opens, "before the restart, id {id}");
        }
        wrapped
    };

    let mut second = open(scratch.dir());
    for id in [1u8, 2, 3] {
        let opens = second.unwrap(kek(id), &wrapped).is_ok();
        assert_eq!(second.exists(kek(id)), opens, "after the restart, id {id}");
    }
    assert!(second.exists(kek(1)));
    assert!(!second.exists(kek(2)));
    assert!(!second.exists(kek(3)));
}

/// A destroyed key and a key that was never here are different facts, and whoever
/// is reading the trail needs to be told which one they have.
#[test]
fn a_destroyed_key_says_so_rather_than_failing_the_way_a_wrong_key_fails() {
    let scratch = Scratch::new("says-so");
    let dek = [7u8; 32];

    let mut first = open(scratch.dir());
    let wrapped = first.wrap(kek(1), &dek).expect("a wrap");
    first.wrap(kek(2), &dek).expect("a second key");
    first.destroy(kek(2)).expect("a destruction");
    drop(first);

    let mut second = open(scratch.dir());
    let destroyed = second.unwrap(kek(2), &wrapped).expect_err("a refusal");
    let never_here = second.unwrap(kek(3), &wrapped).expect_err("a refusal");
    assert_ne!(
        destroyed, never_here,
        "a destroyed key and an unknown key gave the same error"
    );
    assert_eq!(destroyed, AdapterError::Rejected("key id was destroyed"));
    assert_eq!(never_here, AdapterError::Rejected("no such key"));
}

/// A wrong root key must be a refusal at the door, not a directory that reads as
/// empty.
///
/// The direction matters more than the message. Reading it as empty would mean a
/// mistyped key silently minted fresh key pairs over live ones, and the first
/// symptom would be every payload written before the typo becoming unreadable.
#[test]
fn a_wrong_root_key_refuses_the_directory_rather_than_reading_it_as_empty() {
    let scratch = Scratch::new("wrong-root");
    {
        let mut first = open(scratch.dir());
        first.wrap(kek(1), &[7u8; 32]).expect("a wrap");
    }

    let refused = PersistedKeyProvider::open(scratch.dir(), other_root());
    assert!(
        matches!(refused, Err(CustodyError::WrongKey(_))),
        "a custodian opened somebody else's directory: {refused:?}"
    );
}

/// A key file that will not read back is treated as a destroyed key, never as an
/// absent one.
///
/// Absent is the only state that lets `wrap` mint a fresh key pair under an id, so
/// it is the one state a damaged file must never be read as: doing so would strand
/// every payload already wrapped under that id and report success while doing it.
#[test]
fn a_key_file_that_does_not_read_back_is_never_read_as_an_absent_one() {
    let scratch = Scratch::new("torn");
    let dek = [7u8; 32];
    let wrapped = {
        let mut first = open(scratch.dir());
        first.wrap(kek(1), &dek).expect("a wrap")
    };

    let file = PersistedKeyProvider::key_file(scratch.dir(), kek(1));
    let mut bytes = std::fs::read(&file).expect("the key file");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&file, &bytes).expect("a torn key file");

    let mut second = open(scratch.dir());
    assert!(!second.exists(kek(1)));
    assert!(second.unwrap(kek(1), &wrapped).is_err());
    assert!(
        second.wrap(kek(1), &dek).is_err(),
        "a torn key file was read as an absent one and a new key pair was minted"
    );
}

/// **The whole of the at-rest decision, as a behaviour rather than an assertion
/// about bytes.**
///
/// Somebody takes the disk. They have the key file and not the root key, and the
/// question is whether that is enough. So the file is copied into a second
/// custodian's directory, opened under a different root key, and asked to work: it
/// must not. If the material were written in the clear it would, which is exactly
/// what taking a backup gets an attacker in a custodian that keeps plaintext.
///
/// The structural check beside it is weaker on purpose and still worth having: a
/// sealed file is 3,654 bytes and a plaintext one is a different size, so a build
/// that stopped encrypting would fail here even if the copy somehow did not.
#[test]
fn a_stolen_key_file_is_useless_without_the_root_key() {
    let held = Scratch::new("at-rest");
    let stolen = Scratch::new("at-rest-copy");
    let dek = [7u8; 32];

    let mut first = open(held.dir());
    let wrapped = first.wrap(kek(1), &dek).expect("a wrap");
    assert_eq!(first.unwrap(kek(1), &wrapped).expect("an unwrap"), dek);

    // A thief with the directory and not the key. The second custodian is opened
    // under its own root key first, so the check file is its own and the copied key
    // file is the only thing that came from elsewhere.
    let mut thief = PersistedKeyProvider::open(stolen.dir(), other_root()).expect("a custodian");
    std::fs::copy(
        PersistedKeyProvider::key_file(held.dir(), kek(1)),
        PersistedKeyProvider::key_file(stolen.dir(), kek(1)),
    )
    .expect("the file is taken");

    assert!(
        !thief.exists(kek(1)),
        "a key file read under a root key that did not write it"
    );
    assert!(
        thief.unwrap(kek(1), &wrapped).is_err(),
        "the payload key came out of a stolen file without the root key"
    );

    let bytes =
        std::fs::read(PersistedKeyProvider::key_file(held.dir(), kek(1))).expect("the key file");
    assert_eq!(
        bytes.len(),
        8 + 1 + 12 + 1 + 2400 + 32 + 1184 + 16,
        "the key file is not the size a sealed one is"
    );
}

/// **The ordering, held in process.** A destruction that cannot be committed is
/// reported as a failure, and the key still works.
///
/// The crash is produced without a signal, the way `crates/trailryx-node/tests/cursor.rs`
/// produces one: a directory is put where the temporary file has to be written, so
/// the commit fails exactly where a `SIGKILL` between the write and the rename
/// would stop it. The opposite answer, `Ok(Destroyed::Now)` over a tombstone that
/// never landed, is the failure this component cannot survive.
#[test]
fn a_destruction_that_cannot_be_committed_is_reported_as_a_failure() {
    let scratch = Scratch::new("blocked");
    let dek = [7u8; 32];
    let mut provider = open(scratch.dir());
    let wrapped = provider.wrap(kek(1), &dek).expect("a wrap");

    let blocker = PersistedKeyProvider::commit_file(scratch.dir(), kek(1));
    std::fs::create_dir_all(&blocker).expect("a directory where the temporary goes");

    let answer = provider.destroy(kek(1));
    assert!(
        answer.is_err(),
        "a destruction that never reached the disk was reported as {answer:?}"
    );
    assert!(
        provider.exists(kek(1)),
        "the key was reported gone and is gone, but the report failed"
    );
    assert_eq!(
        provider.unwrap(kek(1), &wrapped).expect("an unwrap"),
        dek,
        "the key stopped working without any destruction being committed"
    );

    // And once the way is clear the destruction lands, so this is a refusal rather
    // than a custodian that has broken itself.
    std::fs::remove_dir_all(&blocker).expect("the blocker goes");
    assert_eq!(provider.destroy(kek(1)), Ok(Destroyed::Now));
}
