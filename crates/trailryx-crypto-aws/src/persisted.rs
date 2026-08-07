//! A key custodian whose keys outlive the process that made them.
//!
//! # What this is for
//!
//! [`crate::custody::HybridKeyProvider`] performs the hybrid exchange the record
//! format names, and keeps its recipient key pairs in memory. That makes it correct
//! and undeployable: a restart makes every payload the previous process wrapped
//! unreadable, which is safe in the direction erasure cares about and useless in the
//! direction durability cares about. This is the same KEM with the keys written down,
//! and it is what makes the other one's guarantee usable rather than only true.
//!
//! It is **not** a key management service and does not want to become one. What it is
//! is the local half that a KMS adapter would replace: one directory, one file per
//! key-encryption key, and a commit protocol the rest of this repository already uses.
//!
//! # The file at rest, which is the decision worth arguing about
//!
//! A custodian's directory is the whole secret. If private keys sit in the clear
//! beside the sealed segments then anyone who takes the disk takes everything, and
//! crypto-erasure becomes theatre: destroying a key means nothing if somebody copied
//! it yesterday. A backup, a snapshot, a replica and a stolen laptop are all that
//! copy.
//!
//! So this custodian **refuses to open without a root key it did not make**.
//! [`CustodyKey`] is 32 bytes an operator holds somewhere this process does not: an
//! environment variable, a file with `0600` on it, a secret manager, eventually a KMS
//! or an HSM. There is deliberately no "generate one if it is missing", because a
//! custodian that mints its own root key and writes it beside the data is plaintext
//! with extra steps, and it would read in a review as though something had been done.
//!
//! Each key file is sealed with AES-256-GCM under a key derived from that root by
//! HKDF-SHA-384, salted per key id, with the key id as associated data. What that
//! buys and what it does not, stated plainly because both matter:
//!
//! - **It buys the offline case, which is the one that happens.** A copied disk, a
//!   backup tape, an object-store snapshot, a decommissioned SSD: none of them yield
//!   a payload without the root key.
//! - **It does not buy the online case.** An attacker who has the running process has
//!   the root key in memory and every key the process can read. Nothing at this layer
//!   can change that, and a KMS would: the point of moving custody into an HSM is
//!   that the private key never enters this address space at all.
//! - **It does not make erasure retroactive.** Destroying a key destroys this
//!   custodian's copy. A copy somebody took while the key was live, decrypted, is
//!   beyond the reach of anything written here, and the honest statement of what
//!   crypto-erasure is includes that sentence.
//! - **The root key is now the single point of failure, in both directions.** Lose it
//!   and every payload is unreadable, which is erasure of the whole store by
//!   accident. Destroy it deliberately and that is the same operation performed on
//!   purpose, which is a feature an operator should know they have.
//!
//! A passphrase was the other candidate and is not what this takes. A passphrase is
//! only worth what a memory-hard derivation makes it worth, aws-lc-rs offers PBKDF2
//! and not Argon2, and PBKDF2 over a human passphrase protecting a file that IS the
//! whole secret is a weaker promise stated more comfortably. Thirty-two real bytes,
//! or nothing.
//!
//! # The ordering, which is the part that must not be got wrong
//!
//! Crypto-erasure is what this repository sells, so **a destruction is durable before
//! it is reported**. Reporting one that a crash then rolls back is the worst failure
//! this component can have, because somebody has already told a regulator the data is
//! gone. The opposite error, a key destroyed on disk and reported as failed, is
//! recoverable and loud, and it is the side every failure here falls on.
//!
//! The commit point is a single `rename` of a tombstone **over** the key file, which
//! is the same publication protocol `trailryx_node::plane::write_committing` uses for
//! a manifest and a cursor, with one difference stated rather than inherited: the
//! directory `fsync` here is **required rather than best effort**, because the answer
//! this function returns is a claim about the disk. That is why this is a second
//! implementation of a shape that already exists in the tree rather than a call to
//! the first one, and it is the only reason: `trailryx-node` sits above this crate
//! and a KEM adapter must not depend on the assembled plane.
//!
//! One rename does both halves at once, which is what makes the ordering provable
//! rather than merely careful. There is no window in which the key is gone and the
//! tombstone is not, or the tombstone is there and the key material is still beside
//! it: the old inode is unlinked by the same operation that publishes the new one.
//!
//! `wrap` commits the same way and for the mirrored reason: a wrapped key handed back
//! before its recipient key pair is on the disk is a payload the next process cannot
//! open, so the write is durable before the caller ever sees the blob.
//!
//! **What is measured and what is argued, because they are not the same here.**
//! `trailryx-kill custody` kills this code with a `SIGKILL` and asks a new custodian
//! over the same directory about every answer the dead one gave: 25 kills, 615
//! destructions reported and none undone, 937 wraps reported and none lost. That is
//! evidence about the **ordering**, and the harness was watched failing (207
//! resurrections against a `destroy` that reports and writes nothing), so it is not
//! reporting zero because it cannot see. It is **not** evidence about the `fsync`s:
//! with both of them removed the same run is still clean, because killing a process
//! leaves the kernel and its page cache alive. Only a machine dying would separate
//! those two, and `VALIDATION.md` keeps that in *not yet measured* rather than
//! implying it. The `fsync`s stay on the argument, and they cost about 10 ms per
//! committed operation on APFS, which is the figure a caller wrapping one key per
//! record needs to know.
//!
//! # What a torn or unreadable file means, and why it is not "absent"
//!
//! Absent is the only state that lets `wrap` mint a fresh key pair under an id. So a
//! file that is present and does not read back is treated as a **destroyed** key and
//! never as an absent one, and an I/O error that is not `NotFound` is treated the
//! same way. `crates/trailryx-node/src/cursor.rs` takes every failure the other
//! direction, to duplication rather than to loss, and the two are the same rule
//! applied to opposite costs: there the loud failure is reading a line twice, here it
//! is refusing to open a payload.
//!
//! # What a KMS adapter would need from here
//!
//! Nothing in this file, which is the point of saying it. `KeyProvider` is four
//! methods and a KMS satisfies them by calling `Encrypt`, `Decrypt`,
//! `ScheduleKeyDeletion` and `DescribeKey`; `Destroyed::Scheduled` already exists for
//! the answer every real service gives, and `trailryx_erasure::Vault` already refuses
//! to report a schedule as an erasure. What such an adapter would need that this
//! branch adds is the seam being real rather than notional: a second implementation
//! of `KeyProvider` that persists proves the trait is sufficient to persist through,
//! and the conformance suite in `trailryx_contracts::conformance::key_provider` is
//! what it would be held to. It would need a crate of its own on the declared list in
//! `scripts/declared-deps.sh`, a cloud SDK or a signed HTTP client, and an account,
//! and none of those three is in this repository today.

use std::io::Write;
use std::path::{Path, PathBuf};

use aws_lc_rs::hkdf::{HKDF_SHA384, KeyType, Salt};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use trailryx_contracts::contracts::{AdapterError, AdapterResult, Destroyed, KeyId, KeyProvider};
use trailryx_erasure::aead::{Aead, Dek, NONCE_BYTES};

use crate::AwsAead;
use crate::custody::{HEADER_BYTES, WRAP_VERSION, wrap_aad};
use crate::hybrid::{self, CIPHERTEXT_BYTES, Recipient, RecipientSecret};

/// The root key an operator supplies. Not a passphrase, and not derived from one.
pub const CUSTODY_KEY_BYTES: usize = 32;

/// The extension a live or destroyed key-encryption key is kept under.
const KEY_EXTENSION: &str = "kek";
/// The temporary a commit writes before renaming it into place.
const COMMIT_SUFFIX: &str = ".part";
/// What a directory holds so a wrong root key is a refusal rather than an emptiness.
const CHECK_FILE: &str = "custody.check";

/// The first bytes of every key file. A file that does not start with these is not
/// one of ours, and is refused rather than guessed at.
const FILE_MAGIC: &[u8; 8] = b"trlx-kek";
/// The shape below. A byte, so a later shape is refused rather than read as this one.
const FILE_VERSION: u8 = 1;

/// A file holding a live recipient key pair.
const KIND_LIVE: u8 = 1;
/// A file holding the fact that this key id was destroyed.
const KIND_TOMBSTONE: u8 = 2;

/// Everything before the sealed body: magic, version, nonce.
const FILE_HEADER_BYTES: usize = FILE_MAGIC.len() + 1 + NONCE_BYTES;

/// Domain separators. Three different derivations from one root key, and each one
/// says what it is for, so that no output of one can be mistaken for another's.
const LABEL_FILE_KEY: &[u8] = b"trailryx.custody.file-key.v1";
const LABEL_CHECK: &[u8] = b"trailryx.custody.root-check.v1";
const LABEL_FILE_AAD: &[u8] = b"trailryx.custody.file.v1";

/// The 32 bytes an operator holds and this process never writes down.
///
/// It is the whole of the at-rest protection: every key file in a custodian's
/// directory is sealed under a key derived from this one, and the directory without
/// it is 3,654 bytes of ciphertext per key.
pub struct CustodyKey([u8; CUSTODY_KEY_BYTES]);

impl std::fmt::Debug for CustodyKey {
    /// Written rather than derived. A derived `Debug` on this type is the shortest
    /// path from a root key to a log file.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustodyKey(<redacted>)")
    }
}

impl Drop for CustodyKey {
    /// Best effort, with the same limit as everything else here: this workspace
    /// forbids `unsafe`, so the zeroing is a plain loop the optimiser is asked not to
    /// remove rather than a volatile write.
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

impl CustodyKey {
    /// A fresh root key, returned and **not** written anywhere.
    ///
    /// Where it goes is the operator's decision and this crate has no opinion it
    /// could safely act on. What it must not do is put the key beside the data it
    /// protects, which is what a `generate_if_missing` would have done.
    pub fn generate() -> Option<Self> {
        let mut bytes = [0u8; CUSTODY_KEY_BYTES];
        SystemRandom::new().fill(&mut bytes).ok()?;
        Some(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; CUSTODY_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// 64 hexadecimal characters, which is the shape an environment variable or a
    /// secret manager entry takes.
    pub fn from_hex(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.len() != CUSTODY_KEY_BYTES * 2 {
            return None;
        }
        let mut bytes = [0u8; CUSTODY_KEY_BYTES];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// The same, from a file the operator points at.
    ///
    /// Whitespace is trimmed, so a file written by `echo` works. Nothing about the
    /// file's permissions is checked here: this process cannot fix them and refusing
    /// to start over a mode bit would be a check that teaches people to work around
    /// it. `SECURITY.md` says what the mode should be.
    pub fn read_from(path: &Path) -> Result<Self, CustodyError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CustodyError::Io(format!("{}: {e}", path.display())))?;
        Self::from_hex(&text).ok_or_else(|| {
            CustodyError::Malformed(format!(
                "{}: a custody key is {} hexadecimal characters",
                path.display(),
                CUSTODY_KEY_BYTES * 2
            ))
        })
    }

    /// The one place this value becomes a string.
    ///
    /// It exists so that a freshly generated key can be handed to whoever is going to
    /// keep it, once. Everything else about this type is arranged so the bytes do not
    /// travel, and this is the deliberate exception rather than an oversight.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A key derived from this one, for a named purpose, bound to `context`.
    fn derive(&self, label: &[u8], context: &[u8]) -> Option<[u8; 32]> {
        let prk = Salt::new(HKDF_SHA384, label).extract(&self.0);
        let mut out = [0u8; 32];
        prk.expand(&[label, context], Len(32))
            .ok()?
            .fill(&mut out)
            .ok()?;
        Some(out)
    }
}

/// The length `Prk::expand` is asked for. AWS-LC takes a type rather than a number.
#[derive(Debug, Clone, Copy)]
struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// Why a custodian would not open.
///
/// Three, and they are three different things an operator does about: a filesystem
/// problem, the wrong key, and a directory that is not a custodian's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyError {
    Io(String),
    /// The directory exists and was made under a different root key.
    ///
    /// A refusal rather than an empty directory, deliberately. Reading it as empty
    /// would mean a mistyped key silently minted fresh key pairs over live ones, and
    /// the first symptom would be every payload written before the typo becoming
    /// unreadable, weeks later, with nothing pointing at the cause.
    WrongKey(String),
    Malformed(String),
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "{s}"),
            Self::WrongKey(s) => write!(f, "{s}"),
            Self::Malformed(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for CustodyError {}

/// What is on the disk for one key id.
///
/// Four states and not three. `Unusable` is separate from `Destroyed` because an
/// operator does different things about them, and separate from `Absent` because
/// reading it as absent is the one mistake this type exists to prevent.
#[derive(Debug)]
enum OnDisk {
    /// No file. The only state under which a new key pair may be minted.
    Absent,
    Live(Box<Recipient>),
    Destroyed,
    /// A file is here and this build cannot use it: torn, sealed under another root
    /// key, written by a later version, or unreadable for a reason that is not
    /// `NotFound`.
    Unusable,
}

/// Custody of key-encryption keys in a directory, with the hybrid KEM behind each one.
///
/// One file per key id. A file is either a live recipient key pair or a tombstone,
/// and a tombstone is written **over** the key it replaces, so the destruction and
/// the removal of the material are one atomic step.
///
/// Nothing is cached. Every call reads the file it is about, which costs one read and
/// one AES-GCM open per operation and buys the property that matters more here than
/// speed: the answer is about what is on the disk now, not about what this process
/// saw when it started. A cache would also have to be invalidated by `destroy`, and a
/// stale entry there is a destroyed key that still opens payloads.
pub struct PersistedKeyProvider {
    dir: PathBuf,
    root: CustodyKey,
    rng: SystemRandom,
}

impl std::fmt::Debug for PersistedKeyProvider {
    /// The directory and nothing else. Not the root key, and not a count, because a
    /// count here costs a directory walk and a `Debug` that does I/O is a trap.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PersistedKeyProvider {{ dir: {:?} }}", self.dir)
    }
}

impl PersistedKeyProvider {
    /// Open a custodian over a directory, creating it if it is not there.
    ///
    /// A directory that has been used before is checked against the root key first,
    /// and a disagreement is refused. That check is a KDF output rather than anything
    /// derived from the key material directly, so the file says whether this is the
    /// right key and nothing else about it; against a 256-bit root key an offline
    /// search of it is not a threat worth a paragraph.
    pub fn open(dir: &Path, root: CustodyKey) -> Result<Self, CustodyError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| CustodyError::Io(format!("{}: {e}", dir.display())))?;
        restrict(dir, 0o700);

        let expected = root
            .derive(LABEL_CHECK, dir_context())
            .ok_or_else(|| CustodyError::Malformed("the root key would not derive".to_owned()))?;
        let path = dir.join(CHECK_FILE);
        match std::fs::read(&path) {
            Ok(found) if found == expected => {}
            Ok(_) => {
                return Err(CustodyError::WrongKey(format!(
                    "{}: this directory was written under a different custody key",
                    dir.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                commit(&path, &expected)
                    .map_err(|e| CustodyError::Io(format!("{}: {e}", path.display())))?;
            }
            Err(e) => return Err(CustodyError::Io(format!("{}: {e}", path.display()))),
        }

        Ok(Self {
            dir: dir.to_path_buf(),
            root,
            rng: SystemRandom::new(),
        })
    }

    /// The directory this custodian keeps its keys in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where one key id is kept. Public so a test can reach the file this writes;
    /// an operator reads it to know what to back up and what to shred.
    pub fn key_file(dir: &Path, kek: KeyId) -> PathBuf {
        dir.join(format!("{}.{KEY_EXTENSION}", kek.0.to_hex()))
    }

    /// The temporary a commit for that key writes before renaming it into place.
    ///
    /// Public for the same reason: the test that proves a destruction which cannot
    /// land is reported as a failure produces the crash by putting a directory here.
    pub fn commit_file(dir: &Path, kek: KeyId) -> PathBuf {
        let mut name = Self::key_file(dir, kek).into_os_string();
        name.push(COMMIT_SUFFIX);
        PathBuf::from(name)
    }

    /// How many key-encryption keys this custodian can still open payloads under.
    ///
    /// A directory walk and a decryption per file. Fine for a report at the end of a
    /// run and wrong inside a loop, which is why nothing in this file calls it.
    pub fn live_keys(&self) -> usize {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return 0;
        };
        entries
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == KEY_EXTENSION))
            .filter(|e| {
                std::fs::read(e.path())
                    .ok()
                    .and_then(|bytes| self.decode(&bytes, &file_aad_from(&e.path())))
                    .is_some_and(|(kind, _)| kind == KIND_LIVE)
            })
            .count()
    }

    /// What the disk says about one key id.
    ///
    /// The `NotFound` arm is the load-bearing one. Every other error becomes
    /// `Unusable`, because `Absent` is the state that lets a new key pair be minted
    /// and a transient read failure must never reach it.
    fn state(&self, kek: KeyId) -> OnDisk {
        let path = Self::key_file(&self.dir, kek);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return OnDisk::Absent,
            Err(_) => return OnDisk::Unusable,
        };
        match self.decode(&bytes, &file_aad(kek)) {
            Some((KIND_TOMBSTONE, _)) => OnDisk::Destroyed,
            Some((KIND_LIVE, body)) => match RecipientSecret::from_bytes(&body)
                .as_ref()
                .and_then(Recipient::from_secret)
            {
                Some(recipient) => OnDisk::Live(Box::new(recipient)),
                None => OnDisk::Unusable,
            },
            _ => OnDisk::Unusable,
        }
    }

    /// Seal a body under a key derived for this file, and put the frame round it.
    fn encode(&self, aad: &[u8], kind: u8, body: &[u8]) -> AdapterResult<Vec<u8>> {
        let key = self
            .root
            .derive(LABEL_FILE_KEY, aad)
            .ok_or(AdapterError::Unavailable("the file key would not derive"))?;
        let mut nonce = [0u8; NONCE_BYTES];
        self.rng
            .fill(&mut nonce)
            .map_err(|_| AdapterError::Unavailable("the system entropy source failed"))?;

        // The kind is inside the sealed part rather than beside it, so a tombstone
        // cannot be turned back into a live key, or a live key into a tombstone, by
        // anybody who can write to the directory but does not hold the root key.
        let mut plaintext = Vec::with_capacity(1 + body.len());
        plaintext.push(kind);
        plaintext.extend_from_slice(body);
        let sealed = AwsAead.seal(&Dek::new(key), &nonce, aad, &plaintext);
        plaintext.fill(0);
        std::hint::black_box(&plaintext);

        let mut out = Vec::with_capacity(FILE_HEADER_BYTES + sealed.len());
        out.extend_from_slice(FILE_MAGIC);
        out.push(FILE_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// The inverse, and `None` for every failure without saying which.
    ///
    /// One answer for a torn file, a wrong root key, a later version and a forged
    /// one, for the reason `Aead::open` gives: a caller that could tell them apart is
    /// an oracle. The caller here turns all of them into `Unusable`, which is the
    /// same answer as `Destroyed` to everything except an operator reading a message.
    fn decode(&self, bytes: &[u8], aad: &[u8]) -> Option<(u8, Vec<u8>)> {
        if bytes.len() <= FILE_HEADER_BYTES
            || !bytes.starts_with(FILE_MAGIC)
            || bytes[FILE_MAGIC.len()] != FILE_VERSION
        {
            return None;
        }
        let key = self.root.derive(LABEL_FILE_KEY, aad)?;
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&bytes[FILE_MAGIC.len() + 1..FILE_HEADER_BYTES]);
        let plaintext = AwsAead.open(&Dek::new(key), &nonce, aad, &bytes[FILE_HEADER_BYTES..])?;
        let (kind, body) = plaintext.split_first()?;
        Some((*kind, body.to_vec()))
    }

    /// Write a key file so that all of it lands or none of it does.
    fn put(&self, kek: KeyId, kind: u8, body: &[u8]) -> AdapterResult<()> {
        let bytes = self.encode(&file_aad(kek), kind, body)?;
        commit(&Self::key_file(&self.dir, kek), &bytes)
            .map_err(|_| AdapterError::Unavailable("the key file could not be committed"))
    }
}

impl KeyProvider for PersistedKeyProvider {
    /// Wrap a data key, minting the recipient key pair on first use.
    ///
    /// **The write happens before the blob is returned.** A wrapped key handed to a
    /// caller whose recipient is not yet on the disk is a payload the next process
    /// cannot open, which is the same ordering rule `destroy` obeys, pointing the
    /// other way.
    fn wrap(&mut self, kek: KeyId, dek: &[u8]) -> AdapterResult<Vec<u8>> {
        let recipient = match self.state(kek) {
            OnDisk::Live(recipient) => *recipient,
            OnDisk::Destroyed => return Err(AdapterError::Rejected("key id was destroyed")),
            OnDisk::Unusable => {
                return Err(AdapterError::Rejected("the key file did not read back"));
            }
            OnDisk::Absent => {
                let recipient = Recipient::generate()
                    .ok_or(AdapterError::Unavailable("no key pair could be generated"))?;
                let secret = recipient
                    .secret()
                    .ok_or(AdapterError::Unavailable("the key pair is not storable"))?;
                self.put(kek, KIND_LIVE, secret.as_bytes())?;
                recipient
            }
        };

        let public = recipient
            .public_key()
            .ok_or(AdapterError::Unavailable("the public key is unreadable"))?;
        let sent = hybrid::encapsulate(&public)
            .ok_or(AdapterError::Unavailable("the encapsulation failed"))?;

        let mut nonce = [0u8; NONCE_BYTES];
        self.rng
            .fill(&mut nonce)
            .map_err(|_| AdapterError::Unavailable("the system entropy source failed"))?;

        let key = Dek::new(*sent.shared_secret.as_bytes());
        let sealed = AwsAead.seal(&key, &nonce, &wrap_aad(kek), dek);

        let mut out = Vec::with_capacity(HEADER_BYTES + sealed.len());
        out.push(WRAP_VERSION);
        out.extend_from_slice(&sent.ciphertext);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// The blob is the same shape `HybridKeyProvider` writes, and deliberately so:
    /// the two differ in where the recipient lives and in nothing a stored envelope
    /// can see.
    fn unwrap(&mut self, kek: KeyId, wrapped: &[u8]) -> AdapterResult<Vec<u8>> {
        let recipient = match self.state(kek) {
            OnDisk::Live(recipient) => recipient,
            OnDisk::Absent => return Err(AdapterError::Rejected("no such key")),
            OnDisk::Destroyed => return Err(AdapterError::Rejected("key id was destroyed")),
            OnDisk::Unusable => {
                return Err(AdapterError::Rejected("the key file did not read back"));
            }
        };

        if wrapped.len() <= HEADER_BYTES || wrapped[0] != WRAP_VERSION {
            return Err(AdapterError::Rejected("not a wrapped key this build wrote"));
        }
        let ciphertext = &wrapped[1..1 + CIPHERTEXT_BYTES];
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&wrapped[1 + CIPHERTEXT_BYTES..HEADER_BYTES]);
        let sealed = &wrapped[HEADER_BYTES..];

        let secret = recipient
            .decapsulate(ciphertext)
            .ok_or(AdapterError::Rejected("the wrapped key did not open"))?;
        AwsAead
            .open(
                &Dek::new(*secret.as_bytes()),
                &nonce,
                &wrap_aad(kek),
                sealed,
            )
            .ok_or(AdapterError::Rejected("the wrapped key did not open"))
    }

    /// Destroy a key, durably, before saying so.
    ///
    /// The tombstone is renamed **over** the key file, so one atomic operation both
    /// publishes the destruction and unlinks the material. If it fails, this returns
    /// an error and the key still works, which is the recoverable direction; there is
    /// no path here that reports `Now` over a tombstone that did not land.
    ///
    /// What this does not claim: that the bytes are unrecoverable from the physical
    /// medium. A rename unlinks an inode; it does not overwrite the blocks, and on a
    /// copy-on-write filesystem or an SSD nothing at this level could. The reason
    /// that is survivable rather than fatal is the layer above it: those blocks hold
    /// ciphertext under a key derived from a root key this process never wrote down.
    fn destroy(&mut self, kek: KeyId) -> AdapterResult<Destroyed> {
        let existed = match self.state(kek) {
            // Already a tombstone. Nothing is written, so a retry costs no `fsync`
            // and, more to the point, cannot move anything: an erasure job retrying
            // must find the same answer it found the first time.
            OnDisk::Destroyed => return Ok(Destroyed::Already),
            OnDisk::Live(_) => true,
            // Never here, or here and unreadable. The tombstone is written either
            // way, because the guarantee is that the id is never reissued, and that
            // has to hold for an id nobody ever wrapped under.
            OnDisk::Absent | OnDisk::Unusable => false,
        };
        self.put(kek, KIND_TOMBSTONE, &[])?;
        Ok(if existed {
            Destroyed::Now
        } else {
            // `Already` for a key this custodian could not read, rather than `Now`.
            // Something was replaced, and claiming to have destroyed material that
            // could not be identified would be a stronger statement than the facts.
            Destroyed::Already
        })
    }

    fn exists(&self, kek: KeyId) -> bool {
        matches!(self.state(kek), OnDisk::Live(_))
    }
}

/// What a key file is bound to.
///
/// The key id, so a file cannot be renamed onto another id's name and read: that swap
/// is otherwise undetectable and it is how a destroyed key would come back.
fn file_aad(kek: KeyId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LABEL_FILE_AAD.len() + 48);
    aad.extend_from_slice(LABEL_FILE_AAD);
    aad.extend_from_slice(kek.0.as_bytes());
    aad
}

/// The same, rebuilt from a file name, for the one caller that has a path and no id.
///
/// A name that is not 96 hexadecimal characters yields associated data nothing will
/// open, which is the right answer: a file whose name is not a key id is not a key
/// file, and [`PersistedKeyProvider::live_keys`] must not count it.
fn file_aad_from(path: &Path) -> Vec<u8> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let mut aad = Vec::with_capacity(LABEL_FILE_AAD.len() + 48);
    aad.extend_from_slice(LABEL_FILE_AAD);
    for i in (0..stem.len().saturating_sub(1)).step_by(2) {
        match stem
            .get(i..i + 2)
            .and_then(|p| u8::from_str_radix(p, 16).ok())
        {
            Some(byte) => aad.push(byte),
            None => return Vec::new(),
        }
    }
    aad
}

/// What the check file is derived over.
///
/// A constant rather than the directory's path: a custodian's directory is routinely
/// moved, restored from a backup under another name, or mounted somewhere else in a
/// container, and a check that failed on any of those would teach an operator that
/// this refusal is noise.
fn dir_context() -> &'static [u8] {
    b"trailryx.custody.directory.v1"
}

/// Write a file so that a reader sees all of it or none of it, and so that the rename
/// is on the disk before this returns.
///
/// The same temporary-then-rename `trailryx_node::plane::write_committing` uses, with
/// the directory `fsync` **required** rather than best effort. That difference is the
/// whole reason this is written twice rather than shared: what this function returns
/// is the evidence a destruction is reported on, and "probably durable on every
/// filesystem we have tried" is not evidence.
fn commit(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(COMMIT_SUFFIX);
    let tmp = PathBuf::from(tmp);
    {
        let mut file = std::fs::File::create(&tmp)?;
        restrict(&tmp, 0o600);
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;

    let dir = path.parent().unwrap_or(Path::new("."));
    let handle = std::fs::File::open(dir)?;
    // `sync_all` on a directory is `F_FULLFSYNC` on macOS, which the platform
    // refuses on some directory handles; `sync_data` is the `fsync` that POSIX
    // defines for exactly this. Both are tried and the error is returned, because a
    // silent `let _ =` here is the whole failure this file is arranged against.
    handle.sync_all().or_else(|_| handle.sync_data())
}

/// Tighten a path's mode where the platform has one.
///
/// Best effort and deliberately not a failure: a filesystem without Unix permissions
/// is not a reason to refuse to start, and the file's contents are sealed either way.
/// This narrows who has to be trusted, it is not what protects the key.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::RECIPIENT_SECRET_BYTES;
    use trailryx_contracts::conformance;
    use trailryx_record::Hash;

    /// A directory of this process's own, removed when the test ends. Invariant 29
    /// for the name and invariant 31 for the removal.
    #[derive(Debug)]
    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("trailryx-persisted-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            Self { path }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn root() -> CustodyKey {
        CustodyKey::from_bytes([3u8; CUSTODY_KEY_BYTES])
    }

    fn kek(byte: u8) -> KeyId {
        KeyId(Hash([byte; 48]))
    }

    fn provider(scratch: &Scratch) -> PersistedKeyProvider {
        PersistedKeyProvider::open(&scratch.path, root()).expect("a custodian")
    }

    /// Invariant 14: every adapter passes the conformance suite before it enters a
    /// build. This is the suite that decides whether a destroyed key stays destroyed.
    #[test]
    fn the_persisted_custodian_conforms() {
        let scratch = Scratch::new("conformance");
        let mut provider = provider(&scratch);
        let report = conformance::key_provider(&mut provider);
        assert!(report.passed(), "{}", report.summary());
    }

    #[test]
    fn the_root_key_does_not_print_itself() {
        let key = CustodyKey::from_bytes([9u8; CUSTODY_KEY_BYTES]);
        assert_eq!(format!("{key:?}"), "CustodyKey(<redacted>)");
        assert!(!format!("{key:?}").contains('9'));
    }

    #[test]
    fn a_root_key_reads_back_from_its_own_hexadecimal() {
        let key = CustodyKey::generate().expect("a key");
        let text = key.to_hex();
        assert_eq!(text.len(), CUSTODY_KEY_BYTES * 2);
        assert_eq!(CustodyKey::from_hex(&text).expect("it reads back").0, key.0);
        // And nothing else is accepted, so a truncated secret is a refusal rather
        // than a shorter key. The malformed cases are built from a fixed key rather
        // than the generated one: substituting a character into random hexadecimal
        // is a no-op whenever that character happens not to occur, which for one
        // digit in sixty-four characters is about one run in sixty-four.
        let fixed = CustodyKey::from_bytes([0u8; CUSTODY_KEY_BYTES]).to_hex();
        assert!(CustodyKey::from_hex(&fixed[..62]).is_none());
        assert!(CustodyKey::from_hex(&format!("{fixed}00")).is_none());
        assert!(CustodyKey::from_hex(&fixed.replace('0', "z")).is_none());
        assert!(CustodyKey::from_hex("").is_none());
    }

    /// A file cannot be copied from one key id's name to another's and read.
    ///
    /// **What refuses it here is the associated data, not the derivation**, and the
    /// name used to claim otherwise. Measured: making `derive` ignore its context, so
    /// that every file in a directory is sealed under one key, leaves this test
    /// green, because the key id is also in the associated data and the tag fails
    /// before the difference in keys could matter. Two locks, one behaviour, and the
    /// behavioural test can only ever reach the outer one. The derivation is held by
    /// [`two_key_ids_derive_two_different_file_keys`] instead, which is the same
    /// shape `custody.rs` uses for `the_wrap_is_bound_to_its_key_id`.
    #[test]
    fn a_key_file_does_not_open_under_another_key_id() {
        let scratch = Scratch::new("file-keys");
        let provider = provider(&scratch);
        let one = provider
            .encode(&file_aad(kek(1)), KIND_LIVE, b"body")
            .expect("one");
        assert!(provider.decode(&one, &file_aad(kek(1))).is_some());
        assert!(
            provider.decode(&one, &file_aad(kek(2))).is_none(),
            "one key id's file opened under another's"
        );
    }

    /// The second lock, held directly because behaviour cannot reach it.
    #[test]
    fn two_key_ids_derive_two_different_file_keys() {
        let root = root();
        assert_ne!(
            root.derive(LABEL_FILE_KEY, &file_aad(kek(1))),
            root.derive(LABEL_FILE_KEY, &file_aad(kek(2))),
            "every key file in a directory is sealed under one key"
        );
        // And the two purposes this root key serves do not collide either.
        assert_ne!(
            root.derive(LABEL_FILE_KEY, &file_aad(kek(1))),
            root.derive(LABEL_CHECK, &file_aad(kek(1))),
        );
    }

    /// The kind is inside the sealed part, so it cannot be flipped from outside.
    ///
    /// The first assertion is the one that bites, and it took a mutation to find
    /// that out: the tearing loop below **never reaches a decoded file at all**,
    /// because every byte of this format is either the magic, the version, the nonce
    /// or the sealed region, so a flipped bit anywhere is refused. Written with only
    /// the loop, this test asserted nothing and passed against a build that wrote
    /// every file as live. The loop stays because "no single-bit change produces a
    /// live key" is worth pinning; what it is not is evidence on its own.
    #[test]
    fn a_tombstone_cannot_be_turned_back_into_a_live_key_from_outside() {
        let scratch = Scratch::new("kind");
        let provider = provider(&scratch);
        let dead = provider
            .encode(&file_aad(kek(1)), KIND_TOMBSTONE, &[])
            .expect("a tombstone");
        assert_eq!(
            provider
                .decode(&dead, &file_aad(kek(1)))
                .expect("it reads back")
                .0,
            KIND_TOMBSTONE,
            "a tombstone did not read back as one"
        );

        let mut decoded = 0;
        for i in 0..dead.len() {
            let mut torn = dead.clone();
            torn[i] ^= 0x01;
            if let Some((kind, _)) = provider.decode(&torn, &file_aad(kek(1))) {
                decoded += 1;
                assert_eq!(kind, KIND_TOMBSTONE, "byte {i} changed the kind");
            }
        }
        assert_eq!(
            decoded, 0,
            "a torn file decoded, which this format cannot do"
        );
    }

    /// A file name that is not a key id contributes no associated data anything
    /// opens, so a stray file in the directory is not counted as a live key.
    #[test]
    fn a_file_that_is_not_a_key_file_is_not_counted() {
        let scratch = Scratch::new("stray");
        let mut provider = provider(&scratch);
        provider.wrap(kek(1), &[7u8; 32]).expect("a wrap");
        assert_eq!(provider.live_keys(), 1);

        std::fs::write(scratch.path.join("notes.kek"), b"whatever").expect("a stray file");
        assert_eq!(provider.live_keys(), 1, "a stray file was counted as a key");
    }

    /// The header this file writes, held against the arithmetic that reads it.
    #[test]
    fn a_key_file_is_the_size_the_layout_says() {
        let scratch = Scratch::new("size");
        let mut provider = provider(&scratch);
        provider.wrap(kek(1), &[7u8; 32]).expect("a wrap");
        let bytes = std::fs::read(PersistedKeyProvider::key_file(&scratch.path, kek(1)))
            .expect("the key file");
        // magic + version + nonce + AES-GCM(kind + dk_PQ + sk_T + ek_PQ)
        assert_eq!(
            bytes.len(),
            FILE_HEADER_BYTES + 1 + RECIPIENT_SECRET_BYTES + 16
        );
        assert_eq!(RECIPIENT_SECRET_BYTES, 2400 + 32 + 1184);
    }
}
