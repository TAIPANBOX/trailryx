//! A signer that is somebody else's code.
//!
//! This repository contains no signing code and should not: a private key and a
//! nonce belong behind a validated module. So the demo drives OpenSSL as a
//! subprocess, and the signatures the verifier accepts are made by an
//! implementation with no shared ancestry with ours.
//!
//! Where OpenSSL is missing, the demo says the pack is unsigned and carries on.
//! The verifier already reports an unsigned pack as a weakness, so the demo
//! shows a true thing either way.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use trailryx_record::SigAlg;
use trailryx_sign::{SignError, Signer};

#[derive(Debug)]
pub struct Openssl {
    key: PathBuf,
    public: Vec<u8>,
    scratch: PathBuf,
}

impl Openssl {
    /// `None` when there is no usable OpenSSL on the machine.
    pub fn new(dir: &std::path::Path, name: &str) -> Option<Self> {
        let scratch = dir.join(name);
        std::fs::create_dir_all(&scratch).ok()?;
        let key = scratch.join("key.pem");

        let made = Command::new("openssl")
            .args(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out"])
            .arg(&key)
            .status()
            .ok()?;
        if !made.success() {
            return None;
        }
        let spki = Command::new("openssl")
            .arg("ec")
            .arg("-in")
            .arg(&key)
            .args(["-pubout", "-outform", "DER"])
            .output()
            .ok()?;
        if !spki.status.success() || spki.stdout.len() < 97 {
            return None;
        }
        let public = spki.stdout[spki.stdout.len() - 97..].to_vec();
        if public[0] != 0x04 {
            return None;
        }
        Some(Self {
            key,
            public,
            scratch,
        })
    }
}

impl Signer for Openssl {
    fn algorithm(&self) -> SigAlg {
        SigAlg::Es384
    }

    fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn is_validated(&self) -> bool {
        // A command-line tool driven over temporary files is not a key
        // management story. It signs correctly and it is not a deployment.
        false
    }

    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let path = self.scratch.join("message.bin");
        std::fs::write(&path, message).map_err(|e| SignError::Unavailable(e.to_string()))?;
        let out = Command::new("openssl")
            .args(["dgst", "-sha384", "-sign"])
            .arg(&self.key)
            .arg(&path)
            .output()
            .map_err(|e| SignError::Unavailable(e.to_string()))?;
        if !out.status.success() {
            return Err(SignError::Unavailable("openssl refused to sign".into()));
        }
        der_to_raw(&out.stdout).ok_or_else(|| SignError::Unavailable("unreadable DER".into()))
    }
}

/// `SEQUENCE { INTEGER r, INTEGER s }` to the fixed 96 bytes the format wants.
///
/// DER lets the same number be written more than one way, and nothing this
/// project hashes accepts two spellings of one value.
fn der_to_raw(der: &[u8]) -> Option<Vec<u8>> {
    if der.first()? != &0x30 {
        return None;
    }
    let mut at = if der[1] < 0x80 {
        2
    } else {
        2 + usize::from(der[1] & 0x7f)
    };
    let mut out = Vec::with_capacity(96);
    for _ in 0..2 {
        if *der.get(at)? != 0x02 {
            return None;
        }
        let len = usize::from(*der.get(at + 1)?);
        let value = der.get(at + 2..at + 2 + len)?;
        at += 2 + len;
        let trimmed: Vec<u8> = value.iter().copied().skip_while(|b| *b == 0).collect();
        if trimmed.len() > 48 {
            return None;
        }
        out.extend(std::iter::repeat_n(0u8, 48 - trimmed.len()));
        out.extend_from_slice(&trimmed);
    }
    Some(out)
}

/// Write bytes to a file, best effort, so a demo step can hand one to a tool.
pub fn write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
