//! Writing an evidence pack.
//!
//! The counterpart to `trailryx-verify`, and deliberately the only thing the
//! two share: a format, written down. No types, no helper crate, no generated
//! code. If the writer and the verifier shared an encoder, a bug in it would
//! produce a pack the verifier accepts and nobody else can read, which is the
//! opposite of what an evidence pack is for.
//!
//! # What goes in
//!
//! The record bytes, exactly as the journal wrote them, and the manifests. That
//! is all. Every chain link, index key, index root and tree root is derivable
//! from those, so none of them is written down: a field the pack states is a
//! field the pack can lie about, and one it derives cannot disagree with
//! itself.
//!
//! # What stays out
//!
//! Payloads. A pack travels to an auditor and the audit trail is metadata; a
//! pack carrying prompts would turn every audit into a data export, and the
//! erasure guarantees would have to follow it out of the building.

use trailryx_index::segment::{Segment, SegmentManifest, ShardTree, StoreTree};
use trailryx_journal::wire::encode_record;
use trailryx_record::{Hash, TenantId, Timestamp};
use trailryx_sign::{RootSignature, WitnessAttestation};

pub const MAGIC: &[u8; 7] = b"TRXEVID";
/// Three.
///
/// Two, because the signature moved out of the header into sections of its own
/// once there could be more than one of them. Three, because [`SECTION_ANCHOR`]
/// was added: an older verifier meeting one would report an unknown section, and
/// a version says why instead.
///
/// A version 2 pack still parses, and must: a pack written by an older commit
/// keeps verifying, which is the same promise the frozen record format makes.
pub const VERSION: u8 = 3;

const SECTION_END: u8 = 0;
const SECTION_HEADER: u8 = 1;
const SECTION_SHARD: u8 = 2;
const SECTION_SEGMENT: u8 = 3;
const SECTION_RECORDS: u8 = 4;
const SECTION_SIGNATURE: u8 = 5;
const SECTION_WITNESS: u8 = 6;
const SECTION_ANCHOR: u8 = 7;

/// A pack under construction.
#[derive(Debug)]
pub struct PackBuilder {
    tenant: TenantId,
    generated_at: Timestamp,
    signature: Option<RootSignature>,
    witnesses: Vec<WitnessAttestation>,
    anchors: Vec<AnchorPart>,
    shards: Vec<ShardPart>,
}

/// External evidence that a root existed by a time this store did not choose.
///
/// Three kinds, because `docs/planning/trailryx-plan.md` item 15 names three and
/// says the format is prepared for all of them from the start. The challenge is
/// stored because without it nobody can later show a timestamp token answers a
/// particular request rather than being a replay of an older one for the same
/// root: a root does not change between retries, so the challenge is the only
/// thing that distinguishes them, and a store that threw it away would be keeping
/// evidence it had made uncheckable.
#[derive(Debug, Clone)]
struct AnchorPart {
    kind: u8,
    authority: String,
    algorithm: String,
    root: Hash,
    challenge: Vec<u8>,
    evidence: Vec<u8>,
}

/// The anchor kinds, matching `trailryx_verify::pack::AnchorKind`.
///
/// Duplicated rather than shared, like every other constant in this writer: the
/// verifier depends on nothing, so the two sides agree by test and not by import.
pub const ANCHOR_TSP: u8 = 1;
pub const ANCHOR_TRANSPARENCY_LOG: u8 = 2;
pub const ANCHOR_SIGNED_ARTIFACT: u8 = 3;

#[derive(Debug)]
struct ShardPart {
    shard: u16,
    root: Hash,
    segments: Vec<(SegmentManifest, Vec<Vec<u8>>)>,
}

impl PackBuilder {
    pub fn new(tenant: TenantId, generated_at: Timestamp) -> Self {
        Self {
            tenant,
            generated_at,
            signature: None,
            witnesses: Vec::new(),
            anchors: Vec::new(),
            shards: Vec::new(),
        }
    }

    /// Attach the publisher's signature over the store root.
    ///
    /// Without one a pack proves it is self-consistent and not who published
    /// it, and the verifier reports exactly that rather than a clean bill.
    pub fn signed_with(mut self, signature: RootSignature) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Attach an independent attestation that the root existed at a time.
    ///
    /// This is the part a signature cannot supply. The publisher chooses the
    /// timestamp they sign, so nothing in their own signature rules out a
    /// history written today and dated last year. Somebody else saying they saw
    /// the root does.
    pub fn witnessed_by(mut self, attestation: WitnessAttestation) -> Self {
        self.witnesses.push(attestation);
        self
    }

    /// Add an RFC 3161 timestamp token obtained over a root.
    ///
    /// `root` is what the token was requested over, and it is stored rather than
    /// assumed to be the store root: the verifier compares the two and refuses an
    /// anchor over anything else. Passing the wrong one produces a pack that fails
    /// its own verification, which is the correct outcome.
    ///
    /// This crate does not obtain tokens. `trailryx-anchor` does, and it lives
    /// outside the verifier for the reason that crate documents.
    pub fn anchored_by(
        self,
        authority: impl Into<String>,
        root: Hash,
        nonce: u64,
        token: Vec<u8>,
    ) -> Self {
        // The nonce goes in as eight big-endian bytes, which is what the verifier
        // reads back and compares against the nonce inside the token.
        self.anchored(
            ANCHOR_TSP,
            authority,
            "",
            root,
            nonce.to_be_bytes().to_vec(),
            token,
        )
    }

    /// Add an anchor of any kind, including one this build's verifier cannot read.
    ///
    /// The general form. A transparency-log checkpoint and a signed build artifact
    /// are both anchors and neither is a timestamp token, so the shape has to take
    /// all three: the first version of this took a nonce and a token and could
    /// only ever have taken one of them.
    ///
    /// `algorithm` names the signature scheme for evidence that does not name its
    /// own. Empty for a timestamp token, which carries its own identifiers.
    pub fn anchored(
        mut self,
        kind: u8,
        authority: impl Into<String>,
        algorithm: impl Into<String>,
        root: Hash,
        challenge: Vec<u8>,
        evidence: Vec<u8>,
    ) -> Self {
        self.anchors.push(AnchorPart {
            kind,
            authority: authority.into(),
            algorithm: algorithm.into(),
            root,
            challenge,
            evidence,
        });
        self
    }

    /// Add a shard: its tree, and the sealed segments behind it, in order.
    ///
    /// The segments must be the ones the tree was built from, in the same
    /// order. Handing over a mismatched pair produces a pack that fails its own
    /// verification, which is the correct outcome and not a pleasant one to
    /// debug, so the two arrive together.
    pub fn shard(mut self, tree: &ShardTree, segments: &[&Segment]) -> Self {
        self.shards.push(ShardPart {
            shard: tree.shard().0,
            root: tree.root(),
            segments: segments
                .iter()
                .map(|s| {
                    (
                        s.manifest().clone(),
                        s.records().iter().map(encode_record).collect(),
                    )
                })
                .collect(),
        });
        self
    }

    pub fn build(self, store: &StoreTree) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);

        let algorithms = self
            .shards
            .first()
            .and_then(|s| s.segments.first())
            .map(|(m, _)| algorithm_code(m))
            .unwrap_or([1, 1, 1]);

        let mut header = Vec::new();
        put_str(&mut header, self.tenant.as_str());
        header.extend_from_slice(&self.generated_at.as_nanos().to_be_bytes());
        header.extend_from_slice(store.root().as_bytes());
        header.extend_from_slice(&(self.shards.len() as u32).to_be_bytes());
        header.extend_from_slice(&algorithms);
        section(&mut out, SECTION_HEADER, &header);

        if let Some(signature) = &self.signature {
            let mut body = Vec::new();
            put_str(&mut body, signature.algorithm.as_str());
            put_bytes(&mut body, &signature.public_key);
            put_bytes(&mut body, &signature.signature);
            section(&mut out, SECTION_SIGNATURE, &body);
        }

        for attestation in &self.witnesses {
            let mut body = Vec::new();
            put_str(&mut body, &attestation.witness);
            body.extend_from_slice(&attestation.seen_at.as_nanos().to_be_bytes());
            put_str(&mut body, attestation.algorithm.as_str());
            put_bytes(&mut body, &attestation.public_key);
            put_bytes(&mut body, &attestation.signature);
            section(&mut out, SECTION_WITNESS, &body);
        }

        for anchor in &self.anchors {
            let mut body = Vec::new();
            body.push(anchor.kind);
            put_str(&mut body, &anchor.authority);
            put_str(&mut body, &anchor.algorithm);
            body.extend_from_slice(anchor.root.as_bytes());
            put_bytes(&mut body, &anchor.challenge);
            put_bytes(&mut body, &anchor.evidence);
            section(&mut out, SECTION_ANCHOR, &body);
        }

        for shard in &self.shards {
            let mut body = Vec::new();
            body.extend_from_slice(&shard.shard.to_be_bytes());
            body.extend_from_slice(&(shard.segments.len() as u32).to_be_bytes());
            body.extend_from_slice(shard.root.as_bytes());
            section(&mut out, SECTION_SHARD, &body);
        }

        for shard in &self.shards {
            for (manifest, records) in &shard.segments {
                section(&mut out, SECTION_SEGMENT, &encode_manifest(manifest));

                let mut body = Vec::new();
                body.extend_from_slice(&manifest.shard.0.to_be_bytes());
                body.extend_from_slice(&manifest.segment.0.to_be_bytes());
                body.extend_from_slice(&(records.len() as u64).to_be_bytes());
                for record in records {
                    put_bytes(&mut body, record);
                }
                section(&mut out, SECTION_RECORDS, &body);
            }
        }

        out.push(SECTION_END);
        out
    }
}

fn section(out: &mut Vec<u8>, kind: u8, body: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&(body.len() as u64).to_be_bytes());
    out.extend_from_slice(body);
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

fn encode_manifest(m: &SegmentManifest) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&m.format_version.to_be_bytes());
    out.extend_from_slice(&m.segment.0.to_be_bytes());
    out.extend_from_slice(&m.shard.0.to_be_bytes());
    out.extend_from_slice(&m.records.to_be_bytes());
    out.extend_from_slice(m.history_root.as_bytes());
    out.extend_from_slice(m.chain_before.as_bytes());
    out.extend_from_slice(m.chain_after.as_bytes());
    out.extend_from_slice(&(m.index_roots.len() as u64).to_be_bytes());
    for (dimension, root) in &m.index_roots {
        put_str(&mut out, dimension.as_str());
        out.extend_from_slice(root.as_bytes());
    }
    out.extend_from_slice(&m.first_recorded_at.as_nanos().to_be_bytes());
    out.extend_from_slice(&m.last_recorded_at.as_nanos().to_be_bytes());
    out.extend_from_slice(&algorithm_code(m));
    out
}

/// The same three bytes the manifest root commits to.
///
/// Duplicated from the index crate rather than exposed from it: the pack is a
/// format, and a format that quietly follows an internal function changes
/// whenever that function does.
fn algorithm_code(m: &SegmentManifest) -> [u8; 3] {
    use trailryx_record::{HashAlg, KemAlg, SigAlg};
    [
        match m.algorithms.hash {
            HashAlg::Sha384 => 1,
        },
        match m.algorithms.signature {
            SigAlg::Es256 => 1,
            SigAlg::MlDsa65 => 2,
            SigAlg::SlhDsa => 3,
            SigAlg::Es384 => 4,
        },
        match m.algorithms.kem {
            KemAlg::X25519MlKem768 => 1,
        },
    ]
}
