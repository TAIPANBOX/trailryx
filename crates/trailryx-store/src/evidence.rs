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

pub const MAGIC: &[u8; 7] = b"TRXEVID";
pub const VERSION: u8 = 1;

const SECTION_END: u8 = 0;
const SECTION_HEADER: u8 = 1;
const SECTION_SHARD: u8 = 2;
const SECTION_SEGMENT: u8 = 3;
const SECTION_RECORDS: u8 = 4;

/// A pack under construction.
#[derive(Debug)]
pub struct PackBuilder {
    tenant: TenantId,
    generated_at: Timestamp,
    signature: Vec<u8>,
    shards: Vec<ShardPart>,
}

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
            signature: Vec::new(),
            shards: Vec::new(),
        }
    }

    /// Attach a signature over the store root.
    ///
    /// Without one a pack proves it is self-consistent and not who published
    /// it, and the verifier reports exactly that rather than a clean bill.
    pub fn signed_with(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
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
        put_bytes(&mut header, &self.signature);
        section(&mut out, SECTION_HEADER, &header);

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
        },
        match m.algorithms.kem {
            KemAlg::X25519MlKem768 => 1,
        },
    ]
}
