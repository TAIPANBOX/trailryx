//! Which object store the acceptance run publishes to.
//!
//! # Why the demo grew this
//!
//! Stage 13 asks for a **multi-cloud demo run, twice in a row from nothing**. The
//! eight steps ran twice from an empty directory and always into memory, so the
//! criterion was not met, and nothing said so: `VALIDATION.md` listed the things
//! that had not been measured and this was not among them, which made it read as
//! done. It is the same failure the rest of that file exists to prevent, found in
//! the file itself.
//!
//! # What this is and is not
//!
//! It is a store chosen at startup, so the same eight steps run against memory, an
//! S3-compatible endpoint, a GCS bucket, or Azure Blob Storage without the steps
//! knowing which. It is not a deployment feature: production wiring belongs to
//! whatever assembles a node, and this exists so an acceptance run can be pointed at
//! a real endpoint and say what it was pointed at.
//!
//! The credentials come from the environment and never from a flag, because a
//! secret on a command line is a secret in every shell history and process list on
//! the machine.

use trailryx_contracts::contracts::{AdapterResult, ObjectStore, PutOutcome, VersionId};
use trailryx_contracts::fakes::MemoryObjectStore;

/// One store, whichever it is.
///
/// A boxed trait object rather than making the whole run generic: the vault is
/// already generic over four parameters, and threading a fifth choice through every
/// step's signature would put the demo's plumbing in front of what the demo shows.
/// One virtual call per object write is not what an acceptance run is measuring.
pub struct Chosen {
    inner: Box<dyn ObjectStore + Send>,
    /// What to print, so a run that passed against a real bucket cannot be
    /// mistaken later for a run that passed against memory.
    described: String,
}

impl Chosen {
    pub fn describe(&self) -> &str {
        &self.described
    }
}

impl Default for Chosen {
    fn default() -> Self {
        Self {
            inner: Box::new(MemoryObjectStore::default()),
            described: "in memory".to_owned(),
        }
    }
}

impl ObjectStore for Chosen {
    fn put_if_absent(
        &mut self,
        key: &str,
        bytes: &[u8],
    ) -> AdapterResult<(PutOutcome, Option<VersionId>)> {
        self.inner.put_if_absent(key, bytes)
    }

    fn get(&mut self, key: &str) -> AdapterResult<Option<Vec<u8>>> {
        self.inner.get(key)
    }

    fn get_version(&mut self, key: &str, version: &VersionId) -> AdapterResult<Option<Vec<u8>>> {
        self.inner.get_version(key, version)
    }

    fn list(&mut self, prefix: &str) -> AdapterResult<Vec<String>> {
        self.inner.list(prefix)
    }
}

/// Read `TRAILRYX_DEMO_STORE` and build what it names.
///
/// Anything other than a recognised name is an error rather than a fallback to
/// memory: a run that was asked for a cloud and quietly used memory would print
/// eight passing steps about nothing.
pub fn from_environment() -> Result<Chosen, String> {
    match std::env::var("TRAILRYX_DEMO_STORE").as_deref() {
        Err(_) | Ok("") | Ok("memory") => Ok(Chosen::default()),
        Ok("s3") => s3(Flavour::Aws),
        Ok("gcs") => s3(Flavour::Gcs),
        Ok("azure") => azure(),
        Ok(other) => Err(format!(
            "TRAILRYX_DEMO_STORE={other} is not a store this run knows: \
             memory, s3, gcs or azure"
        )),
    }
}

use trailryx_s3::Flavour;

fn need(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn s3(flavour: Flavour) -> Result<Chosen, String> {
    let endpoint = need("TRAILRYX_S3_ENDPOINT")?;
    let bucket = need("TRAILRYX_S3_BUCKET")?;
    let region = std::env::var("TRAILRYX_S3_REGION").unwrap_or_else(|_| "us-east-1".to_owned());
    let addressing = match std::env::var("TRAILRYX_S3_ADDRESSING").as_deref() {
        Ok("virtual") => trailryx_s3::Addressing::VirtualHosted,
        _ => trailryx_s3::Addressing::Path,
    };
    let store = trailryx_s3::S3::new(
        &endpoint,
        bucket.clone(),
        region,
        trailryx_s3::Credentials::new(need("TRAILRYX_S3_KEY")?, need("TRAILRYX_S3_SECRET")?),
        addressing,
        // The acceptance run publishes segments, and publishing without a
        // conditional write is the one thing this project refuses to do quietly.
        trailryx_s3::Conditional::IfNoneMatchStar,
    )
    .map_err(|e| e.to_string())?
    .with_flavour(flavour);
    let cloud = match flavour {
        Flavour::Aws => "S3",
        Flavour::Gcs => "Google Cloud Storage",
    };
    Ok(Chosen {
        inner: Box::new(store),
        described: format!("{cloud} at {endpoint}, bucket {bucket}"),
    })
}

fn azure() -> Result<Chosen, String> {
    let endpoint = need("TRAILRYX_AZURE_ENDPOINT")?;
    let container = need("TRAILRYX_AZURE_CONTAINER")?;
    let account = need("TRAILRYX_AZURE_ACCOUNT")?;
    let credentials = trailryx_azure::Credentials::new(account, &need("TRAILRYX_AZURE_KEY")?)
        .ok_or("TRAILRYX_AZURE_KEY is not base64")?;
    let store = trailryx_azure::Azure::new(&endpoint, container.clone(), credentials)
        .map_err(|e| e.to_string())?;
    Ok(Chosen {
        inner: Box::new(store),
        described: format!("Azure Blob Storage at {endpoint}, container {container}"),
    })
}
