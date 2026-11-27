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
    from_settings(&|name| std::env::var(name).ok())
}

/// The same choice, from whatever answers for the environment. A variable that is
/// unset and one that is not unicode both answer `None`, as they always did.
fn from_settings(var: &dyn Fn(&str) -> Option<String>) -> Result<Chosen, String> {
    match var("TRAILRYX_DEMO_STORE").as_deref() {
        None | Some("") | Some("memory") => Ok(Chosen::default()),
        Some("s3") => s3(Flavour::Aws, var),
        Some("gcs") => s3(Flavour::Gcs, var),
        Some("azure") => azure(var),
        Some(other) => Err(format!(
            "TRAILRYX_DEMO_STORE={other} is not a store this run knows: \
             memory, s3, gcs or azure"
        )),
    }
}

use trailryx_s3::Flavour;

fn need(var: &dyn Fn(&str) -> Option<String>, name: &str) -> Result<String, String> {
    var(name).ok_or_else(|| format!("{name} is not set"))
}

fn s3(flavour: Flavour, var: &dyn Fn(&str) -> Option<String>) -> Result<Chosen, String> {
    let endpoint = need(var, "TRAILRYX_S3_ENDPOINT")?;
    let bucket = need(var, "TRAILRYX_S3_BUCKET")?;
    let region = var("TRAILRYX_S3_REGION").unwrap_or_else(|| "us-east-1".to_owned());
    let addressing = match var("TRAILRYX_S3_ADDRESSING").as_deref() {
        Some("virtual") => trailryx_s3::Addressing::VirtualHosted,
        _ => trailryx_s3::Addressing::Path,
    };
    let store = trailryx_s3::S3::new(
        &endpoint,
        bucket.clone(),
        region,
        trailryx_s3::Credentials::new(
            need(var, "TRAILRYX_S3_KEY")?,
            need(var, "TRAILRYX_S3_SECRET")?,
        ),
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

fn azure(var: &dyn Fn(&str) -> Option<String>) -> Result<Chosen, String> {
    let endpoint = need(var, "TRAILRYX_AZURE_ENDPOINT")?;
    let container = need(var, "TRAILRYX_AZURE_CONTAINER")?;
    let account = need(var, "TRAILRYX_AZURE_ACCOUNT")?;
    let credentials = trailryx_azure::Credentials::new(account, &need(var, "TRAILRYX_AZURE_KEY")?)
        .ok_or("TRAILRYX_AZURE_KEY is not base64")?;
    let store = trailryx_azure::Azure::new(&endpoint, container.clone(), credentials)
        .map_err(|e| e.to_string())?;
    Ok(Chosen {
        inner: Box::new(store),
        described: format!("Azure Blob Storage at {endpoint}, container {container}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An environment of exactly these variables and no others.
    fn settings(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name: &str| {
            owned
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
    }

    fn chosen(pairs: &[(&str, &str)]) -> Result<String, String> {
        from_settings(&settings(pairs)).map(|c| c.describe().to_owned())
    }

    const S3: &[(&str, &str)] = &[
        ("TRAILRYX_S3_ENDPOINT", "http://127.0.0.1:9000"),
        ("TRAILRYX_S3_BUCKET", "evidence"),
        ("TRAILRYX_S3_KEY", "AKIDEXAMPLE"),
        ("TRAILRYX_S3_SECRET", "wJalrXUtnFEMI"),
    ];

    #[test]
    fn unset_empty_and_memory_all_mean_memory() {
        assert_eq!(chosen(&[]), Ok("in memory".to_owned()));
        assert_eq!(
            chosen(&[("TRAILRYX_DEMO_STORE", "")]),
            Ok("in memory".to_owned())
        );
        assert_eq!(
            chosen(&[("TRAILRYX_DEMO_STORE", "memory")]),
            Ok("in memory".to_owned())
        );
    }

    #[test]
    fn a_store_this_run_does_not_know_is_refused_rather_than_read_as_memory() {
        assert_eq!(
            chosen(&[("TRAILRYX_DEMO_STORE", "floppy")]),
            Err("TRAILRYX_DEMO_STORE=floppy is not a store this run knows: \
                 memory, s3, gcs or azure"
                .to_owned())
        );
    }

    #[test]
    fn s3_and_gcs_are_the_same_client_named_for_the_cloud_they_reach() {
        let mut aws = S3.to_vec();
        aws.push(("TRAILRYX_DEMO_STORE", "s3"));
        assert_eq!(
            chosen(&aws),
            Ok("S3 at http://127.0.0.1:9000, bucket evidence".to_owned())
        );
        let mut gcs = S3.to_vec();
        gcs.push(("TRAILRYX_DEMO_STORE", "gcs"));
        gcs.push(("TRAILRYX_S3_ADDRESSING", "virtual"));
        assert_eq!(
            chosen(&gcs),
            Ok("Google Cloud Storage at http://127.0.0.1:9000, bucket evidence".to_owned())
        );
    }

    #[test]
    fn every_s3_setting_without_a_default_is_named_when_it_is_missing() {
        for missing in [
            "TRAILRYX_S3_ENDPOINT",
            "TRAILRYX_S3_BUCKET",
            "TRAILRYX_S3_KEY",
            "TRAILRYX_S3_SECRET",
        ] {
            let mut pairs: Vec<(&str, &str)> =
                S3.iter().copied().filter(|(k, _)| *k != missing).collect();
            pairs.push(("TRAILRYX_DEMO_STORE", "s3"));
            assert_eq!(chosen(&pairs), Err(format!("{missing} is not set")));
        }
    }

    #[test]
    fn azure_names_a_missing_setting_and_refuses_a_key_that_is_not_base64() {
        let complete = [
            ("TRAILRYX_DEMO_STORE", "azure"),
            ("TRAILRYX_AZURE_ENDPOINT", "http://127.0.0.1:10000"),
            ("TRAILRYX_AZURE_CONTAINER", "evidence"),
            ("TRAILRYX_AZURE_ACCOUNT", "devstoreaccount1"),
            ("TRAILRYX_AZURE_KEY", "a2V5"),
        ];
        assert_eq!(
            chosen(&complete),
            Ok("Azure Blob Storage at http://127.0.0.1:10000, container evidence".to_owned())
        );
        let mut bad_key = complete;
        bad_key[4] = ("TRAILRYX_AZURE_KEY", "not base64!");
        assert_eq!(
            chosen(&bad_key),
            Err("TRAILRYX_AZURE_KEY is not base64".to_owned())
        );
        assert_eq!(
            chosen(&complete[..2]),
            Err("TRAILRYX_AZURE_CONTAINER is not set".to_owned())
        );
    }

    #[test]
    fn the_chosen_store_passes_every_call_through() {
        let mut store = Chosen::default();
        assert_eq!(
            store.put_if_absent("segments/1", b"one"),
            Ok((PutOutcome::Written, None)),
            "memory writes and offers no version"
        );
        assert_eq!(
            store.put_if_absent("segments/1", b"two"),
            Ok((PutOutcome::AlreadyExists, None)),
            "a conditional write does not replace"
        );
        assert_eq!(store.get("segments/1"), Ok(Some(b"one".to_vec())));
        assert_eq!(store.get("segments/2"), Ok(None));
        assert!(
            store
                .get_version("segments/1", &VersionId("1".to_owned()))
                .is_err(),
            "a store with no versions refuses a versioned read rather than guessing"
        );
        assert_eq!(store.list("segments/"), Ok(vec!["segments/1".to_owned()]));
        assert_eq!(store.list("payload/"), Ok(Vec::new()));
    }
}
