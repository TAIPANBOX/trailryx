//! The declaration in `components.json` is only worth reading if this repository
//! proves it, and proves it against the toolchain rather than by describing.
//!
//! estate-gates cannot do this. It has no Rust toolchain, and building
//! twenty-two repositories in its CI is a matrix it does not have. This
//! repository already runs `cargo test --workspace` on every push.
//!
//! What is proved here is exactly the `checked` bucket and nothing else. The
//! `declared` bucket is not asserted against anything, on purpose: a test that
//! pretended to verify a sentence about purpose would be the failure this whole
//! design exists to avoid.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The repository root. `CARGO_MANIFEST_DIR` is `crates/trailryx-demo`.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/trailryx-demo has two ancestors")
        .to_path_buf()
}

fn manifest() -> Value {
    let path = root().join("components.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("components.json is valid JSON")
}

fn components(m: &Value) -> Vec<&Value> {
    let cs = m["components"].as_array().expect("components is an array");
    assert!(
        !cs.is_empty(),
        "components.json declares nothing, so every test here measured nothing"
    );
    cs.iter().collect()
}

fn binaries(workspace: &str) -> BTreeMap<String, String> {
    let manifest_path = root().join(workspace).join("Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("cargo metadata runs");
    assert!(
        out.status.success(),
        "cargo metadata for {}: {}",
        manifest_path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: Value = serde_json::from_slice(&out.stdout).expect("cargo metadata is JSON");
    let mut found = BTreeMap::new();
    for p in meta["packages"].as_array().expect("packages") {
        for t in p["targets"].as_array().expect("targets") {
            if t["kind"]
                .as_array()
                .expect("kind")
                .iter()
                .any(|k| k == "bin")
            {
                found.insert(
                    t["name"].as_str().expect("target name").to_string(),
                    p["name"].as_str().expect("package name").to_string(),
                );
            }
        }
    }
    found
}

/// THE ONE THAT CLOSES THE HOLE. Ten binaries here and estate.json names none of
/// them: its `runs` list carries two ROUTINE names. Only the repository can say
/// what it builds.
#[test]
fn every_binary_this_workspace_builds_is_declared_and_the_reverse() {
    let m = manifest();
    let comps = components(&m);

    let mut workspaces: BTreeSet<String> = BTreeSet::new();
    for c in &comps {
        workspaces.insert(
            c["checked"]["workspace"]
                .as_str()
                .unwrap_or_else(|| panic!("component {} declares no workspace", c["name"]))
                .to_string(),
        );
    }
    let mut built: BTreeMap<String, String> = BTreeMap::new();
    for w in &workspaces {
        built.extend(binaries(w));
    }
    assert!(
        !built.is_empty(),
        "cargo metadata found no binary in {workspaces:?}, so this measured nothing"
    );

    let declared: BTreeMap<String, String> = comps
        .iter()
        .filter_map(|c| {
            let b = c["checked"]["binary"].as_str()?;
            let k = c["checked"]["crate"].as_str()?;
            Some((b.to_string(), k.to_string()))
        })
        .collect();
    assert!(
        !declared.is_empty(),
        "no component declares a binary, so this measured nothing"
    );

    for b in built.keys() {
        assert!(
            declared.contains_key(b),
            "this workspace builds `{b}` and components.json does not declare it.\n\
             A component nobody declares is one nobody can ask about."
        );
    }
    for b in declared.keys() {
        assert!(
            built.contains_key(b),
            "components.json declares the binary `{b}` and no workspace builds it"
        );
    }
    // The crate each component names is the one that actually carries it. Four of
    // these binaries live in a crate whose name is not theirs.
    for (b, k) in &declared {
        assert_eq!(
            built.get(b),
            Some(k),
            "components.json says `{b}` comes from crate `{k}`; cargo says {:?}",
            built.get(b)
        );
    }
}

/// `dev-tool` is a promise about deployments, so it has to be spelled the same
/// way every time or the check that will read it later matches nothing.
///
/// The three classes here mean different things to whoever asks "why does no
/// deployment install this": for `service` and `tool` that is a question, and
/// for `dev-tool` it is the answer.
#[test]
fn every_component_carries_one_of_the_classes_this_estate_uses() {
    let m = manifest();
    let known = ["service", "tool", "daemon", "dev-tool"];
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for c in components(&m) {
        let class = c["checked"]["class"]
            .as_str()
            .or_else(|| c["class"].as_str())
            .unwrap_or_else(|| panic!("component {} declares no class", c["name"]));
        assert!(
            known.contains(&class),
            "component {} has class {class:?}, which is not one of {known:?}.\n\
             A class nothing recognises is a class no check can act on.",
            c["name"]
        );
        *seen.entry(class.to_string()).or_default() += 1;
    }
    // A repository of nothing but dev-tools would contribute nothing to a stack,
    // and this one contributes three things.
    assert!(
        seen.keys().any(|k| k != "dev-tool"),
        "every component here is a dev-tool, so this repository declares nothing installable"
    );
}

/// Every declared subcommand is one the binary actually dispatches on.
#[test]
fn every_declared_subcommand_is_one_the_binary_dispatches_on() {
    let m = manifest();
    let main = std::fs::read_to_string(root().join("crates/trailryx-node/src/main.rs"))
        .expect("reading trailryx-node's main.rs");

    let mut checked = 0;
    for c in components(&m) {
        let Some(subs) = c["checked"]["subcommands"].as_array() else {
            continue;
        };
        for s in subs {
            let s = s.as_str().expect("a subcommand is a string");
            checked += 1;
            assert!(
                main.contains(&format!("\"{s}\"")),
                "components.json says {} takes `{s}` and its main.rs never mentions it",
                c["name"]
            );
        }
    }
    assert!(
        checked > 0,
        "no component declares a subcommand, so this measured nothing"
    );
}

/// The declared listen default is the address the receiver actually falls back
/// to, read from the constant rather than from its own help text.
#[test]
fn the_declared_listen_default_is_the_one_the_code_uses() {
    let m = manifest();
    let cfg = std::fs::read_to_string(root().join("crates/trailryx-ingest/src/config.rs"))
        .expect("reading trailryx-ingest's config.rs");

    let mut checked = 0;
    for c in components(&m) {
        let Some(want) = c["checked"]["listen_default"].as_str() else {
            continue;
        };
        checked += 1;
        let (host, port) = want.rsplit_once(':').expect("an address:port");
        assert_eq!(
            host, "127.0.0.1",
            "only the loopback default is checked here"
        );
        assert!(
            cfg.contains(&format!("Ipv4Addr::LOCALHOST), {port})")),
            "components.json says {} listens on {want} by default and config.rs \
             does not build that address",
            c["name"]
        );
    }
    assert!(
        checked > 0,
        "no component declares a listen default, so this measured nothing"
    );
}

/// Every `TRAILRYX_` name in non-test source, against every one declared.
///
/// TRAILRYX_TRUST_DOMAIN is deliberately absent: stack-k8s sets it in a
/// ConfigMap and interpolates it into a `--trust-domain` argument, and no code
/// here reads it. It is the deployment's variable, and this check is what keeps
/// it out.
#[test]
fn every_environment_variable_this_repository_reads_is_declared_and_the_reverse() {
    let m = manifest();
    let mut declared: BTreeSet<String> = BTreeSet::new();
    for c in components(&m) {
        if let Some(env) = c["checked"]["env"].as_object() {
            declared.extend(env.keys().cloned());
        }
    }
    assert!(
        !declared.is_empty(),
        "no component declares an environment variable, so this measured nothing"
    );

    let mut in_source: BTreeSet<String> = BTreeSet::new();
    walk(&root(), &mut |p: &Path| {
        let s = p.to_string_lossy();
        if !s.ends_with(".rs") || s.contains("/target/") || s.contains("/tests/") {
            return;
        }
        let Ok(body) = std::fs::read_to_string(p) else {
            return;
        };
        for n in names_in(&body) {
            if !n.ends_with('_') {
                in_source.insert(n);
            }
        }
    });
    assert!(
        !in_source.is_empty(),
        "no TRAILRYX_ name found in any non-test .rs file, so this measured nothing"
    );

    let missing: Vec<_> = in_source.difference(&declared).cloned().collect();
    let extra: Vec<_> = declared.difference(&in_source).cloned().collect();
    assert!(
        missing.is_empty(),
        "the code reads these and components.json declares none of them: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "components.json declares these and no non-test source reads them: {extra:?}"
    );
}

fn names_in(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let needle = b"TRAILRYX_";
    let mut out = Vec::new();
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            while j < bytes.len()
                && (bytes[j].is_ascii_uppercase() || bytes[j].is_ascii_digit() || bytes[j] == b'_')
            {
                j += 1;
            }
            out.push(String::from_utf8_lossy(&bytes[i..j]).into_owned());
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn walk(dir: &Path, f: &mut impl FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if p.is_dir() {
            if name == "target" || name == ".git" {
                continue;
            }
            walk(&p, f);
        } else {
            f(&p);
        }
    }
}
