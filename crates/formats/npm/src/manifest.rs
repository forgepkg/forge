//! Version manifests: the object a packument lists under `versions`.
//!
//! Forge stores two forms of a version's manifest:
//!
//! * the **manifest** as published (the version object of the publish
//!   document, or of the upstream packument), README included, as the
//!   version's `package.json` asset;
//! * its **summary** ([`summary`]), the manifest without its README, as the
//!   version's manifest summary, with the dependencies as the web UI's
//!   package page reads them ([`DEPENDENCY_GROUPS`]). Every packument is
//!   rendered from the summaries alone, one query for every version.
//!
//! A version deprecated with `npm deprecate` keeps its summary: Forge
//! stores the message beside it, and it wins over the summary's own
//! `deprecated` (an upstream's).

use serde_json::{json, Map, Value};

/// The key of a summary holding the version's dependencies in the shape the
/// web UI's package page reads (`[{"target_framework", "dependencies":
/// [{"id", "range"}]}]`, a group per dependency kind). Packuments leave it
/// out.
pub const DEPENDENCY_GROUPS: &str = "dependency_groups";

/// The kinds of dependencies that install with a version, in the order the
/// web UI lists them.
pub const DEPENDENCY_KINDS: &[&str] = &["dependencies", "optionalDependencies", "peerDependencies"];

/// A manifest's dependencies, `(kind, [(name, range)])` for each kind of
/// [`DEPENDENCY_KINDS`] it has.
pub fn dependencies(manifest: &Map<String, Value>) -> Vec<(String, Vec<(String, String)>)> {
    DEPENDENCY_KINDS
        .iter()
        .filter_map(|kind| {
            let deps: Vec<(String, String)> = manifest
                .get(*kind)?
                .as_object()?
                .iter()
                .map(|(name, range)| (name.clone(), range.as_str().unwrap_or_default().to_string()))
                .collect();
            (!deps.is_empty()).then(|| (kind.to_string(), deps))
        })
        .collect()
}

/// The fields of a version an install needs: what the abbreviated
/// metadata (`application/vnd.npm.install-v1+json`) carries of it.
pub const ABBREVIATED_FIELDS: &[&str] = &[
    "name",
    "version",
    "deprecated",
    "dependencies",
    "optionalDependencies",
    "devDependencies",
    "bundleDependencies",
    "bundledDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "bin",
    "directories",
    "dist",
    "engines",
    "_hasShrinkwrap",
    "hasInstallScript",
    "cpu",
    "os",
    "libc",
];

/// Fields a summary drops: the README, which the packument carries once,
/// at the top.
const UNSUMMARIZED: &[&str] = &["readme", "readmeFilename"];

/// The largest summary kept whole. A larger one keeps the fields an
/// install needs and the small display fields only.
pub const MAX_SUMMARY_BYTES: usize = 256 * 1024;

/// Display fields kept in a cut-down summary, besides [`ABBREVIATED_FIELDS`].
const DISPLAY_FIELDS: &[&str] = &[
    "_id",
    "description",
    "license",
    "homepage",
    "repository",
    "bugs",
    "author",
    "keywords",
    "maintainers",
    "_npmUser",
    "gitHead",
    "type",
    "main",
];

/// Whether a summary keeps the manifest's field `key`.
fn summarized(key: &str) -> bool {
    !UNSUMMARIZED.contains(&key) && key != DEPENDENCY_GROUPS
}

/// The summary of a version manifest: see the module documentation.
pub fn summary(manifest: &Map<String, Value>) -> Map<String, Value> {
    into_summary(
        manifest
            .iter()
            .filter(|(key, _)| summarized(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

/// [`summary`] of a manifest the caller is done with, without a copy.
pub fn into_summary(mut out: Map<String, Value>) -> Map<String, Value> {
    out.retain(|key, _| summarized(key));
    if serde_json::to_vec(&out).map_or(0, |v| v.len()) > MAX_SUMMARY_BYTES {
        out.retain(|key, _| {
            ABBREVIATED_FIELDS.contains(&key.as_str()) || DISPLAY_FIELDS.contains(&key.as_str())
        });
        if let Some(Value::String(description)) = out.get_mut("description") {
            truncate(description, 1024);
        }
        for key in DISPLAY_FIELDS {
            if out
                .get(*key)
                .is_some_and(|v| serde_json::to_vec(v).map_or(0, |v| v.len()) > 16 * 1024)
            {
                out.remove(*key);
            }
        }
    }
    let groups: Vec<Value> = dependencies(&out)
        .into_iter()
        .map(|(kind, deps)| {
            json!({
                "target_framework": kind,
                "dependencies": deps
                    .into_iter()
                    .map(|(id, range)| json!({"id": id, "range": range}))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    if !groups.is_empty() {
        out.insert(DEPENDENCY_GROUPS.into(), Value::Array(groups));
    }
    out
}

/// A summary as a packument lists it: without what Forge keeps for itself
/// ([`DEPENDENCY_GROUPS`]).
pub fn served(summary: &Map<String, Value>) -> Map<String, Value> {
    let mut out = summary.clone();
    out.remove(DEPENDENCY_GROUPS);
    out
}

/// Cut `s` to at most `max` bytes, at a character boundary.
pub fn truncate(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

/// The abbreviated form of a summary.
pub fn abbreviated(summary: &Map<String, Value>) -> Map<String, Value> {
    ABBREVIATED_FIELDS
        .iter()
        .filter_map(|key| summary.get(*key).map(|v| (key.to_string(), v.clone())))
        .collect()
}

/// Whether a manifest runs an install script: what the registry reports as
/// `hasInstallScript`, so that installers know before they unpack it.
pub fn has_install_script(manifest: &Map<String, Value>) -> bool {
    let scripts = manifest.get("scripts").and_then(Value::as_object);
    ["preinstall", "install", "postinstall"]
        .iter()
        .any(|s| scripts.is_some_and(|scripts| scripts.contains_key(*s)))
        || manifest.get("gypfile").and_then(Value::as_bool) == Some(true)
}

/// The `deprecated` message of a summary, if the version is deprecated (an
/// empty message is none).
pub fn deprecation(summary: &Map<String, Value>) -> Option<&str> {
    summary
        .get("deprecated")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn object(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn summaries_drop_the_readme() {
        let m = object(json!({
            "name": "a", "version": "1.0.0", "readme": "# A", "readmeFilename": "README.md",
            "dependencies": {"b": "^1"}, "scripts": {"test": "x"}
        }));
        let s = summary(&m);
        assert!(!s.contains_key("readme") && !s.contains_key("readmeFilename"));
        assert_eq!(s["scripts"], json!({"test": "x"}));
        let a = abbreviated(&s);
        assert_eq!(
            a,
            object(json!({"name": "a", "version": "1.0.0", "dependencies": {"b": "^1"}}))
        );
    }

    #[test]
    fn a_huge_manifest_keeps_what_installs_need() {
        let m = object(json!({
            "name": "a", "version": "1.0.0",
            "description": "x".repeat(400_000),
            "jsii": {"huge": "y".repeat(400_000)},
            "dependencies": {"b": "^1"},
            "repository": {"url": "z".repeat(20_000)},
        }));
        let s = summary(&m);
        assert!(serde_json::to_vec(&s).unwrap().len() < MAX_SUMMARY_BYTES);
        assert_eq!(s["dependencies"], json!({"b": "^1"}));
        assert_eq!(s["description"].as_str().unwrap().len(), 1024);
        assert!(!s.contains_key("jsii") && !s.contains_key("repository"));
    }

    #[test]
    fn install_scripts_and_deprecation() {
        assert!(has_install_script(&object(
            json!({"scripts": {"postinstall": "x"}})
        )));
        assert!(has_install_script(&object(json!({"gypfile": true}))));
        assert!(!has_install_script(&object(
            json!({"scripts": {"test": "x"}})
        )));
        assert_eq!(
            deprecation(&object(json!({"deprecated": "use b"}))),
            Some("use b")
        );
        assert_eq!(deprecation(&object(json!({"deprecated": ""}))), None);
        let mut s = "héllo".to_string();
        truncate(&mut s, 2);
        assert_eq!(s, "h");
    }
}
