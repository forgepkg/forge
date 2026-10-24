//! Packuments: the package documents an npm client reads.
//!
//! A [`Packument`] is what a repository knows of a package (its versions'
//! summaries, its dist-tags, the latest README); [`Packument::render`]
//! writes it as the full document (`application/json`) or as the
//! abbreviated metadata installs ask for
//! (`application/vnd.npm.install-v1+json`). Every `dist.tarball` points at
//! the repository the packument is served from, never upstream.

use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Map, Value};

use crate::manifest;
use crate::name::PackageName;
use crate::version;

/// The media type of abbreviated metadata.
pub const ABBREVIATED_MEDIA_TYPE: &str = "application/vnd.npm.install-v1+json";

/// The dist-tag every package has, unless it has no version.
pub const LATEST: &str = "latest";

/// One version of a packument.
#[derive(Debug, Clone, PartialEq)]
pub struct PackumentVersion {
    /// The version, normalized.
    pub version: String,
    /// Its manifest summary ([`manifest::summary`]).
    pub summary: Map<String, Value>,
    /// When it was published, if known.
    pub published: Option<DateTime<Utc>>,
}

/// What a repository knows of a package.
#[derive(Debug, Clone, PartialEq)]
pub struct Packument {
    pub name: PackageName,
    /// In any order.
    pub versions: Vec<PackumentVersion>,
    pub dist_tags: BTreeMap<String, String>,
    /// The README of the latest version.
    pub readme: Option<String>,
}

/// The URL of a version's tarball in the repository at `base` (no trailing
/// slash): `{base}/{name}/-/{name without scope}-{version}.tgz`, as the npm
/// registry writes it.
pub fn tarball_url(base: &str, name: &PackageName, version: &str) -> String {
    format!("{base}/{name}/-/{}", name.tarball_file(version))
}

/// The time format of a packument's `time`: RFC 3339 in UTC with
/// milliseconds.
pub fn timestamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// The version `latest` defaults to: the highest stable version, else the
/// highest.
pub fn default_latest<'a>(versions: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let mut all: Vec<&str> = versions.collect();
    all.sort_by(|a, b| version::compare(a, b));
    all.iter()
        .rev()
        .find(|v| !version::is_prerelease(v))
        .or(all.last())
        .copied()
}

/// `tags` without the ones naming a version not in `versions`, and with a
/// `latest` whenever there is a version: the default one if `latest` was
/// missing or named a version that is gone.
pub fn heal_dist_tags(
    tags: &BTreeMap<String, String>,
    versions: &[&str],
) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = tags
        .iter()
        .filter(|(_, v)| versions.contains(&v.as_str()))
        .map(|(t, v)| (t.clone(), v.clone()))
        .collect();
    if !out.contains_key(LATEST) {
        if let Some(latest) = default_latest(versions.iter().copied()) {
            out.insert(LATEST.to_string(), latest.to_string());
        }
    }
    out
}

impl Packument {
    /// The versions in ascending precedence.
    fn sorted(&self) -> Vec<&PackumentVersion> {
        let mut versions: Vec<&PackumentVersion> = self.versions.iter().collect();
        versions.sort_by(|a, b| version::compare(&a.version, &b.version));
        versions
    }

    /// The dist-tags as served: see [`heal_dist_tags`].
    pub fn served_dist_tags(&self) -> BTreeMap<String, String> {
        let versions: Vec<&str> = self.versions.iter().map(|v| v.version.as_str()).collect();
        heal_dist_tags(&self.dist_tags, &versions)
    }

    /// When the package last changed: its newest version's publish time.
    pub fn modified(&self) -> Option<DateTime<Utc>> {
        self.versions.iter().filter_map(|v| v.published).max()
    }

    /// A revision for clients that send one back (`npm unpublish`): it is
    /// not checked.
    pub fn rev(&self) -> String {
        let stamp = self.modified().map_or(0, |t| t.timestamp_millis());
        format!("{}-{stamp:x}", self.versions.len())
    }

    /// The summary of a version with its `dist.tarball` pointing at `base`.
    fn served_summary(&self, base: &str, v: &PackumentVersion) -> Map<String, Value> {
        let mut summary = manifest::served(&v.summary);
        let url = tarball_url(base, &self.name, &v.version);
        match summary.get_mut("dist").and_then(Value::as_object_mut) {
            Some(dist) => {
                dist.insert("tarball".into(), Value::String(url));
            }
            None => {
                summary.insert("dist".into(), json!({ "tarball": url }));
            }
        }
        summary.insert("name".into(), Value::String(self.name.to_string()));
        summary.insert("version".into(), Value::String(v.version.clone()));
        summary
    }

    /// One version's object (`GET /<package>/<version>`), with its
    /// tarball at `base`.
    pub fn render_version(&self, base: &str, version: &str) -> Option<Value> {
        let v = self.versions.iter().find(|v| v.version == version)?;
        Some(Value::Object(self.served_summary(base, v)))
    }

    /// The document, full or `abbreviated`, with tarballs at `base`.
    pub fn render(&self, base: &str, abbreviated: bool) -> Value {
        let versions = self.sorted();
        let tags = self.served_dist_tags();
        let modified = self.modified();
        let mut rendered = Map::new();
        for v in &versions {
            let summary = self.served_summary(base, v);
            let summary = if abbreviated {
                manifest::abbreviated(&summary)
            } else {
                summary
            };
            rendered.insert(v.version.clone(), Value::Object(summary));
        }
        let name = self.name.to_string();
        if abbreviated {
            let mut doc = Map::new();
            doc.insert("name".into(), Value::String(name));
            if let Some(modified) = modified {
                doc.insert("modified".into(), Value::String(timestamp(modified)));
            }
            doc.insert("dist-tags".into(), json!(tags));
            doc.insert("versions".into(), Value::Object(rendered));
            return Value::Object(doc);
        }
        let mut time = Map::new();
        if let Some(created) = versions.iter().filter_map(|v| v.published).min() {
            time.insert("created".into(), Value::String(timestamp(created)));
        }
        if let Some(modified) = modified {
            time.insert("modified".into(), Value::String(timestamp(modified)));
        }
        for v in &versions {
            if let Some(published) = v.published {
                time.insert(v.version.clone(), Value::String(timestamp(published)));
            }
        }
        let mut doc = Map::new();
        doc.insert("_id".into(), Value::String(name.clone()));
        doc.insert("_rev".into(), Value::String(self.rev()));
        doc.insert("name".into(), Value::String(name));
        // The display fields of the package are its latest version's.
        let latest = tags
            .get(LATEST)
            .and_then(|l| versions.iter().find(|v| &v.version == l));
        if let Some(latest) = latest {
            for key in [
                "description",
                "keywords",
                "license",
                "homepage",
                "repository",
                "bugs",
                "author",
                "maintainers",
            ] {
                if let Some(value) = latest.summary.get(key) {
                    doc.insert(key.into(), value.clone());
                }
            }
        }
        doc.insert("dist-tags".into(), json!(tags));
        doc.insert("versions".into(), Value::Object(rendered));
        doc.insert("time".into(), Value::Object(time));
        if let Some(readme) = &self.readme {
            doc.insert("readme".into(), Value::String(readme.clone()));
        }
        Value::Object(doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn version(v: &str, day: u32) -> PackumentVersion {
        PackumentVersion {
            version: v.to_string(),
            summary: json!({
                "name": "@acme/a", "version": v, "description": format!("v{v}"),
                "dependencies": {"b": "^1"}, "scripts": {"test": "x"},
                "dist": {"integrity": "sha512-x", "shasum": "ab", "tarball": "https://upstream/x.tgz"}
            })
            .as_object()
            .unwrap()
            .clone(),
            published: Some(Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap()),
        }
    }

    fn packument() -> Packument {
        Packument {
            name: PackageName::parse("@acme/a").unwrap(),
            versions: vec![
                version("1.10.0", 3),
                version("1.2.0", 1),
                version("2.0.0-rc.1", 4),
            ],
            dist_tags: BTreeMap::from([
                ("next".to_string(), "2.0.0-rc.1".to_string()),
                ("gone".to_string(), "0.1.0".to_string()),
            ]),
            readme: Some("# A".into()),
        }
    }

    #[test]
    fn renders_the_abbreviated_metadata() {
        let doc = packument().render("https://forge/repository/r", true);
        assert_eq!(doc["name"], "@acme/a");
        assert_eq!(doc["modified"], "2026-01-04T00:00:00.000Z");
        assert_eq!(
            doc["dist-tags"],
            json!({"latest": "1.10.0", "next": "2.0.0-rc.1"})
        );
        let v = &doc["versions"]["1.2.0"];
        assert_eq!(
            v["dist"]["tarball"],
            "https://forge/repository/r/@acme/a/-/a-1.2.0.tgz"
        );
        assert_eq!(v["dist"]["integrity"], "sha512-x");
        assert_eq!(v["dependencies"], json!({"b": "^1"}));
        assert!(v.get("scripts").is_none() && v.get("description").is_none());
        assert!(doc.get("time").is_none() && doc.get("readme").is_none());
        let keys: Vec<&String> = doc["versions"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["1.10.0", "1.2.0", "2.0.0-rc.1"]);
    }

    #[test]
    fn renders_the_full_document() {
        let doc = packument().render("https://forge/repository/r", false);
        assert_eq!(doc["_id"], "@acme/a");
        assert_eq!(doc["description"], "v1.10.0");
        assert_eq!(doc["readme"], "# A");
        assert_eq!(doc["time"]["created"], "2026-01-01T00:00:00.000Z");
        assert_eq!(doc["time"]["1.10.0"], "2026-01-03T00:00:00.000Z");
        assert_eq!(doc["versions"]["1.10.0"]["scripts"], json!({"test": "x"}));
        assert!(doc["_rev"].as_str().unwrap().starts_with("3-"));
    }

    #[test]
    fn heals_dist_tags() {
        let tags = BTreeMap::from([("latest".to_string(), "9.9.9".to_string())]);
        assert_eq!(
            heal_dist_tags(&tags, &["1.0.0", "2.0.0-rc.1"]),
            BTreeMap::from([("latest".to_string(), "1.0.0".to_string())])
        );
        assert_eq!(
            heal_dist_tags(&BTreeMap::new(), &["2.0.0-rc.1"]),
            BTreeMap::from([("latest".to_string(), "2.0.0-rc.1".to_string())])
        );
        assert!(heal_dist_tags(&tags, &[]).is_empty());
    }
}
