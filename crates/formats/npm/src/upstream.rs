//! Packuments a proxy reads from its upstream registry.
//!
//! An upstream packument may be large (tens of MiB for a package with
//! thousands of versions, most of it READMEs and the `users` who starred
//! it). [`read`] reads it as a stream and keeps only what a proxy serves:
//! the name, the dist-tags, the publish times, the version objects without
//! their READMEs, and the top-level README (bounded). The result is what a
//! proxy stores and serves from until it asks the upstream again.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

use chrono::{DateTime, Utc};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::manifest;
use crate::version;

/// The longest top-level README kept.
pub const MAX_README_BYTES: usize = 512 * 1024;

/// What a proxy keeps of an upstream packument.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UpstreamPackument {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: BTreeMap<String, String>,
    /// `created`, `modified` and a publish time per version, as written.
    #[serde(default)]
    pub time: BTreeMap<String, String>,
    /// The version objects by version as the upstream writes it, without
    /// their READMEs.
    #[serde(default)]
    pub versions: BTreeMap<String, Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readme: Option<String>,
}

/// One version of an upstream packument, normalized.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamVersion<'a> {
    /// The version, normalized.
    pub version: String,
    /// The version as the upstream writes it (its key in `versions`).
    pub original: &'a str,
    pub manifest: &'a Map<String, Value>,
    /// When it was published, if the upstream says.
    pub published: Option<DateTime<Utc>>,
}

impl UpstreamVersion<'_> {
    /// Where the upstream serves the tarball.
    pub fn tarball(&self) -> Option<&str> {
        self.dist()
            .and_then(|d| d.get("tarball"))
            .and_then(Value::as_str)
    }

    /// `dist.integrity`.
    pub fn integrity(&self) -> Option<&str> {
        self.dist()
            .and_then(|d| d.get("integrity"))
            .and_then(Value::as_str)
    }

    /// `dist.shasum`.
    pub fn shasum(&self) -> Option<&str> {
        self.dist()
            .and_then(|d| d.get("shasum"))
            .and_then(Value::as_str)
    }

    fn dist(&self) -> Option<&Map<String, Value>> {
        self.manifest.get("dist").and_then(Value::as_object)
    }

    /// The version's manifest summary.
    pub fn summary(&self) -> Map<String, Value> {
        manifest::summary(self.manifest)
    }
}

/// A publish time as the registry writes it.
pub fn parse_time(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

impl UpstreamPackument {
    /// The versions that normalize, each once (a key that is already
    /// normalized wins over another spelling of the same version), in
    /// ascending precedence.
    pub fn versions(&self) -> Vec<UpstreamVersion<'_>> {
        let mut by_version: BTreeMap<String, UpstreamVersion<'_>> = BTreeMap::new();
        for (original, manifest) in &self.versions {
            let Ok(normalized) = version::normalize(original) else {
                continue;
            };
            let entry = UpstreamVersion {
                version: normalized.clone(),
                original,
                manifest,
                published: self.time.get(original).and_then(|t| parse_time(t)),
            };
            match by_version.get(&normalized) {
                Some(existing) if existing.original == normalized => {}
                _ => {
                    by_version.insert(normalized, entry);
                }
            }
        }
        let mut out: Vec<UpstreamVersion<'_>> = by_version.into_values().collect();
        out.sort_by(|a, b| version::compare(&a.version, &b.version));
        out
    }

    /// The version `version` (normalized), if the upstream has it.
    pub fn version(&self, version: &str) -> Option<UpstreamVersion<'_>> {
        self.versions().into_iter().find(|v| v.version == version)
    }

    /// The dist-tags, with normalized versions.
    pub fn normalized_dist_tags(&self) -> BTreeMap<String, String> {
        self.dist_tags
            .iter()
            .filter_map(|(tag, v)| Some((tag.clone(), version::normalize(v).ok()?)))
            .collect()
    }
}

/// Read an upstream packument from `reader`; see the module documentation.
pub fn read(reader: impl Read) -> Result<UpstreamPackument, String> {
    let mut de = serde_json::Deserializer::from_reader(std::io::BufReader::new(reader));
    let doc = de
        .deserialize_map(TopVisitor)
        .map_err(|e| format!("not a packument: {e}"))?;
    de.end().map_err(|e| format!("not a packument: {e}"))?;
    Ok(doc)
}

struct TopVisitor;

/// The string values of a map, other values left out.
fn strings(map: BTreeMap<String, Value>) -> BTreeMap<String, String> {
    map.into_iter()
        .filter_map(|(k, v)| match v {
            Value::String(s) => Some((k, s)),
            _ => None,
        })
        .collect()
}

impl<'de> Visitor<'de> for TopVisitor {
    type Value = UpstreamPackument;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a packument object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = UpstreamPackument::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "name" => {
                    out.name = map
                        .next_value::<Value>()?
                        .as_str()
                        .unwrap_or_default()
                        .to_string()
                }
                "dist-tags" => {
                    out.dist_tags = strings(
                        map.next_value::<Option<BTreeMap<String, Value>>>()?
                            .unwrap_or_default(),
                    )
                }
                "time" => {
                    out.time = strings(
                        map.next_value::<Option<BTreeMap<String, Value>>>()?
                            .unwrap_or_default(),
                    )
                }
                "versions" => out.versions = map.next_value_seed(VersionsSeed)?,
                "readme" => {
                    out.readme = map.next_value::<Value>()?.as_str().map(|r| {
                        let mut r = r.to_string();
                        manifest::truncate(&mut r, MAX_README_BYTES);
                        r
                    })
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(out)
    }
}

struct VersionsSeed;

impl<'de> DeserializeSeed<'de> for VersionsSeed {
    type Value = BTreeMap<String, Map<String, Value>>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(VersionsVisitor)
    }
}

struct VersionsVisitor;

impl<'de> Visitor<'de> for VersionsVisitor {
    type Value = BTreeMap<String, Map<String, Value>>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the versions object")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(BTreeMap::new())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if let Some(manifest) = map.next_value_seed(ManifestSeed)? {
                out.insert(key, manifest);
            }
        }
        Ok(out)
    }
}

struct ManifestSeed;

impl<'de> DeserializeSeed<'de> for ManifestSeed {
    type Value = Option<Map<String, Value>>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(ManifestVisitor)
    }
}

/// A version object without its README; anything else is no version.
struct ManifestVisitor;

macro_rules! not_a_manifest {
    ($($name:ident: $ty:ty),*) => {
        $(fn $name<E>(self, _: $ty) -> Result<Self::Value, E> { Ok(None) })*
    };
}

impl<'de> Visitor<'de> for ManifestVisitor {
    type Value = Option<Map<String, Value>>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a version object")
    }

    not_a_manifest!(visit_bool: bool, visit_i64: i64, visit_u64: u64, visit_f64: f64, visit_str: &str);

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key == "readme" || key == "readmeFilename" {
                map.next_value::<IgnoredAny>()?;
            } else {
                out.insert(key, map.next_value::<Value>()?);
            }
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keeps_what_a_proxy_serves() {
        let body = json!({
            "_id": "left-pad", "_rev": "12-abc", "name": "left-pad",
            "dist-tags": {"latest": "1.3.0", "bogus": 1},
            "versions": {
                "1.3.0": {"name": "left-pad", "version": "1.3.0", "readme": "# huge", "dist": {
                    "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-x", "shasum": "ab"}},
                "v1.2.0": {"name": "left-pad", "version": "1.2.0"},
                "1.2.0": {"name": "left-pad", "version": "1.2.0", "canonical": true},
                "not-a-version": {"name": "left-pad"},
                "1.1.0": null
            },
            "time": {"created": "2016-03-23T20:00:00.000Z", "1.3.0": "2018-04-09T01:57:31.231Z", "x": 5},
            "users": {"someone": true},
            "readme": "# left-pad",
            "_attachments": {}
        });
        let doc = read(serde_json::to_vec(&body).unwrap().as_slice()).unwrap();
        assert_eq!(doc.name, "left-pad");
        assert_eq!(
            doc.dist_tags,
            BTreeMap::from([("latest".into(), "1.3.0".into())])
        );
        assert_eq!(doc.readme.as_deref(), Some("# left-pad"));
        assert!(!doc.time.contains_key("x"));
        assert!(doc.versions["1.3.0"].get("readme").is_none());
        let versions = doc.versions();
        let names: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(names, ["1.2.0", "1.3.0"]);
        assert_eq!(versions[0].original, "1.2.0");
        assert_eq!(versions[0].manifest["canonical"], true);
        let latest = doc.version("1.3.0").unwrap();
        assert_eq!(
            latest.tarball(),
            Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
        );
        assert_eq!(latest.integrity(), Some("sha512-x"));
        assert_eq!(latest.published, parse_time("2018-04-09T01:57:31.231Z"));
        // What a proxy stores reads back the same.
        let stored = serde_json::to_vec(&doc).unwrap();
        assert_eq!(
            serde_json::from_slice::<UpstreamPackument>(&stored).unwrap(),
            doc
        );
    }

    #[test]
    fn refuses_what_is_no_packument() {
        assert!(read(&b"[1,2]"[..]).is_err());
        assert!(read(&b"{\"name\": \"x\"} trailing"[..]).is_err());
        assert!(read(&b"<html>"[..]).is_err());
    }
}
