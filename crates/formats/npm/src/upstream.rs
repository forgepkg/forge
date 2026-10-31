//! Packuments a proxy reads from its upstream registry.
//!
//! An upstream packument may be large (tens of MiB for a package with
//! thousands of versions: `typescript`'s full packument is 15 MiB, `vite`'s
//! 37 MiB with a copy of its license in every version). Held as JSON values,
//! every version's object takes several times its size, and each operation
//! of a packument read asks for the document again. So [`read`] reads it as
//! a stream and keeps only what the operation asks for ([`Select`]): the
//! name and the dist-tags, which versions there are, the objects of the
//! versions asked for (without their READMEs) or just their summaries, and
//! the publish times and the top-level README (bounded) when asked. An
//! import of another registry ([`crate::import`]) keeps what it copies of
//! every version ([`Keep::Release`]).

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::Read;

use chrono::{DateTime, Utc};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use serde_json::{Map, Value};

use crate::manifest;
use crate::version;

/// The longest top-level README kept.
pub const MAX_README_BYTES: usize = 512 * 1024;

/// What [`read`] keeps of a packument besides its name, its dist-tags and
/// which versions it has. The default keeps nothing more.
#[derive(Debug, Clone, Copy, Default)]
pub struct Select<'a> {
    /// The versions (normalized) whose objects are kept, as `keep` says;
    /// every other version is only listed ([`Kept::Listed`]).
    pub versions: &'a [String],
    /// Keep the object of every version, not only of `versions`.
    pub every: bool,
    pub keep: Keep,
    /// The publish times (`time`).
    pub time: bool,
    /// The top-level README.
    pub readme: bool,
}

/// How [`read`] keeps the objects of the versions [`Select`] names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Keep {
    /// The manifest, without its README.
    #[default]
    Manifest,
    /// Its summary ([`manifest::summary`]) alone, as JSON.
    Summary,
    /// What an import copies of it, as a [`Kept::Manifest`]: its `name`,
    /// `version`, `dist` and `deprecated`.
    Release,
}

/// The fields of a version object [`Keep::Release`] keeps.
const RELEASE_FIELDS: &[&str] = &["name", "version", "dist", "deprecated"];

/// A version object as [`read`] kept it.
#[derive(Debug, Clone, PartialEq)]
pub enum Kept {
    /// Not kept: the version is listed, nothing more.
    Listed,
    /// The manifest, without its README (or, with [`Keep::Release`], the
    /// fields it keeps).
    Manifest(Map<String, Value>),
    /// Its summary, as JSON.
    Summary(String),
}

/// What a read kept of an upstream packument.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UpstreamPackument {
    pub name: String,
    pub dist_tags: BTreeMap<String, String>,
    /// `created`, `modified` and a publish time per version, as written;
    /// empty unless [`Select::time`].
    pub time: BTreeMap<String, String>,
    /// The version objects by version as the upstream writes it, for the
    /// versions that normalize.
    pub versions: BTreeMap<String, Kept>,
    /// Unless [`Select::readme`], `None`.
    pub readme: Option<String>,
}

/// One version of an upstream packument, normalized.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamVersion<'a> {
    /// The version, normalized.
    pub version: String,
    /// The version as the upstream writes it (its key in `versions`).
    pub original: &'a str,
    pub kept: &'a Kept,
    /// When it was published, if the upstream says (and it was read).
    pub published: Option<DateTime<Utc>>,
}

impl<'a> UpstreamVersion<'a> {
    /// The manifest, if it was kept.
    pub fn manifest(&self) -> Option<&'a Map<String, Value>> {
        match self.kept {
            Kept::Manifest(manifest) => Some(manifest),
            Kept::Listed | Kept::Summary(_) => None,
        }
    }

    /// Where the upstream serves the tarball.
    pub fn tarball(&self) -> Option<&'a str> {
        self.dist()
            .and_then(|d| d.get("tarball"))
            .and_then(Value::as_str)
    }

    /// `dist.integrity`.
    pub fn integrity(&self) -> Option<&'a str> {
        self.dist()
            .and_then(|d| d.get("integrity"))
            .and_then(Value::as_str)
    }

    /// `dist.shasum`.
    pub fn shasum(&self) -> Option<&'a str> {
        self.dist()
            .and_then(|d| d.get("shasum"))
            .and_then(Value::as_str)
    }

    /// Why the version is deprecated, if it is (an empty message is none).
    pub fn deprecated(&self) -> Option<&'a str> {
        self.manifest()?
            .get("deprecated")
            .and_then(Value::as_str)
            .filter(|m| !m.is_empty())
    }

    fn dist(&self) -> Option<&'a Map<String, Value>> {
        self.manifest()?.get("dist").and_then(Value::as_object)
    }
}

/// A publish time as the registry writes it.
pub fn parse_time(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

impl UpstreamPackument {
    /// The versions, each once (a key that is already normalized wins over
    /// another spelling of the same version), in ascending precedence.
    pub fn versions(&self) -> Vec<UpstreamVersion<'_>> {
        let mut by_version: BTreeMap<String, UpstreamVersion<'_>> = BTreeMap::new();
        for (original, kept) in &self.versions {
            let Ok(normalized) = version::normalize(original) else {
                continue;
            };
            let entry = UpstreamVersion {
                version: normalized.clone(),
                original,
                kept,
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

/// Read what `select` asks for of an upstream packument from `reader`; see
/// the module documentation.
pub fn read(reader: impl Read, select: Select<'_>) -> Result<UpstreamPackument, String> {
    let mut de = serde_json::Deserializer::from_reader(std::io::BufReader::new(reader));
    let doc = de
        .deserialize_map(TopVisitor {
            select,
            wanted: select.versions.iter().map(String::as_str).collect(),
        })
        .map_err(|e| format!("not a packument: {e}"))?;
    de.end().map_err(|e| format!("not a packument: {e}"))?;
    Ok(doc)
}

/// Read one version object (what `GET /{name}/{version}` answers) from
/// `reader`, without its README.
pub fn read_manifest(reader: impl Read) -> Result<Map<String, Value>, String> {
    let mut de = serde_json::Deserializer::from_reader(std::io::BufReader::new(reader));
    let kept = ObjectSeed(Some(Keep::Manifest))
        .deserialize(&mut de)
        .map_err(|e| format!("not a version: {e}"))?;
    de.end().map_err(|e| format!("not a version: {e}"))?;
    match kept {
        Some(Kept::Manifest(manifest)) => Ok(manifest),
        _ => Err("not a version: not an object".into()),
    }
}

struct TopVisitor<'a> {
    select: Select<'a>,
    wanted: HashSet<&'a str>,
}

/// The string values of a map, other values left out.
fn strings(map: BTreeMap<String, Value>) -> BTreeMap<String, String> {
    map.into_iter()
        .filter_map(|(k, v)| match v {
            Value::String(s) => Some((k, s)),
            _ => None,
        })
        .collect()
}

impl<'de> Visitor<'de> for TopVisitor<'_> {
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
                "time" if self.select.time => {
                    out.time = strings(
                        map.next_value::<Option<BTreeMap<String, Value>>>()?
                            .unwrap_or_default(),
                    )
                }
                "versions" => {
                    out.versions = map.next_value_seed(VersionsSeed {
                        wanted: &self.wanted,
                        every: self.select.every,
                        keep: self.select.keep,
                    })?
                }
                "readme" if self.select.readme => {
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

/// The `versions` object: the objects of the `wanted` versions (normalized),
/// or of `every` version, kept as `keep` says, the others only listed.
struct VersionsSeed<'s, 'a> {
    wanted: &'s HashSet<&'a str>,
    every: bool,
    keep: Keep,
}

impl<'de> DeserializeSeed<'de> for VersionsSeed<'_, '_> {
    type Value = BTreeMap<String, Kept>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for VersionsSeed<'_, '_> {
    type Value = BTreeMap<String, Kept>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the versions object")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(BTreeMap::new())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let Ok(normalized) = version::normalize(&key) else {
                map.next_value::<IgnoredAny>()?;
                continue;
            };
            let keep =
                (self.every || self.wanted.contains(normalized.as_str())).then_some(self.keep);
            if let Some(kept) = map.next_value_seed(ObjectSeed(keep))? {
                out.insert(key, kept);
            }
        }
        Ok(out)
    }
}

/// A version object kept as the [`Keep`] says, or only listed without one;
/// anything else is no version (`None`).
struct ObjectSeed(Option<Keep>);

impl<'de> DeserializeSeed<'de> for ObjectSeed {
    type Value = Option<Kept>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}

macro_rules! not_a_manifest {
    ($($name:ident: $ty:ty),*) => {
        $(fn $name<E>(self, _: $ty) -> Result<Self::Value, E> { Ok(None) })*
    };
}

impl<'de> Visitor<'de> for ObjectSeed {
    type Value = Option<Kept>;

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
        let Some(keep) = self.0 else {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            return Ok(Some(Kept::Listed));
        };
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let skipped = match keep {
                Keep::Release => !RELEASE_FIELDS.contains(&key.as_str()),
                Keep::Manifest | Keep::Summary => key == "readme" || key == "readmeFilename",
            };
            if skipped {
                map.next_value::<IgnoredAny>()?;
            } else {
                out.insert(key, map.next_value::<Value>()?);
            }
        }
        Ok(Some(match keep {
            Keep::Manifest | Keep::Release => Kept::Manifest(out),
            Keep::Summary => Kept::Summary(
                serde_json::to_string(&manifest::into_summary(out))
                    .map_err(<A::Error as serde::de::Error>::custom)?,
            ),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn left_pad() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "_id": "left-pad", "_rev": "12-abc", "name": "left-pad",
            "dist-tags": {"latest": "1.3.0", "bogus": 1},
            "versions": {
                "1.3.0": {"name": "left-pad", "version": "1.3.0", "readme": "# huge", "dist": {
                    "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-x", "shasum": "ab"},
                    "dependencies": {"b": "^1"}},
                "v1.2.0": {"name": "left-pad", "version": "1.2.0"},
                "1.2.0": {"name": "left-pad", "version": "1.2.0", "canonical": true},
                "not-a-version": {"name": "left-pad"},
                "1.1.0": null
            },
            "time": {"created": "2016-03-23T20:00:00.000Z", "1.3.0": "2018-04-09T01:57:31.231Z", "x": 5},
            "users": {"someone": true},
            "readme": "# left-pad",
            "_attachments": {}
        }))
        .unwrap()
    }

    fn wanted(versions: &[&str]) -> Vec<String> {
        versions.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn keeps_what_a_proxy_serves() {
        let versions = wanted(&["1.2.0", "1.3.0"]);
        let doc = read(
            &left_pad()[..],
            Select {
                versions: &versions,
                every: false,
                keep: Keep::Manifest,
                time: true,
                readme: true,
            },
        )
        .unwrap();
        assert_eq!(doc.name, "left-pad");
        assert_eq!(
            doc.dist_tags,
            BTreeMap::from([("latest".into(), "1.3.0".into())])
        );
        assert_eq!(doc.readme.as_deref(), Some("# left-pad"));
        assert!(!doc.time.contains_key("x"));
        assert!(!doc.versions.contains_key("not-a-version"));
        let Kept::Manifest(latest) = &doc.versions["1.3.0"] else {
            panic!("{:?}", doc.versions["1.3.0"])
        };
        assert!(latest.get("readme").is_none());
        let versions = doc.versions();
        let names: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(names, ["1.2.0", "1.3.0"]);
        assert_eq!(versions[0].original, "1.2.0");
        assert_eq!(versions[0].manifest().unwrap()["canonical"], true);
        let latest = doc.version("1.3.0").unwrap();
        assert_eq!(
            latest.tarball(),
            Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
        );
        assert_eq!(latest.integrity(), Some("sha512-x"));
        assert_eq!(latest.published, parse_time("2018-04-09T01:57:31.231Z"));
    }

    #[test]
    fn keeps_only_what_is_selected() {
        // By default: the name, the tags and which versions there are.
        let doc = read(&left_pad()[..], Select::default()).unwrap();
        assert_eq!(doc.name, "left-pad");
        assert_eq!(doc.dist_tags.len(), 1);
        assert!(doc.time.is_empty() && doc.readme.is_none());
        let versions = doc.versions();
        let names: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(names, ["1.2.0", "1.3.0"]);
        assert!(versions.iter().all(|v| v.kept == &Kept::Listed));
        assert_eq!(versions[1].published, None);
        assert_eq!(versions[1].tarball(), None);

        // The summaries of the versions asked for, the others listed.
        let versions = wanted(&["1.3.0"]);
        let doc = read(
            &left_pad()[..],
            Select {
                versions: &versions,
                keep: Keep::Summary,
                ..Select::default()
            },
        )
        .unwrap();
        assert_eq!(doc.versions["1.2.0"], Kept::Listed);
        let Kept::Summary(summary) = &doc.versions["1.3.0"] else {
            panic!("{:?}", doc.versions["1.3.0"])
        };
        let summary: Map<String, Value> = serde_json::from_str(summary).unwrap();
        let manifest = json!({"name": "left-pad", "version": "1.3.0", "dist": {
            "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "integrity": "sha512-x", "shasum": "ab"}, "dependencies": {"b": "^1"}});
        assert_eq!(summary, manifest::summary(manifest.as_object().unwrap()));
        assert!(summary.contains_key(manifest::DEPENDENCY_GROUPS));
    }

    #[test]
    fn reads_one_version_object() {
        let manifest =
            read_manifest(&br#"{"name": "a", "version": "1.0.0", "readme": "x", "dist": {}}"#[..])
                .unwrap();
        assert_eq!(
            Value::Object(manifest),
            json!({"name": "a", "version": "1.0.0", "dist": {}})
        );
        assert!(read_manifest(&b"[1]"[..]).is_err());
        assert!(read_manifest(&b"null"[..]).is_err());
    }

    #[test]
    fn refuses_what_is_no_packument() {
        assert!(read(&b"[1,2]"[..], Select::default()).is_err());
        assert!(read(&b"{\"name\": \"x\"} trailing"[..], Select::default()).is_err());
        assert!(read(&b"<html>"[..], Select::default()).is_err());
        // Even where nothing is kept, the document is read whole.
        assert!(read(&b"{\"versions\": {\"1.0.0\": {]}}"[..], Select::default()).is_err());
    }
}
