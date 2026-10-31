//! What an import reads of another npm registry (Nexus, Verdaccio,
//! Artifactory, another Forge) to copy its packages into a hosted
//! repository. The host sends the requests; this module says where to, and
//! reads the answers.
//!
//! npm's protocol has no listing of every package, so the names come from
//! one of:
//!
//! * the search, `GET /-/v1/search?text=&size=&from=` ([`search_url`],
//!   [`read_search`]), paged with `from`. With an empty `text` another Forge
//!   lists every package; Nexus 3.70 finds nothing, and Verdaccio refuses
//!   it. Nexus also answers a scoped package by its name alone (`ui` for
//!   `@acme/ui`), without a `scope`;
//! * the legacy listing, `GET /-/all` ([`ALL_PATH`], [`read_all`]): an object
//!   keyed by every package's name, which Nexus' hosted repositories and
//!   Verdaccio still serve;
//! * the names, or scopes (`@acme`, [`parse_scope`]), the import gives.
//!
//! A package's versions come from its full packument ([`read_package`],
//! fetched with [`packument_url`]): each version's `dist.integrity` (its
//! SHA-512) and `dist.shasum`, its publish time (`time`), its `deprecated`
//! message, and the package's dist-tags. The tarball is fetched from the
//! import's URL ([`tarball_url`]), not from `dist.tarball`, whose host is
//! the source's configured base URL, which need not be one the importing
//! server reaches the source on.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

use chrono::{DateTime, Utc};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::Deserializer;
use serde_json::Value;

use crate::integrity::sha512_of;
use crate::upstream::{self, Keep, Select};
use crate::PackageName;

/// The largest page of a search (npm's registry allows 250).
pub const MAX_SEARCH_SIZE: u32 = 250;

/// The legacy listing of every package, below the registry's URL.
pub const ALL_PATH: &str = "/-/all";

/// `/-/v1/search` of the registry at `base` (no trailing `/`), for `text`.
pub fn search_url(base: &str, text: &str, from: u32, size: u32) -> String {
    format!(
        "{base}/-/v1/search?text={}&size={}&from={from}",
        encode(text),
        size.clamp(1, MAX_SEARCH_SIZE)
    )
}

/// The packument of `name` at the registry at `base`.
pub fn packument_url(base: &str, name: &PackageName) -> String {
    format!("{base}/{}", name.escaped())
}

/// The tarball `file` of `name` at the registry at `base`:
/// `<base>/<name>/-/<file>`, as npm's registry, Nexus, Verdaccio and Forge
/// serve it.
pub fn tarball_url(base: &str, name: &PackageName, file: &str) -> String {
    format!("{base}/{name}/-/{file}")
}

/// `s` percent-encoded for a query string.
pub(crate) fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The scope an import names, `@acme` (also written `@acme/` or
/// `@acme/*`), as `@acme`; `None` when `raw` names no scope.
pub fn parse_scope(raw: &str) -> Option<String> {
    let scope = raw.strip_prefix('@')?;
    let scope = scope
        .strip_suffix("/*")
        .or_else(|| scope.strip_suffix('/'))
        .unwrap_or(scope);
    // A scope is what a scoped name's scope may be.
    PackageName::parse(&format!("@{scope}/x")).ok()?;
    Some(format!("@{scope}"))
}

/// One page of a registry's search.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SearchPage {
    /// The matches the registry counts.
    pub total: u64,
    /// The names of the page's packages, in its order.
    pub names: Vec<String>,
}

/// Read a page of `/-/v1/search`. A package named without its scope, with
/// the scope beside it (`"scope": "acme"`), is named with it; a name that is
/// none is left out.
pub fn read_search(body: &[u8]) -> Result<SearchPage, String> {
    let page: Value =
        serde_json::from_slice(body).map_err(|e| format!("the search answer is no JSON: {e}"))?;
    let objects = page
        .get("objects")
        .and_then(Value::as_array)
        .ok_or("the search answer lists no objects")?;
    let names = objects
        .iter()
        .filter_map(|object| {
            let package = object.get("package")?;
            let name = package.get("name")?.as_str()?;
            let scope = package
                .get("scope")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && *s != "unscoped");
            let name = match scope {
                Some(scope) if !name.starts_with('@') => format!("@{scope}/{name}"),
                _ => name.to_string(),
            };
            PackageName::parse(&name).ok()?;
            Some(name)
        })
        .collect();
    Ok(SearchPage {
        total: page.get("total").and_then(Value::as_u64).unwrap_or(0),
        names,
    })
}

/// Read `/-/all` from `reader`: the names of the packages it lists, sorted,
/// each once. What its entries say is skipped as it streams by.
pub fn read_all(reader: impl Read) -> Result<Vec<String>, String> {
    let mut de = serde_json::Deserializer::from_reader(std::io::BufReader::new(reader));
    let mut names = de
        .deserialize_map(Keys)
        .map_err(|e| format!("not a listing: {e}"))?;
    de.end().map_err(|e| format!("not a listing: {e}"))?;
    names.sort();
    names.dedup();
    Ok(names)
}

/// The keys of an object that are package names (`_updated` is none).
struct Keys;

impl<'de> Visitor<'de> for Keys {
    type Value = Vec<String>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an object of packages")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut names = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            map.next_value::<IgnoredAny>()?;
            if PackageName::parse(&key).is_ok() {
                names.push(key);
            }
        }
        Ok(names)
    }
}

/// One version of a package at the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Normalized.
    pub version: String,
    /// When it was published (`time`), if the packument says.
    pub published: Option<DateTime<Utc>>,
    /// `dist.integrity`, an SRI string.
    pub integrity: Option<String>,
    /// `dist.shasum`, hex SHA-1.
    pub shasum: Option<String>,
    /// Why it is deprecated, if it is.
    pub deprecated: Option<String>,
    /// The tarball's file name: the last segment of `dist.tarball` where it
    /// is `…/-/<file>`, otherwise `<name>-<version>.tgz`.
    pub file: String,
}

impl Release {
    /// The SHA-512 of the tarball, base64, where `dist.integrity` lists one.
    pub fn sha512(&self) -> Option<String> {
        self.integrity.as_deref().and_then(sha512_of)
    }
}

/// A package at the source: its versions, in ascending precedence, and its
/// dist-tags (normalized versions; a tag naming a version the packument
/// does not have is left out).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Package {
    pub name: String,
    pub dist_tags: BTreeMap<String, String>,
    pub releases: Vec<Release>,
}

/// Read the full packument of `name` from `reader`: what an import copies of
/// every version. A packument of another package is refused.
pub fn read_package(reader: impl Read, name: &PackageName) -> Result<Package, String> {
    let doc = upstream::read(
        reader,
        Select {
            every: true,
            keep: Keep::Release,
            time: true,
            ..Select::default()
        },
    )?;
    let expected = name.to_string();
    if !doc.name.is_empty() && doc.name != expected {
        return Err(format!(
            "the registry answered package {:?} for {expected:?}",
            doc.name
        ));
    }
    let releases: Vec<Release> = doc
        .versions()
        .into_iter()
        .map(|v| Release {
            file: tarball_file(v.tarball(), name, v.original),
            published: v.published,
            integrity: v.integrity().map(str::to_string),
            shasum: v.shasum().map(str::to_ascii_lowercase),
            deprecated: v.deprecated().map(str::to_string),
            version: v.version,
        })
        .collect();
    let dist_tags = doc
        .normalized_dist_tags()
        .into_iter()
        .filter(|(_, version)| releases.iter().any(|r| &r.version == version))
        .collect();
    Ok(Package {
        name: expected,
        dist_tags,
        releases,
    })
}

/// The file name of a tarball: `dist.tarball`'s, where it is
/// `…/-/<file>`, otherwise npm's `<name>-<version>.tgz`.
fn tarball_file(tarball: Option<&str>, name: &PackageName, version: &str) -> String {
    let path = tarball.map(|t| t.split(['?', '#']).next().unwrap_or(t));
    path.and_then(|p| p.rsplit_once("/-/"))
        .map(|(_, file)| file)
        .filter(|file| !file.is_empty() && !file.contains('/') && file.ends_with(".tgz"))
        .map(str::to_string)
        .unwrap_or_else(|| name.tarball_file(version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn name(raw: &str) -> PackageName {
        PackageName::parse(raw).unwrap()
    }

    #[test]
    fn urls_are_built_from_the_registry_url() {
        let base = "http://nexus:8081/repository/npm-hosted";
        assert_eq!(
            search_url(base, "", 500, 1000),
            "http://nexus:8081/repository/npm-hosted/-/v1/search?text=&size=250&from=500"
        );
        assert_eq!(
            search_url(base, "@acme", 0, 100),
            "http://nexus:8081/repository/npm-hosted/-/v1/search?text=%40acme&size=100&from=0"
        );
        assert_eq!(
            packument_url(base, &name("@acme/ui")),
            "http://nexus:8081/repository/npm-hosted/@acme%2fui"
        );
        assert_eq!(
            tarball_url(base, &name("@acme/ui"), "ui-1.0.0.tgz"),
            "http://nexus:8081/repository/npm-hosted/@acme/ui/-/ui-1.0.0.tgz"
        );
    }

    #[test]
    fn scopes_are_named_with_their_at() {
        assert_eq!(parse_scope("@acme").as_deref(), Some("@acme"));
        assert_eq!(parse_scope("@acme/").as_deref(), Some("@acme"));
        assert_eq!(parse_scope("@acme/*").as_deref(), Some("@acme"));
        assert_eq!(parse_scope("@acme/ui"), None);
        assert_eq!(parse_scope("acme"), None);
        assert_eq!(parse_scope("@"), None);
        assert_eq!(parse_scope("@.acme"), None);
        assert_eq!(parse_scope("@ac/me/"), None);
    }

    #[test]
    fn a_search_names_packages_with_their_scope() {
        let body = serde_json::to_vec(&json!({
            "objects": [
                {"package": {"name": "alpha", "version": "1.0.0"}},
                {"package": {"name": "@acme/ui", "scope": "acme", "version": "1.0.0"}},
                {"package": {"name": "core", "scope": "acme", "version": "0.1.0"}},
                {"package": {"name": "beta", "scope": "unscoped", "version": "0.1.0"}},
                {"package": {"name": "../x", "version": "1.0.0"}},
                {"package": {"version": "1.0.0"}},
            ],
            "total": 9
        }))
        .unwrap();
        assert_eq!(
            read_search(&body).unwrap(),
            SearchPage {
                total: 9,
                names: vec![
                    "alpha".into(),
                    "@acme/ui".into(),
                    "@acme/core".into(),
                    "beta".into()
                ],
            }
        );
        assert!(read_search(b"{\"error\": \"text required\"}").is_err());
        assert!(read_search(b"<html>").is_err());
    }

    #[test]
    fn the_legacy_listing_names_every_package() {
        let body = serde_json::to_vec(&json!({
            "_updated": 1793435634215u64,
            "zeta": {"name": "zeta", "versions": {"1.0.0": "latest"}},
            "@acme/ui": {"name": "@acme/ui", "dist-tags": {"latest": "1.0.1"}},
            "alpha": {"name": "alpha"},
        }))
        .unwrap();
        assert_eq!(read_all(&body[..]).unwrap(), ["@acme/ui", "alpha", "zeta"]);
        assert!(read_all(&b"[]"[..]).is_err());
        assert!(read_all(&b"{\"a\": 1} trailing"[..]).is_err());
    }

    #[test]
    fn a_packument_gives_every_version_with_its_checksums_time_and_deprecation() {
        let body = serde_json::to_vec(&json!({
            "name": "@acme/ui",
            "dist-tags": {"latest": "1.1.0", "next": "2.0.0-rc.1", "gone": "9.9.9"},
            "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "1.1.0": "2021-02-03T04:05:06.789Z"
            },
            "versions": {
                "1.0.0": {
                    "name": "@acme/ui", "version": "1.0.0", "readme": "# big",
                    "deprecated": "use 1.1.0",
                    "dependencies": {"b": "^1"},
                    "dist": {
                        "tarball": "https://registry.example.com/@acme/ui/-/ui-1.0.0.tgz",
                        "integrity": "sha512-AAAA sha1-BBBB", "shasum": "ABCD"
                    }
                },
                "1.1.0": {
                    "name": "@acme/ui", "version": "1.1.0", "deprecated": "",
                    "dist": {"tarball": "https://cdn.example.com/download/ui/1.1.0", "shasum": "ef01"}
                },
                "2.0.0-rc.1": {"name": "@acme/ui", "version": "2.0.0-rc.1", "dist": {
                    "tarball": "http://old-host/repository/npm/@acme/ui/-/ui-2.0.0-rc.1.tgz?x=1",
                    "integrity": "sha512-CCCC"
                }}
            }
        }))
        .unwrap();
        let package = read_package(&body[..], &name("@acme/ui")).unwrap();
        assert_eq!(package.name, "@acme/ui");
        assert_eq!(
            package.dist_tags,
            BTreeMap::from([
                ("latest".into(), "1.1.0".into()),
                ("next".into(), "2.0.0-rc.1".into())
            ])
        );
        let versions: Vec<&str> = package
            .releases
            .iter()
            .map(|r| r.version.as_str())
            .collect();
        assert_eq!(versions, ["1.0.0", "1.1.0", "2.0.0-rc.1"]);
        let first = &package.releases[0];
        assert_eq!(first.sha512().as_deref(), Some("AAAA"));
        assert_eq!(first.shasum.as_deref(), Some("abcd"));
        assert_eq!(first.deprecated.as_deref(), Some("use 1.1.0"));
        assert_eq!(first.file, "ui-1.0.0.tgz");
        assert_eq!(
            first.published,
            upstream::parse_time("2020-01-01T00:00:00.000Z")
        );
        // An unconventional tarball URL: npm's file name. No integrity: no
        // SHA-512; an empty deprecation is none.
        let second = &package.releases[1];
        assert_eq!(second.file, "ui-1.1.0.tgz");
        assert_eq!(second.sha512(), None);
        assert_eq!(second.shasum.as_deref(), Some("ef01"));
        assert_eq!(second.deprecated, None);
        // The file of a tarball on another host, its query left out.
        let third = &package.releases[2];
        assert_eq!(third.file, "ui-2.0.0-rc.1.tgz");
        assert_eq!(third.published, None);

        assert!(read_package(&body[..], &name("@acme/other")).is_err());
        assert!(read_package(&b"[]"[..], &name("@acme/ui")).is_err());
    }
}
