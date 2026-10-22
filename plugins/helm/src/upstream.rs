//! The upstream side of Helm proxies: another chart repository, read through
//! the host ([`FormatPlugin::upstream`](forge_plugin_api::FormatPlugin::upstream)).
//!
//! A chart repository is one document, its `index.yaml`: every chart, every
//! version, and where each version's archive is. Every operation reads it
//! (the host caches it for the repository's metadata TTL). The upstream's
//! index ([`Remote::index`]) is just its base URL.
//!
//! Parsing a large index takes long (half a second and some 200 MB for a
//! 10 MB one), and a proxy's chart listing runs several operations per
//! chart, so the built-in plugin keeps the parsed index while the upstream
//! serves the same document, and parses one index at a time
//! ([`parsed_index`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use forge_plugin_api::{
    Fetch, FetchResult, Fetched, FormatError, Freshness, PackageMetadata, PackageRef,
    PackageVersions, Remote, SearchQuery, UpstreamAnswer, UpstreamHit, UpstreamOp, UpstreamSearch,
    UpstreamStep, VersionMetadata,
};
use serde_json::{json, Map, Value};

use crate::chart::{self, to_json};
use crate::semver::Version;

/// The default page of an upstream search.
const DEFAULT_TAKE: usize = 20;

/// One chart version an upstream index lists. Compact, since parsed
/// indexes are kept ([`parsed_index`]): the entry itself stays JSON text,
/// read back only for the versions an operation describes.
struct Entry {
    /// The chart name, as written.
    name: String,
    version: Version,
    /// Its `created`.
    created: Option<String>,
    /// The first of its `urls`.
    url: Option<String>,
    /// The index entry (Chart.yaml's metadata, `urls`, `created`, `digest`),
    /// as JSON.
    metadata: Box<str>,
}

impl Entry {
    /// The index entry ([`Entry::metadata`]).
    fn metadata(&self) -> Map<String, Value> {
        serde_json::from_str(&self.metadata).unwrap_or_default()
    }
}

/// An upstream index: each chart's versions by canonical name, ascending.
type Index = BTreeMap<String, Vec<Entry>>;

/// One step of the conversation for `op` ([`crate::Helm`]'s
/// `FormatPlugin::upstream`).
pub(crate) fn step(
    remote: &Remote,
    op: &UpstreamOp,
    fetched: &[FetchResult],
) -> Result<UpstreamStep, FormatError> {
    let base = match op {
        UpstreamOp::Index => remote.url.trim_end_matches('/').to_string(),
        _ => match remote
            .index
            .as_deref()
            .and_then(|i| serde_json::from_str::<Value>(i).ok())
            .and_then(|i| i.get("base")?.as_str().map(str::to_string))
        {
            Some(base) => base,
            None => return Ok(failed("the upstream's index is not resolved")),
        },
    };
    // Nothing to read: a chart repository has no manifest without its
    // chart, so the host takes the manifest from the package.
    if let UpstreamOp::Manifest(_) = op {
        return Ok(done(UpstreamAnswer::Manifest(None)));
    }
    let url = format!("{base}/index.yaml");
    let index = match fetched
        .iter()
        .find(|f| f.fetch.url == url)
        .map(|f| &f.outcome)
    {
        None => {
            return Ok(UpstreamStep::Fetch(vec![Fetch {
                url,
                freshness: Freshness::Metadata,
            }]))
        }
        Some(Fetched::Found(body)) => match parsed_index(&url, body) {
            Ok(index) => index,
            Err(e) => return Ok(failed(format!("upstream index {url}: {e}"))),
        },
        Some(Fetched::NotFound) => return Ok(failed(format!("upstream index {url} returned 404"))),
        Some(Fetched::Failed(reason)) => return Ok(failed(reason.clone())),
    };
    Ok(match op {
        UpstreamOp::Index => done(UpstreamAnswer::Index(json!({ "base": base }).to_string())),
        UpstreamOp::Versions(id) => {
            done(UpstreamAnswer::Versions(index.get(id).map(|versions| {
                versions.iter().map(|e| e.version.to_string()).collect()
            })))
        }
        UpstreamOp::Package(target) => {
            done(UpstreamAnswer::Package(package_url(&base, &index, target)))
        }
        UpstreamOp::Manifest(_) => unreachable!("answered above"),
        UpstreamOp::Metadata(wanted) => metadata(&index, wanted, false),
        UpstreamOp::Dating(wanted) => metadata(&index, wanted, true),
        UpstreamOp::Search(query) => done(UpstreamAnswer::Search(Some(search(&index, query)))),
    })
}

fn done(answer: UpstreamAnswer) -> UpstreamStep {
    UpstreamStep::Done(answer)
}

fn failed(reason: impl Into<String>) -> UpstreamStep {
    done(UpstreamAnswer::Failed(reason.into()))
}

/// The parsed `index.yaml` at `url` whose bytes are `body`.
///
/// The built-in plugin keeps the last few it parsed, one per URL, and reuses
/// one while the upstream serves the same bytes (the host hands every
/// operation the document it caches for the metadata TTL): comparing the
/// bytes takes a millisecond where parsing takes half a second. Since the
/// result depends on the bytes alone, it is the same for every repository
/// that fetches them. Parses run one at a time: concurrent operations on a
/// document nobody has parsed yet wait for the first parse instead of each
/// running their own, and memory holds one parse at most.
///
/// A WebAssembly build parses for every operation: its instances are
/// recycled and their memory is bounded, so it keeps nothing.
fn parsed_index(url: &str, body: &[u8]) -> Result<Arc<Index>, String> {
    #[cfg(not(target_family = "wasm"))]
    {
        parsed::get_or_parse(url, body)
    }
    #[cfg(target_family = "wasm")]
    {
        let _ = url;
        parse_index(body).map(Arc::new)
    }
}

#[cfg(not(target_family = "wasm"))]
mod parsed {
    use std::sync::{Arc, Mutex, PoisonError};

    use super::{parse_index, Index};

    /// How many parsed indexes are kept, the most recently used.
    pub(super) const KEPT: usize = 4;

    /// A parsed index and the bytes it was parsed from.
    struct Parsed {
        url: String,
        body: Arc<[u8]>,
        index: Arc<Index>,
        /// When it was last used ([`State::clock`]).
        used: u64,
    }

    struct State {
        parsed: Vec<Parsed>,
        clock: u64,
    }

    static STATE: Mutex<State> = Mutex::new(State {
        parsed: Vec::new(),
        clock: 0,
    });

    /// Held while an index is parsed.
    static PARSING: Mutex<()> = Mutex::new(());

    pub(super) fn get_or_parse(url: &str, body: &[u8]) -> Result<Arc<Index>, String> {
        if let Some(index) = lookup(url, body) {
            return Ok(index);
        }
        let _parsing = PARSING.lock().unwrap_or_else(PoisonError::into_inner);
        // Parsed while this one waited.
        if let Some(index) = lookup(url, body) {
            return Ok(index);
        }
        let index = Arc::new(parse_index(body)?);
        let mut state = STATE.lock().unwrap_or_else(PoisonError::into_inner);
        state.clock += 1;
        let used = state.clock;
        state.parsed.retain(|p| p.url != url);
        if state.parsed.len() >= KEPT {
            if let Some(oldest) = (0..state.parsed.len()).min_by_key(|&i| state.parsed[i].used) {
                state.parsed.swap_remove(oldest);
            }
        }
        state.parsed.push(Parsed {
            url: url.to_string(),
            body: body.into(),
            index: Arc::clone(&index),
            used,
        });
        Ok(index)
    }

    /// The index kept for `url`, when it was parsed from `body`.
    fn lookup(url: &str, body: &[u8]) -> Option<Arc<Index>> {
        let (kept, index) = {
            let state = STATE.lock().unwrap_or_else(PoisonError::into_inner);
            let p = state.parsed.iter().find(|p| p.url == url)?;
            (Arc::clone(&p.body), Arc::clone(&p.index))
        };
        // Compared outside the lock: a large index takes a moment.
        if *kept != *body {
            return None;
        }
        let mut state = STATE.lock().unwrap_or_else(PoisonError::into_inner);
        state.clock += 1;
        let now = state.clock;
        if let Some(p) = state
            .parsed
            .iter_mut()
            .find(|p| p.url == url && Arc::ptr_eq(&p.index, &index))
        {
            p.used = now;
        }
        Some(index)
    }
}

/// Read an `index.yaml` (or a JSON one: JSON is YAML). Entries that are not
/// a valid chart version (name, version) are left out.
fn parse_index(body: &[u8]) -> Result<Index, String> {
    let text = std::str::from_utf8(body).map_err(|_| "not UTF-8".to_string())?;
    let docs = crate::yaml::load(text).map_err(|e| format!("not YAML: {e}"))?;
    let doc = docs.first().map(to_json).unwrap_or(Value::Null);
    let Some(entries) = doc.get("entries").and_then(Value::as_object) else {
        // An empty repository may write `entries: {}` or leave it out, but
        // a document without `apiVersion` is no chart repository index.
        return match doc.get("apiVersion") {
            Some(_) => Ok(Index::new()),
            None => Err("not a chart repository index (no apiVersion)".into()),
        };
    };
    let mut index = Index::new();
    for versions in entries.values() {
        let Some(versions) = versions.as_array() else {
            continue;
        };
        for entry in versions {
            let Some(metadata) = entry.as_object() else {
                continue;
            };
            let (Some(name), Some(version)) = (
                metadata.get("name").and_then(Value::as_str),
                metadata.get("version").and_then(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                }),
            ) else {
                continue;
            };
            let (true, Ok(version)) = (chart::valid_name(name), Version::parse(&version)) else {
                continue;
            };
            index
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(Entry {
                    name: name.to_string(),
                    version,
                    created: metadata
                        .get("created")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    url: metadata
                        .get("urls")
                        .and_then(Value::as_array)
                        .and_then(|urls| urls.first())
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    metadata: serde_json::to_string(metadata).unwrap_or_default().into(),
                });
        }
    }
    for versions in index.values_mut() {
        versions.sort_by(|a, b| a.version.cmp(&b.version));
        versions.dedup_by(|a, b| a.version == b.version);
    }
    Ok(index)
}

/// Where a version's archive is: the first of its `urls`, resolved against
/// the repository (`charts/x-1.0.0.tgz`, `/x-1.0.0.tgz`, or absolute). A
/// version the index does not list gets the conventional
/// `{base}/{name}-{version}.tgz`, which an upstream without it answers with
/// a 404.
fn package_url(base: &str, index: &Index, target: &PackageRef) -> String {
    let listed = index.get(&target.id).and_then(|versions| {
        versions
            .iter()
            .find(|e| e.version.to_string() == target.version)
    });
    let url = listed.and_then(|e| e.url.clone());
    match url {
        Some(url) => resolve(base, &url),
        None => format!("{base}/{}-{}.tgz", target.id, target.version),
    }
}

/// `url` resolved against the repository's base URL.
fn resolve(base: &str, url: &str) -> String {
    if url.starts_with("https://") || url.starts_with("http://") {
        return url.to_string();
    }
    if let Some(path) = url.strip_prefix('/') {
        // Relative to the host: keep the base's scheme and authority.
        let authority_end = base
            .find("://")
            .map(|i| i + 3)
            .and_then(|start| base[start..].find('/').map(|end| start + end))
            .unwrap_or(base.len());
        return format!("{}/{path}", &base[..authority_end]);
    }
    format!("{base}/{}", url.trim_start_matches("./"))
}

/// The index's metadata of `wanted.versions`: every chart version is
/// listed, published and created when its entry says (`created`), and
/// summarized like its Chart.yaml.
fn metadata(index: &Index, wanted: &PackageVersions, dating: bool) -> UpstreamStep {
    let Some(versions) = index.get(&wanted.id) else {
        return done(UpstreamAnswer::Metadata(PackageMetadata::default()));
    };
    done(UpstreamAnswer::Metadata(PackageMetadata {
        // The name the newest version is published under.
        original_id: versions.last().map(|e| e.name.clone()),
        versions: versions
            .iter()
            .filter(|e| wanted.versions.contains(&e.version.to_string()))
            .map(|e| VersionMetadata {
                version: e.version.to_string(),
                original_id: Some(e.name.clone()),
                listed: true,
                published: e.created.clone(),
                created: if dating { e.created.clone() } else { None },
                summary: Some(crate::summary(&e.metadata())),
            })
            .collect(),
    }))
}

/// A page of the charts whose name matches `query`: each term must match,
/// `id:x` and `packageid:x` exactly, any other as a part of the name.
fn search(index: &Index, query: &SearchQuery) -> UpstreamSearch {
    let terms: Vec<String> = query
        .text
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    let matches = |name: &str| {
        terms.iter().all(|term| {
            match term
                .strip_prefix("packageid:")
                .or_else(|| term.strip_prefix("id:"))
            {
                Some(exact) => name == exact,
                None => name.contains(term.as_str()),
            }
        })
    };
    let matched: Vec<&Vec<Entry>> = index
        .iter()
        .filter(|(name, _)| matches(name))
        .map(|(_, versions)| versions)
        .filter(|versions| !versions.is_empty())
        .collect();
    let take = match query.take {
        0 => DEFAULT_TAKE,
        n => usize::try_from(n).unwrap_or(usize::MAX),
    };
    let hits = matched
        .iter()
        .skip(usize::try_from(query.skip).unwrap_or(usize::MAX))
        .take(take)
        .map(|versions| {
            let newest = versions.last().expect("non-empty");
            UpstreamHit {
                id: newest.name.clone(),
                versions: versions.iter().map(|e| e.version.to_string()).collect(),
                summary: Some(crate::summary(&newest.metadata())),
                total_downloads: None,
            }
        })
        .collect();
    UpstreamSearch {
        total: matched.len() as u64,
        hits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_resolve_against_the_repository() {
        let base = "https://charts.example/stable";
        assert_eq!(
            resolve(base, "charts/x-1.0.0.tgz"),
            "https://charts.example/stable/charts/x-1.0.0.tgz"
        );
        assert_eq!(
            resolve(base, "./x-1.0.0.tgz"),
            "https://charts.example/stable/x-1.0.0.tgz"
        );
        assert_eq!(
            resolve(base, "/dl/x-1.0.0.tgz"),
            "https://charts.example/dl/x-1.0.0.tgz"
        );
        assert_eq!(
            resolve(base, "https://cdn.example/x-1.0.0.tgz"),
            "https://cdn.example/x-1.0.0.tgz"
        );
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn a_parsed_index_is_kept_while_the_upstream_serves_the_same_document() {
        let url = "https://kept.example/stable/index.yaml";
        let body = "apiVersion: v1\nentries:\n  demo:\n    - name: demo\n      version: 1.0.0\n";
        // Concurrent operations on a new document share one parse.
        let first: Vec<Arc<Index>> = std::thread::scope(|s| {
            let parses: Vec<_> = (0..8)
                .map(|_| s.spawn(|| parsed_index(url, body.as_bytes()).unwrap()))
                .collect();
            parses.into_iter().map(|p| p.join().unwrap()).collect()
        });
        assert!(first.iter().all(|p| Arc::ptr_eq(p, &first[0])));
        assert!(Arc::ptr_eq(
            &parsed_index(url, body.as_bytes()).unwrap(),
            &first[0]
        ));

        // A changed document is parsed again.
        let changed = format!("{body}    - name: demo\n      version: 2.0.0\n");
        let again = parsed_index(url, changed.as_bytes()).unwrap();
        assert!(!Arc::ptr_eq(&again, &first[0]));
        assert_eq!(again["demo"].len(), 2);

        // A few are kept: more push the least recently used out.
        for n in 0..parsed::KEPT {
            parsed_index(
                &format!("https://other{n}.example/index.yaml"),
                body.as_bytes(),
            )
            .unwrap();
        }
        let evicted = parsed_index(url, changed.as_bytes()).unwrap();
        assert!(!Arc::ptr_eq(&evicted, &again));
    }

    #[test]
    fn an_index_keeps_valid_chart_versions() {
        let index = parse_index(
            b"apiVersion: v1\nentries:\n  Demo:\n    - name: Demo\n      version: v1.2\n    - name: Demo\n      version: 1.0.0\n    - name: Demo\n      version: not-a-version\n  ../evil:\n    - name: ../evil\n      version: 1.0.0\n",
        )
        .unwrap();
        assert_eq!(index.keys().collect::<Vec<_>>(), ["demo"]);
        let versions: Vec<String> = index["demo"]
            .iter()
            .map(|e| e.version.to_string())
            .collect();
        assert_eq!(versions, ["1.0.0", "1.2.0"]);
        assert!(parse_index(b"apiVersion: v1\n").unwrap().is_empty());
        assert!(parse_index(b"<html>portal</html>").is_err());
    }
}
