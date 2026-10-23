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
/// The built-in plugin keeps what it parsed, one index per URL, as many as
/// fit in [`parsed::BUDGET`] (one budget for every Helm proxy of the
/// process), and reuses one while the upstream serves the same bytes (the
/// host hands every operation the document it caches for the metadata TTL):
/// comparing the bytes takes a millisecond where parsing takes half a second.
/// Since the result depends on the bytes alone, it is the same for every
/// repository that fetches them. Parses run one at a time: concurrent
/// operations on a document nobody has parsed yet wait for the first parse
/// instead of each running their own, and memory holds one parse at most.
///
/// A group asks its members in turn for every chart, so the indexes of all
/// its upstreams are in use at once. Making room by evicting the least
/// recently used would evict the very index the group asks for next, and
/// every chart would parse every member's index again. So only an index
/// nobody used for [`parsed::IDLE`] makes room for a new one; while every
/// kept index is in use, a new one that does not fit is served without
/// being kept. Past the budget, a group keeps the indexes that fit and
/// parses only the others for each chart.
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
    use std::time::{Duration, Instant};

    use super::{parse_index, Index};

    /// What the kept indexes may hold together ([`retained`]), about twice
    /// the size of their documents, so about 60 MB of `index.yaml`: the
    /// indexes of a few dozen typical chart repositories, or of a handful of
    /// the largest public ones. A new index that does not fit takes the
    /// place of kept ones that went unused for [`IDLE`], or is not kept. One
    /// that alone is larger is kept while nothing else is.
    pub(super) const BUDGET: usize = 128 * 1024 * 1024;

    /// How long a kept index must go unused before a new one may take its
    /// place. A group's listing uses each of its members' indexes for every
    /// chart, so the ones it keeps stay in place until it is done.
    pub(super) const IDLE: Duration = Duration::from_secs(60);

    /// A parsed index and the bytes it was parsed from.
    pub(super) struct Parsed {
        url: String,
        body: Arc<[u8]>,
        index: Arc<Index>,
        /// What it holds ([`retained`]).
        bytes: usize,
        /// When it was last used.
        used: Instant,
    }

    impl Parsed {
        pub(super) fn new(url: &str, body: &[u8], index: Arc<Index>, now: Instant) -> Self {
            Self {
                url: url.to_string(),
                bytes: retained(body, &index),
                body: body.into(),
                index,
                used: now,
            }
        }
    }

    pub(super) struct State {
        parsed: Vec<Parsed>,
    }

    impl State {
        pub(super) const fn new() -> Self {
            Self { parsed: Vec::new() }
        }

        /// The bytes and the index kept for `url`.
        pub(super) fn find(&self, url: &str) -> Option<(Arc<[u8]>, Arc<Index>)> {
            let p = self.parsed.iter().find(|p| p.url == url)?;
            Some((Arc::clone(&p.body), Arc::clone(&p.index)))
        }

        /// Marks `index`, kept for `url`, as used at `now`.
        pub(super) fn touch(&mut self, url: &str, index: &Arc<Index>, now: Instant) {
            if let Some(p) = self
                .parsed
                .iter_mut()
                .find(|p| p.url == url && Arc::ptr_eq(&p.index, index))
            {
                p.used = now;
            }
        }

        /// Keeps `parsed` as the index of its URL, if it fits in `budget`
        /// once the others unused for [`IDLE`] since it was parsed gave way,
        /// the least recently used first, or nothing else is kept. Returns
        /// the indexes it does not keep, `parsed` among them when it does
        /// not fit.
        pub(super) fn keep(&mut self, parsed: Parsed, budget: usize) -> Vec<Parsed> {
            let now = parsed.used;
            let mut removed = Vec::new();
            if let Some(i) = self.parsed.iter().position(|p| p.url == parsed.url) {
                removed.push(self.parsed.swap_remove(i));
            }
            let mut total: usize = self.parsed.iter().map(|p| p.bytes).sum();
            while total + parsed.bytes > budget {
                let Some(oldest) = (0..self.parsed.len())
                    .filter(|&i| now.saturating_duration_since(self.parsed[i].used) >= IDLE)
                    .min_by_key(|&i| self.parsed[i].used)
                else {
                    break;
                };
                let oldest = self.parsed.swap_remove(oldest);
                total -= oldest.bytes;
                removed.push(oldest);
            }
            if total + parsed.bytes > budget && !self.parsed.is_empty() {
                // The kept ones are in use: keeping this one would push out
                // what the next operation asks for.
                removed.push(parsed);
            } else {
                self.parsed.push(parsed);
            }
            removed
        }
    }

    static STATE: Mutex<State> = Mutex::new(State::new());

    /// Held while an index is parsed.
    static PARSING: Mutex<()> = Mutex::new(());

    pub(super) fn get_or_parse(url: &str, body: &[u8]) -> Result<Arc<Index>, String> {
        get_or_parse_in(&STATE, url, body, Instant::now, BUDGET)
    }

    /// [`get_or_parse`] with the indexes kept in `state`, the time from
    /// `clock`, and `budget`.
    pub(super) fn get_or_parse_in(
        state: &Mutex<State>,
        url: &str,
        body: &[u8],
        clock: impl Fn() -> Instant,
        budget: usize,
    ) -> Result<Arc<Index>, String> {
        if let Some(index) = lookup(state, url, body, clock()) {
            return Ok(index);
        }
        let _parsing = PARSING.lock().unwrap_or_else(PoisonError::into_inner);
        // Parsed while this one waited.
        if let Some(index) = lookup(state, url, body, clock()) {
            return Ok(index);
        }
        let index = Arc::new(parse_index(body)?);
        // Sized, copied and dropped outside the lock: a large index takes a
        // moment.
        let parsed = Parsed::new(url, body, Arc::clone(&index), clock());
        let removed = state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keep(parsed, budget);
        drop(removed);
        Ok(index)
    }

    /// The index kept in `state` for `url`, when it was parsed from `body`.
    fn lookup(state: &Mutex<State>, url: &str, body: &[u8], now: Instant) -> Option<Arc<Index>> {
        let (kept, index) = state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .find(url)?;
        // Compared outside the lock: a large index takes a moment.
        if *kept != *body {
            return None;
        }
        state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .touch(url, &index, now);
        Some(index)
    }

    /// About what `index`, parsed from `body`, holds while kept: the
    /// document and the entries.
    pub(super) fn retained(body: &[u8], index: &Index) -> usize {
        let entries: usize = index
            .iter()
            .map(|(name, versions)| {
                name.len()
                    + versions
                        .iter()
                        .map(|e| {
                            std::mem::size_of_val(e)
                                + e.name.len()
                                + e.created.as_ref().map_or(0, String::len)
                                + e.url.as_ref().map_or(0, String::len)
                                + e.metadata.len()
                        })
                        .sum::<usize>()
            })
            .sum();
        body.len() + entries
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
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn a_group_of_many_upstreams_parses_each_index_once() {
        // A group asks its members in turn for every chart: each member's
        // index is parsed for the first chart and kept for the others.
        let body = "apiVersion: v1\nentries:\n  demo:\n    - name: demo\n      version: 1.0.0\n";
        let urls: Vec<String> = (0..12)
            .map(|n| format!("https://member{n}.example/index.yaml"))
            .collect();
        let first: Vec<Arc<Index>> = urls
            .iter()
            .map(|url| parsed_index(url, body.as_bytes()).unwrap())
            .collect();
        for _chart in 0..3 {
            for (url, first) in urls.iter().zip(&first) {
                assert!(Arc::ptr_eq(
                    &parsed_index(url, body.as_bytes()).unwrap(),
                    first
                ));
            }
        }
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn kept_indexes_fit_in_the_budget() {
        use std::time::{Duration, Instant};

        let body = b"apiVersion: v1\nentries:\n  demo:\n    - name: demo\n      version: 1.0.0\n";
        let index = Arc::new(parse_index(body).unwrap());
        let one = parsed::retained(body, &index);
        assert!(one > body.len());
        let kept = |state: &parsed::State| -> Vec<&str> {
            ["a", "b", "c", "d", "e"]
                .into_iter()
                .filter(|url| state.find(url).is_some())
                .collect()
        };
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let parsed = |url, secs| parsed::Parsed::new(url, body, Arc::clone(&index), at(secs));

        let mut state = parsed::State::new();
        for (secs, url) in [(0, "a"), (1, "b"), (2, "c")] {
            state.keep(parsed(url, secs), 3 * one);
        }
        assert_eq!(kept(&state), ["a", "b", "c"]);
        // While the kept ones are in use, one that does not fit is not kept.
        state.touch("a", &index, at(30));
        state.keep(parsed("d", 31), 3 * one);
        assert_eq!(kept(&state), ["a", "b", "c"]);
        // One unused for IDLE gives way, the least recently used first.
        let later = 2 + parsed::IDLE.as_secs();
        state.keep(parsed("d", later), 3 * one);
        assert_eq!(kept(&state), ["a", "c", "d"]);
        // A document parsed again replaces the index of its URL.
        state.keep(parsed("c", later), 3 * one);
        assert_eq!(kept(&state), ["a", "c", "d"]);

        // An index larger than the budget is kept while nothing else is.
        let mut state = parsed::State::new();
        state.keep(parsed("e", 0), one - 1);
        assert_eq!(kept(&state), ["e"]);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn a_group_past_the_budget_parses_only_the_indexes_that_do_not_fit() {
        use std::cell::Cell;
        use std::sync::Mutex;
        use std::time::{Duration, Instant};

        let body = b"apiVersion: v1\nentries:\n  demo:\n    - name: demo\n      version: 1.0.0\n";
        let one = parsed::retained(body, &parse_index(body).unwrap());
        let state = Mutex::new(parsed::State::new());
        let start = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let clock = || start + elapsed.get();
        let members: Vec<String> = (0..6)
            .map(|n| format!("https://member{n}.example/index.yaml"))
            .collect();
        let mut last: Vec<Option<Arc<Index>>> = vec![None; members.len()];
        // Asks the members from `first` on for `charts` charts in turn,
        // 10 ms apart, as a group's listing does; how many indexes that
        // parsed.
        let mut list = |first: usize, charts: usize| {
            let mut parses = 0;
            for _ in 0..charts {
                for (m, url) in members.iter().enumerate().skip(first) {
                    elapsed.set(elapsed.get() + Duration::from_millis(10));
                    let index = parsed::get_or_parse_in(&state, url, body, clock, 4 * one).unwrap();
                    if !last[m].as_ref().is_some_and(|l| Arc::ptr_eq(l, &index)) {
                        parses += 1;
                    }
                    last[m] = Some(index);
                }
            }
            parses
        };

        // Four of the six indexes fit: those are parsed once, the other two
        // for every chart.
        assert_eq!(list(0, 50), 4 + 2 * 50);
        // Once members 0 and 1 go unused, 4 and 5 take their places.
        elapsed.set(elapsed.get() + parsed::IDLE);
        assert_eq!(list(2, 50), 2);
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

    #[test]
    fn an_index_leaves_out_versions_longer_than_an_oci_tag() {
        let longest = format!(
            "1.0.0-{}",
            "a".repeat(crate::semver::MAX_VERSION_LENGTH - 6)
        );
        let mut body = String::from("apiVersion: v1\nentries:\n  demo:\n");
        for version in [
            "1.0.0".to_string(),
            longest.clone(),
            format!("{longest}a"),
            format!("2.0.0-{}", "x".repeat(4096)),
        ] {
            body.push_str(&format!("    - name: demo\n      version: {version}\n"));
        }
        let index = parse_index(body.as_bytes()).unwrap();
        let versions: Vec<String> = index["demo"]
            .iter()
            .map(|e| e.version.to_string())
            .collect();
        assert_eq!(versions, [longest, "1.0.0".to_string()]);
    }
}
