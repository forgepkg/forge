//! The upstream side of NuGet proxies: a NuGet V3 feed, read through the
//! host ([`FormatPlugin::upstream`](forge_plugin_api::FormatPlugin::upstream)).
//!
//! The upstream's index is its service index's resources: the flat
//! container (`PackageBaseAddress`), the registration (`RegistrationsBaseUrl`,
//! preferring the SemVer 2.0.0 variants) and the search service
//! (`SearchQueryService`). Every operation is a short conversation: the
//! first call asks for the documents it needs, the next reads them (and may
//! ask for more), and the host performs, caches and bounds every request.

use std::collections::BTreeMap;

use forge_plugin_api::{
    Fetch, FetchResult, Fetched, FormatError, Freshness, PackageMetadata, PackageRef,
    PackageVersions, Remote, SearchQuery, UpstreamAnswer, UpstreamHit, UpstreamOp, UpstreamSearch,
    UpstreamStep, VersionMetadata,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{Dependency, DependencyGroup, NupkgLimits};
use crate::{nuspec, version};

/// At most this many non-inlined registration pages are read for a
/// registration (newest first). nuget.org pages hold 64 versions, so this
/// covers the newest ~640; older versions of a larger package are served
/// with the listing's metadata.
const MAX_REGISTRATION_PAGES: usize = 10;
/// Dating the package delay reads every registration page that covers a
/// version still inside it, up to this many (8192 versions on nuget.org). It
/// runs when a listing is refreshed, and a version leaves the delay once
/// dated, so a package's older pages are read about once.
const MAX_DATING_REGISTRATION_PAGES: usize = 128;
/// At most this many catalog entries are read per dating to date unlisted
/// versions; the rest are dated at the next refresh.
const MAX_CATALOG_FETCHES: usize = 32;

/// The resources of a V3 service index: the upstream's index
/// ([`Remote::index`]). The base-address style resources keep a trailing
/// slash, so path segments append directly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    /// `PackageBaseAddress/3.0.0` (the flat container).
    pub package_base_address: Option<String>,
    /// `RegistrationsBaseUrl`, any 3.x variant.
    pub registrations_base_url: Option<String>,
    /// `SearchQueryService`, any 3.x variant.
    pub search_query_service: Option<String>,
}

impl Resources {
    /// The resources a V3 service-index document advertises.
    ///
    /// Picks the first match for each resource family, accepting any
    /// `@type` of the family (NuGet advertises versioned aliases like
    /// `SearchQueryService/3.5.0`); of the registrations, a SemVer 2.0.0
    /// variant (`3.6.0`, `Versioned`), which lists every version, wins over
    /// the older ones, which omit SemVer 2.0.0 packages.
    pub fn from_service_index(doc: &Value) -> Self {
        let mut out = Resources::default();
        let mut registration_rank = 0;
        let Some(resources) = doc.get("resources").and_then(Value::as_array) else {
            return out;
        };
        for res in resources {
            let Some(id) = res.get("@id").and_then(Value::as_str) else {
                continue;
            };
            // `@type` can be a string or an array of strings.
            let types: Vec<&str> = match res.get("@type") {
                Some(Value::String(s)) => vec![s.as_str()],
                Some(Value::Array(arr)) => arr.iter().filter_map(Value::as_str).collect(),
                _ => continue,
            };
            for ty in types {
                let family = ty.split('/').next().unwrap_or(ty);
                match family {
                    "PackageBaseAddress" if out.package_base_address.is_none() => {
                        out.package_base_address = Some(with_trailing_slash(id));
                    }
                    "RegistrationsBaseUrl" => {
                        let rank = match ty {
                            "RegistrationsBaseUrl/3.6.0" => 3,
                            "RegistrationsBaseUrl/Versioned" => 2,
                            _ => 1,
                        };
                        if rank > registration_rank {
                            registration_rank = rank;
                            out.registrations_base_url = Some(with_trailing_slash(id));
                        }
                    }
                    "SearchQueryService" if out.search_query_service.is_none() => {
                        out.search_query_service = Some(id.to_string());
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

fn with_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{s}/")
    }
}

/// One step of the conversation for `op` ([`crate::Nuget`]'s
/// `FormatPlugin::upstream`).
pub(crate) fn step(
    remote: &Remote,
    op: &UpstreamOp,
    fetched: &[FetchResult],
    limits: &NupkgLimits,
) -> Result<UpstreamStep, FormatError> {
    if let UpstreamOp::Index = op {
        return Ok(index(&remote.url, fetched));
    }
    let Some(resources) = remote
        .index
        .as_deref()
        .and_then(|index| serde_json::from_str::<Resources>(index).ok())
    else {
        return Ok(failed("the upstream's service index is not resolved"));
    };
    Ok(match op {
        UpstreamOp::Index => unreachable!("answered above"),
        UpstreamOp::Versions(id) => versions(&resources, id, fetched),
        UpstreamOp::Package(target) => match &resources.package_base_address {
            Some(base) => done(UpstreamAnswer::Package(package_url(base, target, "nupkg"))),
            None => failed("upstream advertises no PackageBaseAddress"),
        },
        UpstreamOp::Manifest(target) => manifest(&resources, target, fetched, limits),
        UpstreamOp::Metadata(wanted) => metadata(&resources, wanted, false, fetched),
        UpstreamOp::Dating(wanted) => metadata(&resources, wanted, true, fetched),
        UpstreamOp::Search(query) => search(&resources, query, fetched),
        // A feed holds packages: it has no files to fetch.
        UpstreamOp::File(_) => done(UpstreamAnswer::File(None)),
        // NuGet has no tags.
        UpstreamOp::Tags(_) => done(UpstreamAnswer::Tags(None)),
        UpstreamOp::ImageName(_)
        | UpstreamOp::ImageManifest { .. }
        | UpstreamOp::ImageBlob { .. }
        | UpstreamOp::ImageTags { .. }
        | UpstreamOp::ImageReferrers { .. } => failed("a feed holds no images"),
    })
}

fn done(answer: UpstreamAnswer) -> UpstreamStep {
    UpstreamStep::Done(answer)
}

fn failed(reason: impl Into<String>) -> UpstreamStep {
    done(UpstreamAnswer::Failed(reason.into()))
}

fn get(url: &str, freshness: Freshness) -> Fetch {
    Fetch::new(url, freshness)
}

/// How the fetch of `url` went, if it has been fetched.
fn outcome<'a>(fetched: &'a [FetchResult], url: &str) -> Option<&'a Fetched> {
    fetched
        .iter()
        .find(|f| f.fetch.url == url)
        .map(|f| &f.outcome)
}

/// A fetched JSON document: `Ok(None)` while not fetched yet, `Err` with
/// the reason when it is not usable.
enum Doc {
    Wanted,
    Found(Value),
    NotFound,
    Failed(String),
}

fn json(fetched: &[FetchResult], url: &str) -> Doc {
    match outcome(fetched, url) {
        None => Doc::Wanted,
        Some(Fetched::Found(body)) => match serde_json::from_slice(body) {
            Ok(doc) => Doc::Found(doc),
            Err(e) => Doc::Failed(format!("invalid JSON from {url}: {e}")),
        },
        Some(Fetched::NotFound) => Doc::NotFound,
        Some(Fetched::Failed(reason)) => Doc::Failed(reason.clone()),
    }
}

/// The service index of `url`, as the upstream's index. One without a
/// package base address is not a NuGet V3 service index (a captive portal,
/// a gateway's error page, a mistyped URL): an upstream failure, so the
/// host keeps the last good index rather than taking it for an empty feed.
fn index(url: &str, fetched: &[FetchResult]) -> UpstreamStep {
    match json(fetched, url) {
        Doc::Wanted => UpstreamStep::Fetch(vec![get(url, Freshness::Metadata)]),
        Doc::Found(doc) => {
            let resources = Resources::from_service_index(&doc);
            if resources.package_base_address.is_none() {
                return failed(format!(
                    "upstream service index {url} advertises no PackageBaseAddress"
                ));
            }
            match serde_json::to_string(&resources) {
                Ok(index) => done(UpstreamAnswer::Index(index)),
                Err(e) => failed(format!("serialize the service index: {e}")),
            }
        }
        Doc::NotFound => failed(format!("upstream service index {url} returned 404")),
        Doc::Failed(reason) => failed(reason),
    }
}

/// The flat-container URL of a version's `.nupkg` or `.nuspec`.
fn package_url(base: &str, target: &PackageRef, kind: &str) -> String {
    let (id, v) = (&target.id, &target.version);
    match kind {
        "nupkg" => format!("{base}{id}/{v}/{id}.{v}.nupkg"),
        _ => format!("{base}{id}/{v}/{id}.nuspec"),
    }
}

/// The flat-container version listing of `id`. A document without a
/// `versions` array is not a listing: an upstream failure, never "no
/// versions", which would retire them all.
fn versions(resources: &Resources, id: &str, fetched: &[FetchResult]) -> UpstreamStep {
    let Some(base) = &resources.package_base_address else {
        return failed("upstream advertises no PackageBaseAddress");
    };
    let url = format!("{base}{id}/index.json");
    match json(fetched, &url) {
        Doc::Wanted => UpstreamStep::Fetch(vec![get(&url, Freshness::Metadata)]),
        Doc::Found(doc) => {
            let Some(listed) = doc.get("versions").and_then(Value::as_array) else {
                return failed(format!("upstream listing {url} has no versions array"));
            };
            let versions = listed
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|raw| version::normalize(raw).ok())
                .collect();
            done(UpstreamAnswer::Versions(Some(versions)))
        }
        Doc::NotFound => done(UpstreamAnswer::Versions(None)),
        Doc::Failed(reason) => failed(reason),
    }
}

/// The flat container's `.nuspec` of a version, served only when it declares
/// exactly that version (the upstream controls these bytes and where its
/// redirects lead). A published manifest never changes.
fn manifest(
    resources: &Resources,
    target: &PackageRef,
    fetched: &[FetchResult],
    limits: &NupkgLimits,
) -> UpstreamStep {
    let Some(base) = &resources.package_base_address else {
        return failed("upstream advertises no PackageBaseAddress");
    };
    let url = package_url(base, target, "nuspec");
    match outcome(fetched, &url) {
        None => UpstreamStep::Fetch(vec![get(&url, Freshness::Immutable)]),
        Some(Fetched::Found(bytes)) => match nuspec::manifest_identity(bytes, limits) {
            Ok((id, v)) if id == target.id && v == target.version => {
                done(UpstreamAnswer::Manifest(Some(bytes.clone())))
            }
            // Another package's manifest, or none: the host reads the
            // package itself, whose identity it verifies the same way.
            _ => done(UpstreamAnswer::Manifest(None)),
        },
        Some(Fetched::NotFound) => done(UpstreamAnswer::Manifest(None)),
        Some(Fetched::Failed(reason)) => failed(reason.clone()),
    }
}

/// One version's metadata from the upstream registration (a leaf's inlined
/// `catalogEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Leaf {
    /// The id as the upstream publishes it (original casing).
    id: Option<String>,
    listed: bool,
    published: Option<String>,
    groups: Vec<DependencyGroup>,
    /// The `@id` of the version's catalog entry, which names when the
    /// version was created even when it is unlisted.
    catalog_url: Option<String>,
}

/// One page of a registration index.
#[derive(Debug)]
struct Page {
    /// The page `@id`, read when its leaves are not inlined.
    url: Option<String>,
    /// Normalized lowest / highest version on the page (`None` = unknown).
    lower: Option<String>,
    upper: Option<String>,
    /// Inlined leaves by normalized version; `None` ⇒ read [`Self::url`].
    leaves: Option<BTreeMap<String, Leaf>>,
}

/// The upstream registration's metadata of `wanted.versions`: inlined
/// leaves cost no request; of the pages covering a wanted version, the
/// newest are read (up to [`MAX_REGISTRATION_PAGES`], or
/// [`MAX_DATING_REGISTRATION_PAGES`] when dating). Dating also reads the
/// catalog entries of unlisted versions ([`MAX_CATALOG_FETCHES`]). Best
/// effort: what cannot be read is left out.
fn metadata(
    resources: &Resources,
    wanted: &PackageVersions,
    dating: bool,
    fetched: &[FetchResult],
) -> UpstreamStep {
    let Some(base) = &resources.registrations_base_url else {
        return done(UpstreamAnswer::Metadata(PackageMetadata::default()));
    };
    let index_url = format!("{base}{}/index.json", wanted.id);
    let index = match json(fetched, &index_url) {
        Doc::Wanted => {
            return UpstreamStep::Fetch(vec![get(&index_url, Freshness::Metadata)]);
        }
        Doc::Found(doc) => doc,
        Doc::NotFound => return done(UpstreamAnswer::Metadata(PackageMetadata::default())),
        Doc::Failed(reason) => return failed(format!("registration {index_url}: {reason}")),
    };
    let pages = registration_pages(&index);
    // The newest version the index names (the highest page `upper`),
    // whether or not its leaf is read.
    let newest = pages
        .iter()
        .filter_map(|page| page.upper.clone())
        .max_by(|a, b| version::compare(a, b));

    let mut leaves: BTreeMap<String, Leaf> = BTreeMap::new();
    let mut to_read: Vec<(Option<String>, String)> = Vec::new();
    for page in pages {
        match page.leaves {
            Some(inlined) => leaves.extend(inlined),
            None => {
                let covers = wanted.versions.iter().any(|v| {
                    page.lower
                        .as_deref()
                        .is_none_or(|lo| version::compare(lo, v).is_le())
                        && page
                            .upper
                            .as_deref()
                            .is_none_or(|hi| version::compare(v, hi).is_le())
                });
                if let (true, Some(url)) = (covers, page.url) {
                    to_read.push((page.upper, url));
                }
            }
        }
    }
    // Newest pages first; an unknown upper bound sorts last.
    to_read.sort_by(|a, b| match (&a.0, &b.0) {
        (Some(x), Some(y)) => version::compare(y, x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    to_read.truncate(if dating {
        MAX_DATING_REGISTRATION_PAGES
    } else {
        MAX_REGISTRATION_PAGES
    });
    let unread: Vec<Fetch> = to_read
        .iter()
        .filter(|(_, url)| outcome(fetched, url).is_none())
        .map(|(_, url)| get(url, Freshness::Metadata))
        .collect();
    if !unread.is_empty() {
        return UpstreamStep::Fetch(unread);
    }
    for (_, url) in &to_read {
        // A page that cannot be read leaves its versions to the listing.
        if let Doc::Found(page) = json(fetched, url) {
            leaves.extend(registration_leaves(&page));
        }
    }
    // A leaf naming another package is not this package's metadata.
    leaves.retain(|_, leaf| {
        leaf.id
            .as_deref()
            .is_none_or(|id| nuspec::lower_id(id) == wanted.id)
    });

    // Each version keeps the casing it was pushed with (`jQuery` /
    // `jquery`), so the package's casing is its newest version's, the one
    // nuget.org shows, and only when that leaf was read: taking any leaf
    // made the casing, and search, flip between reads.
    let original_id = leaves
        .iter()
        .filter_map(|(version, leaf)| leaf.id.as_deref().map(|id| (version, id)))
        .max_by(|(a, _), (b, _)| version::compare(a, b))
        .filter(|(version, _)| {
            newest
                .as_deref()
                .is_none_or(|newest| version::compare(version, newest).is_ge())
        })
        .map(|(_, id)| id.to_string());

    let wanted_leaves: Vec<(&String, &Leaf)> = leaves
        .iter()
        .filter(|(version, _)| wanted.versions.contains(version))
        .collect();

    // When an unlisted version was created: its catalog entry says (its
    // registration's publish time is nuget.org's 1900 marker).
    let mut created: BTreeMap<&str, String> = BTreeMap::new();
    if dating {
        let catalogs: Vec<(&String, &str)> = wanted_leaves
            .iter()
            .filter(|(_, leaf)| !leaf.listed)
            .filter_map(|(version, leaf)| Some((*version, leaf.catalog_url.as_deref()?)))
            .take(MAX_CATALOG_FETCHES)
            .collect();
        let unread: Vec<Fetch> = catalogs
            .iter()
            .filter(|(_, url)| outcome(fetched, url).is_none())
            .map(|(_, url)| get(url, Freshness::Immutable))
            .collect();
        if !unread.is_empty() {
            return UpstreamStep::Fetch(unread);
        }
        for (version, url) in catalogs {
            if let Doc::Found(entry) = json(fetched, url) {
                if let Some(at) = entry.get("created").and_then(Value::as_str) {
                    created.insert(version.as_str(), at.to_string());
                }
            }
        }
    }

    let versions = wanted_leaves
        .into_iter()
        .map(|(version, leaf)| {
            let manifest = nuspec::synthesize_nuspec(
                leaf.id.as_deref().unwrap_or(&wanted.id),
                version,
                &leaf.groups,
            );
            VersionMetadata {
                version: version.clone(),
                original_id: leaf.id.clone(),
                listed: leaf.listed,
                published: leaf.published.clone(),
                created: dating
                    .then(|| match leaf.listed {
                        true => leaf.published.clone(),
                        false => created.get(version.as_str()).cloned(),
                    })
                    .flatten(),
                summary: nuspec::manifest_summary(&manifest)
                    .ok()
                    .and_then(|summary| serde_json::to_string(&summary).ok()),
            }
        })
        .collect();
    done(UpstreamAnswer::Metadata(PackageMetadata {
        original_id,
        versions,
    }))
}

/// The pages of a registration index document (`items[]`).
fn registration_pages(doc: &Value) -> Vec<Page> {
    let normalize = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .and_then(|raw| version::normalize(raw).ok())
    };
    doc.get("items")
        .and_then(Value::as_array)
        .map(|pages| {
            pages
                .iter()
                .map(|page| Page {
                    url: page.get("@id").and_then(Value::as_str).map(str::to_string),
                    lower: normalize(page.get("lower")),
                    upper: normalize(page.get("upper")),
                    leaves: page
                        .get("items")
                        .filter(|items| items.is_array())
                        .map(|_| registration_leaves(page)),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The leaves (`items[]`) of a registration page, by normalized version. A
/// leaf whose `catalogEntry` is not inlined carries no metadata and is
/// skipped.
fn registration_leaves(page: &Value) -> BTreeMap<String, Leaf> {
    let mut out = BTreeMap::new();
    let Some(items) = page.get("items").and_then(Value::as_array) else {
        return out;
    };
    for item in items {
        let Some(entry) = item.get("catalogEntry").filter(|e| e.is_object()) else {
            continue;
        };
        let Some(version) = entry
            .get("version")
            .and_then(Value::as_str)
            .and_then(|raw| version::normalize(raw).ok())
        else {
            continue;
        };
        let published = entry
            .get("published")
            .and_then(Value::as_str)
            .map(str::to_string);
        // `listed` is optional; NuGet clients then treat nuget.org's
        // 1900-01-01 `published` marker as unlisted.
        let listed = entry
            .get("listed")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| published.as_deref().and_then(year).is_none_or(|y| y > 1900));
        let groups = entry
            .get("dependencyGroups")
            .and_then(Value::as_array)
            .map(|groups| groups.iter().map(dependency_group).collect())
            .unwrap_or_default();
        out.insert(
            version,
            Leaf {
                id: entry.get("id").and_then(Value::as_str).map(str::to_string),
                listed,
                published,
                groups,
                catalog_url: entry.get("@id").and_then(Value::as_str).map(str::to_string),
            },
        );
    }
    out
}

fn dependency_group(group: &Value) -> DependencyGroup {
    DependencyGroup {
        target_framework: group
            .get("targetFramework")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_string),
        dependencies: group
            .get("dependencies")
            .and_then(Value::as_array)
            .map(|deps| {
                deps.iter()
                    .filter_map(|dep| {
                        Some(Dependency {
                            id: dep.get("id")?.as_str()?.to_string(),
                            range: dep.get("range").and_then(Value::as_str).map(str::to_string),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// The year of an RFC 3339 time (`1900-01-01T00:00:00+00:00` → 1900).
fn year(raw: &str) -> Option<i32> {
    let (year, rest) = raw.split_at_checked(4)?;
    rest.starts_with('-').then_some(())?;
    year.parse().ok()
}

/// A page of the upstream's `SearchQueryService` results for `query`.
fn search(resources: &Resources, query: &SearchQuery, fetched: &[FetchResult]) -> UpstreamStep {
    // nuget.org limits skip to 3,000. Deeper pages use the proxy's local search
    // rather than requesting a rejected offset or silently changing the page.
    if query.skip > 3_000 {
        return done(UpstreamAnswer::Search(None));
    }
    let Some(service) = &resources.search_query_service else {
        return done(UpstreamAnswer::Search(None));
    };
    let url = search_url(service, query);
    match json(fetched, &url) {
        Doc::Wanted => UpstreamStep::Fetch(vec![get(&url, Freshness::Metadata)]),
        Doc::Found(doc) => done(UpstreamAnswer::Search(Some(search_page(&doc, query)))),
        Doc::NotFound => failed(format!("upstream search {url} returned 404")),
        Doc::Failed(reason) => failed(reason),
    }
}

/// `service` with the V3 search parameters of `query`.
fn search_url(service: &str, query: &SearchQuery) -> String {
    let take = if query.take == 0 { 20 } else { query.take };
    let pairs = [
        ("q", query.text.as_str()),
        ("skip", &query.skip.to_string()),
        ("take", &take.to_string()),
        (
            "prerelease",
            if query.prerelease { "true" } else { "false" },
        ),
        ("semVerLevel", if query.semver2 { "2.0.0" } else { "1.0.0" }),
    ]
    .map(|(k, v)| format!("{k}={}", form_encode(v)));
    let separator = match service.find('?') {
        None => "?",
        Some(_) if service.ends_with('?') || service.ends_with('&') => "",
        Some(_) => "&",
    };
    format!("{service}{separator}{}", pairs.join("&"))
}

/// `application/x-www-form-urlencoded`: letters, digits and `*-._` as is,
/// a space as `+`, everything else percent-encoded.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(char::from(b))
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// An upstream search response: at most `take` hits. An entry without a
/// well-formed id (ids end up in Forge's URLs) is dropped, and the
/// upstream's total reduced by it.
fn search_page(doc: &Value, query: &SearchQuery) -> UpstreamSearch {
    let take = if query.take == 0 { 20 } else { query.take } as usize;
    let entries: Vec<&Value> = doc
        .get("data")
        .and_then(Value::as_array)
        .map(|data| data.iter().take(take).collect())
        .unwrap_or_default();
    let returned = entries.len() as u64;
    let hits: Vec<UpstreamHit> = entries.into_iter().filter_map(search_hit).collect();
    let total = doc
        .get("totalHits")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .saturating_sub(returned - hits.len() as u64)
        .max(u64::from(query.skip) + hits.len() as u64);
    UpstreamSearch { total, hits }
}

/// One upstream search result entry with its parseable versions; `None`
/// when its id is not well-formed.
fn search_hit(entry: &Value) -> Option<UpstreamHit> {
    let id = entry.get("id")?.as_str()?.trim();
    nuspec::validate_package_id(id).ok()?;
    let normalize = |raw: &str| version::normalize(raw).ok();
    let mut versions: Vec<String> = entry
        .get("versions")
        .and_then(Value::as_array)
        .map(|versions| {
            versions
                .iter()
                .filter_map(|v| normalize(v.get("version")?.as_str()?))
                .collect()
        })
        .unwrap_or_default();
    if versions.is_empty() {
        versions.extend(
            entry
                .get("version")
                .and_then(Value::as_str)
                .and_then(normalize),
        );
    }
    versions.sort_by(|a, b| version::compare(a, b));
    versions.dedup();
    Some(UpstreamHit {
        id: id.to_string(),
        versions,
        summary: serde_json::to_string(&nuspec::summary_from_search_hit(entry)).ok(),
        total_downloads: entry.get("totalDownloads").and_then(Value::as_u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_index_prefers_the_semver2_registration_variant() {
        let doc = serde_json::json!({
            "resources": [
                { "@id": "https://up/registration5-semver1/", "@type": "RegistrationsBaseUrl" },
                { "@id": "https://up/registration5-gz-semver2/", "@type": "RegistrationsBaseUrl/3.6.0" },
                { "@id": "https://up/registration5-gz-semver1", "@type": "RegistrationsBaseUrl/3.4.0" },
                { "@id": "https://up/flat", "@type": "PackageBaseAddress/3.0.0" },
            ]
        });
        let res = Resources::from_service_index(&doc);
        assert_eq!(
            res.registrations_base_url.as_deref(),
            Some("https://up/registration5-gz-semver2/")
        );
        assert_eq!(
            res.package_base_address.as_deref(),
            Some("https://up/flat/")
        );

        let only_semver1 = serde_json::json!({
            "resources": [ { "@id": "https://up/reg", "@type": "RegistrationsBaseUrl" } ]
        });
        assert_eq!(
            Resources::from_service_index(&only_semver1)
                .registrations_base_url
                .as_deref(),
            Some("https://up/reg/")
        );
    }

    #[test]
    fn the_index_keeps_the_persisted_shape() {
        // What the host stored before the upstream protocol moved into the
        // plugin reads back as the same resources.
        let resources = Resources {
            package_base_address: Some("https://up/flat/".into()),
            registrations_base_url: None,
            search_query_service: None,
        };
        let json = serde_json::to_value(&resources).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "package_base_address": "https://up/flat/",
                "registrations_base_url": null,
                "search_query_service": null,
            })
        );
        assert_eq!(
            serde_json::from_value::<Resources>(json).unwrap(),
            resources
        );
    }

    #[test]
    fn search_parameters_are_form_encoded() {
        let query = SearchQuery {
            text: "id:a b&c/é".into(),
            skip: 20,
            take: 0,
            prerelease: true,
            semver2: false,
            upstream: true,
        };
        assert_eq!(
            search_url("https://up/query", &query),
            "https://up/query?q=id%3Aa+b%26c%2F%C3%A9&skip=20&take=20&prerelease=true&semVerLevel=1.0.0"
        );
        assert!(search_url("https://up/query?x=1", &query).starts_with("https://up/query?x=1&q="));
    }

    #[test]
    fn a_missing_listed_flag_reads_the_1900_marker() {
        let page = serde_json::json!({ "items": [
            { "catalogEntry": { "version": "1.0.0", "published": "1900-01-01T00:00:00+00:00" } },
            { "catalogEntry": { "version": "2.0.0", "published": "2021-05-01T00:00:00+00:00" } },
            { "catalogEntry": { "version": "3.0.0" } },
        ]});
        let leaves = registration_leaves(&page);
        assert!(!leaves["1.0.0"].listed);
        assert!(leaves["2.0.0"].listed);
        assert!(leaves["3.0.0"].listed);
    }
}
