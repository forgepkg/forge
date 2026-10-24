//! The NuGet V3 protocol: which URL answers what, and the documents it answers
//! with.
//!
//! Every `@id` is absolute, built from the repository's base URL
//! (`{public_base_url}/v3/{repo}`). The host has authorized the request
//! before [`handle`] sees it; publishing, unlisting and relisting are host
//! actions, offered for hosted repositories only. Paths match literal
//! segments as sent and percent-decode parameters; an unknown path answers
//! `404` with an empty body, a known path with another method `405` with
//! `Allow`.

use std::collections::HashMap;

use forge_plugin_api::{
    Action, Answer, ChangeRequest, Loaded, PackageInfo, PackageRef, PackageVersions,
    PublishRequest, Query, Repository, RepositoryKind, Request, Response, SearchQuery,
    SearchResult, Upload, VersionInfo,
};
use serde_json::{json, Value};

use crate::nuspec::{self, ManifestSummary};
use crate::version;

/// Versions per registration page (nuget.org uses the same size).
pub const PAGE_SIZE: usize = 64;

/// Packages with at most this many versions get every page inlined in the
/// registration index; larger ones are paged.
pub const MAX_INLINED_LEAVES: usize = 128;

/// Most versions one page request renders. A page an index advertised holds
/// [`PAGE_SIZE`]; versions pushed into its range since then can add more.
pub const MAX_PAGE_LEAVES: usize = 4 * PAGE_SIZE;

/// nuget.org's convention for an unlisted version's `published` timestamp.
const UNLISTED_PUBLISHED: &str = "1900-01-01T00:00:00+00:00";

/// The search page size when the client names none.
const DEFAULT_TAKE: u32 = 20;

/// What a request is.
enum Route {
    ServiceIndex,
    FlatVersions {
        id: String,
    },
    FlatContent {
        id: String,
        version: String,
        file: String,
    },
    RegistrationIndex {
        id: String,
    },
    RegistrationPage {
        id: String,
        lower: String,
        upper_file: String,
    },
    RegistrationLeaf {
        id: String,
        file: String,
    },
    Catalog {
        id: String,
        file: String,
    },
    Search,
    Push,
    Unlist {
        id: String,
        version: String,
    },
    Relist {
        id: String,
        version: String,
    },
}

fn empty(status: u16) -> Response {
    Response {
        status,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn not_allowed(allow: &str) -> Response {
    empty(405).with_header("allow", allow)
}

fn json_response(value: &Value) -> Response {
    Response::new(200, "application/json", value.to_string())
}

/// A path parameter, percent-decoded; never empty.
fn param(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let request = Request::new("GET", &format!("/{raw}"));
    request.segments()?.pop()
}

/// The route of `req`, or the response to a path or method no route takes.
fn route(req: &Request, kind: RepositoryKind) -> Result<Route, Response> {
    let raw: Vec<&str> = req
        .path
        .strip_prefix('/')
        .unwrap_or(&req.path)
        .split('/')
        .collect();
    let read = matches!(req.method.as_str(), "GET" | "HEAD");
    let read_only = |route: Route| {
        if read {
            Ok(route)
        } else {
            Err(not_allowed("GET,HEAD"))
        }
    };
    let p = |i: usize| raw.get(i).and_then(|s| param(s));
    let unknown = || Err(empty(404));
    match raw.as_slice() {
        ["index.json"] => read_only(Route::ServiceIndex),
        ["flat", _, "index.json"] => match p(1) {
            Some(id) => read_only(Route::FlatVersions { id }),
            None => unknown(),
        },
        ["flat", _, _, _] => match (p(1), p(2), p(3)) {
            (Some(id), Some(version), Some(file)) => {
                read_only(Route::FlatContent { id, version, file })
            }
            _ => unknown(),
        },
        ["registration", _, "index.json"] => match p(1) {
            Some(id) => read_only(Route::RegistrationIndex { id }),
            None => unknown(),
        },
        ["registration", _, "page", _, _] => match (p(1), p(3), p(4)) {
            (Some(id), Some(lower), Some(upper_file)) => read_only(Route::RegistrationPage {
                id,
                lower,
                upper_file,
            }),
            _ => unknown(),
        },
        ["registration", _, _] => match (p(1), p(2)) {
            (Some(id), Some(file)) => read_only(Route::RegistrationLeaf { id, file }),
            _ => unknown(),
        },
        ["catalog", _, _] => match (p(1), p(2)) {
            (Some(id), Some(file)) => read_only(Route::Catalog { id, file }),
            _ => unknown(),
        },
        ["query"] => read_only(Route::Search),
        // PackagePublish: hosted repositories only. The official client
        // appends a slash to the PackagePublish `@id` (`…/package/`).
        ["package"] | ["package", ""] if kind == RepositoryKind::Hosted => {
            if req.method == "PUT" {
                Ok(Route::Push)
            } else {
                Err(not_allowed("PUT"))
            }
        }
        ["package", _, _] if kind == RepositoryKind::Hosted => match (p(1), p(2)) {
            (Some(id), Some(version)) => match req.method.as_str() {
                "DELETE" => Ok(Route::Unlist { id, version }),
                "POST" => Ok(Route::Relist { id, version }),
                _ => Err(not_allowed("DELETE,POST")),
            },
            _ => unknown(),
        },
        _ => unknown(),
    }
}

/// The lowered package id of a request path, or `None` when it is not a
/// well-formed id. Every id-addressed route answers such a request 404
/// before any data is loaded: a proxy pastes the id into credentialed
/// upstream URLs.
fn package_id(raw: &str) -> Option<String> {
    let lower = nuspec::lower_id(raw);
    nuspec::validate_package_id(&lower).ok().map(|()| lower)
}

/// The normalized version of a request path, or `None` when it is not a
/// version or is longer than any publishable one.
fn package_version(raw: &str) -> Option<String> {
    if raw.trim().len() > version::MAX_VERSION_LENGTH {
        return None;
    }
    version::normalize(raw).ok()
}

/// `(lowered id, normalized version)` of a registration leaf or catalog
/// entry file `{version}.json`.
fn leaf_ref(id: &str, file: &str) -> Option<PackageRef> {
    let id = package_id(id)?;
    let version = package_version(file.strip_suffix(".json")?)?;
    Some(PackageRef { id, version })
}

pub(crate) fn handle(repo: &Repository, req: &Request) -> Action {
    let route = match route(req, repo.kind) {
        Ok(route) => route,
        Err(response) => return Action::Respond(response),
    };
    let not_found = |text: &str| Action::Respond(Response::text(404, text));
    match route {
        Route::ServiceIndex => Action::Respond(json_response(&service_index(repo))),
        Route::FlatVersions { id } => match package_id(&id) {
            Some(lower) => Action::Load(vec![Query::Versions(lower)]),
            None => not_found("package not found"),
        },
        Route::FlatContent { id, version, file } => {
            let Some(id) = package_id(&id) else {
                return not_found("package not found");
            };
            let Some(version) = package_version(&version) else {
                return not_found("invalid version");
            };
            let file = file.to_ascii_lowercase();
            let target = PackageRef { id, version };
            if file.ends_with(".nupkg") {
                Action::Download(target)
            } else if file.ends_with(".nuspec") {
                Action::Load(vec![Query::Manifest(target)])
            } else {
                not_found("unknown content")
            }
        }
        Route::RegistrationIndex { id } => match package_id(&id) {
            Some(lower) => Action::Load(vec![Query::Versions(lower)]),
            None => not_found("registration not found"),
        },
        Route::RegistrationPage { id, upper_file, .. } => {
            match (package_id(&id), upper_file.strip_suffix(".json")) {
                (Some(lower), Some(_)) => Action::Load(vec![Query::Versions(lower)]),
                _ => not_found("registration page not found"),
            }
        }
        Route::RegistrationLeaf { id, file } | Route::Catalog { id, file } => {
            match leaf_ref(&id, &file) {
                Some(target) => Action::Load(vec![Query::Package(target)]),
                None => not_found("registration leaf not found"),
            }
        }
        Route::Search => Action::Load(vec![Query::Search(search_query(req))]),
        Route::Push => Action::Publish(PublishRequest {
            // The first part is the raw `.nupkg`, whatever its name.
            upload: Upload::FirstPart,
            // Both create and redeploy answer 201.
            done: empty(201),
        }),
        Route::Unlist { id, version } => Action::Unlist(ChangeRequest {
            target: PackageRef { id, version },
            done: empty(204),
        }),
        Route::Relist { id, version } => Action::Relist(ChangeRequest {
            target: PackageRef { id, version },
            done: empty(200),
        }),
    }
}

pub(crate) fn render(repo: &Repository, req: &Request, data: &[Loaded]) -> Action {
    let respond = Action::Respond;
    let not_found = |text: &str| Action::Respond(Response::text(404, text));
    let Ok(route) = route(req, repo.kind) else {
        return not_found("not found");
    };
    let versions = || {
        data.iter().find_map(|l| match &l.answer {
            Answer::Versions(v) => Some(v.as_slice()),
            _ => None,
        })
    };
    let packages = || {
        data.iter().find_map(|l| match &l.answer {
            Answer::Packages(p) => Some(p.as_slice()),
            _ => None,
        })
    };
    let package = || {
        data.iter().find_map(|l| match &l.answer {
            Answer::Package(p) => p.as_ref(),
            _ => None,
        })
    };
    let base = &repo.base_url;
    match route {
        Route::FlatVersions { .. } => match versions() {
            Some(v) if !v.is_empty() => respond(json_response(&json!({
                "versions": v.iter().map(|v| v.version.clone()).collect::<Vec<_>>(),
            }))),
            _ => not_found("package not found"),
        },
        Route::FlatContent { .. } => {
            let manifest = data.iter().find_map(|l| match &l.answer {
                Answer::Manifest(m) => m.clone(),
                _ => None,
            });
            match manifest {
                Some(bytes) => respond(Response::new(200, "application/xml", bytes)),
                None => not_found("nuspec not found"),
            }
        }
        Route::RegistrationIndex { id } => {
            let Some(lower) = package_id(&id) else {
                return not_found("registration not found");
            };
            match packages() {
                // A package with too many versions to inline gets an index
                // of page bounds: its versions' metadata is not loaded.
                None => {
                    let versions = version_strings(versions().unwrap_or_default());
                    if versions.len() > MAX_INLINED_LEAVES {
                        respond(json_response(&paged_registration_json(
                            base, &lower, &versions,
                        )))
                    } else {
                        Action::Load(vec![Query::Packages(lower)])
                    }
                }
                Some([]) => not_found("registration not found"),
                Some(entries) => respond(json_response(&registration_json(base, &lower, entries))),
            }
        }
        Route::RegistrationPage {
            id,
            lower,
            upper_file,
        } => {
            let (Some(lower_id), Some(upper)) = (package_id(&id), upper_file.strip_suffix(".json"))
            else {
                return not_found("registration page not found");
            };
            match packages() {
                None => {
                    let versions = version_strings(versions().unwrap_or_default());
                    match registration_page_versions(&versions, &lower, upper) {
                        // Only the page's versions are loaded.
                        Some(in_range) => Action::Load(vec![Query::PackagesOf(PackageVersions {
                            id: lower_id,
                            versions: in_range.to_vec(),
                        })]),
                        None => not_found("registration page not found"),
                    }
                }
                Some(entries) => respond(json_response(&registration_page_json(
                    base, &lower_id, entries, &lower, upper,
                ))),
            }
        }
        Route::RegistrationLeaf { id, .. } => match (package_id(&id), package()) {
            (Some(lower), Some(entry)) => {
                respond(json_response(&leaf_document(base, &lower, entry)))
            }
            _ => not_found("registration leaf not found"),
        },
        Route::Catalog { id, .. } => match (package_id(&id), package()) {
            (Some(lower), Some(entry)) => {
                respond(json_response(&catalog_entry(base, &lower, entry)))
            }
            _ => not_found("registration leaf not found"),
        },
        Route::Search => {
            let result = data.iter().find_map(|l| match &l.answer {
                Answer::Search(result) => Some(result),
                _ => None,
            });
            match result {
                Some(result) => respond(json_response(&search_json(base, result))),
                None => not_found("not found"),
            }
        }
        // Answered by `handle`.
        Route::ServiceIndex | Route::Push | Route::Unlist { .. } | Route::Relist { .. } => {
            not_found("not found")
        }
    }
}

fn version_strings(versions: &[VersionInfo]) -> Vec<String> {
    versions.iter().map(|v| v.version.clone()).collect()
}

// ── Service index ────────────────────────────────────────────────────────────

/// The service index: the absolute resource `@id`s a client uses to
/// self-configure. `PackagePublish/2.0.0` is advertised for hosted
/// repositories only.
fn service_index(repo: &Repository) -> Value {
    let base = &repo.base_url;
    let mut resources = vec![
        json!({ "@id": format!("{base}/query"), "@type": "SearchQueryService/3.5.0" }),
        // Common alias many clients still probe for.
        json!({ "@id": format!("{base}/query"), "@type": "SearchQueryService/3.0.0-rc" }),
        // Every registration variant points at the same hive: older clients
        // (VS2015, nuget.exe 3.x/4.x, packages.config resolvers) look up the
        // unversioned / 3.0.0 / 3.4.0 types and find no registration otherwise.
        json!({ "@id": format!("{base}/registration/"), "@type": "RegistrationsBaseUrl" }),
        json!({ "@id": format!("{base}/registration/"), "@type": "RegistrationsBaseUrl/3.0.0-beta" }),
        json!({ "@id": format!("{base}/registration/"), "@type": "RegistrationsBaseUrl/3.0.0-rc" }),
        json!({ "@id": format!("{base}/registration/"), "@type": "RegistrationsBaseUrl/3.4.0" }),
        json!({ "@id": format!("{base}/registration/"), "@type": "RegistrationsBaseUrl/3.6.0" }),
        json!({ "@id": format!("{base}/flat/"), "@type": "PackageBaseAddress/3.0.0" }),
    ];
    if repo.kind == RepositoryKind::Hosted {
        resources.push(json!({
            "@id": format!("{base}/package"),
            "@type": "PackagePublish/2.0.0"
        }));
    }
    json!({
        "version": "3.0.0",
        "resources": resources,
    })
}

// ── Registration ─────────────────────────────────────────────────────────────

/// The absolute `packageContent` URL of a version.
fn package_content_url(base: &str, lower_id: &str, version: &str) -> String {
    let lower_ver = version.to_ascii_lowercase();
    format!("{base}/flat/{lower_id}/{lower_ver}/{lower_id}.{lower_ver}.nupkg")
}

/// Absolute URL of a version's registration leaf document.
fn leaf_url(base: &str, lower_id: &str, version: &str) -> String {
    format!(
        "{base}/registration/{lower_id}/{}.json",
        version.to_ascii_lowercase()
    )
}

/// Absolute URL of a version's catalog-entry document.
fn catalog_url(base: &str, lower_id: &str, version: &str) -> String {
    format!(
        "{base}/catalog/{lower_id}/{}.json",
        version.to_ascii_lowercase()
    )
}

/// `published` (RFC 3339, from the host), or nuget.org's 1900 marker for
/// unlisted versions.
fn published(entry: &PackageInfo) -> Option<String> {
    if !entry.listed {
        return Some(UNLISTED_PUBLISHED.to_string());
    }
    entry.published.clone()
}

/// The manifest summary the host passes with a version; empty when it has
/// none or it does not read.
fn summary(text: Option<&str>) -> ManifestSummary {
    text.and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// The `dependencyGroups` JSON array of a version's manifest summary.
fn dependency_groups(summary: &ManifestSummary) -> Value {
    let arr: Vec<Value> = summary
        .dependency_groups
        .clone()
        .into_iter()
        .map(|g| {
            let deps: Vec<Value> = g
                .dependencies
                .into_iter()
                .map(|d| {
                    json!({
                        "id": d.id,
                        "range": d.range.unwrap_or_else(|| "(, )".to_string()),
                    })
                })
                .collect();
            let mut obj = serde_json::Map::new();
            if let Some(tfm) = g.target_framework {
                obj.insert("targetFramework".to_string(), Value::String(tfm));
            }
            obj.insert("dependencies".to_string(), Value::Array(deps));
            Value::Object(obj)
        })
        .collect();
    Value::Array(arr)
}

/// The catalog entry (`PackageDetails`) of one version: identity, listing
/// state, hash, content URL, dependency groups, and the display metadata from
/// the version's manifest summary.
pub(crate) fn catalog_entry(base: &str, lower_id: &str, entry: &PackageInfo) -> Value {
    let mut catalog = serde_json::Map::new();
    let mut put = |k: &str, v: Value| {
        catalog.insert(k.to_string(), v);
    };
    put(
        "@id",
        Value::String(catalog_url(base, lower_id, &entry.version)),
    );
    put("@type", Value::String("PackageDetails".into()));
    put("id", Value::String(entry.original_id.clone()));
    put("version", Value::String(entry.version.clone()));
    put("listed", Value::Bool(entry.listed));
    if let Some(published) = published(entry) {
        put("published", Value::String(published));
    }
    if let Some(hash) = &entry.sha512 {
        put("packageHash", Value::String(hash.clone()));
        put("packageHashAlgorithm", Value::String("SHA512".into()));
    }
    put(
        "packageContent",
        Value::String(package_content_url(base, lower_id, &entry.version)),
    );
    let summary = summary(entry.summary.as_deref());
    put("dependencyGroups", dependency_groups(&summary));

    let meta = summary.metadata;
    let mut put_str = |k: &str, v: &Option<String>| {
        if let Some(v) = v {
            catalog.insert(k.to_string(), Value::String(v.clone()));
        }
    };
    put_str("title", &meta.title);
    put_str("description", &meta.description);
    put_str("summary", &meta.summary);
    put_str("authors", &meta.authors);
    put_str("projectUrl", &meta.project_url);
    put_str("iconUrl", &meta.icon_url);
    put_str("language", &meta.language);
    put_str("minClientVersion", &meta.min_client_version);
    put_str("releaseNotes", &meta.release_notes);
    put_str("copyright", &meta.copyright);
    put_str("licenseExpression", &meta.license_expression);
    // Like nuget.org: an expression-only license gets a resolvable URL.
    let license_url = meta.license_url.clone().or_else(|| {
        meta.license_expression
            .as_ref()
            .map(|expr| format!("https://licenses.nuget.org/{expr}"))
    });
    put_str("licenseUrl", &license_url);
    catalog.insert(
        "requireLicenseAcceptance".into(),
        Value::Bool(meta.require_license_acceptance),
    );
    catalog.insert(
        "tags".into(),
        Value::Array(meta.tags.into_iter().map(Value::String).collect()),
    );
    Value::Object(catalog)
}

/// A registration leaf (`items[].items[]` element) with its inlined catalog
/// entry.
fn leaf(base: &str, lower_id: &str, entry: &PackageInfo) -> Value {
    json!({
        "@id": leaf_url(base, lower_id, &entry.version),
        "@type": "Package",
        "catalogEntry": catalog_entry(base, lower_id, entry),
        "packageContent": package_content_url(base, lower_id, &entry.version),
        "registration": format!("{base}/registration/{lower_id}/index.json"),
    })
}

/// The registration leaf document a leaf's `@id` points at.
fn leaf_document(base: &str, lower_id: &str, entry: &PackageInfo) -> Value {
    let mut doc = json!({
        "@id": leaf_url(base, lower_id, &entry.version),
        "@type": ["Package", "http://schema.nuget.org/catalog#Permalink"],
        "catalogEntry": catalog_url(base, lower_id, &entry.version),
        "listed": entry.listed,
        "packageContent": package_content_url(base, lower_id, &entry.version),
        "registration": format!("{base}/registration/{lower_id}/index.json"),
    });
    if let Some(published) = published(entry) {
        doc["published"] = Value::String(published);
    }
    doc
}

/// URL of the registration page holding `lower..=upper`.
fn page_url(base: &str, lower_id: &str, lower: &str, upper: &str) -> String {
    format!(
        "{base}/registration/{lower_id}/page/{}/{}.json",
        lower.to_ascii_lowercase(),
        upper.to_ascii_lowercase()
    )
}

/// One registration page (`catalog:CatalogPage`) over `entries` (ascending),
/// with its leaves when `inline`.
fn page_json(base: &str, lower_id: &str, entries: &[PackageInfo], inline: bool) -> Value {
    let lower = entries.first().map(|e| e.version.as_str()).unwrap_or("");
    let upper = entries.last().map(|e| e.version.as_str()).unwrap_or("");
    let index_url = format!("{base}/registration/{lower_id}/index.json");
    let mut page = json!({
        "@id": page_url(base, lower_id, lower, upper),
        "@type": "catalog:CatalogPage",
        "count": entries.len(),
        "lower": lower,
        "upper": upper,
        "parent": index_url,
    });
    if inline {
        page["items"] = Value::Array(entries.iter().map(|e| leaf(base, lower_id, e)).collect());
    }
    page
}

/// A page of the registration index that is not inlined: its bounds and
/// URL over `versions` (ascending), no leaves.
fn page_stub_json(base: &str, lower_id: &str, versions: &[String]) -> Value {
    let lower = versions.first().map(String::as_str).unwrap_or("");
    let upper = versions.last().map(String::as_str).unwrap_or("");
    json!({
        "@id": page_url(base, lower_id, lower, upper),
        "@type": "catalog:CatalogPage",
        "count": versions.len(),
        "lower": lower,
        "upper": upper,
        "parent": format!("{base}/registration/{lower_id}/index.json"),
    })
}

/// The registration index of a package with more than
/// [`MAX_INLINED_LEAVES`] versions (ascending): pages of [`PAGE_SIZE`] that
/// name only their bounds, so no version's metadata is loaded for it.
fn paged_registration_json(base: &str, lower_id: &str, versions: &[String]) -> Value {
    let pages: Vec<Value> = versions
        .chunks(PAGE_SIZE)
        .map(|chunk| page_stub_json(base, lower_id, chunk))
        .collect();
    json!({
        "@id": format!("{base}/registration/{lower_id}/index.json"),
        "@type": ["catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"],
        "count": pages.len(),
        "items": pages,
    })
}

/// The registration index of a package's versions (ascending): pages of
/// [`PAGE_SIZE`], inlined up to [`MAX_INLINED_LEAVES`] versions.
fn registration_json(base: &str, lower_id: &str, entries: &[PackageInfo]) -> Value {
    let inline = entries.len() <= MAX_INLINED_LEAVES;
    let pages: Vec<Value> = entries
        .chunks(PAGE_SIZE)
        .map(|chunk| page_json(base, lower_id, chunk, inline))
        .collect();
    json!({
        "@id": format!("{base}/registration/{lower_id}/index.json"),
        "@type": ["catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"],
        "count": pages.len(),
        "items": pages,
    })
}

/// The versions of `versions` (ascending) in the registration page
/// `lower..=upper`: every version in that range by precedence.
///
/// The range decides, not the current chunking. A client fetches a page by
/// the URL of an index it may have cached, and a push, a delete, a proxy
/// version leaving its delay window or a failing group member re-chunks the
/// index; NuGet clients fail the whole operation on a page 404. `None` (404)
/// for an unknown id, bounds that are not versions, or a range over more
/// than [`MAX_PAGE_LEAVES`] versions.
pub fn registration_page_versions<'v>(
    versions: &'v [String],
    lower: &str,
    upper: &str,
) -> Option<&'v [String]> {
    if versions.is_empty() {
        return None;
    }
    version::normalize(lower).ok()?;
    version::normalize(upper).ok()?;
    let start = versions.partition_point(|v| version::compare(v, lower).is_lt());
    let end = versions.partition_point(|v| version::compare(v, upper).is_le());
    let in_range = versions.get(start..end.max(start))?;
    (in_range.len() <= MAX_PAGE_LEAVES).then_some(in_range)
}

/// The registration page `lower..=upper` with its leaves, over the entries
/// of the versions in that range ([`registration_page_versions`]).
fn registration_page_json(
    base: &str,
    lower_id: &str,
    in_range: &[PackageInfo],
    lower: &str,
    upper: &str,
) -> Value {
    let mut page = page_json(base, lower_id, in_range, true);
    // The page answers for the bounds it was asked for.
    page["@id"] = json!(page_url(base, lower_id, lower, upper));
    page["lower"] = json!(lower);
    page["upper"] = json!(upper);
    page
}

// ── Search ───────────────────────────────────────────────────────────────────

/// The query parameters, the last value of a repeated name winning.
fn query_params(req: &Request) -> HashMap<String, String> {
    req.query_pairs().into_iter().collect()
}

/// `GET {base}/query?q=&skip=&take=&prerelease=&semVerLevel=`: SemVer 2.0.0
/// versions only for clients that send `semVerLevel=2.0.0` (or higher), as
/// the protocol requires; `prerelease` defaults to `false`. A proxy also
/// searches its upstream.
fn search_query(req: &Request) -> SearchQuery {
    let raw = query_params(req);
    let number = |key: &str, default: u32| {
        raw.get(key)
            .and_then(|s| s.parse::<u64>().ok())
            .map_or(default, |n| u32::try_from(n).unwrap_or(u32::MAX))
    };
    SearchQuery {
        text: raw.get("q").cloned().unwrap_or_default(),
        skip: number("skip", 0),
        take: number("take", DEFAULT_TAKE),
        prerelease: raw
            .get("prerelease")
            .is_some_and(|s| s.eq_ignore_ascii_case("true")),
        semver2: raw
            .get("semVerLevel")
            .and_then(|v| v.split('.').next())
            .and_then(|major| major.trim().parse::<u32>().ok())
            .is_some_and(|major| major >= 2),
        upstream: true,
    }
}

/// The search response: `{ totalHits, data: [ { id, version, description,
/// versions: [...], … } ] }`. Version filtering (listed, prerelease, SemVer
/// 2.0.0) already happened in the host, before paging.
fn search_json(base: &str, result: &SearchResult) -> Value {
    let data: Vec<Value> = result
        .hits
        .iter()
        .map(|hit| {
            let lower_id = nuspec::lower_id(&hit.original_id);
            let versions: Vec<Value> = hit
                .versions
                .iter()
                .map(|v| {
                    json!({
                        "version": v.version,
                        "downloads": 0,
                        "@id": format!(
                            "{base}/registration/{lower_id}/{}.json",
                            v.version.to_ascii_lowercase()
                        ),
                    })
                })
                .collect();
            let meta = summary(hit.summary.as_deref()).metadata;
            let authors: Vec<Value> = meta
                .authors
                .as_deref()
                .map(|a| {
                    a.split(',')
                        .map(str::trim)
                        .filter(|a| !a.is_empty())
                        .map(|a| Value::String(a.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let package_types: Vec<Value> = if meta.package_types.is_empty() {
                vec![json!({ "name": "Dependency" })]
            } else {
                meta.package_types
                    .iter()
                    .map(|name| json!({ "name": name }))
                    .collect()
            };
            let license_url = meta.license_url.clone().or_else(|| {
                meta.license_expression
                    .as_ref()
                    .map(|expr| format!("https://licenses.nuget.org/{expr}"))
            });
            let mut obj = json!({
                "@id": format!("{base}/registration/{lower_id}/index.json"),
                "@type": "Package",
                "registration": format!("{base}/registration/{lower_id}/index.json"),
                "id": hit.original_id,
                "version": hit.latest_version,
                "description": meta.description.clone().unwrap_or_default(),
                "summary": meta.summary.clone().unwrap_or_default(),
                "title": meta.title.clone().unwrap_or_else(|| hit.original_id.clone()),
                "authors": authors,
                "tags": meta.tags,
                "totalDownloads": hit.total_downloads.unwrap_or(0),
                "verified": false,
                "packageTypes": package_types,
                "versions": versions,
            });
            for (key, value) in [
                ("iconUrl", meta.icon_url),
                ("projectUrl", meta.project_url),
                ("licenseUrl", license_url),
            ] {
                if let Some(value) = value {
                    obj[key] = Value::String(value);
                }
            }
            obj
        })
        .collect();
    json!({
        "totalHits": result.total,
        "data": data,
    })
}
