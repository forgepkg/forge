//! Registration (`RegistrationsBaseUrl`, all 3.x variants), spec §6 +
//! Appendix A.
//!
//! The index splits versions into pages of [`PAGE_SIZE`]. Up to
//! [`MAX_INLINED_LEAVES`] versions, every page is inlined in the index;
//! beyond that, the index lists the pages (bounds and URL only) and each is
//! served by `/registration/{id}/page/{lower}/{upper}.json`, so a package with
//! thousands of versions never renders them all in one response. Each leaf
//! carries a
//! `catalogEntry` with id, version, `listed`, `published`, `packageHash`
//! (base64 SHA-512) + `packageHashAlgorithm`, an absolute `packageContent`
//! URL, `dependencyGroups`, and the display metadata (description, authors,
//! tags, license, project/icon URLs, …) parsed from the stored `.nuspec`.
//! Every advertised `@id` resolves: `/registration/{id}/{version}.json`
//! serves the leaf document and `/catalog/{id}/{version}.json` the catalog
//! entry.
//!
//! Versions (including unlisted) are returned ascending by precedence — the
//! ordering is the core op's responsibility.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::repo::RegistrationEntry;
use serde_json::{json, Value};

use crate::routes::{package_id, package_version, repo_error_response, RouteContext};
use crate::{nuspec, version};

/// Build the absolute `packageContent` URL for a `(lower_id, version)`.
fn package_content_url(base: &str, lower_id: &str, version: &str) -> String {
    // {base}/flat/{lower_id}/{lower_ver}/{lower_id}.{lower_ver}.nupkg
    let lower_ver = version.to_ascii_lowercase();
    format!("{base}/flat/{lower_id}/{lower_ver}/{lower_id}.{lower_ver}.nupkg")
}

/// Versions per registration page (nuget.org uses the same size).
pub const PAGE_SIZE: usize = 64;

/// Packages with at most this many versions get every page inlined in the
/// registration index; larger ones are paged.
pub const MAX_INLINED_LEAVES: usize = 128;

/// Render the `dependencyGroups` JSON array of a version's manifest summary.
///
/// A missing or unreadable manifest yields an empty array rather than
/// failing the whole registration page.
fn dependency_groups(summary: &nuspec::ManifestSummary) -> Value {
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

/// nuget.org's convention for an unlisted version's `published` timestamp.
const UNLISTED_PUBLISHED: &str = "1900-01-01T00:00:00+00:00";

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

/// `published` in RFC 3339, or nuget.org's 1900 marker for unlisted versions.
fn published(entry: &RegistrationEntry) -> Option<String> {
    if !entry.listed {
        return Some(UNLISTED_PUBLISHED.to_string());
    }
    entry
        .published
        .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Millis, false))
}

/// The catalog entry (`PackageDetails`) of one version: identity, listing
/// state, hash, content URL, dependency groups, and the display metadata from
/// the stored `.nuspec`.
pub fn catalog_entry(base: &str, lower_id: &str, entry: &RegistrationEntry) -> Value {
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
    if let Some(hash) = &entry.package_hash_sha512_base64 {
        put("packageHash", Value::String(hash.clone()));
        put("packageHashAlgorithm", Value::String("SHA512".into()));
    }
    put(
        "packageContent",
        Value::String(package_content_url(base, lower_id, &entry.version)),
    );
    // The summary stored at publish; only older versions parse the manifest.
    let summary = nuspec::summary_of(
        entry.manifest_summary.as_ref(),
        entry.nuspec_bytes.as_deref(),
    );
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

/// Build a single registration leaf (`items[].items[]` element) with its
/// inlined catalog entry.
fn leaf(base: &str, lower_id: &str, entry: &RegistrationEntry) -> Value {
    json!({
        "@id": leaf_url(base, lower_id, &entry.version),
        "@type": "Package",
        "catalogEntry": catalog_entry(base, lower_id, entry),
        "packageContent": package_content_url(base, lower_id, &entry.version),
        "registration": format!("{base}/registration/{lower_id}/index.json"),
    })
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
fn page_json(base: &str, lower_id: &str, entries: &[RegistrationEntry], inline: bool) -> Value {
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
pub fn paged_registration_json(ctx: &RouteContext, lower_id: &str, versions: &[String]) -> Value {
    let base = ctx.base();
    let pages: Vec<Value> = versions
        .chunks(PAGE_SIZE)
        .map(|chunk| page_stub_json(&base, lower_id, chunk))
        .collect();
    json!({
        "@id": format!("{base}/registration/{lower_id}/index.json"),
        "@type": ["catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"],
        "count": pages.len(),
        "items": pages,
    })
}

/// Build the registration index JSON for a package's versions (ascending):
/// pages of [`PAGE_SIZE`], inlined up to [`MAX_INLINED_LEAVES`] versions.
pub fn registration_json(
    ctx: &RouteContext,
    lower_id: &str,
    entries: &[RegistrationEntry],
) -> Value {
    let base = ctx.base();
    let inline = entries.len() <= MAX_INLINED_LEAVES;
    let pages: Vec<Value> = entries
        .chunks(PAGE_SIZE)
        .map(|chunk| page_json(&base, lower_id, chunk, inline))
        .collect();
    json!({
        "@id": format!("{base}/registration/{lower_id}/index.json"),
        "@type": ["catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"],
        "count": pages.len(),
        "items": pages,
    })
}

/// Most versions one page request renders. A page an index advertised holds
/// [`PAGE_SIZE`]; versions pushed into its range since then can add more.
pub const MAX_PAGE_LEAVES: usize = 4 * PAGE_SIZE;

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
pub fn registration_page_json(
    ctx: &RouteContext,
    lower_id: &str,
    in_range: &[RegistrationEntry],
    lower: &str,
    upper: &str,
) -> Value {
    let base = ctx.base();
    let mut page = page_json(&base, lower_id, in_range, true);
    // The page answers for the bounds it was asked for.
    page["@id"] = json!(page_url(&base, lower_id, lower, upper));
    page["lower"] = json!(lower);
    page["upper"] = json!(upper);
    page
}

/// Handler: `GET`/`HEAD` `/registration/{id}/index.json`.
pub async fn index(State(ctx): State<RouteContext>, Path(id): Path<String>) -> Response {
    let Some(lower) = package_id(&ctx, &id) else {
        return (StatusCode::NOT_FOUND, "registration not found").into_response();
    };
    // A package with too many versions to inline gets an index of page
    // bounds: its versions' metadata is not loaded at all.
    let versions = match ctx.ops.registration_versions(&ctx.repo, &lower).await {
        Ok(v) => v,
        Err(e) => return repo_error_response(e),
    };
    if versions.len() > MAX_INLINED_LEAVES {
        return render_blocking(move || Some(paged_registration_json(&ctx, &lower, &versions)))
            .await;
    }
    let entries = match ctx.ops.registration(&ctx.repo, &lower).await {
        Ok(e) => e,
        Err(e) => return repo_error_response(e),
    };
    if entries.is_empty() {
        return (StatusCode::NOT_FOUND, "registration not found").into_response();
    }
    // Rendering (and, for versions without a stored summary, manifest
    // parsing) is CPU work: keep it off the async workers.
    render_blocking(move || Some(registration_json(&ctx, &lower, &entries))).await
}

/// Handler: `GET`/`HEAD` `/registration/{id}/page/{lower}/{upper}.json` — one
/// page of a paged registration index.
pub async fn page(
    State(ctx): State<RouteContext>,
    Path((id, lower_version, upper_file)): Path<(String, String, String)>,
) -> Response {
    let not_found = || (StatusCode::NOT_FOUND, "registration page not found").into_response();
    let Some(lower) = package_id(&ctx, &id) else {
        return not_found();
    };
    let Some(upper_version) = upper_file.strip_suffix(".json").map(str::to_string) else {
        return not_found();
    };
    let versions = match ctx.ops.registration_versions(&ctx.repo, &lower).await {
        Ok(v) => v,
        Err(e) => return repo_error_response(e),
    };
    let Some(in_range) = registration_page_versions(&versions, &lower_version, &upper_version)
    else {
        return not_found();
    };
    // Only the page's versions are loaded.
    let mut entries = match ctx
        .ops
        .registration_entries(&ctx.repo, &lower, in_range)
        .await
    {
        Ok(e) => e,
        Err(e) => return repo_error_response(e),
    };
    entries.sort_by(|a, b| version::compare(&a.version, &b.version));
    render_blocking(move || {
        Some(registration_page_json(
            &ctx,
            &lower,
            &entries,
            &lower_version,
            &upper_version,
        ))
    })
    .await
}

/// Build a JSON document on the blocking pool; `None` answers 404.
async fn render_blocking<F>(render: F) -> Response
where
    F: FnOnce() -> Option<Value> + Send + 'static,
{
    match tokio::task::spawn_blocking(render).await {
        Ok(Some(doc)) => Json(doc).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "registration page not found").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response(),
    }
}

/// Resolve `(id, "{version}.json")` to its registration entry.
#[allow(clippy::result_large_err)] // the Err is a ready-made axum Response
async fn find_entry(
    ctx: &RouteContext,
    id: &str,
    file: &str,
) -> Result<(String, RegistrationEntry), Response> {
    let not_found = || (StatusCode::NOT_FOUND, "registration leaf not found").into_response();
    let lower = package_id(ctx, id).ok_or_else(not_found)?;
    let raw_version = file.strip_suffix(".json").ok_or_else(not_found)?;
    let version = package_version(ctx, raw_version).ok_or_else(not_found)?;
    // One version, looked up directly (not every version of the package).
    let entry = ctx
        .ops
        .registration_entry(&ctx.repo, &lower, &version)
        .await
        .map_err(repo_error_response)?
        .ok_or_else(not_found)?;
    Ok((lower, entry))
}

/// Handler: `GET`/`HEAD` `/registration/{id}/{version}.json` — the
/// registration leaf document the index's leaf `@id`s point at.
pub async fn leaf_document(
    State(ctx): State<RouteContext>,
    Path((id, file)): Path<(String, String)>,
) -> Response {
    let (lower, entry) = match find_entry(&ctx, &id, &file).await {
        Ok(found) => found,
        Err(resp) => return resp,
    };
    let base = ctx.base();
    let mut doc = json!({
        "@id": leaf_url(&base, &lower, &entry.version),
        "@type": ["Package", "http://schema.nuget.org/catalog#Permalink"],
        "catalogEntry": catalog_url(&base, &lower, &entry.version),
        "listed": entry.listed,
        "packageContent": package_content_url(&base, &lower, &entry.version),
        "registration": format!("{base}/registration/{lower}/index.json"),
    });
    if let Some(published) = published(&entry) {
        doc["published"] = Value::String(published);
    }
    Json(doc).into_response()
}

/// Handler: `GET`/`HEAD` `/catalog/{id}/{version}.json` — the catalog entry a
/// registration leaf's `catalogEntry` URL points at.
pub async fn catalog_document(
    State(ctx): State<RouteContext>,
    Path((id, file)): Path<(String, String)>,
) -> Response {
    let (lower, entry) = match find_entry(&ctx, &id, &file).await {
        Ok(found) => found,
        Err(resp) => return resp,
    };
    Json(catalog_entry(&ctx.base(), &lower, &entry)).into_response()
}
