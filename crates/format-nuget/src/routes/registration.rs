//! Registration (`RegistrationsBaseUrl`, all 3.x variants), spec §6 +
//! Appendix A.
//!
//! The index always returns a single inlined page. Each leaf carries a
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

use crate::nuspec;
use crate::routes::{repo_error_response, RouteContext};

/// Build the absolute `packageContent` URL for a `(lower_id, version)`.
fn package_content_url(base: &str, lower_id: &str, version: &str) -> String {
    // {base}/flat/{lower_id}/{lower_ver}/{lower_id}.{lower_ver}.nupkg
    let lower_ver = version.to_ascii_lowercase();
    format!("{base}/flat/{lower_id}/{lower_ver}/{lower_id}.{lower_ver}.nupkg")
}

/// Render the `dependencyGroups` JSON array from stored nuspec bytes.
///
/// A parse failure (or missing nuspec) yields an empty array rather than
/// failing the whole registration page.
fn dependency_groups(entry: &RegistrationEntry) -> Value {
    let groups = match entry.nuspec_bytes.as_deref() {
        Some(bytes) => nuspec::dependency_groups_from_nuspec(bytes).unwrap_or_default(),
        None => Vec::new(),
    };
    let arr: Vec<Value> = groups
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
    put("dependencyGroups", dependency_groups(entry));

    let meta = entry
        .nuspec_bytes
        .as_deref()
        .and_then(|b| nuspec::metadata_from_nuspec(b).ok())
        .unwrap_or_default();
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

/// Build the full registration index JSON for a package's versions.
pub fn registration_json(
    ctx: &RouteContext,
    lower_id: &str,
    entries: &[RegistrationEntry],
) -> Value {
    let base = ctx.base();
    let leaves: Vec<Value> = entries.iter().map(|e| leaf(&base, lower_id, e)).collect();

    // Entries are ascending by precedence, so first = lower, last = upper.
    let lower = entries
        .first()
        .map(|e| e.version.clone())
        .unwrap_or_default();
    let upper = entries
        .last()
        .map(|e| e.version.clone())
        .unwrap_or_default();

    let index_url = format!("{base}/registration/{lower_id}/index.json");
    json!({
        "@id": index_url,
        "@type": ["catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"],
        "count": 1,
        "items": [{
            "@id": format!("{index_url}#page/{lower}/{upper}"),
            "@type": "catalog:CatalogPage",
            "count": leaves.len(),
            "lower": lower,
            "upper": upper,
            "parent": index_url,
            "items": leaves,
        }],
    })
}

/// Handler: `GET`/`HEAD` `/registration/{id}/index.json`.
pub async fn index(State(ctx): State<RouteContext>, Path(id): Path<String>) -> Response {
    let lower = ctx.format.lower_id(&id);
    let entries = match ctx.ops.registration(&ctx.repo, &lower).await {
        Ok(e) => e,
        Err(e) => return repo_error_response(e),
    };
    if entries.is_empty() {
        return (StatusCode::NOT_FOUND, "registration not found").into_response();
    }
    Json(registration_json(&ctx, &lower, &entries)).into_response()
}

/// Resolve `(id, "{version}.json")` to its registration entry.
#[allow(clippy::result_large_err)] // the Err is a ready-made axum Response
async fn find_entry(
    ctx: &RouteContext,
    id: &str,
    file: &str,
) -> Result<(String, RegistrationEntry), Response> {
    let not_found = || (StatusCode::NOT_FOUND, "registration leaf not found").into_response();
    let lower = ctx.format.lower_id(id);
    let raw_version = file.strip_suffix(".json").ok_or_else(not_found)?;
    let version = ctx
        .format
        .normalize_version(raw_version)
        .map_err(|_| not_found())?;
    let entries = ctx
        .ops
        .registration(&ctx.repo, &lower)
        .await
        .map_err(repo_error_response)?;
    let entry = entries
        .into_iter()
        .find(|e| e.version.eq_ignore_ascii_case(&version))
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
