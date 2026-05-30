//! Registration (`RegistrationsBaseUrl/3.6.0`), spec §6 + Appendix A.
//!
//! Slice 1 always returns a single inlined page. Each leaf carries a
//! `catalogEntry` with id, version, `listed`, `packageHash` (base64 SHA-512) +
//! `packageHashAlgorithm`, an absolute `packageContent` URL, and
//! `dependencyGroups` extracted from the stored `.nuspec`.
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

/// Build a single registration leaf (`items[].items[]` element).
fn leaf(base: &str, lower_id: &str, entry: &RegistrationEntry) -> Value {
    let package_content = package_content_url(base, lower_id, &entry.version);
    let registration_leaf_id = format!("{base}/registration/{lower_id}/{}.json", entry.version);

    let mut catalog = serde_json::Map::new();
    catalog.insert(
        "@id".to_string(),
        Value::String(registration_leaf_id.clone()),
    );
    catalog.insert("id".to_string(), Value::String(entry.original_id.clone()));
    catalog.insert("version".to_string(), Value::String(entry.version.clone()));
    catalog.insert("listed".to_string(), Value::Bool(entry.listed));
    if let Some(hash) = &entry.package_hash_sha512_base64 {
        catalog.insert("packageHash".to_string(), Value::String(hash.clone()));
        catalog.insert(
            "packageHashAlgorithm".to_string(),
            Value::String("SHA512".to_string()),
        );
    }
    catalog.insert(
        "packageContent".to_string(),
        Value::String(package_content.clone()),
    );
    catalog.insert("dependencyGroups".to_string(), dependency_groups(entry));

    json!({
        "@id": registration_leaf_id,
        "catalogEntry": Value::Object(catalog),
        "packageContent": package_content,
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

    json!({
        "count": 1,
        "items": [{
            "@id": format!("{base}/registration/{lower_id}/index.json#page"),
            "count": leaves.len(),
            "lower": lower,
            "upper": upper,
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
