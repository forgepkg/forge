//! Search (`SearchQueryService/3.5.0`), spec §6 + Appendix A.
//!
//! `GET {base}/query?q=&skip=&take=&prerelease=&semVerLevel=` →
//! `{ totalHits, data: [ { id, version, description, versions: [...] } ] }`.
//!
//! `prerelease` defaults to `false`; `skip`/`take` are clamped by the core op.
//! `q` understands `packageid:`, `id:` and multi-term queries (see
//! [`forge_core::repo::SearchQuery`]). SemVer 2.0.0 versions (dotted
//! prerelease labels, build metadata) are only returned to clients that send
//! `semVerLevel=2.0.0`, as the protocol requires; core drops them before
//! counting and paging, so pages stay full and `totalHits` exact. Hits carry
//! description, authors, tags, icon/project/license URLs, package types and
//! total downloads from the latest version's manifest.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::response::Json;
use forge_core::repo::SearchParams;
use serde_json::{json, Value};

use crate::nuspec;
use crate::routes::RouteContext;

/// Parse the raw query map into [`SearchParams`].
fn parse_params(raw: &HashMap<String, String>) -> SearchParams {
    let q = raw.get("q").cloned().unwrap_or_default();
    let skip = raw
        .get("skip")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let take = raw
        .get("take")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(SearchParams::DEFAULT_TAKE);
    let prerelease = raw
        .get("prerelease")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    SearchParams {
        q,
        skip,
        take,
        prerelease,
        include_semver2: wants_semver2(raw),
    }
}

/// Whether the client asked for SemVer 2.0.0 packages (`semVerLevel=2.0.0`
/// or higher). Without it, SemVer2 versions must not be returned.
fn wants_semver2(raw: &HashMap<String, String>) -> bool {
    raw.get("semVerLevel")
        .and_then(|v| v.split('.').next())
        .and_then(|major| major.trim().parse::<u32>().ok())
        .is_some_and(|major| major >= 2)
}

/// Build the search-response JSON from core search results.
///
/// Version filtering (listed, prerelease, SemVer 2.0.0) already happened in
/// core, before paging, so every hit and `total_hits` are rendered as is.
pub fn search_json(ctx: &RouteContext, result: &forge_core::repo::SearchResult) -> Value {
    let base = ctx.base();
    let data: Vec<Value> = result
        .hits
        .iter()
        .map(|hit| {
            let lower_id = ctx.format.lower_id(&hit.original_id);
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
            let meta =
                nuspec::summary_of(hit.manifest_summary.as_ref(), hit.nuspec_bytes.as_deref())
                    .metadata;
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
        "totalHits": result.total_hits,
        "data": data,
    })
}

/// Handler: `GET`/`HEAD` `/query`.
pub async fn query(
    State(ctx): State<RouteContext>,
    Query(raw): Query<HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let params = parse_params(&raw);
    match ctx.ops.search(&ctx.repo, &params).await {
        Ok(result) => Json(search_json(&ctx, &result)).into_response(),
        Err(e) => crate::routes::repo_error_response(e),
    }
}
