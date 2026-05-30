//! Search (`SearchQueryService/3.5.0`), spec §6 + Appendix A.
//!
//! `GET {base}/query?q=&skip=&take=&prerelease=&semVerLevel=` →
//! `{ totalHits, data: [ { id, version, description, versions: [...] } ] }`.
//!
//! `prerelease` defaults to `false`; `skip`/`take` are clamped by the core op.
//! `semVerLevel` is accepted for client compatibility — slice 1 always returns
//! SemVer2 versions when `prerelease` is set, so no additional filtering is
//! applied here.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::response::Json;
use forge_core::repo::SearchParams;
use serde_json::{json, Value};

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
    }
}

/// Build the search-response JSON from core search results.
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
                        "@id": format!("{base}/registration/{lower_id}/{}.json", v.version),
                    })
                })
                .collect();
            json!({
                "id": hit.original_id,
                "version": hit.latest_version,
                "description": "",
                "versions": versions,
            })
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
