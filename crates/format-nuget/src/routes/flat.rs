//! Flat container (`PackageBaseAddress/3.0.0`), spec §6 + Appendix A.
//!
//! * `GET {base}/flat/{id}/index.json` → `{ "versions": [..] }` (normalized,
//!   lowercased, **including unlisted**; 404 if the id has no versions).
//! * `GET {base}/flat/{id}/{version}/{file}` → `.nupkg` bytes or `.nuspec` XML.
//!
//! Ids are lowercased and versions normalized via the repository [`Format`]
//! before lookup, so callers may use any casing / version spelling.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};

use crate::routes::{package_id, repo_error_response, RouteContext};

/// Handler: `GET`/`HEAD` `/flat/{id}/index.json`.
pub async fn versions(State(ctx): State<RouteContext>, Path(id): Path<String>) -> Response {
    let Some(lower) = package_id(&ctx, &id) else {
        return (StatusCode::NOT_FOUND, "package not found").into_response();
    };
    let versions = match ctx.ops.list_versions(&ctx.repo, &lower).await {
        Ok(v) => v,
        Err(e) => return repo_error_response(e),
    };
    if versions.is_empty() {
        return (StatusCode::NOT_FOUND, "package not found").into_response();
    }
    let body: Value = json!({
        "versions": versions.iter().map(|v| v.version.clone()).collect::<Vec<_>>(),
    });
    Json(body).into_response()
}

/// Handler: `GET`/`HEAD` `/flat/{id}/{version}/{filename}`.
///
/// Dispatches on the filename extension: `*.nupkg` streams the package blob,
/// `*.nuspec` serves the stored manifest. The id/version embedded in the
/// filename are not trusted; the `{id}`/`{version}` path segments drive lookup.
pub async fn content(
    State(ctx): State<RouteContext>,
    method: Method,
    Path((id, version, filename)): Path<(String, String, String)>,
) -> Response {
    let Some(lower) = package_id(&ctx, &id) else {
        return (StatusCode::NOT_FOUND, "package not found").into_response();
    };
    let norm_ver = match ctx.format.normalize_version(&version) {
        Ok(v) => v,
        Err(_) => return (StatusCode::NOT_FOUND, "invalid version").into_response(),
    };

    let lower_file = filename.to_ascii_lowercase();
    if lower_file.ends_with(".nupkg") {
        serve_nupkg(&ctx, &lower, &norm_ver, method == Method::HEAD).await
    } else if lower_file.ends_with(".nuspec") {
        serve_nuspec(&ctx, &lower, &norm_ver).await
    } else {
        (StatusCode::NOT_FOUND, "unknown content").into_response()
    }
}

async fn serve_nupkg(ctx: &RouteContext, id: &str, version: &str, head: bool) -> Response {
    let loc = match ctx.ops.resolve_nupkg(&ctx.repo, id, version).await {
        Ok(Some(l)) => l,
        Ok(None) => return (StatusCode::NOT_FOUND, "package not found").into_response(),
        Err(e) => return repo_error_response(e),
    };
    let headers = [
        (header::CONTENT_TYPE, loc.content_type.clone()),
        (header::CONTENT_LENGTH, loc.size.to_string()),
    ];
    // A HEAD only needs the headers; don't open (or bill) an S3 GET for it.
    if head {
        return (StatusCode::OK, headers).into_response();
    }
    let stream = match ctx.nupkg.open(&loc.blob_s3_key).await {
        Ok(s) => s,
        Err(e) => return repo_error_response(e),
    };
    (StatusCode::OK, headers, Body::from_stream(stream)).into_response()
}

async fn serve_nuspec(ctx: &RouteContext, id: &str, version: &str) -> Response {
    let bytes = match ctx.ops.resolve_nuspec(&ctx.repo, id, version).await {
        Ok(Some(b)) => b,
        Ok(None) => return (StatusCode::NOT_FOUND, "nuspec not found").into_response(),
        Err(e) => return repo_error_response(e),
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/xml".to_string()),
            (header::CONTENT_LENGTH, bytes.len().to_string()),
        ],
        Body::from(bytes),
    )
        .into_response()
}
