//! PackagePublish surface (`PackagePublish/2.0.0`, spec §6, hosted only).
//!
//! * `PUT /package` — `multipart/form-data`; the first part is the raw `.nupkg`,
//!   streamed straight through the content-addressed store with a
//!   `max_upload_bytes` cap (413 on overrun). Requires an `X-NuGet-ApiKey`
//!   header (principal authorization is enforced upstream in the server's
//!   middleware/dispatch). Returns 201 on create/redeploy, 400 on an invalid
//!   package, 409 on a duplicate when redeploy is disabled.
//! * `DELETE /package/{id}/{version}` — **unlist** (soft delete): 204 / 404.
//! * `POST /package/{id}/{version}` — relist: 200 / 404.
//!
//! Hard delete is an admin operation of the server's admin API
//! (`DELETE /admin/repositories/{repo}/packages/{id}/{version}`), not part of
//! the feed surface.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRequest, Multipart, Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use forge_core::{DeleteOutcome, PublishOutcome};
use futures_util::{Stream, StreamExt};
use tokio_util::io::StreamReader;

use crate::routes::{write_error_response, RouteContext};

/// Header carrying the NuGet API key on publish/delete requests.
const API_KEY_HEADER: &str = "X-NuGet-ApiKey";

/// Enforce presence of a wire credential on write routes.
///
/// The outer server middleware has already authenticated the value. This local
/// route guard accepts every transport supported by WIF: `X-NuGet-ApiKey`,
/// `Authorization: Bearer`, or Basic with the workload token as password.
fn require_write_credentials(ctx: &RouteContext, headers: &HeaderMap) -> Option<Response> {
    // Same Basic challenge as the dispatcher's 401, so clients know to send
    // the stored source credentials (token as password).
    let challenge = [(
        axum::http::header::WWW_AUTHENTICATE,
        "Basic realm=\"Forge\"",
    )];
    if !ctx.protocol_mutations_allowed {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                challenge,
                "API token or workload identity required",
            )
                .into_response(),
        );
    }
    if !headers.contains_key(API_KEY_HEADER)
        && !headers.contains_key(axum::http::header::AUTHORIZATION)
    {
        return Some((StatusCode::UNAUTHORIZED, challenge, "missing credentials").into_response());
    }
    None
}

/// Most bytes a push body may carry before the headers of its first part are
/// complete (any preamble, the first boundary and the part headers). The
/// multipart parser buffers everything up to the first boundary in memory, so
/// without this bound one request could make it hold `max_upload_bytes`.
pub const MAX_MULTIPART_PREAMBLE_BYTES: usize = 64 * 1024;

/// The `boundary` parameter of a `multipart/form-data` content type.
pub fn multipart_boundary(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"').to_string())
            .filter(|b| !b.is_empty())
    })
}

/// Pass `body` through unchanged, but fail it (setting `overrun`) once
/// [`MAX_MULTIPART_PREAMBLE_BYTES`] have gone by without the first part's
/// headers being complete.
pub fn preamble_guard(
    body: impl Stream<Item = Result<Bytes, axum::Error>> + Send + 'static,
    boundary: &str,
    overrun: Arc<AtomicBool>,
) -> impl Stream<Item = Result<Bytes, axum::Error>> + Send + 'static {
    let delimiter = format!("--{boundary}").into_bytes();
    async_stream::try_stream! {
        let mut head: Option<Vec<u8>> = Some(Vec::new());
        let mut delimiter_at: Option<usize> = None;
        // How far `head` has been searched for what is still being looked
        // for. Each search resumes a needle's length before that, so a match
        // split across chunks is found and a body trickled in tiny chunks
        // costs linear, not quadratic, time.
        let mut searched = 0usize;
        futures_util::pin_mut!(body);
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            if let Some(seen) = head.as_mut() {
                // Only the first MAX + 1 bytes matter: the first part's
                // headers must end within them.
                let room = (MAX_MULTIPART_PREAMBLE_BYTES + 1).saturating_sub(seen.len());
                seen.extend_from_slice(&chunk[..chunk.len().min(room)]);
                if delimiter_at.is_none() {
                    let from = searched.saturating_sub(delimiter.len());
                    match find(&seen[from..], &delimiter) {
                        Some(i) => {
                            delimiter_at = Some(from + i);
                            searched = from + i;
                        }
                        None => searched = seen.len(),
                    }
                }
                let mut headers_end = None;
                if let Some(at) = delimiter_at {
                    let from = searched.saturating_sub(4).max(at);
                    match find(&seen[from..], b"\r\n\r\n") {
                        Some(i) => headers_end = Some(from + i + 4),
                        None => searched = seen.len(),
                    }
                }
                if headers_end.is_some_and(|end| end <= MAX_MULTIPART_PREAMBLE_BYTES) {
                    head = None;
                } else if seen.len() > MAX_MULTIPART_PREAMBLE_BYTES {
                    overrun.store(true, Ordering::Relaxed);
                    Err(axum::Error::new(std::io::Error::other(
                        "multipart preamble exceeds its limit",
                    )))?;
                }
            }
            yield chunk;
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Handler: `PUT /package` — publish (or redeploy) a `.nupkg`.
pub async fn push(State(ctx): State<RouteContext>, req: Request) -> Response {
    let Some(write) = ctx.write.clone() else {
        // Should never be mounted for non-hosted repos; guard anyway.
        return (StatusCode::NOT_FOUND, "publish not supported").into_response();
    };

    // Push requires authentication: an API key must be present.
    if let Some(resp) = require_write_credentials(&ctx, req.headers()) {
        return resp;
    }

    // Bound what the multipart parser may buffer before the package bytes
    // start (see [`MAX_MULTIPART_PREAMBLE_BYTES`]).
    let preamble_overrun = Arc::new(AtomicBool::new(false));
    let req = match req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(multipart_boundary)
    {
        Some(boundary) => {
            let (parts, body) = req.into_parts();
            let guarded =
                preamble_guard(body.into_data_stream(), &boundary, preamble_overrun.clone());
            Request::from_parts(parts, Body::from_stream(guarded))
        }
        // Not multipart: the extractor below refuses it.
        None => req,
    };
    let multipart = match Multipart::from_request(req, &()).await {
        Ok(multipart) => multipart,
        Err(rejection) => return rejection.into_response(),
    };

    // Build an **owned** byte stream over the first multipart part so it can be
    // handed to the CAS as a `'static` reader. The stream owns `multipart`,
    // yielding the package bytes chunk-by-chunk (true streaming — never buffered
    // whole in memory; the CAS enforces the size cap as it copies to disk).
    //
    // The request body limit (set on the publish routes, see
    // `routes::nuget_router`) surfaces here as a multipart error with status
    // 413; remember it so the response is a 413, not a generic storage error.
    let body_limit_hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let limit_flag = body_limit_hit.clone();
    let multipart_err = move |e: axum::extract::multipart::MultipartError| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            limit_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        std::io::Error::other(e)
    };
    let byte_stream = async_stream::try_stream! {
        let mut multipart = multipart;
        match multipart.next_field().await {
            Ok(Some(mut field)) => {
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => yield chunk,
                        Ok(None) => break,
                        Err(e) => Err(multipart_err(e))?,
                    }
                }
            }
            Ok(None) => Err(std::io::Error::other("missing package part"))?,
            Err(e) => Err(multipart_err(e))?,
        }
    };
    let byte_stream: std::pin::Pin<
        Box<dyn futures_util::Stream<Item = std::io::Result<Bytes>> + Send>,
    > = Box::pin(byte_stream);
    let reader: forge_core::UploadReader = Box::new(StreamReader::new(byte_stream));

    match write
        .store_upload(&ctx.repo, reader, ctx.max_upload_bytes)
        .await
    {
        // Both create and redeploy return 201 Created per the NuGet protocol.
        Ok(PublishOutcome::Created) | Ok(PublishOutcome::Replaced) => {
            StatusCode::CREATED.into_response()
        }
        Err(_) if body_limit_hit.load(std::sync::atomic::Ordering::Relaxed) => {
            write_error_response(forge_core::WriteError::TooLarge {
                limit: ctx.max_upload_bytes,
            })
        }
        Err(_) if preamble_overrun.load(Ordering::Relaxed) => (
            StatusCode::BAD_REQUEST,
            "multipart body: no package part within the first 64 KiB",
        )
            .into_response(),
        Err(e) => write_error_response(e),
    }
}

/// Handler: `DELETE /package/{id}/{version}` — unlist (soft delete).
pub async fn unlist(
    State(ctx): State<RouteContext>,
    headers: HeaderMap,
    Path((id, version)): Path<(String, String)>,
) -> Response {
    if let Some(resp) = require_write_credentials(&ctx, &headers) {
        return resp;
    }
    if !super::package_id(&ctx, &id).is_some_and(|lower| ctx.package_filter.allows(&lower))
        || super::package_version(&ctx, &version).is_none()
    {
        return (StatusCode::NOT_FOUND, "package not found").into_response();
    }
    unlist_version(&ctx, &id, &version).await
}

/// Handler: `POST /package/{id}/{version}` — relist.
pub async fn relist(
    State(ctx): State<RouteContext>,
    headers: HeaderMap,
    Path((id, version)): Path<(String, String)>,
) -> Response {
    if let Some(resp) = require_write_credentials(&ctx, &headers) {
        return resp;
    }
    if !super::package_id(&ctx, &id).is_some_and(|lower| ctx.package_filter.allows(&lower))
        || super::package_version(&ctx, &version).is_none()
    {
        return (StatusCode::NOT_FOUND, "package not found").into_response();
    }
    let Some(write) = ctx.write.clone() else {
        return (StatusCode::NOT_FOUND, "relist not supported").into_response();
    };
    match write.relist(&ctx.repo, &id, &version).await {
        Ok(DeleteOutcome::Relisted) => StatusCode::OK.into_response(),
        Ok(DeleteOutcome::NotFound) => (StatusCode::NOT_FOUND, "package not found").into_response(),
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => write_error_response(e),
    }
}

/// Unlist (soft-delete) a version.
async fn unlist_version(ctx: &RouteContext, id: &str, version: &str) -> Response {
    let Some(write) = ctx.write.clone() else {
        return (StatusCode::NOT_FOUND, "delete not supported").into_response();
    };
    match write.delete_component(&ctx.repo, id, version, false).await {
        Ok(DeleteOutcome::Unlisted) | Ok(DeleteOutcome::Deleted) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(DeleteOutcome::NotFound) => (StatusCode::NOT_FOUND, "package not found").into_response(),
        Ok(DeleteOutcome::Relisted) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => write_error_response(e),
    }
}
