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
//! Hard delete is an admin operation, exposed via [`admin_hard_delete`] and
//! wired by the server under `/admin/...` (Phase 10), not advertised here.

use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use forge_core::{DeleteOutcome, PublishOutcome};
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
    if !ctx.protocol_mutations_allowed {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                "API token or workload identity required",
            )
                .into_response(),
        );
    }
    if !headers.contains_key(API_KEY_HEADER)
        && !headers.contains_key(axum::http::header::AUTHORIZATION)
    {
        return Some((StatusCode::UNAUTHORIZED, "missing credentials").into_response());
    }
    None
}

/// Handler: `PUT /package` — publish (or redeploy) a `.nupkg`.
pub async fn push(
    State(ctx): State<RouteContext>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    let Some(write) = ctx.write.clone() else {
        // Should never be mounted for non-hosted repos; guard anyway.
        return (StatusCode::NOT_FOUND, "publish not supported").into_response();
    };

    // Push requires authentication: an API key must be present.
    if let Some(resp) = require_write_credentials(&ctx, &headers) {
        return resp;
    }

    // Build an **owned** byte stream over the first multipart part so it can be
    // handed to the CAS as a `'static` reader. The stream owns `multipart`,
    // yielding the package bytes chunk-by-chunk (true streaming — never buffered
    // whole in memory; the CAS enforces the size cap as it copies to disk).
    let byte_stream = async_stream::try_stream! {
        let mut multipart = multipart;
        match multipart.next_field().await {
            Ok(Some(mut field)) => {
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => yield chunk,
                        Ok(None) => break,
                        Err(e) => Err(std::io::Error::other(e))?,
                    }
                }
            }
            Ok(None) => Err(std::io::Error::other("missing package part"))?,
            Err(e) => Err(std::io::Error::other(e))?,
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
    if !ctx.package_filter.allows(&ctx.format.lower_id(&id)) {
        return (StatusCode::NOT_FOUND, "package not found").into_response();
    }
    delete_version(&ctx, &id, &version, false).await
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
    if !ctx.package_filter.allows(&ctx.format.lower_id(&id)) {
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

/// Admin-only hard delete: `DELETE /admin/repositories/{repo}/packages/{id}/{ver}`.
///
/// Wired into the server under the admin router (Phase 10); admin authorization
/// is enforced there. Removes the component + assets and dereferences the
/// backing blobs (deferred S3 delete via the outbox). 204 / 404.
pub async fn admin_hard_delete(
    State(ctx): State<RouteContext>,
    Path((id, version)): Path<(String, String)>,
) -> Response {
    delete_version(&ctx, &id, &version, true).await
}

/// Shared delete path for soft (unlist) and hard (admin) removal.
async fn delete_version(ctx: &RouteContext, id: &str, version: &str, hard: bool) -> Response {
    let Some(write) = ctx.write.clone() else {
        return (StatusCode::NOT_FOUND, "delete not supported").into_response();
    };
    match write.delete_component(&ctx.repo, id, version, hard).await {
        Ok(DeleteOutcome::Unlisted) | Ok(DeleteOutcome::Deleted) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(DeleteOutcome::NotFound) => (StatusCode::NOT_FOUND, "package not found").into_response(),
        Ok(DeleteOutcome::Relisted) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => write_error_response(e),
    }
}
