//! The local blob cache's statistics.
//!
//! * `GET /admin/blob-cache` → `{"enabled": false}` without a cache;
//!   otherwise its size, effective limit and activity since startup (hit
//!   ratio, bytes served from the cache, fills, evictions, hits served while
//!   S3 was down) — see [`crate::object_store::stats_json`]. Each instance
//!   has a cache of its own: the numbers are those of the instance that
//!   answered, which `instance` names (host name and start time).

use axum::extract::State;
use axum::response::{IntoResponse, Json, Response};

use crate::state::AppState;

/// `GET /admin/blob-cache`
pub async fn stats(State(state): State<AppState>) -> Response {
    Json(crate::object_store::stats_json(
        &state.blob_store,
        &state.instance,
    ))
    .into_response()
}
