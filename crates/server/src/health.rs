//! Liveness / readiness probes for orchestrators and load balancers.
//!
//! * `GET /healthz` — liveness: the process is up and serving HTTP. Never
//!   touches a dependency, so a slow database does not get the pod killed.
//! * `GET /readyz` — readiness: PostgreSQL answers `SELECT 1` and the S3 bucket
//!   is reachable, each within a short deadline. Returns 503 with the failing
//!   check names otherwise, so traffic is routed away from an instance that
//!   cannot serve.
//!
//! * `GET /version` — the running build: crate version and, when the image was
//!   built with `FORGE_GIT_SHA`, the source revision.
//!
//! All are unauthenticated and reveal nothing beyond check names and the
//! build identity.

use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use serde_json::json;

use crate::state::AppState;

const CHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// Router with the probe and version endpoints.
pub fn health_router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/version", get(version))
}

async fn version() -> Response {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "revision": option_env!("FORGE_GIT_SHA").unwrap_or("unknown"),
    }))
    .into_response()
}

async fn healthz() -> Response {
    (StatusCode::OK, "ok").into_response()
}

async fn readyz(State(state): State<AppState>) -> Response {
    let db = tokio::time::timeout(
        CHECK_TIMEOUT,
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.pool),
    );
    let s3 = tokio::time::timeout(CHECK_TIMEOUT, state.blob_store.ping());
    let (db, s3) = tokio::join!(db, s3);

    let db_ok = matches!(db, Ok(Ok(1)));
    let s3_ok = matches!(s3, Ok(Ok(())));
    if !db_ok {
        tracing::warn!(result = ?db.map(|r| r.map(|_| ())), "readiness: database check failed");
    }
    if !s3_ok {
        tracing::warn!(result = ?s3.map(|r| r.map(|_| ())), "readiness: object-store check failed");
    }
    let status = if db_ok && s3_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status": if status == StatusCode::OK { "ok" } else { "unavailable" },
            "checks": { "database": db_ok, "object_store": s3_ok },
        })),
    )
        .into_response()
}
