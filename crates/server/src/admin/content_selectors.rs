//! Admin content-selector management.
//!
//! A content selector is a reusable named include/exclude glob set on the
//! (lowercased) package name. It scopes a grant down to matching packages.
//!
//! * `GET    /admin/content-selectors`        — list.
//! * `POST   /admin/content-selectors`        — create.
//! * `GET    /admin/content-selectors/{id}`   — fetch one.
//! * `PATCH  /admin/content-selectors/{id}`   — update description/includes/excludes
//!   (true PATCH: an omitted field keeps its stored value).
//! * `DELETE /admin/content-selectors/{id}`   — delete (cascades scoped grants).
//!
//! Globs are validated at write time by compiling them: an invalid pattern is a
//! **400**, never persisted (a selector that can't compile would fail-closed at
//! evaluation, so we reject it early). Every mutation blanket-invalidates the
//! authz cache (a selector edit changes which packages a scoped grant exposes).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::authz::{invalidate_all, SelectorPatterns};
use forge_db::authz_dao::{self, ContentSelector};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::db_error;
use crate::state::AppState;

/// A content-selector view.
#[derive(Debug, Serialize)]
pub struct SelectorView {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub includes: JsonValue,
    pub excludes: JsonValue,
}

impl From<ContentSelector> for SelectorView {
    fn from(s: ContentSelector) -> Self {
        SelectorView {
            id: s.id,
            name: s.name,
            description: s.description,
            includes: s.includes,
            excludes: s.excludes,
        }
    }
}

/// Create-selector request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSelector {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
}

/// Update-selector request (name is immutable) with **PATCH semantics**: an
/// absent (or `null`) field keeps the stored value; a present one replaces it.
///
/// This matters for safety, not just convenience: an empty `includes` list
/// means *match-all*, so defaulting an omitted `includes` to `[]` would turn a
/// scoped selector into "every package" for every grant that uses it. To
/// really make a selector match all packages, send `"includes": []`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSelector {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub includes: Option<Vec<String>>,
    #[serde(default)]
    pub excludes: Option<Vec<String>>,
}

/// Validate that every include/exclude glob compiles, returning a ready 400
/// response on the first invalid pattern (or `None` when all compile). Returning
/// `Option<Response>` rather than `Result<(), Response>` keeps clippy's
/// `result_large_err` lint happy (the boxed `Response` is large).
fn glob_error(includes: &[String], excludes: &[String]) -> Option<Response> {
    let patterns = SelectorPatterns {
        includes: includes.to_vec(),
        excludes: excludes.to_vec(),
    };
    match patterns.compile_check() {
        Ok(()) => None,
        Err(e) => Some(
            (
                StatusCode::BAD_REQUEST,
                format!("invalid content-selector glob: {e}"),
            )
                .into_response(),
        ),
    }
}

/// `GET /admin/content-selectors`
pub async fn list(State(state): State<AppState>) -> Response {
    match authz_dao::list_content_selectors(&state.pool).await {
        Ok(sels) => {
            let views: Vec<SelectorView> = sels.into_iter().map(SelectorView::from).collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `GET /admin/content-selectors/{id}`
pub async fn get(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match authz_dao::find_content_selector_by_id(&state.pool, id).await {
        Ok(Some(s)) => Json(SelectorView::from(s)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "content selector not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// `POST /admin/content-selectors`
pub async fn create(State(state): State<AppState>, Json(body): Json<CreateSelector>) -> Response {
    let name = body.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "selector name is required").into_response();
    }
    if let Some(resp) = glob_error(&body.includes, &body.excludes) {
        return resp;
    }
    match authz_dao::create_content_selector(
        &state.pool,
        name,
        &body.description,
        &body.includes,
        &body.excludes,
    )
    .await
    {
        Ok(s) => {
            // A new selector is referenced by no grant yet; invalidate
            // defensively against id/TTL reuse.
            invalidate_all(&state.cache).await;
            (StatusCode::CREATED, Json(SelectorView::from(s))).into_response()
        }
        Err(e) if is_unique_violation(&e) => {
            (StatusCode::CONFLICT, "selector name already exists").into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `PATCH /admin/content-selectors/{id}`
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateSelector>,
) -> Response {
    // Each list compiles independently, so validating only the supplied ones
    // is enough (the stored ones were validated when they were written).
    if let Some(resp) = glob_error(
        body.includes.as_deref().unwrap_or_default(),
        body.excludes.as_deref().unwrap_or_default(),
    ) {
        return resp;
    }
    match authz_dao::update_content_selector(
        &state.pool,
        id,
        body.description.as_deref(),
        body.includes.as_deref(),
        body.excludes.as_deref(),
    )
    .await
    {
        Ok(Some(s)) => {
            invalidate_all(&state.cache).await;
            Json(SelectorView::from(s)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "content selector not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/content-selectors/{id}`
pub async fn delete(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match authz_dao::delete_content_selector(&state.pool, id).await {
        Ok(true) => {
            invalidate_all(&state.cache).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "content selector not found").into_response(),
        Err(e) => db_error(e),
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}
