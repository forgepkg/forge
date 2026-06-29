//! Admin auth-realm CRUD (12.7 §3.5). **Admin-only** (mounted behind
//! [`super::require_admin`]).
//!
//! Secrets inside a realm `config` (OIDC `client_secret`, credential-forwarding
//! `key_pepper`) are **write-only**: every response carries a redacted config
//! (`<key>_set` markers instead of values) and an update that omits/blanks a
//! secret keeps the stored one.
//!
//! Every successful write invalidates the local realm snapshot so this
//! instance converges immediately; peers converge within
//! `auth.realm_cache_ttl_seconds`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use forge_db::auth_realm_dao::{self, AuthRealmUpdate, NewAuthRealm};
use forge_db::model::AuthRealm;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::db_error;
use crate::auth::{merge_secrets, redact_config, validate_config, KIND_LOCAL, KIND_OIDC};
use crate::state::AppState;

/// Secret-free view of a realm (config redacted via
/// [`crate::auth::redact_config`]).
#[derive(Debug, Serialize)]
pub struct RealmView {
    pub id: i64,
    pub kind: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub config: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&AuthRealm> for RealmView {
    fn from(r: &AuthRealm) -> Self {
        RealmView {
            id: r.id,
            kind: r.kind.clone(),
            name: r.name.clone(),
            enabled: r.enabled,
            priority: r.priority,
            config: redact_config(&r.kind, &r.config),
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Create-realm request body.
#[derive(Debug, Deserialize)]
pub struct CreateRealm {
    /// `local` | `oidc` | `credential_forwarding` | `workload_identity`.
    pub kind: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Kind-specific config; validated and normalized before persisting.
    #[serde(default)]
    pub config: JsonValue,
}

/// Update-realm request body. Absent fields keep their stored value; `kind` is
/// immutable; ordering changes go through the dedicated reorder endpoint.
#[derive(Debug, Deserialize)]
pub struct UpdateRealm {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<JsonValue>,
}

/// Reorder request body: the complete desired try-order (every realm id).
#[derive(Debug, Deserialize)]
pub struct ReorderRealms {
    pub order: Vec<i64>,
}

fn default_true() -> bool {
    true
}

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

/// Refuse a write that would leave more than one **enabled** `oidc` realm
/// (12.7 ships single-IdP; multi-IdP selection/routing is a later slice).
async fn assert_single_enabled_oidc(
    state: &AppState,
    exclude_id: Option<i64>,
) -> Result<(), Response> {
    match auth_realm_dao::list_enabled_realms(&state.pool).await {
        Ok(realms) => {
            let other = realms
                .iter()
                .any(|r| r.kind == KIND_OIDC && Some(r.id) != exclude_id);
            if other {
                Err(bad_request(
                    "only one enabled oidc realm is supported (disable the other first)",
                ))
            } else {
                Ok(())
            }
        }
        Err(e) => Err(db_error(e)),
    }
}

/// `GET /admin/realms` — all realms in try-order, configs redacted.
pub async fn list(State(state): State<AppState>) -> Response {
    match auth_realm_dao::list_realms(&state.pool).await {
        Ok(realms) => {
            let views: Vec<RealmView> = realms.iter().map(RealmView::from).collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `GET /admin/realms/{id}`
pub async fn get(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match auth_realm_dao::find_realm_by_id(&state.pool, id).await {
        Ok(Some(r)) => Json(RealmView::from(&r)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "realm not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// `POST /admin/realms` — create a realm (appended at the end of the order).
pub async fn create(State(state): State<AppState>, Json(body): Json<CreateRealm>) -> Response {
    if body.kind == KIND_LOCAL {
        // Exactly one local realm exists (seeded by migration); a second adds
        // nothing — the same provider twice.
        return bad_request("the built-in local realm already exists");
    }
    let config = match validate_config(&body.kind, &body.config) {
        Ok(c) => c,
        Err(msg) => return bad_request(msg),
    };
    if body.kind == KIND_OIDC && body.enabled {
        if let Err(resp) = assert_single_enabled_oidc(&state, None).await {
            return resp;
        }
    }

    let priority = match auth_realm_dao::next_priority(&state.pool).await {
        Ok(p) => p,
        Err(e) => return db_error(e),
    };
    let new = NewAuthRealm {
        kind: body.kind.clone(),
        name: body.name.trim().to_string(),
        enabled: body.enabled,
        priority,
        config,
    };
    match auth_realm_dao::insert_realm(&state.pool, new).await {
        Ok(r) => {
            state.realms.invalidate().await;
            tracing::info!(realm = %r.name, kind = %r.kind, "auth realm created");
            (StatusCode::CREATED, Json(RealmView::from(&r))).into_response()
        }
        Err(e) if is_unique_violation(&e) => {
            (StatusCode::CONFLICT, "realm name already exists").into_response()
        }
        // The DB CHECK constraints (kind set, name shape) surface as 23514.
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23514") => {
            bad_request("invalid realm name (lowercase slug) or kind")
        }
        Err(e) => db_error(e),
    }
}

/// `PATCH /admin/realms/{id}` — update name/enabled/config (kind immutable).
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateRealm>,
) -> Response {
    let existing = match auth_realm_dao::find_realm_by_id(&state.pool, id).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
        Err(e) => return db_error(e),
    };

    let enabled = body.enabled.unwrap_or(existing.enabled);
    if existing.kind == KIND_OIDC && enabled {
        if let Err(resp) = assert_single_enabled_oidc(&state, Some(existing.id)).await {
            return resp;
        }
    }

    // Merge write-only secrets from the stored config, then re-validate the
    // full document (an update may not leave a realm in an invalid state).
    let config = match &body.config {
        Some(incoming) => {
            let merged = merge_secrets(&existing.kind, &existing.config, incoming);
            match validate_config(&existing.kind, &merged) {
                Ok(c) => c,
                Err(msg) => return bad_request(msg),
            }
        }
        None => existing.config.clone(),
    };

    let upd = AuthRealmUpdate {
        name: body
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .unwrap_or(&existing.name)
            .to_string(),
        enabled,
        priority: existing.priority,
        config,
    };
    match auth_realm_dao::update_realm(&state.pool, id, upd).await {
        Ok(Some(r)) => {
            state.realms.invalidate().await;
            tracing::info!(realm = %r.name, kind = %r.kind, enabled = r.enabled, "auth realm updated");
            Json(RealmView::from(&r)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "realm not found").into_response(),
        Err(e) if is_unique_violation(&e) => {
            (StatusCode::CONFLICT, "realm name already exists").into_response()
        }
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23514") => {
            bad_request("invalid realm name (lowercase slug)")
        }
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/realms/{id}` — the built-in `local` realm cannot be deleted
/// (disable it instead).
pub async fn delete(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match auth_realm_dao::find_realm_by_id(&state.pool, id).await {
        Ok(Some(r)) if r.kind == KIND_LOCAL => {
            bad_request("the built-in local realm cannot be deleted; disable it instead")
        }
        Ok(Some(_)) => match auth_realm_dao::delete_realm(&state.pool, id).await {
            Ok(true) => {
                state.realms.invalidate().await;
                StatusCode::NO_CONTENT.into_response()
            }
            Ok(false) => (StatusCode::NOT_FOUND, "realm not found").into_response(),
            Err(e) => db_error(e),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "realm not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// `PUT /admin/realms/order` — set the complete try-order. The body must list
/// **every** realm id exactly once (defends against a stale UI dropping rows).
pub async fn reorder(State(state): State<AppState>, Json(body): Json<ReorderRealms>) -> Response {
    let realms = match auth_realm_dao::list_realms(&state.pool).await {
        Ok(r) => r,
        Err(e) => return db_error(e),
    };
    let mut expected: Vec<i64> = realms.iter().map(|r| r.id).collect();
    let mut given = body.order.clone();
    expected.sort_unstable();
    given.sort_unstable();
    if expected != given {
        return bad_request("order must list every realm id exactly once");
    }

    match auth_realm_dao::reorder_realms(&state.pool, &body.order).await {
        Ok(()) => {
            state.realms.invalidate().await;
            match auth_realm_dao::list_realms(&state.pool).await {
                Ok(realms) => {
                    let views: Vec<RealmView> = realms.iter().map(RealmView::from).collect();
                    Json(views).into_response()
                }
                Err(e) => db_error(e),
            }
        }
        Err(e) => db_error(e),
    }
}
