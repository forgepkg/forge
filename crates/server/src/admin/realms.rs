//! Admin auth-realm CRUD (12.7 §3.5). **Admin-only** (mounted behind
//! [`super::require_admin`]).
//!
//! Secrets inside a realm `config` (OIDC `client_secret`, credential-forwarding
//! `key_pepper`) are **write-only**: every response carries a redacted config
//! (`<key>_set` markers instead of values) and an update that omits/blanks a
//! secret keeps the stored one. With `[crypto]` enabled they are encrypted at
//! rest in `auth_realm.secrets_enc` (every write re-encrypts; legacy plaintext
//! rows are still read).
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
use forge_db::secret_dao::{self, SecretDbError};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::db_error;
use crate::auth::{
    forget_seed, merge_secrets, redact_config, secret_keys, validate_config, KIND_LOCAL, KIND_OIDC,
    KIND_WORKLOAD_IDENTITY,
};
use crate::state::AppState;

const WIF_ISSUER_UNIQUE_INDEX: &str = "auth_realm_enabled_wif_issuer_uq";

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
        let mut config = redact_config(&r.kind, &r.config);
        // Encrypted secrets are stripped from `config`; validation requires every
        // secret key, so a sealed secrets document means all of them are set.
        if r.secrets_enc.is_some() {
            if let JsonValue::Object(map) = &mut config {
                for key in secret_keys(&r.kind) {
                    map.insert(format!("{key}_set"), JsonValue::Bool(true));
                }
            }
        }
        RealmView {
            id: r.id,
            kind: r.kind.clone(),
            name: r.name.clone(),
            enabled: r.enabled,
            priority: r.priority,
            config,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Map a realm-secret write error: database errors go through the caller's
/// constraint mapping, envelope failures are a 500.
fn secret_db_error(e: SecretDbError) -> Result<sqlx::Error, Response> {
    match e {
        SecretDbError::Db(e) => Ok(e),
        other => {
            tracing::error!(error = %other, "realm secret encryption failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "realm secret encryption failed",
            )
                .into_response())
        }
    }
}

/// Create-realm request body. Unknown fields are rejected, not dropped.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
/// Unknown fields are rejected, not dropped.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

fn is_wif_issuer_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db)
        if db.code().as_deref() == Some("23505")
            && db.constraint() == Some(WIF_ISSUER_UNIQUE_INDEX))
}

fn normalized_wif_issuer(config: &JsonValue) -> Option<&str> {
    config
        .get("issuer")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .map(|issuer| issuer.trim_end_matches('/'))
        .filter(|issuer| !issuer.is_empty())
}

/// Friendly pre-check for enabled WIF issuer ownership. Migration 0013's
/// partial unique index is the authoritative race-safe enforcement.
async fn assert_unique_enabled_wif_issuer(
    state: &AppState,
    issuer: &str,
    exclude_id: Option<i64>,
) -> Result<(), Response> {
    match auth_realm_dao::list_enabled_realms(&state.pool).await {
        Ok(realms) => {
            let duplicate = realms.iter().any(|realm| {
                realm.kind == KIND_WORKLOAD_IDENTITY
                    && Some(realm.id) != exclude_id
                    && normalized_wif_issuer(&realm.config) == Some(issuer)
            });
            if duplicate {
                Err((
                    StatusCode::CONFLICT,
                    "an enabled workload identity realm already uses this issuer",
                )
                    .into_response())
            } else {
                Ok(())
            }
        }
        Err(error) => Err(db_error(error)),
    }
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
    if body.kind == KIND_WORKLOAD_IDENTITY && body.enabled {
        let Some(issuer) = normalized_wif_issuer(&config) else {
            return bad_request("workload identity config must contain an issuer");
        };
        if let Err(response) = assert_unique_enabled_wif_issuer(&state, issuer, None).await {
            return response;
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
    let inserted = match secret_dao::insert_realm_with_secrets(
        &state.pool,
        state.envelope.as_deref(),
        new,
        secret_keys(&body.kind),
    )
    .await
    {
        Ok(r) => Ok(r),
        Err(e) => match secret_db_error(e) {
            Ok(db) => Err(db),
            Err(resp) => return resp,
        },
    };
    match inserted {
        Ok(r) => {
            state.realms.invalidate().await;
            tracing::info!(realm = %r.name, kind = %r.kind, "auth realm created");
            (StatusCode::CREATED, Json(RealmView::from(&r))).into_response()
        }
        Err(e) if is_wif_issuer_unique_violation(&e) => (
            StatusCode::CONFLICT,
            "an enabled workload identity realm already uses this issuer",
        )
            .into_response(),
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

    // The stored *logical* config (encrypted secrets merged in) — secrets are
    // write-only, so an omitted one must be kept from here.
    let existing_config = match secret_dao::realm_config(state.envelope.as_deref(), &existing).await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(realm = %existing.name, error = %e, "realm secrets unreadable");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "realm secrets unreadable",
            )
                .into_response();
        }
    };

    // Merge write-only secrets from the stored config, then re-validate the
    // full document (an update may not leave a realm in an invalid state).
    let config = match &body.config {
        Some(incoming) => {
            let merged = merge_secrets(&existing.kind, &existing_config, incoming);
            match validate_config(&existing.kind, &merged) {
                Ok(c) => c,
                Err(msg) => return bad_request(msg),
            }
        }
        None if existing.kind == KIND_WORKLOAD_IDENTITY => {
            match validate_config(&existing.kind, &existing_config) {
                Ok(config) => config,
                Err(message) => return bad_request(message),
            }
        }
        // Re-stored below, which also (re-)encrypts legacy plaintext secrets.
        None => existing_config,
    };
    if existing.kind == KIND_WORKLOAD_IDENTITY && enabled {
        let Some(issuer) = normalized_wif_issuer(&config) else {
            return bad_request("workload identity config must contain an issuer");
        };
        if let Err(response) =
            assert_unique_enabled_wif_issuer(&state, issuer, Some(existing.id)).await
        {
            return response;
        }
    }

    if body.config.is_some() {
        // An operator edit of a seeded realm wins over its legacy config block.
        if let Err(e) = forget_seed(&state.pool, &existing).await {
            return db_error(e);
        }
    }

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
    let updated = match secret_dao::update_realm_with_secrets(
        &state.pool,
        state.envelope.as_deref(),
        id,
        upd,
        secret_keys(&existing.kind),
    )
    .await
    {
        Ok(r) => Ok(r),
        Err(e) => match secret_db_error(e) {
            Ok(db) => Err(db),
            Err(resp) => return resp,
        },
    };
    match updated {
        Ok(Some(r)) => {
            state.realms.invalidate().await;
            tracing::info!(realm = %r.name, kind = %r.kind, enabled = r.enabled, "auth realm updated");
            Json(RealmView::from(&r)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "realm not found").into_response(),
        Err(e) if is_wif_issuer_unique_violation(&e) => (
            StatusCode::CONFLICT,
            "an enabled workload identity realm already uses this issuer",
        )
            .into_response(),
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
        Ok(Some(r)) => match auth_realm_dao::delete_realm(&state.pool, id).await {
            Ok(true) => {
                // The kind's next boot re-imports a still-present legacy block
                // as a fresh row; a stale marker must not outlive this one.
                if let Err(e) = forget_seed(&state.pool, &r).await {
                    tracing::warn!(realm = %r.name, error = %e, "seed marker not dropped");
                }
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
