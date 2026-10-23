//! Admin settings: the sign-in policy (#294) and retention (#429).
//! **Admin-only** (mounted behind [`super::require_admin`]).
//!
//! `GET /admin/settings/retention` answers whether retention runs and how
//! long its audit log is kept ([`RetentionSettings`]); `PUT` changes the
//! fields a body names, for every instance at once.
//!
//! `GET /admin/settings/auth` answers the sign-in and anonymous-access policy
//! ([`AuthSettings`]); `PUT` changes it, for every instance: the fields a body
//! names, the others keep their value. A value out of range, a mode that does
//! not exist or an allowlist entry that does not parse is refused with 400 and
//! what is wrong. This instance applies a change at once; the others within
//! `auth.realm_cache_ttl_seconds` ([`crate::auth::AuthSettingsCache`]).
//!
//! Both read the stored row rather than this instance's copy, so a change
//! another instance took a moment ago is never answered stale or undone.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::auth::principal::Principal;
use forge_db::retention_dao::{self, RetentionSettings};

use crate::auth::{load_auth_settings, AuthSettings, AuthSettingsUpdate, SaveError};
use crate::state::AppState;

/// The stored settings, or the 500 answer when they cannot be read.
async fn stored(state: &AppState) -> Result<AuthSettings, Response> {
    load_auth_settings(&state.pool).await.map_err(|e| {
        tracing::error!(error = %format!("{e:#}"), "cannot read the auth settings");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot read the auth settings",
        )
            .into_response()
    })
}

/// `GET /admin/settings/auth`
pub async fn get_auth(State(state): State<AppState>) -> Response {
    match stored(&state).await {
        Ok(settings) => Json(settings).into_response(),
        Err(resp) => resp,
    }
}

/// `PUT /admin/settings/auth` — change the fields the body names.
pub async fn put_auth(
    State(state): State<AppState>,
    axum::Extension(principal): axum::Extension<Principal>,
    Json(update): Json<AuthSettingsUpdate>,
) -> Response {
    let current = match stored(&state).await {
        Ok(settings) => settings,
        Err(resp) => return resp,
    };
    let next = match update.apply_to(&current) {
        Ok(next) => next,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let changed = current.changed_keys(&next);
    match state.auth_settings.save(next).await {
        Ok(saved) => {
            if !changed.is_empty() {
                tracing::info!(
                    target: "forge::audit",
                    changed = %changed.join(", "),
                    settings = ?saved.settings,
                    principal = %principal.audit_label(),
                    "auth settings changed"
                );
            }
            Json(&saved.settings).into_response()
        }
        Err(SaveError::Invalid(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(SaveError::Db(e)) => super::db_error(e),
    }
}

/// `PUT /admin/settings/retention` body: the fields to change (#429). Unknown
/// fields are refused, so a misspelled one is not dropped.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionSettingsUpdate {
    /// Whether retention runs, for every repository.
    #[serde(default)]
    pub runs_enabled: Option<bool>,
    /// How long audit rows are kept (seconds); `0` keeps them all.
    #[serde(default)]
    pub audit_retention_seconds: Option<u64>,
}

/// The stored retention settings, or the 500 answer when they cannot be read.
async fn stored_retention(state: &AppState) -> Result<RetentionSettings, Response> {
    retention_dao::read_settings(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "cannot read the retention settings");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "cannot read the retention settings",
            )
                .into_response()
        })
}

/// `GET /admin/settings/retention` — whether retention runs and how long its
/// audit log is kept, for every instance.
pub async fn get_retention(State(state): State<AppState>) -> Response {
    match stored_retention(&state).await {
        Ok(settings) => Json(settings).into_response(),
        Err(resp) => resp,
    }
}

/// `PUT /admin/settings/retention` — change the fields the body names. Every
/// instance applies a change at once: the worker, its run fence and the audit
/// prune read the stored settings where they apply them.
pub async fn put_retention(
    State(state): State<AppState>,
    axum::Extension(principal): axum::Extension<Principal>,
    Json(update): Json<RetentionSettingsUpdate>,
) -> Response {
    let current = match stored_retention(&state).await {
        Ok(settings) => settings,
        Err(resp) => return resp,
    };
    let mut next = current.clone();
    if let Some(on) = update.runs_enabled {
        next.runs_enabled = on;
    }
    if let Some(secs) = update.audit_retention_seconds {
        if secs > retention_dao::MAX_AUDIT_RETENTION_SECONDS {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "audit_retention_seconds must be at most {} (100 years), or 0 to keep every row",
                    retention_dao::MAX_AUDIT_RETENTION_SECONDS
                ),
            )
                .into_response();
        }
        next.audit_retention_seconds = secs;
    }
    if next != current {
        if let Err(e) = retention_dao::write_settings(&state.pool, &next).await {
            return super::db_error(e);
        }
        tracing::info!(
            target: "forge::audit",
            settings = ?next,
            principal = %principal.audit_label(),
            "retention settings changed"
        );
    }
    Json(next).into_response()
}
