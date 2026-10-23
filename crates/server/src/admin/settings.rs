//! Admin auth settings (#294). **Admin-only** (mounted behind
//! [`super::require_admin`]).
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
