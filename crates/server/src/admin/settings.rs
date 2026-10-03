//! Install-wide admin settings (`forge_setting` rows).
//!
//! * `GET /admin/settings/legacy-open-access` → `{"enabled": bool}`.
//! * `PUT /admin/settings/legacy-open-access` with `{"enabled": bool}` → the
//!   new value.
//!
//! `legacy_open_access` is recorded by migration 0007: `true` on a database
//! that already had users when RBAC arrived (an upgrade of a pre-release
//! install), `false` on a fresh install. While it is `true`, every newly
//! created user — admin API, OIDC and credential-forwarding auto-provisioning —
//! is assigned the built-in `authenticated` role (read + write on every
//! repository), reproducing the pre-RBAC "any signed-in user may do anything"
//! rule. Switching it off is how an upgraded install moves to deny-by-default
//! for new accounts. It is a live switch (the flag is read at each user
//! creation), so no restart is needed.
//!
//! Switching it off does **not** revoke the role from existing users: review
//! them with `GET /admin/users/{id}/roles` and remove it with
//! `DELETE /admin/users/{id}/roles/{role_id}` (or remove the `authenticated`
//! role's grants) to close access for them too.

use axum::extract::State;
use axum::response::{IntoResponse, Json, Response};
use forge_db::authz_dao;
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::state::AppState;

/// The `legacy_open_access` switch, as read and written by the admin API.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyOpenAccess {
    /// `true` ⇒ new users are auto-assigned the `authenticated` role.
    pub enabled: bool,
}

/// `GET /admin/settings/legacy-open-access`
pub async fn get_legacy_open_access(State(state): State<AppState>) -> Response {
    match authz_dao::legacy_open_access(&state.pool).await {
        Ok(enabled) => Json(LegacyOpenAccess { enabled }).into_response(),
        Err(e) => db_error(e),
    }
}

/// `PUT /admin/settings/legacy-open-access`
///
/// No authz cache invalidation is needed: the flag affects only *future* role
/// assignments, and each of those invalidates the user it touches.
pub async fn put_legacy_open_access(
    State(state): State<AppState>,
    Json(body): Json<LegacyOpenAccess>,
) -> Response {
    if let Err(e) = authz_dao::set_legacy_open_access(&state.pool, body.enabled).await {
        return db_error(e);
    }
    tracing::info!(
        enabled = body.enabled,
        "legacy_open_access changed by an administrator"
    );
    Json(LegacyOpenAccess {
        enabled: body.enabled,
    })
    .into_response()
}
