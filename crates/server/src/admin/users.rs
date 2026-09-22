//! Admin user CRUD (plan 10.4). Passwords are hashed with argon2id; the hash is
//! never returned.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_db::authz_dao;
use forge_db::model::AppUser;
use forge_db::user_dao::{self, NewUser};
use serde::{Deserialize, Serialize};

use super::{db_error, hash_password};
use crate::state::AppState;

/// Password-free view of a user.
#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub active: bool,
}

impl From<&AppUser> for UserView {
    fn from(u: &AppUser) -> Self {
        UserView {
            id: u.id,
            username: u.username.clone(),
            is_admin: u.is_admin,
            active: u.active,
        }
    }
}

/// Create-user request.
#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default = "default_true")]
    pub active: bool,
}

fn default_true() -> bool {
    true
}

/// `GET /admin/users`
pub async fn list(State(state): State<AppState>) -> Response {
    match user_dao::list_users(&state.pool).await {
        Ok(users) => {
            let views: Vec<UserView> = users.iter().map(UserView::from).collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `POST /admin/users`
pub async fn create(State(state): State<AppState>, Json(body): Json<CreateUser>) -> Response {
    if body.username.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "username is required").into_response();
    }
    if body.password.is_empty() {
        return (StatusCode::BAD_REQUEST, "password is required").into_response();
    }

    let password_hash = match hash_password(body.password.clone()).await {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    let new = NewUser::local(
        body.username.clone(),
        password_hash,
        body.is_admin,
        body.active,
    );
    let u = match user_dao::insert_user(&state.pool, new).await {
        Ok(u) => u,
        Err(e) if is_unique_violation(&e) => {
            return (StatusCode::CONFLICT, "username already exists").into_response();
        }
        Err(e) => return db_error(e),
    };

    // §12.4 Phase 5: on a legacy-open-access (upgraded slice-1) install, a brand
    // new authenticated user must inherit the `authenticated` role *now* —
    // `ensure_legacy_rbac` runs only once per install, so otherwise a freshly
    // created user would silently lose the slice-1 "read/write everywhere"
    // behavior. Fail-closed installs leave the flag false and skip
    // this. Idempotent.
    match authz_dao::assign_authenticated_if_legacy_open(&state.pool, u.id).await {
        Ok(true) => {
            // No cached effective set should exist for a just-created id, but
            // invalidate defensively in case the id was reused within a TTL window.
            forge_core::authz::cache::invalidate_user(&state.cache, u.id).await;
        }
        Ok(false) => {}
        Err(e) => return db_error(e),
    }

    (StatusCode::CREATED, Json(UserView::from(&u))).into_response()
}

/// `DELETE /admin/users/{id}`
pub async fn delete(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match user_dao::delete_user(&state.pool, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// `POST /admin/users/{id}/reauth` — force re-validation of a user's forwarded
/// credentials (slice 12.3, plan §2.5/§2.7).
///
/// Purges every cached `validated_credential` verdict for the user (across all
/// providers) and broadcasts a cache-layer invalidation, so the **next**
/// password-Basic request for that user re-forwards to the upstream instead of
/// serving a possibly-stale cached positive. Use after disabling the user
/// upstream, after a password change, or to shrink the trust window. `204` on
/// success (idempotent — a user with no cached verdicts still returns `204`).
pub async fn reauth(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let user = match user_dao::find_user_by_id(&state.pool, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    };

    match forge_core::auth::revoke_credentials_for_user(&state.cache, &state.pool, &user.username)
        .await
    {
        Ok(_deleted) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!(error = %e, user_id = id, "reauth credential revoke failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}
