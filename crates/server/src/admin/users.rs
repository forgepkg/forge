//! Admin user CRUD (plan 10.4). Passwords are hashed with argon2id; the hash is
//! never returned.
//!
//! Cutting a user off (review M5) works the same for every account kind,
//! federated ones included: `PATCH /admin/users/{id}` with `{"active": false}`
//! deactivates the account, revokes its sessions and purges its cached
//! upstream verdicts. Deleting is *not* a block for federated users — an
//! auto-provisioning realm re-creates a deleted account on its next valid
//! upstream login — so deactivate instead.
//!
//! Neither may remove the last active administrator: deactivating or deleting
//! that user answers **409** ([`super::last_admin_conflict`]).
//!
//! A credential-forwarding account whose realm keeps password hashes
//! (`capture_password_hash`) can be switched to a local account with the last
//! password its upstream accepted: `POST /admin/users/{id}/convert-to-local`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use forge_db::authz_dao;
use forge_db::model::AppUser;
use forge_db::user_dao::{self, ConvertedUser, NewUser};
use serde::{Deserialize, Serialize};

use super::{db_error, hash_password, last_admin_conflict};
use crate::state::AppState;

/// Password-free view of a user.
#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub is_admin: bool,
    pub active: bool,
    /// How the account signs in: `local` (a Forge password), `oidc` (an
    /// identity provider) or `upstream-basic` (a credential-forwarding
    /// realm). Two accounts can look alike by name (`bob`, `bob@entra`); this
    /// tells them apart before a grant goes to the wrong one.
    pub auth_source: String,
    /// When the account's realm last kept a hash of the password its upstream
    /// accepted (`capture_password_hash`); `null` when it keeps none. Such an
    /// account can be switched to a local one
    /// (`POST /admin/users/{id}/convert-to-local`).
    pub captured_password_at: Option<DateTime<Utc>>,
    /// The names of the RBAC roles the user holds, sorted. What the user may
    /// do follows from these (and `is_admin`), not from `is_admin` alone.
    pub roles: Vec<String>,
}

impl From<&AppUser> for UserView {
    fn from(u: &AppUser) -> Self {
        UserView {
            id: u.id,
            username: u.username.clone(),
            is_admin: u.is_admin,
            active: u.active,
            auth_source: u.auth_source.clone(),
            captured_password_at: None,
            roles: Vec::new(),
        }
    }
}

impl UserView {
    /// The view of `u`, with its kept-password time and roles read from the
    /// database.
    async fn load(state: &AppState, u: &AppUser) -> Result<Self, Response> {
        let captured_password_at = user_dao::captured_password_at(&state.pool, u.id)
            .await
            .map_err(db_error)?;
        let roles = authz_dao::list_roles_for_user(&state.pool, u.id)
            .await
            .map_err(db_error)?
            .into_iter()
            .map(|r| r.name)
            .collect();
        Ok(UserView {
            captured_password_at,
            roles,
            ..UserView::from(u)
        })
    }
}

/// Create-user request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Update-user request (`PATCH /admin/users/{id}`). Only the account state is
/// settable; unknown fields (e.g. an attempted `is_admin`) are rejected rather
/// than silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUser {
    /// `false` deactivates (and cuts off) the user, `true` reactivates it.
    #[serde(default)]
    pub active: Option<bool>,
}

/// `GET /admin/users`
pub async fn list(State(state): State<AppState>) -> Response {
    let users = match user_dao::list_users(&state.pool).await {
        Ok(users) => users,
        Err(e) => return db_error(e),
    };
    let captured: std::collections::HashMap<i64, DateTime<Utc>> =
        match user_dao::captured_password_times(&state.pool).await {
            Ok(times) => times.into_iter().collect(),
            Err(e) => return db_error(e),
        };
    let mut roles: std::collections::HashMap<i64, Vec<String>> = std::collections::HashMap::new();
    match authz_dao::list_user_role_names(&state.pool).await {
        Ok(assignments) => {
            for (user_id, role) in assignments {
                roles.entry(user_id).or_default().push(role);
            }
        }
        Err(e) => return db_error(e),
    }
    let views: Vec<UserView> = users
        .iter()
        .map(|u| UserView {
            captured_password_at: captured.get(&u.id).copied(),
            roles: roles.remove(&u.id).unwrap_or_default(),
            ..UserView::from(u)
        })
        .collect();
    Json(views).into_response()
}

/// `POST /admin/users`
pub async fn create(State(state): State<AppState>, Json(body): Json<CreateUser>) -> Response {
    // Stored canonical (trimmed, NFC, lowercased), like every login looks it up,
    // without a `:`, which no password login accepts, and never a reserved
    // protocol name such as the workload-identity username `oidc`.
    let username = match forge_core::auth::canonical_account_username(&body.username, true) {
        Ok(u) => u,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid username: {e}")).into_response()
        }
    };
    if body.password.is_empty() {
        return (StatusCode::BAD_REQUEST, "password is required").into_response();
    }

    let password_hash = match hash_password(body.password.clone()).await {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    let new = NewUser::local(username, password_hash, body.is_admin, body.active);
    let u = match user_dao::insert_user(&state.pool, new).await {
        Ok(u) => u,
        Err(e) if is_unique_violation(&e) => {
            return (StatusCode::CONFLICT, "username already exists").into_response();
        }
        Err(e) => return db_error(e),
    };

    // An admin created here holds the built-in `admin` role as well as the
    // legacy flag, so the role-assignment API sees (and can revoke) it.
    if u.is_admin {
        if let Err(e) = authz_dao::sync_admin_role(&state.pool, u.id, true).await {
            return db_error(e);
        }
    }

    match UserView::load(&state, &u).await {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(resp) => resp,
    }
}

/// `PATCH /admin/users/{id}` — deactivate (`{"active": false}`) or reactivate
/// (`{"active": true}`) a user. Returns the updated [`UserView`]; idempotent.
///
/// Deactivation is the cut-off for every account kind, federated
/// (credential-forwarding / OIDC) users included:
/// 1. `active = false` — every authentication path (API tokens, password
///    Basic, the browser session, OIDC and credential-forwarding logins)
///    refuses an inactive user, and no auto-provisioning path reactivates it;
/// 2. all of the user's sessions are revoked;
/// 3. the user's validated-credential verdicts are purged (all providers,
///    cluster-wide cache invalidation), so a later reactivation re-validates
///    against the upstream instead of trusting a pre-deactivation verdict.
///
/// For a credential-forwarding user, deactivation holds for the canonical
/// username: an upstream that accepts another spelling of the same account
/// (`DOMAIN\user`, `user@domain`) signs that spelling in as a new account
/// unless the realm sets `identity_path` or turns `auto_provision` off.
///
/// API tokens are refused while the user is inactive but not revoked, so a
/// reactivated user's tokens work again; revoke them individually
/// (`DELETE /admin/tokens/{id}`) to kill them for good. Reactivation changes
/// only the flag.
///
/// Deactivating the last active administrator is refused (**409**).
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateUser>,
) -> Response {
    let Some(active) = body.active else {
        return (
            StatusCode::BAD_REQUEST,
            "nothing to update (expected {\"active\": true|false})",
        )
            .into_response();
    };
    let user = match set_active_guarded(&state, id, active).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(resp) => return resp,
    };
    if !active {
        if let Err(resp) = revoke_sessions_and_verdicts(&state, &user).await {
            return resp;
        }
        tracing::info!(user_id = user.id, username = %user.username, "user deactivated");
    }
    forge_core::authz::cache::invalidate_user(&state.cache, user.id).await;
    match UserView::load(&state, &user).await {
        Ok(view) => Json(view).into_response(),
        Err(resp) => resp,
    }
}

/// `DELETE /admin/users/{id}` — delete the user (sessions, tokens, role
/// assignments and identity links cascade) and purge the username's cached
/// validated-credential verdicts, so no pre-deletion upstream verdict
/// outlives the account. Deleting the last active administrator is refused
/// (**409**).
pub async fn delete(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let user = match user_dao::find_user_by_id(&state.pool, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    };
    match delete_guarded(&state, id).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(resp) => return resp,
    }
    // After the delete, so a verdict cached by a login racing the delete is
    // purged too (a forward still in flight is fenced by the revocation).
    if let Err(e) =
        forge_core::auth::revoke_credentials_for_user(&state.cache, &state.pool, &user.username)
            .await
    {
        tracing::error!(error = %e, user_id = id, "deleted user's credential verdicts could not be purged");
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /admin/users/{id}/reauth` — force re-validation of a user's forwarded
/// credentials (slice 12.3, plan §2.5/§2.7).
///
/// Purges every cached `validated_credential` verdict for the user (across all
/// providers) and broadcasts a cache-layer invalidation, so the **next**
/// password-Basic request for that user re-forwards to the upstream instead of
/// serving a possibly-stale cached positive, and revokes all of the user's
/// browser sessions, so a signed-in browser must log in (and thus
/// re-validate) again. Use after disabling the user upstream, after a password
/// change, or to shrink the trust window. API tokens the user minted from a
/// session that credential forwarding established are revoked as well (they
/// rest on the same upstream verdict); tokens an administrator minted for the
/// user are untouched. `204` on success (idempotent — a user with no cached
/// verdicts, sessions or such tokens still returns `204`).
pub async fn reauth(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let user = match user_dao::find_user_by_id(&state.pool, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    };

    if let Err(resp) = revoke_sessions_and_verdicts(&state, &user).await {
        return resp;
    }
    match forge_db::token_dao::revoke_forwarded_tokens_for_user(&state.pool, user.id).await {
        Ok(revoked) => {
            if revoked > 0 {
                tracing::info!(
                    user_id = user.id,
                    revoked,
                    "reauth revoked tokens minted via credential forwarding"
                );
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `POST /admin/users/{id}/convert-to-local` — switch a credential-forwarding
/// account to a local one whose password is the hash its realm kept
/// (`capture_password_hash`): the last password the upstream accepted for it.
///
/// The account keeps its id, roles, tokens and admin and active flags, and
/// leaves its realm: from then on the local-password realm owns the name, so
/// the password is never forwarded upstream again, and a password changed
/// upstream since the hash was kept no longer works here. The account signs
/// in only while the local realm is enabled and comes before any
/// credential-forwarding realm whose upstream still accepts the name. An
/// orphan of a deleted realm converts the same way. Its cached upstream
/// verdicts are purged.
///
/// Returns the updated [`UserView`]; **409** when the account is not a
/// credential-forwarding one or keeps no password.
pub async fn convert_to_local(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let converted = match user_dao::convert_to_local(&state.pool, id).await {
        Ok(Some(converted)) => converted,
        Ok(None) => {
            return match user_dao::find_user_by_id(&state.pool, id).await {
                Ok(Some(_)) => (
                    StatusCode::CONFLICT,
                    "only a credential-forwarding account with a kept password can be \
                     switched to a local one",
                )
                    .into_response(),
                Ok(None) => (StatusCode::NOT_FOUND, "user not found").into_response(),
                Err(e) => db_error(e),
            }
        }
        Err(e) => return db_error(e),
    };
    if let Err(resp) = purge_converted(&state, std::slice::from_ref(&converted)).await {
        return resp;
    }
    match user_dao::find_user_by_id(&state.pool, id).await {
        Ok(Some(user)) => match UserView::load(&state, &user).await {
            Ok(view) => Json(view).into_response(),
            Err(resp) => resp,
        },
        Ok(None) => (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// After accounts were switched to local ones: purge their cached upstream
/// verdicts (all providers, broadcast to peer caches), which no longer speak
/// for them.
pub(crate) async fn purge_converted(
    state: &AppState,
    converted: &[ConvertedUser],
) -> Result<(), Response> {
    for user in converted {
        tracing::info!(user_id = user.id, username = %user.username, "account switched to a local password");
        if let Err(e) =
            forge_core::auth::revoke_credentials_for_user(&state.cache, &state.pool, &user.username)
                .await
        {
            tracing::error!(error = %e, user_id = user.id, "credential verdict revoke failed");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response());
        }
    }
    Ok(())
}

/// Set `active` in a transaction under the last-admin guard (only a
/// deactivation can remove an admin). `Ok(None)` when no such user exists.
async fn set_active_guarded(
    state: &AppState,
    id: i64,
    active: bool,
) -> Result<Option<AppUser>, Response> {
    let mut tx = state.pool.begin().await.map_err(db_error)?;
    if !active
        && authz_dao::would_leave_no_admin(&mut tx, id)
            .await
            .map_err(db_error)?
    {
        return Err(last_admin_conflict());
    }
    let user = user_dao::set_active(&mut *tx, id, active)
        .await
        .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(user)
}

/// Delete the user in a transaction under the last-admin guard. `Ok(false)`
/// when no such user exists.
async fn delete_guarded(state: &AppState, id: i64) -> Result<bool, Response> {
    let mut tx = state.pool.begin().await.map_err(db_error)?;
    if authz_dao::would_leave_no_admin(&mut tx, id)
        .await
        .map_err(db_error)?
    {
        return Err(last_admin_conflict());
    }
    let deleted = user_dao::delete_user(&mut *tx, id)
        .await
        .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(deleted)
}

/// Revoke what lets an already-authenticated `user` keep going without
/// proving themselves again: every browser session, then every cached
/// validated-credential verdict (all providers, broadcast to peer caches).
async fn revoke_sessions_and_verdicts(state: &AppState, user: &AppUser) -> Result<(), Response> {
    if let Err(e) = state.sessions.revoke_all_for_user(user.id).await {
        tracing::error!(error = %e, user_id = user.id, "session revoke failed");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response());
    }
    if let Err(e) =
        forge_core::auth::revoke_credentials_for_user(&state.cache, &state.pool, &user.username)
            .await
    {
        tracing::error!(error = %e, user_id = user.id, "credential verdict revoke failed");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response());
    }
    Ok(())
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}
