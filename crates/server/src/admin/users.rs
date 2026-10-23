//! Admin user CRUD. Passwords are hashed with argon2id; the hash is never
//! returned.
//!
//! Cutting a user off (review M5) works the same for every account kind,
//! federated ones included: `PATCH /admin/users/{id}` with `{"active": false}`
//! deactivates the account, revokes its sessions and purges its cached
//! upstream verdicts. Deleting is *not* a block for OIDC users — an
//! auto-provisioning OIDC realm re-creates a deleted account on its next
//! login — so deactivate instead.
//!
//! Neither may remove the last active administrator: deactivating or deleting
//! that user answers **409** ([`super::last_admin_conflict`]).
//!
//! Every account is named by a UPN. `POST /admin/users` creates a local
//! account without a password and invites its user to choose one (#322,
//! [`crate::invitations`]): by email when an email service is configured,
//! otherwise with a link the response carries once. With `realm` it creates
//! an account of that credential-forwarding realm instead: such a realm
//! creates no accounts on its own, and signs in only those created here
//! (forwarding the local part of the name to its upstream). `role` makes the
//! account a reader (the default), a writer or an administrator.
//!
//! An invited account signs in by no path until its user has chosen the
//! password. `POST /admin/users/{id}/invitation` makes a new invitation
//! (sent, or as a link to copy), replacing the previous one, and `DELETE`
//! revokes it; deactivating or deleting the account revokes it too.
//!
//! A credential-forwarding account whose realm keeps password hashes
//! (`capture_password_hash`) can be switched to a local account with the last
//! password its upstream accepted: `POST /admin/users/{id}/convert-to-local`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::Extension;
use chrono::{DateTime, Utc};
use forge_core::auth::principal::Principal;
use forge_db::authz_dao;
use forge_db::invitation_dao::{self, Invitation, Onboarding};
use forge_db::model::AppUser;
use forge_db::user_dao::{self, ConvertedUser};
use serde::{Deserialize, Serialize};

use super::{db_error, last_admin_conflict};
use crate::invitations::{self, Delivery};
use crate::state::AppState;

/// Password-free view of a user.
#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    /// Membership in the built-in `admin` role.
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
    /// do follows from these; `is_admin` only says whether `admin` is one.
    pub roles: Vec<String>,
    /// Where invitations go.
    pub email: Option<String>,
    /// `active`, `inactive`, `invited` (a live invitation waits) or
    /// `invitation_expired` (invited, without a live invitation: make a new
    /// one).
    pub status: &'static str,
    /// The account's invitation while it is invited; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitation: Option<InvitationView>,
}

/// An invitation, without its token.
#[derive(Debug, Clone, Serialize)]
pub struct InvitationView {
    pub email: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// When the email service took it; `null` for a link handed over.
    pub sent_at: Option<DateTime<Utc>>,
}

impl UserView {
    /// The view of `u`, which holds `roles` (sorted role names): it is an
    /// administrator when `admin` is among them.
    fn new(
        u: &AppUser,
        roles: Vec<String>,
        onboarding: Option<&Onboarding>,
        invitation: Option<&Invitation>,
    ) -> Self {
        let invited = onboarding.is_some_and(|o| o.invited);
        let live = invitation.is_some_and(|i| i.is_live(Utc::now()));
        let status = match (u.active, invited, live) {
            (false, _, _) => "inactive",
            (true, true, true) => "invited",
            (true, true, false) => "invitation_expired",
            (true, false, _) => "active",
        };
        UserView {
            id: u.id,
            username: u.username.clone(),
            is_admin: roles.iter().any(|r| r == authz_dao::ADMIN_ROLE),
            active: u.active,
            auth_source: u.auth_source.clone(),
            captured_password_at: None,
            roles,
            email: onboarding.and_then(|o| o.email.clone()),
            status,
            invitation: invitation
                .filter(|i| invited && i.accepted_at.is_none())
                .map(|i| InvitationView {
                    email: i.email.clone(),
                    expires_at: i.expires_at,
                    created_at: i.created_at,
                    sent_at: i.sent_at,
                }),
        }
    }

    /// The view of `u`, with its roles, kept-password time and invitation
    /// read from the database.
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
        let onboarding = invitation_dao::onboarding(&state.pool, u.id)
            .await
            .map_err(db_error)?;
        let invitation = invitation_dao::get(&state.pool, u.id)
            .await
            .map_err(db_error)?;
        Ok(UserView {
            captured_password_at,
            ..Self::new(u, roles, onboarding.as_ref(), invitation.as_ref())
        })
    }
}

/// What a new account may do: its built-in role.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessRole {
    /// Reads what every signed-in user reads: no built-in role.
    #[default]
    Reader,
    /// The built-in `writer` role: publishes to every repository.
    Writer,
    /// The built-in `admin` role.
    Admin,
}

impl AccessRole {
    fn role_name(self) -> Option<&'static str> {
        match self {
            AccessRole::Reader => None,
            AccessRole::Writer => Some(authz_dao::WRITER_ROLE),
            AccessRole::Admin => Some(authz_dao::ADMIN_ROLE),
        }
    }
}

/// Create-user request: a local account whose user is invited to choose
/// the password, or an account of the credential-forwarding realm named
/// `realm` (it signs in with the upstream's password). No password is ever
/// taken here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUser {
    pub username: String,
    /// Where the invitation goes; the username when absent.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub role: AccessRole,
    /// The name of a `credential_forwarding` realm.
    #[serde(default)]
    pub realm: Option<String>,
}

/// The create-user answer: the user and, for a local account, the
/// invitation just made (in place of the view's `invitation`).
#[derive(Debug, Serialize)]
pub struct CreatedUser {
    #[serde(flatten)]
    pub user: UserView,
    pub invitation: Option<invitations::Issued>,
}

impl CreatedUser {
    fn new(mut user: UserView, invitation: Option<invitations::Issued>) -> Self {
        user.invitation = None;
        CreatedUser { user, invitation }
    }
}

/// `POST /admin/users/{id}/invitation` body.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewInvitation {
    /// `false` makes a link to copy instead of sending it.
    #[serde(default = "default_true")]
    pub send_email: bool,
    /// Another address; it becomes the account's.
    #[serde(default)]
    pub email: Option<String>,
}

fn default_true() -> bool {
    true
}

/// `email` checked and normalized: an address, at most 320 bytes.
fn parse_email(email: &str) -> Result<String, Response> {
    let email = email.trim();
    let valid = email.len() <= 320
        && !email.chars().any(char::is_control)
        && email.parse::<lettre::Address>().is_ok();
    if valid {
        Ok(email.to_string())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            format!("{email:?} is not an email address"),
        )
            .into_response())
    }
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
    let onboarding: std::collections::HashMap<i64, Onboarding> =
        match invitation_dao::list_onboarding(&state.pool).await {
            Ok(rows) => rows.into_iter().map(|o| (o.user_id, o)).collect(),
            Err(e) => return db_error(e),
        };
    let invitations: std::collections::HashMap<i64, Invitation> =
        match invitation_dao::list(&state.pool).await {
            Ok(rows) => rows.into_iter().map(|i| (i.user_id, i)).collect(),
            Err(e) => return db_error(e),
        };
    let views: Vec<UserView> = users
        .iter()
        .map(|u| UserView {
            captured_password_at: captured.get(&u.id).copied(),
            ..UserView::new(
                u,
                roles.remove(&u.id).unwrap_or_default(),
                onboarding.get(&u.id),
                invitations.get(&u.id),
            )
        })
        .collect();
    Json(views).into_response()
}

/// `POST /admin/users`: create an invited local account and invite its user
/// (module docs), or an account of a credential-forwarding realm. **201**
/// with the user and, for a local account, its invitation: whether the
/// email went out, and the link when it did not.
pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Json(body): Json<CreateUser>,
) -> Response {
    // Stored canonical (trimmed, NFC, lowercased), like every login looks it up,
    // without a `:`, which no password login accepts, and never a reserved
    // protocol name such as the workload-identity username `oidc`.
    let username = match forge_core::auth::canonical_account_username(&body.username, true) {
        Ok(u) => u,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid username: {e}")).into_response()
        }
    };
    let email = match body
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        Some(email) => match parse_email(email) {
            Ok(email) => Some(email),
            Err(resp) => return resp,
        },
        None => None,
    };
    let account = match body.realm.as_deref() {
        Some(realm) => {
            match forge_db::auth_realm_dao::find_realm_by_name(&state.pool, realm.trim()).await {
                Ok(Some(r)) if r.kind == crate::auth::KIND_CRED_FORWARD => {
                    NewAccount::Forwarded { realm_id: r.id }
                }
                Ok(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("no credential-forwarding realm is named {realm:?}"),
                    )
                        .into_response()
                }
                Err(e) => return db_error(e),
            }
        }
        None => {
            // The invitation goes to the username unless told otherwise; a
            // UPN is not always a mailbox.
            let to = match &email {
                Some(email) => email.clone(),
                None => match parse_email(&username) {
                    Ok(email) => email,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            "the username is no email address: give the address to invite",
                        )
                            .into_response()
                    }
                },
            };
            NewAccount::Invited { email: to }
        }
    };

    let u = match insert_with_role(&state, &username, &account, email.as_deref(), body.role).await {
        Ok(u) => u,
        Err(e) if is_unique_violation(&e) => {
            return (StatusCode::CONFLICT, "username already exists").into_response();
        }
        Err(e) => return db_error(e),
    };
    let invitation = match &account {
        NewAccount::Invited { email } => {
            match invitations::issue(
                &state,
                &u,
                email,
                principal_user_id(&principal),
                Delivery::Email,
            )
            .await
            {
                Ok(issued) => issued,
                Err(e) => return db_error(e),
            }
        }
        NewAccount::Forwarded { .. } => None,
    };
    match UserView::load(&state, &u).await {
        Ok(user) => (
            StatusCode::CREATED,
            Json(CreatedUser::new(user, invitation)),
        )
            .into_response(),
        Err(resp) => resp,
    }
}

/// The administrator acting, when a user (not a workload) is.
fn principal_user_id(principal: &Principal) -> Option<i64> {
    match principal {
        Principal::User { user_id, .. } => Some(*user_id),
        _ => None,
    }
}

/// The kind of account [`create`] makes.
enum NewAccount {
    /// An invited local account, whose invitation goes to `email`.
    Invited { email: String },
    /// An account of this credential-forwarding realm.
    Forwarded { realm_id: i64 },
}

/// Insert the user (with `email` as its address) and assign it `role`'s
/// built-in role in the same transaction.
async fn insert_with_role(
    state: &AppState,
    username: &str,
    account: &NewAccount,
    email: Option<&str>,
    role: AccessRole,
) -> sqlx::Result<AppUser> {
    let mut tx = state.pool.begin().await?;
    let user = match account {
        NewAccount::Invited { email } => {
            invitation_dao::insert_invited_user(&mut *tx, username, email).await?
        }
        NewAccount::Forwarded { realm_id } => {
            let user = user_dao::insert_forwarded_user(&mut *tx, username, *realm_id, true).await?;
            if email.is_some() {
                invitation_dao::set_email(&mut *tx, user.id, email).await?;
            }
            user
        }
    };
    if let Some(name) = role.role_name() {
        let role_id = authz_dao::role_id_by_name(&mut *tx, name)
            .await?
            .ok_or_else(|| sqlx::Error::Protocol(format!("the built-in {name} role is missing")))?;
        authz_dao::assign_role(&mut *tx, user.id, role_id).await?;
    }
    tx.commit().await?;
    Ok(user)
}

/// `POST /admin/users/{id}/invitation`: a new invitation for an invited
/// account, replacing its previous one (whose link stops working). Sent by
/// email (`send_email`, the default), or made as a link to copy, shown once.
/// **409** when the account is not an active invited one.
pub async fn invite(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<i64>,
    body: Option<Json<NewInvitation>>,
) -> Response {
    let body = body.map(|Json(b)| b).unwrap_or(NewInvitation {
        send_email: true,
        email: None,
    });
    let user = match user_dao::find_user_by_id(&state.pool, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    };
    let onboarding = match invitation_dao::onboarding(&state.pool, id).await {
        Ok(Some(o)) => o,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    };
    if !onboarding.invited || !user.active {
        return (
            StatusCode::CONFLICT,
            "only an active account whose user has not chosen a password yet can be invited",
        )
            .into_response();
    }
    let to = match body
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        Some(email) => match parse_email(email) {
            Ok(email) => {
                if let Err(e) = invitation_dao::set_email(&state.pool, id, Some(&email)).await {
                    return db_error(e);
                }
                email
            }
            Err(resp) => return resp,
        },
        None => match onboarding.email.clone().map(|e| parse_email(&e)) {
            Some(Ok(email)) => email,
            _ => match parse_email(&user.username) {
                Ok(email) => email,
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "the account has no email address: give the address to invite",
                    )
                        .into_response()
                }
            },
        },
    };
    let delivery = if body.send_email {
        Delivery::Email
    } else {
        Delivery::Link
    };
    match invitations::issue(&state, &user, &to, principal_user_id(&principal), delivery).await {
        Ok(Some(issued)) => Json(issued).into_response(),
        Ok(None) => (
            StatusCode::CONFLICT,
            "only an active account whose user has not chosen a password yet can be invited",
        )
            .into_response(),
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/users/{id}/invitation`: revoke the account's invitation
/// (its link stops working). **404** when there is none.
pub async fn revoke_invitation(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match invitation_dao::revoke(&state.pool, id).await {
        Ok(true) => {
            tracing::info!(user_id = id, "invitation revoked");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no invitation to revoke").into_response(),
        Err(e) => db_error(e),
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
///    the account's invitation is revoked;
/// 2. all of the user's sessions are revoked;
/// 3. the user's validated-credential verdicts are purged (all providers,
///    cluster-wide cache invalidation), so a later reactivation re-validates
///    against the upstream instead of trusting a pre-deactivation verdict.
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
        // Its invitation's link stops working: a reactivated account is
        // invited anew.
        if let Err(e) = invitation_dao::revoke(&state.pool, user.id).await {
            return db_error(e);
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
/// credentials.
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
