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
//! (forwarding the local part of the name to its upstream). Or of that
//! trusted-header realm: the headers of the proxy in front then name it (a
//! realm without `auto_provision` names only the accounts created here).
//! `role` makes the account a reader (the default), a writer or an
//! administrator; an account of a trusted-header realm is never an
//! administrator (**400**, #547): its headers never make it one.
//!
//! An invited account signs in by no path until its user has chosen the
//! password. `POST /admin/users/{id}/invitation` makes a new invitation
//! (sent, or as a link to copy), replacing the previous one, and `DELETE`
//! revokes it; deactivating or deleting the account revokes it too.
//! `POST /admin/users/{id}/invitation/accept` accepts it on the user's
//! behalf with a password the administrator sets (#653), for an account
//! handed over ready to use: the only way an administrator sets another
//! person's password.
//!
//! A credential-forwarding account whose realm keeps password hashes
//! (`capture_password_hash`) can be switched to a local account with the last
//! password its upstream accepted: `POST /admin/users/{id}/convert-to-local`.
//!
//! ## Service accounts (#508)
//! `"kind": "service"` creates a service account instead: an account for a
//! machine or a network (a CI pipeline, a build agent, a network the load
//! balancer admits) that nobody signs in to. It has a description (what it
//! is for, who owns it) and no password, invitation or email, and never holds
//! the built-in `admin` role. It authenticates with the API tokens an
//! administrator issues for it (`POST /admin/users/{id}/tokens`), or through
//! the trusted-header realm named `realm`, which alone may name it. Roles,
//! grants, tokens and deactivation work as for a user;
//! `PATCH /admin/users/{id}` also sets its `description` and `realm`.
//! Invitations, `reauth` and `convert-to-local` refuse it (**409**), and
//! `GET /admin/users?kind=service` lists the service accounts alone.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::Extension;
use chrono::{DateTime, Utc};
use forge_core::auth::principal::Principal;
use forge_db::authz_dao;
use forge_db::invitation_dao::{self, Invitation, Onboarding};
use forge_db::model::AppUser;
use forge_db::user_dao::{self, AccountDetails, ConvertedUser};
use serde::{Deserialize, Serialize};

use super::{db_error, double_option, last_admin_conflict};
use crate::invitations::{self, Delivery};
use crate::state::AppState;

/// Password-free view of a user.
#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    /// `user` (a person) or `service` (a service account: a machine or a
    /// network nobody signs in to).
    pub kind: AccountKind,
    /// What a service account is for and who owns it; `null` for a user.
    pub description: Option<String>,
    /// Membership in the built-in `admin` role.
    pub is_admin: bool,
    pub active: bool,
    /// How the account signs in: `local` (a Forge password), `oidc` (an
    /// identity provider), `upstream-basic` (a credential-forwarding realm),
    /// `trusted-header` (the headers of a trusted-header realm's proxy) or
    /// `service` (a service account: its API tokens, or the headers of its
    /// trusted-header realm). Two accounts can look alike by name (`bob`,
    /// `bob@entra`); this tells them apart before a grant goes to the wrong
    /// one.
    pub auth_source: String,
    /// The name of the realm the account belongs to (a credential-forwarding
    /// or trusted-header one); `null` for none, or when it was deleted.
    pub realm: Option<String>,
    /// When the account last authenticated: the latest use of one of its API
    /// tokens, or the last request its trusted-header realm named it in.
    pub last_used_at: Option<DateTime<Utc>>,
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
        details: Option<&AccountDetails>,
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
            kind: AccountKind::of(u),
            description: details.and_then(|d| d.description.clone()),
            is_admin: roles.iter().any(|r| r == authz_dao::ADMIN_ROLE),
            active: u.active,
            auth_source: u.auth_source.clone(),
            realm: details.and_then(|d| d.realm.clone()),
            last_used_at: details.and_then(|d| d.last_used_at),
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
        let details = user_dao::account_details(&state.pool, Some(u.id))
            .await
            .map_err(db_error)?;
        Ok(UserView {
            captured_password_at,
            ..Self::new(
                u,
                roles,
                onboarding.as_ref(),
                invitation.as_ref(),
                details.first(),
            )
        })
    }
}

/// Whether an account stands for a person or for a machine or a network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountKind {
    /// A person.
    #[default]
    User,
    /// A service account: a machine or a network nobody signs in to.
    Service,
}

impl AccountKind {
    fn of(u: &AppUser) -> Self {
        if u.is_service_account() {
            AccountKind::Service
        } else {
            AccountKind::User
        }
    }
}

/// Longest accepted service-account description, in characters.
const MAX_DESCRIPTION_CHARS: usize = 1000;

/// A service account's description, trimmed (`None` when blank), or the
/// **400** that refuses it: too long, or holding a control character other
/// than a newline or tab, or a format character ([`is_format_character`]),
/// with which the description would read otherwise in the admin list than
/// it is.
fn parse_description(description: Option<&str>) -> Result<Option<String>, Response> {
    let Some(description) = description.map(str::trim).filter(|d| !d.is_empty()) else {
        return Ok(None);
    };
    if description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("description must be at most {MAX_DESCRIPTION_CHARS} characters"),
        )
            .into_response());
    }
    if description
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "description must not contain control characters",
        )
            .into_response());
    }
    if let Some(c) = description.chars().find(|&c| is_format_character(c)) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "description must not contain invisible formatting characters such as U+{:04X}",
                c as u32
            ),
        )
            .into_response());
    }
    Ok(Some(description.to_string()))
}

/// A Unicode format character (general category `Cf`): the bidirectional
/// embeddings, overrides and isolates (U+202E reverses what follows it),
/// zero-width and other invisible characters, and tags. Not the zero-width
/// non-joiner and joiner (U+200C, U+200D), which emoji and several scripts
/// need.
fn is_format_character(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B
            | 0x200E..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

/// The id of the trusted-header realm named `name`, which a service account
/// may belong to, or the **400** that refuses the name.
async fn service_account_realm(state: &AppState, name: &str) -> Result<i64, Response> {
    match forge_db::auth_realm_dao::find_realm_by_name(&state.pool, name.trim()).await {
        Ok(Some(r)) if r.kind == crate::auth::KIND_TRUSTED_HEADER => Ok(r.id),
        Ok(_) => Err((
            StatusCode::BAD_REQUEST,
            format!("no trusted-header realm is named {name:?}"),
        )
            .into_response()),
        Err(e) => Err(db_error(e)),
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
/// `realm` (it signs in with the upstream's password) or of the
/// trusted-header realm named `realm` (the proxy's headers name it). No
/// password is ever taken here. With `"kind": "service"`, a service account
/// (module docs), of the trusted-header realm `realm` or of none.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUser {
    pub username: String,
    #[serde(default)]
    pub kind: AccountKind,
    /// What a service account is for and who owns it.
    #[serde(default)]
    pub description: Option<String>,
    /// Where the invitation goes; the username when absent. A service
    /// account has none.
    #[serde(default)]
    pub email: Option<String>,
    /// `admin` is refused for a service account.
    #[serde(default)]
    pub role: AccessRole,
    /// The name of a `credential_forwarding` or `trusted_header` realm; for
    /// a service account, of a `trusted_header` one.
    #[serde(default)]
    pub realm: Option<String>,
}

/// `GET /admin/users` query.
#[derive(Debug, Default, Deserialize)]
pub struct ListUsers {
    /// Only the accounts of this kind.
    #[serde(default)]
    pub kind: Option<AccountKind>,
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
/// settable, and a service account's description and realm; unknown fields
/// (e.g. an attempted `is_admin`) are rejected rather than silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateUser {
    /// `false` deactivates (and cuts off) the user, `true` reactivates it.
    #[serde(default)]
    pub active: Option<bool>,
    /// A service account's description; `null` or blank clears it.
    #[serde(default, deserialize_with = "double_option")]
    pub description: Option<Option<String>>,
    /// The trusted-header realm a service account belongs to, by name;
    /// `null` for none (only its tokens authenticate it then).
    #[serde(default, deserialize_with = "double_option")]
    pub realm: Option<Option<String>>,
}

/// `GET /admin/users`, or `?kind=user` / `?kind=service` for the accounts of
/// that kind alone.
pub async fn list(State(state): State<AppState>, Query(query): Query<ListUsers>) -> Response {
    let users = match user_dao::list_users(&state.pool).await {
        Ok(users) => users,
        Err(e) => return db_error(e),
    };
    let users: Vec<AppUser> = users
        .into_iter()
        .filter(|u| query.kind.is_none_or(|kind| AccountKind::of(u) == kind))
        .collect();
    let details: std::collections::HashMap<i64, AccountDetails> =
        match user_dao::account_details(&state.pool, None).await {
            Ok(rows) => rows.into_iter().map(|d| (d.id, d)).collect(),
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
                details.get(&u.id),
            )
        })
        .collect();
    Json(views).into_response()
}

/// `POST /admin/users`: create an invited local account and invite its user
/// (module docs), an account of a credential-forwarding or trusted-header
/// realm, or a service account. **201** with the user and, for a local
/// account, its invitation: whether the email went out, and the link when it
/// did not.
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
    let account = match (body.kind, body.realm.as_deref()) {
        (AccountKind::Service, realm) => {
            if email.is_some() {
                return (
                    StatusCode::BAD_REQUEST,
                    "a service account has no email address: nobody signs in to it",
                )
                    .into_response();
            }
            if body.role == AccessRole::Admin {
                return service_account_admin_refused();
            }
            let description = match parse_description(body.description.as_deref()) {
                Ok(description) => description,
                Err(resp) => return resp,
            };
            let realm_id = match realm {
                Some(realm) => match service_account_realm(&state, realm).await {
                    Ok(id) => Some(id),
                    Err(resp) => return resp,
                },
                None => None,
            };
            NewAccount::Service {
                description,
                realm_id,
            }
        }
        (AccountKind::User, _) if body.description.is_some() => {
            return (
                StatusCode::BAD_REQUEST,
                "only a service account has a description",
            )
                .into_response()
        }
        (AccountKind::User, Some(realm)) => {
            match forge_db::auth_realm_dao::find_realm_by_name(&state.pool, realm.trim()).await {
                Ok(Some(r)) if r.kind == crate::auth::KIND_CRED_FORWARD => {
                    NewAccount::Forwarded { realm_id: r.id }
                }
                Ok(Some(r)) if r.kind == crate::auth::KIND_TRUSTED_HEADER => {
                    if body.role == AccessRole::Admin {
                        return trusted_header_admin_refused();
                    }
                    NewAccount::TrustedHeader { realm_id: r.id }
                }
                Ok(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!(
                            "no credential-forwarding or trusted-header realm is named {realm:?}"
                        ),
                    )
                        .into_response()
                }
                Err(e) => return db_error(e),
            }
        }
        (AccountKind::User, None) => {
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
        NewAccount::Forwarded { .. }
        | NewAccount::TrustedHeader { .. }
        | NewAccount::Service { .. } => None,
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
    /// An account of this trusted-header realm.
    TrustedHeader { realm_id: i64 },
    /// A service account, of this trusted-header realm or of none.
    Service {
        description: Option<String>,
        realm_id: Option<i64>,
    },
}

/// The **400** to the `admin` role for a service account.
pub(crate) fn service_account_admin_refused() -> Response {
    (
        StatusCode::BAD_REQUEST,
        "a service account cannot hold the admin role; for admin automation, issue an \
         administrator a token with the admin scope",
    )
        .into_response()
}

/// The **400** to the `admin` role for an account of a trusted-header realm:
/// its headers never make it an administrator, and holding the role it would
/// still count as one, so the last real administrator could go (#547).
pub(crate) fn trusted_header_admin_refused() -> Response {
    (
        StatusCode::BAD_REQUEST,
        "an account of a trusted-header realm cannot hold the admin role: the headers never \
         make anyone an administrator",
    )
        .into_response()
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
    let mut tx = forge_db::begin(&state.pool).await?;
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
        NewAccount::TrustedHeader { realm_id } => {
            let user = user_dao::insert_trusted_header_user(&mut *tx, username, *realm_id).await?;
            if email.is_some() {
                invitation_dao::set_email(&mut *tx, user.id, email).await?;
            }
            user
        }
        NewAccount::Service {
            description,
            realm_id,
        } => {
            user_dao::insert_service_account(&mut *tx, username, description.as_deref(), *realm_id)
                .await?
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

/// `POST /admin/users/{id}/invitation/accept` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptInvitation {
    /// The account's password from now on.
    pub password: String,
}

/// `POST /admin/users/{id}/invitation/accept`: accept an invited account's
/// invitation on its user's behalf, with a password the administrator sets,
/// for an account handed over ready to use (an install without email, a
/// user without a mailbox). The password becomes the account's, the account
/// is `active`, and its invitation, if there is one, is marked accepted, so
/// its link stops working: one transaction. It works with a live invitation
/// waiting or without one (`invited`, `invitation_expired`). This is the
/// only way an administrator sets another person's password.
///
/// **400** for a password the invitation page refuses too
/// ([`invitations::check_password`]); **404** for no account; **409** for an
/// account that is not an active invited one (its user chose a password
/// already, an account of another realm, a service account, a deactivated
/// account).
pub async fn accept_invitation(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<i64>,
    Json(body): Json<AcceptInvitation>,
) -> Response {
    const NOT_INVITED: &str = "only an active local account whose user has not chosen a \
                               password yet can have its invitation accepted";
    if let Err(why) = invitations::check_password(&body.password) {
        return (StatusCode::BAD_REQUEST, why).into_response();
    }
    let user = match user_dao::find_user_by_id(&state.pool, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    };
    // Before the argon2 work; the update checks again, in its transaction.
    let invited = match invitation_dao::onboarding(&state.pool, id).await {
        Ok(onboarding) => onboarding.is_some_and(|o| o.invited),
        Err(e) => return db_error(e),
    };
    if !invited || !user.active || user.auth_source != "local" || user.is_service_account() {
        return (StatusCode::CONFLICT, NOT_INVITED).into_response();
    }
    let password_hash = match super::hash_password(body.password).await {
        Ok(hash) => hash,
        Err(resp) => return resp,
    };
    let accepted = match invitation_dao::accept_for_user(&state.pool, id, &password_hash).await {
        Ok(Some(user)) => user,
        // Accepted, deactivated or deleted meanwhile.
        Ok(None) => {
            return match user_dao::find_user_by_id(&state.pool, id).await {
                Ok(Some(_)) => (StatusCode::CONFLICT, NOT_INVITED).into_response(),
                Ok(None) => (StatusCode::NOT_FOUND, "user not found").into_response(),
                Err(e) => db_error(e),
            }
        }
        Err(e) => return db_error(e),
    };
    tracing::info!(
        target: "forge::audit",
        user_id = accepted.id,
        username = %accepted.username,
        principal = %principal.audit_label(),
        "invitation accepted by an administrator: the password is set"
    );
    match UserView::load(&state, &accepted).await {
        Ok(view) => Json(view).into_response(),
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
///
/// A service account's `description` and `realm` (the trusted-header realm
/// that names it, or `null` for none) are set here too; a user's are refused
/// (**409**). A new realm names the account from the next request, and the
/// one before stops naming it. Every field of a request is applied in one
/// transaction: all of them, or none.
pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateUser>,
) -> Response {
    if body.active.is_none() && body.description.is_none() && body.realm.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "nothing to update (expected {\"active\": true|false}, or a service account's \
             description or realm)",
        )
            .into_response();
    }
    let changes = if body.description.is_some() || body.realm.is_some() {
        match service_account_changes(&state, id, &body).await {
            Ok(changes) => Some(changes),
            Err(resp) => return resp,
        }
    } else {
        None
    };
    let user = match apply_update(&state, id, changes.as_ref(), body.active).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(resp) => return resp,
    };
    if changes.is_some() {
        tracing::info!(
            user_id = user.id,
            username = %user.username,
            "service account updated"
        );
    }
    if body.active == Some(false) {
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

/// The `description` and `realm` a PATCH sets on a service account, each
/// `None` when the request leaves it as it is.
struct ServiceAccountChanges {
    description: Option<Option<String>>,
    realm_id: Option<Option<i64>>,
}

/// The `description` and `realm` a PATCH carries for the service account
/// `id`, checked: **404** for no account, **409** for a user's, **400** for
/// a description or realm that is refused.
async fn service_account_changes(
    state: &AppState,
    id: i64,
    body: &UpdateUser,
) -> Result<ServiceAccountChanges, Response> {
    let user = match user_dao::find_user_by_id(&state.pool, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err((StatusCode::NOT_FOUND, "user not found").into_response()),
        Err(e) => return Err(db_error(e)),
    };
    if !user.is_service_account() {
        return Err((
            StatusCode::CONFLICT,
            "only a service account's description and realm are set here: a user's realm is \
             how they sign in",
        )
            .into_response());
    }
    let description = match &body.description {
        Some(description) => Some(parse_description(description.as_deref())?),
        None => None,
    };
    let realm_id = match &body.realm {
        Some(Some(realm)) => Some(Some(service_account_realm(state, realm).await?)),
        Some(None) => Some(None),
        None => None,
    };
    Ok(ServiceAccountChanges {
        description,
        realm_id,
    })
}

/// Apply a PATCH to the account `id` in one transaction: a service
/// account's `changes`, then `active` under the last-admin guard (only a
/// deactivation can remove an admin). `Ok(None)` when no such account
/// exists.
async fn apply_update(
    state: &AppState,
    id: i64,
    changes: Option<&ServiceAccountChanges>,
    active: Option<bool>,
) -> Result<Option<AppUser>, Response> {
    let mut tx = forge_db::begin(&state.pool).await.map_err(db_error)?;
    if let Some(changes) = changes {
        if let Some(description) = &changes.description {
            user_dao::set_service_account_description(&mut *tx, id, description.as_deref())
                .await
                .map_err(db_error)?;
        }
        if let Some(realm_id) = changes.realm_id {
            user_dao::set_service_account_realm(&mut *tx, id, realm_id)
                .await
                .map_err(db_error)?;
        }
    }
    let user = match active {
        Some(active) => {
            if !active
                && authz_dao::would_leave_no_admin(&mut tx, id)
                    .await
                    .map_err(db_error)?
            {
                return Err(last_admin_conflict());
            }
            user_dao::set_active(&mut *tx, id, active)
                .await
                .map_err(db_error)?
        }
        None => user_dao::find_user_by_id(&mut *tx, id)
            .await
            .map_err(db_error)?,
    };
    tx.commit().await.map_err(db_error)?;
    Ok(user)
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
/// verdicts, sessions or such tokens still returns `204`). **409** for a
/// service account, which nobody signs in to: revoke its tokens or
/// deactivate it instead.
pub async fn reauth(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let user = match user_dao::find_user_by_id(&state.pool, id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return db_error(e),
    };
    if user.is_service_account() {
        return (
            StatusCode::CONFLICT,
            "nobody signs in to a service account: revoke its tokens or deactivate it",
        )
            .into_response();
    }

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

/// Delete the user in a transaction under the last-admin guard. `Ok(false)`
/// when no such user exists.
async fn delete_guarded(state: &AppState, id: i64) -> Result<bool, Response> {
    let mut tx = forge_db::begin(&state.pool).await.map_err(db_error)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptions_refuse_what_reads_otherwise_than_it_is() {
        let parsed = |d: &str| parse_description(Some(d)).ok().flatten();
        assert_eq!(
            parsed("  CI of the web team  ").as_deref(),
            Some("CI of the web team")
        );
        assert_eq!(
            parsed("owner:\n\tplatform").as_deref(),
            Some("owner:\n\tplatform")
        );
        // Emoji and scripts keep their joiners.
        assert!(parsed("runners \u{1F468}\u{200D}\u{1F4BB}").is_some());
        assert!(
            parsed("\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}").is_some()
        );
        assert_eq!(parse_description(Some("   ")).ok(), Some(None));
        for c in [
            '\u{7}',
            '\u{202E}',
            '\u{202D}',
            '\u{2066}',
            '\u{2069}',
            '\u{200E}',
            '\u{200F}',
            '\u{061C}',
            '\u{200B}',
            '\u{2060}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{E0041}',
        ] {
            assert!(
                parse_description(Some(&format!("build {c}agent"))).is_err(),
                "U+{:04X}",
                c as u32
            );
        }
    }
}
