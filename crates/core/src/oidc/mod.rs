//! OpenID Connect support.
//!
//! This module implements the IdP-facing half of interactive OIDC login:
//!
//! * [`jwks`] — OIDC **discovery** (`/.well-known/openid-configuration`) and
//!   **JWKS** fetching, both cached through [`forge_cache::Cache`], plus an
//!   **ID-token verifier** that checks the RS/PS signature against the JWKS and
//!   the `iss` / `aud` / `exp` / `nbf` / `nonce` claims.
//! * [`flow`] — the authorization-code + PKCE flow: [`flow::begin_login`] builds
//!   the authorize URL (state/nonce/PKCE) and persists an `oidc_flow` row;
//!   [`flow::complete_login`] consumes that row (single-use), exchanges the code,
//!   and verifies the ID token. All flow state lives in Postgres, so any instance
//!   can complete a callback another instance began.
//! * [`assertion`] — forge as the issuer of its own client assertions: the
//!   rotating RSA key set, its JWKS, and the signed `client_assertion` an
//!   `oidc` realm can authenticate with instead of a client secret.
//! * [`claims`] — pure claim → user mapping + `is_admin` derivation.
//! * [`resolve_user`] — identity resolution: find via `external_identity`, else
//!   auto-provision / link an existing local user / reject; recompute `is_admin`.
//!
//! ## Multi-instance / no-advisory-lock posture
//!
//! Discovery and JWKS are cached via [`forge_cache::Cache`]
//! (L1 moka + optional Redis L2 + invalidation backplane). Request coalescing is
//! moka's per-instance [`try_get_with`](forge_cache::Cache::get_or_try_insert_with);
//! an occasional duplicate JWKS fetch across instances is harmless, so we use
//! **no** Postgres advisory locks. On a `kid` miss (Entra rotated keys before the
//! TTL elapsed) we force exactly one cache-bypassing refetch, repopulate the
//! cache, broadcast an invalidation, and retry validation once. Auth-code-flow
//! state and sessions live in Postgres (`oidc_flow` / `session`), never process
//! memory.

pub mod assertion;
pub mod claims;
pub mod flow;
pub mod jwks;

use forge_db::model::AppUser;
use forge_db::user_dao::{self, NewUser};
use forge_db::{authz_dao, external_identity_dao, oidc_flow_dao, session_dao};
use sqlx::PgPool;

pub use assertion::{AssertionClaims, IssuerKeySet};
pub use claims::{map_claims, ClaimMapping, MappedClaims};
pub use flow::{
    begin_login, browser_binding, complete_login, BeginLogin, CallbackParams, ClientAssertion,
    ClientAuth, ClientParams, FlowError, ValidatedLogin,
};
pub use jwks::{
    DiscoveryDocument, IdTokenClaims, OidcError, OidcMetadataClient, Verified, VerifyParams,
};

// Re-export the DAO types the server's `/auth` routes drive, so callers reach
// them through `forge_core::oidc::*` without depending on `forge_db` directly
// for the OIDC tables.
pub use external_identity_dao::IdentityClaims;
pub use oidc_flow_dao::NewOidcFlow;
pub use session_dao::NewSession;

/// Errors raised while resolving / provisioning the `app_user` for a login.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// No linked identity, no matching local user (when linking is on), and
    /// `auto_provision = false`: the operator must pre-create the user.
    #[error("oidc user not provisioned")]
    NotProvisioned,
    /// The resolved/linked `app_user` is `active = false`: reject even though the
    /// IdP authenticated successfully.
    #[error("oidc user is inactive")]
    Inactive,
    /// A database error during resolution.
    #[error("oidc resolve db error: {0}")]
    Db(String),
}

/// How identity resolution should provision / link users. Built by the server
/// from its `OidcConfig`; kept in `core` so the resolution logic is testable
/// without the server crate.
#[derive(Debug, Clone)]
pub struct ResolvePolicy {
    /// Create a fresh `app_user` on first login when no link/match exists.
    pub auto_provision: bool,
    /// Link a *new* OIDC identity to an existing `app_user` whose `username`
    /// equals the resolved username claim. **Off by default**: the username
    /// claim is IdP-controlled and often user-editable. Even when enabled, only
    /// an account that no other credential owns is linked this way — never one
    /// with a local password, admin rights, a credential-forwarding origin or
    /// an existing IdP link (see [`resolve_user`]).
    pub link_existing_by_username: bool,
    /// When set, an auto-provisioned account is named `{claim}@{namespace}`
    /// instead of the bare username claim. The server sets it to the OIDC
    /// realm's name while a credential-forwarding realm is enabled: a
    /// forwarded user's account is created on their first password login, so
    /// a bare claim (which users may choose at some IdPs) could take that
    /// name first and lock the directory user out.
    pub provision_namespace: Option<String>,
}

impl Default for ResolvePolicy {
    fn default() -> Self {
        Self {
            auto_provision: true,
            link_existing_by_username: false,
            provision_namespace: None,
        }
    }
}

/// Resolve (and, per policy, provision or link) the `app_user` for a validated
/// login, recomputing `is_admin` from the current claims.
///
/// Order:
/// 1. **Existing link** `(issuer, subject)` → load that user, recompute admin,
///    refresh the denormalized identity claims. This stable, issuer-scoped key
///    is the identity of an OIDC user — never the username or email.
/// 2. **No link, matching username** + `link_existing_by_username` (off by
///    default) → link the existing user, but **only** if no other credential
///    owns it: no local password, not an admin (column or `admin` role), not a
///    credential-forwarding (`upstream-basic`) account, and not linked to any
///    IdP identity yet (of this or another issuer). A colliding
///    `preferred_username` must never take over a password account, an
///    administrator, a directory account or another person's IdP account.
///    Otherwise fall through (a fresh, suffixed user is provisioned
///    instead).
/// 3. **No link, no linkable match** + `auto_provision` → create a no-password
///    user, link.
/// 4. **Else** → [`ResolveError::NotProvisioned`].
///
/// In every path the resolved user's `active` flag is enforced
/// ([`ResolveError::Inactive`]) — an IdP login can't bypass a locally disabled
/// account.
///
/// **Concurrent first logins.** Two callbacks for the same new `(issuer,
/// subject)` can both miss step 1 and both provision. The `(issuer, subject)`
/// link is unique and never re-pointed, so exactly one account wins it; the
/// loser adopts the account the link actually names (the `user_id` the link
/// upsert returns) and deletes the orphan it just provisioned — a session is
/// never minted for an account the identity is not linked to.
pub async fn resolve_user(
    pool: &PgPool,
    login: &ValidatedLogin,
    mapped: &MappedClaims,
    policy: &ResolvePolicy,
) -> Result<AppUser, ResolveError> {
    let identity_claims = IdentityClaims {
        preferred_username: Some(mapped.username.clone()),
        email: mapped.email.clone(),
        display_name: mapped.display_name.clone(),
    };

    // 1. Existing link by the stable (issuer, subject) key.
    if let Some(user) =
        external_identity_dao::find_user_by_subject(pool, &login.issuer, &login.subject)
            .await
            .map_err(|e| ResolveError::Db(e.to_string()))?
    {
        return finalize(pool, user, login, &identity_claims, mapped, false).await;
    }

    // 2. No link, but an existing user owns this username → link it, unless
    //    it is a password account or an admin (never linkable by name).
    if policy.link_existing_by_username {
        if let Some(user) = user_dao::find_user_by_username(pool, &mapped.username)
            .await
            .map_err(|e| ResolveError::Db(e.to_string()))?
        {
            let is_admin_role = authz_dao::user_has_role(pool, user.id, authz_dao::ADMIN_ROLE)
                .await
                .map_err(|e| ResolveError::Db(e.to_string()))?;
            let already_linked = external_identity_dao::user_has_identity(pool, user.id)
                .await
                .map_err(|e| ResolveError::Db(e.to_string()))?;
            if user.password_hash.is_none()
                && !user.is_admin
                && !is_admin_role
                && user.auth_source != "upstream-basic"
                && !already_linked
            {
                return finalize(pool, user, login, &identity_claims, mapped, false).await;
            }
            tracing::warn!(
                username = %mapped.username,
                "oidc login not linked by username: target has a password, is an admin, \
                 is a credential-forwarding account or is already linked to an identity"
            );
        }
    }

    // 3. Auto-provision a fresh, password-less user, then link.
    if policy.auto_provision {
        let user = match provision_oidc_user(pool, login, mapped, policy).await? {
            Provisioned::New(user) => {
                finalize(pool, user, login, &identity_claims, mapped, true).await?
            }
            // A concurrent first login provisioned and linked the identity
            // while this one was still looking for a free username.
            Provisioned::AlreadyLinked(user) => {
                finalize(pool, user, login, &identity_claims, mapped, false).await?
            }
        };
        // §12.4 Phase 5: on a legacy-open-access (upgraded slice-1) install, a
        // freshly auto-provisioned OIDC user must inherit the `authenticated` role
        // immediately so it has the slice-1 "read/write everywhere" reach —
        // `ensure_legacy_rbac` runs only once per install. The
        // assignment is idempotent and gated on the install-wide flag, so a fresh
        // (fail-closed) install leaves the user with no automatic grants. (When
        // a concurrent login won the link, this is the winner's account, for
        // which the assignment is equally due — and idempotent.)
        authz_dao::assign_authenticated_if_legacy_open(pool, user.id)
            .await
            .map_err(|e| ResolveError::Db(e.to_string()))?;
        return Ok(user);
    }

    // 4. No link, no match, no provisioning → reject.
    Err(ResolveError::NotProvisioned)
}

/// Outcome of [`provision_oidc_user`].
enum Provisioned {
    /// This call inserted the account; [`finalize`] must still link it.
    New(AppUser),
    /// A concurrent first login already provisioned and linked the identity.
    AlreadyLinked(AppUser),
}

/// Upper bound on username-collision retries while provisioning. Each
/// collision means a concurrent insert won that name, so the bound only needs
/// to exceed the number of first logins for one identity racing at once.
const PROVISION_ATTEMPTS: u32 = 16;

/// Insert the auto-provisioned, password-less OIDC user. A username collision
/// with a concurrent insert (several first logins picking the same free name
/// at once) is retried: if a concurrent login has meanwhile linked this very
/// identity, its account is adopted instead of provisioning another one;
/// otherwise the retry allocates the next free suffix, and the link step in
/// [`finalize`] settles which account the identity belongs to.
async fn provision_oidc_user(
    pool: &PgPool,
    login: &ValidatedLogin,
    mapped: &MappedClaims,
    policy: &ResolvePolicy,
) -> Result<Provisioned, ResolveError> {
    let base = match &policy.provision_namespace {
        Some(namespace) => format!("{}@{namespace}", mapped.username),
        None => mapped.username.clone(),
    };
    let mut attempt = 0;
    loop {
        let username = unique_username(pool, &base).await?;
        let inserted = user_dao::insert_user(
            pool,
            NewUser {
                username,
                // No local password; `auth_source` records provenance instead.
                // A NULL hash means password-basic can never authenticate this
                // user (the local-password provider skips it); the (issuer,
                // subject) link in external_identity is the authority for OIDC
                // logins.
                password_hash: None,
                is_admin: mapped.is_admin,
                active: true,
                auth_source: "oidc".to_string(),
                external_subject: Some(login.subject.clone()),
            },
        )
        .await;
        match inserted {
            Ok(user) => return Ok(Provisioned::New(user)),
            Err(sqlx::Error::Database(db))
                if db.code().as_deref() == Some("23505") && attempt < PROVISION_ATTEMPTS =>
            {
                attempt += 1;
                if let Some(user) =
                    external_identity_dao::find_user_by_subject(pool, &login.issuer, &login.subject)
                        .await
                        .map_err(|e| ResolveError::Db(e.to_string()))?
                {
                    return Ok(Provisioned::AlreadyLinked(user));
                }
            }
            Err(e) => return Err(ResolveError::Db(e.to_string())),
        }
    }
}

/// Common tail for every resolution branch: enforce `active`, upsert the
/// `external_identity` link (insert, or refresh denormalized claims +
/// `last_login_at`), then recompute admin from the current claims (when the IdP
/// is authoritative for it) on the account the link **actually** names.
///
/// The link is unique on `(issuer, subject)` and never re-pointed, so when a
/// concurrent first login linked the identity to another account first, the
/// upsert returns that account's id: it is adopted (its own `active` flag
/// enforced), and — when `provisioned` says `user` was created by this very
/// call — the now-orphaned `user` is deleted.
async fn finalize(
    pool: &PgPool,
    user: AppUser,
    login: &ValidatedLogin,
    identity_claims: &IdentityClaims,
    mapped: &MappedClaims,
    provisioned: bool,
) -> Result<AppUser, ResolveError> {
    if !user.active {
        return Err(ResolveError::Inactive);
    }

    // Never re-points an existing link at a different user (the DAO only sets
    // user_id on insert).
    let link = external_identity_dao::link(
        pool,
        user.id,
        &login.issuer,
        &login.subject,
        identity_claims.clone(),
    )
    .await
    .map_err(|e| ResolveError::Db(e.to_string()))?;

    let user = if link.user_id == user.id {
        user
    } else {
        // Lost the race for the link: the identity belongs to `link.user_id`.
        if provisioned {
            tracing::info!(
                orphan_user_id = user.id,
                linked_user_id = link.user_id,
                "concurrent first oidc login: dropping the duplicate provisioned account"
            );
            user_dao::delete_user(pool, user.id)
                .await
                .map_err(|e| ResolveError::Db(e.to_string()))?;
        }
        let linked = user_dao::find_user_by_id(pool, link.user_id)
            .await
            .map_err(|e| ResolveError::Db(e.to_string()))?
            .ok_or_else(|| ResolveError::Db("linked oidc user vanished".into()))?;
        if !linked.active {
            return Err(ResolveError::Inactive);
        }
        linked
    };

    // Recompute admin on every login so IdP grant/revoke takes effect — but
    // only when the realm maps admin groups; otherwise admins are managed
    // locally and a login must not touch them. Both the legacy column and the
    // built-in `admin` role follow the claim, so a demotion also removes the
    // role (the column alone is only a dual-read fallback). The caller
    // invalidates the user's cached effective set.
    let user = if mapped.admin_managed {
        let user = if user.is_admin != mapped.is_admin {
            user_dao::update_is_admin(pool, user.id, mapped.is_admin)
                .await
                .map_err(|e| ResolveError::Db(e.to_string()))?
        } else {
            user
        };
        let changed = authz_dao::sync_admin_role(pool, user.id, mapped.is_admin)
            .await
            .map_err(|e| ResolveError::Db(e.to_string()))?;
        if changed && !mapped.is_admin {
            crate::auth::chain::revoke_sessions_on_demotion(pool, user.id)
                .await
                .map_err(|e| ResolveError::Db(e.to_string()))?;
        }
        user
    } else {
        user
    };

    Ok(user)
}

/// Find a free username, suffixing `-2`, `-3`, … on collision so auto-provision
/// never fails the unique constraint. (Only reached when there is no existing
/// `(issuer, subject)` link, so a collision means a *different* account
/// already owns the base name and was not linked.) A
/// [reserved](forge_db::username::RESERVED_USERNAMES) base name is never
/// free, so an IdP user called `oidc` becomes `oidc-2`.
async fn unique_username(pool: &PgPool, base: &str) -> Result<String, ResolveError> {
    let reserved = forge_db::username::canonical_username(base)
        .is_ok_and(|canonical| forge_db::username::is_reserved_username(&canonical));
    if !reserved
        && user_dao::find_user_by_username(pool, base)
            .await
            .map_err(|e| ResolveError::Db(e.to_string()))?
            .is_none()
    {
        return Ok(base.to_string());
    }
    for n in 2..1000 {
        let candidate = format!("{base}-{n}");
        if user_dao::find_user_by_username(pool, &candidate)
            .await
            .map_err(|e| ResolveError::Db(e.to_string()))?
            .is_none()
        {
            return Ok(candidate);
        }
    }
    Err(ResolveError::Db(
        "could not allocate a unique username".into(),
    ))
}
