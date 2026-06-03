//! OpenID Connect support (slice 12.2).
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
//! * [`claims`] — pure claim → user mapping + `is_admin` derivation (§3.6).
//! * [`resolve_user`] — identity resolution: find via `external_identity`, else
//!   auto-provision / link an existing local user / reject; recompute `is_admin`.
//!
//! ## Multi-instance / no-advisory-lock posture
//!
//! Discovery and JWKS are cached via the slice-1 [`forge_cache::Cache`]
//! (L1 moka + optional Redis L2 + invalidation backplane). Request coalescing is
//! moka's per-instance [`try_get_with`](forge_cache::Cache::get_or_try_insert_with);
//! an occasional duplicate JWKS fetch across instances is harmless, so we use
//! **no** Postgres advisory locks. On a `kid` miss (Entra rotated keys before the
//! TTL elapsed) we force exactly one cache-bypassing refetch, repopulate the
//! cache, broadcast an invalidation, and retry validation once. Auth-code-flow
//! state and sessions live in Postgres (`oidc_flow` / `session`), never process
//! memory.

pub mod claims;
pub mod flow;
pub mod jwks;

use forge_db::model::AppUser;
use forge_db::user_dao::{self, NewUser};
use forge_db::{authz_dao, external_identity_dao, oidc_flow_dao, session_dao};
use sqlx::PgPool;

pub use claims::{map_claims, ClaimMapping, MappedClaims};
pub use flow::{
    begin_login, complete_login, BeginLogin, CallbackParams, ClientParams, FlowError,
    ValidatedLogin,
};
pub use jwks::{
    DiscoveryDocument, IdTokenClaims, OidcError, OidcMetadataClient, Verified, VerifyParams,
};

// Re-export the slice-1 DAOs that the server's `/auth` routes (Phase 5) drive,
// so callers reach them through `forge_core::oidc::*` without depending on
// `forge_db` directly for the OIDC tables.
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
    /// IdP authenticated successfully (§6 account-state check).
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
    /// Link an OIDC identity to an existing local `app_user` whose `username`
    /// equals the resolved username claim (bootstrap-admin interplay). Risky if
    /// the username claim is attacker-influenced — operators set this `false` in
    /// hardened deployments.
    pub link_existing_by_username: bool,
}

impl Default for ResolvePolicy {
    fn default() -> Self {
        Self {
            auto_provision: true,
            link_existing_by_username: true,
        }
    }
}

/// Resolve (and, per policy, provision or link) the `app_user` for a validated
/// login, recomputing `is_admin` from the current claims (§3.6).
///
/// Order:
/// 1. **Existing link** `(issuer, subject)` → load that user, recompute admin,
///    refresh the denormalized identity claims.
/// 2. **No link, matching local username** + `link_existing_by_username` → link
///    the existing user (bootstrap-admin interplay), recompute admin.
/// 3. **No link, no match** + `auto_provision` → create a no-password user, link.
/// 4. **Else** → [`ResolveError::NotProvisioned`].
///
/// In every path the resolved user's `active` flag is enforced
/// ([`ResolveError::Inactive`]) — an IdP login can't bypass a locally disabled
/// account.
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
        return finalize(pool, user, login, &identity_claims, mapped.is_admin).await;
    }

    // 2. No link, but a local user already owns this username → link it.
    if policy.link_existing_by_username {
        if let Some(user) = user_dao::find_user_by_username(pool, &mapped.username)
            .await
            .map_err(|e| ResolveError::Db(e.to_string()))?
        {
            return finalize(pool, user, login, &identity_claims, mapped.is_admin).await;
        }
    }

    // 3. Auto-provision a fresh, password-less user, then link.
    if policy.auto_provision {
        let username = unique_username(pool, &mapped.username).await?;
        let user = user_dao::insert_user(
            pool,
            NewUser {
                username,
                // No local password: slice 12.3 made password_hash nullable and
                // records provenance instead. A NULL hash means password-basic
                // can never authenticate this user (token.rs short-circuits on
                // None); the (issuer, subject) link in external_identity is the
                // authority for OIDC logins.
                password_hash: None,
                is_admin: mapped.is_admin,
                active: true,
                auth_source: "oidc".to_string(),
                external_subject: Some(login.subject.clone()),
            },
        )
        .await
        .map_err(|e| ResolveError::Db(e.to_string()))?;
        // §12.4 Phase 5: on a legacy-open-access (upgraded slice-1) install, a
        // freshly auto-provisioned OIDC user must inherit the `authenticated` role
        // immediately so it has the slice-1 "read/write everywhere" reach —
        // `ensure_legacy_rbac` only folds in new users at the next boot. The
        // assignment is idempotent and gated on the install-wide flag, so a fresh
        // (fail-closed) install leaves the user with no automatic grants.
        authz_dao::assign_authenticated_if_legacy_open(pool, user.id)
            .await
            .map_err(|e| ResolveError::Db(e.to_string()))?;
        return finalize(pool, user, login, &identity_claims, mapped.is_admin).await;
    }

    // 4. No link, no match, no provisioning → reject.
    Err(ResolveError::NotProvisioned)
}

/// Common tail for every resolution branch: enforce `active`, recompute
/// `is_admin` from the current claims, refresh the `external_identity` link
/// (insert or update denormalized claims + `last_login_at`).
async fn finalize(
    pool: &PgPool,
    user: AppUser,
    login: &ValidatedLogin,
    identity_claims: &IdentityClaims,
    is_admin: bool,
) -> Result<AppUser, ResolveError> {
    if !user.active {
        return Err(ResolveError::Inactive);
    }

    // Recompute admin on every login so IdP grant/revoke takes effect.
    let user = if user.is_admin != is_admin {
        user_dao::update_is_admin(pool, user.id, is_admin)
            .await
            .map_err(|e| ResolveError::Db(e.to_string()))?
    } else {
        user
    };

    // Upsert the (issuer, subject) link — inserts on first login, refreshes
    // denormalized claims + last_login_at thereafter. Never re-points an existing
    // link at a different user (the DAO only sets user_id on insert).
    external_identity_dao::link(
        pool,
        user.id,
        &login.issuer,
        &login.subject,
        identity_claims.clone(),
    )
    .await
    .map_err(|e| ResolveError::Db(e.to_string()))?;

    Ok(user)
}

/// Find a free username, suffixing `-2`, `-3`, … on collision so auto-provision
/// never fails the unique constraint. (Only reached when there is no existing
/// `(issuer, subject)` link, so a collision means a *different* local account
/// already owns the base name and linking was disabled.)
async fn unique_username(pool: &PgPool, base: &str) -> Result<String, ResolveError> {
    if user_dao::find_user_by_username(pool, base)
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
