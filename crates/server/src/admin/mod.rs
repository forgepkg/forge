//! Admin REST API (spec §5/§8, plan 10.4). **Admin-only.**
//!
//! Mounted under `/admin`. Every route is gated by [`require_admin`], which
//! reads the [`Principal`] the principal middleware attached and returns:
//! * **401** for an unauthenticated / anonymous caller (so a client knows to
//!   authenticate), and
//! * **403** for an authenticated non-admin user.
//!
//! Sub-modules:
//! * [`repositories`] — repository CRUD (incl. proxy fields; `upstream_password`
//!   is write-only and REDACTED in responses; `remote_url` is SSRF-validated;
//!   nested-group members and duplicate priorities are rejected) and package
//!   hard-delete (A12).
//! * [`users`] — user CRUD with argon2id password hashing.
//! * [`tokens`] — token issue (plaintext returned **once**, only the hash is
//!   stored) + revoke + list.
//! * [`members`] — group membership management.
//! * [`crypto`] — §12.5 secret-encryption key **metadata** + per-layer rotation
//!   triggers (never returns key bytes or decrypted secrets).
//! * [`settings`] — install-wide switches (`legacy_open_access`).
//!
//! **API tokens and `/admin/*`.** A token is a feed credential, not an admin
//! login: a token-authenticated caller passes [`require_admin`] only when the
//! token's scope lists the `admin` action explicitly (and does not restrict
//! repositories) — e.g. `{"actions": ["admin"]}` for automation. An unscoped
//! token of an admin account gets 403 here (it keeps the owner's
//! read/write/delete reach on the feed).
//!
//! **Passwords and `/admin/*`.** A password sent over HTTP Basic is refused
//! here (403) even for an administrator: NuGet clients store that password
//! and replay it on every feed request, and with credential forwarding it is
//! the upstream directory's password. Administration takes a browser session
//! (sign in through `/auth/login` or OIDC) or an admin-scoped token.

pub mod content_selectors;
pub mod crypto;
pub mod effective;
pub mod grants;
pub mod members;
pub mod realms;
pub mod repositories;
pub mod retention;
pub mod roles;
pub mod settings;
pub mod token_scope;
pub mod tokens;
pub mod user_roles;
pub mod users;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use forge_core::auth::principal::{AuthMethod, Principal};

use crate::middleware::principal_of;
use crate::state::AppState;

/// Middleware: allow only **global admins** past. Non-admins → 403,
/// unauthenticated/anonymous → 401.
///
/// §12.4: admin is now decided by RBAC via [`Authz::is_global_admin`] — a member
/// of the built-in `admin` role (with the slice-1 `app_user.is_admin` column as a
/// dual-read fallback, folded into the effective set). This means a user made
/// admin **only** via the `admin` role (no `is_admin` column) is correctly
/// allowed, and an admin demoted by removing the role is correctly rejected
/// (within the cache TTL / on invalidation). Fail-closed: an evaluation error
/// denies. A 401 (vs 403) distinction is kept for anonymous/unauthenticated so a
/// client knows to authenticate.
///
/// **Tokens (B4).** For a token principal (`token_id: Some`) the verdict is the
/// *token's* effective set, in which `admin` survives only when the token's
/// scope names the `admin` action and does not restrict repositories (see
/// `EffectiveSet::intersect_scope`). An unscoped token of an admin is
/// therefore refused with 403: otherwise a leaked feed token could create
/// admins and mint replacement tokens, surviving its own revocation.
///
/// [`Authz::is_global_admin`]: forge_core::auth::authz::Authz::is_global_admin
pub async fn require_admin(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let principal = principal_of(&req);
    match principal {
        Principal::Anonymous { .. } | Principal::Unauthenticated => {
            return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
        }
        // A password replayed over HTTP Basic is a feed credential, never an
        // admin login (see the module docs).
        Principal::User {
            method: AuthMethod::Password,
            ..
        } => {
            return (
                StatusCode::FORBIDDEN,
                "the admin API needs a signed-in session or an admin-scoped API token; \
                 a password sent over HTTP Basic is not accepted here",
            )
                .into_response();
        }
        // A user or a WIF workload may hold the admin role; the RBAC check below
        // is authoritative.
        Principal::User { .. } | Principal::Workload { .. } => {}
    }
    if state.authz.is_global_admin(&principal).await {
        let method = req.method().clone();
        // The nested router strips `/admin`; log the path as requested.
        let path = req
            .extensions()
            .get::<axum::extract::OriginalUri>()
            .map_or_else(
                || req.uri().path().to_string(),
                |uri| uri.path().to_string(),
            );
        let response = next.run(req).await;
        if !matches!(method, axum::http::Method::GET | axum::http::Method::HEAD) {
            // The administration audit trail: every change (users, roles,
            // grants, realms, repositories, hard deletes, key rotation) with
            // who made it.
            tracing::info!(
                target: "forge::audit",
                %method,
                path,
                status = response.status().as_u16(),
                principal = %principal.audit_label(),
                "admin change"
            );
        }
        response
    } else {
        (StatusCode::FORBIDDEN, "admin privileges required").into_response()
    }
}

/// Build the `/admin` router, gated by the [`require_admin`] middleware.
///
/// Takes the [`AppState`] so the admin gate (`from_fn_with_state`) can call the
/// RBAC [`Authz`](forge_core::auth::authz::Authz) service to decide global-admin
/// membership. Returns a `Router<AppState>`; the caller applies the shared state
/// once when assembling the full app.
pub fn admin_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/repositories",
            get(repositories::list).post(repositories::create),
        )
        .route(
            "/repositories/{name}",
            get(repositories::get)
                .put(repositories::update)
                .delete(repositories::delete),
        )
        .route(
            "/repositories/{name}/packages/{id}/{version}",
            axum::routing::delete(repositories::hard_delete_package),
        )
        .route(
            "/repositories/{name}/retention",
            get(retention::get)
                .put(retention::put)
                .delete(retention::delete),
        )
        .route(
            "/repositories/{name}/retention/preview",
            axum::routing::post(retention::preview),
        )
        .route(
            "/repositories/{name}/retention/run",
            axum::routing::post(retention::run),
        )
        .route(
            "/repositories/{name}/retention/audit",
            get(retention::audit),
        )
        .route(
            "/repositories/{name}/members",
            get(members::list).post(members::add),
        )
        .route(
            "/repositories/{name}/members/{member}",
            axum::routing::patch(members::update).delete(members::remove),
        )
        .route("/users", get(users::list).post(users::create))
        .route(
            "/users/{id}",
            axum::routing::patch(users::update).delete(users::delete),
        )
        .route("/users/{id}/reauth", axum::routing::post(users::reauth))
        .route(
            "/users/{id}/tokens",
            get(tokens::list_for_user).post(tokens::create),
        )
        .route("/tokens/{id}", axum::routing::delete(tokens::revoke))
        // --- §12.4 Phase 6: RBAC management ---------------------------------
        .route("/roles", get(roles::list).post(roles::create))
        .route(
            "/roles/{id}",
            get(roles::get).patch(roles::update).delete(roles::delete),
        )
        .route("/roles/{id}/grants", get(grants::list).put(grants::add))
        .route(
            "/roles/{id}/grants/{grant_id}",
            axum::routing::delete(grants::remove),
        )
        .route(
            "/users/{id}/roles",
            get(user_roles::list).put(user_roles::assign),
        )
        .route(
            "/users/{id}/roles/{role_id}",
            axum::routing::delete(user_roles::unassign),
        )
        .route(
            "/content-selectors",
            get(content_selectors::list).post(content_selectors::create),
        )
        .route(
            "/content-selectors/{id}",
            get(content_selectors::get)
                .patch(content_selectors::update)
                .delete(content_selectors::delete),
        )
        // --- 12.7: auth realm management -------------------------------------
        .route("/realms", get(realms::list).post(realms::create))
        .route("/realms/order", axum::routing::put(realms::reorder))
        .route(
            "/realms/{id}",
            get(realms::get)
                .patch(realms::update)
                .delete(realms::delete),
        )
        .route("/tokens/{id}/scope", axum::routing::patch(token_scope::set))
        .route(
            "/settings/legacy-open-access",
            get(settings::get_legacy_open_access).put(settings::put_legacy_open_access),
        )
        .route("/users/{id}/effective", get(effective::for_user))
        .route("/anonymous/effective", get(effective::for_anonymous))
        // --- §12.5: secret encryption at rest -------------------------------
        .route("/crypto/keys", get(crypto::list_keys))
        .route(
            "/crypto/rotate/{layer}",
            axum::routing::post(crypto::rotate),
        )
        .layer(axum::middleware::from_fn_with_state(state, require_admin))
}

/// Hash a plaintext password with argon2id (PHC string), on a blocking thread.
pub(crate) async fn hash_password(password: String) -> Result<String, Response> {
    use argon2::Argon2;
    use argon2::PasswordHasher;

    let joined = tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| e.to_string())
    })
    .await;

    let hashed: Result<String, String> = match joined {
        Ok(inner) => inner,
        Err(e) => Err(format!("hashing task panicked: {e}")),
    };

    hashed.map_err(|msg| {
        tracing::error!(error = %msg, "password hashing failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    })
}

/// Helper used by handlers to turn a `sqlx::Error` into a 500 response.
pub(crate) fn db_error(e: sqlx::Error) -> Response {
    tracing::error!(error = %e, "admin db error");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/// Deserialize a field that distinguishes *absent* (`None`, through
/// `#[serde(default)]`) from JSON `null` (`Some(None)`) and a value
/// (`Some(Some(v))`).
pub(crate) fn double_option<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(de).map(Some)
}
