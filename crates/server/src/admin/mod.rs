//! Admin REST API. **Admin-only.**
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
//!   duplicate member priorities are rejected, nested groups only when they
//!   would form a cycle or exceed the depth limit) and package hard-delete.
//! * [`users`] — user CRUD with argon2id password hashing.
//! * [`tokens`] — token issue (plaintext returned **once**, only the hash is
//!   stored) + revoke + list.
//! * [`members`] — group membership management.
//! * [`crypto`] — secret-encryption key **metadata** + per-layer rotation
//!   triggers (never returns key bytes or decrypted secrets).
//! * [`blob_cache`] — the local blob cache's statistics.
//! * [`proxy_cache`] — invalidating what a proxy repository cached from its
//!   upstream (its "not found" answers, listings and documents).
//! * [`imports`] — importing a Nexus hosted repository into a hosted
//!   repository (start with a preflight, progress, cancel, resume, retry).
//! * [`settings`] — the sign-in and anonymous-access policy (anonymous mode,
//!   login mode, password Basic, session lifetimes, lockout).
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

pub mod blob_cache;
pub mod content_selectors;
pub mod crypto;
pub mod effective;
pub mod formats;
pub mod grants;
pub mod imports;
pub mod members;
pub mod proxy_cache;
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
/// Admin is decided by RBAC via [`Authz::is_global_admin`] — a member of the
/// built-in `admin` role. An admin demoted by removing the role is rejected
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
        .route("/formats", get(formats::list))
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
            "/repositories/{name}/files",
            axum::routing::delete(crate::raw::web::admin_delete),
        )
        .route(
            "/repositories/{name}/proxy-cache/invalidate",
            axum::routing::post(proxy_cache::invalidate),
        )
        .route(
            "/repositories/{name}/imports",
            get(imports::list).post(imports::create),
        )
        .route(
            "/repositories/{name}/imports/{id}",
            get(imports::get).delete(imports::delete),
        )
        .route(
            "/repositories/{name}/imports/{id}/items",
            get(imports::items),
        )
        .route(
            "/repositories/{name}/imports/{id}/cancel",
            axum::routing::post(imports::cancel),
        )
        .route(
            "/repositories/{name}/imports/{id}/resume",
            axum::routing::post(imports::resume),
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
            "/users/{id}/convert-to-local",
            axum::routing::post(users::convert_to_local),
        )
        .route(
            "/users/{id}/tokens",
            get(tokens::list_for_user).post(tokens::create),
        )
        .route("/tokens/{id}", axum::routing::delete(tokens::revoke))
        // --- RBAC management -----------------------------------------------
        .route("/roles", get(roles::list).post(roles::create))
        .route(
            "/roles/{id}",
            get(roles::get).patch(roles::update).delete(roles::delete),
        )
        .route("/roles/{id}/users", get(roles::users))
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
            "/content-selectors/match",
            axum::routing::post(content_selectors::test_match),
        )
        .route(
            "/content-selectors/{id}",
            get(content_selectors::get)
                .patch(content_selectors::update)
                .delete(content_selectors::delete),
        )
        .route(
            "/content-selectors/{id}/grants",
            get(content_selectors::grants),
        )
        // --- auth realm management -----------------------------------------
        .route("/realms", get(realms::list).post(realms::create))
        .route("/realms/order", axum::routing::put(realms::reorder))
        .route(
            "/realms/{id}",
            get(realms::get)
                .patch(realms::update)
                .delete(realms::delete),
        )
        .route(
            "/realms/{id}/captured-passwords",
            get(realms::captured_passwords),
        )
        .route(
            "/realms/{id}/convert-to-local",
            axum::routing::post(realms::convert_to_local),
        )
        // --- sign-in and anonymous-access policy (#294) -----------------------
        .route(
            "/settings/auth",
            get(settings::get_auth).put(settings::put_auth),
        )
        .route("/tokens/{id}/scope", axum::routing::patch(token_scope::set))
        .route("/users/{id}/effective", get(effective::for_user))
        .route("/anonymous/effective", get(effective::for_anonymous))
        // --- secret encryption at rest -------------------------------------
        .route("/crypto/keys", get(crypto::list_keys))
        // --- local blob cache ----------------------------------------------
        .route("/blob-cache", get(blob_cache::stats))
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

/// The **503** answer for a repository whose format is not installed (a
/// format plugin missing from the configuration): it cannot be read or
/// changed until the format is back.
pub(crate) fn format_unavailable(e: forge_core::repo::RepoError) -> Response {
    tracing::warn!(error = %e, "repository format unavailable");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "the repository's format is not installed on this server",
    )
        .into_response()
}

/// The **409** answer to a change refused by the last-admin guard
/// ([`forge_db::authz_dao::would_leave_no_admin`]): deactivating, deleting or
/// unassigning the `admin` role of the last active administrator. Without it
/// the install would need direct SQL to get an administrator back: a deleted
/// bootstrap admin is never re-created.
pub(crate) fn last_admin_conflict() -> Response {
    (
        StatusCode::CONFLICT,
        "this would leave no active administrator; make another user an admin first",
    )
        .into_response()
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
