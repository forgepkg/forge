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

pub mod content_selectors;
pub mod crypto;
pub mod effective;
pub mod grants;
pub mod members;
pub mod realms;
pub mod repositories;
pub mod retention;
pub mod roles;
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
use forge_core::auth::principal::Principal;

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
        // A user or a WIF workload may hold the admin role; the RBAC check below
        // is authoritative.
        Principal::User { .. } | Principal::Workload { .. } => {}
    }
    if state.authz.is_global_admin(&principal).await {
        next.run(req).await
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
            axum::routing::delete(members::remove),
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
