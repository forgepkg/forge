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

pub mod members;
pub mod repositories;
pub mod tokens;
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

/// Middleware: allow only authenticated admins past. Non-admins → 403,
/// unauthenticated/anonymous → 401.
pub async fn require_admin(req: Request, next: Next) -> Response {
    match principal_of(&req) {
        Principal::User { is_admin: true, .. } => next.run(req).await,
        Principal::User {
            is_admin: false, ..
        } => (StatusCode::FORBIDDEN, "admin privileges required").into_response(),
        Principal::Anonymous { .. } | Principal::Unauthenticated => {
            (StatusCode::UNAUTHORIZED, "authentication required").into_response()
        }
    }
}

/// Build the `/admin` router (caller mounts it and wraps it with the principal
/// middleware + this module's [`require_admin`] gate).
///
/// Returns a `Router<AppState>` so the caller applies the shared state once when
/// assembling the full app.
pub fn admin_router() -> Router<AppState> {
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
            "/repositories/{name}/members",
            get(members::list).post(members::add),
        )
        .route(
            "/repositories/{name}/members/{member}",
            axum::routing::delete(members::remove),
        )
        .route("/users", get(users::list).post(users::create))
        .route("/users/{id}", axum::routing::delete(users::delete))
        .route(
            "/users/{id}/tokens",
            get(tokens::list_for_user).post(tokens::create),
        )
        .route("/tokens/{id}", axum::routing::delete(tokens::revoke))
        .layer(axum::middleware::from_fn(require_admin))
}

/// Hash a plaintext password with argon2id (PHC string), on a blocking thread.
pub(crate) async fn hash_password(password: String) -> Result<String, Response> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;

    let joined = tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
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
