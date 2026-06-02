//! Admin user CRUD (plan 10.4). Passwords are hashed with argon2id; the hash is
//! never returned.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
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
    match user_dao::insert_user(&state.pool, new).await {
        Ok(u) => (StatusCode::CREATED, Json(UserView::from(&u))).into_response(),
        Err(e) if is_unique_violation(&e) => {
            (StatusCode::CONFLICT, "username already exists").into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/users/{id}`
pub async fn delete(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match user_dao::delete_user(&state.pool, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => db_error(e),
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}
