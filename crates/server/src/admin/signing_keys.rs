//! The OpenPGP keys that sign a repository's indexes (a hosted repository of
//! a format that keeps signed indexes: apt).
//!
//! * `GET /admin/repositories/{name}/signing-keys` — the keys, oldest first,
//!   each with its fingerprint, algorithm, user id and ASCII-armored public
//!   key ([`KeyView`]). A repository without one gets one first.
//! * `POST /admin/repositories/{name}/signing-keys` — add a key: `{}` (or
//!   `{"generate": true}`) generates an Ed25519 key, `{"secret_key":
//!   "<ASCII-armored secret key>", "passphrase": "…"}` imports one (its
//!   passphrase is removed: the key is kept sealed by the secret encryption,
//!   and never returned). 201 with the new key; 409 when the repository has
//!   it already.
//! * `DELETE /admin/repositories/{name}/signing-keys/{fingerprint}` — remove
//!   a key; 409 for a repository's last key.
//!
//! Every key of a repository signs its indexes, so a rotation is: add the
//! new key, let clients trust it (its public key is in the repository's
//! `key.asc` with the old one), then delete the old key.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_db::model::Repository;
use forge_db::{repository_dao, signing_key_dao};
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::indexes::{self, signing::Key};
use crate::state::AppState;

/// What is shown of a key; its secret never is.
#[derive(Debug, Serialize)]
pub struct KeyView {
    pub fingerprint: String,
    pub algorithm: String,
    pub user_id: String,
    pub public_key: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<signing_key_dao::SigningKeyRow> for KeyView {
    fn from(row: signing_key_dao::SigningKeyRow) -> Self {
        KeyView {
            fingerprint: row.fingerprint,
            algorithm: row.algorithm,
            user_id: row.user_id,
            public_key: row.public_key,
            created_at: row.created_at,
        }
    }
}

/// Body of `POST …/signing-keys`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddKey {
    /// Generate a key (the default when no `secret_key` is given).
    #[serde(default)]
    pub generate: Option<bool>,
    /// An ASCII-armored OpenPGP secret key to import.
    #[serde(default)]
    pub secret_key: Option<String>,
    /// The imported key's passphrase, if it has one.
    #[serde(default)]
    pub passphrase: Option<String>,
}

fn problem(status: StatusCode, message: impl Into<String>) -> Response {
    (status, message.into()).into_response()
}

fn index_error(e: indexes::IndexError) -> Response {
    match e {
        indexes::IndexError::Unavailable(m) => problem(StatusCode::SERVICE_UNAVAILABLE, m),
        indexes::IndexError::Internal(m) => {
            tracing::error!(error = %m, "signing keys failed");
            problem(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// The repository `name`, if it keeps signed indexes.
async fn repository(state: &AppState, name: &str) -> Result<Repository, Response> {
    match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(repo)) if indexes::keeps_indexes(state, &repo) => Ok(repo),
        Ok(Some(_)) => Err(problem(
            StatusCode::BAD_REQUEST,
            "only a hosted repository of a format with signed indexes (apt) has signing keys",
        )),
        Ok(None) => Err(problem(StatusCode::NOT_FOUND, "repository not found")),
        Err(e) => Err(db_error(e)),
    }
}

/// `GET /admin/repositories/{name}/signing-keys`
pub async fn list(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let repo = match repository(&state, &name).await {
        Ok(repo) => repo,
        Err(resp) => return resp,
    };
    match indexes::keys(&state, &repo).await {
        Ok(keys) => Json(keys.into_iter().map(KeyView::from).collect::<Vec<_>>()).into_response(),
        Err(e) => index_error(e),
    }
}

/// `POST /admin/repositories/{name}/signing-keys`
pub async fn add(
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Option<Json<AddKey>>,
) -> Response {
    let repo = match repository(&state, &name).await {
        Ok(repo) => repo,
        Err(resp) => return resp,
    };
    let body = body.map(|b| b.0).unwrap_or_default();
    let added = match (body.secret_key, body.generate) {
        (Some(_), Some(true)) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "either generate a key or import secret_key, not both",
            )
        }
        (Some(armored), _) => {
            let passphrase = body.passphrase;
            let imported =
                tokio::task::spawn_blocking(move || Key::import(&armored, passphrase.as_deref()))
                    .await;
            let key = match imported {
                Ok(Ok(key)) => key,
                Ok(Err(e)) => return problem(StatusCode::BAD_REQUEST, e.to_string()),
                Err(e) => return index_error(indexes::IndexError::Internal(e.to_string())),
            };
            match indexes::add_key(&state, &repo, &key).await {
                Ok(Some(info)) => info.fingerprint,
                Ok(None) => {
                    return problem(StatusCode::CONFLICT, "the repository has this key already")
                }
                Err(e) => return index_error(e),
            }
        }
        (None, Some(false)) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "give secret_key to import a key, or generate one",
            )
        }
        (None, _) => match indexes::generate_key(&state, &repo).await {
            Ok(info) => info.fingerprint,
            Err(e) => return index_error(e),
        },
    };
    tracing::info!(target: "forge::audit", repo = %repo.name, fingerprint = %added, "signing key added");
    match signing_key_dao::list(&state.pool, repo.id).await {
        Ok(keys) => match keys.into_iter().find(|k| k.fingerprint == added) {
            Some(key) => (StatusCode::CREATED, Json(KeyView::from(key))).into_response(),
            None => problem(StatusCode::CONFLICT, "the key was removed meanwhile"),
        },
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/repositories/{name}/signing-keys/{fingerprint}`
pub async fn delete(
    State(state): State<AppState>,
    Path((name, fingerprint)): Path<(String, String)>,
) -> Response {
    let repo = match repository(&state, &name).await {
        Ok(repo) => repo,
        Err(resp) => return resp,
    };
    let fingerprint = fingerprint.to_ascii_uppercase();
    match signing_key_dao::delete(&state.pool, repo.id, &fingerprint).await {
        Ok(Some(true)) => {
            tracing::info!(target: "forge::audit", repo = %repo.name, %fingerprint, "signing key deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Some(false)) => problem(
            StatusCode::CONFLICT,
            "a repository keeps at least one signing key: add the new key before deleting the last",
        ),
        Ok(None) => problem(StatusCode::NOT_FOUND, "no such key"),
        Err(e) => db_error(e),
    }
}
