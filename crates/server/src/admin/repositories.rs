//! Admin repository CRUD + package hard-delete (plan 10.4, A12).
//!
//! `upstream_password` is **write-only**: accepted on create/update, never
//! returned (responses carry a [`RepoView`] with no password field). On update
//! a `null`/absent password leaves the stored secret unchanged; a present value
//! replaces it.
//!
//! `remote_url` on a proxy is **scheme-validated** at create/update time
//! (http/https only — 12.7 §3.6 dropped the private-range restriction) so a bad
//! upstream is rejected before any fetch. The configured host is logged on save
//! for operator visibility (the URL may point at internal addresses).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use forge_core::net::ssrf::validate_url;
use forge_db::model::{RepoKind, Repository, PREFER_HOSTED_KEY};
use forge_db::repository_dao::{self, NewRepository, RepositoryUpdate};
use forge_db::{asset_dao, blob_dao, component_dao};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::db_error;
use crate::state::AppState;

/// Public, password-free view of a repository (REDACTED secrets).
#[derive(Debug, Serialize)]
pub struct RepoView {
    pub id: i64,
    pub name: String,
    pub format: String,
    pub kind: String,
    pub anonymous_read: bool,
    pub online: bool,
    pub remote_url: Option<String>,
    pub package_delay_seconds: i32,
    pub upstream_username: Option<String>,
    /// `true` when an `upstream_password` is stored; the value itself is never
    /// returned.
    pub has_upstream_password: bool,
    pub metadata_ttl_seconds: Option<i32>,
    pub not_found_ttl_seconds: Option<i32>,
    pub allow_redeploy: bool,
    /// Group dependency-confusion guard (see [`Repository::prefer_hosted`]).
    pub prefer_hosted: bool,
}

impl From<&Repository> for RepoView {
    fn from(r: &Repository) -> Self {
        RepoView {
            id: r.id,
            name: r.name.clone(),
            format: r.format.clone(),
            kind: r.kind.clone(),
            anonymous_read: r.anonymous_read,
            online: r.online,
            remote_url: r.remote_url.clone(),
            package_delay_seconds: r.package_delay_seconds,
            upstream_username: r.upstream_username.clone(),
            // §12.5: true for an encrypted blob OR a (pre-backfill) plaintext.
            has_upstream_password: r.has_upstream_password(),
            metadata_ttl_seconds: r.metadata_ttl_seconds,
            not_found_ttl_seconds: r.not_found_ttl_seconds,
            allow_redeploy: r.allow_redeploy,
            prefer_hosted: r.prefer_hosted(),
        }
    }
}

/// Create-repository request body.
#[derive(Debug, Deserialize)]
pub struct CreateRepo {
    pub name: String,
    /// `hosted` | `proxy` | `group`.
    pub kind: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub anonymous_read: bool,
    #[serde(default = "default_true")]
    pub online: bool,
    // Proxy fields:
    #[serde(default)]
    pub remote_url: Option<String>,
    #[serde(default)]
    pub package_delay_seconds: i32,
    #[serde(default)]
    pub upstream_username: Option<String>,
    #[serde(default)]
    pub upstream_password: Option<String>,
    #[serde(default)]
    pub metadata_ttl_seconds: Option<i32>,
    #[serde(default)]
    pub not_found_ttl_seconds: Option<i32>,
    #[serde(default)]
    pub allow_redeploy: bool,
    /// Group only: hide proxy versions of ids a hosted member has (default on).
    #[serde(default)]
    pub prefer_hosted: Option<bool>,
}

/// Update-repository request body. Identity columns (`kind`, `format`) are not
/// updatable. A present `upstream_password` replaces the stored one; an absent
/// one leaves it unchanged.
#[derive(Debug, Deserialize)]
pub struct UpdateRepo {
    pub name: Option<String>,
    pub anonymous_read: Option<bool>,
    pub online: Option<bool>,
    pub remote_url: Option<String>,
    pub package_delay_seconds: Option<i32>,
    pub upstream_username: Option<String>,
    pub upstream_password: Option<String>,
    pub metadata_ttl_seconds: Option<i32>,
    pub not_found_ttl_seconds: Option<i32>,
    pub allow_redeploy: Option<bool>,
    /// Group only.
    pub prefer_hosted: Option<bool>,
}

fn default_format() -> String {
    "nuget".into()
}
fn default_true() -> bool {
    true
}

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

/// Scheme-validate a proxy `remote_url` (http/https only). `None` is OK at this
/// layer (proxy-without-url is rejected separately). Logs the configured host
/// (12.7 §3.6: the URL may legitimately point at internal addresses; the log
/// line gives operators an audit trail of where forge was pointed).
#[allow(clippy::result_large_err)] // the Err is a ready-made axum Response
fn validate_remote_url(url: &str) -> Result<(), Response> {
    validate_url(url).map_err(|e| bad_request(format!("invalid remote_url: {e}")))?;
    if let Ok(parsed) = url::Url::parse(url) {
        // Credentials embedded in the URL would be stored, logged and returned
        // in plaintext; they belong in the write-only upstream_username /
        // upstream_password fields.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(bad_request(
                "remote_url must not embed credentials; use upstream_username / upstream_password",
            ));
        }
        tracing::info!(
            host = parsed.host_str().unwrap_or(""),
            "proxy remote_url configured"
        );
    }
    Ok(())
}

/// `GET /admin/repositories`
pub async fn list(State(state): State<AppState>) -> Response {
    match repository_dao::list_repositories(&state.pool).await {
        Ok(repos) => {
            let views: Vec<RepoView> = repos.iter().map(RepoView::from).collect();
            Json(views).into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `GET /admin/repositories/{name}`
pub async fn get(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => Json(RepoView::from(&r)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// `POST /admin/repositories`
pub async fn create(State(state): State<AppState>, Json(body): Json<CreateRepo>) -> Response {
    let kind = match body.kind.as_str() {
        "hosted" | "proxy" | "group" => body.kind.clone(),
        other => return bad_request(format!("invalid kind {other:?}")),
    };
    let parsed_kind = RepoKind::from(kind.as_str());

    // Proxy must carry a remote_url; SSRF-validate it. Non-proxies must not.
    if parsed_kind == RepoKind::Proxy {
        let Some(url) = body.remote_url.as_deref() else {
            return bad_request("proxy repository requires remote_url");
        };
        if let Err(resp) = validate_remote_url(url) {
            return resp;
        }
    } else if body.remote_url.is_some() {
        return bad_request("remote_url is only valid for proxy repositories");
    }
    if body.prefer_hosted.is_some() && parsed_kind != RepoKind::Group {
        return bad_request("prefer_hosted is only valid for group repositories");
    }
    let mut config = json!({});
    if parsed_kind == RepoKind::Group {
        config[PREFER_HOSTED_KEY] = json!(body.prefer_hosted.unwrap_or(true));
    }

    // §12.5: with encryption enabled the password is NOT inserted as plaintext;
    // the row is created first (the AAD binds the ciphertext to the row id,
    // which does not exist before the INSERT) and the secret is sealed below.
    let encrypting = state.envelope.is_some();
    let new = NewRepository {
        name: body.name.clone(),
        format: body.format.clone(),
        kind: kind.clone(),
        anonymous_read: body.anonymous_read,
        online: body.online,
        config,
        remote_url: body.remote_url.clone(),
        package_delay_seconds: body.package_delay_seconds,
        upstream_username: body.upstream_username.clone(),
        upstream_password: if encrypting {
            None
        } else {
            body.upstream_password.clone()
        },
        metadata_ttl_seconds: body.metadata_ttl_seconds,
        not_found_ttl_seconds: body.not_found_ttl_seconds,
        allow_redeploy: body.allow_redeploy,
    };

    let repo = match repository_dao::insert_repository(&state.pool, new).await {
        Ok(r) => r,
        Err(e) if is_unique_violation(&e) => {
            return (StatusCode::CONFLICT, "repository name already exists").into_response()
        }
        Err(e) => return db_error(e),
    };

    match (&state.envelope, &body.upstream_password) {
        (Some(envelope), Some(pw)) => {
            if let Err(resp) = store_encrypted_password(&state, envelope, repo.id, pw.clone()).await
            {
                return resp;
            }
            // Re-fetch so the view reflects the sealed secret.
            match repository_dao::find_repository_by_id(&state.pool, repo.id).await {
                Ok(Some(r)) => (StatusCode::CREATED, Json(RepoView::from(&r))).into_response(),
                Ok(None) => db_error(sqlx::Error::RowNotFound),
                Err(e) => db_error(e),
            }
        }
        _ => (StatusCode::CREATED, Json(RepoView::from(&repo))).into_response(),
    }
}

/// Seal `password` under the active DEK and store it on `repo_id`
/// (`secret_dao::set_upstream_password`); map failures to a 500 response. The
/// error string carries no key material or plaintext by construction.
async fn store_encrypted_password(
    state: &AppState,
    envelope: &forge_crypto::service::EnvelopeService,
    repo_id: i64,
    password: String,
) -> Result<(), Response> {
    let secret = forge_crypto::PlaintextSecret::from(password);
    forge_db::secret_dao::set_upstream_password(&state.pool, envelope, repo_id, Some(&secret))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, repo_id, "failed to store encrypted upstream password");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to store encrypted upstream password",
            )
                .into_response()
        })
}

/// `PUT /admin/repositories/{name}`
pub async fn update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<UpdateRepo>,
) -> Response {
    let existing = match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => return db_error(e),
    };

    // Merge: each absent field keeps the existing value. `upstream_password`
    // absent ⇒ keep stored secret; present ⇒ replace.
    let remote_url = match &body.remote_url {
        Some(u) => Some(u.clone()),
        None => existing.remote_url.clone(),
    };

    // Re-validate the remote_url for proxies whenever it changed.
    if existing.kind() == RepoKind::Proxy {
        if let Some(url) = remote_url.as_deref() {
            if body.remote_url.is_some() {
                if let Err(resp) = validate_remote_url(url) {
                    return resp;
                }
            }
        }
    }

    let mut config = existing.config.clone();
    if let Some(prefer_hosted) = body.prefer_hosted {
        if existing.kind() != RepoKind::Group {
            return bad_request("prefer_hosted is only valid for group repositories");
        }
        if !config.is_object() {
            config = json!({});
        }
        config[PREFER_HOSTED_KEY] = json!(prefer_hosted);
    }

    let upd = RepositoryUpdate {
        name: body.name.clone().unwrap_or(existing.name.clone()),
        anonymous_read: body.anonymous_read.unwrap_or(existing.anonymous_read),
        online: body.online.unwrap_or(existing.online),
        config,
        remote_url,
        package_delay_seconds: body
            .package_delay_seconds
            .unwrap_or(existing.package_delay_seconds),
        upstream_username: match &body.upstream_username {
            Some(u) => Some(u.clone()),
            None => existing.upstream_username.clone(),
        },
        // §12.5: with encryption enabled the plaintext column is only ever
        // carried through unchanged (preserving a not-yet-backfilled value); a
        // *new* password is sealed via secret_dao below, never stored here.
        upstream_password: if state.envelope.is_some() {
            existing.upstream_password.clone()
        } else {
            match &body.upstream_password {
                Some(p) => Some(p.clone()),
                None => existing.upstream_password.clone(),
            }
        },
        metadata_ttl_seconds: body.metadata_ttl_seconds.or(existing.metadata_ttl_seconds),
        not_found_ttl_seconds: body
            .not_found_ttl_seconds
            .or(existing.not_found_ttl_seconds),
        allow_redeploy: body.allow_redeploy.unwrap_or(existing.allow_redeploy),
    };

    let updated = match repository_dao::update_repository(&state.pool, existing.id, upd).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) if is_unique_violation(&e) => {
            return (StatusCode::CONFLICT, "repository name already exists").into_response()
        }
        Err(e) => return db_error(e),
    };

    // §12.5: a present password replaces the stored secret through the
    // envelope (clearing any legacy plaintext for this row); absent keeps it.
    match (&state.envelope, &body.upstream_password) {
        (Some(envelope), Some(pw)) => {
            if let Err(resp) =
                store_encrypted_password(&state, envelope, updated.id, pw.clone()).await
            {
                return resp;
            }
            match repository_dao::find_repository_by_id(&state.pool, updated.id).await {
                Ok(Some(r)) => Json(RepoView::from(&r)).into_response(),
                Ok(None) => db_error(sqlx::Error::RowNotFound),
                Err(e) => db_error(e),
            }
        }
        _ => Json(RepoView::from(&updated)).into_response(),
    }
}

/// `DELETE /admin/repositories/{name}`
///
/// A raw cascade would drop a repository's `component`/`asset` rows via FK while
/// leaving the referenced `blob` ref-counts inflated and their S3 objects
/// unreclaimable. Both hosted *and* proxy repositories accumulate
/// component/asset/blob rows (a proxy persists them when it caches a package
/// downloaded from upstream — see `forge_core::repo::proxy`), so the blob
/// ref-counts must be decremented before the repository is removed regardless of
/// kind.
///
/// - **Hosted** repos refuse deletion while they still own components — the
///   admin must hard-delete its packages first (an explicit, auditable step,
///   since hosted content is uploaded and not reproducible).
/// - **Proxy** repos hold only a reconstructible upstream cache, so deletion
///   transactionally decrefs every referenced blob (enqueuing outbox deletes at
///   zero refs) and removes the components before dropping the repository.
pub async fn delete(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let existing = match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => return db_error(e),
    };

    // Hosted repos may still own (non-reproducible) components; require them
    // gone first so the deletion is an explicit admin action.
    if existing.kind() == RepoKind::Hosted {
        match component_dao::list_components_for_repo(&state.pool, existing.id).await {
            Ok(comps) if !comps.is_empty() => {
                return (
                    StatusCode::CONFLICT,
                    "repository still has packages; hard-delete them first",
                )
                    .into_response();
            }
            Ok(_) => {}
            Err(e) => return db_error(e),
        }
    } else {
        // Proxy (and any non-hosted) repos: decref every blob referenced by the
        // repo's cached components so blob GC stays correct, then the cascade
        // can safely drop the now-zero-ref component/asset rows.
        let grace = state.config.outbox.grace();
        if let Err(e) = purge_repo_blob_refs(&state, existing.id, grace).await {
            return db_error(e);
        }
    }

    match repository_dao::delete_repository(&state.pool, existing.id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// Transactionally decrement the ref-count of every blob referenced by any asset
/// of any component in `repo_id`, enqueuing an outbox delete when a blob reaches
/// zero refs, then delete the components (assets cascade via FK). Mirrors the
/// per-package [`hard_delete`] path so blob GC stays correct when a whole
/// repository is removed.
async fn purge_repo_blob_refs(
    state: &AppState,
    repo_id: i64,
    grace: chrono::Duration,
) -> sqlx::Result<()> {
    let components = component_dao::list_components_for_repo(&state.pool, repo_id).await?;
    if components.is_empty() {
        return Ok(());
    }

    let mut tx = state.pool.begin().await?;
    for comp in &components {
        let assets = asset_dao::assets_for_component(&mut *tx, comp.id).await?;
        for asset in &assets {
            blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &asset.blob_sha256, grace).await?;
        }
        component_dao::delete_component(&mut *tx, repo_id, &comp.name, &comp.version).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// `DELETE /admin/repositories/{name}/packages/{id}/{version}` — **hard delete**
/// (A12): remove the component + its assets and decrement the referenced blobs'
/// ref-counts (enqueuing outbox deletes at zero) in one transaction.
pub async fn hard_delete_package(
    State(state): State<AppState>,
    Path((name, id, version)): Path<(String, String, String)>,
) -> Response {
    let repo = match repository_dao::find_repository_by_name(&state.pool, &name).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Err(e) => return db_error(e),
    };
    if repo.kind() != RepoKind::Hosted {
        return (
            StatusCode::BAD_REQUEST,
            "hard delete is only supported for hosted repositories",
        )
            .into_response();
    }

    let format = state.formats.for_repository(&repo);
    let lower = format.lower_id(&id);
    let norm_ver = match format.normalize_version(&version) {
        Ok(v) => v,
        Err(_) => return (StatusCode::NOT_FOUND, "package not found").into_response(),
    };

    let grace = state.config.outbox.grace();
    match hard_delete(&state, repo.id, &lower, &norm_ver, grace).await {
        Ok(true) => {
            state
                .cache
                .invalidate(crate::state::NS_PACKAGE, &format!("{}/{lower}", repo.name))
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "package not found").into_response(),
        Err(e) => db_error(e),
    }
}

/// Transactionally remove a component, its assets, and decref each referenced
/// blob (enqueuing an outbox delete when a blob reaches zero refs). Mirrors the
/// hosted write path's hard-delete so blob GC stays correct.
async fn hard_delete(
    state: &AppState,
    repo_id: i64,
    lower_id: &str,
    version: &str,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let mut tx = state.pool.begin().await?;

    let Some(comp) = component_dao::find_component(&mut *tx, repo_id, lower_id, version).await?
    else {
        return Ok(false);
    };

    // Decref every blob this component's assets reference.
    let assets = asset_dao::assets_for_component(&mut *tx, comp.id).await?;
    for asset in &assets {
        blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &asset.blob_sha256, grace).await?;
    }

    // Remove the component (assets cascade via FK).
    component_dao::delete_component(&mut *tx, repo_id, lower_id, version).await?;

    tx.commit().await?;
    Ok(true)
}

/// Whether a `sqlx::Error` is a Postgres unique-violation (23505).
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}
