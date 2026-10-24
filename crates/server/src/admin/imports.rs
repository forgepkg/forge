//! Imports from Nexus into a hosted repository ([`crate::nexus_import`]).
//! **Admin-only.**
//!
//! * `GET    /admin/repositories/{name}/imports` — the repository's imports,
//!   newest first ([`ImportView`]).
//! * `POST   /admin/repositories/{name}/imports` — start one
//!   ([`CreateImport`]). The source is checked first (the **preflight**):
//!   Nexus answers its status endpoint, the Nexus repository exists, is
//!   hosted and of the repository's format, and, for Docker, its registry
//!   API answers. A failed check is a 400 (502 when Nexus is unreachable)
//!   saying what is wrong; nothing is stored. A repository runs one import
//!   at a time (409). `dry_run` decides every item without writing a
//!   package: what would be copied, how much, and the conflicts.
//! * `GET    …/imports/{id}` — one import and its progress.
//! * `GET    …/imports/{id}/items?state=&after=&limit=` — its items in the
//!   order they were found ([`forge_db::import_dao::ImportItem`]), paged
//!   by item id.
//! * `POST   …/imports/{id}/cancel` — cancel: a queued import at once, a
//!   running one after the items in flight. It keeps its cursor and
//!   password and can be resumed.
//! * `POST   …/imports/{id}/resume` — queue a stopped import again
//!   ([`ResumeImport`]): a cancelled or failed one continues where it
//!   stopped; `retry_failed` (or `items`) puts its failed items back. A
//!   completed import's password was deleted: retrying its failed items
//!   needs the password again.
//! * `DELETE …/imports/{id}` — delete a stopped import, its items and its
//!   password.
//!
//! The password is write-only: views say only whether one is stored. It is
//! sealed with the secret encryption (`[crypto]`; without it, stored like
//! proxy passwords) and deleted when the import completes.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::Extension;
use chrono::{DateTime, Utc};
use forge_core::auth::principal::Principal;
use forge_core::net::ssrf::validate_url;
use forge_db::import_dao::{self, NewImport, NexusImport};
use forge_db::model::{RepoKind, Repository};
use forge_db::{repository_dao, secret_dao};
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::nexus_import::nexus::{Nexus, NexusError};
use crate::nexus_import::{default_registry_url, password_secret, FORMATS};
use crate::state::AppState;

/// Imports listed per repository.
const LIST_LIMIT: i64 = 50;

/// Default and cap of an item page.
const ITEMS_DEFAULT_LIMIT: i64 = 100;
const ITEMS_MAX_LIMIT: i64 = 1000;

/// Item states a listing may filter by.
const ITEM_STATES: &[&str] = &[
    "pending",
    "imported",
    "replaced",
    "identical",
    "conflict",
    "failed",
    "planned",
];

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

fn conflict(msg: impl Into<String>) -> Response {
    (StatusCode::CONFLICT, msg.into()).into_response()
}

fn not_found(what: &str) -> Response {
    (StatusCode::NOT_FOUND, format!("{what} not found")).into_response()
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

/// `POST /admin/repositories/{name}/imports`. Unknown fields are refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateImport {
    /// The Nexus server, e.g. `https://nexus.example.com` (with its context
    /// path, if it has one).
    pub url: String,
    /// The Nexus hosted repository to copy.
    pub repository: String,
    /// Nexus credentials (both, or neither for anonymous access).
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Docker: the Nexus repository's registry API, e.g. its connector
    /// `http://nexus.example.com:8082`. Default: `<url>/repository/<name>`.
    #[serde(default)]
    pub registry_url: Option<String>,
    /// A version Forge holds with other bytes: `skip` (and report),
    /// `overwrite`, or `fail` the import.
    #[serde(default = "default_on_conflict")]
    pub on_conflict: String,
    /// Items copied at a time (1–16).
    #[serde(default = "default_concurrency")]
    pub concurrency: i32,
    /// Decide every item without writing a package.
    #[serde(default)]
    pub dry_run: bool,
}

fn default_on_conflict() -> String {
    "skip".into()
}

fn default_concurrency() -> i32 {
    4
}

/// `POST …/imports/{id}/resume`; every field optional.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeImport {
    /// The Nexus password, when the import no longer holds it (it
    /// completed) or it changed.
    #[serde(default)]
    pub password: Option<String>,
    /// Put every failed item back to pending.
    #[serde(default)]
    pub retry_failed: bool,
    /// Put these failed items back to pending (implies a retry).
    #[serde(default)]
    pub items: Option<Vec<i64>>,
}

/// `GET …/imports/{id}/items` query.
#[derive(Debug, Deserialize)]
pub struct ItemsQuery {
    pub state: Option<String>,
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

/// An import's progress, from its items.
#[derive(Debug, Default, Serialize)]
pub struct Progress {
    /// Items the scan found so far.
    pub found: i64,
    pub pending: i64,
    pub imported: i64,
    pub replaced: i64,
    pub identical: i64,
    pub conflict: i64,
    pub failed: i64,
    /// Dry run: items that would be copied.
    pub planned: i64,
    /// Their size in Nexus.
    pub planned_size: i64,
    /// Bytes downloaded from Nexus.
    pub bytes_copied: i64,
    /// Every asset the scan saw in the Nexus repository, and their size.
    pub assets: i64,
    pub size: i64,
}

/// An import, without its password.
#[derive(Debug, Serialize)]
pub struct ImportView {
    pub id: i64,
    pub repository: String,
    /// The Nexus server and repository.
    pub url: String,
    pub source_repository: String,
    pub registry_url: Option<String>,
    pub username: Option<String>,
    pub has_password: bool,
    pub on_conflict: String,
    pub concurrency: i32,
    pub dry_run: bool,
    /// `queued`, `running`, `cancelled`, `failed` or `completed`.
    pub state: String,
    /// `scan` or `copy`.
    pub phase: String,
    pub cancel_requested: bool,
    pub nexus_version: Option<String>,
    pub last_error: Option<String>,
    pub created_by: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub progress: Progress,
}

async fn view(
    state: &AppState,
    repo: &Repository,
    import: NexusImport,
) -> sqlx::Result<ImportView> {
    let counts = import_dao::counts(&state.pool, import.id).await?;
    let count = |s: &str| counts.get(s).map(|c| c.items).unwrap_or(0);
    let progress = Progress {
        found: counts.values().map(|c| c.items).sum(),
        pending: count("pending"),
        imported: count("imported"),
        replaced: count("replaced"),
        identical: count("identical"),
        conflict: count("conflict"),
        failed: count("failed"),
        planned: count("planned"),
        planned_size: counts.get("planned").map(|c| c.size).unwrap_or(0),
        bytes_copied: counts.values().map(|c| c.bytes_copied).sum(),
        assets: import.assets_seen,
        size: import.bytes_seen,
    };
    Ok(ImportView {
        id: import.id,
        repository: repo.name.clone(),
        url: import.base_url,
        source_repository: import.source_repository,
        registry_url: import.registry_url,
        username: import.username,
        has_password: import.has_password,
        on_conflict: import.on_conflict,
        concurrency: import.concurrency,
        dry_run: import.dry_run,
        state: import.state,
        phase: import.phase,
        cancel_requested: import.cancel_requested,
        nexus_version: import.nexus_version,
        last_error: import.last_error,
        created_by: import.created_by,
        created_at: import.created_at,
        started_at: import.started_at,
        finished_at: import.finished_at,
        updated_at: import.updated_at,
        progress,
    })
}

async fn view_response(state: &AppState, repo: &Repository, import: NexusImport) -> Response {
    match view(state, repo, import).await {
        Ok(view) => Json(view).into_response(),
        Err(e) => db_error(e),
    }
}

async fn resolve_repo(state: &AppState, name: &str) -> Result<Repository, Response> {
    match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(repo)) => Ok(repo),
        Ok(None) => Err(not_found("repository")),
        Err(e) => Err(db_error(e)),
    }
}

/// The repository and its import `id`.
async fn resolve(
    state: &AppState,
    name: &str,
    id: i64,
) -> Result<(Repository, NexusImport), Response> {
    let repo = resolve_repo(state, name).await?;
    match import_dao::get(&state.pool, id).await {
        Ok(Some(import)) if import.repository_id == repo.id => Ok((repo, import)),
        Ok(_) => Err(not_found("import")),
        Err(e) => Err(db_error(e)),
    }
}

/// A preflight failure as the administrator sees it.
fn preflight_error(what: &str, e: NexusError) -> Response {
    let status = match e {
        NexusError::Unreachable(_) => StatusCode::BAD_GATEWAY,
        NexusError::Status { status, .. } if status.is_server_error() => StatusCode::BAD_GATEWAY,
        _ => StatusCode::BAD_REQUEST,
    };
    (status, format!("{what}: {e}")).into_response()
}

/// `GET /admin/repositories/{name}/imports`
pub async fn list(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let repo = match resolve_repo(&state, &name).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let imports = match import_dao::list(&state.pool, repo.id, LIST_LIMIT).await {
        Ok(imports) => imports,
        Err(e) => return db_error(e),
    };
    let mut views = Vec::with_capacity(imports.len());
    for import in imports {
        match view(&state, &repo, import).await {
            Ok(view) => views.push(view),
            Err(e) => return db_error(e),
        }
    }
    Json(views).into_response()
}

/// `POST /admin/repositories/{name}/imports`
pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(name): Path<String>,
    Json(body): Json<CreateImport>,
) -> Response {
    let repo = match resolve_repo(&state, &name).await {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let Principal::User { user_id, .. } = principal else {
        return (
            StatusCode::FORBIDDEN,
            "an import runs as the administrator who starts it; sign in, or use an admin-scoped token",
        )
            .into_response();
    };
    if repo.kind() != RepoKind::Hosted {
        return bad_request(
            "imports go to a hosted repository; a proxy refills from its upstream, and a group is configuration",
        );
    }
    if !FORMATS.contains(&repo.format.as_str()) {
        return bad_request(format!(
            "importing {} repositories from Nexus is not supported; supported: {}",
            repo.format,
            FORMATS.join(", ")
        ));
    }

    // The request itself.
    let url = body.url.trim().trim_end_matches('/').to_string();
    if let Err(e) = validate_url(&url) {
        return bad_request(format!("invalid url: {e}"));
    }
    let source_repository = body.repository.trim().to_string();
    if source_repository.is_empty() || source_repository.contains('/') {
        return bad_request("repository must name one Nexus repository");
    }
    let username = body.username.filter(|u| !u.is_empty());
    let password = password_secret(body.password);
    if username.is_some() != password.is_some() {
        return bad_request("give both a username and a password, or neither");
    }
    if !matches!(body.on_conflict.as_str(), "skip" | "overwrite" | "fail") {
        return bad_request("on_conflict must be skip, overwrite or fail");
    }
    if !(1..=16).contains(&body.concurrency) {
        return bad_request("concurrency must be between 1 and 16");
    }
    let images = state.formats.stores_images(&repo.format);
    let registry_url = match body
        .registry_url
        .map(|u| u.trim().trim_end_matches('/').to_string())
    {
        Some(_) if !images => {
            return bad_request("registry_url applies to Docker repositories only")
        }
        Some(u) if u.is_empty() => None,
        Some(u) => match validate_url(&u) {
            Ok(()) => Some(u),
            Err(e) => return bad_request(format!("invalid registry_url: {e}")),
        },
        None => None,
    };

    // The preflight: is it Nexus, and the right repository?
    let nexus = Nexus::new(
        state.upstream.clone(),
        &url,
        username.clone(),
        password.clone(),
    );
    let version = match nexus.status().await {
        Ok(version) => version,
        Err(e) => return preflight_error(&format!("Nexus at {url}"), e),
    };
    match nexus.repository(&source_repository).await {
        Ok(Some(source)) => {
            if source.kind != "hosted" {
                return bad_request(format!(
                    "{source_repository} is a {} repository in Nexus; only hosted repositories are imported (a proxy refills from its upstream, a group is configuration)",
                    source.kind
                ));
            }
            if source.format != repo.format {
                return bad_request(format!(
                    "{source_repository} is a {} repository in Nexus, but {} holds {}",
                    source.format, repo.name, repo.format
                ));
            }
        }
        Ok(None) => {
            return bad_request(format!(
                "Nexus has no repository {source_repository}, or the credentials may not see it"
            ));
        }
        Err(e) => return preflight_error("listing the Nexus repositories", e),
    }
    if images {
        let registry = registry_url
            .clone()
            .unwrap_or_else(|| default_registry_url(&url, &source_repository));
        let probe = Nexus::new(
            state.upstream.clone(),
            &registry,
            username.clone(),
            password.clone(),
        );
        if let Err(e) = probe.probe_registry(&format!("{registry}/v2/")).await {
            return preflight_error(
                &format!(
                    "the registry API of {source_repository} does not answer at {registry}/v2/ (set registry_url to the repository's connector, e.g. http://nexus.example.com:8082)"
                ),
                e,
            );
        }
    }

    let created = async {
        let mut tx = state.pool.begin().await?;
        let id = import_dao::insert(
            &mut *tx,
            NewImport {
                repository_id: repo.id,
                base_url: &url,
                source_repository: &source_repository,
                registry_url: registry_url.as_deref(),
                username: username.as_deref(),
                on_conflict: &body.on_conflict,
                concurrency: body.concurrency,
                dry_run: body.dry_run,
                nexus_version: Some(&version),
                created_by: Some(user_id),
            },
        )
        .await?;
        if let Some(password) = &password {
            secret_dao::set_import_password(&mut tx, &state.envelope, id, password).await?;
        }
        tx.commit().await?;
        Ok::<_, secret_dao::SecretDbError>(id)
    }
    .await;
    let id = match created {
        Ok(id) => id,
        Err(secret_dao::SecretDbError::Db(e)) if is_unique_violation(&e) => {
            return conflict("the repository has an import queued or running");
        }
        Err(secret_dao::SecretDbError::Db(e)) => return db_error(e),
        Err(e) => {
            tracing::error!(error = %e, "sealing an import's password failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "sealing the password failed",
            )
                .into_response();
        }
    };
    tracing::info!(
        import = id,
        repository = %repo.name,
        source = %url,
        source_repository = %source_repository,
        nexus = %version,
        dry_run = body.dry_run,
        "nexus import queued"
    );
    match import_dao::get(&state.pool, id).await {
        Ok(Some(import)) => match view(&state, &repo, import).await {
            Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
            Err(e) => db_error(e),
        },
        Ok(None) => not_found("import"),
        Err(e) => db_error(e),
    }
}

/// `GET /admin/repositories/{name}/imports/{id}`
pub async fn get(State(state): State<AppState>, Path((name, id)): Path<(String, i64)>) -> Response {
    match resolve(&state, &name, id).await {
        Ok((repo, import)) => view_response(&state, &repo, import).await,
        Err(response) => response,
    }
}

/// `GET /admin/repositories/{name}/imports/{id}/items`
pub async fn items(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, i64)>,
    Query(query): Query<ItemsQuery>,
) -> Response {
    let (_, import) = match resolve(&state, &name, id).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    if let Some(s) = &query.state {
        if !ITEM_STATES.contains(&s.as_str()) {
            return bad_request(format!("state must be one of {}", ITEM_STATES.join(", ")));
        }
    }
    let limit = query
        .limit
        .unwrap_or(ITEMS_DEFAULT_LIMIT)
        .clamp(1, ITEMS_MAX_LIMIT);
    match import_dao::list_items(
        &state.pool,
        import.id,
        query.state.as_deref(),
        query.after.unwrap_or(0),
        limit,
    )
    .await
    {
        Ok(items) => Json(items).into_response(),
        Err(e) => db_error(e),
    }
}

/// `POST /admin/repositories/{name}/imports/{id}/cancel`
pub async fn cancel(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, i64)>,
) -> Response {
    let (repo, import) = match resolve(&state, &name, id).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    if !import.is_active() {
        return conflict(format!(
            "the import is {}, not queued or running",
            import.state
        ));
    }
    match import_dao::cancel(&state.pool, import.id).await {
        Ok(Some(import)) => view_response(&state, &repo, import).await,
        Ok(None) => not_found("import"),
        Err(e) => db_error(e),
    }
}

/// `POST /admin/repositories/{name}/imports/{id}/resume`
pub async fn resume(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, i64)>,
    body: Option<Json<ResumeImport>>,
) -> Response {
    let (repo, import) = match resolve(&state, &name, id).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let body = body.map(|b| b.0).unwrap_or_default();
    if import.is_active() {
        return conflict(format!("the import is {}", import.state));
    }
    let retry = body.retry_failed || body.items.is_some();
    if import.state == "completed" && !retry {
        return bad_request(
            "a completed import has nothing to resume; retry its failed items, or start a new import to copy what is new",
        );
    }
    let password = password_secret(body.password);
    if password.is_some() && import.username.is_none() {
        return bad_request("the import reads Nexus anonymously; it takes no password");
    }
    if import.username.is_some() && !import.has_password && password.is_none() {
        return bad_request(
            "the import's password was deleted when it completed; give the Nexus password again",
        );
    }
    let resumed = async {
        let mut tx = state.pool.begin().await?;
        let retried = import_dao::requeue(&mut tx, import.id, retry, body.items.as_deref()).await?;
        if retried.is_some() {
            if let Some(password) = &password {
                secret_dao::set_import_password(&mut tx, &state.envelope, import.id, password)
                    .await?;
            }
            tx.commit().await?;
        }
        Ok::<_, secret_dao::SecretDbError>(retried)
    }
    .await;
    match resumed {
        Ok(Some(_)) => {}
        Ok(None) => return conflict("another import of the repository is queued or running"),
        Err(secret_dao::SecretDbError::Db(e)) if is_unique_violation(&e) => {
            return conflict("another import of the repository is queued or running");
        }
        Err(secret_dao::SecretDbError::Db(e)) => return db_error(e),
        Err(e) => {
            tracing::error!(error = %e, "sealing an import's password failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "sealing the password failed",
            )
                .into_response();
        }
    }
    match import_dao::get(&state.pool, import.id).await {
        Ok(Some(import)) => view_response(&state, &repo, import).await,
        Ok(None) => not_found("import"),
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/repositories/{name}/imports/{id}`
pub async fn delete(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, i64)>,
) -> Response {
    let (_, import) = match resolve(&state, &name, id).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    match import_dao::delete(&state.pool, import.id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => conflict("the import is queued or running; cancel it first"),
        Err(e) => db_error(e),
    }
}
