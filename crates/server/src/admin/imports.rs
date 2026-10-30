//! Imports into a hosted repository from another server ([`crate::import`]):
//! a NuGet feed or a registry, read through the format's own protocol.
//! **Admin-only.**
//!
//! * `GET    /admin/repositories/{name}/imports` — the repository's imports,
//!   newest first ([`ImportView`]).
//! * `POST   /admin/repositories/{name}/imports` — start one
//!   ([`CreateImport`]). The source is checked first (the **preflight**):
//!   a feed's service index resolves and its search answers (with how many
//!   packages it finds), or a registry answers its API and serves a
//!   catalog; an import that names its package ids or images needs no
//!   search or catalog. A failed check is a 400 (502 when the source is
//!   unreachable or failing) saying what is wrong; nothing is stored. A
//!   repository runs one import at a time (409). `dry_run` decides every
//!   item without writing a package: what would be copied, and the
//!   conflicts.
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
use forge_core::repo::proxy::Credentials;
use forge_db::import_dao::{self, NewImport, RepositoryImport};
use forge_db::model::{RepoKind, Repository};
use forge_db::{repository_dao, secret_dao};
use serde::{Deserialize, Serialize};

use super::db_error;
use crate::images::import::ImportSource;
use crate::import::feed::Feed;
use crate::import::{
    nexus_source_url, password_secret, source_url, Listing, SourceError, FORMATS, MAX_NAMES,
    SEARCH_PAGE,
};
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
    /// The source: a NuGet feed's service index
    /// (`https://nexus.example.com/repository/nuget-hosted/index.json`), or a
    /// registry (`https://registry.example.com`). With `repository`, a Nexus
    /// server instead (the request before imports read the format's
    /// protocol).
    pub url: String,
    /// The Nexus repository at `url` to read (with `url` naming the Nexus
    /// server): its service index, `<url>/repository/<name>/index.json`, or
    /// its registry API, `registry_url` or `<url>/repository/<name>`.
    #[serde(default)]
    pub repository: Option<String>,
    /// With `repository`: the Nexus Docker repository's connector, e.g.
    /// `http://nexus.example.com:8082`.
    #[serde(default)]
    pub registry_url: Option<String>,
    /// The package ids or images to copy, instead of every package the
    /// feed's search finds (every image the registry's catalog lists).
    #[serde(default)]
    pub names: Option<Vec<String>>,
    /// The source's credentials (both, or neither for anonymous access).
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
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
    /// The source's password, when the import no longer holds it (it
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
    /// Their size, where the source says (a referrer's).
    pub planned_size: i64,
    /// Bytes downloaded from the source.
    pub bytes_copied: i64,
}

/// An import, without its password.
#[derive(Debug, Serialize)]
pub struct ImportView {
    pub id: i64,
    pub repository: String,
    /// The source: a feed's service index or a registry.
    pub url: String,
    /// The package ids or images it copies; `null`: every one the source's
    /// search or catalog lists.
    pub names: Option<Vec<String>>,
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
    /// The `Server` header the source answered the preflight with.
    pub source_server: Option<String>,
    /// How many packages the feed's search finds: what it reported in the
    /// preflight, or as many as the scan walked, whichever is more.
    pub source_total: Option<i64>,
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
    import: RepositoryImport,
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
    };
    Ok(ImportView {
        id: import.id,
        repository: repo.name.clone(),
        url: source_url(&import, state.formats.stores_images(&repo.format)),
        names: import.names,
        username: import.username,
        has_password: import.has_password,
        on_conflict: import.on_conflict,
        concurrency: import.concurrency,
        dry_run: import.dry_run,
        state: import.state,
        phase: import.phase,
        cancel_requested: import.cancel_requested,
        source_server: import.source_server,
        source_total: import.source_total,
        last_error: import.last_error,
        created_by: import.created_by,
        created_at: import.created_at,
        started_at: import.started_at,
        finished_at: import.finished_at,
        updated_at: import.updated_at,
        progress,
    })
}

async fn view_response(state: &AppState, repo: &Repository, import: RepositoryImport) -> Response {
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
) -> Result<(Repository, RepositoryImport), Response> {
    let repo = resolve_repo(state, name).await?;
    match import_dao::get(&state.pool, id).await {
        Ok(Some(import)) if import.repository_id == repo.id => Ok((repo, import)),
        Ok(_) => Err(not_found("import")),
        Err(e) => Err(db_error(e)),
    }
}

/// A preflight failure as the administrator sees it.
fn preflight_error(what: &str, e: SourceError) -> Response {
    let status = if e.is_transient() {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::BAD_REQUEST
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
            "importing {} repositories is not supported; supported: {}",
            repo.format,
            FORMATS.join(", ")
        ));
    }
    let images = state.formats.stores_images(&repo.format);
    let Some(format) = state.formats.get(&repo.format) else {
        return bad_request(format!("the {} format is not loaded", repo.format));
    };

    // The request itself.
    let url = body.url.trim().trim_end_matches('/').to_string();
    if let Err(e) = validate_url(&url) {
        return bad_request(format!("invalid url: {e}"));
    }
    let registry_url = body
        .registry_url
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty());
    let source = match body.repository.map(|r| r.trim().to_string()) {
        Some(repository) => {
            if repository.is_empty() || repository.contains('/') {
                return bad_request("repository must name one Nexus repository");
            }
            if registry_url.is_some() && !images {
                return bad_request("registry_url applies to Docker repositories only");
            }
            if let Some(registry_url) = &registry_url {
                if let Err(e) = validate_url(registry_url) {
                    return bad_request(format!("invalid registry_url: {e}"));
                }
            }
            nexus_source_url(&url, &repository, registry_url.as_deref(), images)
        }
        None if registry_url.is_some() => {
            return bad_request(
                "registry_url goes with repository (a Nexus server's url); give the registry as url",
            );
        }
        None => url,
    };
    let names = match body.names {
        None => None,
        Some(names) => {
            let mut seen = std::collections::HashSet::new();
            let mut kept = Vec::new();
            for name in names {
                let name = name.trim().to_string();
                if name.is_empty() {
                    continue;
                }
                if let Err(e) = format.validate_id(&name) {
                    return bad_request(format!("names: {name:?} is no valid name: {e}"));
                }
                if seen.insert(format.lower_id(&name)) {
                    kept.push(name);
                }
            }
            if kept.is_empty() {
                return bad_request("names lists no package id or image; leave it out to copy every one the source lists");
            }
            if kept.len() > MAX_NAMES {
                return bad_request(format!("names lists more than {MAX_NAMES}"));
            }
            Some(kept)
        }
    };
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

    // The preflight: does the source speak the format's protocol, and list
    // what to copy?
    let (server, total) = if images {
        let credentials = match (&username, &password) {
            (Some(username), Some(password)) => Some(Credentials::for_url(
                &source,
                username.clone(),
                password.clone(),
            )),
            _ => None,
        };
        let from = ImportSource::new(&source, credentials, "import:preflight".into());
        let registry = state.registry();
        let server = match registry.probe_source(&from).await {
            Ok(server) => server,
            Err(e) => {
                return preflight_error(
                    &format!("the registry API does not answer at {source}/v2/"),
                    SourceError::of_image(e),
                )
            }
        };
        if names.is_none() {
            match registry.source_catalog(&from, None, 1).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return bad_request(format!(
                        "the registry at {source} serves no catalog (/v2/_catalog); name the images to import"
                    ))
                }
                Err(e) => {
                    return preflight_error("reading the registry's catalog", SourceError::of_image(e))
                }
            }
        }
        (server, None)
    } else {
        let feed = match Feed::open(
            state.upstream.clone(),
            format,
            &source,
            username.clone(),
            password.clone(),
        )
        .await
        {
            Ok(feed) => feed,
            Err(e) => return preflight_error(&format!("the NuGet feed at {source}"), e),
        };
        let total = if names.is_none() {
            // A page's worth: Nexus reports the hits of the page it answers
            // as the search's total.
            match feed.search(0, SEARCH_PAGE).await {
                Ok(Some((total, ids))) => {
                    Some(i64::try_from(total.max(ids.len() as u64)).unwrap_or(i64::MAX))
                }
                Ok(None) => {
                    return bad_request(format!(
                        "the NuGet feed at {source} offers no search; name the packages to import"
                    ))
                }
                Err(e) => return preflight_error("searching the feed", e),
            }
        } else {
            None
        };
        (feed.server().map(str::to_string), total)
    };
    let listing = Listing::of(images, names.is_some());

    let created = async {
        let mut tx = forge_db::begin(&state.pool).await?;
        let id = import_dao::insert(
            &mut *tx,
            NewImport {
                repository_id: repo.id,
                url: &source,
                names: names.as_deref(),
                username: username.as_deref(),
                on_conflict: &body.on_conflict,
                concurrency: body.concurrency,
                dry_run: body.dry_run,
                scan_listing: listing.as_str(),
                source_server: server.as_deref(),
                source_total: total,
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
        source = %source,
        server = server.as_deref(),
        total,
        dry_run = body.dry_run,
        "import queued"
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
        return bad_request("the import reads its source anonymously; it takes no password");
    }
    if import.username.is_some() && !import.has_password && password.is_none() {
        return bad_request(
            "the import's password was deleted when it completed; give the source's password again",
        );
    }
    let resumed = async {
        let mut tx = forge_db::begin(&state.pool).await?;
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
