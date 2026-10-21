//! Admin retention-policy REST API (slice 12.1, design §3.3). **Admin-only.**
//!
//! Mounted under `/admin/repositories/{name}/retention`. Every route resolves
//! the repository by name first (404 if absent), then operates on its
//! `retention_policy` jsonb and the `retention_run` coordination ledger via
//! [`forge_db::retention_dao`].
//!
//! * `GET    …/retention`         — the stored policy + the ledger run state.
//! * `PUT    …/retention`         — validate + store a policy (arms the worker).
//! * `DELETE …/retention`         — clear the policy (disarm; ledger row left).
//! * `POST   …/retention/preview` — **dry run**: snapshot + the pure evaluator,
//!   returning what *would* be deleted/unlisted with **zero** mutation and
//!   **zero** outbox rows.
//! * `POST   …/retention/run`     — schedule a run promptly (`next_run_at=now()`);
//!   the background worker claims it on its next poll (does **not** run inline).
//! * `GET    …/retention/audit`   — recent audit rows (newest first), optionally
//!   filtered by `run_id` and paged with `before`/`limit`.
//!
//! Nothing here deletes S3 objects: applied runs go through the worker + the
//! slice-1 blob outbox. Preview never mutates at all. Policies carry no secrets,
//! so nothing is redacted.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use forge_core::retention::evaluate::{
    evaluate, evaluate_proxy, CandidateComponent, ProxyCandidate,
};
use forge_core::retention::images::{validate_image_policy, ImageDecisions, ImageRetentionPolicy};
use forge_core::retention::model::{validate_policy, RetentionPolicy};
use forge_db::model::RepoKind;
use forge_db::{repository_dao, retention_dao};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{db_error, format_unavailable};
use crate::state::AppState;

/// Default + cap for the audit page size.
const AUDIT_DEFAULT_LIMIT: i64 = 100;
const AUDIT_MAX_LIMIT: i64 = 1000;

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "repository not found").into_response()
}

/// Resolve a repository id + kind by name (404 → caller returns it).
async fn resolve_repo(
    state: &AppState,
    name: &str,
) -> Result<forge_db::model::Repository, Response> {
    match repository_dao::find_repository_by_name(&state.pool, name).await {
        Ok(Some(r)) => Ok(r),
        Ok(None) => Err(not_found()),
        Err(e) => Err(db_error(e)),
    }
}

/// `GET /admin/repositories/{name}/retention` — the stored policy (or null) plus
/// the coordination-ledger run state (or null if never scheduled).
#[derive(Debug, Serialize)]
pub struct RetentionView {
    /// The raw stored policy jsonb, or `null` when no retention is configured.
    pub policy: Option<JsonValue>,
    /// The `retention_run` ledger row, or `null` if the repo was never armed.
    pub last_run: Option<retention_dao::RunState>,
}

/// `GET /admin/repositories/{name}/retention`
pub async fn get(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let repo = match resolve_repo(&state, &name).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let policy = match retention_dao::read_policy(&state.pool, repo.id).await {
        Ok(p) => p,
        Err(e) => return db_error(e),
    };
    let last_run = match retention_dao::get_run(&state.pool, repo.id).await {
        Ok(r) => r,
        Err(e) => return db_error(e),
    };

    Json(RetentionView { policy, last_run }).into_response()
}

/// PUT body: the policy to store. Unknown fields are rejected, here and inside
/// the policy: an omitted policy field takes the less safe default
/// (`dry_run_only: false`, no `package_name_prefix`, no protection), so a
/// misspelled one must not be dropped.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutBody {
    /// A package policy ([`RetentionPolicy`]), or for a docker repository an
    /// image policy ([`ImageRetentionPolicy`]).
    pub policy: JsonValue,
}

/// A policy body that does not parse as its repository's policy model:
/// 422, as a malformed JSON body is.
fn unprocessable(e: serde_json::Error) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        format!("invalid retention policy: {e}"),
    )
        .into_response()
}

/// `PUT /admin/repositories/{name}/retention` — validate + store a policy.
///
/// The policy is parsed (serde) and validated against the repo kind
/// (`validate_policy` rejects e.g. `scope: proxy_cached` on a non-proxy repo,
/// a hosted-scope rule — the default when `scope` is omitted — on a proxy
/// repo, zero counts, empty rules). On success the ledger row is upserted (by the
/// DAO) so the worker can claim it, and the repo's package cache is invalidated.
pub async fn put(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<PutBody>,
) -> Response {
    let repo = match resolve_repo(&state, &name).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Parsed with its repository's model and stored in its canonical form.
    let normalized = if repo.is_docker() {
        let policy: ImageRetentionPolicy = match serde_json::from_value(body.policy) {
            Ok(p) => p,
            Err(e) => return unprocessable(e),
        };
        if let Err(e) = validate_image_policy(&policy, repo.kind()) {
            return bad_request(format!("invalid retention policy: {e}"));
        }
        serde_json::to_value(&policy)
    } else {
        let policy: RetentionPolicy = match serde_json::from_value(body.policy) {
            Ok(p) => p,
            Err(e) => return unprocessable(e),
        };
        if let Err(e) = validate_policy(&policy, repo.kind()) {
            return bad_request(format!("invalid retention policy: {e}"));
        }
        serde_json::to_value(&policy)
    };
    let policy_json = match normalized {
        Ok(v) => v,
        Err(e) => return bad_request(format!("could not serialize policy: {e}")),
    };

    match retention_dao::write_policy(&state.pool, repo.id, Some(&policy_json)).await {
        Ok(true) => Json(RetentionView {
            policy: Some(policy_json),
            last_run: retention_dao::get_run(&state.pool, repo.id)
                .await
                .ok()
                .flatten(),
        })
        .into_response(),
        Ok(false) => not_found(),
        Err(e) => db_error(e),
    }
}

/// `DELETE /admin/repositories/{name}/retention` — clear the policy (disarm).
///
/// The `retention_run` ledger row is left in place (harmless; the claim query
/// skips repos with a null policy), so re-arming later resumes scheduling.
pub async fn delete(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let repo = match resolve_repo(&state, &name).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match retention_dao::write_policy(&state.pool, repo.id, None).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(),
        Err(e) => db_error(e),
    }
}

/// `POST …/retention/preview` request body (all optional).
#[derive(Debug, Default, Deserialize)]
pub struct PreviewBody {
    /// Evaluate as-of this instant instead of `now()` (for staging/testing).
    #[serde(default)]
    pub at: Option<chrono::DateTime<Utc>>,
}

/// Counts for a preview pass.
#[derive(Debug, Default, Serialize)]
pub struct PreviewCounts {
    /// Candidates inspected (hosted components + proxy cached versions).
    pub evaluated: usize,
    /// Versions that would be unlisted.
    pub unlisted: usize,
    /// Versions/cached entries that would be hard-deleted.
    pub deleted: usize,
}

/// Preview response: the exact decision set the worker would apply, with no
/// mutation and no outbox rows.
#[derive(Debug, Serialize)]
pub struct PreviewView {
    /// Hosted component decisions (unlist | hard_delete).
    pub decisions: Vec<forge_core::retention::evaluate::Decision>,
    /// Proxy cached-version eviction decisions (always delete).
    pub proxy_decisions: Vec<forge_core::retention::evaluate::ProxyDecision>,
    /// Docker repositories: the tags and manifests that would be deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_decisions: Option<ImageDecisions>,
    pub counts: PreviewCounts,
}

/// `POST /admin/repositories/{name}/retention/preview` — **dry run**.
///
/// Snapshots the repo's candidates and runs the *pure* evaluator, returning the
/// decision set without applying anything (no row changes, no `blob_outbox`
/// rows). A missing/disabled policy yields an empty decision set. This mirrors
/// exactly what the worker's evaluation step would produce.
pub async fn preview(
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Option<Json<PreviewBody>>,
) -> Response {
    let repo = match resolve_repo(&state, &name).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Load + validate the policy. No policy / disabled ⇒ empty preview.
    let policy_json = match retention_dao::read_policy(&state.pool, repo.id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Json(PreviewView {
                decisions: Vec::new(),
                proxy_decisions: Vec::new(),
                image_decisions: repo.is_docker().then(ImageDecisions::default),
                counts: PreviewCounts::default(),
            })
            .into_response()
        }
        Err(e) => return db_error(e),
    };
    if repo.is_docker() {
        return preview_images(&state, &repo, policy_json, body.and_then(|b| b.0.at)).await;
    }
    let policy: RetentionPolicy = match serde_json::from_value(policy_json) {
        Ok(p) => p,
        Err(e) => return bad_request(format!("stored policy is unparseable: {e}")),
    };
    if let Err(e) = validate_policy(&policy, repo.kind()) {
        return bad_request(format!("stored policy is invalid: {e}"));
    }
    if !policy.enabled {
        return Json(PreviewView {
            decisions: Vec::new(),
            proxy_decisions: Vec::new(),
            image_decisions: None,
            counts: PreviewCounts::default(),
        })
        .into_response();
    }

    let now = body.and_then(|b| b.0.at).unwrap_or_else(Utc::now);
    let kind = repo.kind();
    let format = match state.formats.for_repository(&repo) {
        Ok(format) => format,
        Err(e) => return format_unavailable(e),
    };

    // Snapshot hosted candidates (never on a proxy: its components are cache
    // entries evicted only through `proxy_cached_version`, as in the worker).
    let hosted: Vec<CandidateComponent> = if kind == RepoKind::Proxy {
        Vec::new()
    } else {
        match retention_dao::load_candidate_components(
            &state.pool,
            repo.id,
            format.package_asset_path(),
        )
        .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|(r, _sha)| CandidateComponent {
                    component_id: r.component_id,
                    package_name: r.name,
                    version: r.version,
                    listed: r.listed,
                    created_at: r.created_at,
                    last_downloaded_at: r.last_downloaded_at,
                })
                .collect(),
            Err(e) => return db_error(e),
        }
    };

    // Snapshot proxy candidates (only meaningful for proxy repos).
    let proxy: Vec<ProxyCandidate> = if kind == RepoKind::Proxy {
        match retention_dao::load_proxy_candidates(&state.pool, repo.id).await {
            Ok(rows) => rows
                .into_iter()
                .map(|r| ProxyCandidate {
                    cached_version_id: r.cached_version_id,
                    package_name: r.name,
                    version: r.version,
                    first_seen_at: r.first_seen_at,
                    last_downloaded_at: r.last_downloaded_at,
                })
                .collect(),
            Err(e) => return db_error(e),
        }
    } else {
        Vec::new()
    };

    let evaluated = hosted.len() + proxy.len();
    // The evaluator is CPU-bound and grows with the repository: run it on the
    // blocking pool so a large preview does not stall a runtime worker thread.
    let evaluation = tokio::task::spawn_blocking(move || {
        (
            evaluate(format.as_ref(), now, &policy, &hosted),
            evaluate_proxy(now, &policy, &proxy),
        )
    })
    .await;
    let (decisions, proxy_decisions) = match evaluation {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, repo = %repo.name, "retention preview evaluation failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    use forge_core::retention::model::Action;
    let unlisted = decisions
        .iter()
        .filter(|d| d.action == Action::Unlist)
        .count();
    let deleted = decisions
        .iter()
        .filter(|d| d.action == Action::HardDelete)
        .count()
        + proxy_decisions.len();

    Json(PreviewView {
        decisions,
        proxy_decisions,
        image_decisions: None,
        counts: PreviewCounts {
            evaluated,
            unlisted,
            deleted,
        },
    })
    .into_response()
}

/// [`preview`] of a docker repository's image policy.
async fn preview_images(
    state: &AppState,
    repo: &forge_db::model::Repository,
    policy_json: JsonValue,
    at: Option<chrono::DateTime<Utc>>,
) -> Response {
    let policy: ImageRetentionPolicy = match serde_json::from_value(policy_json) {
        Ok(p) => p,
        Err(e) => return bad_request(format!("stored policy is unparseable: {e}")),
    };
    if let Err(e) = validate_image_policy(&policy, repo.kind()) {
        return bad_request(format!("stored policy is invalid: {e}"));
    }
    let empty = |evaluated| PreviewView {
        decisions: Vec::new(),
        proxy_decisions: Vec::new(),
        image_decisions: Some(ImageDecisions::default()),
        counts: PreviewCounts {
            evaluated,
            ..PreviewCounts::default()
        },
    };
    if !policy.enabled {
        return Json(empty(0)).into_response();
    }
    let now = match at {
        Some(at) => at,
        None => match forge_db::db_now(&state.pool).await {
            Ok(now) => now,
            Err(e) => return db_error(e),
        },
    };
    match forge_core::retention::images::evaluate_repository(&state.pool, repo.id, now, &policy)
        .await
    {
        Ok((decisions, evaluated)) => {
            let deleted = decisions.tags.len() + decisions.manifests.len();
            Json(PreviewView {
                decisions: Vec::new(),
                proxy_decisions: Vec::new(),
                image_decisions: Some(decisions),
                counts: PreviewCounts {
                    evaluated: evaluated as usize,
                    unlisted: 0,
                    deleted,
                },
            })
            .into_response()
        }
        Err(e) => db_error(e),
    }
}

/// `POST …/retention/run` response.
#[derive(Debug, Serialize)]
pub struct RunScheduled {
    /// True once the repo is scheduled for a prompt run.
    pub scheduled: bool,
}

/// `POST /admin/repositories/{name}/retention/run` — schedule a prompt run.
///
/// Sets `retention_run.next_run_at = now()` so the worker claims the repo on its
/// next poll. Does **not** run inline. Requires an armed (non-null) policy:
/// a repo without a policy returns 409.
pub async fn run(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let repo = match resolve_repo(&state, &name).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match retention_dao::schedule_now(&state.pool, repo.id).await {
        Ok(true) => (StatusCode::ACCEPTED, Json(RunScheduled { scheduled: true })).into_response(),
        // schedule_now returns false when the repo has no policy (nothing to run).
        Ok(false) => (
            StatusCode::CONFLICT,
            "repository has no retention policy to run",
        )
            .into_response(),
        Err(e) => db_error(e),
    }
}

/// Query params for the audit listing.
#[derive(Debug, Default, Deserialize)]
pub struct AuditQuery {
    /// Restrict to one evaluation pass.
    #[serde(default)]
    pub run_id: Option<uuid::Uuid>,
    /// Page backwards: only rows with `id <` this value (older than the cursor).
    #[serde(default)]
    pub before: Option<i64>,
    /// Page size (clamped to [1, AUDIT_MAX_LIMIT]; default AUDIT_DEFAULT_LIMIT).
    #[serde(default)]
    pub limit: Option<i64>,
}

/// Audit listing response.
#[derive(Debug, Serialize)]
pub struct AuditView {
    pub items: Vec<retention_dao::AuditRecord>,
}

/// `GET /admin/repositories/{name}/retention/audit`
pub async fn audit(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<AuditQuery>,
) -> Response {
    let repo = match resolve_repo(&state, &name).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let limit = q
        .limit
        .unwrap_or(AUDIT_DEFAULT_LIMIT)
        .clamp(1, AUDIT_MAX_LIMIT);

    match retention_dao::read_audit(&state.pool, repo.id, q.run_id, q.before, limit).await {
        Ok(items) => Json(AuditView { items }).into_response(),
        Err(e) => db_error(e),
    }
}
