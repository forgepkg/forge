//! Repository dispatch for `/v3/{repo}/...` (spec §6, plan 10.3).
//!
//! A single fallback handler under `/v3/{repo}` resolves the repository row,
//! enforces authorization, then builds the per-repository NuGet router
//! ([`forge_nuget::routes::nuget_router`]) and dispatches the remaining path
//! into it. Branching on [`RepoKind`] selects the read ops (hosted / proxy /
//! group); publish routes are mounted only for hosted repos by the router
//! factory itself.
//!
//! ## Authorization
//! Resolution runs **before** dispatch:
//! * Unknown repo → **404**.
//! * Read methods (`GET`/`HEAD`) require [`can_read`]; a denied authenticated
//!   user is impossible in Slice 1 (any user can read), so a denial means an
//!   anonymous/unauthenticated caller → **401** (so a NuGet client knows to send
//!   credentials).
//! * Publish/relist methods (`PUT`/`POST`) require `write`; package deletion
//!   (`DELETE`) requires the distinct `delete` privilege. An
//!   unauthenticated caller → **401**, an authenticated-but-disallowed caller →
//!   **403** (none in Slice 1, but the distinction is wired for §12.4).

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use forge_core::auth::principal::Principal;
use forge_core::authz::{Action, PackageFilter};
use forge_core::repo::RepoKind;
use forge_db::model::Repository;
use forge_db::repository_dao;
use forge_nuget::routes::{nuget_router, RouteContext};
use sha2::Digest;
use tower::ServiceExt;

use crate::middleware::principal_of;
use crate::state::AppState;

/// `Retry-After` (seconds) of an offline repository's 503.
const OFFLINE_RETRY_AFTER_SECS: &str = "60";

/// Whether `repo` is switched off for maintenance and so serves nothing: an
/// offline hosted or group repository. An offline proxy still serves what it
/// cached, without asking its upstream.
pub(crate) fn offline_serves_nothing(repo: &Repository) -> bool {
    !repo.online && repo.kind() != RepoKind::Proxy
}

/// The answer of a repository that [`offline_serves_nothing`]: 503 with
/// `Retry-After`. Callers send it only after authorization, so it reveals
/// nothing to a caller who may not use the repository.
pub(crate) fn offline_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, OFFLINE_RETRY_AFTER_SECS)],
        "repository is offline",
    )
        .into_response()
}

/// RBAC action corresponding to one NuGet protocol request.
fn action_for_method(method: &Method) -> Action {
    match *method {
        Method::PUT | Method::POST => Action::Write,
        Method::DELETE => Action::Delete,
        _ => Action::Read,
    }
}

/// Strip the `/v3/{repo}` prefix from the original request path, returning the
/// remainder (always starting with `/`, e.g. `/index.json`, `/flat/x/...`).
fn subpath(uri: &Uri, repo: &str) -> String {
    let prefix = format!("/v3/{repo}");
    let path = uri.path();
    let rest = path.strip_prefix(&prefix).unwrap_or("");
    let rest = if rest.is_empty() { "/" } else { rest };
    match uri.query() {
        Some(q) => format!("{rest}?{q}"),
        None => rest.to_string(),
    }
}

/// Build a [`RouteContext`] for a resolved repository + principal.
/// `replace_filter` is the caller's delete predicate, which a redeploy needs
/// (only computed for writes).
async fn route_context(
    state: &AppState,
    repo: &Repository,
    principal: Principal,
    package_filter: PackageFilter,
    replace_filter: PackageFilter,
) -> Option<RouteContext> {
    let kind = repo.kind();
    let format = state.formats.for_repository(repo);
    let ops = state.read_ops_for(repo, principal).await.ok()?;
    let protocol_mutations_allowed = principal_allows_protocol_mutations(&principal);

    // Write ops only for hosted repos; the router mounts publish routes only for
    // hosted, so proxy/group never reach a write handler.
    let write: Option<std::sync::Arc<dyn forge_core::repo::RepoWriteOps>> = match kind {
        RepoKind::Hosted => Some(std::sync::Arc::new(HostedWriteAdapter::new(
            state,
            format.clone(),
            repo.id,
            repo.name.clone(),
            principal,
            package_filter.clone(),
            replace_filter,
        ))),
        _ => None,
    };

    Some(RouteContext {
        repo: repo.name.clone(),
        kind,
        public_base_url: state.config.public_base_url(),
        ops,
        format,
        nupkg: state.blob_bytes(),
        write,
        protocol_mutations_allowed,
        package_filter,
        max_upload_bytes: state.config.server.max_upload_bytes,
    })
}

/// NuGet mutation endpoints accept only credentials designed for non-browser
/// package clients. A session/password principal is intentionally insufficient:
/// otherwise adding an unrelated `Authorization` header to a cookie-authenticated
/// request would turn that browser session into a package publishing credential.
fn principal_allows_protocol_mutations(principal: &Principal) -> bool {
    matches!(
        principal,
        Principal::Workload { .. }
            | Principal::User {
                token_id: Some(_),
                ..
            }
    )
}

/// Axum fallback handler mounted at `/v3/{repo}` (and everything under it).
///
/// Every response — including the unknown-repository and authorization
/// answers produced here — gets the feed's browser-hardening headers
/// ([`forge_nuget::routes::harden_response_headers`]).
pub async fn dispatch(State(state): State<AppState>, req: Request<Body>) -> Response {
    let mut response = dispatch_request(state, req).await;
    forge_nuget::routes::harden_response_headers(response.headers_mut());
    response
}

async fn dispatch_request(state: AppState, req: Request<Body>) -> Response {
    let principal = principal_of(&req);
    let method = req.method().clone();
    let uri = req.uri().clone();

    // The first path segment after /v3/ is the repository name.
    let Some(repo_name) = repo_name_from_path(uri.path()) else {
        return (StatusCode::NOT_FOUND, "repository not found").into_response();
    };

    let repo = match repository_dao::find_repository_by_name(&state.pool, &repo_name).await {
        Ok(Some(r)) => r,
        // Answer an unknown name exactly like a repository the caller may
        // not read, so repository names cannot be enumerated; only a global
        // admin (who can list them anyway) learns that it does not exist.
        Ok(None) if state.authz.is_global_admin(&principal).await => {
            return (StatusCode::NOT_FOUND, "repository not found").into_response();
        }
        Ok(None) => return authz_denied(&principal),
        Err(e) => {
            tracing::error!(error = %e, repo = %repo_name, "repo lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    // Authorization gate (before any handler runs). Delete is a distinct
    // privilege from publish/relist; selectors are evaluated separately below.
    let action = action_for_method(&method);
    let allowed = match action {
        Action::Read => state.authz.can_read(&principal, &repo).await,
        Action::Write => state.authz.can_write(&principal, &repo).await,
        Action::Delete => state.authz.can_delete(&principal, &repo).await,
        Action::Admin => false,
    };
    if !allowed {
        return authz_denied(&principal);
    }
    // An offline hosted or group repository serves nothing (a maintenance
    // window). Answered after authorization.
    if offline_serves_nothing(&repo) {
        return offline_response();
    }
    let package_filter = state
        .authz
        .package_filter_for(&principal, &repo, action)
        .await;

    // A redeploy replaces a version's bytes: it takes the delete permission
    // (and its selectors) as well as write. Only writes need it, and for a
    // token it costs a scope lookup.
    let replace_filter = if action == Action::Write && repo.kind() == RepoKind::Hosted {
        state
            .authz
            .package_filter_for(&principal, &repo, Action::Delete)
            .await
    } else {
        PackageFilter::DenyAll
    };
    let Some(ctx) = route_context(&state, &repo, principal, package_filter, replace_filter).await
    else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    };

    // Dispatch the `/v3/{repo}`-stripped sub-path into the per-repo router.
    //
    // We rebuild the request from its parts rather than mutating the URI in
    // place: the outer router (`/v3/{repo}/{*rest}`) left its own matched path
    // params (`repo`, `rest`) in the request extensions, and the inner router's
    // `Path` extractors would otherwise read those stale params (causing a
    // "wrong number of path arguments" 500). Dropping the extensions clears
    // them. Method, headers (Content-Type / X-NuGet-ApiKey for publish), and
    // the body are all carried over.
    let rest = subpath(&uri, &repo.name);
    let new_uri: Uri = match rest.parse() {
        Ok(u) => u,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = new_uri;
    parts.extensions.clear();
    let sub_req = Request::from_parts(parts, body);

    let router = nuget_router(repo.kind(), ctx);
    let response = match router.oneshot(sub_req).await {
        Ok(resp) => resp,
        Err(infallible) => match infallible {},
    };
    if action != Action::Read {
        // Every package mutation (push, unlist, relist) that reached its
        // handler, whatever its outcome, with who sent it: the trail a leaked
        // credential's writes are traced by (workload publishes are also in
        // trusted_publish_audit). Requests the repository gate refuses are
        // not logged.
        tracing::info!(
            target: "forge::audit",
            %method,
            repo = %repo.name,
            path = %rest,
            status = response.status().as_u16(),
            principal = %principal.audit_label(),
            "package mutation"
        );
    }
    response
}

/// Map an authorization denial to the right status: unauthenticated → 401 (send
/// credentials), authenticated-but-forbidden → 403, anonymous-denied → 401.
fn authz_denied(principal: &Principal) -> Response {
    match principal {
        // An authenticated identity (user or WIF workload) that is nonetheless
        // denied by RBAC → 403.
        Principal::User { .. } | Principal::Workload { .. } => {
            (StatusCode::FORBIDDEN, "forbidden").into_response()
        }
        // No/insufficient identity → 401 so the client knows to authenticate.
        Principal::Anonymous { .. } | Principal::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            [(
                axum::http::header::WWW_AUTHENTICATE,
                "Basic realm=\"Forge\"",
            )],
            "authentication required",
        )
            .into_response(),
    }
}

/// Extract the repository name (first segment after `/v3/`).
fn repo_name_from_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/v3/")?;
    let seg = rest.split('/').next()?;
    if seg.is_empty() {
        return None;
    }
    Some(seg.to_string())
}

// ── Hosted write adapter ────────────────────────────────────────────────────

use forge_core::format::Format;
use forge_core::repo::hosted::HostedWrite;
use forge_core::repo::{
    DeleteOutcome, PublishAuthorizationContext, PublishOutcome, PublishPolicy, RepoError,
    RepoWriteOps, UploadReader, WriteError,
};
use forge_db::trusted_publish_audit_dao::{self, NewTrustedPublishAudit};
use std::sync::Arc;

/// Bridges the object-safe [`RepoWriteOps`] trait (which takes a boxed
/// [`UploadReader`]) to [`HostedWrite`]'s generic `store_upload<R>`.
struct HostedWriteAdapter {
    inner: HostedWrite,
}

impl HostedWriteAdapter {
    fn new(
        state: &AppState,
        format: Arc<dyn Format>,
        repository_id: i64,
        repository_name: String,
        principal: Principal,
        package_filter: PackageFilter,
        replace_filter: PackageFilter,
    ) -> Self {
        let policy: Arc<dyn PublishPolicy> = Arc::new(SelectorPublishPolicy {
            filter: package_filter.clone(),
            replace_filter,
            repository_id,
            repository_name,
        });
        let inner = HostedWrite::new(
            state.pool.clone(),
            format,
            state.cas.clone(),
            state.cache_invalidator(),
            state.config.outbox.grace(),
        )
        .with_publish_policy(principal, policy)
        .with_mutation_filter(package_filter);
        HostedWriteAdapter { inner }
    }
}

/// Request-scoped publication policy. The canonical package id is available
/// only after format parsing, so this hook is the first safe point at which the
/// selector can be applied without trusting multipart metadata.
struct SelectorPublishPolicy {
    filter: PackageFilter,
    /// The caller's delete predicate, required to replace an existing version.
    replace_filter: PackageFilter,
    repository_id: i64,
    repository_name: String,
}

#[async_trait::async_trait]
impl PublishPolicy for SelectorPublishPolicy {
    async fn authorize(&self, context: &PublishAuthorizationContext) -> Result<(), WriteError> {
        if self.filter.allows(&context.package_id) {
            Ok(())
        } else {
            Err(WriteError::ForbiddenPackage {
                id: context.package_id.clone(),
            })
        }
    }

    async fn authorize_replace(
        &self,
        context: &PublishAuthorizationContext,
    ) -> Result<(), WriteError> {
        if self.replace_filter.allows(&context.package_id) {
            Ok(())
        } else {
            Err(WriteError::ForbiddenPackage {
                id: context.package_id.clone(),
            })
        }
    }

    async fn record_in_transaction(
        &self,
        context: &PublishAuthorizationContext,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<(), WriteError> {
        let Principal::Workload {
            realm_id,
            role_id,
            issuer_sha256,
            config_sha256,
            subject_sha256,
            jti_sha256,
            issued_at,
        } = context.principal
        else {
            // This ledger is specifically the federated trusted-publishing
            // provenance record. Existing user/token publication behavior is
            // unchanged and is not mislabeled as workload identity.
            return Ok(());
        };
        let token_issued_at = chrono::DateTime::<chrono::Utc>::from_timestamp(issued_at, 0)
            .ok_or_else(|| RepoError::Storage("validated workload iat is out of range".into()))?;
        let identity = trusted_publish_audit_dao::lock_identity_snapshot(tx, realm_id, role_id)
            .await
            .map_err(RepoError::from)?
            .ok_or_else(|| WriteError::ForbiddenPackage {
                id: context.package_id.clone(),
            })?;
        let current_issuer_hash: [u8; 32] =
            sha2::Sha256::digest(identity.issuer.trim_end_matches('/').as_bytes()).into();
        if current_issuer_hash != issuer_sha256 {
            // A stale in-memory realm snapshot authenticated against an issuer
            // that has since been replaced. The row locks above make this check
            // authoritative for the rest of the package transaction.
            return Err(WriteError::ForbiddenPackage {
                id: context.package_id.clone(),
            });
        }
        let current_config_hash = crate::auth::workload_identity_config_sha256(
            &identity.realm_config,
        )
        .map_err(|error| {
            tracing::warn!(
                realm_id,
                error = %error,
                "current WIF realm config is invalid; publish denied"
            );
            WriteError::ForbiddenPackage {
                id: context.package_id.clone(),
            }
        })?;
        if current_config_hash != config_sha256 {
            // Audience, lifetime, authorized-party, or claim-rule policy changed
            // after this peer built its realm snapshot. Do not let the stale
            // principal publish under the new configuration's identity.
            return Err(WriteError::ForbiddenPackage {
                id: context.package_id.clone(),
            });
        }

        trusted_publish_audit_dao::insert(
            tx,
            NewTrustedPublishAudit {
                repository_id: self.repository_id,
                repository_name: &self.repository_name,
                package_name: &context.package_id,
                package_version: &context.package_version,
                realm_id,
                realm_name: &identity.realm_name,
                issuer: &identity.issuer,
                role_id,
                role_name: &identity.role_name,
                subject_sha256: &subject_sha256,
                jti_sha256: jti_sha256.as_ref(),
                token_issued_at,
                action: context.action.as_str(),
            },
        )
        .await
        .map_err(RepoError::from)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl RepoWriteOps for HostedWriteAdapter {
    async fn store_upload(
        &self,
        repo: &str,
        reader: UploadReader,
        max_upload_bytes: u64,
    ) -> Result<PublishOutcome, WriteError> {
        self.inner
            .store_upload(repo, reader, max_upload_bytes)
            .await
    }

    async fn delete_component(
        &self,
        repo: &str,
        id: &str,
        version: &str,
        hard: bool,
    ) -> Result<DeleteOutcome, WriteError> {
        self.inner.delete_component(repo, id, version, hard).await
    }

    async fn relist(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<DeleteOutcome, WriteError> {
        self.inner.relist(repo, id, version).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Uri;

    #[test]
    fn repo_name_extraction() {
        assert_eq!(
            repo_name_from_path("/v3/my-repo/index.json").as_deref(),
            Some("my-repo")
        );
        assert_eq!(
            repo_name_from_path("/v3/my-repo").as_deref(),
            Some("my-repo")
        );
        assert_eq!(repo_name_from_path("/v3/").as_deref(), None);
        assert_eq!(repo_name_from_path("/other").as_deref(), None);
    }

    #[test]
    fn subpath_strips_prefix_and_keeps_query() {
        let uri: Uri = "/v3/my-repo/query?q=foo&take=5".parse().unwrap();
        assert_eq!(subpath(&uri, "my-repo"), "/query?q=foo&take=5");
        let uri: Uri = "/v3/my-repo/index.json".parse().unwrap();
        assert_eq!(subpath(&uri, "my-repo"), "/index.json");
        let uri: Uri = "/v3/my-repo".parse().unwrap();
        assert_eq!(subpath(&uri, "my-repo"), "/");
    }

    #[test]
    fn protocol_methods_map_to_distinct_actions() {
        assert_eq!(action_for_method(&Method::PUT), Action::Write);
        assert_eq!(action_for_method(&Method::POST), Action::Write);
        assert_eq!(action_for_method(&Method::DELETE), Action::Delete);
        assert_eq!(action_for_method(&Method::GET), Action::Read);
        assert_eq!(action_for_method(&Method::HEAD), Action::Read);
    }

    #[test]
    fn only_api_tokens_and_workloads_are_protocol_mutation_credentials() {
        assert!(principal_allows_protocol_mutations(&Principal::User {
            user_id: 1,
            token_id: Some(7),
            is_admin: false,
            method: forge_core::auth::AuthMethod::Token
        }));
        assert!(principal_allows_protocol_mutations(&Principal::Workload {
            realm_id: 1,
            role_id: 2,
            issuer_sha256: [1; 32],
            config_sha256: [3; 32],
            subject_sha256: [2; 32],
            jti_sha256: None,
            issued_at: 1,
        }));
        assert!(!principal_allows_protocol_mutations(&Principal::User {
            user_id: 1,
            token_id: None,
            is_admin: true,
            method: forge_core::auth::AuthMethod::Password
        }));
        assert!(!principal_allows_protocol_mutations(
            &Principal::Unauthenticated
        ));
    }
}
