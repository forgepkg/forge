//! Authorization and write plumbing shared by every format's feed, served by
//! [`crate::plugins`] under `/repository/{repo}`.
//!
//! ## Authorization
//! Resolution runs **before** a format sees the request:
//! * Unknown repo → **404** to a global admin, otherwise answered like a
//!   repository the caller may not read.
//! * Read methods (`GET`/`HEAD`) require the level `read`; publish/relist
//!   methods (`PUT`/`POST`) require `write`; package deletion (`DELETE`)
//!   requires `delete`, the highest level. An unauthenticated caller → **401** (so a
//!   package client knows to send credentials), an authenticated-but-
//!   disallowed caller → **403** ([`authz_denied`]).

use axum::http::{header, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use forge_core::auth::principal::Principal;
use forge_core::authz::{Level, PackageFilter};
use forge_core::repo::RepoKind;
use forge_db::model::Repository;
use sha2::Digest;

use crate::state::AppState;

#[derive(Clone, Copy)]
pub(crate) struct AuthzDenied;

/// `Retry-After` (seconds) of an offline repository's 503.
pub(crate) const OFFLINE_RETRY_AFTER_SECS: &str = "60";

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

/// The access level one package protocol request requires.
pub(crate) fn level_for_method(method: &Method) -> Level {
    match *method {
        Method::PUT | Method::POST => Level::Write,
        Method::DELETE => Level::Delete,
        _ => Level::Read,
    }
}

/// Package mutations accept only credentials designed for non-browser
/// package clients. A session/password principal is intentionally insufficient:
/// otherwise adding an unrelated `Authorization` header to a cookie-authenticated
/// request would turn that browser session into a package publishing credential.
pub(crate) fn principal_allows_protocol_mutations(principal: &Principal) -> bool {
    matches!(
        principal,
        Principal::Workload { .. }
            | Principal::User {
                token_id: Some(_),
                ..
            }
    )
}

/// Map an authorization denial to the right status: unauthenticated → 401 (send
/// credentials), authenticated-but-forbidden → 403, anonymous-denied → 401.
pub(crate) fn authz_denied(principal: &Principal) -> Response {
    let mut response = match principal {
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
    };
    response.extensions_mut().insert(AuthzDenied);
    response
}

// ── Hosted write adapter ────────────────────────────────────────────────────

use forge_core::format::Format;
use forge_core::repo::hosted::HostedWrite;
use forge_core::repo::{
    DeleteOutcome, PublishAuthorizationContext, PublishOutcome, PublishPolicy, RepoError,
    RepoWriteOps, UploadReader, WriteError,
};
use forge_db::trusted_publish_audit_dao::{self, NewTrustedPublishAudit};
use forge_db::trusted_publisher_dao;
use std::sync::Arc;

/// Bridges the object-safe [`RepoWriteOps`] trait (which takes a boxed
/// [`UploadReader`]) to [`HostedWrite`]'s generic `store_upload<R>`.
pub(crate) struct HostedWriteAdapter {
    inner: HostedWrite,
}

impl HostedWriteAdapter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        state: &AppState,
        format: Arc<dyn Format>,
        repository_id: i64,
        repository_name: String,
        principal: Principal,
        package_filter: PackageFilter,
        replace_filter: PackageFilter,
        role_filter: PackageFilter,
        role_replace_filter: PackageFilter,
    ) -> Self {
        let inner = hosted_write(
            state,
            format,
            repository_id,
            repository_name,
            principal,
            package_filter,
            replace_filter,
            role_filter,
            role_replace_filter,
        );
        HostedWriteAdapter { inner }
    }
}

/// The hosted write path of `principal` in a repository: publishes limited
/// to `package_filter`, replacing a version to `replace_filter`, and the
/// trusted-publishing ledger of a workload.
#[allow(clippy::too_many_arguments)]
pub(crate) fn hosted_write(
    state: &AppState,
    format: Arc<dyn Format>,
    repository_id: i64,
    repository_name: String,
    principal: Principal,
    package_filter: PackageFilter,
    replace_filter: PackageFilter,
    role_filter: PackageFilter,
    role_replace_filter: PackageFilter,
) -> HostedWrite {
    let policy: Arc<dyn PublishPolicy> = Arc::new(SelectorPublishPolicy {
        filter: package_filter.clone(),
        replace_filter,
        role_filter,
        role_replace_filter,
        repository_id,
        repository_name,
    });
    HostedWrite::new(
        state.pool.clone(),
        format,
        state.cas.clone(),
        state.cache_invalidator(),
        state.config.outbox.grace(),
    )
    .with_publish_policy(principal, policy)
    .with_mutation_filter(package_filter)
}

/// The trusted-publishing ledger policy of a registry push to `repository`:
/// a workload's manifest push is recorded (and re-validated against the
/// current realm) like a package publish. Selectors are checked by the
/// registry itself, so this policy allows every image.
pub(crate) fn workload_ledger_policy(
    repository: &Repository,
    role_filter: PackageFilter,
    role_replace_filter: PackageFilter,
) -> Arc<dyn PublishPolicy> {
    Arc::new(SelectorPublishPolicy {
        filter: PackageFilter::AllowAll,
        replace_filter: PackageFilter::AllowAll,
        role_filter,
        role_replace_filter,
        repository_id: repository.id,
        repository_name: repository.name.clone(),
    })
}

/// Request-scoped publication policy. The canonical package id is available
/// only after format parsing, so this hook is the first safe point at which the
/// selector can be applied without trusting multipart metadata.
struct SelectorPublishPolicy {
    filter: PackageFilter,
    /// The caller's delete predicate, required to replace an existing version.
    replace_filter: PackageFilter,
    role_filter: PackageFilter,
    role_replace_filter: PackageFilter,
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
            matched_publishers,
            ..
        } = &context.principal
        else {
            // This ledger is specifically the federated trusted-publishing
            // provenance record. Existing user/token publication behavior is
            // unchanged and is not mislabeled as workload identity.
            return Ok(());
        };
        let token_issued_at = chrono::DateTime::<chrono::Utc>::from_timestamp(*issued_at, 0)
            .ok_or_else(|| RepoError::Storage("validated workload iat is out of range".into()))?;
        let identity = trusted_publish_audit_dao::lock_identity_snapshot(tx, *realm_id, *role_id)
            .await
            .map_err(RepoError::from)?
            .ok_or_else(|| WriteError::ForbiddenPackage {
                id: context.package_id.clone(),
            })?;
        let current_issuer_hash: [u8; 32] =
            sha2::Sha256::digest(identity.issuer.trim_end_matches('/').as_bytes()).into();
        if current_issuer_hash != *issuer_sha256 {
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
                realm_id = *realm_id,
                error = %error,
                "current WIF realm config is invalid; publish denied"
            );
            WriteError::ForbiddenPackage {
                id: context.package_id.clone(),
            }
        })?;
        if current_config_hash != *config_sha256 {
            // Audience, lifetime, authorized-party, or claim-rule policy changed
            // after this peer built its realm snapshot. Do not let the stale
            // principal publish under the new configuration's identity.
            return Err(WriteError::ForbiddenPackage {
                id: context.package_id.clone(),
            });
        }

        let publisher_matches: Vec<_> = matched_publishers
            .iter()
            .map(
                |matched| forge_db::trusted_publisher_dao::TrustedPublisherMatch {
                    id: matched.id,
                    definition_sha256: matched.definition_sha256,
                },
            )
            .collect();
        let (current_publishers, _) =
            trusted_publisher_dao::lock_matches_with_rows(tx, &publisher_matches)
                .await
                .map_err(RepoError::from)?;
        let required_action = match context.action {
            forge_core::repo::PackageMutation::Unlist
            | forge_core::repo::PackageMutation::Delete => "delete",
            forge_core::repo::PackageMutation::Publish
            | forge_core::repo::PackageMutation::Relist => "write",
        };
        let role_action_filter = if required_action == "delete" {
            &self.role_replace_filter
        } else {
            &self.role_filter
        };
        let role_allows_action = role_action_filter.allows(&context.package_id);
        let role_allows_delete =
            !context.requires_delete || self.role_replace_filter.allows(&context.package_id);
        let role_authorized = role_allows_action && role_allows_delete;
        let needs_publisher_action = !role_allows_action;
        let needs_publisher_delete =
            context.requires_delete && !self.role_replace_filter.allows(&context.package_id);
        let mut publisher_action = None;
        let mut publisher_delete = None;
        for publisher in current_publishers
            .iter()
            .filter(|publisher| publisher.repository_id == self.repository_id)
        {
            if (!needs_publisher_action || publisher_action.is_some())
                && (!needs_publisher_delete || publisher_delete.is_some())
            {
                break;
            }
            let patterns = match (
                serde_json::from_value::<Vec<String>>(publisher.includes.clone()),
                serde_json::from_value::<Vec<String>>(publisher.excludes.clone()),
            ) {
                (Ok(includes), Ok(excludes)) => {
                    forge_core::authz::SelectorPatterns { includes, excludes }
                }
                (Err(error), _) | (_, Err(error)) => {
                    tracing::error!(error = %error, publisher_id = publisher.id, "malformed trusted-publisher selector");
                    continue;
                }
            };
            if !patterns.matches(&context.package_id).unwrap_or(false) {
                continue;
            }
            if needs_publisher_action
                && publisher
                    .actions
                    .iter()
                    .any(|action| action == required_action)
            {
                publisher_action = Some((publisher.id, publisher.name.as_str()));
            }
            if needs_publisher_delete && publisher.actions.iter().any(|action| action == "delete") {
                publisher_delete = Some((publisher.id, publisher.name.as_str()));
            }
        }
        if (needs_publisher_action && publisher_action.is_none())
            || (needs_publisher_delete && publisher_delete.is_none())
        {
            return Err(WriteError::ForbiddenPackage {
                id: context.package_id.clone(),
            });
        }
        let trusted_publisher = if role_authorized {
            None
        } else {
            publisher_action.or(publisher_delete)
        };
        trusted_publish_audit_dao::insert(
            tx,
            NewTrustedPublishAudit {
                repository_id: self.repository_id,
                repository_name: &self.repository_name,
                package_name: &context.package_id,
                package_version: &context.package_version,
                realm_id: *realm_id,
                realm_name: &identity.realm_name,
                issuer: &identity.issuer,
                role_id: *role_id,
                role_name: &identity.role_name,
                subject_sha256,
                jti_sha256: jti_sha256.as_ref(),
                token_issued_at,
                action: context.action.as_str(),
                trusted_publisher_id: trusted_publisher.map(|(id, _)| id),
                trusted_publisher_name: trusted_publisher.map(|(_, name)| name),
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

    #[test]
    fn protocol_methods_map_to_levels() {
        assert_eq!(level_for_method(&Method::PUT), Level::Write);
        assert_eq!(level_for_method(&Method::POST), Level::Write);
        assert_eq!(level_for_method(&Method::DELETE), Level::Delete);
        assert_eq!(level_for_method(&Method::GET), Level::Read);
        assert_eq!(level_for_method(&Method::HEAD), Level::Read);
    }

    #[test]
    fn only_api_tokens_and_workloads_are_protocol_mutation_credentials() {
        assert!(principal_allows_protocol_mutations(&Principal::User {
            user_id: 1,
            token_id: Some(7),
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
            key_id: None,
            expires_at: 2,
            matched_publishers: Arc::from([]),
        }));
        assert!(!principal_allows_protocol_mutations(&Principal::User {
            user_id: 1,
            token_id: None,
            method: forge_core::auth::AuthMethod::Password
        }));
        assert!(!principal_allows_protocol_mutations(
            &Principal::Unauthenticated
        ));
    }
}
