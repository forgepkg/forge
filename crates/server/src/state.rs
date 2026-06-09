//! Application state shared across all requests (spec §8, plan 10.1/10.3).
//!
//! [`AppState`] holds the database pool, the S3 blob store + content-addressed
//! store, the hybrid cache, the package-format registry, and the parsed
//! configuration. It is cheaply cloneable (everything inside is `Arc`-shared or
//! itself clone-cheap) and is the axum router state.
//!
//! It also owns the small adapter types that bridge `forge-core`'s storage- and
//! cache-agnostic seams to the concrete `forge-storage` / `forge-cache`
//! implementations:
//!
//! * [`BlobBytes`] implements both [`forge_core::repo::hosted::BlobFetch`] and
//!   [`forge_nuget::routes::NupkgBytes`] over a [`forge_storage::BlobStore`].
//! * [`CacheInvalidatorAdapter`] implements
//!   [`forge_core::repo::CacheInvalidator`] over a [`forge_cache::Cache`].
//! * [`MemberFactory`] implements [`forge_core::repo::group::MemberOpsFactory`]
//!   by branching on a member repository's `kind`.

use std::sync::Arc;

use async_trait::async_trait;
use forge_cache::Cache;
use forge_core::auth::authz::Authz;
use forge_core::auth::principal::Principal;
use forge_core::format::Format;
use forge_core::repo::group::{GroupRepo, MemberOpsFactory};
use forge_core::repo::hosted::{BlobFetch, HostedRepo};
use forge_core::repo::proxy::ProxyRepo;
use forge_core::repo::{CacheInvalidator, RepoError, RepoReadOps};
use forge_db::model::{RepoKind, Repository};
use forge_storage::{BlobStore, Cas};
use sqlx::PgPool;

use crate::config::Config;

/// Namespace under which hosted read responses are cached / invalidated.
///
/// The write path invalidates `(NS_PACKAGE, "{repo}/{lower_id}")` after a
/// publish/unlist/relist so stale registration/search/flat reads are dropped.
pub const NS_PACKAGE: &str = "package";

/// Shared, cheaply-cloneable application state.
#[derive(Clone)]
pub struct AppState {
    /// PostgreSQL connection pool.
    pub pool: PgPool,
    /// Raw S3 object store (bucket already ensured at startup).
    pub blob_store: BlobStore,
    /// Content-addressed ingest over [`Self::blob_store`] + [`Self::pool`].
    pub cas: Cas,
    /// Two-tier read cache (L1 always; L2 Redis when configured).
    pub cache: Cache,
    /// Authorization decision service (§12.4 seam): every read/write/admin gate
    /// routes through this.
    pub authz: Authz,
    /// Package-format registry. Slice 1 ships a single NuGet format; the map is
    /// keyed by `Format::id()` so additional formats slot in without a refactor.
    pub formats: Arc<FormatRegistry>,
    /// Parsed server configuration.
    pub config: Arc<Config>,
    /// Interactive OIDC login runtime (slice 12.2). `None` ⇒ OIDC disabled and
    /// no `/auth/oidc/*` routes are mounted.
    pub oidc: Option<crate::auth::OidcRuntime>,
    /// Secret encryption at rest (slice 12.5). `None` ⇒ disabled: secrets use
    /// the legacy plaintext columns and `/admin/crypto/*` reports disabled.
    /// Built fallibly by [`crate::crypto::build_envelope`] **before**
    /// [`AppState::new`] (a configured-but-broken root key must abort startup)
    /// and attached via [`AppState::with_envelope`].
    pub envelope: Option<std::sync::Arc<forge_crypto::service::EnvelopeService>>,
}

/// Format registry: maps a format id (e.g. `"nuget"`) to its [`Format`].
pub struct FormatRegistry {
    nuget: Arc<dyn Format>,
}

impl FormatRegistry {
    /// Build a registry from the NuGet format implementation.
    pub fn new(nuget: Arc<dyn Format>) -> Self {
        FormatRegistry { nuget }
    }

    /// Resolve the format for a repository by its `format` column. Slice 1 only
    /// knows `"nuget"`; any other value falls back to it (no other formats
    /// exist yet).
    pub fn for_repository(&self, _repo: &Repository) -> Arc<dyn Format> {
        self.nuget.clone()
    }

    /// The NuGet format.
    pub fn nuget(&self) -> Arc<dyn Format> {
        self.nuget.clone()
    }
}

impl AppState {
    /// Construct state from its parts.
    ///
    /// When the config has an **enabled** `[oidc]` section, the OIDC login
    /// runtime is built here (SSRF-guarded HTTP client + discovery/JWKS metadata
    /// client + session service); on a build failure we log and disable OIDC
    /// rather than failing startup. A disabled/absent section leaves `oidc =
    /// None` and mounts no `/auth/oidc/*` routes.
    pub fn new(
        pool: PgPool,
        blob_store: BlobStore,
        cache: Cache,
        nuget: Arc<dyn Format>,
        config: Config,
    ) -> Self {
        let cas = Cas::new(blob_store.clone(), pool.clone());

        let oidc = match &config.oidc {
            Some(o) if o.enabled => {
                match crate::auth::OidcRuntime::build(
                    o,
                    pool.clone(),
                    &config.public_base_url(),
                    cache.clone(),
                ) {
                    Ok(rt) => Some(rt),
                    Err(e) => {
                        tracing::error!(error = %e, "OIDC runtime build failed; OIDC disabled");
                        None
                    }
                }
            }
            _ => None,
        };

        let authz = Authz::new(pool.clone(), cache.clone());

        AppState {
            pool,
            blob_store,
            cas,
            cache,
            authz,
            formats: Arc::new(FormatRegistry::new(nuget)),
            config: Arc::new(config),
            oidc,
            envelope: None,
        }
    }

    /// Attach the secret-encryption envelope service (slice 12.5). Kept out of
    /// [`AppState::new`] because building it reads the root key and must be
    /// able to fail startup; `None` keeps encryption disabled.
    pub fn with_envelope(
        mut self,
        envelope: Option<Arc<forge_crypto::service::EnvelopeService>>,
    ) -> Self {
        self.envelope = envelope;
        self
    }

    /// A blob-byte fetcher over the S3 store (serves `BlobFetch`/`NupkgBytes`).
    pub fn blob_bytes(&self) -> Arc<BlobBytes> {
        Arc::new(BlobBytes {
            store: self.blob_store.clone(),
        })
    }

    /// A cache invalidator over the hybrid cache.
    pub fn cache_invalidator(&self) -> Arc<CacheInvalidatorAdapter> {
        Arc::new(CacheInvalidatorAdapter {
            cache: self.cache.clone(),
        })
    }

    /// Build the read ops for a single repository, branching on its `kind`.
    ///
    /// The `principal` is needed only for **group** repositories, whose member
    /// visibility is identity-aware; hosted/proxy ignore it.
    pub fn read_ops_for(
        &self,
        repo: &Repository,
        principal: Principal,
    ) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        let format = self.formats.for_repository(repo);
        match repo.kind() {
            RepoKind::Hosted => Ok(Arc::new(HostedRepo::new(
                self.pool.clone(),
                format,
                self.blob_bytes(),
            ))),
            RepoKind::Proxy => Ok(Arc::new(
                ProxyRepo::new(
                    self.pool.clone(),
                    format,
                    self.cas.clone(),
                    self.cache.clone(),
                )
                // §12.5: lets the upstream fetch decrypt an encrypted password.
                .with_envelope(self.envelope.clone()),
            )),
            RepoKind::Group => Ok(Arc::new(GroupRepo::new(
                self.pool.clone(),
                principal,
                Arc::new(self.member_factory()),
                self.authz.clone(),
                self.config.groups.max_nesting_depth.max(0) as u32,
            ))),
        }
    }

    /// A member-ops factory for group resolution (hosted/proxy members only).
    pub fn member_factory(&self) -> MemberFactory {
        MemberFactory {
            pool: self.pool.clone(),
            blob_store: self.blob_store.clone(),
            cas: self.cas.clone(),
            cache: self.cache.clone(),
            formats: self.formats.clone(),
            envelope: self.envelope.clone(),
        }
    }
}

/// Reads whole blobs from the S3 store. Implements the two byte-fetch seams.
pub struct BlobBytes {
    store: BlobStore,
}

impl BlobBytes {
    async fn read_all(&self, s3_key: &str) -> Result<Vec<u8>, RepoError> {
        let stream = self.store.get(s3_key).await.map_err(|e| {
            tracing::error!(error = %e, %s3_key, "s3 get failed");
            RepoError::Storage(format!("s3 get {s3_key}: {e}"))
        })?;
        let bytes = stream
            .collect()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, %s3_key, "s3 body read failed");
                RepoError::Storage(format!("read blob {s3_key}: {e}"))
            })?
            .into_bytes();
        Ok(bytes.to_vec())
    }
}

#[async_trait]
impl BlobFetch for BlobBytes {
    async fn fetch_all(&self, s3_key: &str) -> Result<Vec<u8>, RepoError> {
        self.read_all(s3_key).await
    }
}

#[async_trait]
impl forge_nuget::routes::NupkgBytes for BlobBytes {
    async fn fetch_all(&self, s3_key: &str) -> Result<Vec<u8>, RepoError> {
        self.read_all(s3_key).await
    }
}

/// Invalidates cached read responses for a `(repo, id)` after a write.
pub struct CacheInvalidatorAdapter {
    cache: Cache,
}

#[async_trait]
impl CacheInvalidator for CacheInvalidatorAdapter {
    async fn invalidate_package(&self, repo: &str, lower_id: &str) {
        self.cache
            .invalidate(NS_PACKAGE, &format!("{repo}/{lower_id}"))
            .await;
    }
}

/// Builds member read ops for group resolution by branching on `kind`.
///
/// Nested-group members are rejected here as a defense in depth (the admin API
/// already refuses to persist one).
pub struct MemberFactory {
    pool: PgPool,
    blob_store: BlobStore,
    cas: Cas,
    cache: Cache,
    formats: Arc<FormatRegistry>,
    /// §12.5: proxy members decrypt their upstream password through this.
    envelope: Option<Arc<forge_crypto::service::EnvelopeService>>,
}

impl MemberOpsFactory for MemberFactory {
    fn ops_for(&self, member: &Repository) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        let format = self.formats.for_repository(member);
        match member.kind() {
            RepoKind::Hosted => Ok(Arc::new(HostedRepo::new(
                self.pool.clone(),
                format,
                Arc::new(BlobBytes {
                    store: self.blob_store.clone(),
                }),
            ))),
            RepoKind::Proxy => Ok(Arc::new(
                ProxyRepo::new(
                    self.pool.clone(),
                    format,
                    self.cas.clone(),
                    self.cache.clone(),
                )
                .with_envelope(self.envelope.clone()),
            )),
            RepoKind::Group => Err(RepoError::WrongKind {
                name: member.name.clone(),
                kind: member.kind.clone(),
            }),
        }
    }
}
