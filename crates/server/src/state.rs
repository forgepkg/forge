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
//! * [`MemberFactory`] implements [`forge_core::repo::group::MemberOpsFactory`]
//!   by branching on a member repository's `kind`.

use std::sync::Arc;

use async_trait::async_trait;
use forge_cache::Cache;
use forge_core::auth::authz::Authz;
use forge_core::auth::principal::Principal;
use forge_core::format::Format;
use forge_core::net::upstream::UpstreamHttp;
use forge_core::repo::downloads::DownloadTally;
use forge_core::repo::group::{GroupRepo, MemberOpsFactory};
use forge_core::repo::hosted::{BlobFetch, HostedRepo};
use forge_core::repo::proxy::ProxyRepo;
use forge_core::repo::{
    CacheInvalidator, NoopCacheInvalidator, NupkgLocation, PackageFilteredReadOps, RepoError,
    RepoReadOps,
};
use forge_core::session::SessionService;
use forge_db::model::{RepoKind, Repository};
use forge_storage::{BlobRef, BlobStore, Cas, S3Error};
use sqlx::PgPool;

use crate::auth::RealmAuth;
use crate::config::Config;

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
    /// DB-backed auth realms (12.7): the snapshot cache the password chain,
    /// the OIDC login runtime and the login UX endpoints are built from.
    pub realms: Arc<RealmAuth>,
    /// Browser-session lifecycle, shared by local-password login and OIDC.
    pub sessions: SessionService,
    /// Whether session cookies carry `Secure` (https `public_base_url`).
    pub cookie_secure: bool,
    /// Password-failure lockout per `(client IP, username)`, shared by
    /// `POST /auth/login` and the wire Basic password path.
    pub login_throttle: Arc<forge_core::auth::LoginThrottle>,
    /// Rate limit on starting OIDC logins, per client network
    /// (`auth.oidc_login_starts_per_minute`).
    pub oidc_login_starts: Arc<forge_core::auth::WindowLimiter>,
    /// Secret encryption at rest (slice 12.5). `None` ⇒ disabled: secrets use
    /// the legacy plaintext columns and `/admin/crypto/*` reports disabled.
    /// Built fallibly by [`crate::crypto::build_envelope`] **before**
    /// [`AppState::new`] (a configured-but-broken root key must abort startup)
    /// and attached via [`AppState::with_envelope`].
    pub envelope: Option<std::sync::Arc<forge_crypto::service::EnvelopeService>>,
    /// Pooled, timeout- and size-bounded client for proxy upstream traffic,
    /// built once from `[proxy]` and shared by every proxy repository.
    pub upstream: UpstreamHttp,
    /// Download counts of every hosted and proxy repository, written in
    /// batches (#119).
    pub downloads: Arc<DownloadTally>,
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
    /// Authentication runtimes (the password chain, the OIDC login flow) are
    /// **not** built here: they live behind [`RealmAuth`], which rebuilds them
    /// from the `auth_realm` table on demand (12.7). The session service and
    /// cookie security bit are config-derived and shared by every login path.
    pub fn new(
        pool: PgPool,
        blob_store: BlobStore,
        cache: Cache,
        nuget: Arc<dyn Format>,
        config: Config,
    ) -> Self {
        let staging = forge_storage::Staging::new(config.staging_dir(), config.staging_budget())
            .unwrap_or_else(|e| {
                // main() already created the directory at startup; this only
                // fires for embedders that skipped that.
                tracing::error!(error = %e, "staging directory unusable; staging without a budget in the temp directory");
                forge_storage::Staging::default()
            });
        let cas = Cas::new(blob_store.clone(), pool.clone()).with_staging(staging);
        // Signed-in callers share the public read reach only where everyone
        // may read anonymously (see `Authz::with_public_read_for_signed_in`).
        let authz = Authz::new(pool.clone(), cache.clone())
            .with_public_read_for_signed_in(config.auth.anonymous_mode.eq_ignore_ascii_case("all"));
        let config = Arc::new(config);

        let (idle, absolute) = config.session_ttls();
        let sessions = SessionService::new(
            pool.clone(),
            chrono::Duration::seconds(idle as i64),
            chrono::Duration::seconds(absolute as i64),
        );
        let cookie_secure = config.public_base_url().starts_with("https://");
        let realms = Arc::new(RealmAuth::new(pool.clone(), cache.clone(), config.clone()));
        let upstream = UpstreamHttp::new(config.proxy.upstream_http()).unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to build the configured proxy upstream client; using defaults");
            UpstreamHttp::shared_default()
        });
        let login_throttle = Arc::new(
            forge_core::auth::LoginThrottle::new(
                config.auth.login_max_failures,
                std::time::Duration::from_secs(config.auth.login_failure_window_seconds),
            )
            .with_known_network_store(Arc::new(
                forge_core::auth::PgKnownNetworks::new(pool.clone()),
            )),
        );
        let oidc_login_starts = Arc::new(forge_core::auth::WindowLimiter::new(
            config.auth.oidc_login_starts_per_minute,
            std::time::Duration::from_secs(60),
        ));

        AppState {
            downloads: DownloadTally::new(pool.clone()),
            pool,
            blob_store,
            cas,
            cache,
            authz,
            formats: Arc::new(FormatRegistry::new(nuget)),
            config,
            realms,
            sessions,
            cookie_secure,
            login_throttle,
            oidc_login_starts,
            envelope: None,
            upstream,
        }
    }

    /// Attach the secret-encryption envelope service (slice 12.5). Kept out of
    /// [`AppState::new`] because building it reads the root key and must be
    /// able to fail startup; `None` keeps encryption disabled.
    pub fn with_envelope(
        mut self,
        envelope: Option<Arc<forge_crypto::service::EnvelopeService>>,
    ) -> Self {
        // Realm secrets may be encrypted too (P1.5): rebuild the (still
        // unshared, empty) realm snapshot cache with the envelope attached.
        self.realms = Arc::new(
            RealmAuth::new(self.pool.clone(), self.cache.clone(), self.config.clone())
                .with_envelope(envelope.clone()),
        );
        self.envelope = envelope;
        self
    }

    /// A blob-byte fetcher over the S3 store (serves `BlobFetch`/`NupkgBytes`).
    pub fn blob_bytes(&self) -> Arc<BlobBytes> {
        Arc::new(BlobBytes {
            store: self.blob_store.clone(),
        })
    }

    /// The invalidator the write path and retention call after a package
    /// changes. Hosted reads (registration, search, flat container) are not
    /// cached, so there is nothing to drop: invalidating a namespace nobody
    /// reads only cost every push, unlist, delete and retention decision a
    /// Redis round-trip (and stalled them while Redis did).
    pub fn cache_invalidator(&self) -> Arc<dyn CacheInvalidator> {
        Arc::new(NoopCacheInvalidator)
    }

    /// Build the read ops for a single repository, branching on its `kind`.
    ///
    /// The `principal` is needed only for **group** repositories, whose member
    /// visibility is identity-aware; hosted/proxy ignore it.
    pub async fn read_ops_for(
        &self,
        repo: &Repository,
        principal: Principal,
    ) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        let format = self.formats.for_repository(repo);
        let filter = self.authz.package_filter(&principal, repo).await;
        let inner: Arc<dyn RepoReadOps> = match repo.kind() {
            RepoKind::Hosted => Arc::new(
                HostedRepo::new(self.pool.clone(), format, self.blob_bytes())
                    .with_download_tally(self.downloads.clone()),
            ),
            RepoKind::Proxy => Arc::new(self.proxy_repo(format)),
            RepoKind::Group => Arc::new(
                GroupRepo::new(
                    self.pool.clone(),
                    principal,
                    Arc::new(self.member_factory()),
                    self.authz.clone(),
                    self.config.groups.max_nesting_depth.max(0) as u32,
                )
                .with_format(format),
            ),
        };
        Ok(Arc::new(PackageFilteredReadOps::new(inner, filter)))
    }

    /// A fully wired proxy read facade: shared upstream client, local blob
    /// access, and (§12.5) the envelope service for encrypted upstream
    /// passwords.
    pub fn proxy_repo(&self, format: Arc<dyn Format>) -> ProxyRepo {
        ProxyRepo::new(
            self.pool.clone(),
            format,
            self.cas.clone(),
            self.cache.clone(),
        )
        .with_envelope(self.envelope.clone())
        .with_http(self.upstream.clone())
        .with_blob_fetch(self.blob_bytes())
        .with_download_tally(self.downloads.clone())
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
            upstream: self.upstream.clone(),
            downloads: self.downloads.clone(),
        }
    }
}

/// Reads blobs through the blob store (and its local cache, when enabled):
/// whole small metadata blobs (`BlobFetch`, the `.nuspec`) and streamed
/// packages (`NupkgBytes`).
pub struct BlobBytes {
    store: BlobStore,
}

/// A storage error as a [`RepoError`]: S3 being down is "try again later"
/// (503), anything else a server error.
fn storage_error(error: S3Error, s3_key: &str) -> RepoError {
    if error.is_unavailable() {
        tracing::warn!(error = %error, %s3_key, "object store unavailable; blob not in the local cache");
        RepoError::Busy(format!("object store unavailable: {error}"))
    } else {
        tracing::error!(error = %error, %s3_key, "s3 get failed");
        RepoError::Storage(format!("s3 get {s3_key}: {error}"))
    }
}

#[async_trait]
impl BlobFetch for BlobBytes {
    async fn fetch_all(&self, blob: &forge_db::model::Blob) -> Result<Vec<u8>, RepoError> {
        let blob_ref = BlobRef {
            sha256: &blob.sha256,
            s3_key: &blob.s3_key,
            size: u64::try_from(blob.size).unwrap_or(0),
        };
        self.store
            .read_all(blob_ref)
            .await
            .map_err(|e| storage_error(e, &blob.s3_key))
    }
}

#[async_trait]
impl forge_nuget::routes::NupkgBytes for BlobBytes {
    async fn open(
        &self,
        loc: &NupkgLocation,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<forge_nuget::routes::BlobByteStream, RepoError> {
        let blob = BlobRef {
            sha256: &loc.blob_sha256,
            s3_key: &loc.blob_s3_key,
            size: u64::try_from(loc.size).unwrap_or(0),
        };
        self.store
            .open(blob, range)
            .await
            .map_err(|e| storage_error(e, &loc.blob_s3_key))
    }

    /// Ranges are served with the local blob cache only, so a server
    /// without one answers downloads exactly as before it existed.
    fn serves_ranges(&self) -> bool {
        self.store.cache().is_some()
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
    /// Shared proxy upstream client.
    upstream: UpstreamHttp,
    /// Shared download counts.
    downloads: Arc<DownloadTally>,
}

impl MemberOpsFactory for MemberFactory {
    fn ops_for(&self, member: &Repository) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        let format = self.formats.for_repository(member);
        match member.kind() {
            RepoKind::Hosted => Ok(Arc::new(
                HostedRepo::new(
                    self.pool.clone(),
                    format,
                    Arc::new(BlobBytes {
                        store: self.blob_store.clone(),
                    }),
                )
                .with_download_tally(self.downloads.clone()),
            )),
            RepoKind::Proxy => Ok(Arc::new(
                ProxyRepo::new(
                    self.pool.clone(),
                    format,
                    self.cas.clone(),
                    self.cache.clone(),
                )
                .with_envelope(self.envelope.clone())
                .with_http(self.upstream.clone())
                .with_blob_fetch(Arc::new(BlobBytes {
                    store: self.blob_store.clone(),
                }))
                .with_download_tally(self.downloads.clone()),
            )),
            RepoKind::Group => Err(RepoError::WrongKind {
                name: member.name.clone(),
                kind: member.kind.clone(),
            }),
        }
    }
}
