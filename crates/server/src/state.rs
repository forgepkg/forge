//! Application state shared across all requests.
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
//!   [`crate::feed::PackageBytes`] over a [`forge_storage::BlobStore`].
//! * [`MemberFactory`] implements [`forge_core::repo::group::MemberOpsFactory`]
//!   by branching on a member repository's `kind`.

use std::collections::BTreeMap;
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
use forge_core::retention::FormatResolver;
use forge_core::session::SessionService;
use forge_db::model::{RepoKind, Repository, DOCKER_FORMAT};
use forge_storage::{BlobRef, BlobStore, Cas, S3Error};
use sqlx::PgPool;

use crate::auth::{AssertionIssuer, AuthSettingsCache, RealmAuth};
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
    /// Authorization decision service: every read/write/admin gate routes
    /// through this.
    pub authz: Authz,
    /// Package-format registry, keyed by `Format::id()`: the format plugins
    /// (NuGet).
    pub formats: Arc<FormatRegistry>,
    /// Parsed server configuration.
    pub config: Arc<Config>,
    /// DB-backed auth realms: the snapshot cache the password chain, the OIDC
    /// login runtime and the login UX endpoints are built from.
    pub realms: Arc<RealmAuth>,
    /// Browser-session lifecycle, shared by local-password login and OIDC;
    /// its lifetimes follow [`Self::auth_settings`].
    pub sessions: SessionService,
    /// The sign-in and anonymous-access policy administrators set at runtime
    /// (the anonymous mode, the login mode, password Basic, session lifetimes
    /// and the lockout), as this instance last read it.
    pub auth_settings: Arc<AuthSettingsCache>,
    /// Whether session cookies carry `Secure` (https `public_base_url`).
    pub cookie_secure: bool,
    /// Password-failure lockout per `(client IP, username)`, shared by
    /// `POST /auth/login` and the wire Basic password path; its limits follow
    /// [`Self::auth_settings`].
    pub login_throttle: Arc<forge_core::auth::LoginThrottle>,
    /// Failed invitation lookups and acceptances per client network (#322),
    /// with the login lockout's budget and window, which follow
    /// [`Self::auth_settings`].
    pub invitation_throttle: Arc<forge_core::auth::LoginThrottle>,
    /// Rate limit on starting OIDC logins, per client network
    /// (`auth.oidc_login_starts_per_minute`).
    pub oidc_login_starts: Arc<forge_core::auth::WindowLimiter>,
    /// Secret encryption at rest. `None` ⇒ disabled: secrets use the legacy
    /// plaintext columns and `/admin/crypto/*` reports disabled.
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
    /// Signing keys of registry Bearer tokens (`/v2/token`). [`AppState::new`]
    /// starts with a random per-process key; startup replaces it with the
    /// install's shared one ([`crate::registry::load_token_keys`] via
    /// [`AppState::with_registry_keys`]) so every instance accepts every
    /// instance's tokens.
    pub registry_keys: forge_oci::token::TokenKeys,
    /// This process among the instances of an install, as per-instance
    /// reports (the local blob cache's statistics) name it.
    pub instance: Arc<Instance>,
    /// Forge's own OIDC issuer: the keys a `federated_credential` OIDC realm
    /// signs its client assertions with, published under `/.well-known/`.
    pub assertion_issuer: AssertionIssuer,
    /// The email service (`/admin/settings/email`): sends invitations and
    /// test messages with the settings stored in the database.
    pub mailer: Arc<crate::email::Mailer>,
}

/// One instance of Forge: each replica of an install has state of its own
/// (the local blob cache), and what reports it names the instance.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Instance {
    /// The host name: `HOSTNAME` (a container's name, a pod's on
    /// Kubernetes), else the kernel's; `None` when neither is known.
    pub host: Option<String>,
    /// When this process built its state, i.e. started.
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl Instance {
    /// This process, starting now.
    pub fn current() -> Self {
        let host = std::env::var("HOSTNAME")
            .ok()
            .filter(|h| !h.trim().is_empty())
            .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty());
        Instance {
            host,
            started_at: chrono::Utc::now(),
        }
    }
}

/// Format registry: maps a format id (the `repository.format` column) to its
/// [`Format`] and its plugin: the built-in format plugins
/// ([`crate::plugins::builtin`]: NuGet, raw) and Docker.
///
/// Docker ([`DOCKER_FORMAT`]) is installed but has no [`Format`]: its
/// repositories hold images (manifests and blobs), not package versions,
/// and are served by the registry under `/v2` ([`crate::registry`]), so none
/// of the package seams (parsing, version order, the read ops) apply to
/// them. A files format (raw) has a [`Format`] whose
/// [`Format::stores_files`] says so: its repositories hold files in the
/// file store ([`crate::files`]).
pub struct FormatRegistry {
    formats: BTreeMap<String, Arc<dyn Format>>,
    /// Every format's plugin, by format id: its client protocol.
    plugins: BTreeMap<String, Arc<forge_plugin::Plugin>>,
}

impl FormatRegistry {
    /// A registry holding the built-in format plugins, NuGet reading
    /// archives and upstream manifests under `nuget_limits`.
    pub fn new(nuget_limits: forge_format_nuget::NupkgLimits) -> Self {
        let mut registry = FormatRegistry {
            formats: BTreeMap::new(),
            plugins: BTreeMap::new(),
        };
        for plugin in crate::plugins::builtin(nuget_limits) {
            registry = registry
                .with_plugin(plugin)
                .expect("built-in format ids are distinct");
        }
        registry
    }

    /// Add `format` under its [`Format::id`]. An id that is already taken
    /// (NuGet's and Docker's included) is refused: a plugin never shadows
    /// another format.
    pub fn with_format(mut self, format: Arc<dyn Format>) -> Result<Self, String> {
        let id = format.id().to_string();
        if self.is_installed(&id) {
            let built_in = Self::is_native(&id) || self.plugins.contains_key(&id);
            return Err(if built_in {
                format!("format {id:?} is built into this server")
            } else {
                format!("format {id:?} is already registered")
            });
        }
        self.formats.insert(id, format);
        Ok(self)
    }

    /// Add a format plugin: its [`Format`] and its client protocol. Its id
    /// must be free: a plugin never replaces another format.
    pub fn with_plugin(mut self, plugin: Arc<forge_plugin::Plugin>) -> Result<Self, String> {
        let format = Arc::new(forge_plugin::PluginFormat::new(&plugin));
        self = self.with_format(format)?;
        self.plugins.insert(plugin.id().to_string(), plugin);
        Ok(self)
    }

    /// The format with id `id`, if installed.
    pub fn get(&self, id: &str) -> Option<Arc<dyn Format>> {
        self.formats.get(id).cloned()
    }

    /// The plugin serving format `id`, if it is a plugin format.
    pub fn plugin(&self, id: &str) -> Option<Arc<forge_plugin::Plugin>> {
        self.plugins.get(id).cloned()
    }

    /// The plugin formats, by format id.
    pub fn plugins(&self) -> impl Iterator<Item = &Arc<forge_plugin::Plugin>> {
        self.plugins.values()
    }

    /// Whether format `id` is one served natively, without a [`Format`]:
    /// Docker.
    pub fn is_native(id: &str) -> bool {
        id == DOCKER_FORMAT
    }

    /// Whether format `id` is installed: Docker, or a format plugin.
    pub fn is_installed(&self, id: &str) -> bool {
        Self::is_native(id) || self.formats.contains_key(id)
    }

    /// Whether format `id`'s repositories hold files under paths (raw): it
    /// is installed and its descriptor says `Storage::Files`.
    pub fn stores_files(&self, id: &str) -> bool {
        self.formats.get(id).is_some_and(|f| f.stores_files())
    }

    /// The mounts plugin formats are served under, sorted and distinct
    /// (`/repository`, and any other a plugin names).
    pub fn mounts(&self) -> Vec<&str> {
        let mut mounts: Vec<&str> = self
            .plugins
            .values()
            .map(|p| p.descriptor().mount)
            .collect();
        mounts.sort_unstable();
        mounts.dedup();
        mounts
    }

    /// The installed format ids, sorted.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        let mut ids: Vec<&str> = self.formats.keys().map(String::as_str).collect();
        ids.push(DOCKER_FORMAT);
        ids.sort_unstable();
        ids.into_iter()
    }

    /// The repository kinds format `id` supports, `None` when it is not
    /// installed. Docker has every kind; a format plugin serves the kinds its
    /// descriptor names (NuGet's and raw's all three).
    pub fn kinds(&self, id: &str) -> Option<Vec<&'static str>> {
        if Self::is_native(id) {
            return Some(vec!["hosted", "proxy", "group"]);
        }
        let plugin = self.plugins.get(id)?;
        Some(
            plugin
                .descriptor()
                .kinds
                .iter()
                .map(|kind| kind.as_str())
                .collect(),
        )
    }

    /// Resolve the format for a repository by its `format` column. A format
    /// that is not installed is an error ([`RepoError::FormatUnavailable`]),
    /// never a fallback to another format: a repository is only ever read and
    /// written by the format that created it.
    pub fn for_repository(&self, repo: &Repository) -> Result<Arc<dyn Format>, RepoError> {
        self.get(&repo.format)
            .ok_or_else(|| RepoError::FormatUnavailable(repo.format.clone()))
    }
}

/// [`FormatResolver`] over the shared registry (the retention worker's view).
pub struct RegistryResolver(pub Arc<FormatRegistry>);

impl FormatResolver for RegistryResolver {
    fn resolve(&self, id: &str) -> Option<Arc<dyn Format>> {
        self.0.get(id)
    }
}

impl AppState {
    /// Construct state from its parts.
    ///
    /// Authentication runtimes (the password chain, the OIDC login flow) are
    /// **not** built here: they live behind [`RealmAuth`], which rebuilds them
    /// from the `auth_realm` table on demand. The session service is
    /// shared by every login path; it, the lockout and authorization's public
    /// read follow the auth settings ([`AuthSettingsCache`]), read from the
    /// database on demand too.
    pub fn new(pool: PgPool, blob_store: BlobStore, cache: Cache, config: Config) -> Self {
        let staging = forge_storage::Staging::new(config.staging_dir(), config.staging_budget())
            .unwrap_or_else(|e| {
                // main() already created the directory at startup; this only
                // fires for embedders that skipped that.
                tracing::error!(error = %e, "staging directory unusable; staging without a budget in the temp directory");
                forge_storage::Staging::default()
            });
        let cas = Cas::new(blob_store.clone(), pool.clone()).with_staging(staging);
        // Signed-in callers share the public read reach only where everyone
        // may read anonymously (see `Authz::with_public_read_for_signed_in`):
        // the auth settings turn it on and off.
        let authz = Authz::new(pool.clone(), cache.clone());
        let config = Arc::new(config);

        let login_throttle = Arc::new(
            forge_core::auth::LoginThrottle::default().with_known_network_store(Arc::new(
                forge_core::auth::PgKnownNetworks::new(pool.clone()),
            )),
        );
        let invitation_throttle = Arc::new(forge_core::auth::LoginThrottle::default());
        let auth_settings = Arc::new(
            AuthSettingsCache::new(
                pool.clone(),
                std::time::Duration::from_secs(config.auth.realm_cache_ttl_seconds.max(1)),
            )
            .with_authz(authz.clone())
            .with_login_throttle(login_throttle.clone())
            .with_login_throttle(invitation_throttle.clone()),
        );
        let sessions = auth_settings.sessions().clone();
        let cookie_secure = config.public_base_url().starts_with("https://");
        let assertion_issuer = AssertionIssuer::new(pool.clone(), None, config.public_base_url());
        let realms = Arc::new(RealmAuth::new(
            pool.clone(),
            cache.clone(),
            config.clone(),
            assertion_issuer.clone(),
            auth_settings.clone(),
        ));
        let upstream = UpstreamHttp::new(config.proxy.upstream_http()).unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to build the configured proxy upstream client; using defaults");
            UpstreamHttp::shared_default()
        });
        let oidc_login_starts = Arc::new(forge_core::auth::WindowLimiter::new(
            config.auth.oidc_login_starts_per_minute,
            std::time::Duration::from_secs(60),
        ));

        let (pool_for_mailer, config_for_mailer) = (pool.clone(), config.clone());
        AppState {
            downloads: DownloadTally::new(pool.clone()),
            pool,
            blob_store,
            cas,
            cache,
            authz,
            formats: Arc::new(FormatRegistry::new(config.nuget.limits())),
            config,
            realms,
            sessions,
            auth_settings,
            cookie_secure,
            login_throttle,
            invitation_throttle,
            oidc_login_starts,
            envelope: None,
            upstream,
            registry_keys: forge_oci::token::TokenKeys::new(vec![{
                use rand::Rng;
                let mut key = vec![0u8; 32];
                rand::rng().fill_bytes(&mut key);
                key
            }]),
            instance: Arc::new(Instance::current()),
            mailer: Arc::new(crate::email::Mailer::new(
                pool_for_mailer,
                None,
                assertion_issuer.clone(),
                &config_for_mailer,
            )),
            assertion_issuer,
        }
    }

    /// Use `keys` to sign and verify registry tokens.
    pub fn with_registry_keys(mut self, keys: forge_oci::token::TokenKeys) -> Self {
        self.registry_keys = keys;
        self
    }

    /// The Docker / OCI registry service, wired to this state.
    pub fn registry(&self) -> forge_oci::Registry {
        forge_oci::Registry::new(forge_oci::RegistryParts {
            pool: self.pool.clone(),
            cas: self.cas.clone(),
            store: self.blob_store.clone(),
            cache: self.cache.clone(),
            authz: self.authz.clone(),
            http: self.upstream.clone(),
            envelope: self.envelope.clone(),
            config: forge_oci::RegistryConfig {
                public_base_url: self.config.public_base_url(),
                max_blob_bytes: self.config.docker_max_blob_bytes(),
                default_max_upload_bytes: self.config.default_upload_limit(DOCKER_FORMAT),
                token_ttl_seconds: self.config.docker.token_ttl_seconds,
                delete_grace: self.config.outbox.grace(),
                max_group_depth: self.config.groups.max_nesting_depth.max(0) as u32,
                // Validated to at most 100 years.
                unreferenced_blob_ttl: chrono::Duration::seconds(
                    self.config.docker.unreferenced_blob_ttl_seconds as i64,
                ),
            },
            keys: self.registry_keys.clone(),
            recorder: Some(Arc::new(crate::registry::LedgerRecorder)),
            workloads: Some(Arc::new(crate::registry::WorkloadLiveness {
                realms: self.realms.clone(),
                pool: self.pool.clone(),
            })),
        })
    }

    /// Attach the secret-encryption envelope service. Kept out of
    /// [`AppState::new`] because building it reads the root key and must be
    /// able to fail startup; `None` keeps encryption disabled.
    pub fn with_envelope(
        mut self,
        envelope: Option<Arc<forge_crypto::service::EnvelopeService>>,
    ) -> Self {
        // Realm secrets may be encrypted too (P1.5), and so are the issuer
        // keys: rebuild both (still unshared and empty) with the envelope
        // attached.
        self.assertion_issuer = AssertionIssuer::new(
            self.pool.clone(),
            envelope.clone(),
            self.config.public_base_url(),
        );
        self.realms = Arc::new(
            RealmAuth::new(
                self.pool.clone(),
                self.cache.clone(),
                self.config.clone(),
                self.assertion_issuer.clone(),
                self.auth_settings.clone(),
            )
            .with_envelope(envelope.clone()),
        );
        // The email settings' secrets are sealed with it too.
        self.mailer = Arc::new(crate::email::Mailer::new(
            self.pool.clone(),
            envelope.clone(),
            self.assertion_issuer.clone(),
            &self.config,
        ));
        self.envelope = envelope;
        self
    }

    /// Install further format plugins next to the built-in formats (the
    /// tests' own). A plugin whose format id is taken (a built-in plugin, or
    /// another plugin) is an error.
    pub fn with_plugins(mut self, plugins: Vec<Arc<forge_plugin::Plugin>>) -> Result<Self, String> {
        let mut registry = FormatRegistry::new(self.config.nuget.limits());
        for plugin in plugins {
            registry = registry.with_plugin(plugin)?;
        }
        self.formats = Arc::new(registry);
        Ok(self)
    }

    /// The largest push `repo` accepts (for docker, the largest blob): its
    /// own limit, else the default of its format
    /// ([`Config::default_upload_limit`]).
    pub fn upload_limit(&self, repo: &Repository) -> u64 {
        repo.max_upload_bytes()
            .unwrap_or_else(|| self.config.default_upload_limit(&repo.format))
    }

    /// A blob-byte fetcher over the S3 store (serves `BlobFetch`/`PackageBytes`).
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
        let format = self.formats.for_repository(repo)?;
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
    /// access, and the envelope service for encrypted upstream passwords.
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
/// packages (`PackageBytes`).
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
impl crate::feed::PackageBytes for BlobBytes {
    async fn open(
        &self,
        loc: &NupkgLocation,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<crate::feed::BlobByteStream, RepoError> {
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
    /// Proxy members decrypt their upstream password through this.
    envelope: Option<Arc<forge_crypto::service::EnvelopeService>>,
    /// Shared proxy upstream client.
    upstream: UpstreamHttp,
    /// Shared download counts.
    downloads: Arc<DownloadTally>,
}

impl MemberOpsFactory for MemberFactory {
    fn ops_for(&self, member: &Repository) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        let format = self.formats.for_repository(member)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use forge_core::domain::{FormatError, ParsedUpload};
    use forge_core::format::ReadSeek;

    /// A format that only has an id.
    struct Named(&'static str);

    impl Format for Named {
        fn id(&self) -> &'static str {
            self.0
        }
        fn parse_upload(&self, _: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
            Err(FormatError::InvalidPackage("none".into()))
        }
        fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
            Ok(raw.to_string())
        }
        fn compare_versions(&self, a: &str, b: &str) -> std::cmp::Ordering {
            a.cmp(b)
        }
        fn lower_id(&self, id: &str) -> String {
            id.to_lowercase()
        }
    }

    #[test]
    fn docker_is_installed_without_a_package_format() {
        let registry = FormatRegistry::new(Default::default());
        assert!(registry.is_installed(DOCKER_FORMAT));
        assert!(registry.get(DOCKER_FORMAT).is_none());
        assert_eq!(
            registry.ids().collect::<Vec<_>>(),
            ["docker", "nuget", "raw"]
        );
        // Raw is a built-in plugin whose repositories hold files.
        assert!(registry.get("raw").is_some());
        assert!(registry.stores_files("raw"));
        assert!(!registry.stores_files("nuget"));
        assert!(!registry.stores_files(DOCKER_FORMAT));
        assert_eq!(
            registry.kinds("raw"),
            Some(vec!["hosted", "proxy", "group"])
        );
        assert_eq!(
            registry.kinds(DOCKER_FORMAT),
            Some(vec!["hosted", "proxy", "group"])
        );
        assert_eq!(
            registry.kinds("nuget"),
            Some(vec!["hosted", "proxy", "group"])
        );
        assert_eq!(registry.kinds("helm"), None);
        assert_eq!(registry.kinds("npm"), None);
        assert!(!registry.is_installed("npm"));
    }

    #[test]
    fn a_plugin_cannot_take_dockers_or_a_builtin_plugins_id() {
        for id in ["docker", "nuget", "raw"] {
            let registry = FormatRegistry::new(Default::default());
            let err = registry
                .with_format(Arc::new(Named(id)))
                .err()
                .expect("refused");
            assert!(err.contains("built into this server"), "{err}");
        }
    }
}
