//! Proxy-repository read operations (spec §7 "Proxy", plan Phase 8).
//!
//! A proxy repository mirrors an upstream NuGet **V3 service index** named by
//! `repository.remote_url`. On a read miss it discovers the upstream's resource
//! `@id`s, fetches metadata/artifacts on demand, content-addresses the bytes
//! through the [`Cas`], and records a `proxy_cached_version` row so future reads
//! are served locally.
//!
//! ## Hard invariants enforced here
//! * **Outbound scheme guard** — upstream URLs are validated to be http/https
//!   at config time ([`crate::net::ssrf::validate_url`]). Private/loopback
//!   upstreams are permitted (12.7 §3.6 — admin-only config).
//! * **Bounded upstream I/O** — every request goes through the shared
//!   [`UpstreamHttp`] client: connect / idle-read / total deadlines, size caps
//!   enforced while streaming, metadata spooled (memory → temp file) and
//!   `.nupkg` bodies streamed straight into a CAS temp file. Nothing is ever
//!   buffered whole in memory.
//! * **Credentials on every upstream request** — the configured Basic
//!   credentials are sent with the service index, version listing, `.nuspec`
//!   and `.nupkg` requests, but only to the `remote_url` host
//!   ([`crate::net::upstream`] credential scoping).
//! * **NO advisory locks, no DB transaction across network I/O** — first-time
//!   fetch singleflight is a plain row lock:
//!   [`proxy_dao::upsert_cached_version`] (INSERT … ON CONFLICT DO NOTHING) to
//!   guarantee a row exists, then [`proxy_dao::lock_cached_version_for_update`]
//!   (SELECT … FOR UPDATE). The lock is held only for the short state-decision
//!   and finalize transactions; it is **released before** the upstream HTTP
//!   fetch and the CAS/S3 PUT (Addendum A7). The singleflight is therefore
//!   best-effort: under contention more than one caller may fetch from
//!   upstream, but the CAS is content-addressed and the finalize tx re-checks
//!   `downloaded`, so concurrent fetches converge on identical state. The
//!   upstream-index refresh likewise never holds a lock over the fetch; the
//!   per-instance cache coalesces concurrent refreshes.
//! * **Package delay** — a version discovered from upstream is recorded with
//!   `first_seen_at = now()` but is **not** served until
//!   `now − first_seen_at ≥ package_delay_seconds`. Inside the window it is
//!   omitted from enumeration/registration/search and direct download 404s. A
//!   delay-gated 404 is **never** written to the not-found negative cache.
//! * **Negative cache** — a genuine upstream 404 sets `not_found = true` +
//!   `not_found_at = now()`, honored for `not_found_ttl_seconds`.
//! * **Metadata TTL** — the upstream service index *and* each package's
//!   version listing are re-fetched at most once per `metadata_ttl_seconds`.
//! * **Offline** — `repository.online == false` serves only already-cached data;
//!   no upstream requests are made.

use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use forge_cache::Cache;
use forge_crypto::ExposeSecret;
use forge_db::asset_dao::{self, NewAsset};
use forge_db::component_dao::{self, NewComponent};
use forge_db::model::Repository;
use forge_db::proxy_dao::{self, NewProxyCachedVersion};
use forge_db::{blob_dao, repository_dao};
use forge_storage::{Cas, CasError};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;

use crate::authz::PackageFilter;
use crate::format::Format;
use crate::net::upstream::{Origin, RequestClass, UpstreamAuth, UpstreamError, UpstreamHttp};
use crate::repo::hosted::BlobFetch;
use crate::repo::{
    NupkgLocation, RegistrationEntry, RepoError, RepoReadOps, SearchHit, SearchParams,
    SearchResult, VersionEntry, NUPKG_ASSET_PATH, NUPKG_CONTENT_TYPE, NUSPEC_ASSET_PATH,
    NUSPEC_CONTENT_TYPE,
};

/// Cache namespace for resolved upstream service indexes, keyed by repo name.
pub const NS_UPSTREAM_INDEX: &str = "proxy_index";
/// Cache namespace marking a package's upstream version listing as fresh,
/// keyed by `"{repo}/{lower_id}"`.
pub const NS_UPSTREAM_VERSIONS: &str = "proxy_versions";
/// Cache namespace for upstream `.nuspec` documents of not-yet-downloaded
/// versions, keyed by `"{repo}/{lower_id}/{version}"`.
pub const NS_UPSTREAM_NUSPEC: &str = "proxy_nuspec";

/// Default metadata TTL when a proxy leaves `metadata_ttl_seconds` unset.
const DEFAULT_METADATA_TTL_SECONDS: i64 = 600;
/// Default negative-cache TTL when a proxy leaves `not_found_ttl_seconds` unset.
const DEFAULT_NOT_FOUND_TTL_SECONDS: i64 = 600;
/// A published `(id, version)`'s manifest is immutable, so an upstream
/// `.nuspec` can be cached far longer than the version listing.
const NUSPEC_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// The upstream resource `@id`s resolved from a V3 service index, persisted as
/// the `proxy_upstream_index.resources` JSON and cached.
///
/// Stored absolute (the upstream advertises absolute `@id`s); we always keep a
/// trailing slash on the base-address style resources so we can append path
/// segments directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamResources {
    /// `PackageBaseAddress/3.0.0` base (flat container), trailing slash.
    pub package_base_address: Option<String>,
    /// `RegistrationsBaseUrl` base (any 3.x variant), trailing slash.
    pub registrations_base_url: Option<String>,
    /// `SearchQueryService` `@id` (any 3.x variant).
    pub search_query_service: Option<String>,
}

impl UpstreamResources {
    /// Resolve the resource `@id`s out of a V3 service-index JSON document.
    ///
    /// Picks the first match for each resource family, preferring exact
    /// `PackageBaseAddress/3.0.0` etc. but accepting any `@type` whose prefix
    /// matches (NuGet advertises versioned aliases like
    /// `SearchQueryService/3.5.0`).
    fn from_service_index(doc: &JsonValue) -> Self {
        let mut out = UpstreamResources {
            package_base_address: None,
            registrations_base_url: None,
            search_query_service: None,
        };
        let Some(resources) = doc.get("resources").and_then(|r| r.as_array()) else {
            return out;
        };
        for res in resources {
            let Some(id) = res.get("@id").and_then(|v| v.as_str()) else {
                continue;
            };
            // `@type` can be a string or an array of strings.
            let types: Vec<&str> = match res.get("@type") {
                Some(JsonValue::String(s)) => vec![s.as_str()],
                Some(JsonValue::Array(arr)) => arr.iter().filter_map(|v| v.as_str()).collect(),
                _ => continue,
            };
            for ty in types {
                let family = ty.split('/').next().unwrap_or(ty);
                match family {
                    "PackageBaseAddress" if out.package_base_address.is_none() => {
                        out.package_base_address = Some(with_trailing_slash(id));
                    }
                    "RegistrationsBaseUrl" if out.registrations_base_url.is_none() => {
                        out.registrations_base_url = Some(with_trailing_slash(id));
                    }
                    "SearchQueryService" if out.search_query_service.is_none() => {
                        out.search_query_service = Some(id.to_string());
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

fn with_trailing_slash(s: &str) -> String {
    if s.ends_with('/') {
        s.to_string()
    } else {
        format!("{s}/")
    }
}

/// Map an upstream transport/size/parse failure onto the read-path error.
fn upstream_err(e: UpstreamError) -> RepoError {
    RepoError::Storage(e.to_string())
}

/// Decrypted upstream Basic credentials, held only for one request.
struct Credentials {
    origin: Option<Origin>,
    username: String,
    password: forge_crypto::PlaintextSecret,
}

impl Credentials {
    fn auth(&self) -> UpstreamAuth<'_> {
        UpstreamAuth {
            origin: self.origin.clone(),
            username: &self.username,
            password: self.password.expose_secret(),
        }
    }
}

/// Storage-backed proxy read implementation.
///
/// Constructed per request (cheap: clones of shared handles) with the resolved
/// repository row already in hand, or via [`ProxyRepo::new`] which resolves the
/// row by name on each call.
pub struct ProxyRepo {
    pool: PgPool,
    format: Arc<dyn Format>,
    cas: Cas,
    cache: Cache,
    /// Pooled, timeout- and size-bounded upstream client.
    http: UpstreamHttp,
    /// Byte access to locally stored blobs (the cached `.nuspec`). `None` ⇒
    /// manifests are only served from upstream.
    blobs: Option<Arc<dyn BlobFetch>>,
    /// Envelope service decrypting the encrypted `upstream_password_enc`
    /// (slice 12.5). `None` ⇒ secret encryption is not configured; only the
    /// legacy plaintext column can be used and a row that holds an encrypted
    /// blob fails the fetch (fail closed — never a silent unauthenticated
    /// request against a credentialed upstream).
    envelope: Option<Arc<forge_crypto::service::EnvelopeService>>,
}

impl ProxyRepo {
    /// Build a proxy read facade over the process-wide default upstream client.
    pub fn new(pool: PgPool, format: Arc<dyn Format>, cas: Cas, cache: Cache) -> Self {
        ProxyRepo {
            pool,
            format,
            cas,
            cache,
            http: UpstreamHttp::shared_default(),
            blobs: None,
            envelope: None,
        }
    }

    /// Use `http` (built from the server's `[proxy]` config) for upstream
    /// traffic.
    pub fn with_http(mut self, http: UpstreamHttp) -> Self {
        self.http = http;
        self
    }

    /// Attach blob byte access so cached manifests can be served locally.
    pub fn with_blob_fetch(mut self, blobs: Arc<dyn BlobFetch>) -> Self {
        self.blobs = Some(blobs);
        self
    }

    /// Attach the envelope service so this proxy can decrypt an encrypted
    /// `upstream_password_enc` (slice 12.5). Without it, only legacy plaintext
    /// passwords work and encrypted rows fail closed.
    pub fn with_envelope(
        mut self,
        envelope: Option<Arc<forge_crypto::service::EnvelopeService>>,
    ) -> Self {
        self.envelope = envelope;
        self
    }

    /// Resolve the upstream password for the outbound Basic header — the
    /// **single sanctioned decrypt site** of the proxy credential (plan §2.4):
    /// an encrypted row decrypts through `forge_db::secret_dao` (re-reading the
    /// row so the AAD binds to fresh data); a not-yet-backfilled row falls back
    /// to the legacy plaintext column. Fail closed: an encrypted blob without a
    /// configured envelope service is an error, not an anonymous fetch.
    async fn upstream_password(
        &self,
        repo: &Repository,
    ) -> Result<Option<forge_crypto::PlaintextSecret>, RepoError> {
        match (&repo.upstream_password_enc, &self.envelope) {
            (Some(_), Some(envelope)) => {
                forge_db::secret_dao::get_upstream_password(&self.pool, envelope, repo.id)
                    .await
                    .map_err(|e| RepoError::Storage(format!("decrypt upstream password: {e}")))
            }
            (Some(_), None) => Err(RepoError::Storage(
                "repository stores an encrypted upstream password but secret encryption is not \
                 configured (missing [crypto] config)"
                    .into(),
            )),
            (None, _) => Ok(repo
                .upstream_password
                .clone()
                .map(forge_crypto::PlaintextSecret::from)),
        }
    }

    /// The Basic credentials for `repo`'s upstream, if both a username and a
    /// password are configured.
    async fn credentials(&self, repo: &Repository) -> Result<Option<Credentials>, RepoError> {
        let Some(username) = repo.upstream_username.clone() else {
            return Ok(None);
        };
        let Some(password) = self.upstream_password(repo).await? else {
            return Ok(None);
        };
        Ok(Some(Credentials {
            origin: repo.remote_url.as_deref().and_then(Origin::of),
            username,
            password,
        }))
    }

    /// GET an upstream JSON document with the proxy's credentials. `None` on
    /// a genuine 404.
    async fn fetch_json(
        &self,
        repo: &Repository,
        url: &str,
    ) -> Result<Option<JsonValue>, RepoError> {
        let creds = self.credentials(repo).await?;
        let auth = creds.as_ref().map(Credentials::auth);
        self.http
            .get_json(url, auth.as_ref())
            .await
            .map_err(upstream_err)
    }

    /// Resolve the repository row by name, erroring if missing or not a proxy.
    async fn proxy_repo(&self, repo: &str) -> Result<Repository, RepoError> {
        let row = repository_dao::find_repository_by_name(&self.pool, repo)
            .await?
            .ok_or_else(|| RepoError::RepoNotFound(repo.to_string()))?;
        if row.kind() != forge_db::model::RepoKind::Proxy {
            return Err(RepoError::WrongKind {
                name: repo.to_string(),
                kind: row.kind.clone(),
            });
        }
        Ok(row)
    }

    fn metadata_ttl(repo: &Repository) -> Duration {
        Duration::seconds(
            repo.metadata_ttl_seconds
                .map(i64::from)
                .unwrap_or(DEFAULT_METADATA_TTL_SECONDS)
                .max(0),
        )
    }

    fn not_found_ttl(repo: &Repository) -> Duration {
        Duration::seconds(
            repo.not_found_ttl_seconds
                .map(i64::from)
                .unwrap_or(DEFAULT_NOT_FOUND_TTL_SECONDS),
        )
    }

    /// Whether a version with the given `first_seen_at` has cleared the proxy's
    /// package-delay window and may now be served/enumerated.
    fn delay_cleared(repo: &Repository, first_seen_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        let delay = Duration::seconds(i64::from(repo.package_delay_seconds));
        now - first_seen_at >= delay
    }

    // ── Upstream service-index discovery (Task 8.1) ──────────────────────────

    /// Resolve the upstream resource `@id`s for `repo`, reading through the
    /// cache (L1/L2) and persisting to `proxy_upstream_index`.
    ///
    /// Layering:
    /// 1. **Cache** (`get_or_try_insert_with`, TTL = metadata_ttl) — per-instance
    ///    coalescing + short-circuit; a 2nd call within TTL never touches DB or
    ///    upstream.
    /// 2. **DB freshness** — on an L1 miss, if `proxy_upstream_index.fetched_at`
    ///    is within metadata_ttl, reuse it without a network call.
    /// 3. **Refresh** — otherwise fetch the upstream index (no DB transaction
    ///    or row lock held across the request), resolve the `@id`s, and
    ///    upsert them. Concurrent instances may both refresh; the result is
    ///    idempotent.
    ///
    /// The cache key includes the repository id and `remote_url` so a changed
    /// upstream (or a deleted-and-recreated repository) never serves the old
    /// upstream's resources.
    pub async fn resolve_upstream_index(
        &self,
        repo: &Repository,
    ) -> Result<UpstreamResources, RepoError> {
        let ttl = Self::metadata_ttl(repo);
        let remote_url = repo
            .remote_url
            .clone()
            .ok_or_else(|| RepoError::Storage("proxy repository has no remote_url".into()))?;
        let key = format!("{}/{}/{}", repo.name, repo.id, remote_url);

        // The cache factory error must be `Clone` (moka coalescing shares an
        // `Arc<E>` across waiters); `RepoError` wraps non-`Clone` `sqlx::Error`,
        // so the factory yields a `String` and we re-wrap it on the way out.
        self.cache
            .get_or_try_insert_with(
                NS_UPSTREAM_INDEX,
                &key,
                ttl.to_std().unwrap_or_default(),
                || async {
                    self.resolve_index_uncached(repo, ttl, &remote_url)
                        .await
                        .map_err(|e| e.to_string())
                },
            )
            .await
            .map_err(RepoError::Storage)
    }

    /// The uncached body of [`Self::resolve_upstream_index`]: DB-freshness
    /// short-circuit, offline handling, and refetch.
    async fn resolve_index_uncached(
        &self,
        repo: &Repository,
        ttl: Duration,
        remote_url: &str,
    ) -> Result<UpstreamResources, RepoError> {
        let persisted = proxy_dao::get_upstream_index(&self.pool, repo.id).await?;
        if let Some(idx) = &persisted {
            if Utc::now() - idx.fetched_at < ttl {
                return Ok(parse_resources(idx.resources.clone()));
            }
        }

        // Offline: never fetch. Serve a persisted (possibly stale) index if present.
        if !repo.online {
            return match persisted {
                Some(idx) => Ok(parse_resources(idx.resources)),
                None => Err(RepoError::Storage(
                    "proxy is offline and has no cached upstream index".into(),
                )),
            };
        }

        let doc = match self.fetch_json(repo, remote_url).await {
            Ok(Some(doc)) => doc,
            Ok(None) => {
                return Err(RepoError::Storage(format!(
                    "upstream service index {remote_url} returned 404"
                )))
            }
            Err(e) => {
                // A stale persisted index is better than failing every read
                // while the upstream is briefly unreachable.
                if let Some(idx) = persisted {
                    tracing::warn!(repo = %repo.name, error = %e, "upstream index refresh failed; serving stale index");
                    return Ok(parse_resources(idx.resources));
                }
                return Err(e);
            }
        };
        let resources = UpstreamResources::from_service_index(&doc);
        let resources_json = serde_json::to_value(&resources)
            .map_err(|e| RepoError::Storage(format!("serialize resources: {e}")))?;

        sqlx::query!(
            r#"
            INSERT INTO proxy_upstream_index (repository_id, resources, fetched_at, etag)
            VALUES ($1, $2, now(), NULL)
            ON CONFLICT (repository_id)
            DO UPDATE SET resources = EXCLUDED.resources, fetched_at = EXCLUDED.fetched_at, etag = EXCLUDED.etag
            "#,
            repo.id,
            resources_json,
        )
        .execute(&self.pool)
        .await?;

        Ok(resources)
    }

    // ── Metadata discovery: enumerate upstream versions (Task 8.2) ───────────

    /// Discover the upstream versions of `lower_id`, recording each as a
    /// `proxy_cached_version` (first sighting stamps `first_seen_at`). Returns
    /// the recorded rows (post-upsert) for the caller to delay-gate.
    ///
    /// The upstream listing is fetched at most once per metadata TTL (the
    /// fresh marker lives in the shared cache, so it also coalesces concurrent
    /// requests). Offline ⇒ serves only existing cached rows; a genuine
    /// upstream 404 sets the negative cache on a synthetic row and returns
    /// empty.
    async fn discover_versions(
        &self,
        repo: &Repository,
        lower_id: &str,
    ) -> Result<Vec<forge_db::model::ProxyCachedVersion>, RepoError> {
        // Offline: only what we already cached.
        if !repo.online {
            return self.cached_rows(repo.id, lower_id).await;
        }

        let ttl = Self::metadata_ttl(repo).to_std().unwrap_or_default();
        let key = format!("{}/{}/{lower_id}", repo.name, repo.id);
        let refreshed = self
            .cache
            .get_or_try_insert_with(NS_UPSTREAM_VERSIONS, &key, ttl, || async {
                Box::pin(self.refresh_versions(repo, lower_id))
                    .await
                    .map_err(|e| e.to_string())
            })
            .await;
        match refreshed {
            Ok(true) => self.cached_rows(repo.id, lower_id).await,
            Ok(false) => Ok(Vec::new()),
            Err(e) => {
                // Upstream unreachable: degrade to what is already cached
                // locally rather than failing a restore that could be served.
                let rows = self.cached_rows(repo.id, lower_id).await?;
                if rows.is_empty() {
                    return Err(RepoError::Storage(e));
                }
                tracing::warn!(repo = %repo.name, id = %lower_id, error = %e, "upstream version listing failed; serving cached versions");
                Ok(rows)
            }
        }
    }

    /// Fetch the upstream flat-container listing for `lower_id` and record
    /// every version. Returns `false` when the upstream does not know the id.
    async fn refresh_versions(&self, repo: &Repository, lower_id: &str) -> Result<bool, RepoError> {
        let resources = Box::pin(self.resolve_upstream_index(repo)).await?;
        let Some(base) = resources.package_base_address else {
            return Ok(true);
        };
        let url = format!("{base}{lower_id}/index.json");
        match self.fetch_json(repo, &url).await? {
            Some(doc) => {
                let versions: Vec<String> = doc
                    .get("versions")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .filter_map(|raw| self.format.normalize_version(raw).ok())
                            .collect()
                    })
                    .unwrap_or_default();

                // Record each version's first sighting (idempotent, one round-trip).
                proxy_dao::upsert_cached_versions(&self.pool, repo.id, lower_id, &versions).await?;
                Ok(true)
            }
            None => {
                // Genuine upstream 404 for the whole package id → negative cache.
                // We model it on a synthetic `*` version row so a later request
                // can short-circuit without re-hitting upstream within the TTL.
                self.mark_not_found(repo.id, lower_id, "*").await?;
                Ok(false)
            }
        }
    }

    /// Fetch all cached-version rows for `(repo, lower_id)` except the synthetic
    /// negative-cache marker (`version = "*"`).
    async fn cached_rows(
        &self,
        repo_id: i64,
        lower_id: &str,
    ) -> Result<Vec<forge_db::model::ProxyCachedVersion>, RepoError> {
        let rows = sqlx::query_as!(
            forge_db::model::ProxyCachedVersion,
            r#"
            SELECT id, repository_id, name, version, listed, first_seen_at,
                   downloaded, metadata_refreshed_at, not_found, not_found_at
            FROM proxy_cached_version
            WHERE repository_id = $1 AND name = $2 AND version <> '*'
            "#,
            repo_id,
            lower_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Whether a genuine-404 negative-cache marker for `(repo, lower_id)` is
    /// still valid (within `not_found_ttl`).
    async fn negative_cached(
        &self,
        repo: &Repository,
        lower_id: &str,
        version: &str,
    ) -> Result<bool, RepoError> {
        let row = proxy_dao::get_cached_version(&self.pool, repo.id, lower_id, version).await?;
        let Some(row) = row else { return Ok(false) };
        if !row.not_found {
            return Ok(false);
        }
        let Some(at) = row.not_found_at else {
            return Ok(false);
        };
        Ok(Utc::now() - at < Self::not_found_ttl(repo))
    }

    /// Write/refresh a genuine-404 negative-cache marker.
    async fn mark_not_found(
        &self,
        repo_id: i64,
        lower_id: &str,
        version: &str,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            INSERT INTO proxy_cached_version
                (repository_id, name, version, listed, downloaded, not_found, not_found_at)
            VALUES ($1, $2, $3, false, false, true, now())
            ON CONFLICT (repository_id, name, version)
            DO UPDATE SET not_found = true, not_found_at = now()
            "#,
            repo_id,
            lower_id,
            version,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Read-through download with row-lock singleflight (Task 8.2) ──────────

    /// Ensure the `.nupkg` for `(lower_id, version)` is cached locally, fetching
    /// it from upstream under a row-lock singleflight if needed. Returns the
    /// local [`NupkgLocation`], or `None` if the upstream lacks it (genuine 404)
    /// or it is delay-gated.
    async fn ensure_downloaded(
        &self,
        repo: &Repository,
        lower_id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        // Already cached + downloaded + delay-cleared? Serve immediately.
        if let Some(row) =
            proxy_dao::get_cached_version(&self.pool, repo.id, lower_id, version).await?
        {
            if row.downloaded {
                if !Self::delay_cleared(repo, row.first_seen_at, Utc::now()) {
                    return Ok(None);
                }
                return self.local_nupkg(repo.id, lower_id, version).await;
            }
            // A still-valid genuine-404 marker short-circuits (no upstream call).
            if row.not_found {
                if let Some(at) = row.not_found_at {
                    if Utc::now() - at < Self::not_found_ttl(repo) {
                        return Ok(None);
                    }
                }
            }
        }

        // Offline and not yet downloaded ⇒ nothing to serve.
        if !repo.online {
            return Ok(None);
        }

        // Singleflight: guarantee a row exists, then lock it FOR UPDATE so
        // concurrent first-time downloads collapse to one upstream fetch.
        proxy_dao::upsert_cached_version(
            &self.pool,
            NewProxyCachedVersion {
                repository_id: repo.id,
                name: lower_id.to_string(),
                version: version.to_string(),
                listed: true,
                downloaded: false,
                not_found: false,
            },
        )
        .await?;

        // ── Singleflight gate (short tx, NO network/S3 held under the lock) ──
        //
        // Addendum A7: never hold a DB transaction across an S3/network call.
        // We therefore split the work into three phases:
        //   1. a short tx that locks the row, re-checks state, and decides
        //      whether this caller must perform the upstream fetch — then
        //      *commits immediately*, releasing the row lock;
        //   2. the bounded network I/O (upstream HTTP fetch streamed into a
        //      CAS temp file) and the S3 PUT, with NO transaction held;
        //   3. a second short tx that re-locks the row, re-checks (a racing
        //      caller may have finished in the meantime), and finalizes.
        let first_seen_at = {
            let mut tx = self.pool.begin().await?;
            let locked =
                proxy_dao::lock_cached_version_for_update(&mut tx, repo.id, lower_id, version)
                    .await?
                    .ok_or_else(|| {
                        RepoError::Storage("cached-version row vanished under lock".into())
                    })?;

            // A racing caller already finished the fetch.
            if locked.downloaded {
                tx.commit().await?;
                if !Self::delay_cleared(repo, locked.first_seen_at, Utc::now()) {
                    return Ok(None);
                }
                return self.local_nupkg(repo.id, lower_id, version).await;
            }
            // A still-valid genuine-404 marker short-circuits (no upstream call).
            if locked.not_found {
                if let Some(at) = locked.not_found_at {
                    if Utc::now() - at < Self::not_found_ttl(repo) {
                        tx.commit().await?;
                        return Ok(None);
                    }
                }
            }

            // This caller will perform the fetch; release the lock first.
            tx.commit().await?;
            locked.first_seen_at
        };

        // ── Network I/O — performed with NO transaction held (A7). ───────────
        let resources = self.resolve_upstream_index(repo).await?;
        let Some(base) = resources.package_base_address else {
            return Err(RepoError::Storage(
                "upstream advertises no PackageBaseAddress".into(),
            ));
        };

        // NuGet flat-container nupkg path: {base}{id}/{version}/{id}.{version}.nupkg
        let url = format!("{base}{lower_id}/{version}/{lower_id}.{version}.nupkg");
        // §12.5: decrypt-on-use; the plaintext lives only inside this request
        // (and the zeroizing secret wrapper) — never in a log or model.
        let resp = {
            let creds = self.credentials(repo).await?;
            let auth = creds.as_ref().map(Credentials::auth);
            self.http
                .get(&url, RequestClass::Download, auth.as_ref())
                .await
                .map_err(upstream_err)?
        };

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            // Genuine upstream 404 → negative cache on this exact version row.
            // Short tx; re-lock and only set the marker if no racing caller has
            // since downloaded it.
            let mut tx = self.pool.begin().await?;
            if let Some(row) =
                proxy_dao::lock_cached_version_for_update(&mut tx, repo.id, lower_id, version)
                    .await?
            {
                if !row.downloaded {
                    sqlx::query!(
                        r#"UPDATE proxy_cached_version SET not_found = true, not_found_at = now() WHERE id = $1"#,
                        row.id
                    )
                    .execute(&mut *tx)
                    .await?;
                }
            }
            tx.commit().await?;
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(RepoError::Storage(format!(
                "upstream nupkg fetch {url} returned {}",
                resp.status()
            )));
        }

        // Stream the body straight into a CAS temp file (size-capped while
        // copying; never buffered in memory).
        let max_bytes = self.http.config().max_package_bytes;
        if resp.content_length().is_some_and(|len| len > max_bytes) {
            return Err(RepoError::Storage(format!(
                "upstream nupkg {url} exceeds {max_bytes} bytes"
            )));
        }
        let body = futures_util::TryStreamExt::map_err(resp.bytes_stream(), std::io::Error::other);
        let reader = tokio_util::io::StreamReader::new(body);
        let staged = self
            .cas
            .stage(reader, max_bytes)
            .await
            .map_err(|e| match e {
                CasError::TooLarge { limit } => {
                    RepoError::Storage(format!("upstream nupkg {url} exceeds {limit} bytes"))
                }
                other => RepoError::Storage(format!("read upstream nupkg {url}: {other}")),
            })?;

        // Parse from the temp file on the blocking pool to obtain the canonical
        // identity and the manifest.
        let parsed = {
            let format = self.format.clone();
            let path = staged.temp_path.to_path_buf();
            tokio::task::spawn_blocking(move || {
                let mut file = std::fs::File::open(&path)?;
                format
                    .parse_upload(&mut file)
                    .map_err(|e| std::io::Error::other(e.to_string()))
            })
            .await
            .map_err(|e| RepoError::Storage(format!("parse upstream nupkg: {e}")))?
            .map_err(|e| RepoError::Storage(format!("parse upstream nupkg: {e}")))?
        };
        // Never cache a package under an identity it does not carry: a
        // misbehaving upstream must not be able to plant `evil 1.0.0` bytes at
        // `good/1.0.0`.
        if parsed.id != lower_id || parsed.version != version {
            return Err(RepoError::Storage(format!(
                "upstream nupkg at {url} identifies as {} {}",
                parsed.id, parsed.version
            )));
        }

        // Promote into CAS (dedup applies across repos). S3 PUT — still NO tx.
        let stored = self
            .cas
            .commit(staged)
            .await
            .map_err(|e| RepoError::Storage(format!("cas store upstream nupkg: {e}")))?;
        let nuspec = self
            .cas
            .store(Cursor::new(parsed.nuspec_bytes.clone()), max_bytes)
            .await
            .map_err(|e| RepoError::Storage(format!("cas store upstream nuspec: {e}")))?;

        let size = i64::try_from(stored.size)
            .map_err(|_| RepoError::Storage("nupkg size overflow".into()))?;
        let nuspec_size = i64::try_from(nuspec.size)
            .map_err(|_| RepoError::Storage("nuspec size overflow".into()))?;

        // ── Finalize (short tx) — re-lock, re-check, attach, mark downloaded. ─
        let mut tx = self.pool.begin().await?;
        let locked = proxy_dao::lock_cached_version_for_update(&mut tx, repo.id, lower_id, version)
            .await?
            .ok_or_else(|| RepoError::Storage("cached-version row vanished under lock".into()))?;

        // A racing caller finished while we were fetching. The blob we stored is
        // already on disk (CAS dedup); just roll back and serve the local copy.
        if locked.downloaded {
            tx.rollback().await?;
            if !Self::delay_cleared(repo, locked.first_seen_at, Utc::now()) {
                return Ok(None);
            }
            return self.local_nupkg(repo.id, lower_id, version).await;
        }

        // Insert the component if it is not already present (a prior metadata
        // discovery never inserts components, so normally absent here).
        let comp = match component_dao::find_component(&mut *tx, repo.id, lower_id, version).await?
        {
            Some(c) => c,
            None => {
                component_dao::insert_component(
                    &mut *tx,
                    NewComponent {
                        repository_id: repo.id,
                        name: lower_id.to_string(),
                        original_id: parsed.original_id.clone(),
                        version: version.to_string(),
                        version_original: parsed.version_original.clone(),
                        listed: true,
                    },
                )
                .await?
            }
        };

        // Attach the .nupkg / .nuspec assets if absent. Each blob reference is
        // taken only when its asset row is actually inserted; an unused ingest
        // lease simply expires.
        if asset_dao::find_asset(&mut *tx, comp.id, NUPKG_ASSET_PATH)
            .await?
            .is_none()
        {
            blob_dao::commit_ingest_and_incref(&mut tx, &stored.sha256, stored.ingest_token)
                .await?;
            asset_dao::insert_asset(
                &mut *tx,
                NewAsset {
                    component_id: comp.id,
                    path: NUPKG_ASSET_PATH.to_string(),
                    content_type: NUPKG_CONTENT_TYPE.to_string(),
                    blob_sha256: stored.sha256.clone(),
                    size,
                    sha512_base64: Some(stored.sha512_base64.clone()),
                },
            )
            .await?;
        }
        if asset_dao::find_asset(&mut *tx, comp.id, NUSPEC_ASSET_PATH)
            .await?
            .is_none()
        {
            blob_dao::commit_ingest_and_incref(&mut tx, &nuspec.sha256, nuspec.ingest_token)
                .await?;
            asset_dao::insert_asset(
                &mut *tx,
                NewAsset {
                    component_id: comp.id,
                    path: NUSPEC_ASSET_PATH.to_string(),
                    content_type: NUSPEC_CONTENT_TYPE.to_string(),
                    blob_sha256: nuspec.sha256.clone(),
                    size: nuspec_size,
                    sha512_base64: None,
                },
            )
            .await?;
        }

        sqlx::query!(
            r#"UPDATE proxy_cached_version SET downloaded = true, not_found = false, not_found_at = NULL WHERE id = $1"#,
            locked.id
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        // Delay gate on the recorded first sighting.
        if !Self::delay_cleared(repo, first_seen_at, Utc::now()) {
            return Ok(None);
        }
        self.local_nupkg(repo.id, lower_id, version).await
    }

    /// Resolve the locally-stored `.nupkg` location for a cached version.
    async fn local_nupkg(
        &self,
        repo_id: i64,
        lower_id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        let Some(comp) =
            component_dao::find_component(&self.pool, repo_id, lower_id, version).await?
        else {
            return Ok(None);
        };
        let Some(asset) = asset_dao::find_asset(&self.pool, comp.id, NUPKG_ASSET_PATH).await?
        else {
            return Ok(None);
        };
        let Some(blob) = blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? else {
            return Ok(None);
        };
        Ok(Some(NupkgLocation {
            blob_s3_key: blob.s3_key,
            size: asset.size,
            content_type: asset.content_type,
        }))
    }

    /// The locally cached `.nuspec` of a downloaded version, if stored.
    async fn local_nuspec(
        &self,
        repo_id: i64,
        lower_id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        let Some(blobs) = &self.blobs else {
            return Ok(None);
        };
        let Some(comp) =
            component_dao::find_component(&self.pool, repo_id, lower_id, version).await?
        else {
            return Ok(None);
        };
        let Some(asset) = asset_dao::find_asset(&self.pool, comp.id, NUSPEC_ASSET_PATH).await?
        else {
            return Ok(None);
        };
        let Some(blob) = blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? else {
            return Ok(None);
        };
        Ok(Some(blobs.fetch_all(&blob.s3_key).await?))
    }

    /// Fetch the upstream `.nuspec` for a known, not-yet-downloaded version.
    /// Cached (L1/L2) — a published manifest never changes.
    async fn upstream_nuspec(
        &self,
        repo: &Repository,
        lower_id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        let key = format!("{}/{}/{lower_id}/{version}", repo.name, repo.id);
        let fetched: Result<Option<Vec<u8>>, String> = self
            .cache
            .get_or_try_insert_with(NS_UPSTREAM_NUSPEC, &key, NUSPEC_CACHE_TTL, || async {
                let resources = Box::pin(self.resolve_upstream_index(repo))
                    .await
                    .map_err(|e| e.to_string())?;
                let Some(base) = resources.package_base_address else {
                    return Ok(None);
                };
                let url = format!("{base}{lower_id}/{version}/{lower_id}.nuspec");
                let creds = self.credentials(repo).await.map_err(|e| e.to_string())?;
                let auth = creds.as_ref().map(Credentials::auth);
                self.http
                    .get_bytes(&url, auth.as_ref())
                    .await
                    .map_err(|e| e.to_string())
            })
            .await;
        fetched.map_err(RepoError::Storage)
    }

    /// Search the locally known proxy corpus once, applying authorization
    /// before total-count calculation and client paging. The id substring
    /// filter runs in PostgreSQL so a large proxy cache is not loaded whole.
    async fn search_filtered(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        let now = Utc::now();
        let q = params.q.trim().to_lowercase();
        let rows = sqlx::query_as!(
            forge_db::model::ProxyCachedVersion,
            r#"
            SELECT id, repository_id, name, version, listed, first_seen_at,
                   downloaded, metadata_refreshed_at, not_found, not_found_at
            FROM proxy_cached_version
            WHERE repository_id = $1 AND version <> '*' AND not_found = false
              AND listed AND ($2 = '' OR strpos(name, $2) > 0)
            ORDER BY name
            "#,
            repo_row.id,
            q,
        )
        .fetch_all(&self.pool)
        .await?;

        use std::collections::BTreeMap;
        let mut by_id: BTreeMap<String, Vec<forge_db::model::ProxyCachedVersion>> = BTreeMap::new();
        for r in rows {
            if !Self::delay_cleared(&repo_row, r.first_seen_at, now) || !filter.allows(&r.name) {
                continue;
            }
            by_id.entry(r.name.clone()).or_default().push(r);
        }

        let mut hits: Vec<SearchHit> = Vec::new();
        for (_name, rows) in by_id {
            let mut versions: Vec<VersionEntry> = rows
                .into_iter()
                .filter(|r| params.prerelease || !is_prerelease(&r.version))
                .map(|r| VersionEntry {
                    original_id: r.name.clone(),
                    version: r.version.clone(),
                    version_original: r.version,
                    listed: r.listed,
                })
                .collect();
            versions.sort_by(|a, b| self.format.compare_versions(&a.version, &b.version));
            if versions.is_empty() {
                continue;
            }
            let latest = versions.last().expect("non-empty versions");
            hits.push(SearchHit {
                original_id: latest.original_id.clone(),
                latest_version: latest.version.clone(),
                versions,
            });
        }
        hits.sort_by(|a, b| a.original_id.cmp(&b.original_id));

        let total_hits = hits.len();
        let hits = hits
            .into_iter()
            .skip(params.skip.min(total_hits))
            .take(params.effective_take())
            .collect();
        Ok(SearchResult { total_hits, hits })
    }
}

/// Fire a best-effort proxy download-tracking bump off the response hot path
/// (slice 12.1 §3.7). Failures are logged, not propagated — the data only feeds
/// retention's download-sensitive criteria and is non-authoritative.
fn spawn_proxy_download_bump(pool: PgPool, repo_id: i64, name: String, version: String) {
    tokio::spawn(async move {
        if let Err(e) =
            forge_db::download_dao::bump_proxy_download_by_name(&pool, repo_id, &name, &version)
                .await
        {
            tracing::warn!(error = %e, repo_id, %name, %version, "proxy download tracking bump failed");
        }
    });
}

/// Parse a stored `resources` JSON into [`UpstreamResources`], tolerating a
/// shape mismatch by falling back to an empty resource set.
fn parse_resources(value: JsonValue) -> UpstreamResources {
    serde_json::from_value::<UpstreamResources>(value).unwrap_or(UpstreamResources {
        package_base_address: None,
        registrations_base_url: None,
        search_query_service: None,
    })
}

/// A normalized NuGet version is prerelease iff it carries a `-label` suffix.
fn is_prerelease(version: &str) -> bool {
    version.contains('-')
}

#[async_trait]
impl RepoReadOps for ProxyRepo {
    async fn list_versions(&self, repo: &str, id: &str) -> Result<Vec<VersionEntry>, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        let lower = self.format.lower_id(id);

        // Honor a still-valid genuine-404 negative cache for the whole id.
        if self.negative_cached(&repo_row, &lower, "*").await? {
            return Ok(Vec::new());
        }

        let rows = self.discover_versions(&repo_row, &lower).await?;
        let now = Utc::now();
        let mut versions: Vec<VersionEntry> = rows
            .into_iter()
            .filter(|r| !r.not_found)
            .filter(|r| Self::delay_cleared(&repo_row, r.first_seen_at, now))
            .map(|r| VersionEntry {
                original_id: r.name.clone(),
                version: r.version.clone(),
                version_original: r.version.clone(),
                listed: r.listed,
            })
            .collect();
        versions.sort_by(|a, b| self.format.compare_versions(&a.version, &b.version));
        Ok(versions)
    }

    async fn resolve_nupkg(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        let lower = self.format.lower_id(id);
        let norm = self
            .format
            .normalize_version(version)
            .map_err(|e| RepoError::Storage(format!("normalize version: {e}")))?;
        let loc = Box::pin(self.ensure_downloaded(&repo_row, &lower, &norm)).await?;
        if loc.is_some() {
            // Download tracking (slice 12.1 §3.7): a served cached `.nupkg` is a
            // pull. Stamp `proxy_cached_version.last_downloaded_at` (drives the
            // proxy "not pulled in X days" eviction) + mirror onto the parallel
            // component/asset. Best-effort, off the hot path — never blocks or
            // fails the download.
            spawn_proxy_download_bump(self.pool.clone(), repo_row.id, lower, norm);
        }
        Ok(loc)
    }

    /// Serve the manifest of a proxied version: the locally stored `.nuspec`
    /// once the package is cached, otherwise the upstream's flat-container
    /// `.nuspec` (without downloading the whole package). Delay-gated and
    /// negative-cached exactly like the version listing.
    async fn resolve_nuspec(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        let lower = self.format.lower_id(id);
        let Ok(norm) = self.format.normalize_version(version) else {
            return Ok(None);
        };

        if let Some(row) =
            proxy_dao::get_cached_version(&self.pool, repo_row.id, &lower, &norm).await?
        {
            if !row.not_found && !Self::delay_cleared(&repo_row, row.first_seen_at, Utc::now()) {
                return Ok(None);
            }
            if row.downloaded {
                if let Some(bytes) = self.local_nuspec(repo_row.id, &lower, &norm).await? {
                    return Ok(Some(bytes));
                }
            }
        }

        if self.negative_cached(&repo_row, &lower, "*").await? {
            return Ok(None);
        }
        // The version must be known upstream (and past its delay window).
        let known = Box::pin(self.discover_versions(&repo_row, &lower))
            .await?
            .into_iter()
            .any(|r| {
                r.version == norm
                    && !r.not_found
                    && Self::delay_cleared(&repo_row, r.first_seen_at, Utc::now())
            });
        if !known {
            return Ok(None);
        }
        if repo_row.online {
            if let Some(bytes) = Box::pin(self.upstream_nuspec(&repo_row, &lower, &norm)).await? {
                return Ok(Some(bytes));
            }
        }
        // Upstream serves no manifest (or we are offline): fall back to the
        // package itself, which also caches the manifest locally.
        if Box::pin(self.ensure_downloaded(&repo_row, &lower, &norm))
            .await?
            .is_some()
        {
            return self.local_nuspec(repo_row.id, &lower, &norm).await;
        }
        Ok(None)
    }

    async fn registration(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        let lower = self.format.lower_id(id);

        if self.negative_cached(&repo_row, &lower, "*").await? {
            return Ok(Vec::new());
        }

        let rows = self.discover_versions(&repo_row, &lower).await?;
        let now = Utc::now();
        let mut visible: Vec<forge_db::model::ProxyCachedVersion> = rows
            .into_iter()
            .filter(|r| !r.not_found)
            .filter(|r| Self::delay_cleared(&repo_row, r.first_seen_at, now))
            .collect();
        visible.sort_by(|a, b| self.format.compare_versions(&a.version, &b.version));

        let mut out = Vec::with_capacity(visible.len());
        for r in visible {
            // packageHash + dependency groups are known only for downloaded
            // versions; others are served without them (avoids a fetch per
            // entry).
            let (hash, nuspec) = if r.downloaded {
                match component_dao::find_component(&self.pool, repo_row.id, &r.name, &r.version)
                    .await?
                {
                    Some(comp) => {
                        let asset =
                            asset_dao::find_asset(&self.pool, comp.id, NUPKG_ASSET_PATH).await?;
                        let nuspec = self
                            .local_nuspec(repo_row.id, &r.name, &r.version)
                            .await
                            .unwrap_or_else(|e| {
                                tracing::warn!(error = %e, id = %r.name, version = %r.version, "cached nuspec read failed");
                                None
                            });
                        (asset.and_then(|a| a.sha512_base64), nuspec)
                    }
                    None => (None, None),
                }
            } else {
                (None, None)
            };
            out.push(RegistrationEntry {
                original_id: r.name.clone(),
                version: r.version.clone(),
                listed: r.listed,
                package_hash_sha512_base64: hash,
                nuspec_bytes: nuspec,
            });
        }
        Ok(out)
    }

    async fn search(&self, repo: &str, params: &SearchParams) -> Result<SearchResult, RepoError> {
        self.search_filtered(repo, params, &PackageFilter::AllowAll)
            .await
    }

    async fn search_with_package_filter(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        self.search_filtered(repo, params, filter).await
    }
}
