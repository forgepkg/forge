//! Proxy-repository read operations (spec §7 "Proxy", plan Phase 8).
//!
//! A proxy repository mirrors an upstream NuGet **V3 service index** named by
//! `repository.remote_url`. On a read miss it discovers the upstream's resource
//! `@id`s, fetches metadata/artifacts on demand, content-addresses the bytes
//! through the [`Cas`], and records a `proxy_cached_version` row so future reads
//! are served locally.
//!
//! ## Hard invariants enforced here
//! * **SSRF guard** — every upstream request goes through
//!   [`crate::net::ssrf::guarded_client`], honoring the per-proxy
//!   `allow_private_upstream` flag; redirects are re-validated per hop.
//! * **NO advisory locks** — first-time fetch singleflight is a plain row lock:
//!   [`proxy_dao::upsert_cached_version`] (INSERT … ON CONFLICT DO NOTHING) to
//!   guarantee a row exists, then [`proxy_dao::lock_cached_version_for_update`]
//!   (SELECT … FOR UPDATE). The lock is held only for the short state-decision
//!   and finalize transactions; it is **released before** the upstream HTTP
//!   fetch and the CAS/S3 PUT (Addendum A7 — never hold a DB tx across a
//!   network/S3 call). The singleflight is therefore best-effort: under
//!   contention more than one caller may fetch from upstream, but the CAS is
//!   content-addressed and the finalize tx re-checks `downloaded`, so
//!   concurrent fetches converge on identical state.
//!   Upstream-index refresh serializes on a `SELECT … FOR UPDATE` of the proxy
//!   `repository` row (spec A11).
//! * **Package delay** — a version discovered from upstream is recorded with
//!   `first_seen_at = now()` but is **not** served until
//!   `now − first_seen_at ≥ package_delay_seconds`. Inside the window it is
//!   omitted from enumeration/registration/search and direct download 404s. A
//!   delay-gated 404 is **never** written to the not-found negative cache.
//! * **Negative cache** — a genuine upstream 404 sets `not_found = true` +
//!   `not_found_at = now()`, honored for `not_found_ttl_seconds`.
//! * **Offline** — `repository.online == false` serves only already-cached data;
//!   no upstream requests are made.

use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use forge_cache::Cache;
use forge_db::asset_dao::{self, NewAsset};
use forge_db::component_dao::{self, NewComponent};
use forge_db::model::Repository;
use forge_db::proxy_dao::{self, NewProxyCachedVersion};
use forge_db::{blob_dao, repository_dao};
use forge_storage::Cas;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;

use crate::format::Format;
use crate::net::ssrf::{guarded_client, IpResolver, SystemResolver};
use crate::repo::{
    NupkgLocation, RegistrationEntry, RepoError, RepoReadOps, SearchHit, SearchParams,
    SearchResult, VersionEntry, NUPKG_ASSET_PATH, NUPKG_CONTENT_TYPE,
};

/// Cache namespace for resolved upstream service indexes, keyed by repo name.
const NS_UPSTREAM_INDEX: &str = "proxy_index";

/// Default metadata TTL when a proxy leaves `metadata_ttl_seconds` unset.
const DEFAULT_METADATA_TTL_SECONDS: i64 = 600;
/// Default negative-cache TTL when a proxy leaves `not_found_ttl_seconds` unset.
const DEFAULT_NOT_FOUND_TTL_SECONDS: i64 = 600;

/// Upper bound on a fetched upstream metadata document (service index, flat
/// container listing). Generous, but bounds memory against a hostile upstream.
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;

/// Upper bound on a proxied `.nupkg` artifact fetched from upstream. Bounds
/// memory/disk against a hostile or misconfigured upstream.
const MAX_NUPKG_BYTES: u64 = 512 * 1024 * 1024;

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
    resolver: Arc<dyn IpResolver>,
    /// Grace period passed to blob deref (unused on the read path today, kept for
    /// symmetry with the hosted facade should proxy eviction land later).
    #[allow(dead_code)]
    delete_grace: Duration,
    /// Envelope service decrypting the encrypted `upstream_password_enc`
    /// (slice 12.5). `None` ⇒ secret encryption is not configured; only the
    /// legacy plaintext column can be used and a row that holds an encrypted
    /// blob fails the fetch (fail closed — never a silent unauthenticated
    /// request against a credentialed upstream).
    envelope: Option<Arc<forge_crypto::service::EnvelopeService>>,
}

impl ProxyRepo {
    /// Build a proxy read facade using the default system DNS resolver for the
    /// SSRF guard.
    pub fn new(pool: PgPool, format: Arc<dyn Format>, cas: Cas, cache: Cache) -> Self {
        Self::with_resolver(pool, format, cas, cache, Arc::new(SystemResolver))
    }

    /// Build a proxy read facade with an injectable DNS resolver (tests pin
    /// upstream hostnames to loopback while keeping the SSRF policy honest by
    /// flipping `allow_private_upstream`).
    pub fn with_resolver(
        pool: PgPool,
        format: Arc<dyn Format>,
        cas: Cas,
        cache: Cache,
        resolver: Arc<dyn IpResolver>,
    ) -> Self {
        ProxyRepo {
            pool,
            format,
            cas,
            cache,
            resolver,
            delete_grace: Duration::seconds(0),
            envelope: None,
        }
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
                .unwrap_or(DEFAULT_METADATA_TTL_SECONDS),
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

    /// Build an SSRF-guarded client for this proxy's privacy policy.
    fn client(&self, repo: &Repository) -> Result<reqwest::Client, RepoError> {
        guarded_client(self.resolver.clone(), repo.allow_private_upstream)
            .map_err(|e| RepoError::Storage(format!("build upstream client: {e}")))
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
    /// 3. **Cross-instance singleflight (A11)** — otherwise take a `FOR UPDATE`
    ///    row lock on the proxy `repository` row, re-check freshness, then fetch
    ///    the upstream index, resolve the `@id`s, and persist — all in that tx.
    pub async fn resolve_upstream_index(
        &self,
        repo: &Repository,
    ) -> Result<UpstreamResources, RepoError> {
        let ttl = Self::metadata_ttl(repo);
        let pool = self.pool.clone();
        let repo_id = repo.id;
        let remote_url = repo
            .remote_url
            .clone()
            .ok_or_else(|| RepoError::Storage("proxy repository has no remote_url".into()))?;
        let client = self.client(repo)?;
        let online = repo.online;
        let allow_private = repo.allow_private_upstream;
        let resolver = self.resolver.clone();

        let _ = (&resolver, allow_private); // policy is enforced inside `client`.

        // The cache factory error must be `Clone` (moka coalescing shares an
        // `Arc<E>` across waiters); `RepoError` wraps non-`Clone` `sqlx::Error`,
        // so the factory yields a `String` and we re-wrap it on the way out.
        self.cache
            .get_or_try_insert_with(
                NS_UPSTREAM_INDEX,
                &repo.name,
                ttl.to_std().unwrap_or_default(),
                || async move {
                    resolve_index_uncached(&pool, repo_id, ttl, online, &remote_url, &client)
                        .await
                        .map_err(|e| e.to_string())
                },
            )
            .await
            .map_err(RepoError::Storage)
    }

    // ── Metadata discovery: enumerate upstream versions (Task 8.2) ───────────

    /// Discover the upstream versions of `lower_id`, recording each as a
    /// `proxy_cached_version` (first sighting stamps `first_seen_at`). Returns
    /// the recorded rows (post-upsert) for the caller to delay-gate.
    ///
    /// Offline ⇒ serves only existing cached rows; a genuine upstream 404 sets
    /// the negative cache on a synthetic row and returns empty.
    async fn discover_versions(
        &self,
        repo: &Repository,
        lower_id: &str,
    ) -> Result<Vec<forge_db::model::ProxyCachedVersion>, RepoError> {
        // Offline: only what we already cached.
        if !repo.online {
            return self.cached_rows(repo.id, lower_id).await;
        }

        let resources = self.resolve_upstream_index(repo).await?;
        let Some(base) = resources.package_base_address else {
            return self.cached_rows(repo.id, lower_id).await;
        };

        let client = self.client(repo)?;
        let url = format!("{base}{lower_id}/index.json");
        match fetch_json_opt(&client, &url).await? {
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

                // Record each version's first sighting (idempotent).
                for v in &versions {
                    proxy_dao::upsert_cached_version(
                        &self.pool,
                        NewProxyCachedVersion {
                            repository_id: repo.id,
                            name: lower_id.to_string(),
                            version: v.clone(),
                            listed: true,
                            downloaded: false,
                            not_found: false,
                        },
                    )
                    .await?;
                }
                self.cached_rows(repo.id, lower_id).await
            }
            None => {
                // Genuine upstream 404 for the whole package id → negative cache.
                // We model it on a synthetic `*` version row so a later request
                // can short-circuit without re-hitting upstream within the TTL.
                self.mark_not_found(repo.id, lower_id, "*").await?;
                Ok(Vec::new())
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
        //   2. the unbounded network I/O (upstream HTTP fetch) and the S3 PUT
        //      (CAS store), with NO transaction held;
        //   3. a second short tx that re-locks the row, re-checks (a racing
        //      caller may have finished in the meantime), and finalizes.
        //
        // The row lock no longer spans the network round-trip, so a slow or
        // misbehaving upstream can no longer pin a Postgres connection. The
        // cost is that the singleflight window is best-effort: under contention
        // more than one caller may fetch from upstream. That is safe — the CAS
        // is content-addressed (dedup by sha) and the finalize tx re-checks
        // `downloaded`, so concurrent fetches converge on identical state.
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
        // Resolve the flat-container base.
        let resources = self.resolve_upstream_index(repo).await?;
        let Some(base) = resources.package_base_address else {
            return Err(RepoError::Storage(
                "upstream advertises no PackageBaseAddress".into(),
            ));
        };

        let client = self.client(repo)?;
        // NuGet flat-container nupkg path: {base}{id}/{version}/{id}.{version}.nupkg
        let url = format!("{base}{lower_id}/{version}/{lower_id}.{version}.nupkg");
        let mut req = client.get(&url);
        // §12.5: decrypt-on-use; the plaintext lives only inside this request
        // builder (and the zeroizing secret wrapper) — never in a log or model.
        let upstream_password = self.upstream_password(repo).await?;
        if let (Some(u), Some(p)) = (&repo.upstream_username, &upstream_password) {
            use forge_crypto::ExposeSecret;
            req = req.basic_auth(u, Some(p.expose_secret()));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| RepoError::Storage(format!("upstream nupkg fetch: {e}")))?;

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
                "upstream nupkg fetch returned {}",
                resp.status()
            )));
        }

        // Reject an over-large advertised body before reading it.
        if let Some(len) = resp.content_length() {
            if len > MAX_NUPKG_BYTES {
                return Err(RepoError::Storage("upstream nupkg too large".into()));
            }
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| RepoError::Storage(format!("read upstream nupkg body: {e}")))?;
        if bytes.len() as u64 > MAX_NUPKG_BYTES {
            return Err(RepoError::Storage("upstream nupkg too large".into()));
        }

        // Parse to obtain canonical id/version (and the .nuspec for later).
        let parsed = {
            let mut cur = Cursor::new(bytes.as_ref());
            self.format
                .parse_upload(&mut cur)
                .map_err(|e| RepoError::Storage(format!("parse upstream nupkg: {e}")))?
        };

        // CAS-store the bytes (dedup applies across repos); the CAS re-enforces
        // the cap while streaming to disk. This is an S3 PUT — still NO tx held.
        let stored = self
            .cas
            .store(Cursor::new(bytes.to_vec()), MAX_NUPKG_BYTES)
            .await
            .map_err(|e| RepoError::Storage(format!("cas store upstream nupkg: {e}")))?;

        let size = i64::try_from(stored.size)
            .map_err(|_| RepoError::Storage("nupkg size overflow".into()))?;

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

        // Commit blob + attach component/asset within this short tx.
        blob_dao::commit_and_incref(&mut tx, &stored.sha256).await?;

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

        // Attach the .nupkg asset if absent.
        if asset_dao::find_asset(&mut *tx, comp.id, NUPKG_ASSET_PATH)
            .await?
            .is_none()
        {
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

/// The uncached body of [`ProxyRepo::resolve_upstream_index`]: DB-freshness
/// short-circuit, offline handling, and cross-instance row-locked refetch.
async fn resolve_index_uncached(
    pool: &PgPool,
    repo_id: i64,
    ttl: Duration,
    online: bool,
    remote_url: &str,
    client: &reqwest::Client,
) -> Result<UpstreamResources, RepoError> {
    // 2. DB freshness short-circuit (no lock needed for a read).
    if let Some(idx) = proxy_dao::get_upstream_index(pool, repo_id).await? {
        if Utc::now() - idx.fetched_at < ttl {
            return Ok(parse_resources(idx.resources));
        }
    }

    // Offline: never fetch. Serve a persisted (possibly stale) index if present.
    if !online {
        return match proxy_dao::get_upstream_index(pool, repo_id).await? {
            Some(idx) => Ok(parse_resources(idx.resources)),
            None => Err(RepoError::Storage(
                "proxy is offline and has no cached upstream index".into(),
            )),
        };
    }

    // 3. Cross-instance singleflight: row-lock the proxy `repository` row (A11).
    let mut tx = pool.begin().await?;
    sqlx::query!(
        r#"SELECT id FROM repository WHERE id = $1 FOR UPDATE"#,
        repo_id
    )
    .fetch_one(&mut *tx)
    .await?;

    // Re-check freshness inside the lock — another instance may have refreshed it.
    let recheck = sqlx::query!(
        r#"SELECT resources, fetched_at FROM proxy_upstream_index WHERE repository_id = $1"#,
        repo_id
    )
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = recheck {
        if Utc::now() - row.fetched_at < ttl {
            let resources = parse_resources(row.resources);
            tx.commit().await?;
            return Ok(resources);
        }
    }

    // Fetch the upstream service index (SSRF-guarded by `client`).
    let doc = fetch_json(client, remote_url).await?;
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
        repo_id,
        resources_json,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(resources)
}

/// Fetch a URL expecting JSON, mapping a non-success status to an error.
async fn fetch_json(client: &reqwest::Client, url: &str) -> Result<JsonValue, RepoError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| RepoError::Storage(format!("upstream GET {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(RepoError::Storage(format!(
            "upstream GET {url} returned {}",
            resp.status()
        )));
    }
    let bytes = bounded_body(resp).await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| RepoError::Storage(format!("parse upstream JSON: {e}")))
}

/// Like [`fetch_json`] but returns `Ok(None)` on a genuine 404.
async fn fetch_json_opt(
    client: &reqwest::Client,
    url: &str,
) -> Result<Option<JsonValue>, RepoError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| RepoError::Storage(format!("upstream GET {url}: {e}")))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(RepoError::Storage(format!(
            "upstream GET {url} returned {}",
            resp.status()
        )));
    }
    let bytes = bounded_body(resp).await?;
    let doc = serde_json::from_slice(&bytes)
        .map_err(|e| RepoError::Storage(format!("parse upstream JSON: {e}")))?;
    Ok(Some(doc))
}

/// Read a response body, capping it at [`MAX_METADATA_BYTES`].
async fn bounded_body(resp: reqwest::Response) -> Result<Vec<u8>, RepoError> {
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| RepoError::Storage(format!("read upstream body: {e}")))?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(RepoError::Storage("upstream metadata too large".into()));
    }
    Ok(bytes.to_vec())
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
        let loc = self.ensure_downloaded(&repo_row, &lower, &norm).await?;
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

    async fn resolve_nuspec(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        // Proxy nuspec serving is derived from the cached nupkg in a later slice;
        // for now return None (the route falls back to extracting on demand).
        let _ = (repo, id, version);
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
            // Pull the packageHash + nuspec only for already-downloaded versions;
            // otherwise serve metadata without a hash (avoids a fetch per entry).
            let (hash, nuspec) =
                match component_dao::find_component(&self.pool, repo_row.id, &r.name, &r.version)
                    .await?
                {
                    Some(comp) => {
                        let asset =
                            asset_dao::find_asset(&self.pool, comp.id, NUPKG_ASSET_PATH).await?;
                        (asset.and_then(|a| a.sha512_base64), None)
                    }
                    None => (None, None),
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
        let repo_row = self.proxy_repo(repo).await?;
        let now = Utc::now();

        // Search over locally-known cached versions (slice 1 does not proxy the
        // upstream search endpoint; it surfaces what has been discovered).
        let rows = sqlx::query_as!(
            forge_db::model::ProxyCachedVersion,
            r#"
            SELECT id, repository_id, name, version, listed, first_seen_at,
                   downloaded, metadata_refreshed_at, not_found, not_found_at
            FROM proxy_cached_version
            WHERE repository_id = $1 AND version <> '*' AND not_found = false
            "#,
            repo_row.id,
        )
        .fetch_all(&self.pool)
        .await?;

        let q = params.q.trim().to_lowercase();
        use std::collections::BTreeMap;
        let mut by_id: BTreeMap<String, Vec<forge_db::model::ProxyCachedVersion>> = BTreeMap::new();
        for r in rows {
            if !Self::delay_cleared(&repo_row, r.first_seen_at, now) {
                continue;
            }
            if !q.is_empty() && !r.name.contains(&q) {
                continue;
            }
            by_id.entry(r.name.clone()).or_default().push(r);
        }

        let mut hits: Vec<SearchHit> = Vec::new();
        for (_name, rows) in by_id {
            let mut versions: Vec<VersionEntry> = rows
                .into_iter()
                .filter(|r| r.listed)
                .filter(|r| params.prerelease || !is_prerelease(&r.version))
                .map(|r| VersionEntry {
                    original_id: r.name.clone(),
                    version: r.version.clone(),
                    version_original: r.version.clone(),
                    listed: r.listed,
                })
                .collect();
            versions.sort_by(|a, b| self.format.compare_versions(&a.version, &b.version));
            if versions.is_empty() {
                continue;
            }
            let latest = versions.last().unwrap();
            hits.push(SearchHit {
                original_id: latest.original_id.clone(),
                latest_version: latest.version.clone(),
                versions,
            });
        }
        hits.sort_by(|a, b| a.original_id.cmp(&b.original_id));

        let total_hits = hits.len();
        let skip = params.skip.min(total_hits);
        let take = params.effective_take();
        let page = hits.into_iter().skip(skip).take(take).collect();
        Ok(SearchResult {
            total_hits,
            hits: page,
        })
    }
}
