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
//!   [`proxy_dao::insert_unconfirmed_cached_version`] (INSERT … ON CONFLICT DO NOTHING) to
//!   guarantee a row exists, then [`proxy_dao::lock_or_insert_cached_version`]
//!   (SELECT … FOR UPDATE). The lock is held only for the short state-decision
//!   and finalize transactions; it is **released before** the upstream HTTP
//!   fetch and the CAS/S3 PUT (Addendum A7), so the reconciler may prune a
//!   still-unconfirmed row meanwhile; the next lock then creates it again.
//!   Within one instance, concurrent first-time fetches of the same version
//!   are serialized by an in-process
//!   gate ([`inflight_gate`]): the first caller fetches, the others wait and
//!   then find `downloaded` set, so N simultaneous restores cost one upstream
//!   download and one temp file. Across instances the singleflight is
//!   best-effort (at most one fetch per instance): the CAS is
//!   content-addressed and the finalize tx re-checks `downloaded`, so
//!   concurrent fetches converge on identical state. The
//!   upstream-index refresh likewise never holds a lock over the fetch; the
//!   per-instance cache coalesces concurrent refreshes.
//! * **Package delay** — a version discovered from upstream is recorded with
//!   `first_seen_at = now()` but is **not** served until
//!   `now − first_seen_at ≥ package_delay_seconds`. Inside the window it is
//!   omitted from enumeration/registration/search and direct download 404s. A
//!   delay-gated 404 is **never** written to the not-found negative cache.
//!   The delay quarantines new releases: when a listing refresh finds
//!   versions inside it, `first_seen_at` is moved back to the upstream
//!   registration's publish time of each listed version (a plausible one; see
//!   `date_delay_from_upstream`), so a release published long ago is served
//!   at its first sighting.
//! * **Negative cache** — a genuine upstream 404 sets `not_found = true` +
//!   `not_found_at = now()`, honored for `not_found_ttl_seconds` — by direct
//!   downloads *and* listings; an expired marker hides nothing. An upstream
//!   version listing that contains the version clears its marker.
//! * **Upstream confirmation** — the download singleflight creates its row for
//!   whatever version a client asks for, so such a row starts *unconfirmed*
//!   and is never enumerated (flat index, registration, search) until an
//!   upstream listing contains the version or a download of it succeeds. A
//!   request for a version that does not exist yet, or a fetch that fails with
//!   a 5xx / timeout, therefore never creates a phantom version, and the first
//!   confirmation restarts `first_seen_at` so a row planted early cannot
//!   shorten the package delay.
//! * **Self-healing cache** — a row marked `downloaded` whose local
//!   component/asset is gone (e.g. deleted by retention) is reset and fetched
//!   again on the next pull; `first_seen_at` is kept.
//! * **Verified upstream bytes** — a proxied `.nupkg` and an upstream `.nuspec`
//!   are served or cached only when their manifest names the requested id and
//!   version. A package rejected for its content (unparseable, mis-identified,
//!   oversized) is remembered for `not_found_ttl_seconds`, so client retries do
//!   not re-download it each time.
//! * **Upstream registration** — the registration of versions not downloaded
//!   yet takes `listed`, `published` and the dependency groups from the
//!   upstream registration (inline leaves, plus a bounded number of
//!   newest-first pages), cached for the metadata TTL; without one it degrades
//!   to the flat-container view (listed, no dependencies).
//! * **Metadata TTL** — the upstream service index *and* each package's
//!   version listing are re-fetched at most once per `metadata_ttl_seconds`.
//! * **Repointing** — the service index, version listings, manifests and
//!   registrations cached from the upstream are tied to the `remote_url` they
//!   came from: once it changes, nothing more is requested from the previous
//!   upstream, and a failing new one is an error, never a fallback to the
//!   previous upstream's index. Packages already downloaded stay cached.
//! * **Search** — forwarded to the upstream's `SearchQueryService` (cached
//!   for the metadata TTL), so packages nobody has restored yet are found.
//!   The caller's package filter, live not-found markers and the package
//!   delay apply to the upstream's hits; when the upstream has no search
//!   service or its search fails, the locally cached packages are searched.
//! * **Offline** — `repository.online == false` serves only already-cached data;
//!   no upstream requests are made.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Datelike, Duration, Utc};
use forge_cache::Cache;
use forge_crypto::ExposeSecret;
use forge_db::asset_dao::{self, NewAsset};
use forge_db::component_dao::{self, NewComponent};
use forge_db::model::Repository;
use forge_db::proxy_dao;
use forge_db::{blob_dao, repository_dao};
use forge_storage::{Cas, CasError};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::authz::PackageFilter;
use crate::domain::{Dependency, DependencyGroup};
use crate::format::Format;
use crate::net::upstream::{Origin, RequestClass, UpstreamAuth, UpstreamError, UpstreamHttp};
use crate::repo::hosted::BlobFetch;
use crate::repo::{
    NupkgLocation, RegistrationEntry, RepoError, RepoReadOps, SearchHit, SearchParams, SearchQuery,
    SearchResult, VersionEntry, NUPKG_ASSET_PATH, NUPKG_CONTENT_TYPE, NUSPEC_ASSET_PATH,
    NUSPEC_CONTENT_TYPE,
};

/// Cache namespace for resolved upstream service indexes, keyed by
/// `"{repo}/{repo_id}/{remote_url}"`.
pub const NS_UPSTREAM_INDEX: &str = "proxy_index";
/// Cache namespace marking a package's upstream version listing as fresh,
/// keyed by `"{scope}/{lower_id}"`. In this and the namespaces below, `scope`
/// is `"{repo}/{repo_id}/{remote_url digest}"`, so nothing cached from a
/// previous upstream is used once a proxy is repointed.
pub const NS_UPSTREAM_VERSIONS: &str = "proxy_versions";
/// Cache namespace for upstream `.nuspec` documents of not-yet-downloaded
/// versions, keyed by `"{scope}/{lower_id}/{version}"`.
pub const NS_UPSTREAM_NUSPEC: &str = "proxy_nuspec";
/// Cache namespace for a package's upstream registration index (its pages,
/// with any inlined leaves), keyed by `"{scope}/{lower_id}"`.
pub const NS_UPSTREAM_REGISTRATION: &str = "proxy_registration";
/// Cache namespace for one non-inlined upstream registration page, keyed by
/// `"{scope}/{page url}"`.
pub const NS_UPSTREAM_REGISTRATION_PAGE: &str = "proxy_registration_page";
/// Cache namespace for one page of upstream search results, keyed by
/// `"{scope}/{search url}"`.
pub const NS_UPSTREAM_SEARCH: &str = "proxy_search";
/// Cache namespace marking a proxy whose upstream search failed, keyed by
/// `"{scope}"`; see [`UPSTREAM_SEARCH_BACKOFF`].
pub const NS_UPSTREAM_SEARCH_FAILED: &str = "proxy_search_failed";
/// Cache namespace remembering why an upstream package was rejected for its
/// content, keyed by `"{scope}/{lower_id}/{version}"`.
pub const NS_UPSTREAM_REJECTED: &str = "proxy_rejected";

/// The earliest upstream publish time the package delay trusts
/// (2010-01-01, before any NuGet feed): nuget.org reports unlisted versions as
/// published in 1900.
fn min_trusted_publish_time() -> DateTime<Utc> {
    DateTime::from_timestamp(1_262_304_000, 0).expect("valid timestamp")
}

/// After an upstream search fails, the proxy searches only its cache for this
/// long, so an upstream that times out does not hold every search for the
/// whole metadata timeout.
const UPSTREAM_SEARCH_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);
/// Default metadata TTL when a proxy leaves `metadata_ttl_seconds` unset.
const DEFAULT_METADATA_TTL_SECONDS: i64 = 600;
/// Default negative-cache TTL when a proxy leaves `not_found_ttl_seconds` unset.
pub const DEFAULT_NOT_FOUND_TTL_SECONDS: i64 = 600;
/// A published `(id, version)`'s manifest is immutable, so an upstream
/// `.nuspec` can be cached far longer than the version listing.
const NUSPEC_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
/// At most this many non-inlined upstream registration pages are fetched for
/// one registration request (newest first). nuget.org pages hold 64 versions,
/// so this covers the newest ~640; older versions of a larger package fall
/// back to the flat-container view.
const MAX_REGISTRATION_PAGES: usize = 10;
/// Concurrent upstream registration page fetches per request.
const REGISTRATION_PAGE_CONCURRENCY: usize = 4;

/// The upstream resource `@id`s resolved from a V3 service index, persisted in
/// the `proxy_upstream_index.resources` JSON (with the URL they came from) and
/// cached.
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
        // Rank of the registration variant picked so far: the SemVer 2.0.0
        // variants (`3.6.0`, `Versioned`) list every version, the older ones
        // omit SemVer 2.0.0 packages.
        let mut registration_rank = 0;
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
                    "RegistrationsBaseUrl" => {
                        let rank = match ty {
                            "RegistrationsBaseUrl/3.6.0" => 3,
                            "RegistrationsBaseUrl/Versioned" => 2,
                            _ => 1,
                        };
                        if rank > registration_rank {
                            registration_rank = rank;
                            out.registrations_base_url = Some(with_trailing_slash(id));
                        }
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

/// The `proxy_upstream_index.resources` JSON: the resolved resources and the
/// `remote_url` they were resolved from. A row that came from another URL (the
/// proxy has been repointed since), or that predates this field, is never used.
#[derive(Serialize, Deserialize)]
struct PersistedIndex {
    remote_url: String,
    #[serde(flatten)]
    resources: UpstreamResources,
}

/// One upstream dependency group as cached: `(targetFramework, [(id, range)])`.
type UpstreamGroup = (Option<String>, Vec<(String, Option<String>)>);

/// One version's metadata from the upstream registration (a leaf's inlined
/// `catalogEntry`), as cached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UpstreamLeaf {
    /// Package id as the upstream publishes it (original casing).
    id: Option<String>,
    /// Whether the upstream lists the version.
    listed: bool,
    /// Upstream publish time.
    published: Option<DateTime<Utc>>,
    /// The dependency groups.
    groups: Vec<UpstreamGroup>,
}

impl UpstreamLeaf {
    fn dependency_groups(&self) -> Vec<DependencyGroup> {
        self.groups
            .iter()
            .map(|(tfm, deps)| DependencyGroup {
                target_framework: tfm.clone(),
                dependencies: deps
                    .iter()
                    .map(|(id, range)| Dependency {
                        id: id.clone(),
                        range: range.clone(),
                    })
                    .collect(),
            })
            .collect()
    }
}

/// One page of a package's upstream registration index, as cached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UpstreamRegistrationPage {
    /// The page `@id`, fetched when its leaves are not inlined.
    url: Option<String>,
    /// Normalized lowest / highest version on the page (`None` = unknown).
    lower: Option<String>,
    upper: Option<String>,
    /// Inlined leaves by normalized version; `None` ⇒ fetch [`Self::url`].
    leaves: Option<BTreeMap<String, UpstreamLeaf>>,
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

/// Key of an in-flight first-time `.nupkg` fetch: `(repository id, lowercase
/// id, version)`.
type InflightKey = (i64, String, String);

/// Process-wide registry of in-flight first-time fetches. Entries are weak so a
/// finished fetch frees its slot as soon as the last waiter drops the gate.
static INFLIGHT: std::sync::LazyLock<
    std::sync::Mutex<
        std::collections::HashMap<InflightKey, std::sync::Weak<tokio::sync::Mutex<()>>>,
    >,
> = std::sync::LazyLock::new(Default::default);

/// The per-version gate serializing first-time fetches within this process.
/// [`ProxyRepo`] is built per request, so the gate cannot live on it.
fn inflight_gate(repository_id: i64, lower_id: &str, version: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut map = INFLIGHT.lock().unwrap_or_else(|p| p.into_inner());
    let key = (repository_id, lower_id.to_string(), version.to_string());
    if let Some(gate) = map.get(&key).and_then(std::sync::Weak::upgrade) {
        return gate;
    }
    // Prune finished entries before growing the map.
    if map.len() >= 1024 {
        map.retain(|_, gate| gate.strong_count() > 0);
    }
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    map.insert(key, Arc::downgrade(&gate));
    gate
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
    /// The lowered id to use in upstream URLs and cache rows, or `None` when
    /// `id` is not a well-formed package id ([`Format::validate_id`]). Every
    /// read entry point checks this first: the id is pasted into URLs sent
    /// with the repository's upstream credentials, so `x/../../admin?q=` must
    /// never get that far (and must never be recorded as a package).
    fn upstream_id(&self, id: &str) -> Option<String> {
        let lower = self.format.lower_id(id);
        self.format.validate_id(&lower).ok().map(|()| lower)
    }

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
    /// row so the AAD binds to fresh data, its `remote_url` origin included);
    /// a not-yet-backfilled row falls back to the legacy plaintext column.
    /// Returns the password with the `remote_url` it belongs to. Fail closed:
    /// an encrypted blob without a configured envelope service is an error,
    /// not an anonymous fetch.
    async fn upstream_password(
        &self,
        repo: &Repository,
    ) -> Result<Option<(forge_crypto::PlaintextSecret, Option<String>)>, RepoError> {
        match (&repo.upstream_password_enc, &self.envelope) {
            (Some(_), Some(envelope)) => {
                forge_db::secret_dao::get_upstream_credential(&self.pool, envelope, repo.id)
                    .await
                    .map(|found| found.map(|p| (p.secret, p.remote_url)))
                    .map_err(|e| RepoError::Storage(format!("decrypt upstream password: {e}")))
            }
            (Some(_), None) => Err(RepoError::Storage(
                "repository stores an encrypted upstream password but secret encryption is not \
                 configured (missing [crypto] config)"
                    .into(),
            )),
            (None, _) => Ok(repo.upstream_password.clone().map(|password| {
                (
                    forge_crypto::PlaintextSecret::from(password),
                    repo.remote_url.clone(),
                )
            })),
        }
    }

    /// The Basic credentials for `repo`'s upstream, if both a username and a
    /// password are configured. They are attached only to the origin of the
    /// `remote_url` the password was read (and, encrypted, bound) with, which
    /// may be newer than the cached `repo` row.
    async fn credentials(&self, repo: &Repository) -> Result<Option<Credentials>, RepoError> {
        let Some(username) = repo.upstream_username.clone() else {
            return Ok(None);
        };
        let Some((password, remote_url)) = self.upstream_password(repo).await? else {
            return Ok(None);
        };
        Ok(Some(Credentials {
            origin: remote_url.as_deref().and_then(Origin::of),
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

    /// The key prefix of everything cached from `repo`'s upstream: the
    /// repository (its id too, so a deleted-and-recreated repository starts
    /// afresh) and a digest of its `remote_url`, so a repointed proxy never
    /// serves what the previous upstream answered. A digest rather than the
    /// URL itself keeps keys that append another URL unambiguous.
    fn upstream_scope(repo: &Repository) -> String {
        let digest = Sha256::digest(repo.remote_url.as_deref().unwrap_or_default());
        format!("{}/{}/{}", repo.name, repo.id, hex::encode(&digest[..8]))
    }

    /// Cache key of the "listing refreshed" marker of `lower_id`.
    fn versions_key(repo: &Repository, lower_id: &str) -> String {
        format!("{}/{lower_id}", Self::upstream_scope(repo))
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

    /// The database's clock. Every time this module compares with is written
    /// by Postgres (`first_seen_at`, `not_found_at`, `fetched_at`,
    /// `metadata_refreshed_at`), so comparing it with the application's clock
    /// would shift the package delay and the TTLs by the clock skew.
    async fn db_now(&self) -> Result<DateTime<Utc>, RepoError> {
        Ok(forge_db::db_now(&self.pool).await?)
    }

    /// Whether a version with the given `first_seen_at` has cleared the proxy's
    /// package-delay window and may now be served/enumerated.
    fn delay_cleared(repo: &Repository, first_seen_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        let delay = Duration::seconds(i64::from(repo.package_delay_seconds));
        now - first_seen_at >= delay
    }

    /// Whether `row` carries a genuine-404 marker that is still within
    /// `not_found_ttl`. An expired marker hides nothing.
    fn not_found_live(
        repo: &Repository,
        row: &forge_db::model::ProxyCachedVersion,
        now: DateTime<Utc>,
    ) -> bool {
        row.not_found
            && row
                .not_found_at
                .is_some_and(|at| now - at < Self::not_found_ttl(repo))
    }

    /// Whether a (confirmed) cached-version row may be enumerated by the flat
    /// index, registration and search: past the package delay and not hidden
    /// by a live not-found marker. Unconfirmed rows are filtered out in SQL.
    fn listable(
        repo: &Repository,
        row: &forge_db::model::ProxyCachedVersion,
        now: DateTime<Utc>,
    ) -> bool {
        !Self::not_found_live(repo, row, now) && Self::delay_cleared(repo, row.first_seen_at, now)
    }

    // ── Upstream service-index discovery (Task 8.1) ──────────────────────────

    /// Resolve the upstream resource `@id`s for `repo`, reading through the
    /// per-instance cache (never Redis) and persisting to
    /// `proxy_upstream_index`.
    ///
    /// Layering:
    /// 1. **Cache** (`get_or_try_insert_local`, TTL = metadata_ttl) — per-instance
    ///    coalescing + short-circuit; a 2nd call within TTL never touches DB or
    ///    upstream.
    /// 2. **DB freshness** — on an L1 miss, if `proxy_upstream_index.fetched_at`
    ///    is within metadata_ttl, reuse it without a network call. Only a row
    ///    fetched from the current `remote_url` is used, fresh or stale.
    /// 3. **Refresh** — otherwise fetch the upstream index (no DB transaction
    ///    or row lock held across the request), resolve the `@id`s, and
    ///    upsert them. Concurrent instances may both refresh; the result is
    ///    idempotent.
    ///
    /// The cache key includes the repository id and `remote_url`, and the
    /// persisted row records its URL, so a changed upstream (or a
    /// deleted-and-recreated repository) never serves the old upstream's
    /// resources.
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
        // Local-only (never read from Redis): the index decides which host
        // packages are downloaded from, and a downloaded package is cached for
        // good, so a forged index in Redis would substitute packages.
        self.cache
            .get_or_try_insert_local(
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
        // An index fetched from another URL is not this upstream's: neither
        // reused nor fallen back to below.
        let persisted = proxy_dao::get_upstream_index(&self.pool, repo.id)
            .await?
            .and_then(|idx| {
                let stored: PersistedIndex = serde_json::from_value(idx.resources).ok()?;
                (stored.remote_url == remote_url).then_some((stored.resources, idx.fetched_at))
            });
        if let Some((resources, fetched_at)) = &persisted {
            if self.db_now().await? - *fetched_at < ttl {
                return Ok(resources.clone());
            }
        }

        // Offline: never fetch. Serve a persisted (possibly stale) index if present.
        if !repo.online {
            return match persisted {
                Some((resources, _)) => Ok(resources),
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
                if let Some((resources, _)) = persisted {
                    tracing::warn!(repo = %repo.name, error = %e, "upstream index refresh failed; serving stale index");
                    return Ok(resources);
                }
                return Err(e);
            }
        };
        let resources = UpstreamResources::from_service_index(&doc);
        // An index without a package base address is not a NuGet V3 service
        // index (a captive portal, a gateway's error page, a mistyped URL):
        // an upstream failure, never stored over the last good index. Taken
        // for an empty upstream, it would answer every id 404.
        if resources.package_base_address.is_none() {
            let e = RepoError::Storage(format!(
                "upstream service index {remote_url} advertises no PackageBaseAddress"
            ));
            if let Some((resources, _)) = persisted {
                tracing::warn!(repo = %repo.name, error = %e, "upstream index refresh failed; serving stale index");
                return Ok(resources);
            }
            return Err(e);
        }
        let resources_json = serde_json::to_value(PersistedIndex {
            remote_url: remote_url.to_string(),
            resources: resources.clone(),
        })
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
        let key = Self::versions_key(repo, lower_id);
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
            return Err(RepoError::Storage(
                "upstream advertises no PackageBaseAddress".into(),
            ));
        };
        let url = format!("{base}{lower_id}/index.json");
        match self.fetch_json(repo, &url).await? {
            Some(doc) => {
                // A document without a `versions` array is not a listing:
                // treat it as an upstream failure (what is cached is served)
                // rather than as "no versions", which would retire them all.
                let Some(listed) = doc.get("versions").and_then(|v| v.as_array()) else {
                    return Err(RepoError::Storage(format!(
                        "upstream listing {url} has no versions array"
                    )));
                };
                let versions: Vec<String> = listed
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|raw| self.format.normalize_version(raw).ok())
                    .collect();

                // Record each version's first sighting (idempotent, one round-trip),
                // then retire versions the upstream no longer lists (deleted
                // upstream; still missing one metadata TTL after the first
                // listing that left them out, since one partial listing is no
                // deletion) and drop a stale package-level not-found marker.
                // An empty listing retires nothing: a feed answers 404 for a
                // package without versions, so an empty 200 is a degraded
                // upstream (an offline or partially synced mirror), not a
                // deletion of every version, downloaded ones included.
                proxy_dao::upsert_cached_versions(&self.pool, repo.id, lower_id, &versions).await?;
                if !versions.is_empty() {
                    proxy_dao::reconcile_listing(
                        &self.pool,
                        repo.id,
                        lower_id,
                        &versions,
                        Self::metadata_ttl(repo).num_seconds(),
                    )
                    .await?;
                }
                if repo.package_delay_seconds > 0 {
                    self.date_delay_from_upstream(repo, lower_id).await;
                }
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

    /// Fetch all upstream-confirmed cached-version rows for `(repo, lower_id)`
    /// (never the synthetic negative-cache marker `version = "*"`, nor a row
    /// only the download singleflight created).
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
            WHERE repository_id = $1 AND name = $2 AND version <> '*' AND confirmed
              AND NOT upstream_missing
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
        let Some(row) =
            proxy_dao::get_cached_version(&self.pool, repo.id, lower_id, version).await?
        else {
            return Ok(false);
        };
        Ok(Self::not_found_live(repo, &row, self.db_now().await?))
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
                (repository_id, name, version, listed, downloaded, not_found, not_found_at,
                 confirmed)
            VALUES ($1, $2, $3, false, false, true, now(), false)
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
    ///
    /// A row marked `downloaded` whose local copy is gone (retention deleted the
    /// component, or reset `downloaded` itself) is fetched again; its
    /// `first_seen_at` is kept, so the package delay does not restart.
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
            let now = self.db_now().await?;
            if row.downloaded {
                if !Self::delay_cleared(repo, row.first_seen_at, now) {
                    return Ok(None);
                }
                if let Some(loc) = self.local_nupkg(repo.id, lower_id, version).await? {
                    return Ok(Some(loc));
                }
                // Marked downloaded but the local copy is gone: re-fetch below.
            } else if Self::not_found_live(repo, &row, now) {
                // A still-valid genuine-404 marker short-circuits (no upstream call).
                return Ok(None);
            }
        }

        // Offline and not (or no longer) cached locally ⇒ nothing to serve.
        if !repo.online {
            return Ok(None);
        }

        // Package delay: never fetch a version from upstream before its delay
        // window has passed. Fetching early would cache bytes that are later
        // served without asking the upstream again — so a release pulled
        // during the quarantine (the point of the delay) would still be
        // served afterwards. A version not confirmed yet is looked up in the
        // upstream listing first: that starts its delay clock.
        if repo.package_delay_seconds > 0
            && !self.delay_cleared_upstream(repo, lower_id, version).await?
        {
            return Ok(None);
        }

        // Singleflight: guarantee a row exists, then lock it FOR UPDATE so
        // concurrent first-time downloads collapse to one upstream fetch. A row
        // created here is unconfirmed — never listed until the upstream
        // confirms the version (listing or successful download).
        proxy_dao::insert_unconfirmed_cached_version(&self.pool, repo.id, lower_id, version)
            .await?;

        // In-process singleflight: wait for any fetch of this version already
        // running on this instance; the gate tx below then sees `downloaded`
        // and serves the local copy instead of fetching again. Held (it is an
        // async mutex, not a DB lock) until this call returns.
        let gate = inflight_gate(repo.id, lower_id, version);
        let _inflight = gate.lock().await;

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
        {
            let mut tx = self.pool.begin().await?;
            let locked =
                proxy_dao::lock_or_insert_cached_version(&mut tx, repo.id, lower_id, version)
                    .await?;
            let now = forge_db::db_now(&mut *tx).await?;

            // Decide on the locked row, then release the lock before any
            // further query.
            tx.commit().await?;
            if locked.downloaded {
                if !Self::delay_cleared(repo, locked.first_seen_at, now) {
                    return Ok(None);
                }
                // A racing caller already finished the fetch.
                if let Some(loc) = self.local_nupkg(repo.id, lower_id, version).await? {
                    return Ok(Some(loc));
                }
                // Self-heal: the local copy vanished. Clear `downloaded` so the
                // finalize below re-attaches fresh assets instead of serving
                // the missing copy (`first_seen_at` and confirmation stay).
                tracing::info!(repo = %repo.name, id = %lower_id, %version, "cached proxy package is missing locally; fetching it again");
                proxy_dao::mark_not_downloaded(&self.pool, locked.id).await?;
            } else if Self::not_found_live(repo, &locked, now) {
                // A still-valid genuine-404 marker short-circuits (no upstream call).
                return Ok(None);
            }
            // This caller performs the fetch.
        }

        // Bytes rejected for their content recently: fail fast instead of
        // downloading them again on every client retry.
        if let Some(reason) = self.recent_rejection(repo, lower_id, version).await {
            return Err(RepoError::Storage(format!(
                "upstream package {lower_id} {version} was rejected recently: {reason}"
            )));
        }

        // ── Network I/O — performed with NO transaction held (A7). ───────────
        let resources = self.resolve_upstream_index(repo).await?;
        let Some(base) = resources.package_base_address else {
            return Err(RepoError::Storage(
                "upstream advertises no PackageBaseAddress".into(),
            ));
        };

        // NuGet flat-container nupkg path: {base}{id}/{version}/{id}.{version}.nupkg
        let url = format!("{base}{lower_id}/{version}/{lower_id}.{version}.nupkg");
        let requested_at = self.db_now().await?;
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
                    // A listing that confirmed the version after this request
                    // started outranks the 404 (a request racing publication,
                    // or a lagging CDN edge): do not hide a version the
                    // upstream has meanwhile vouched for.
                    sqlx::query!(
                        r#"
                        UPDATE proxy_cached_version SET not_found = true, not_found_at = now()
                        WHERE id = $1
                          AND NOT (confirmed AND metadata_refreshed_at IS NOT NULL
                                   AND metadata_refreshed_at >= $2)
                        "#,
                        row.id,
                        requested_at,
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
            return Err(self
                .reject(
                    repo,
                    lower_id,
                    version,
                    format!("upstream nupkg {url} exceeds {max_bytes} bytes"),
                )
                .await);
        }
        let body = futures_util::TryStreamExt::map_err(resp.bytes_stream(), std::io::Error::other);
        let reader = tokio_util::io::StreamReader::new(body);
        let staged = match self.cas.stage(reader, max_bytes).await {
            Ok(staged) => staged,
            Err(CasError::TooLarge { limit }) => {
                return Err(self
                    .reject(
                        repo,
                        lower_id,
                        version,
                        format!("upstream nupkg {url} exceeds {limit} bytes"),
                    )
                    .await)
            }
            Err(e @ CasError::StagingFull { .. }) => return Err(RepoError::Busy(e.to_string())),
            Err(other) => {
                return Err(RepoError::Storage(format!(
                    "read upstream nupkg {url}: {other}"
                )))
            }
        };

        // Parse from the temp file on the blocking pool to obtain the canonical
        // identity and the manifest, and summarize the manifest for
        // registration and search (stored with the component, like a push).
        let parsed = {
            let format = self.format.clone();
            let path = staged.temp_path.to_path_buf();
            tokio::task::spawn_blocking(move || {
                let mut file = std::fs::File::open(&path)?;
                Ok::<_, std::io::Error>(format.parse_upload(&mut file).map(|parsed| {
                    let summary = format.manifest_summary(&parsed.nuspec_bytes);
                    (parsed, summary)
                }))
            })
            .await
            .map_err(|e| RepoError::Storage(format!("parse upstream nupkg: {e}")))?
            .map_err(|e| RepoError::Storage(format!("parse upstream nupkg: {e}")))?
        };
        let (parsed, manifest_summary) = match parsed {
            Ok(parsed) => parsed,
            Err(e) => {
                return Err(self
                    .reject(
                        repo,
                        lower_id,
                        version,
                        format!("parse upstream nupkg {url}: {e}"),
                    )
                    .await)
            }
        };
        // Never cache a package under an identity it does not carry: a
        // misbehaving upstream must not be able to plant `evil 1.0.0` bytes at
        // `good/1.0.0`.
        if parsed.id != lower_id || parsed.version != version {
            return Err(self
                .reject(
                    repo,
                    lower_id,
                    version,
                    format!(
                        "upstream nupkg at {url} identifies as {} {}",
                        parsed.id, parsed.version
                    ),
                )
                .await);
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
            .map_err(|e| match e {
                e @ CasError::StagingFull { .. } => RepoError::Busy(e.to_string()),
                e => RepoError::Storage(format!("cas store upstream nuspec: {e}")),
            })?;

        let size = i64::try_from(stored.size)
            .map_err(|_| RepoError::Storage("nupkg size overflow".into()))?;
        let nuspec_size = i64::try_from(nuspec.size)
            .map_err(|_| RepoError::Storage("nuspec size overflow".into()))?;

        // ── Finalize (short tx) — re-lock, re-check, attach, mark downloaded. ─
        // An unconfirmed row pruned during the fetch is created again here.
        let mut tx = self.pool.begin().await?;
        let locked =
            proxy_dao::lock_or_insert_cached_version(&mut tx, repo.id, lower_id, version).await?;

        // A racing caller finished while we were fetching. The blob we stored is
        // already on disk (CAS dedup); just roll back and serve the local copy.
        if locked.downloaded {
            let now = forge_db::db_now(&mut *tx).await?;
            tx.rollback().await?;
            if !Self::delay_cleared(repo, locked.first_seen_at, now) {
                return Ok(None);
            }
            return self.local_nupkg(repo.id, lower_id, version).await;
        }

        // Insert the component if it is not already present (a prior metadata
        // discovery never inserts components, so normally absent here; after a
        // retention eviction the component is gone as well).
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
                        listed: locked.listed,
                    },
                )
                .await?
            }
        };
        if let Some(summary) = &manifest_summary {
            component_dao::set_manifest_summary(&mut *tx, comp.id, summary).await?;
        }
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

        // Mark downloaded and confirmed; a row only the singleflight knew
        // restarts its delay window here (its first real sighting).
        let first_seen_at = proxy_dao::mark_downloaded(&mut tx, locked.id).await?;
        // The package evidently exists: drop a package-level not-found marker
        // so listings see it again.
        let marker_cleared = proxy_dao::clear_package_marker(&mut tx, repo.id, lower_id).await? > 0;

        tx.commit().await?;
        if marker_cleared {
            // The cached "unknown upstream" listing result goes with it.
            self.cache
                .invalidate(NS_UPSTREAM_VERSIONS, &Self::versions_key(repo, lower_id))
                .await;
        }

        // Delay gate on the recorded first sighting.
        if !Self::delay_cleared(repo, first_seen_at, self.db_now().await?) {
            return Ok(None);
        }
        self.local_nupkg(repo.id, lower_id, version).await
    }

    /// Whether `(lower_id, version)` is confirmed upstream and past its
    /// package delay. A version without a confirmed row is looked up in the
    /// upstream listing first (refreshing it when stale), which confirms it
    /// and starts its delay clock.
    ///
    /// Returns a type-erased future: it is awaited inside
    /// [`Self::ensure_downloaded`], which the listing paths reach in turn, and
    /// the nested `async fn` types would otherwise recurse.
    fn delay_cleared_upstream<'a>(
        &'a self,
        repo: &'a Repository,
        lower_id: &'a str,
        version: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, RepoError>> + Send + 'a>>
    {
        Box::pin(async move {
            let confirmed = |rows: &[forge_db::model::ProxyCachedVersion]| {
                rows.iter()
                    .find(|r| r.version == version)
                    .map(|r| r.first_seen_at)
            };
            let first_seen = match confirmed(&self.cached_rows(repo.id, lower_id).await?) {
                Some(first_seen) => Some(first_seen),
                None => confirmed(&self.discover_versions(repo, lower_id).await?),
            };
            Ok(match first_seen {
                Some(at) => Self::delay_cleared(repo, at, self.db_now().await?),
                None => false,
            })
        })
    }

    /// Cache key of a remembered rejection of `(lower_id, version)`.
    fn rejection_key(repo: &Repository, lower_id: &str, version: &str) -> String {
        format!("{}/{lower_id}/{version}", Self::upstream_scope(repo))
    }

    /// Why a recent fetch of `(lower_id, version)` was rejected for its content
    /// (unparseable, mis-identified or oversized upstream bytes), if that is
    /// still remembered (for `not_found_ttl`).
    async fn recent_rejection(
        &self,
        repo: &Repository,
        lower_id: &str,
        version: &str,
    ) -> Option<String> {
        let ttl = Self::not_found_ttl(repo).to_std().ok()?;
        if ttl.is_zero() {
            return None;
        }
        let key = Self::rejection_key(repo, lower_id, version);
        // Lookup only: the factory never yields a value, so a miss caches nothing.
        self.cache
            .get_or_try_insert_with(NS_UPSTREAM_REJECTED, &key, ttl, || async { Err(()) })
            .await
            .ok()
    }

    /// Remember that the upstream bytes of `(lower_id, version)` were rejected
    /// for their content, so client retries within `not_found_ttl` fail fast
    /// instead of downloading the package again. Returns the error to surface.
    async fn reject(
        &self,
        repo: &Repository,
        lower_id: &str,
        version: &str,
        reason: String,
    ) -> RepoError {
        tracing::warn!(repo = %repo.name, id = %lower_id, %version, %reason, "rejected upstream package");
        if let Some(ttl) = Self::not_found_ttl(repo)
            .to_std()
            .ok()
            .filter(|ttl| !ttl.is_zero())
        {
            let key = Self::rejection_key(repo, lower_id, version);
            let remembered = reason.clone();
            let _ = self
                .cache
                .get_or_try_insert_with(NS_UPSTREAM_REJECTED, &key, ttl, || async move {
                    Ok::<_, ()>(remembered)
                })
                .await;
        }
        RepoError::Storage(reason)
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

    /// The manifest of a version cached before summaries were stored:
    /// summarized off the async workers and backfilled, so later reads skip
    /// the fetch. `(summary, None)` once summarized; `(None, manifest)` when
    /// it cannot be (the format layer then parses the bytes itself).
    async fn summarize_cached(
        &self,
        repo_id: i64,
        lower_id: &str,
        component_id: i64,
        version: &str,
    ) -> (Option<JsonValue>, Option<Vec<u8>>) {
        let bytes = self
            .local_nuspec(repo_id, lower_id, version)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, id = %lower_id, %version, "cached nuspec read failed");
                None
            });
        let Some(bytes) = bytes else {
            return (None, None);
        };
        let format = self.format.clone();
        let parse = bytes.clone();
        let summary = tokio::task::spawn_blocking(move || format.manifest_summary(&parse))
            .await
            .ok()
            .flatten();
        match summary {
            Some(summary) => {
                if let Err(e) =
                    component_dao::backfill_manifest_summary(&self.pool, component_id, &summary)
                        .await
                {
                    tracing::warn!(error = %e, component_id, "manifest summary backfill failed");
                }
                (Some(summary), None)
            }
            None => (None, Some(bytes)),
        }
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
    ///
    /// The upstream controls these bytes (and where its redirects lead), so a
    /// document is served or cached only when it parses as a manifest of
    /// exactly `(lower_id, version)`. Anything else yields `None`, and the
    /// caller falls back to the package itself, whose identity is verified
    /// the same way.
    async fn upstream_nuspec(
        &self,
        repo: &Repository,
        lower_id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        let key = format!("{}/{lower_id}/{version}", Self::upstream_scope(repo));
        let fetched: Result<Option<Vec<u8>>, String> = self
            .cache
            // Local-only, like every upstream document clients act on: a
            // manifest from Redis could rewrite a version's dependencies.
            .get_or_try_insert_local(NS_UPSTREAM_NUSPEC, &key, NUSPEC_CACHE_TTL, || async {
                let resources = Box::pin(self.resolve_upstream_index(repo))
                    .await
                    .map_err(|e| e.to_string())?;
                let Some(base) = resources.package_base_address else {
                    return Err("upstream advertises no PackageBaseAddress".to_string());
                };
                let url = format!("{base}{lower_id}/{version}/{lower_id}.nuspec");
                let creds = self.credentials(repo).await.map_err(|e| e.to_string())?;
                let auth = creds.as_ref().map(Credentials::auth);
                let Some(bytes) = self
                    .http
                    .get_bytes(&url, auth.as_ref())
                    .await
                    .map_err(|e| e.to_string())?
                else {
                    return Ok(None);
                };
                match self.format.manifest_identity(&bytes) {
                    Ok((id, v)) if id == lower_id && v == version => Ok(Some(bytes)),
                    Ok((id, v)) => {
                        tracing::warn!(%url, %id, version = %v, "upstream nuspec names another package; not serving it");
                        Ok(None)
                    }
                    Err(e) => {
                        tracing::warn!(%url, error = %e, "upstream nuspec is not a valid manifest; not serving it");
                        Ok(None)
                    }
                }
            })
            .await;
        fetched.map_err(RepoError::Storage)
    }

    // ── Upstream registration metadata (M11) ────────────────────────────────

    /// Upstream registration metadata for `wanted` versions of `lower_id`,
    /// keyed by normalized version. Best effort and bounded: an offline proxy,
    /// an upstream without a `RegistrationsBaseUrl`, and any upstream or parse
    /// failure yield what could be gathered (possibly nothing), and the caller
    /// falls back to the flat-container view. Inlined leaves cost no extra
    /// request; of the non-inlined pages covering a wanted version, at most
    /// [`MAX_REGISTRATION_PAGES`] (newest first) are fetched. The index and
    /// each page are cached for the metadata TTL.
    async fn upstream_registration(
        &self,
        repo: &Repository,
        lower_id: &str,
        wanted: &[String],
    ) -> HashMap<String, UpstreamLeaf> {
        let mut out = HashMap::new();
        if !repo.online || wanted.is_empty() {
            return out;
        }
        let pages = match Box::pin(self.upstream_registration_index(repo, lower_id)).await {
            Ok(Some(pages)) => pages,
            Ok(None) => return out,
            Err(e) => {
                tracing::warn!(repo = %repo.name, id = %lower_id, error = %e, "upstream registration unavailable; serving flat-container metadata");
                return out;
            }
        };

        let mut to_fetch: Vec<(Option<String>, String)> = Vec::new();
        for page in pages {
            match page.leaves {
                Some(leaves) => out.extend(leaves),
                None => {
                    let covers = wanted.iter().any(|v| {
                        page.lower.as_deref().is_none_or(|lo| {
                            self.format.compare_versions(lo, v) != std::cmp::Ordering::Greater
                        }) && page.upper.as_deref().is_none_or(|hi| {
                            self.format.compare_versions(v, hi) != std::cmp::Ordering::Greater
                        })
                    });
                    if let (true, Some(url)) = (covers, page.url) {
                        to_fetch.push((page.upper, url));
                    }
                }
            }
        }
        // Newest pages first; an unknown upper bound sorts last.
        to_fetch.sort_by(|a, b| match (&a.0, &b.0) {
            (Some(x), Some(y)) => self.format.compare_versions(y, x),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        to_fetch.truncate(MAX_REGISTRATION_PAGES);

        use futures_util::StreamExt;
        let fetched: Vec<_> = futures_util::stream::iter(to_fetch)
            .map(|(_, url)| async move {
                let res = self.upstream_registration_page(repo, &url).await;
                (url, res)
            })
            .buffered(REGISTRATION_PAGE_CONCURRENCY)
            .collect()
            .await;
        for (url, res) in fetched {
            match res {
                Ok(leaves) => out.extend(leaves),
                Err(e) => {
                    tracing::warn!(repo = %repo.name, id = %lower_id, %url, error = %e, "upstream registration page unavailable");
                }
            }
        }
        out
    }

    /// The upstream registration index of `lower_id` (`None`: the upstream has
    /// no registration resource or no registration for the id). Cached for the
    /// metadata TTL.
    async fn upstream_registration_index(
        &self,
        repo: &Repository,
        lower_id: &str,
    ) -> Result<Option<Vec<UpstreamRegistrationPage>>, RepoError> {
        let ttl = Self::metadata_ttl(repo).to_std().unwrap_or_default();
        let key = format!("{}/{lower_id}", Self::upstream_scope(repo));
        self.cache
            // Local-only (listing state, dependencies; see NS_UPSTREAM_NUSPEC).
            .get_or_try_insert_local(NS_UPSTREAM_REGISTRATION, &key, ttl, || async {
                let resources = Box::pin(self.resolve_upstream_index(repo))
                    .await
                    .map_err(|e| e.to_string())?;
                let Some(base) = resources.registrations_base_url else {
                    return Ok(None);
                };
                let url = format!("{base}{lower_id}/index.json");
                let doc = self
                    .fetch_json(repo, &url)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(doc.map(|doc| self.registration_pages(&doc)))
            })
            .await
            .map_err(RepoError::Storage)
    }

    /// The leaves of one non-inlined upstream registration page. Cached for
    /// the metadata TTL.
    async fn upstream_registration_page(
        &self,
        repo: &Repository,
        url: &str,
    ) -> Result<BTreeMap<String, UpstreamLeaf>, RepoError> {
        let ttl = Self::metadata_ttl(repo).to_std().unwrap_or_default();
        let key = format!("{}/{url}", Self::upstream_scope(repo));
        self.cache
            // Local-only (see NS_UPSTREAM_REGISTRATION).
            .get_or_try_insert_local(NS_UPSTREAM_REGISTRATION_PAGE, &key, ttl, || async {
                let doc = self
                    .fetch_json(repo, url)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(doc
                    .map(|doc| self.registration_leaves(&doc))
                    .unwrap_or_default())
            })
            .await
            .map_err(RepoError::Storage)
    }

    /// The pages of a registration index document (`items[]`).
    fn registration_pages(&self, doc: &JsonValue) -> Vec<UpstreamRegistrationPage> {
        let normalize = |v: Option<&JsonValue>| {
            v.and_then(JsonValue::as_str)
                .and_then(|raw| self.format.normalize_version(raw).ok())
        };
        doc.get("items")
            .and_then(JsonValue::as_array)
            .map(|pages| {
                pages
                    .iter()
                    .map(|page| UpstreamRegistrationPage {
                        url: page
                            .get("@id")
                            .and_then(JsonValue::as_str)
                            .map(str::to_string),
                        lower: normalize(page.get("lower")),
                        upper: normalize(page.get("upper")),
                        leaves: page
                            .get("items")
                            .filter(|items| items.is_array())
                            .map(|_| self.registration_leaves(page)),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The leaves (`items[]`) of a registration page, by normalized version.
    /// A leaf whose `catalogEntry` is not inlined carries no metadata and is
    /// skipped.
    fn registration_leaves(&self, page: &JsonValue) -> BTreeMap<String, UpstreamLeaf> {
        let mut out = BTreeMap::new();
        let Some(items) = page.get("items").and_then(JsonValue::as_array) else {
            return out;
        };
        for item in items {
            let Some(entry) = item.get("catalogEntry").filter(|e| e.is_object()) else {
                continue;
            };
            let Some(version) = entry
                .get("version")
                .and_then(JsonValue::as_str)
                .and_then(|raw| self.format.normalize_version(raw).ok())
            else {
                continue;
            };
            let published = entry
                .get("published")
                .and_then(JsonValue::as_str)
                .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
                .map(|at| at.with_timezone(&Utc));
            // `listed` is optional; NuGet clients then treat nuget.org's
            // 1900-01-01 `published` marker as unlisted.
            let listed = entry
                .get("listed")
                .and_then(JsonValue::as_bool)
                .unwrap_or_else(|| published.is_none_or(|at| at.year() > 1900));
            let groups = entry
                .get("dependencyGroups")
                .and_then(JsonValue::as_array)
                .map(|groups| {
                    groups
                        .iter()
                        .map(|group| {
                            let tfm = group
                                .get("targetFramework")
                                .and_then(JsonValue::as_str)
                                .filter(|t| !t.is_empty())
                                .map(str::to_string);
                            let deps = group
                                .get("dependencies")
                                .and_then(JsonValue::as_array)
                                .map(|deps| {
                                    deps.iter()
                                        .filter_map(|dep| {
                                            let id = dep.get("id")?.as_str()?.to_string();
                                            let range = dep
                                                .get("range")
                                                .and_then(JsonValue::as_str)
                                                .map(str::to_string);
                                            Some((id, range))
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            (tfm, deps)
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.insert(
                version,
                UpstreamLeaf {
                    id: entry
                        .get("id")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string),
                    listed,
                    published,
                    groups,
                },
            );
        }
        out
    }

    /// Search the locally known proxy corpus once, applying authorization
    /// before total-count calculation and client paging. Every per-version
    /// condition (listing state, package delay, not-found marker, prerelease,
    /// SemVer 2.0.0) runs in PostgreSQL, which returns only the matching ids;
    /// versions are loaded for the requested page alone, so an empty query
    /// over a large proxy cache does not load every cached version.
    /// With `enrich`, the returned page carries cached manifests
    /// ([`Self::enrich_hits`]); a group searches its members without and
    /// enriches only its own final page.
    async fn search_filtered(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
        enrich: bool,
    ) -> Result<SearchResult, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        let now = self.db_now().await?;
        // The `listable` conditions as bounds: past the delay window, and no
        // not-found marker younger than the TTL.
        let seen_before = now - Duration::seconds(i64::from(repo_row.package_delay_seconds));
        let marked_after = now - Self::not_found_ttl(&repo_row);
        let query = SearchQuery::parse(&params.q);
        let q = query.prefilter().unwrap_or("").to_string();
        // SemVer 2.0.0 for legacy clients: a `.` after a `-`. `version` is the
        // normalized form, which never holds build metadata, so a version whose
        // only SemVer 2.0.0 feature is `+metadata` is shown as its normalized
        // form, which those clients read (hosted filters `version_original`).
        let names = sqlx::query_scalar!(
            r#"
            SELECT DISTINCT name AS "name!"
            FROM proxy_cached_version
            WHERE repository_id = $1 AND version <> '*' AND confirmed AND NOT upstream_missing
              AND listed AND ($2 = '' OR strpos(name, $2) > 0)
              AND first_seen_at <= $3
              AND NOT (not_found AND not_found_at IS NOT NULL AND not_found_at > $4)
              AND ($5 OR strpos(version, '-') = 0)
              AND ($6 OR version !~ '-.*[.]')
            ORDER BY name
            "#,
            repo_row.id,
            q,
            seen_before,
            marked_after,
            params.prerelease,
            params.include_semver2,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut names: Vec<String> = names
            .into_iter()
            .filter(|name| filter.allows(name) && query.matches(name))
            .collect();
        // Byte order, as hosted and group results are ordered (SQL orders by
        // the database collation, which may weigh punctuation differently).
        names.sort_unstable();
        let total_hits = names.len();
        let page: Vec<String> = names
            .into_iter()
            .skip(params.skip.min(total_hits))
            .take(params.effective_take())
            .collect();

        let rows = sqlx::query_as!(
            forge_db::model::ProxyCachedVersion,
            r#"
            SELECT id, repository_id, name, version, listed, first_seen_at,
                   downloaded, metadata_refreshed_at, not_found, not_found_at
            FROM proxy_cached_version
            WHERE repository_id = $1 AND name = ANY($2::text[])
              AND version <> '*' AND confirmed AND NOT upstream_missing AND listed
              AND first_seen_at <= $3
              AND NOT (not_found AND not_found_at IS NOT NULL AND not_found_at > $4)
              AND ($5 OR strpos(version, '-') = 0)
              AND ($6 OR version !~ '-.*[.]')
            "#,
            repo_row.id,
            &page,
            seen_before,
            marked_after,
            params.prerelease,
            params.include_semver2,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut by_id: HashMap<String, Vec<VersionEntry>> = HashMap::new();
        for r in rows {
            by_id.entry(r.name.clone()).or_default().push(VersionEntry {
                original_id: r.name,
                version: r.version.clone(),
                version_original: r.version,
                listed: r.listed,
            });
        }

        // The id as the package spells it (rows hold the lowercased one).
        let original_ids: HashMap<String, String> =
            proxy_dao::original_ids(&self.pool, repo_row.id, &page)
                .await?
                .into_iter()
                .collect();
        let mut hits: Vec<SearchHit> = Vec::with_capacity(page.len());
        for name in &page {
            let Some(mut versions) = by_id.remove(name) else {
                // Changed between the two queries.
                continue;
            };
            versions.sort_by(|a, b| self.format.compare_versions(&a.version, &b.version));
            let original_id = original_ids
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.clone());
            for v in &mut versions {
                v.original_id.clone_from(&original_id);
            }
            let latest = versions.last().expect("non-empty versions");
            hits.push(SearchHit {
                original_id: latest.original_id.clone(),
                latest_version: latest.version.clone(),
                versions,
                ..Default::default()
            });
        }
        if enrich {
            self.enrich_hits(repo_row.id, &mut hits).await;
        }
        Ok(SearchResult { total_hits, hits })
    }

    /// Attach each hit's latest manifest. Manifests are known for cached
    /// packages only (no upstream fan-out per search hit); the local reads run
    /// with bounded concurrency, and a failed read leaves that hit without one.
    async fn enrich_hits(&self, repo_id: i64, hits: &mut [SearchHit]) {
        use futures_util::StreamExt;
        // A hit from the upstream's search carries its metadata already.
        let wanted: Vec<Option<(String, String)>> = hits
            .iter()
            .map(|hit| {
                hit.manifest_summary.is_none().then(|| {
                    (
                        self.format.lower_id(&hit.original_id),
                        hit.latest_version.clone(),
                    )
                })
            })
            .collect();
        let manifests: Vec<Option<Vec<u8>>> = futures_util::stream::iter(wanted)
            .map(|wanted| async move {
                let (id, version) = wanted?;
                self.local_nuspec(repo_id, &id, &version)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::warn!(error = %e, "search: manifest fetch failed");
                        None
                    })
            })
            .buffered(SEARCH_ENRICH_CONCURRENCY)
            .collect()
            .await;
        for (hit, manifest) in hits.iter_mut().zip(manifests) {
            hit.nuspec_bytes = manifest;
        }
    }
    /// The registration entries of `id`: every listable version, or only
    /// those in `only` (normalized). The upstream registration is consulted
    /// for the versions returned only, so a registration page or leaf fetches
    /// just the upstream pages covering its own versions (an index of more
    /// versions than [`MAX_REGISTRATION_PAGES`] upstream pages hold is paged,
    /// never rendered whole).
    async fn registration_of(
        &self,
        repo: &str,
        id: &str,
        only: Option<&[String]>,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        let Some(lower) = self.upstream_id(id) else {
            return Ok(Vec::new());
        };

        if self.negative_cached(&repo_row, &lower, "*").await? {
            return Ok(Vec::new());
        }

        let rows = self.discover_versions(&repo_row, &lower).await?;
        let now = self.db_now().await?;
        let mut visible: Vec<forge_db::model::ProxyCachedVersion> = rows
            .into_iter()
            .filter(|r| Self::listable(&repo_row, r, now))
            .filter(|r| {
                only.is_none_or(|only| only.iter().any(|v| v.eq_ignore_ascii_case(&r.version)))
            })
            .collect();
        visible.sort_by(|a, b| self.format.compare_versions(&a.version, &b.version));

        let wanted: Vec<String> = visible.iter().map(|r| r.version.clone()).collect();
        let upstream = self.upstream_leaves(&repo_row, &lower, &wanted).await;

        // Persist the upstream listing state so the flat index and search
        // report it too (best effort).
        let (changed, listed): (Vec<String>, Vec<bool>) = visible
            .iter()
            .filter_map(|r| {
                let leaf = upstream.get(&r.version)?;
                (leaf.listed != r.listed).then(|| (r.version.clone(), leaf.listed))
            })
            .unzip();
        if let Err(e) =
            proxy_dao::set_listed(&self.pool, repo_row.id, &lower, &changed, &listed).await
        {
            tracing::warn!(repo = %repo_row.name, id = %lower, error = %e, "persisting upstream listing state failed");
        }

        // packageHash + the stored manifest are known only for downloaded
        // versions: one query for all of them, with the manifest summary
        // stored at download. A version cached before summaries were stored
        // has its manifest read once (bounded concurrency) and backfilled.
        let rows = match only {
            None => {
                component_dao::list_registration_rows(
                    &self.pool,
                    repo_row.id,
                    &lower,
                    NUPKG_ASSET_PATH,
                )
                .await?
            }
            Some(_) => {
                component_dao::list_registration_rows_for_versions(
                    &self.pool,
                    repo_row.id,
                    &lower,
                    &wanted,
                    NUPKG_ASSET_PATH,
                )
                .await?
            }
        };
        let mut cached: HashMap<String, component_dao::RegistrationRow> = rows
            .into_iter()
            .map(|row| (row.version.clone(), row))
            .collect();
        let unsummarized: Vec<(i64, String)> = visible
            .iter()
            .filter(|r| r.downloaded)
            .filter_map(|r| cached.get(&r.version))
            .filter(|row| row.manifest_summary.is_none())
            .map(|row| (row.id, row.version.clone()))
            .collect();
        let mut manifests: HashMap<String, (Option<JsonValue>, Option<Vec<u8>>)> = {
            use futures_util::StreamExt;
            let (repo_id, name) = (repo_row.id, lower.as_str());
            futures_util::stream::iter(unsummarized)
                .map(|(component_id, version)| async move {
                    let manifest = self
                        .summarize_cached(repo_id, name, component_id, &version)
                        .await;
                    (version, manifest)
                })
                .buffered(8)
                .collect::<HashMap<_, _>>()
                .await
        };

        let mut out = Vec::with_capacity(visible.len());
        for r in visible {
            let leaf = upstream.get(&r.version);
            let (hash, summary, local) = match cached.remove(&r.version) {
                Some(row) if r.downloaded => {
                    let (summary, local) = match row.manifest_summary {
                        Some(summary) => (Some(summary), None),
                        None => manifests.remove(&r.version).unwrap_or_default(),
                    };
                    (row.package_hash_sha512_base64, summary, local)
                }
                _ => (None, None, None),
            };
            let original_id = leaf
                .and_then(|l| l.id.clone())
                .unwrap_or_else(|| r.name.clone());
            // Not downloaded: the dependency groups are known only from the
            // upstream registration.
            let nuspec_bytes = if summary.is_some() {
                None
            } else {
                local.or_else(|| {
                    leaf.and_then(|l| {
                        self.format.synthesize_manifest(
                            &original_id,
                            &r.version,
                            &l.dependency_groups(),
                        )
                    })
                })
            };
            out.push(RegistrationEntry {
                original_id,
                version: r.version.clone(),
                listed: leaf.map_or(r.listed, |l| l.listed),
                package_hash_sha512_base64: hash,
                nuspec_bytes,
                manifest_summary: summary,
                // Only the upstream registration knows the publish time (the
                // cache time would be misleading).
                published: leaf.and_then(|l| l.published),
            });
        }
        Ok(out)
    }

    /// [`Self::upstream_registration`] for `wanted`, without leaves that name
    /// another package (they are not this package's metadata). Records the
    /// package id's upstream casing for search (best effort).
    async fn upstream_leaves(
        &self,
        repo: &Repository,
        lower_id: &str,
        wanted: &[String],
    ) -> HashMap<String, UpstreamLeaf> {
        let mut upstream = self.upstream_registration(repo, lower_id, wanted).await;
        upstream.retain(|_, leaf| {
            leaf.id
                .as_deref()
                .is_none_or(|id| self.format.lower_id(id) == lower_id)
        });
        if let Some(original_id) = upstream.values().find_map(|leaf| leaf.id.as_deref()) {
            if let Err(e) =
                proxy_dao::record_original_id(&self.pool, repo.id, lower_id, original_id).await
            {
                tracing::warn!(repo = %repo.name, id = %lower_id, error = %e, "recording the upstream id casing failed");
            }
        }
        upstream
    }

    /// Date the package delay of `lower_id`'s versions still inside it from
    /// when the upstream published them, instead of from their first
    /// sighting here. The delay quarantines *new releases*: without this, a
    /// version published years ago but first seen now (every version of a
    /// package this proxy has not served before, all of them on a fresh
    /// install) was hidden for the whole delay.
    ///
    /// Only a listed version's upstream publish time counts, and only a
    /// plausible one: nuget.org reports unlisted versions as published in
    /// 1900, which would let a release unlisted right after publishing skip
    /// the quarantine, and a time in the future is ignored. Best effort: when
    /// the upstream registration is unavailable, the first sighting stands.
    async fn date_delay_from_upstream(&self, repo: &Repository, lower_id: &str) {
        let result: Result<(), RepoError> = async {
            let now = self.db_now().await?;
            let pending: Vec<forge_db::model::ProxyCachedVersion> = self
                .cached_rows(repo.id, lower_id)
                .await?
                .into_iter()
                .filter(|r| !Self::delay_cleared(repo, r.first_seen_at, now))
                .collect();
            if pending.is_empty() {
                return Ok(());
            }
            let wanted: Vec<String> = pending.iter().map(|r| r.version.clone()).collect();
            let leaves = self.upstream_leaves(repo, lower_id, &wanted).await;
            let (versions, published): (Vec<String>, Vec<DateTime<Utc>>) = pending
                .iter()
                .filter_map(|r| {
                    let leaf = leaves.get(&r.version).filter(|leaf| leaf.listed)?;
                    let at = leaf
                        .published
                        .filter(|at| *at >= min_trusted_publish_time() && *at <= now)?;
                    (at < r.first_seen_at).then(|| (r.version.clone(), at))
                })
                .unzip();
            proxy_dao::backdate_first_seen(&self.pool, repo.id, lower_id, &versions, &published)
                .await?;
            Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(repo = %repo.name, id = %lower_id, error = %e, "dating the package delay from the upstream failed");
        }
    }
}

/// Concurrent local manifest reads while enriching one proxy search page.
const SEARCH_ENRICH_CONCURRENCY: usize = 8;

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

#[async_trait]
impl RepoReadOps for ProxyRepo {
    async fn list_versions(&self, repo: &str, id: &str) -> Result<Vec<VersionEntry>, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        let Some(lower) = self.upstream_id(id) else {
            return Ok(Vec::new());
        };

        // Honor a still-valid genuine-404 negative cache for the whole id.
        if self.negative_cached(&repo_row, &lower, "*").await? {
            return Ok(Vec::new());
        }

        let rows = self.discover_versions(&repo_row, &lower).await?;
        let now = self.db_now().await?;
        let mut versions: Vec<VersionEntry> = rows
            .into_iter()
            .filter(|r| Self::listable(&repo_row, r, now))
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
        let Some(lower) = self.upstream_id(id) else {
            return Ok(None);
        };
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

    /// Like [`Self::resolve_nupkg`] (the package is cached on first sight), but
    /// a `HEAD` is not a pull: nothing is stamped.
    async fn resolve_nupkg_head(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        let Some(lower) = self.upstream_id(id) else {
            return Ok(None);
        };
        let norm = self
            .format
            .normalize_version(version)
            .map_err(|e| RepoError::Storage(format!("normalize version: {e}")))?;
        Box::pin(self.ensure_downloaded(&repo_row, &lower, &norm)).await
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
        let Some(lower) = self.upstream_id(id) else {
            return Ok(None);
        };
        let Ok(norm) = self.format.normalize_version(version) else {
            return Ok(None);
        };

        if let Some(row) =
            proxy_dao::get_cached_version(&self.pool, repo_row.id, &lower, &norm).await?
        {
            if !row.not_found
                && !Self::delay_cleared(&repo_row, row.first_seen_at, self.db_now().await?)
            {
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
        let rows = Box::pin(self.discover_versions(&repo_row, &lower)).await?;
        let now = self.db_now().await?;
        let known = rows
            .into_iter()
            .any(|r| r.version == norm && Self::listable(&repo_row, &r, now));
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

    /// Registration entries of the listable versions. `listed`, `published`
    /// and — for versions not downloaded yet — the dependency groups come from
    /// the upstream registration when it is available ([`Self::upstream_registration`]);
    /// the dependency groups are handed to the format layer as a manifest
    /// synthesized by [`Format::synthesize_manifest`]. A downloaded version
    /// serves its stored manifest and package hash.
    async fn registration(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        self.registration_of(repo, id, None).await
    }

    async fn registration_versions(&self, repo: &str, id: &str) -> Result<Vec<String>, RepoError> {
        // The listing alone: an index that does not inline its leaves needs
        // no upstream registration.
        let repo_row = self.proxy_repo(repo).await?;
        let Some(lower) = self.upstream_id(id) else {
            return Ok(Vec::new());
        };
        if self.negative_cached(&repo_row, &lower, "*").await? {
            return Ok(Vec::new());
        }
        let rows = self.discover_versions(&repo_row, &lower).await?;
        let now = self.db_now().await?;
        let mut versions: Vec<String> = rows
            .into_iter()
            .filter(|r| Self::listable(&repo_row, r, now))
            .map(|r| r.version)
            .collect();
        versions.sort_by(|a, b| self.format.compare_versions(a, b));
        Ok(versions)
    }

    async fn registration_entries(
        &self,
        repo: &str,
        id: &str,
        versions: &[String],
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        self.registration_of(repo, id, Some(versions)).await
    }

    async fn registration_entry(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<RegistrationEntry>, RepoError> {
        Ok(self
            .registration_of(repo, id, Some(&[version.to_string()]))
            .await?
            .into_iter()
            .next())
    }

    async fn search(&self, repo: &str, params: &SearchParams) -> Result<SearchResult, RepoError> {
        self.search_through_upstream(repo, params, &PackageFilter::AllowAll, true)
            .await
    }

    async fn search_with_package_filter(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        self.search_through_upstream(repo, params, filter, true)
            .await
    }

    async fn search_unenriched(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        self.search_through_upstream(repo, params, filter, false)
            .await
    }

    async fn enrich_search_hits(
        &self,
        repo: &str,
        hits: &mut [SearchHit],
    ) -> Result<(), RepoError> {
        if hits.is_empty() {
            return Ok(());
        }
        let repo_row = self.proxy_repo(repo).await?;
        self.enrich_hits(repo_row.id, hits).await;
        Ok(())
    }
}

/// One page of an upstream's search results, reduced to what a search hit
/// renders.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpstreamSearchPage {
    /// The upstream's total hit count.
    total_hits: usize,
    hits: Vec<UpstreamSearchHit>,
}

/// One package of an [`UpstreamSearchPage`].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpstreamSearchHit {
    /// Package id as the upstream spells it.
    id: String,
    /// The versions the upstream lists, normalized, ascending.
    versions: Vec<String>,
    /// Display metadata ([`Format::search_hit_summary`]).
    summary: Option<JsonValue>,
    total_downloads: Option<i64>,
}

impl ProxyRepo {
    /// Search `repo` through the upstream's `SearchQueryService` when the
    /// caller allows it ([`SearchParams::include_upstream`]), the proxy is
    /// online and the upstream advertises one; otherwise, and when the
    /// upstream search fails (and for [`UPSTREAM_SEARCH_BACKOFF`] after),
    /// search the cached packages ([`Self::search_filtered`]).
    async fn search_through_upstream(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
        enrich: bool,
    ) -> Result<SearchResult, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        if params.include_upstream
            && repo_row.online
            && !matches!(filter, PackageFilter::DenyAll)
            && !self.upstream_search_failed(&repo_row).await
        {
            match self.upstream_search(&repo_row, params).await {
                Ok(Some(page)) => {
                    return self
                        .upstream_search_result(&repo_row, params, filter, page)
                        .await;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(repo = %repo_row.name, error = %e, "upstream search failed; searching the cached packages for a minute");
                    let _ = self
                        .cache
                        .get_or_try_insert_local(
                            NS_UPSTREAM_SEARCH_FAILED,
                            &Self::upstream_scope(&repo_row),
                            UPSTREAM_SEARCH_BACKOFF,
                            || async { Ok::<_, ()>(true) },
                        )
                        .await;
                }
            }
        }
        self.search_filtered(repo, params, filter, enrich).await
    }

    /// Whether `repo`'s upstream search failed within the last
    /// [`UPSTREAM_SEARCH_BACKOFF`].
    async fn upstream_search_failed(&self, repo: &Repository) -> bool {
        // Lookup only: the factory never yields a value, so a miss caches
        // nothing.
        self.cache
            .get_or_try_insert_local(
                NS_UPSTREAM_SEARCH_FAILED,
                &Self::upstream_scope(repo),
                UPSTREAM_SEARCH_BACKOFF,
                || async { Err::<bool, ()>(()) },
            )
            .await
            .is_ok()
    }

    /// One page of the upstream's search results for `params`, cached for
    /// the metadata TTL. `None` when the upstream advertises no search
    /// service.
    async fn upstream_search(
        &self,
        repo: &Repository,
        params: &SearchParams,
    ) -> Result<Option<UpstreamSearchPage>, RepoError> {
        let resources = self.resolve_upstream_index(repo).await?;
        let Some(service) = resources.search_query_service else {
            return Ok(None);
        };
        let mut url = url::Url::parse(&service)
            .map_err(|e| RepoError::Storage(format!("upstream search service {service}: {e}")))?;
        // As much of `q` as a local search honors.
        let mut q_end = params.q.len().min(SearchQuery::MAX_QUERY_BYTES);
        while !params.q.is_char_boundary(q_end) {
            q_end -= 1;
        }
        let take = params.effective_take();
        url.query_pairs_mut()
            .append_pair("q", &params.q[..q_end])
            .append_pair("skip", &params.skip.to_string())
            .append_pair("take", &take.to_string())
            .append_pair("prerelease", &params.prerelease.to_string())
            .append_pair(
                "semVerLevel",
                if params.include_semver2 {
                    "2.0.0"
                } else {
                    "1.0.0"
                },
            );
        let ttl = Self::metadata_ttl(repo).to_std().unwrap_or_default();
        let key = format!("{}/{url}", Self::upstream_scope(repo));
        self.cache
            // Local-only: which packages exist upstream (see NS_UPSTREAM_NUSPEC).
            .get_or_try_insert_local(NS_UPSTREAM_SEARCH, &key, ttl, || async {
                let doc = self
                    .fetch_json(repo, url.as_str())
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("upstream search {url} returned 404"))?;
                Ok(self.upstream_search_page(&doc, params.skip, take))
            })
            .await
            .map(Some)
            .map_err(RepoError::Storage)
    }

    /// Read an upstream search response: at most `take` hits. An entry
    /// without a well-formed id (ids end up in Forge's URLs) is dropped, and
    /// the upstream's total reduced by it.
    fn upstream_search_page(
        &self,
        doc: &JsonValue,
        skip: usize,
        take: usize,
    ) -> UpstreamSearchPage {
        let entries: Vec<&JsonValue> = doc
            .get("data")
            .and_then(JsonValue::as_array)
            .map(|data| data.iter().take(take).collect())
            .unwrap_or_default();
        let returned = entries.len();
        let hits: Vec<UpstreamSearchHit> = entries
            .into_iter()
            .filter_map(|entry| self.upstream_search_hit(entry))
            .collect();
        let total_hits = doc
            .get("totalHits")
            .and_then(JsonValue::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0)
            .saturating_sub(returned - hits.len())
            .max(skip.saturating_add(hits.len()));
        UpstreamSearchPage { total_hits, hits }
    }

    /// One upstream search result entry with its parseable versions; `None`
    /// when its id is not well-formed.
    fn upstream_search_hit(&self, entry: &JsonValue) -> Option<UpstreamSearchHit> {
        let id = entry.get("id")?.as_str()?.trim();
        self.format.validate_id(id).ok()?;
        let normalize = |raw: &str| self.format.normalize_version(raw).ok();
        let mut versions: Vec<String> = entry
            .get("versions")
            .and_then(JsonValue::as_array)
            .map(|versions| {
                versions
                    .iter()
                    .filter_map(|v| normalize(v.get("version")?.as_str()?))
                    .collect()
            })
            .unwrap_or_default();
        if versions.is_empty() {
            versions.extend(
                entry
                    .get("version")
                    .and_then(JsonValue::as_str)
                    .and_then(normalize),
            );
        }
        versions.sort_by(|a, b| self.format.compare_versions(a, b));
        versions.dedup();
        Some(UpstreamSearchHit {
            id: id.to_string(),
            versions,
            summary: self.format.search_hit_summary(entry),
            total_downloads: entry.get("totalDownloads").and_then(JsonValue::as_i64),
        })
    }

    /// The search result for an upstream `page`, with the caller's package
    /// filter, the prerelease and SemVer 2.0.0 filters, and the proxy's own
    /// state of each version applied:
    ///
    /// * a version, or an id, under a live not-found marker is hidden;
    /// * with a package delay, a version is shown only once the proxy has
    ///   recorded it and it has cleared the delay. An upstream search names
    ///   no publish times, so a version the proxy has not seen yet counts as
    ///   inside the window.
    ///
    /// An id left without versions is dropped, and the upstream's total is
    /// reduced by the ids dropped from this page.
    async fn upstream_search_result(
        &self,
        repo: &Repository,
        params: &SearchParams,
        filter: &PackageFilter,
        page: UpstreamSearchPage,
    ) -> Result<SearchResult, RepoError> {
        let returned = page.hits.len();
        let hits: Vec<UpstreamSearchHit> = page
            .hits
            .into_iter()
            .filter(|hit| filter.allows(&hit.id))
            .collect();
        let names: Vec<String> = hits
            .iter()
            .map(|hit| self.format.lower_id(&hit.id))
            .collect();
        let rows = sqlx::query!(
            r#"
            SELECT name, version, confirmed, first_seen_at, not_found, not_found_at
            FROM proxy_cached_version
            WHERE repository_id = $1 AND name = ANY($2::text[])
            "#,
            repo.id,
            &names,
        )
        .fetch_all(&self.pool)
        .await?;
        let now = self.db_now().await?;
        let not_found_ttl = Self::not_found_ttl(repo);
        // `(name, version)` under a live marker; version `*` marks the id.
        let mut marked: HashSet<(String, String)> = HashSet::new();
        // `(name, version)` recorded and past the package delay.
        let mut cleared: HashSet<(String, String)> = HashSet::new();
        for row in rows {
            if row.not_found && row.not_found_at.is_some_and(|at| now - at < not_found_ttl) {
                marked.insert((row.name.clone(), row.version.clone()));
            }
            if row.confirmed && Self::delay_cleared(repo, row.first_seen_at, now) {
                cleared.insert((row.name, row.version));
            }
        }
        let delayed = repo.package_delay_seconds > 0;

        let mut out: Vec<SearchHit> = Vec::with_capacity(hits.len());
        for (hit, name) in hits.into_iter().zip(names) {
            if marked.contains(&(name.clone(), "*".to_string())) {
                continue;
            }
            let versions: Vec<VersionEntry> = hit
                .versions
                .into_iter()
                .filter(|v| params.prerelease || !v.contains('-'))
                .filter(|v| params.include_semver2 || !crate::repo::is_semver2(v))
                .filter(|v| {
                    let key = (name.clone(), v.clone());
                    !marked.contains(&key) && (!delayed || cleared.contains(&key))
                })
                .map(|version| VersionEntry {
                    original_id: hit.id.clone(),
                    version_original: version.clone(),
                    version,
                    listed: true,
                })
                .collect();
            let Some(latest) = versions.last() else {
                continue;
            };
            out.push(SearchHit {
                original_id: hit.id.clone(),
                latest_version: latest.version.clone(),
                versions,
                nuspec_bytes: None,
                manifest_summary: hit.summary,
                total_downloads: hit.total_downloads,
            });
        }
        let total_hits = page.total_hits.saturating_sub(returned - out.len());
        Ok(SearchResult {
            total_hits,
            hits: out,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_index_prefers_the_semver2_registration_variant() {
        let doc = serde_json::json!({
            "resources": [
                { "@id": "https://up/registration5-semver1/", "@type": "RegistrationsBaseUrl" },
                { "@id": "https://up/registration5-gz-semver2/", "@type": "RegistrationsBaseUrl/3.6.0" },
                { "@id": "https://up/registration5-gz-semver1", "@type": "RegistrationsBaseUrl/3.4.0" },
                { "@id": "https://up/flat", "@type": "PackageBaseAddress/3.0.0" },
            ]
        });
        let res = UpstreamResources::from_service_index(&doc);
        assert_eq!(
            res.registrations_base_url.as_deref(),
            Some("https://up/registration5-gz-semver2/")
        );
        assert_eq!(
            res.package_base_address.as_deref(),
            Some("https://up/flat/")
        );

        let only_semver1 = serde_json::json!({
            "resources": [ { "@id": "https://up/reg", "@type": "RegistrationsBaseUrl" } ]
        });
        assert_eq!(
            UpstreamResources::from_service_index(&only_semver1)
                .registrations_base_url
                .as_deref(),
            Some("https://up/reg/")
        );
    }

    #[test]
    fn persisted_index_records_its_url() {
        let resources = UpstreamResources {
            package_base_address: Some("https://up/flat/".into()),
            registrations_base_url: None,
            search_query_service: None,
        };
        let stored = serde_json::to_value(PersistedIndex {
            remote_url: "https://up/index.json".into(),
            resources: resources.clone(),
        })
        .unwrap();
        // The resources keep their shape; the URL is one more field.
        assert_eq!(
            serde_json::from_value::<UpstreamResources>(stored.clone()).unwrap(),
            resources
        );
        let parsed: PersistedIndex = serde_json::from_value(stored).unwrap();
        assert_eq!(parsed.remote_url, "https://up/index.json");
        assert_eq!(parsed.resources, resources);
        // A row written before the URL was recorded belongs to no URL.
        let legacy = serde_json::to_value(&resources).unwrap();
        assert!(serde_json::from_value::<PersistedIndex>(legacy).is_err());
    }

    #[test]
    fn upstream_leaf_maps_to_dependency_groups() {
        let leaf = UpstreamLeaf {
            id: Some("A".into()),
            listed: true,
            published: None,
            groups: vec![(
                Some("net8.0".into()),
                vec![("B".into(), Some("[1.0.0, )".into())), ("C".into(), None)],
            )],
        };
        let groups = leaf.dependency_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].target_framework.as_deref(), Some("net8.0"));
        assert_eq!(groups[0].dependencies[0].id, "B");
        assert_eq!(groups[0].dependencies[1].range, None);
    }
}
