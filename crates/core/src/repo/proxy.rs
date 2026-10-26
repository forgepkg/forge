//! Proxy-repository read operations.
//!
//! A proxy repository mirrors the upstream named by `repository.remote_url`.
//! What the upstream speaks is its format's business: the format's upstream
//! protocol ([`Format::upstream`], a format plugin's
//! [`forge_plugin_api::FormatPlugin::upstream`]) says which documents to fetch
//! for an operation and reads them; this module performs every request,
//! content-addresses package bytes through the [`Cas`], and records a
//! `proxy_cached_version` row so future reads are served locally. Everything
//! below is the host's, whatever the format.
//!
//! ## Hard invariants enforced here
//! * **Outbound scheme guard** — upstream URLs are validated to be http/https
//!   at config time ([`crate::net::ssrf::validate_url`]). Private/loopback
//!   upstreams are permitted (admin-only config).
//! * **Bounded upstream I/O** — every request goes through the shared
//!   [`UpstreamHttp`] client: connect / idle-read / total deadlines, size caps
//!   enforced while streaming, metadata spooled (memory → temp file) and
//!   `.nupkg` bodies streamed straight into a CAS temp file. Nothing is ever
//!   buffered whole in memory.
//! * **Credentials on every upstream request** — the configured Basic
//!   credentials are sent with the service index, version listing, `.nuspec`
//!   and `.nupkg` requests, but only to the `remote_url` host
//!   ([`crate::net::upstream`] credential scoping).
//! * **Requests only where the upstream points** — a request the format asks
//!   for, and the package URL it answers with, is sent only to the origin of
//!   `remote_url` or to an origin an absolute URL names in a document fetched
//!   from the upstream for the same conversation, or while resolving its
//!   index ([`crate::net::origins`]). Anything else is not sent: a format
//!   plugin may be code from elsewhere, and must not turn the proxy into a
//!   way to read the services around Forge (#233).
//! * **NO advisory locks, no DB transaction across network I/O** — first-time
//!   fetch singleflight is a plain row lock:
//!   [`proxy_dao::insert_unconfirmed_cached_version`] (INSERT … ON CONFLICT DO NOTHING) to
//!   guarantee a row exists, then [`proxy_dao::lock_or_insert_cached_version`]
//!   (SELECT … FOR UPDATE). The lock is held only for the short state-decision
//!   and finalize transactions; it is **released before** the upstream HTTP
//!   fetch and the CAS/S3 PUT, so the reconciler may prune a
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
//!   downloads *and* listings; an expired marker hides nothing, not even
//!   through the listing cached for the metadata TTL. An upstream version
//!   listing that contains the version clears its marker.
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
//! * **Invalidation** — an administrator makes a proxy ask its upstream again
//!   (`POST /admin/repositories/{name}/proxy-cache/invalidate`): the
//!   not-found markers of one package, or of all, are removed and
//!   `updated_at` is bumped, which drops every cached listing, document and
//!   verdict on every instance ([`ProxyRepo::upstream_scope`]); invalidating
//!   the whole repository also makes the upstream index due for a refresh.
//!   Downloaded packages and the package-delay clock are kept.
//! * **Search** — forwarded to the upstream's `SearchQueryService` (cached
//!   for the metadata TTL), so packages nobody has restored yet are found.
//!   The caller's package filter, live not-found markers and the package
//!   delay apply to the upstream's hits; when the upstream has no search
//!   service or its search fails, the locally cached packages are searched.
//! * **Offline** — `repository.online == false` serves only already-cached data;
//!   no upstream requests are made.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
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

use forge_plugin_api as api;
use forge_telemetry::proxy::{Kind as LookupKind, Lookup, Outcome};
use tracing::Instrument;

use crate::authz::PackageFilter;
use crate::format::Format;
use crate::net::origins::{named_origins, UpstreamOrigins};
use crate::net::upstream::{
    status_is_unavailable, Origin, RequestClass, UpstreamAuth, UpstreamError, UpstreamHttp,
};
use crate::repo::downloads::DownloadTally;
use crate::repo::hosted::BlobFetch;
use crate::repo::{
    NupkgLocation, RegistrationEntry, RepoError, RepoReadOps, SearchHit, SearchParams, SearchQuery,
    SearchResult, SharedRepoError, VersionEntry,
};

/// Cache namespace for resolved upstream indexes ([`api::UpstreamOp::Index`]),
/// keyed by `"{scope}"`. In this and the namespaces below, `scope` is
/// `"{repo}/{repo_id}/{remote_url digest}/{updated_at}"`, so nothing cached
/// from a previous upstream, or before a repoint, is used once a proxy is
/// repointed, and an administrator's cache invalidation (which bumps
/// `updated_at`) drops all of it on every instance.
pub const NS_UPSTREAM_INDEX: &str = "proxy_index";
/// Cache namespace marking a package's upstream version listing as fresh,
/// keyed by `"{scope}/{lower_id}"`.
pub const NS_UPSTREAM_VERSIONS: &str = "proxy_versions";
/// Cache namespace for the documents the format's upstream protocol fetched
/// ([`api::Fetch`]), keyed by `"{scope}/{url}"`, for as long as its
/// [`api::Freshness`] says.
pub const NS_UPSTREAM_FETCH: &str = "proxy_fetch";
/// Cache namespace marking a proxy whose upstream search failed, keyed by
/// `"{scope}"`; see [`UPSTREAM_SEARCH_BACKOFF`].
pub const NS_UPSTREAM_SEARCH_FAILED: &str = "proxy_search_failed";
/// Cache namespace remembering why an upstream package was rejected for its
/// content, keyed by `"{scope}/{lower_id}/{version}"`.
pub const NS_UPSTREAM_REJECTED: &str = "proxy_rejected";
/// Cache namespace marking a proxy whose upstream version listing failed,
/// keyed by `"{scope}"`; see [`UPSTREAM_LISTING_BACKOFF`].
pub const NS_UPSTREAM_LISTING_FAILED: &str = "proxy_listing_failed";

/// The earliest upstream creation time the package delay trusts
/// (2010-01-01, before any NuGet feed): nuget.org reports unlisted versions as
/// published in 1900.
fn min_trusted_publish_time() -> DateTime<Utc> {
    DateTime::from_timestamp(1_262_304_000, 0).expect("valid timestamp")
}

/// After an upstream search fails, the proxy searches only its cache for this
/// long, so an upstream that times out does not hold every search for the
/// whole metadata timeout.
const UPSTREAM_SEARCH_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);
/// After an upstream version listing fails, the proxy answers listings of
/// the ids it has cached versions of from its cache, without asking the
/// upstream, for this long: an upstream that times out does not hold every
/// listing for the whole connect or metadata timeout before the cache
/// answers. Ids without cached versions still ask it.
const UPSTREAM_LISTING_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);
/// Default metadata TTL when a proxy leaves `metadata_ttl_seconds` unset.
const DEFAULT_METADATA_TTL_SECONDS: i64 = 600;
/// Default negative-cache TTL when a proxy leaves `not_found_ttl_seconds` unset.
pub const DEFAULT_NOT_FOUND_TTL_SECONDS: i64 = 600;
/// How long a document the upstream publishes once and never changes
/// ([`api::Freshness::Immutable`]: a version's manifest, a catalog entry) is
/// reused.
const IMMUTABLE_FETCH_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
/// Rounds of one upstream conversation ([`ProxyRepo::converse`]).
const MAX_UPSTREAM_ROUNDS: usize = 4;
/// Fetches of one upstream conversation, all rounds together.
const MAX_UPSTREAM_FETCHES: usize = 256;
/// The bytes of the documents one upstream conversation keeps, all rounds
/// together, in documents of `proxy.max_metadata_bytes` (its bound on one
/// document): its fetches are bounded in number, but at that size each, 256
/// of them would hold gigabytes.
const CONVERSATION_BUDGET_DOCUMENTS: u64 = 4;
/// Concurrent fetches of one round.
const FETCH_CONCURRENCY: usize = 4;

/// The `proxy_upstream_index.resources` JSON: the index the format resolved
/// ([`api::UpstreamOp::Index`], a JSON object), the `remote_url` it was
/// resolved from, and the origins the documents fetched to resolve it named.
/// A row that came from another URL (the proxy has been repointed since), or
/// that predates `remote_url`, is never used.
///
/// The host's fields sit beside the format's keys, which may not use their
/// names ([`Self::HOST_KEYS`]): a format must not be able to write the
/// origins its later requests may reach.
#[derive(Clone, Serialize, Deserialize)]
struct PersistedIndex {
    remote_url: String,
    /// The origins the documents fetched while resolving the index named
    /// ([`named_origins`]): every later conversation may reach them
    /// (NuGet's resources on other hosts). `None` in a row written before
    /// they were recorded: it is resolved again at its next use, and serves
    /// meanwhile (offline, or while the upstream fails) with the
    /// `remote_url`'s origin alone, never with origins read from the
    /// format's index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    named_origins: Option<BTreeSet<Origin>>,
    #[serde(flatten)]
    index: serde_json::Map<String, JsonValue>,
}

impl PersistedIndex {
    /// The keys the host keeps beside the format's index.
    const HOST_KEYS: [&'static str; 2] = ["remote_url", "named_origins"];

    /// The index as the format reads it ([`api::Remote::index`]).
    fn index(&self) -> String {
        JsonValue::Object(self.index.clone()).to_string()
    }
}

/// A fetched document as cached: a body (base64, so the cache's JSON
/// encoding stays compact) with the origins its URLs name
/// ([`named_origins`], read once per fetch rather than once per
/// conversation: a Helm index is read by every operation), or a 404.
#[derive(Clone, Serialize, Deserialize)]
enum CachedFetch {
    Found { body: String, named: Vec<Origin> },
    NotFound,
}

/// The outcome of a proxy lookup that failed with `e`: the upstream's fault
/// when the error says so or the path marked it, else Forge's.
fn error_outcome(e: &RepoError, marked: Option<Outcome>) -> Outcome {
    match e {
        RepoError::Upstream(_) | RepoError::BadUpstream(_) => Outcome::UpstreamError,
        _ if marked == Some(Outcome::UpstreamError) => Outcome::UpstreamError,
        _ => Outcome::Error,
    }
}

/// Map an upstream transport/size/parse failure onto the read-path error:
/// an unavailable upstream ([`UpstreamError::is_unavailable`]) is
/// [`RepoError::Upstream`], a refusing one ([`UpstreamError::is_refusal`])
/// [`RepoError::BadUpstream`], any other failure the proxy's own.
fn upstream_err(e: UpstreamError) -> RepoError {
    match Trouble::of(&e) {
        Trouble::Unavailable | Trouble::RateLimited => RepoError::Upstream(e.to_string()),
        Trouble::Refused => RepoError::BadUpstream(e.to_string()),
        Trouble::None => RepoError::Storage(e.to_string()),
    }
}

/// Why a fetch of [`ProxyRepo::fetch`] failed: the reason the format is told,
/// and what it says about the upstream ([`Trouble`]).
#[derive(Clone)]
struct FetchFailure {
    reason: String,
    trouble: Trouble,
}

impl FetchFailure {
    /// A failure of the proxy itself, not of the upstream.
    fn local(reason: String) -> Self {
        Self {
            reason,
            trouble: Trouble::None,
        }
    }
}

/// What a failed fetch says about the upstream, worst last.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Trouble {
    /// Nothing: the fetch went well, or failed on this side.
    #[default]
    None,
    /// It refused the proxy (a 401, a 403): [`RepoError::BadUpstream`].
    Refused,
    /// It rate-limited this request (a 429).
    RateLimited,
    /// It cannot serve now: [`RepoError::Upstream`].
    Unavailable,
}

impl Trouble {
    fn of(e: &UpstreamError) -> Self {
        if matches!(e, UpstreamError::Status { status, .. } if *status == reqwest::StatusCode::TOO_MANY_REQUESTS)
        {
            Trouble::RateLimited
        } else if e.is_unavailable() {
            Trouble::Unavailable
        } else if e.is_refusal() {
            Trouble::Refused
        } else {
            Trouble::None
        }
    }
}

/// Decrypted upstream Basic credentials, held only for one request.
pub struct Credentials {
    origin: Option<Origin>,
    username: String,
    password: forge_crypto::PlaintextSecret,
    bearer: bool,
}

impl Credentials {
    /// Basic credentials sent only to the origin of `url` (and to a token
    /// service that origin's challenge names, see [`Self::auth_for`]).
    pub fn for_url(url: &str, username: String, password: forge_crypto::PlaintextSecret) -> Self {
        Credentials {
            origin: Origin::of(url),
            username,
            password,
            bearer: false,
        }
    }

    /// Send the password as an `Authorization: Bearer` token when there is
    /// no username and `enabled` (a format whose upstreams take tokens so:
    /// npm's `_authToken`).
    pub fn bearer_without_username(mut self, enabled: bool) -> Self {
        self.bearer = enabled && self.username.is_empty();
        self
    }

    /// The credentials, scoped to the origin of the `remote_url` they were
    /// stored for.
    pub fn auth(&self) -> UpstreamAuth<'_> {
        UpstreamAuth {
            origin: self.origin.clone(),
            username: &self.username,
            password: self.password.expose_secret(),
            bearer: self.bearer,
        }
    }

    /// The credentials scoped to `origin` instead: a registry's token service
    /// named by the upstream's own authentication challenge (Docker Hub's
    /// `auth.docker.io` for `registry-1.docker.io`).
    pub fn auth_for(&self, origin: Origin) -> UpstreamAuth<'_> {
        UpstreamAuth {
            origin: Some(origin),
            username: &self.username,
            password: self.password.expose_secret(),
            bearer: self.bearer,
        }
    }
}

/// Resolve the upstream password for the outbound Basic header — the
/// **single sanctioned decrypt site** of the proxy credential,
/// shared by every format's proxy: the sealed password decrypts through
/// `forge_db::secret_dao` (re-reading the row so the AAD binds to fresh data,
/// its `remote_url` origin included). Returns the password with the
/// `remote_url` it belongs to.
async fn upstream_password(
    pool: &PgPool,
    envelope: &forge_crypto::service::EnvelopeService,
    repo: &Repository,
) -> Result<Option<(forge_crypto::PlaintextSecret, Option<String>)>, RepoError> {
    if repo.upstream_password_enc.is_none() {
        return Ok(None);
    }
    forge_db::secret_dao::get_upstream_credential(pool, envelope, repo.id)
        .await
        .map(|found| found.map(|p| (p.secret, p.remote_url)))
        .map_err(|e| RepoError::Storage(format!("decrypt upstream password: {e}")))
}

/// The upstream secret of `repo` alone, with the `remote_url` it belongs
/// to: what a proxy sends as a Bearer token when it has no username (npm
/// registries take a token). Decrypted like [`upstream_credentials`].
pub async fn upstream_secret(
    pool: &PgPool,
    envelope: &forge_crypto::service::EnvelopeService,
    repo: &Repository,
) -> Result<Option<(forge_crypto::PlaintextSecret, Option<String>)>, RepoError> {
    upstream_password(pool, envelope, repo).await
}

/// The Basic credentials for `repo`'s upstream, if both a username and a
/// password are configured. They are attached only to the origin of the
/// `remote_url` the password was read (and, encrypted, bound) with, which
/// may be newer than the cached `repo` row.
pub async fn upstream_credentials(
    pool: &PgPool,
    envelope: &forge_crypto::service::EnvelopeService,
    repo: &Repository,
) -> Result<Option<Credentials>, RepoError> {
    let Some(username) = repo.upstream_username.clone() else {
        return Ok(None);
    };
    let Some((password, remote_url)) = upstream_password(pool, envelope, repo).await? else {
        return Ok(None);
    };
    Ok(Some(Credentials {
        origin: remote_url.as_deref().and_then(Origin::of),
        username,
        password,
        bearer: false,
    }))
}

/// The credentials a proxy sends its upstream: Basic with a username
/// ([`upstream_credentials`]), or, for a format whose upstreams take tokens
/// so (`bearer_token`, [`Format::upstream_bearer_token`]), a password stored
/// without one as a Bearer token.
pub async fn upstream_auth(
    pool: &PgPool,
    envelope: &forge_crypto::service::EnvelopeService,
    repo: &Repository,
    bearer_token: bool,
) -> Result<Option<Credentials>, RepoError> {
    if repo.upstream_username.is_none() && bearer_token {
        return Ok(upstream_password(pool, envelope, repo)
            .await?
            .map(|(password, remote_url)| {
                let url = remote_url
                    .or_else(|| repo.remote_url.clone())
                    .unwrap_or_default();
                Credentials::for_url(&url, String::new(), password).bearer_without_username(true)
            }));
    }
    upstream_credentials(pool, envelope, repo).await
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
    /// Envelope service decrypting the sealed `upstream_password_enc`.
    envelope: Arc<forge_crypto::service::EnvelopeService>,
    /// Counts `.nupkg` downloads and writes them in batches.
    downloads: Arc<DownloadTally>,
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

    /// Build a proxy read facade over the process-wide default upstream client,
    /// decrypting the upstream password with `envelope`. It counts downloads
    /// in a tally of its own unless it is given the process's
    /// ([`Self::with_download_tally`]).
    pub fn new(
        pool: PgPool,
        format: Arc<dyn Format>,
        cas: Cas,
        cache: Cache,
        envelope: Arc<forge_crypto::service::EnvelopeService>,
    ) -> Self {
        ProxyRepo {
            downloads: DownloadTally::new(pool.clone()),
            pool,
            format,
            cas,
            cache,
            http: UpstreamHttp::shared_default(),
            blobs: None,
            envelope,
        }
    }

    /// Use `http` (built from the server's `[proxy]` config) for upstream
    /// traffic.
    pub fn with_http(mut self, http: UpstreamHttp) -> Self {
        self.http = http;
        self
    }

    /// Count downloads in `downloads`, shared with the other facades.
    pub fn with_download_tally(mut self, downloads: Arc<DownloadTally>) -> Self {
        self.downloads = downloads;
        self
    }

    /// Attach blob byte access so cached manifests can be served locally.
    pub fn with_blob_fetch(mut self, blobs: Arc<dyn BlobFetch>) -> Self {
        self.blobs = Some(blobs);
        self
    }

    /// The Basic credentials for `repo`'s upstream (see
    /// [`upstream_credentials`]).
    async fn credentials(&self, repo: &Repository) -> Result<Option<Credentials>, RepoError> {
        upstream_auth(
            &self.pool,
            &self.envelope,
            repo,
            self.format.upstream_bearer_token(),
        )
        .await
    }

    /// Run one upstream conversation: ask the format what to fetch for `op`,
    /// fetch it ([`Self::fetch`]), and ask again with everything fetched so
    /// far, until the format answers. `index` is the resolved upstream index
    /// (`None` while resolving it). Bounded to [`MAX_UPSTREAM_ROUNDS`] rounds
    /// and [`MAX_UPSTREAM_FETCHES`] fetches; the format runs off the async
    /// workers, as a format plugin may take its time.
    ///
    /// The documents fetched are kept up to [`CONVERSATION_BUDGET_DOCUMENTS`]
    /// × `proxy.max_metadata_bytes` in all: a document past that is dropped
    /// (and the conversation's later fetches are not sent), and the format
    /// is told so, as of any failed fetch ([`Self::over_budget`]).
    ///
    /// Only the origins the upstream points at are reached
    /// ([`UpstreamOrigins`]): the `remote_url`'s, those `index` recorded, and
    /// those the documents fetched in earlier rounds name. A fetch anywhere
    /// else is not sent ([`Self::refuse`]), and a package URL anywhere else
    /// is answered as an upstream failure. Returns the answer with the
    /// origins the conversation could reach at its end, which resolving the
    /// index records.
    async fn converse(
        &self,
        repo: &Repository,
        index: Option<&PersistedIndex>,
        op: api::UpstreamOp,
    ) -> Result<(api::UpstreamAnswer, UpstreamOrigins), RepoError> {
        use futures_util::StreamExt;
        let remote = api::Remote {
            url: repo.remote_url.clone().unwrap_or_default(),
            index: index.map(PersistedIndex::index),
        };
        let mut origins = UpstreamOrigins::new(
            &remote.url,
            index
                .and_then(|index| index.named_origins.clone())
                .unwrap_or_default(),
        );
        let mut fetched: Vec<api::FetchResult> = Vec::new();
        // A fetch found the upstream unavailable, or refusing the proxy: the
        // format's failed answer is then the upstream's outage or refusal,
        // not a fault of the proxy.
        let mut trouble = Trouble::None;
        let budget = self
            .http
            .config()
            .max_metadata_bytes
            .saturating_mul(CONVERSATION_BUDGET_DOCUMENTS);
        // The bytes of the bodies in `fetched`, and whether one was dropped
        // for the budget (then nothing more is sent).
        let held = AtomicU64::new(0);
        let exhausted = AtomicBool::new(false);
        for _ in 0..MAX_UPSTREAM_ROUNDS {
            let format = self.format.clone();
            let (asked, round) = (remote.clone(), op.clone());
            let (step, back) = tokio::task::spawn_blocking(move || {
                let step = format.upstream(&asked, &round, &fetched);
                (step, fetched)
            })
            .await
            .map_err(|e| RepoError::Storage(format!("upstream protocol: {e}")))?;
            fetched = back;
            let wanted = match step
                .map_err(|e| RepoError::Storage(format!("upstream protocol: {e}")))?
            {
                api::UpstreamStep::Done(api::UpstreamAnswer::Package(url))
                    if !origins.permits(&url) =>
                {
                    tracing::warn!(format = %self.format.id(), repo = %repo.name, %url, "the format answered a package URL on an origin neither the remote_url nor a document fetched from the upstream names; not downloaded");
                    let reason = format!(
                        "upstream package {url}: not downloaded, its origin is neither the \
                             remote_url's nor named by a document fetched from the upstream"
                    );
                    return Ok((api::UpstreamAnswer::Failed(reason), origins));
                }
                api::UpstreamStep::Done(api::UpstreamAnswer::File(Some(url)))
                    if !origins.permits(&url) =>
                {
                    tracing::warn!(format = %self.format.id(), repo = %repo.name, %url, "the format answered a file URL on an origin neither the remote_url nor a document fetched from the upstream names; not downloaded");
                    let reason = format!(
                        "upstream file {url}: not downloaded, its origin is neither the \
                             remote_url's nor named by a document fetched from the upstream"
                    );
                    return Ok((api::UpstreamAnswer::Failed(reason), origins));
                }
                api::UpstreamStep::Done(api::UpstreamAnswer::Located(location))
                    if !origins.permits(&location.url) =>
                {
                    tracing::warn!(format = %self.format.id(), repo = %repo.name, url = %location.url, "the format answered a package URL on an origin neither the remote_url nor a document fetched from the upstream names; not downloaded");
                    let reason = format!(
                        "upstream package {}: not downloaded, its origin is neither the \
                             remote_url's nor named by a document fetched from the upstream",
                        location.url
                    );
                    return Ok((api::UpstreamAnswer::Failed(reason), origins));
                }
                api::UpstreamStep::Done(api::UpstreamAnswer::Failed(reason))
                    if trouble == Trouble::Unavailable
                        || (trouble == Trouble::RateLimited
                            && !matches!(op, api::UpstreamOp::Search(_))) =>
                {
                    return Err(RepoError::Upstream(reason));
                }
                api::UpstreamStep::Done(api::UpstreamAnswer::Failed(reason))
                    if trouble == Trouble::Refused =>
                {
                    return Err(RepoError::BadUpstream(reason));
                }
                api::UpstreamStep::Done(answer) => return Ok((answer, origins)),
                api::UpstreamStep::Fetch(wanted) => wanted,
            };
            if wanted.is_empty() || fetched.len() + wanted.len() > MAX_UPSTREAM_FETCHES {
                return Err(RepoError::Storage(format!(
                    "upstream protocol asked for {} fetches after {}",
                    wanted.len(),
                    fetched.len()
                )));
            }
            // Each fetch is judged by the origins known when the round
            // starts; what its document names counts from the next round.
            let results: Vec<(api::FetchResult, Vec<Origin>, Trouble)> =
                futures_util::stream::iter(wanted)
                    .map(|fetch| {
                        let permitted = origins.permits(&fetch.url);
                        let (held, exhausted) = (&held, &exhausted);
                        async move {
                            let (outcome, named, down) = if !permitted {
                                (self.refuse(repo, &fetch.url), Vec::new(), Trouble::None)
                            } else if exhausted.load(Ordering::Relaxed) {
                                (Self::over_budget(&fetch.url, budget), Vec::new(), Trouble::None)
                            } else {
                                match self.fetch(repo, &fetch).await {
                                    (api::Fetched::Found(body), named, down) => {
                                        let size = body.len() as u64;
                                        let kept = held
                                            .try_update(Ordering::Relaxed, Ordering::Relaxed, |h| {
                                                h.checked_add(size).filter(|total| *total <= budget)
                                            })
                                            .is_ok();
                                        if kept {
                                            (api::Fetched::Found(body), named, down)
                                        } else {
                                            if !exhausted.swap(true, Ordering::Relaxed) {
                                                tracing::warn!(format = %self.format.id(), repo = %repo.name, url = %fetch.url, budget, "an upstream conversation's documents exceed its byte budget; the rest are not read");
                                            }
                                            (Self::over_budget(&fetch.url, budget), Vec::new(), Trouble::None)
                                        }
                                    }
                                    other => other,
                                }
                            };
                            let result = api::FetchResult {
                                fetch,
                                outcome,
                                status: None,
                                headers: Vec::new(),
                            };
                            (result, named, down)
                        }
                    })
                    .buffered(FETCH_CONCURRENCY)
                    .collect()
                    .await;
            for (result, named, down) in results {
                origins.extend(named);
                fetched.push(result);
                trouble = trouble.max(down);
            }
        }
        Err(RepoError::Storage(format!(
            "upstream protocol needed more than {MAX_UPSTREAM_ROUNDS} rounds"
        )))
    }

    /// The outcome of a fetch past the byte budget of its conversation
    /// ([`Self::converse`]): its body is not kept, or it is not sent at all,
    /// and the format is told so.
    fn over_budget(url: &str, budget: u64) -> api::Fetched {
        api::Fetched::Failed(format!(
            "{url}: not read, the documents fetched for this operation would exceed \
             {budget} bytes ({CONVERSATION_BUDGET_DOCUMENTS} x proxy.max_metadata_bytes)"
        ))
    }

    /// The outcome of a fetch on an origin the conversation may not reach
    /// ([`Self::converse`]): nothing is sent, and the format is told so.
    fn refuse(&self, repo: &Repository, url: &str) -> api::Fetched {
        tracing::warn!(format = %self.format.id(), repo = %repo.name, %url, "the format asked for an upstream URL on an origin neither the remote_url nor a document fetched from the upstream names; not sent");
        api::Fetched::Failed(format!(
            "{url}: not sent, its origin is neither the remote_url's nor named by a document \
             fetched from the upstream"
        ))
    }

    /// GET one upstream document with the proxy's credentials, through the
    /// local cache for as long as its freshness allows (never Redis: what an
    /// upstream answered decides what is downloaded and served). Returns it
    /// with the origins its URLs name ([`named_origins`]).
    ///
    /// A 404 is cached only for an immutable document: a metadata 404 (a
    /// package the upstream does not know yet) is what the not-found
    /// markers track, and they are cleared as soon as the package turns up.
    /// The [`Trouble`] says whether a failed fetch found the upstream
    /// unavailable ([`UpstreamError::is_unavailable`]) or refusing the proxy
    /// ([`UpstreamError::is_refusal`]).
    async fn fetch(
        &self,
        repo: &Repository,
        fetch: &api::Fetch,
    ) -> (api::Fetched, Vec<Origin>, Trouble) {
        let ttl = match fetch.freshness {
            api::Freshness::Metadata => Self::metadata_ttl(repo).to_std().unwrap_or_default(),
            api::Freshness::Immutable => IMMUTABLE_FETCH_TTL,
        };
        // What the fetch accepts is part of what it is (npm's abbreviated
        // and full packuments share a URL).
        let key = match &fetch.accept {
            Some(accept) => format!("{}/{}\n{accept}", Self::upstream_scope(repo), fetch.url),
            None => format!("{}/{}", Self::upstream_scope(repo), fetch.url),
        };
        let cached: Result<CachedFetch, Option<FetchFailure>> = self
            .cache
            .get_or_try_insert_local(NS_UPSTREAM_FETCH, &key, ttl, || async {
                let creds = self
                    .credentials(repo)
                    .await
                    .map_err(|e| Some(FetchFailure::local(e.to_string())))?;
                let auth = creds.as_ref().map(Credentials::auth);
                match self
                    .http
                    .for_repository(&repo.name)
                    .get_bytes_accepting(&fetch.url, auth.as_ref(), fetch.accept.as_deref())
                    .await
                {
                    Ok(Some(bytes)) => {
                        // A document may be megabytes: read off the async
                        // workers.
                        let (bytes, named) = tokio::task::spawn_blocking(move || {
                            let named = named_origins(&bytes);
                            (bytes, named)
                        })
                        .await
                        .map_err(|e| {
                            Some(FetchFailure::local(format!("read {}: {e}", fetch.url)))
                        })?;
                        Ok(CachedFetch::Found {
                            body: base64::engine::general_purpose::STANDARD.encode(bytes),
                            named: named.into_iter().collect(),
                        })
                    }
                    Ok(None) if fetch.freshness == api::Freshness::Immutable => {
                        Ok(CachedFetch::NotFound)
                    }
                    Ok(None) => Err(None),
                    Err(e) => Err(Some(FetchFailure {
                        trouble: Trouble::of(&e),
                        reason: e.to_string(),
                    })),
                }
            })
            .await;
        match cached {
            Ok(CachedFetch::Found { body, named }) => {
                match base64::engine::general_purpose::STANDARD.decode(body) {
                    Ok(bytes) => (api::Fetched::Found(bytes), named, Trouble::None),
                    Err(e) => (
                        api::Fetched::Failed(format!("cached {}: {e}", fetch.url)),
                        Vec::new(),
                        Trouble::None,
                    ),
                }
            }
            Ok(CachedFetch::NotFound) | Err(None) => {
                (api::Fetched::NotFound, Vec::new(), Trouble::None)
            }
            Err(Some(failure)) => (
                api::Fetched::Failed(failure.reason),
                Vec::new(),
                failure.trouble,
            ),
        }
    }

    /// The upstream URL of the file at `path` of proxy `repo`
    /// ([`api::UpstreamOp::File`], a files format), on an origin the
    /// upstream points at; `None` when the upstream cannot have it. The
    /// file store downloads and re-validates it.
    pub async fn file_url(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<Option<String>, RepoError> {
        match self
            .converse_resolved(repo, api::UpstreamOp::File(path.to_string()))
            .await?
        {
            api::UpstreamAnswer::File(url) => Ok(url),
            api::UpstreamAnswer::Failed(reason) => Err(RepoError::Storage(reason)),
            _ => Err(RepoError::Storage(
                "upstream protocol answered file with something else".into(),
            )),
        }
    }

    /// The upstream index, resolved, for `op` on `repo`.
    async fn converse_resolved(
        &self,
        repo: &Repository,
        op: api::UpstreamOp,
    ) -> Result<api::UpstreamAnswer, RepoError> {
        let index = Box::pin(self.upstream_index(repo)).await?;
        let (answer, _) = self.converse(repo, Some(&index), op).await?;
        Ok(answer)
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
    /// afresh), a digest of its `remote_url`, so a repointed proxy never
    /// serves what the previous upstream answered, and the row's
    /// `updated_at`, so every repoint starts afresh too. Repointing resets
    /// what the proxy learned (`reset_for_new_upstream` deletes the listed
    /// versions not downloaded yet); without the timestamp, pointing back to
    /// an upstream within the metadata TTL found that upstream's "listing
    /// refreshed" marker still valid and served the emptied listing until
    /// it expired. The timestamp is also how an administrator invalidates
    /// the cache (`POST /admin/repositories/{name}/proxy-cache/invalidate`):
    /// every instance reads the row per request, so bumping it reaches them
    /// all, Redis or not. A digest rather than the URL itself keeps keys that
    /// append another URL unambiguous.
    pub fn upstream_scope(repo: &Repository) -> String {
        let digest = Sha256::digest(repo.remote_url.as_deref().unwrap_or_default());
        format!(
            "{}/{}/{}/{}",
            repo.name,
            repo.id,
            hex::encode(&digest[..8]),
            repo.updated_at.timestamp_micros()
        )
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

    // ── Upstream index (Task 8.1) ────────────────────────────────────────────

    /// Resolve `repo`'s upstream index ([`api::UpstreamOp::Index`]: for a
    /// NuGet V3 feed, the resources of its service index), reading through
    /// the per-instance cache (never Redis) and persisting to
    /// `proxy_upstream_index`.
    ///
    /// Layering:
    /// 1. **Cache** (`get_or_try_insert_local`, TTL = metadata_ttl) — per-instance
    ///    coalescing + short-circuit; a 2nd call within TTL never touches DB or
    ///    upstream.
    /// 2. **DB freshness** — on an L1 miss, if `proxy_upstream_index.fetched_at`
    ///    is within metadata_ttl, reuse it without a network call. Only a row
    ///    fetched from the current `remote_url` is used, fresh or stale, and
    ///    a row without the origins its documents named
    ///    ([`PersistedIndex::named_origins`]) is never fresh.
    /// 3. **Refresh** — otherwise resolve the index again (no DB transaction
    ///    or row lock held across the requests) and upsert it. Concurrent
    ///    instances may both refresh; the result is idempotent.
    ///
    /// The cache key is the [upstream scope](Self::upstream_scope) and the
    /// persisted row records its URL, so a changed upstream (or a
    /// deleted-and-recreated repository) never serves the old upstream's
    /// index.
    pub async fn resolve_upstream_index(&self, repo: &Repository) -> Result<String, RepoError> {
        Ok(self.upstream_index(repo).await?.index())
    }

    /// [`Self::resolve_upstream_index`], with the origins recorded with the
    /// index ([`PersistedIndex::named_origins`]).
    async fn upstream_index(&self, repo: &Repository) -> Result<PersistedIndex, RepoError> {
        let ttl = Self::metadata_ttl(repo);
        let remote_url = repo
            .remote_url
            .clone()
            .ok_or_else(|| RepoError::Storage("proxy repository has no remote_url".into()))?;
        let key = Self::upstream_scope(repo);

        // The cache factory error must be `Clone` (moka coalescing shares an
        // `Arc<E>` across waiters); `RepoError` wraps non-`Clone` `sqlx::Error`,
        // so the factory yields a `SharedRepoError`, which keeps the error's
        // kind (an unavailable upstream stays one).
        // Local-only (never read from Redis): the index decides which host
        // packages are downloaded from, and a downloaded package is cached for
        // good, so a forged index in Redis would substitute packages (and its
        // origins would let the format reach any host).
        self.cache
            .get_or_try_insert_local(
                NS_UPSTREAM_INDEX,
                &key,
                ttl.to_std().unwrap_or_default(),
                || async {
                    self.resolve_index_uncached(repo, ttl, &remote_url)
                        .await
                        .map_err(SharedRepoError::from)
                },
            )
            .await
            .map_err(RepoError::from)
    }

    /// The uncached body of [`Self::upstream_index`]: DB-freshness
    /// short-circuit, offline handling, and refresh.
    async fn resolve_index_uncached(
        &self,
        repo: &Repository,
        ttl: Duration,
        remote_url: &str,
    ) -> Result<PersistedIndex, RepoError> {
        // An index resolved from another URL is not this upstream's: neither
        // reused nor fallen back to below.
        let persisted = proxy_dao::get_upstream_index(&self.pool, repo.id)
            .await?
            .and_then(|idx| {
                let stored: PersistedIndex = serde_json::from_value(idx.resources).ok()?;
                (stored.remote_url == remote_url).then_some((stored, idx.fetched_at))
            });
        if let Some((stored, fetched_at)) = &persisted {
            // A row without the origins its documents named is resolved
            // again now, whatever its age.
            if stored.named_origins.is_some() && self.db_now().await? - *fetched_at < ttl {
                return Ok(stored.clone());
            }
        }

        // Offline: never fetch. Serve a persisted (possibly stale) index if present.
        if !repo.online {
            return match persisted {
                Some((stored, _)) => Ok(stored),
                None => Err(RepoError::Storage(
                    "proxy is offline and has no cached upstream index".into(),
                )),
            };
        }

        // An upstream that does not resolve (unreachable, a 404, a captive
        // portal or a gateway's error page the format does not recognize)
        // is an upstream failure, never stored over the last good index:
        // taken for an empty upstream, it would answer every id 404.
        let resolved = match self.converse(repo, None, api::UpstreamOp::Index).await {
            Ok((api::UpstreamAnswer::Index(index), origins)) => {
                match serde_json::from_str(&index) {
                    // The host's own fields are not the format's to write.
                    Ok(JsonValue::Object(index))
                        if PersistedIndex::HOST_KEYS
                            .iter()
                            .any(|key| index.contains_key(*key)) =>
                    {
                        Err(RepoError::Storage(format!(
                            "upstream {remote_url} resolved to an index that uses a key the \
                             host keeps ({})",
                            PersistedIndex::HOST_KEYS.join(", ")
                        )))
                    }
                    Ok(JsonValue::Object(index)) => Ok((index, origins)),
                    _ => Err(RepoError::Storage(format!(
                        "upstream {remote_url} resolved to an index that is not a JSON object"
                    ))),
                }
            }
            Ok((api::UpstreamAnswer::Failed(reason), _)) => Err(RepoError::Storage(reason)),
            Ok(_) => Err(RepoError::Storage(
                "upstream protocol answered index with something else".into(),
            )),
            Err(e) => Err(e),
        };
        let (index, origins) = match resolved {
            Ok(resolved) => resolved,
            Err(e) => {
                // A stale persisted index is better than failing every read
                // while the upstream is briefly unreachable.
                if let Some((stored, _)) = persisted {
                    tracing::warn!(repo = %repo.name, error = %e, "upstream index refresh failed; serving stale index");
                    return Ok(stored);
                }
                return Err(e);
            }
        };
        let stored = PersistedIndex {
            remote_url: remote_url.to_string(),
            named_origins: Some(origins.named().clone()),
            index,
        };
        let resources_json = serde_json::to_value(&stored)
            .map_err(|e| RepoError::Storage(format!("serialize the upstream index: {e}")))?;

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

        Ok(stored)
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
        let mut lookup = Lookup::start(&repo.name, LookupKind::Metadata);
        let span = lookup.span();
        let result = self
            .discover(repo, lower_id, &mut lookup)
            .instrument(span)
            .await;
        let outcome = match &result {
            Ok(_) => lookup.marked().unwrap_or(Outcome::Hit),
            Err(e) => error_outcome(e, lookup.marked()),
        };
        lookup.finish(outcome);
        result
    }

    /// [`Self::discover_versions`], marking what it finds on `lookup`.
    async fn discover(
        &self,
        repo: &Repository,
        lower_id: &str,
        lookup: &mut Lookup,
    ) -> Result<Vec<forge_db::model::ProxyCachedVersion>, RepoError> {
        // Offline: only what we already cached.
        if !repo.online {
            lookup.mark(Outcome::Offline);
            return self.cached_rows(repo.id, lower_id).await;
        }
        // The upstream failed a listing moments ago: what is cached is
        // served without waiting for it again.
        if self.upstream_listing_failed(repo).await {
            let rows = self.cached_rows(repo.id, lower_id).await?;
            if !rows.is_empty() {
                lookup.mark(Outcome::StaleServed);
                return Ok(rows);
            }
        }

        let fetched = std::sync::atomic::AtomicBool::new(false);
        let mut refreshed = self.listing_refreshed(repo, lower_id, &fetched).await;
        // "The upstream does not know the id" is cached for the metadata
        // TTL, but stands only while the id's not-found marker does
        // (`not_found_ttl_seconds`, which may be shorter, or 0): past it,
        // the upstream is asked again.
        if matches!(refreshed, Ok(false)) && !self.negative_cached(repo, lower_id, "*").await? {
            self.cache
                .invalidate(NS_UPSTREAM_VERSIONS, &Self::versions_key(repo, lower_id))
                .await;
            refreshed = self.listing_refreshed(repo, lower_id, &fetched).await;
        }
        let fetched = fetched.load(std::sync::atomic::Ordering::Relaxed);
        match refreshed {
            Ok(true) => {
                lookup.mark(if fetched {
                    Outcome::Fetched
                } else {
                    Outcome::Hit
                });
                self.cached_rows(repo.id, lower_id).await
            }
            Ok(false) => {
                lookup.mark(if fetched {
                    Outcome::NotFound
                } else {
                    Outcome::NegativeCached
                });
                Ok(Vec::new())
            }
            Err(e) => {
                // Degrade to what is already cached locally rather than
                // failing a restore that could be served. An outage keeps
                // doing so for a while without asking the upstream; a
                // listing that failed for this id alone (an unusable
                // document) is no reason to stop asking for the others.
                let e = RepoError::from(e);
                let outage = matches!(e, RepoError::Upstream(_));
                if outage {
                    let _ = self
                        .cache
                        .get_or_try_insert_local(
                            NS_UPSTREAM_LISTING_FAILED,
                            &Self::upstream_scope(repo),
                            UPSTREAM_LISTING_BACKOFF,
                            || async { Ok::<_, ()>(true) },
                        )
                        .await;
                }
                let rows = self.cached_rows(repo.id, lower_id).await?;
                if rows.is_empty() {
                    return Err(e);
                }
                lookup.mark(Outcome::StaleServed);
                if outage {
                    tracing::warn!(repo = %repo.name, id = %lower_id, error = %e, "upstream version listing failed; serving cached versions for a minute");
                } else {
                    tracing::warn!(repo = %repo.name, id = %lower_id, error = %e, "upstream version listing failed; serving cached versions");
                }
                Ok(rows)
            }
        }
    }

    /// Whether a version listing of `repo`'s upstream failed within the last
    /// [`UPSTREAM_LISTING_BACKOFF`].
    async fn upstream_listing_failed(&self, repo: &Repository) -> bool {
        // Lookup only: the factory never yields a value, so a miss caches
        // nothing.
        self.cache
            .get_or_try_insert_local(
                NS_UPSTREAM_LISTING_FAILED,
                &Self::upstream_scope(repo),
                UPSTREAM_LISTING_BACKOFF,
                || async { Err::<bool, ()>(()) },
            )
            .await
            .is_ok()
    }

    /// Refresh `lower_id`'s listing ([`Self::refresh_versions`]) unless it
    /// was refreshed within the metadata TTL (the cache coalesces concurrent
    /// refreshes, across instances too). `Ok(false)`: the upstream does not
    /// know the id.
    ///
    /// `fetched` is set when this call asked the upstream itself.
    async fn listing_refreshed(
        &self,
        repo: &Repository,
        lower_id: &str,
        fetched: &std::sync::atomic::AtomicBool,
    ) -> Result<bool, SharedRepoError> {
        let ttl = Self::metadata_ttl(repo).to_std().unwrap_or_default();
        self.cache
            .get_or_try_insert_with(
                NS_UPSTREAM_VERSIONS,
                &Self::versions_key(repo, lower_id),
                ttl,
                || async {
                    fetched.store(true, std::sync::atomic::Ordering::Relaxed);
                    Box::pin(self.refresh_versions(repo, lower_id))
                        .await
                        .map_err(SharedRepoError::from)
                },
            )
            .await
    }

    /// Fetch the upstream's version listing of `lower_id`
    /// ([`api::UpstreamOp::Versions`]) and record every version. Returns
    /// `false` when the upstream does not know the id.
    async fn refresh_versions(&self, repo: &Repository, lower_id: &str) -> Result<bool, RepoError> {
        let answer = self
            .converse_resolved(repo, api::UpstreamOp::Versions(lower_id.to_string()))
            .await?;
        match answer {
            api::UpstreamAnswer::Versions(Some(mut versions)) => {
                // A version the format does not normalize is not the
                // package's: one longer than the format allows would fail
                // the whole listing's insert, so it is left out.
                versions.retain(|v| self.format.normalize_version(v).is_ok());
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
            api::UpstreamAnswer::Versions(None) => {
                // Genuine upstream 404 for the whole package id → negative cache.
                // We model it on a synthetic `*` version row so a later request
                // can short-circuit without re-hitting upstream within the TTL.
                self.mark_not_found(repo.id, lower_id, "*").await?;
                Ok(false)
            }
            // An unusable listing is an upstream failure (what is cached is
            // served), never "no versions", which would retire them all:
            // the upstream answered, but not usably (502).
            api::UpstreamAnswer::Failed(reason) => Err(RepoError::BadUpstream(reason)),
            _ => Err(RepoError::Storage(
                "upstream protocol answered versions with something else".into(),
            )),
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
        let mut lookup = Lookup::start(&repo.name, LookupKind::Package);
        let span = lookup.span();
        let result = self
            .download(repo, lower_id, version, &mut lookup)
            .instrument(span)
            .await;
        let outcome = match &result {
            Ok(Some(_)) => lookup.marked().unwrap_or(Outcome::Hit),
            Ok(None) => lookup.marked().unwrap_or(Outcome::NotFound),
            Err(e) => error_outcome(e, lookup.marked()),
        };
        lookup.finish(outcome);
        result
    }

    /// [`Self::ensure_downloaded`], marking what it finds on `lookup`.
    async fn download(
        &self,
        repo: &Repository,
        lower_id: &str,
        version: &str,
        lookup: &mut Lookup,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        // Already cached + downloaded + delay-cleared? Serve immediately.
        if let Some(row) =
            proxy_dao::get_cached_version(&self.pool, repo.id, lower_id, version).await?
        {
            let now = self.db_now().await?;
            if row.downloaded {
                if !Self::delay_cleared(repo, row.first_seen_at, now) {
                    lookup.mark(Outcome::DelayGated);
                    return Ok(None);
                }
                if let Some(loc) = self.local_nupkg(repo.id, lower_id, version).await? {
                    return Ok(Some(loc));
                }
                // Marked downloaded but the local copy is gone: re-fetch below.
            } else if Self::not_found_live(repo, &row, now) {
                // A still-valid genuine-404 marker short-circuits (no upstream call).
                lookup.mark(Outcome::NegativeCached);
                return Ok(None);
            }
        }

        // Offline and not (or no longer) cached locally ⇒ nothing to serve.
        if !repo.online {
            lookup.mark(Outcome::Offline);
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
            lookup.mark(Outcome::DelayGated);
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
        // Never hold a DB transaction across an S3/network call. We therefore
        // split the work into three phases:
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
                    lookup.mark(Outcome::DelayGated);
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
                lookup.mark(Outcome::NegativeCached);
                return Ok(None);
            }
            // This caller performs the fetch.
        }

        // Bytes rejected for their content recently: fail fast instead of
        // downloading them again on every client retry.
        if let Some(reason) = self.recent_rejection(repo, lower_id, version).await {
            return Err(RepoError::BadUpstream(format!(
                "upstream package {lower_id} {version} was rejected recently: {reason}"
            )));
        }

        // ── Network I/O — performed with NO transaction held ─────────────────
        // Where the package is, as the format's upstream protocol says (for
        // NuGet, `{flat container}{id}/{version}/{id}.{version}.nupkg`), on
        // an origin the upstream points at: [`Self::converse`] answers any
        // other as an upstream failure.
        let (url, digests) = match self
            .converse_resolved(
                repo,
                api::UpstreamOp::Package(api::PackageRef {
                    id: lower_id.to_string(),
                    version: version.to_string(),
                }),
            )
            .await?
        {
            api::UpstreamAnswer::Package(url) => (url, None),
            // The upstream publishes the package's digests: what is
            // downloaded must match them.
            api::UpstreamAnswer::Located(location) => {
                (location.url, Some((location.sha512, location.sha1)))
            }
            api::UpstreamAnswer::Failed(reason) => return Err(RepoError::Storage(reason)),
            _ => {
                return Err(RepoError::Storage(
                    "upstream protocol answered package with something else".into(),
                ))
            }
        };
        let requested_at = self.db_now().await?;
        // Decrypt-on-use: the plaintext lives only inside this request
        // (and the zeroizing secret wrapper) — never in a log or model.
        let resp = {
            let creds = self.credentials(repo).await?;
            let auth = creds.as_ref().map(Credentials::auth);
            self.http
                .for_repository(&repo.name)
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
            lookup.mark(Outcome::UpstreamError);
            let reason = format!("upstream package fetch {url} returned {}", resp.status());
            return Err(if status_is_unavailable(resp.status()) {
                RepoError::Upstream(reason)
            } else if matches!(
                resp.status(),
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
            ) {
                RepoError::BadUpstream(reason)
            } else {
                RepoError::Storage(reason)
            });
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
            Ok(staged) => {
                forge_telemetry::proxy::upstream_bytes(&repo.name, staged.size);
                lookup.mark(Outcome::Fetched);
                staged
            }
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

        if let Some((Some(sha512), _)) = &digests {
            if *sha512 != staged.sha512_base64 {
                return Err(self
                    .reject(
                        repo,
                        lower_id,
                        version,
                        format!("upstream package {url} does not match the SHA-512 its upstream publishes"),
                    )
                    .await);
            }
        }
        // Without a SHA-512, the SHA-1 the upstream publishes (npm's
        // `shasum`), computed while the package is parsed.
        let sha1 = match &digests {
            Some((None, Some(sha1))) => Some(sha1.to_ascii_lowercase()),
            _ => None,
        };

        // Parse from the temp file on the blocking pool to obtain the canonical
        // identity and the manifest, and summarize the manifest for
        // registration and search (stored with the component, like a push).
        let parsed = {
            let format = self.format.clone();
            let path = staged.read_path();
            tokio::task::spawn_blocking(move || {
                if let Some(expected) = sha1 {
                    use sha1::Digest;
                    use std::io::Read;
                    let mut hasher = sha1::Sha1::new();
                    let mut file = std::fs::File::open(&path)?;
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let n = file.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                    }
                    if hex::encode(hasher.finalize()) != expected {
                        return Ok(Err(crate::domain::FormatError::InvalidPackage(
                            "the package does not match the SHA-1 its upstream publishes".into(),
                        )));
                    }
                }
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
        // While S3 is down (the local blob cache serves what it has), the
        // package cannot be stored: "try again later".
        let stored = self.cas.commit(staged).await.map_err(|e| {
            if e.is_unavailable() {
                RepoError::Busy(e.to_string())
            } else {
                RepoError::Storage(format!("cas store upstream nupkg: {e}"))
            }
        })?;
        let nuspec = self
            .cas
            .store(Cursor::new(parsed.nuspec_bytes.clone()), max_bytes)
            .await
            .map_err(|e| match e {
                e @ CasError::StagingFull { .. } => RepoError::Busy(e.to_string()),
                e if e.is_unavailable() => RepoError::Busy(e.to_string()),
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
                lookup.mark(Outcome::DelayGated);
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
        if asset_dao::find_asset(&mut *tx, comp.id, self.format.package_asset_path())
            .await?
            .is_none()
        {
            blob_dao::commit_ingest_and_incref(&mut tx, &stored.sha256, stored.ingest_token)
                .await?;
            asset_dao::insert_asset(
                &mut *tx,
                NewAsset {
                    component_id: comp.id,
                    path: self.format.package_asset_path().to_string(),
                    content_type: self.format.package_content_type().to_string(),
                    blob_sha256: stored.sha256.clone(),
                    size,
                    sha512_base64: Some(stored.sha512_base64.clone()),
                },
            )
            .await?;
        }
        if asset_dao::find_asset(&mut *tx, comp.id, self.format.manifest_asset_path())
            .await?
            .is_none()
        {
            blob_dao::commit_ingest_and_incref(&mut tx, &nuspec.sha256, nuspec.ingest_token)
                .await?;
            asset_dao::insert_asset(
                &mut *tx,
                NewAsset {
                    component_id: comp.id,
                    path: self.format.manifest_asset_path().to_string(),
                    content_type: self.format.manifest_content_type().to_string(),
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
        RepoError::BadUpstream(reason)
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
        let Some(asset) =
            asset_dao::find_asset(&self.pool, comp.id, self.format.package_asset_path()).await?
        else {
            return Ok(None);
        };
        let Some(blob) = blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? else {
            return Ok(None);
        };
        Ok(Some(NupkgLocation {
            blob_sha256: blob.sha256,
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
        let Some(asset) =
            asset_dao::find_asset(&self.pool, comp.id, self.format.manifest_asset_path()).await?
        else {
            return Ok(None);
        };
        let Some(blob) = blob_dao::get_blob(&self.pool, &asset.blob_sha256).await? else {
            return Ok(None);
        };
        Ok(Some(blobs.fetch_all(&blob).await?))
    }

    /// The upstream's manifest of a known, not-yet-downloaded version
    /// ([`api::UpstreamOp::Manifest`]), without downloading the package.
    ///
    /// The upstream controls these bytes (and where its redirects lead), so
    /// the format serves a manifest only when it declares exactly
    /// `(lower_id, version)`. Anything else yields `None`, and the caller
    /// falls back to the package itself, whose identity is verified the same
    /// way.
    async fn upstream_manifest(
        &self,
        repo: &Repository,
        lower_id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        match self
            .converse_resolved(
                repo,
                api::UpstreamOp::Manifest(api::PackageRef {
                    id: lower_id.to_string(),
                    version: version.to_string(),
                }),
            )
            .await?
        {
            api::UpstreamAnswer::Manifest(manifest) => Ok(manifest),
            api::UpstreamAnswer::Failed(reason) => Err(RepoError::Storage(reason)),
            _ => Err(RepoError::Storage(
                "upstream protocol answered manifest with something else".into(),
            )),
        }
    }

    // ── Upstream metadata (M11) ──────────────────────────────────────────────

    /// The upstream's metadata of `wanted` versions of `lower_id`, keyed by
    /// normalized version ([`api::UpstreamOp::Metadata`], or
    /// [`api::UpstreamOp::Dating`] with creation times). Best effort and
    /// bounded by the format: an offline proxy and any upstream or protocol
    /// failure yield nothing, and the caller falls back to the listing's
    /// view (listed, no dependencies). Records the package id's upstream
    /// casing for search (best effort): the newest version's, the one the
    /// upstream shows, as the format reports it.
    async fn upstream_metadata(
        &self,
        repo: &Repository,
        lower_id: &str,
        wanted: &[String],
        dating: bool,
    ) -> HashMap<String, api::VersionMetadata> {
        if !repo.online || wanted.is_empty() {
            return HashMap::new();
        }
        let versions = api::PackageVersions {
            id: lower_id.to_string(),
            versions: wanted.to_vec(),
        };
        let op = if dating {
            api::UpstreamOp::Dating(versions)
        } else {
            api::UpstreamOp::Metadata(versions)
        };
        let metadata = match Box::pin(self.converse_resolved(repo, op)).await {
            Ok(api::UpstreamAnswer::Metadata(metadata)) => metadata,
            Ok(api::UpstreamAnswer::Failed(reason)) => {
                tracing::warn!(repo = %repo.name, id = %lower_id, %reason, "upstream metadata unavailable; serving the listing's");
                return HashMap::new();
            }
            Ok(_) => {
                tracing::warn!(repo = %repo.name, id = %lower_id, "upstream protocol answered metadata with something else");
                return HashMap::new();
            }
            Err(e) => {
                tracing::warn!(repo = %repo.name, id = %lower_id, error = %e, "upstream metadata unavailable; serving the listing's");
                return HashMap::new();
            }
        };
        if let Some(original_id) = metadata
            .original_id
            .as_deref()
            .filter(|id| self.format.lower_id(id) == lower_id)
        {
            if let Err(e) =
                proxy_dao::record_original_id(&self.pool, repo.id, lower_id, original_id).await
            {
                tracing::warn!(repo = %repo.name, id = %lower_id, error = %e, "recording the upstream id casing failed");
            }
        }
        metadata
            .versions
            .into_iter()
            .map(|v| (v.version.clone(), v))
            .collect()
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
    /// those in `only` (normalized). The upstream's metadata is asked for the
    /// versions returned only, so a registration page or leaf reads just the
    /// upstream documents covering its own versions; `dated` asks it for
    /// their publish times too ([`api::UpstreamOp::Dating`]).
    async fn registration_of(
        &self,
        repo: &str,
        id: &str,
        only: Option<&[String]>,
        dated: bool,
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
        let upstream = self
            .upstream_metadata(&repo_row, &lower, &wanted, dated)
            .await;

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
                    self.format.package_asset_path(),
                )
                .await?
            }
            Some(_) => {
                component_dao::list_registration_rows_for_versions(
                    &self.pool,
                    repo_row.id,
                    &lower,
                    &wanted,
                    self.format.package_asset_path(),
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
            let (hash, sha256, size, summary, local, version_original) =
                match cached.remove(&r.version) {
                    Some(row) if r.downloaded => {
                        let (summary, local) = match row.manifest_summary {
                            Some(summary) => (Some(summary), None),
                            None => manifests.remove(&r.version).unwrap_or_default(),
                        };
                        (
                            row.package_hash_sha512_base64,
                            row.package_sha256,
                            row.package_size,
                            summary,
                            local,
                            Some(row.version_original),
                        )
                    }
                    _ => (None, None, None, None, None, None),
                };
            let original_id = leaf
                .and_then(|l| l.original_id.clone())
                .unwrap_or_else(|| r.name.clone());
            // Not downloaded (or its manifest unreadable): the manifest is
            // known only from the upstream's metadata.
            let summary = match (summary, &local) {
                (None, None) => leaf
                    .and_then(|l| l.summary.as_deref())
                    .and_then(|summary| serde_json::from_str(summary).ok()),
                (summary, _) => summary,
            };
            out.push(RegistrationEntry {
                original_id,
                version: r.version.clone(),
                version_original: version_original.unwrap_or_else(|| r.version.clone()),
                listed: leaf.map_or(r.listed, |l| l.listed),
                package_hash_sha512_base64: hash,
                package_sha256: sha256,
                package_size: size,
                nuspec_bytes: local,
                manifest_summary: summary,
                // Only the upstream knows the publish time (the cache time
                // would be misleading).
                published: leaf.and_then(|l| rfc3339(l.published.as_deref())),
                // A proxy's deprecations are its upstream's, in the summary.
                deprecation: None,
            });
        }
        Ok(out)
    }

    /// Date the package delay of `lower_id`'s versions still inside it from
    /// when the upstream created them, instead of from their first sighting
    /// here. The delay quarantines *new releases*: without this, a version
    /// published years ago but first seen now (every version of a package
    /// this proxy has not served before, all of them on a fresh install) was
    /// hidden for the whole delay.
    ///
    /// The creation times are the format's ([`api::UpstreamOp::Dating`]; for
    /// NuGet, a listed version's registration `published` time, an unlisted
    /// one's catalog `created` time, as nuget.org reports unlisted versions as
    /// published in 1900). Only a plausible time counts (not before 2010, not
    /// in the future), and it only ever moves the clock back. Best effort:
    /// when the upstream cannot say, the first sighting stands.
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
            let metadata = self.upstream_metadata(repo, lower_id, &wanted, true).await;
            let plausible = |at: &DateTime<Utc>| *at >= min_trusted_publish_time() && *at <= now;
            let (versions, created): (Vec<String>, Vec<DateTime<Utc>>) = pending
                .iter()
                .filter_map(|r| {
                    let at = metadata
                        .get(&r.version)
                        .and_then(|m| rfc3339(m.created.as_deref()))
                        .filter(plausible)?;
                    (at < r.first_seen_at).then(|| (r.version.clone(), at))
                })
                .unzip();
            proxy_dao::backdate_first_seen(&self.pool, repo.id, lower_id, &versions, &created)
                .await?;
            Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(repo = %repo.name, id = %lower_id, error = %e, "dating the package delay from the upstream failed");
        }
    }
}

/// An RFC 3339 time the upstream reported, if it parses.
fn rfc3339(raw: Option<&str>) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw?)
        .ok()
        .map(|at| at.with_timezone(&Utc))
}

/// Concurrent local manifest reads while enriching one proxy search page.
const SEARCH_ENRICH_CONCURRENCY: usize = 8;

#[async_trait]
impl RepoReadOps for ProxyRepo {
    /// The upstream's tags ([`api::UpstreamOp::Tags`], read through the
    /// fetch cache for the metadata TTL), kept in `package_tag`: what was
    /// last read is served while the proxy is offline or the upstream
    /// fails.
    async fn tags(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<std::collections::BTreeMap<String, String>, RepoError> {
        let repo_row = self.proxy_repo(repo).await?;
        let Some(lower) = self.upstream_id(id) else {
            return Ok(std::collections::BTreeMap::new());
        };
        // A package the upstream does not know has no tags either.
        if self.negative_cached(&repo_row, &lower, "*").await? {
            return Ok(std::collections::BTreeMap::new());
        }
        if repo_row.online {
            match self
                .converse_resolved(&repo_row, api::UpstreamOp::Tags(lower.clone()))
                .await
            {
                Ok(api::UpstreamAnswer::Tags(Some(tags))) => {
                    let tags: std::collections::BTreeMap<String, String> = tags
                        .into_iter()
                        .filter_map(|tag| {
                            let version = self.format.normalize_version(&tag.version).ok()?;
                            Some((tag.name, version))
                        })
                        .collect();
                    let mut tx = self.pool.begin().await?;
                    forge_db::tag_dao::replace_tags(&mut tx, repo_row.id, &lower, &tags).await?;
                    tx.commit().await?;
                    return Ok(tags);
                }
                Ok(api::UpstreamAnswer::Tags(None)) => return Ok(std::collections::BTreeMap::new()),
                Ok(api::UpstreamAnswer::Failed(reason)) => {
                    tracing::warn!(repo = %repo_row.name, id = %lower, %reason, "upstream tags unavailable; serving the last read");
                }
                Ok(_) => {
                    tracing::warn!(repo = %repo_row.name, id = %lower, "upstream protocol answered tags with something else");
                }
                Err(e) => {
                    tracing::warn!(repo = %repo_row.name, id = %lower, error = %e, "upstream tags unavailable; serving the last read");
                }
            }
        }
        Ok(forge_db::tag_dao::tags(&self.pool, repo_row.id, &lower).await?)
    }

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
            // Download tracking: a served cached `.nupkg` is a pull. Stamp
            // `proxy_cached_version.last_downloaded_at` (drives the proxy "not
            // pulled in X days" eviction) + mirror onto the parallel
            // component/asset. Best-effort, counted in memory and written in a
            // batch — never blocks or fails the download.
            self.downloads.count_proxy(repo_row.id, &lower, &norm);
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
            if let Some(bytes) = Box::pin(self.upstream_manifest(&repo_row, &lower, &norm)).await? {
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
    /// and — for versions not downloaded yet — the manifest summary come
    /// from the upstream's metadata when it has any
    /// ([`Self::upstream_metadata`]). A downloaded version serves its stored
    /// manifest and package hash.
    async fn registration(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        self.registration_of(repo, id, None, false).await
    }

    async fn dated_registration(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        self.registration_of(repo, id, None, true).await
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
        self.registration_of(repo, id, Some(versions), false).await
    }

    async fn registration_entry(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<RegistrationEntry>, RepoError> {
        Ok(self
            .registration_of(repo, id, Some(&[version.to_string()]), false)
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
#[derive(Debug, Clone)]
struct UpstreamSearchPage {
    /// The upstream's total hit count.
    total_hits: usize,
    hits: Vec<UpstreamSearchHit>,
}

/// One package of an [`UpstreamSearchPage`].
#[derive(Debug, Clone)]
struct UpstreamSearchHit {
    /// Package id as the upstream spells it.
    id: String,
    /// The versions the upstream lists, normalized, ascending.
    versions: Vec<String>,
    /// A manifest summary of the latest version, as the upstream reports it.
    summary: Option<JsonValue>,
    total_downloads: Option<i64>,
}

impl ProxyRepo {
    /// Search `repo` through the upstream's `SearchQueryService` when the
    /// caller allows it ([`SearchParams::include_upstream`]), the proxy is
    /// online and the upstream advertises one; otherwise, and when the
    /// upstream search fails (and for [`UPSTREAM_SEARCH_BACKOFF`] after an outage),
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
                Err(RepoError::Upstream(e)) => {
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
                Err(e) => {
                    tracing::warn!(repo = %repo_row.name, error = %e, "upstream search failed; searching the cached packages");
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

    /// One page of the upstream's search results for `params`
    /// ([`api::UpstreamOp::Search`]; its documents are cached for the
    /// metadata TTL). `None` when the upstream offers no search. A hit
    /// without a well-formed id (ids end up in Forge's URLs) is dropped, and
    /// the upstream's total reduced by it.
    async fn upstream_search(
        &self,
        repo: &Repository,
        params: &SearchParams,
    ) -> Result<Option<UpstreamSearchPage>, RepoError> {
        // As much of `q` as a local search honors.
        let mut q_end = params.q.len().min(SearchQuery::MAX_QUERY_BYTES);
        while !params.q.is_char_boundary(q_end) {
            q_end -= 1;
        }
        let query = api::SearchQuery {
            text: params.q[..q_end].to_string(),
            skip: u32::try_from(params.skip).unwrap_or(u32::MAX),
            take: u32::try_from(params.effective_take()).unwrap_or(u32::MAX),
            prerelease: params.prerelease,
            semver2: params.include_semver2,
            upstream: true,
        };
        let page = match self
            .converse_resolved(repo, api::UpstreamOp::Search(query))
            .await?
        {
            api::UpstreamAnswer::Search(Some(page)) => page,
            api::UpstreamAnswer::Search(None) => return Ok(None),
            api::UpstreamAnswer::Failed(reason) => return Err(RepoError::Storage(reason)),
            _ => {
                return Err(RepoError::Storage(
                    "upstream protocol answered search with something else".into(),
                ))
            }
        };
        let returned = page.hits.len().min(params.effective_take());
        let hits: Vec<UpstreamSearchHit> = page
            .hits
            .into_iter()
            .take(params.effective_take())
            .filter(|hit| {
                self.format
                    .validate_id(&self.format.lower_id(&hit.id))
                    .is_ok()
            })
            .map(|hit| UpstreamSearchHit {
                id: hit.id,
                versions: hit.versions,
                summary: hit
                    .summary
                    .as_deref()
                    .and_then(|summary| serde_json::from_str(summary).ok()),
                total_downloads: hit.total_downloads.and_then(|n| i64::try_from(n).ok()),
            })
            .collect();
        let total_hits = usize::try_from(page.total)
            .unwrap_or(usize::MAX)
            .saturating_sub(returned.saturating_sub(hits.len()))
            .max(params.skip.saturating_add(hits.len()));
        Ok(Some(UpstreamSearchPage { total_hits, hits }))
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
    /// reduced by the ids dropped from this page; for a caller whose filter
    /// hides packages, the total is what it sees instead.
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
        // The upstream's total counts the packages the caller's filter hides
        // as well: a caller who may see only some is told only what it sees,
        // plus one while the upstream's page was full (so paging goes on).
        let total_hits = if matches!(filter, PackageFilter::AllowAll) {
            page.total_hits.saturating_sub(returned - out.len())
        } else {
            let more = params.take > 0 && returned >= params.take;
            params.skip + out.len() + usize::from(more)
        };
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
    fn persisted_index_records_its_url() {
        let index = serde_json::json!({
            "package_base_address": "https://up/flat/",
            "registrations_base_url": null,
            "search_query_service": null,
        });
        let JsonValue::Object(map) = index.clone() else {
            unreachable!()
        };
        let stored = serde_json::to_value(PersistedIndex {
            remote_url: "https://up/index.json".into(),
            named_origins: Some(BTreeSet::from(
                [Origin::of("https://cdn.example/").unwrap()],
            )),
            index: map,
        })
        .unwrap();
        // The index keeps its shape; the URL and the origins are two more
        // fields beside it.
        assert_eq!(stored["package_base_address"], "https://up/flat/");
        assert_eq!(
            stored["named_origins"],
            serde_json::json!(["https://cdn.example:443"])
        );
        let parsed: PersistedIndex = serde_json::from_value(stored).unwrap();
        assert_eq!(parsed.remote_url, "https://up/index.json");
        assert_eq!(
            parsed.named_origins,
            Some(BTreeSet::from(
                [Origin::of("https://cdn.example/").unwrap()]
            ))
        );
        assert_eq!(
            serde_json::from_str::<JsonValue>(&parsed.index()).unwrap(),
            index
        );
        // A row written before the URL was recorded belongs to no URL.
        assert!(serde_json::from_value::<PersistedIndex>(index.clone()).is_err());
        // One written before the origins were recorded has none: it is
        // resolved again, and its index reaches no origin but the
        // remote_url's meanwhile.
        let mut old = index.clone();
        old["remote_url"] = "https://up/index.json".into();
        let parsed: PersistedIndex = serde_json::from_value(old).unwrap();
        assert_eq!(parsed.named_origins, None);
        assert_eq!(
            serde_json::from_str::<JsonValue>(&parsed.index()).unwrap(),
            index
        );
    }
}
