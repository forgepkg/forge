//! Repository read/write operations, organized by repository kind.
//!
//! Slice 1 implements the **hosted** read path here (Phase 6); proxy and group
//! read paths arrive in later phases. The neutral DTOs in this module are the
//! contract between the storage-backed implementations and the protocol crates
//! (`forge-nuget`): they are format-agnostic and carry exactly what a NuGet
//! route handler needs to render Appendix A JSON, **plus** the raw `.nuspec`
//! bytes so the format layer can extract dependency groups itself (keeping
//! `forge-core` free of NuGet-specific manifest parsing).

pub mod group;
pub mod hosted;
pub mod proxy;

use std::sync::Arc;

use async_trait::async_trait;

use crate::auth::principal::Principal;
use crate::authz::PackageFilter;

/// Re-export of the repository-kind enum so the protocol crates can branch on
/// it without depending on `forge-db` directly.
pub use forge_db::model::RepoKind;

/// Canonical asset path of the stored `.nupkg` blob within a component.
pub const NUPKG_ASSET_PATH: &str = "package.nupkg";
/// Canonical asset path of the derived `.nuspec` blob within a component.
pub const NUSPEC_ASSET_PATH: &str = "package.nuspec";

/// Content type stored/served for the `.nupkg` asset.
pub const NUPKG_CONTENT_TYPE: &str = "application/octet-stream";
/// Content type stored/served for the derived `.nuspec` asset.
pub const NUSPEC_CONTENT_TYPE: &str = "application/xml";

/// Errors the read/write ops surface to callers.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// The named repository does not exist.
    #[error("repository not found: {0}")]
    RepoNotFound(String),
    /// The repository exists but is not of the kind required for this op
    /// (e.g. a publish targeting a proxy).
    #[error("operation not supported for {kind} repository {name:?}")]
    WrongKind {
        /// Repository name.
        name: String,
        /// Actual repository kind.
        kind: String,
    },
    /// A database error bubbled up from the DAO layer.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// A storage/I-O error while fetching blob bytes (e.g. an S3 failure).
    /// The concrete blob fetcher (Phase 10) surfaces transport errors here
    /// rather than overloading [`RepoError::RepoNotFound`].
    #[error("storage error: {0}")]
    Storage(String),
}

/// Errors surfaced by the hosted **write** path (publish / delete / relist).
///
/// Distinct from [`RepoError`] so the protocol layer can map each variant to the
/// right HTTP status: [`WriteError::TooLarge`] → 413, [`WriteError::Conflict`]
/// → 409, [`WriteError::InvalidPackage`] → 400,
/// [`WriteError::ForbiddenPackage`] → 403, and the wrapped [`RepoError`] for
/// not-found / wrong-kind / db / storage.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// Repository / database / storage error (also covers not-found and
    /// wrong-kind via the wrapped [`RepoError`]).
    #[error(transparent)]
    Repo(#[from] RepoError),
    /// The upload exceeded the configured `max_upload_bytes` limit → HTTP 413.
    #[error("upload exceeds limit of {limit} bytes")]
    TooLarge {
        /// The configured byte limit that was exceeded.
        limit: u64,
    },
    /// The uploaded bytes are not a valid package of this format → HTTP 400.
    #[error("invalid package: {0}")]
    InvalidPackage(#[from] crate::domain::FormatError),
    /// `(id, version)` already exists and the repository disallows redeploy →
    /// HTTP 409.
    #[error("package {id} {version} already exists")]
    Conflict {
        /// Package id (original casing).
        id: String,
        /// Normalized version.
        version: String,
    },
    /// A package's canonical id is outside the selector attached to the
    /// caller's write grant. This is surfaced as HTTP 403 for uploads; direct
    /// id/version mutations are converted to `NotFound` before reaching this
    /// error so they retain non-enumerating 404 semantics.
    #[error("not authorized to publish package {id}")]
    ForbiddenPackage {
        /// Canonical (lowercased for NuGet) package id extracted by the format.
        id: String,
    },
}

impl From<forge_storage::CasError> for WriteError {
    fn from(e: forge_storage::CasError) -> Self {
        match e {
            forge_storage::CasError::TooLarge { limit } => WriteError::TooLarge { limit },
            forge_storage::CasError::Db(db) => WriteError::Repo(RepoError::Db(db)),
            other => WriteError::Repo(RepoError::Storage(other.to_string())),
        }
    }
}

/// Outcome of a successful publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// A brand-new `(id, version)` was created → HTTP 201.
    Created,
    /// An existing `(id, version)` was redeployed (assets swapped) → HTTP 201.
    Replaced,
}

/// Outcome of a delete / relist operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The version was unlisted (soft delete) → HTTP 204.
    Unlisted,
    /// The version was hard-deleted (rows removed, blobs dereferenced).
    Deleted,
    /// The version was relisted → HTTP 200.
    Relisted,
    /// The `(id, version)` was unknown → HTTP 404.
    NotFound,
}

/// Seam for invalidating cached read responses after a write.
///
/// Hosted reads (registration/search/flat) may be cached per `(repo, id)` by
/// the server's [`forge_cache::Cache`]; the write path calls
/// [`CacheInvalidator::invalidate_package`] after committing so stale entries
/// are dropped. Abstracted here (like [`hosted::BlobFetch`]) so `forge-core`
/// stays independent of the cache implementation and tests can use a no-op.
#[async_trait]
pub trait CacheInvalidator: Send + Sync {
    /// Invalidate any cached reads for `(repo, lower_id)`.
    async fn invalidate_package(&self, repo: &str, lower_id: &str);
}

/// A [`CacheInvalidator`] that does nothing — for tests and cache-less setups.
#[derive(Debug, Default, Clone)]
pub struct NoopCacheInvalidator;

#[async_trait]
impl CacheInvalidator for NoopCacheInvalidator {
    async fn invalidate_package(&self, _repo: &str, _lower_id: &str) {}
}

/// One resolved version of a package (a `component` row, normalized).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionEntry {
    /// Package id exactly as published (original casing).
    pub original_id: String,
    /// Normalized version string.
    pub version: String,
    /// Version exactly as published.
    pub version_original: String,
    /// Whether the version is listed (visible in search / "latest").
    pub listed: bool,
}

/// A package blob resolved for download (the `.nupkg`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NupkgLocation {
    /// S3 object key of the blob, for streaming from the [`forge_storage`]
    /// blob store.
    pub blob_s3_key: String,
    /// Byte size of the blob.
    pub size: i64,
    /// MIME content type to serve.
    pub content_type: String,
}

/// One package's data for a registration page / search hit, format-neutral.
///
/// Dependency groups are intentionally **not** included: the format layer
/// re-parses [`Self::nuspec_bytes`] to produce them, keeping NuGet manifest
/// parsing out of `forge-core`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrationEntry {
    /// Package id exactly as published.
    pub original_id: String,
    /// Normalized version.
    pub version: String,
    /// Whether listed.
    pub listed: bool,
    /// SHA-512 of the `.nupkg`, base64-encoded (from `asset.sha512_base64`).
    pub package_hash_sha512_base64: Option<String>,
    /// Raw `.nuspec` bytes for this version, if a nuspec asset is stored.
    pub nuspec_bytes: Option<Vec<u8>>,
    /// When this version was published into the repository (`None` when
    /// unknown, e.g. a proxied version not cached yet).
    pub published: Option<chrono::DateTime<chrono::Utc>>,
}

/// A search hit: one package id with all of its (filtered) versions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchHit {
    /// Package id exactly as published (casing from the latest version).
    pub original_id: String,
    /// The latest version among [`Self::versions`] (highest precedence).
    pub latest_version: String,
    /// All matching versions, ascending by precedence.
    pub versions: Vec<VersionEntry>,
    /// Manifest of [`Self::latest_version`], when available, so the format
    /// layer can render description / authors / tags / icon.
    pub nuspec_bytes: Option<Vec<u8>>,
    /// Download count across all versions, when tracked.
    pub total_downloads: Option<i64>,
}

/// A parsed NuGet search query.
///
/// Supports the syntax clients actually send: `packageid:Foo` (exact id,
/// used by Visual Studio / NuGet.exe / Dependabot), `id:foo` (id substring),
/// and free-text terms (every term must occur in the id; terms are split on
/// whitespace, so `newtonsoft json` finds `Newtonsoft.Json`). Unknown
/// `field:value` filters (e.g. `tags:x`, `owner:x`) match their value against
/// the id as a best effort. Matching is ASCII case-insensitive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchQuery {
    /// Lowercased exact package ids (`packageid:`); any one must match.
    pub exact_ids: Vec<String>,
    /// Lowercased substrings that must all occur in the id.
    pub terms: Vec<String>,
}

impl SearchQuery {
    /// Parse a raw `q` value.
    pub fn parse(q: &str) -> Self {
        let mut out = SearchQuery::default();
        for token in q.split_whitespace() {
            // Full Unicode lowercasing, like the format's `lower_id`: stored
            // ids are lowercased that way, so `Ünicode` must find `ünicode.lib`.
            let token = token.trim_matches('"').to_lowercase();
            if token.is_empty() {
                continue;
            }
            match token.split_once(':') {
                Some(("packageid", value)) if !value.is_empty() => {
                    out.exact_ids.push(value.to_string())
                }
                Some((_, value)) if !value.is_empty() => out.terms.push(value.to_string()),
                Some(_) => {}
                None => out.terms.push(token),
            }
        }
        out
    }

    /// Whether the query matches everything.
    pub fn is_empty(&self) -> bool {
        self.exact_ids.is_empty() && self.terms.is_empty()
    }

    /// Whether `lower_id` (already lowercased) matches.
    pub fn matches(&self, lower_id: &str) -> bool {
        (self.exact_ids.is_empty() || self.exact_ids.iter().any(|id| id == lower_id))
            && self.terms.iter().all(|t| lower_id.contains(t.as_str()))
    }

    /// A single substring usable as a SQL prefilter (every match contains
    /// it), if one exists.
    pub fn prefilter(&self) -> Option<&str> {
        self.exact_ids
            .first()
            .filter(|_| self.exact_ids.len() == 1)
            .or_else(|| self.terms.iter().max_by_key(|t| t.len()))
            .map(String::as_str)
    }
}

/// The result of a search query: a clamped page plus the total hit count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// Total number of distinct package ids matching the query (pre-paging).
    pub total_hits: usize,
    /// The page of hits after applying `skip`/`take`.
    pub hits: Vec<SearchHit>,
}

/// Parameters for a search query (already-parsed query string values).
#[derive(Debug, Clone)]
pub struct SearchParams {
    /// Free-text query; empty matches everything.
    pub q: String,
    /// Number of leading hits to skip (clamped to >= 0 by the type).
    pub skip: usize,
    /// Page size; the implementation clamps this to a sane maximum.
    pub take: usize,
    /// Include prerelease versions.
    pub prerelease: bool,
}

impl Default for SearchParams {
    fn default() -> Self {
        SearchParams {
            q: String::new(),
            skip: 0,
            take: SearchParams::DEFAULT_TAKE,
            prerelease: false,
        }
    }
}

impl SearchParams {
    /// NuGet's default page size when `take` is absent.
    pub const DEFAULT_TAKE: usize = 20;
    /// Hard upper bound on `take` to bound work per request.
    pub const MAX_TAKE: usize = 1000;

    /// Clamp `take` into `[1, MAX_TAKE]`, treating zero as the default.
    pub fn effective_take(&self) -> usize {
        match self.take {
            0 => Self::DEFAULT_TAKE,
            n => n.min(Self::MAX_TAKE),
        }
    }
}

/// Read operations a NuGet route handler needs, abstracted so handlers can be
/// unit-tested against an in-memory mock instead of a live database.
///
/// All methods are keyed by **repository name** and **lowercased package id**
/// (the format layer lowercases ids before calling). Versions in inputs are
/// already normalized.
#[async_trait]
pub trait RepoReadOps: Send + Sync {
    /// All versions of `id` in `repo` (including unlisted), ascending by
    /// version precedence. `Ok(vec![])` when the id is unknown — the route
    /// layer maps an empty flat-container listing to 404.
    async fn list_versions(&self, repo: &str, id: &str) -> Result<Vec<VersionEntry>, RepoError>;

    /// Resolve the `.nupkg` blob for an exact `(id, version)`, or `None` if
    /// that version is absent.
    async fn resolve_nupkg(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError>;

    /// Resolve the stored `.nuspec` bytes for an exact `(id, version)`, or
    /// `None` if absent.
    async fn resolve_nuspec(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError>;

    /// All registration entries for `id` (including unlisted), ascending by
    /// version precedence. Empty when the id is unknown.
    async fn registration(&self, repo: &str, id: &str)
        -> Result<Vec<RegistrationEntry>, RepoError>;

    /// Search packages in `repo` honoring listed/prerelease filtering and
    /// `skip`/`take` paging.
    async fn search(&self, repo: &str, params: &SearchParams) -> Result<SearchResult, RepoError>;

    /// Search with an authorization predicate applied **before** paging and
    /// total-count calculation.
    ///
    /// Production backends override this so they can apply the predicate while
    /// building their in-memory/SQL result once. The default preserves the
    /// contract for third-party/test implementations by walking pages; it is a
    /// compatibility fallback, not the preferred implementation for a backend
    /// whose `search` rescans its complete corpus.
    async fn search_with_package_filter(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        if matches!(filter, PackageFilter::AllowAll) {
            return self.search(repo, params).await;
        }
        if matches!(filter, PackageFilter::DenyAll) {
            return Ok(SearchResult {
                total_hits: 0,
                hits: Vec::new(),
            });
        }

        let mut allowed = Vec::new();
        let mut offset = 0usize;
        loop {
            let mut page_params = params.clone();
            page_params.skip = offset;
            page_params.take = SearchParams::MAX_TAKE;
            let page = self.search(repo, &page_params).await?;
            let returned = page.hits.len();
            allowed.extend(
                page.hits
                    .into_iter()
                    .filter(|hit| filter.allows(&hit.original_id)),
            );

            offset = offset.saturating_add(returned);
            if returned == 0 || offset >= page.total_hits {
                break;
            }
        }

        let total_hits = allowed.len();
        let hits = allowed
            .into_iter()
            .skip(params.skip.min(total_hits))
            .take(params.effective_take())
            .collect();
        Ok(SearchResult { total_hits, hits })
    }

    /// [`Self::search_with_package_filter`] without the per-hit enrichment:
    /// the hits carry ids and versions, but [`SearchHit::nuspec_bytes`] and
    /// [`SearchHit::total_downloads`] may be left unset.
    ///
    /// A group asks every member for a full (up to [`SearchParams::MAX_TAKE`])
    /// result to merge, dedup and count, but renders only the client's page.
    /// It therefore searches its members through this method and enriches just
    /// the final page via [`Self::enrich_search_hits`], so manifest reads (S3)
    /// are bounded by the client's `take` rather than by every member's corpus.
    ///
    /// The default returns the enriched result (and [`Self::enrich_search_hits`]
    /// defaults to a no-op): correct for any implementation, merely not cheaper.
    async fn search_unenriched(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        self.search_with_package_filter(repo, params, filter).await
    }

    /// Attach the enrichment [`Self::search_unenriched`] skipped (latest
    /// manifest, download total) to `hits`, which this backend returned for
    /// `repo`. The order and number of `hits` are preserved. The default does
    /// nothing, matching the default [`Self::search_unenriched`].
    async fn enrich_search_hits(
        &self,
        _repo: &str,
        _hits: &mut [SearchHit],
    ) -> Result<(), RepoError> {
        Ok(())
    }
}

/// A package-filtering decorator around any repository read implementation.
///
/// This is the enforcement boundary shared by the NuGet protocol, browse API,
/// hosted/proxy repositories, and group members. Identifier-addressed methods
/// return the same empty/`None` result as an unknown package, preserving 404
/// behavior at the route layer. Search is filtered before caller pagination
/// through [`RepoReadOps::search_with_package_filter`], allowing production
/// backends to scan their corpus once while preserving an exact `total_hits`.
pub struct PackageFilteredReadOps {
    inner: Arc<dyn RepoReadOps>,
    filter: PackageFilter,
}

impl PackageFilteredReadOps {
    /// Wrap `inner` with a precompiled package predicate.
    pub fn new(inner: Arc<dyn RepoReadOps>, filter: PackageFilter) -> Self {
        Self { inner, filter }
    }

    fn allows(&self, id: &str) -> bool {
        self.filter.allows(id)
    }
}

#[async_trait]
impl RepoReadOps for PackageFilteredReadOps {
    async fn list_versions(&self, repo: &str, id: &str) -> Result<Vec<VersionEntry>, RepoError> {
        if !self.allows(id) {
            return Ok(Vec::new());
        }
        self.inner.list_versions(repo, id).await
    }

    async fn resolve_nupkg(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        if !self.allows(id) {
            return Ok(None);
        }
        self.inner.resolve_nupkg(repo, id, version).await
    }

    async fn resolve_nuspec(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        if !self.allows(id) {
            return Ok(None);
        }
        self.inner.resolve_nuspec(repo, id, version).await
    }

    async fn registration(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        if !self.allows(id) {
            return Ok(Vec::new());
        }
        self.inner.registration(repo, id).await
    }

    async fn search(&self, repo: &str, params: &SearchParams) -> Result<SearchResult, RepoError> {
        self.inner
            .search_with_package_filter(repo, params, &self.filter)
            .await
    }

    async fn search_with_package_filter(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        let combined = self.filter.clone().intersect(filter.clone());
        self.inner
            .search_with_package_filter(repo, params, &combined)
            .await
    }

    async fn search_unenriched(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        let combined = self.filter.clone().intersect(filter.clone());
        self.inner.search_unenriched(repo, params, &combined).await
    }

    async fn enrich_search_hits(
        &self,
        repo: &str,
        hits: &mut [SearchHit],
    ) -> Result<(), RepoError> {
        // The hits came out of the filtered search above, so they already pass
        // the predicate; enrichment adds no package identities.
        self.inner.enrich_search_hits(repo, hits).await
    }
}

/// A boxed async byte source, used by [`RepoWriteOps::store_upload`] so the
/// trait stays object-safe (no generic method). The server bridges an axum
/// multipart field stream into this via `tokio_util::io::StreamReader`.
pub type UploadReader = Box<dyn tokio::io::AsyncRead + Send + Unpin>;

/// Provenance available after a package has been parsed into canonical identity
/// but before any CAS, S3, or component mutation occurs.
///
/// The same value is retained through the package transaction and passed to
/// [`PublishPolicy::record_in_transaction`], allowing trusted-publishing audit
/// records to commit atomically with the package without retaining raw claims.
#[derive(Debug, Clone)]
pub struct PublishAuthorizationContext {
    /// Authenticated request actor (user or workload provenance).
    pub principal: Principal,
    /// Canonical package id extracted by the format parser.
    pub package_id: String,
    /// Canonical normalized package version extracted by the format parser.
    pub package_version: String,
}

/// Request-specific policy and provenance hook for package publication.
///
/// `authorize` runs after local staging and format parsing but before the staged
/// bytes are promoted into CAS. `record_in_transaction` runs after component and
/// asset changes on their still-open transaction, immediately before commit.
#[async_trait]
pub trait PublishPolicy: Send + Sync {
    /// Authorize this canonical package identity. A denial must be explicit and
    /// must not cause CAS/DB/S3 mutation.
    async fn authorize(&self, context: &PublishAuthorizationContext) -> Result<(), WriteError>;

    /// Append request provenance in the package transaction. The default is a
    /// no-op so non-audited callers keep their existing behavior.
    async fn record_in_transaction(
        &self,
        _context: &PublishAuthorizationContext,
        _tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<(), WriteError> {
        Ok(())
    }
}

/// Write operations a NuGet **publish** route handler needs, abstracted (like
/// [`RepoReadOps`]) so handlers can be unit-tested against an in-memory mock.
///
/// Keyed by **repository name**; ids/versions are passed as written and
/// normalized internally by the implementation's [`crate::format::Format`].
#[async_trait]
pub trait RepoWriteOps: Send + Sync {
    /// Publish (or redeploy) a package read from `reader`, enforcing
    /// `max_upload_bytes`. See [`hosted::HostedWrite::store_upload`].
    async fn store_upload(
        &self,
        repo: &str,
        reader: UploadReader,
        max_upload_bytes: u64,
    ) -> Result<PublishOutcome, WriteError>;

    /// Soft- or hard-delete a specific version. See
    /// [`hosted::HostedWrite::delete_component`].
    async fn delete_component(
        &self,
        repo: &str,
        id: &str,
        version: &str,
        hard: bool,
    ) -> Result<DeleteOutcome, WriteError>;

    /// Relist a previously unlisted version. See
    /// [`hosted::HostedWrite::relist`].
    async fn relist(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<DeleteOutcome, WriteError>;
}

#[cfg(test)]
mod search_query_tests {
    use super::SearchQuery;

    #[test]
    fn parses_client_syntax() {
        let q = SearchQuery::parse("PackageId:Newtonsoft.Json");
        assert!(q.matches("newtonsoft.json"));
        assert!(!q.matches("newtonsoft.json.bson"));

        let q = SearchQuery::parse("newtonsoft  JSON");
        assert!(q.matches("newtonsoft.json"));
        assert!(q.matches("newtonsoft.json.bson"));
        assert!(!q.matches("system.text.json"));

        let q = SearchQuery::parse("id:json tags:serializer");
        assert_eq!(q.terms, ["json", "serializer"]);

        assert!(SearchQuery::parse("   ").is_empty());
        assert!(SearchQuery::parse("").matches("anything"));
        assert_eq!(SearchQuery::parse("a bcd").prefilter(), Some("bcd"));
        assert_eq!(SearchQuery::parse("packageid:x.y").prefilter(), Some("x.y"));
    }

    #[test]
    fn lowercases_non_ascii_terms_like_stored_ids() {
        assert!(SearchQuery::parse("Ünicode").matches("ünicode.lib"));
        assert!(SearchQuery::parse("PackageId:Ünicode.Lib").matches("ünicode.lib"));
    }
}
