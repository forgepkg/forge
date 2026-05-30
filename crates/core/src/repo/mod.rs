//! Repository read/write operations, organized by repository kind.
//!
//! Slice 1 implements the **hosted** read path here (Phase 6); proxy and group
//! read paths arrive in later phases. The neutral DTOs in this module are the
//! contract between the storage-backed implementations and the protocol crates
//! (`forge-nuget`): they are format-agnostic and carry exactly what a NuGet
//! route handler needs to render Appendix A JSON, **plus** the raw `.nuspec`
//! bytes so the format layer can extract dependency groups itself (keeping
//! `forge-core` free of NuGet-specific manifest parsing).

pub mod hosted;

use async_trait::async_trait;

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
/// → 409, [`WriteError::InvalidPackage`] → 400, and the wrapped [`RepoError`]
/// for not-found / wrong-kind / db / storage.
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

/// A search hit: one package id with all of its (filtered) versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Package id exactly as published (casing from the latest version).
    pub original_id: String,
    /// The latest version among [`Self::versions`] (highest precedence).
    pub latest_version: String,
    /// All matching versions, ascending by precedence.
    pub versions: Vec<VersionEntry>,
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
}
