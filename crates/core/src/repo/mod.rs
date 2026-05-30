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
