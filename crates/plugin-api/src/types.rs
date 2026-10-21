//! The data a plugin and the host exchange: the records and variants of
//! `wit/format.wit`, in Rust.

use std::fmt;

/// A dependency on another package of the same format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// The package id, as written.
    pub id: String,
    /// The version range in the format's syntax; `None` for any version.
    pub range: Option<String>,
}

/// The dependencies that apply to one target (a framework, a platform); a
/// format without targets uses a single group without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyGroup {
    pub target: Option<String>,
    pub dependencies: Vec<Dependency>,
}

/// Why a package, an id or a version was refused. The text is shown to the
/// client that sent it, except for [`FormatError::Internal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    InvalidPackage(String),
    MissingManifest(String),
    MalformedManifest(String),
    InvalidVersion(String),
    InvalidId(String),
    /// The plugin itself failed (a bug, an exhausted resource): the client
    /// gets a server error, not this text.
    Internal(String),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::InvalidPackage(m) => write!(f, "invalid package: {m}"),
            FormatError::MissingManifest(m) => write!(f, "missing manifest: {m}"),
            FormatError::MalformedManifest(m) => write!(f, "malformed manifest: {m}"),
            FormatError::InvalidVersion(m) => write!(f, "invalid version: {m}"),
            FormatError::InvalidId(m) => write!(f, "invalid id: {m}"),
            FormatError::Internal(m) => write!(f, "format plugin failed: {m}"),
        }
    }
}

impl std::error::Error for FormatError {}

/// What a package declares about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPackage {
    /// The canonical id: what [`FormatPlugin::canonical_id`] returns for
    /// `original_id`.
    ///
    /// [`FormatPlugin::canonical_id`]: crate::FormatPlugin::canonical_id
    pub id: String,
    /// The id exactly as the package writes it.
    pub original_id: String,
    /// The normalized version.
    pub version: String,
    /// The version exactly as the package writes it.
    pub version_original: String,
    /// Whether the version shows up in searches and as "latest".
    pub listed: bool,
    /// The manifest (e.g. Chart.yaml, package.json), stored next to the
    /// package and handed back through [`Query::Manifest`]. Keep it small: it
    /// is held in memory.
    pub manifest: Vec<u8>,
    pub dependencies: Vec<DependencyGroup>,
}

/// How a repository stores its packages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryKind {
    Hosted,
    Proxy,
    Group,
}

/// The repository a request is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    pub name: String,
    pub kind: RepositoryKind,
    /// The absolute URL the repository is served at, without a trailing
    /// slash (e.g. `https://forge.example.com/repository/charts`).
    pub base_url: String,
}

/// An HTTP request from a package client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method, upper case.
    pub method: String,
    /// The path below `base_url`, starting with `/`, still percent-encoded
    /// as the client sent it.
    pub path: String,
    /// The query string without its `?`, empty when there is none.
    pub query: String,
    /// The request headers the host passes on (lowercase names): accept,
    /// accept-language, content-type, if-match, if-modified-since,
    /// if-none-match, user-agent. Never credentials or cookies.
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// A request for `target` (a path, optionally with `?query`) without
    /// headers.
    pub fn new(method: &str, target: &str) -> Self {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        Request {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            query: query.to_string(),
            headers: Vec::new(),
        }
    }

    /// Add a header (`name` lowercase).
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), value.to_string()));
        self
    }

    /// The first value of header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The path's segments, percent-decoded (`/flat/a%2Fb/x` → `["flat",
    /// "a/b", "x"]`); a trailing slash adds an empty segment. `None` when an
    /// escape is malformed or a segment is not UTF-8.
    pub fn segments(&self) -> Option<Vec<String>> {
        self.path
            .strip_prefix('/')
            .unwrap_or(&self.path)
            .split('/')
            .map(|segment| percent_decode(segment, false))
            .collect()
    }

    /// The query string's `name=value` pairs, decoded as an HTML form does
    /// (`+` is a space). A pair that does not decode is skipped.
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        self.query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .filter_map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                Some((percent_decode(name, true)?, percent_decode(value, true)?))
            })
            .collect()
    }

    /// The first value of query parameter `name`.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.query_pairs()
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }
}

/// `%XX`-decode `s` (and `+` as a space when `plus_is_space`).
fn percent_decode(s: &str, plus_is_space: bool) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// An HTTP response. The host keeps only the headers it allows (content
/// type, caching and validators, content-disposition, location) and adds its
/// own security headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// A plain-text response (`text/plain; charset=utf-8`).
    pub fn text(status: u16, body: &str) -> Self {
        Response::new(status, "text/plain; charset=utf-8", body)
    }

    /// A response with a body of `content_type`.
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Response {
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body: body.into(),
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// One version of one package (canonical id, normalized version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub id: String,
    pub version: String,
}

/// Some versions of one package (canonical id, normalized versions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageVersions {
    pub id: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    /// Free text; empty matches every package. `packageid:x` and `id:x`
    /// match an id exactly; several terms must all match.
    pub text: String,
    pub skip: u32,
    /// The page size: 0 means the default (20), more than 1000 is 1000.
    pub take: u32,
    /// Include prerelease versions.
    pub prerelease: bool,
    /// Include SemVer 2.0.0 versions (dotted prerelease labels, build
    /// metadata).
    pub semver2: bool,
    /// Let a proxy repository forward the search to its upstream, so packages
    /// it has not cached yet are found too.
    pub upstream: bool,
}

/// Data a plugin can ask for. Package ids are canonical, versions
/// normalized. Everything the caller may not read (package selectors, group
/// members it cannot see) is left out, exactly as for an unknown package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// Every version of a package, ascending.
    Versions(String),
    /// Every version of a package with its metadata, ascending.
    Packages(String),
    /// One version with its metadata.
    Package(PackageRef),
    /// Some versions of a package with their metadata, ascending; versions
    /// it does not have are left out.
    PackagesOf(PackageVersions),
    /// The manifest stored with one version.
    Manifest(PackageRef),
    /// The packages matching a search.
    Search(SearchQuery),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// The id as the package writes it.
    pub original_id: String,
    pub version: String,
    pub version_original: String,
    pub listed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    pub original_id: String,
    pub version: String,
    pub version_original: String,
    pub listed: bool,
    /// When the version was published into the repository: RFC 3339 in UTC
    /// with milliseconds (`2026-10-21T12:00:00.000+00:00`).
    pub published: Option<String>,
    /// The package's SHA-256, lowercase hex.
    pub sha256: Option<String>,
    /// The package's SHA-512, base64.
    pub sha512: Option<String>,
    /// The package's size in bytes.
    pub size: Option<u64>,
    /// What [`FormatPlugin::manifest_summary`] returned at publish.
    ///
    /// [`FormatPlugin::manifest_summary`]: crate::FormatPlugin::manifest_summary
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub original_id: String,
    pub latest_version: String,
    /// Ascending.
    pub versions: Vec<VersionInfo>,
    /// The summary of the latest version.
    pub summary: Option<String>,
    /// Downloads of the package, all versions, when the repository counts
    /// them.
    pub total_downloads: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// Matching packages before paging.
    pub total: u32,
    pub hits: Vec<SearchHit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Versions(Vec<VersionInfo>),
    /// The answer to [`Query::Packages`] and to [`Query::PackagesOf`].
    Packages(Vec<PackageInfo>),
    Package(Option<PackageInfo>),
    Manifest(Option<Vec<u8>>),
    Search(SearchResult),
}

/// A query with its answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub query: Query,
    pub answer: Answer,
}

/// Where a publish request carries the package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upload {
    /// The request body is the package.
    Body,
    /// The package is the `multipart/form-data` part of this name.
    MultipartField(String),
    /// The package is the first part of a `multipart/form-data` body,
    /// whatever its name.
    FirstPart,
}

/// A publish, and the response when it succeeds. When it fails the host
/// answers with its own status (400 invalid package, 403 not allowed, 409
/// version exists, 413 too large).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRequest {
    pub upload: Upload,
    pub done: Response,
}

/// An unlist, relist or delete, and the response when it succeeds (the host
/// answers 404 for an unknown version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRequest {
    pub target: PackageRef,
    pub done: Response,
}

/// What a request is ([`FormatPlugin::handle`]).
///
/// [`FormatPlugin::handle`]: crate::FormatPlugin::handle
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Answer with this response.
    Respond(Response),
    /// Load this data, then call `render` with it.
    Load(Vec<Query>),
    /// Serve the stored package of this version, or 404 when the caller
    /// cannot read it. The host streams it and counts the download.
    Download(PackageRef),
    /// Publish the package the request carries (hosted repositories, write
    /// permission). The host parses it with `parse_package`.
    Publish(PublishRequest),
    /// Hide a version from searches and "latest" (delete permission).
    Unlist(ChangeRequest),
    /// Show an unlisted version again (write permission).
    Relist(ChangeRequest),
    /// Remove a version and its bytes (delete permission).
    Delete(ChangeRequest),
}

/// What a round of [`FormatPlugin::render`] produced.
///
/// [`FormatPlugin::render`]: crate::FormatPlugin::render
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rendered {
    /// Answer with this response.
    Respond(Response),
    /// Load more data, then call `render` again with everything loaded so
    /// far (the host bounds the rounds and the number of queries).
    Load(Vec<Query>),
}

/// The upstream a proxy repository mirrors ([`FormatPlugin::upstream`]).
///
/// [`FormatPlugin::upstream`]: crate::FormatPlugin::upstream
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    /// The upstream's URL as the repository is configured with it.
    pub url: String,
    /// What [`UpstreamOp::Index`] answered for it (a JSON object of the
    /// plugin's own making); `None` while the index is being resolved.
    pub index: Option<String>,
}

/// What the host wants to know about the upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamOp {
    /// Resolve the upstream into the index every other operation gets as
    /// [`Remote::index`]. The host keeps it, refreshes it once per metadata
    /// TTL and falls back to the last good one when a refresh fails.
    Index,
    /// The versions the upstream lists of a package (canonical id).
    Versions(String),
    /// The URL of a version's package. The host downloads it, checks it
    /// with `parse_package` against the version asked for, and stores it.
    Package(PackageRef),
    /// A version's manifest without its package, verified to be that
    /// version's; `None` sends the host to the package instead.
    Manifest(PackageRef),
    /// The upstream's metadata of some versions of a package (listing state,
    /// publish time, manifest summary), best effort.
    Metadata(PackageVersions),
    /// [`UpstreamOp::Metadata`], plus when each version was created
    /// upstream ([`VersionMetadata::created`]): the package delay counts
    /// from it. It may cost more requests.
    Dating(PackageVersions),
    /// A page of the upstream's search results.
    Search(SearchQuery),
}

/// How long the host may reuse a fetched document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// For the repository's metadata TTL: listings, indexes, search pages.
    Metadata,
    /// For a day: a document that never changes once published (a
    /// version's manifest, a catalog entry).
    Immutable,
}

/// A GET the plugin asks the host to send to the upstream.
///
/// The host sends the repository's credentials only to the origin of
/// [`Remote::url`], bounds the response's size and time, inflates a
/// gzip-encoded body, and refuses link-local and cloud-metadata targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    pub url: String,
    pub freshness: Freshness,
}

/// How a [`Fetch`] went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// A 2xx, with its body.
    Found(Vec<u8>),
    /// A 404.
    NotFound,
    /// Anything else: a transport error, another status, a body over the
    /// size limit.
    Failed(String),
}

/// A fetch with how it went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    pub fetch: Fetch,
    pub outcome: Fetched,
}

/// The upstream's metadata of one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMetadata {
    /// Normalized.
    pub version: String,
    /// The id as this version spells it, when the upstream says.
    pub original_id: Option<String>,
    pub listed: bool,
    /// When the upstream published the version: RFC 3339, shown to clients.
    pub published: Option<String>,
    /// When the version was created upstream, RFC 3339 ([`UpstreamOp::Dating`]
    /// only): the package delay of a version first seen now counts from it.
    pub created: Option<String>,
    /// A manifest summary (as [`FormatPlugin::manifest_summary`] returns
    /// one) for a version the proxy has not downloaded yet.
    ///
    /// [`FormatPlugin::manifest_summary`]: crate::FormatPlugin::manifest_summary
    pub summary: Option<String>,
}

/// The answer to [`UpstreamOp::Metadata`] and [`UpstreamOp::Dating`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackageMetadata {
    /// The id as the upstream spells the package (its newest version's),
    /// when known.
    pub original_id: Option<String>,
    /// The versions the upstream has metadata of, among those asked for.
    pub versions: Vec<VersionMetadata>,
}

/// One package of an upstream's search results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHit {
    /// The id as the upstream spells it.
    pub id: String,
    /// Normalized, ascending.
    pub versions: Vec<String>,
    /// A manifest summary of the latest version.
    pub summary: Option<String>,
    pub total_downloads: Option<u64>,
}

/// One page of an upstream's search results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSearch {
    /// Matching packages before paging, as the upstream counts them.
    pub total: u64,
    pub hits: Vec<UpstreamHit>,
}

/// What an [`UpstreamOp`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamAnswer {
    /// The answer to [`UpstreamOp::Index`]: a JSON object.
    Index(String),
    /// `None`: the upstream does not know the package.
    Versions(Option<Vec<String>>),
    /// The package's URL.
    Package(String),
    Manifest(Option<Vec<u8>>),
    /// The answer to [`UpstreamOp::Metadata`] and [`UpstreamOp::Dating`].
    Metadata(PackageMetadata),
    /// `None`: the upstream offers no search.
    Search(Option<UpstreamSearch>),
    /// The upstream answered something unusable: the host serves what it
    /// has cached.
    Failed(String),
}

/// What a round of [`FormatPlugin::upstream`] produced.
///
/// [`FormatPlugin::upstream`]: crate::FormatPlugin::upstream
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamStep {
    /// Fetch these, then call `upstream` again with everything fetched so
    /// far (the host bounds the rounds and the number of fetches).
    Fetch(Vec<Fetch>),
    Done(UpstreamAnswer),
}
