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
    /// The first value of header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    /// Free text; empty matches every package.
    pub text: String,
    pub skip: u32,
    /// Clamped by the host to 1000.
    pub take: u32,
    pub prerelease: bool,
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
    /// When the version was published into the repository (RFC 3339).
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
    /// The package is the `multipart/form-data` file part of this name.
    MultipartField(String),
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
