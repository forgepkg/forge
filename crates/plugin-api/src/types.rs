//! The data a plugin and the host exchange.

use std::fmt;

use crate::images::{
    ImageAnswer, ImageName, ImageQuery, ImageUrl, ManifestInfo, Reference, TagPage,
};

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

impl RepositoryKind {
    /// The name the admin API uses: `hosted`, `proxy` or `group`.
    pub fn as_str(self) -> &'static str {
        match self {
            RepositoryKind::Hosted => "hosted",
            RepositoryKind::Proxy => "proxy",
            RepositoryKind::Group => "group",
        }
    }
}

/// What a format says about itself ([`FormatPlugin::descriptor`]): a
/// `'static` value next to its `impl FormatPlugin`.
///
/// ```no_run
/// use forge_plugin_api::{Assets, Descriptor, RepositoryKind, Storage, UpstreamToken};
///
/// pub const DESCRIPTOR: Descriptor = Descriptor {
///     id: "example",
///     name: "Example packages",
///     version: env!("CARGO_PKG_VERSION"),
///     description: "Example packages: push and pull with the example client.",
///     kinds: &[RepositoryKind::Hosted, RepositoryKind::Group],
///     storage: Storage::Packages,
///     assets: Assets::DEFAULT,
///     upstream_token: UpstreamToken::None,
/// };
/// ```
///
/// [`FormatPlugin::descriptor`]: crate::FormatPlugin::descriptor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    /// The format id repositories are created with (`repository.format`):
    /// 2–32 lowercase letters, digits and `-`, starting with a letter.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// The format's own version, its crate's (`env!("CARGO_PKG_VERSION")`).
    pub version: &'static str,
    /// One line on what the format serves.
    pub description: &'static str,
    /// The repository kinds it supports, each once. `Proxy` only when the
    /// format implements [`FormatPlugin::upstream`].
    ///
    /// [`FormatPlugin::upstream`]: crate::FormatPlugin::upstream
    pub kinds: &'static [RepositoryKind],
    /// What its repositories hold.
    pub storage: Storage,
    /// How a version's files are stored (a package format).
    pub assets: Assets,
    /// What a proxy given a password and no username does with it.
    pub upstream_token: UpstreamToken,
}

/// What a proxy given a password and no username sends its upstream
/// ([`Descriptor::upstream_token`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UpstreamToken {
    /// Nothing: a proxy authenticates with a username and a password only
    /// (Basic).
    #[default]
    None,
    /// The password is a token, sent as `Authorization: Bearer` (npm's
    /// `_authToken`).
    Bearer,
}

/// The mount of an images format ([`Storage::Images`]): the registry API's
/// root, where every distribution-spec client asks.
pub const IMAGES_MOUNT: &str = "/v2";

/// What a format's repositories hold ([`Descriptor::storage`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Storage {
    /// Package versions: an id, a version, a package file and its manifest
    /// (NuGet).
    #[default]
    Packages,
    /// Files under paths, with their digests (raw).
    Files,
    /// Images: blobs and manifests by digest, tags, upload sessions
    /// (Docker / OCI; see [`crate::images`]).
    Images,
}

impl Storage {
    /// The name the admin API uses: `packages`, `files` or `images`.
    pub fn as_str(self) -> &'static str {
        match self {
            Storage::Packages => "packages",
            Storage::Files => "files",
            Storage::Images => "images",
        }
    }
}

/// The names (within a version) and content types of a version's package
/// and manifest ([`Descriptor::assets`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assets {
    /// A plain file name: 1–64 letters, digits, `.`, `_` or `-`, not
    /// starting with `.`.
    pub package: &'static str,
    /// `type/subtype`, parameters allowed.
    pub package_type: &'static str,
    /// A plain file name other than [`Self::package`].
    pub manifest: &'static str,
    /// `type/subtype`, parameters allowed.
    pub manifest_type: &'static str,
}

impl Assets {
    /// `package` and `manifest`, both `application/octet-stream`.
    pub const DEFAULT: Assets = Assets {
        package: "package",
        package_type: "application/octet-stream",
        manifest: "manifest",
        manifest_type: "application/octet-stream",
    };
}

impl Default for Assets {
    fn default() -> Self {
        Assets::DEFAULT
    }
}

/// The repository a request is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    pub name: String,
    pub kind: RepositoryKind,
    /// The absolute URL the repository is served at, without a trailing
    /// slash (e.g. `https://forge.example.com/repository/charts`).
    pub base_url: String,
    /// Files formats: whether the repository's files are displayed by a
    /// browser (its `inline` content disposition) rather than downloaded, as
    /// [`Action::ServeFile`] serves them. Always `false` for a package
    /// format.
    pub inline: bool,
    /// A group's reserved prefixes ([`crate::FormatPlugin::reserved_prefix`]
    /// forms): package ids that are never served from its proxy members.
    /// Empty for any other repository.
    pub reserved_prefixes: Vec<String>,
}

/// An HTTP request from a package client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method, upper case.
    pub method: String,
    /// The path below `base_url`, starting with `/`, still percent-encoded
    /// as the client sent it; empty when the URL ends with the repository's
    /// name.
    pub path: String,
    /// The query string without its `?`, empty when there is none.
    pub query: String,
    /// The request headers the host passes on (lowercase names): accept,
    /// accept-language, content-type, if-match, if-modified-since,
    /// if-none-match, user-agent, and to an images format content-range.
    /// Never credentials or cookies.
    pub headers: Vec<(String, String)>,
    /// The request body, once the plugin asked for it ([`Action::ReadBody`]);
    /// `None` before. A `Content-Encoding: gzip` body is inflated.
    pub body: Option<Vec<u8>>,
    /// Images formats: the image the request is for, as the host resolved
    /// the name [`FormatPlugin::image_path`] split off the path; the path
    /// is then the endpoint. `None` for every other format.
    ///
    /// [`FormatPlugin::image_path`]: crate::FormatPlugin::image_path
    pub image: Option<ImageName>,
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
            body: None,
            image: None,
        }
    }

    /// The request with its body read ([`Action::ReadBody`]).
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// The request for `image` (images formats), the client having named
    /// it `name`.
    pub fn with_image(mut self, image: &str, name: &str) -> Self {
        self.image = Some(ImageName {
            image: image.to_string(),
            name: name.to_string(),
        });
        self
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
/// type, caching and validators, content-disposition, vary, and location and
/// link within the repository) and adds its own security headers.
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

    /// A response without a body or headers (a 204, a redirect).
    pub fn empty(status: u16) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
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

/// A page of a directory of a files repository ([`Query::Directory`]).
///
/// A file path is a list of segments joined by `/`, without a leading or
/// trailing `/` (see [`crate::files`]). A directory is `""` (the root) or a
/// path ending in `/`. The host refuses any other path a plugin names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryQuery {
    pub directory: String,
    /// Start after this entry, a name in the directory (a subdirectory's ends
    /// in `/`); `None` starts at the first.
    pub after: Option<String>,
    /// The page size: 0 means the default (100), more than 1000 is 1000.
    pub limit: u32,
}

/// A file of a files repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    /// What the upload declared, else what its name suggests.
    pub content_type: String,
    /// Lowercase hex.
    pub sha256: String,
    /// Base64.
    pub sha512: String,
    /// Lowercase hex.
    pub sha1: String,
    /// Lowercase hex.
    pub md5: String,
    /// When its content was last stored (uploaded, or fetched by a proxy):
    /// RFC 3339 in UTC.
    pub modified: String,
    /// When it was last downloaded, to the hour: RFC 3339 in UTC.
    pub last_downloaded: Option<String>,
}

/// One entry of a [`DirectoryPage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryEntry {
    File(FileInfo),
    /// A subdirectory: its path, ending in `/`.
    Directory(String),
}

/// A page of a directory ([`Answer::Directory`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryPage {
    /// In byte order of their names, a subdirectory's ending in `/`.
    pub entries: Vec<DirectoryEntry>,
    /// The `after` of the next page; `None` on the last.
    pub next: Option<String>,
}

/// One part of a `multipart/form-data` body ([`Query::Form`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormPart {
    /// The part's field name.
    pub field: String,
    pub content: FormContent,
}

/// What a [`FormPart`] holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormContent {
    /// A file: received and staged by the host, stored with
    /// [`FileSource::Part`] and its index among the form's parts.
    File(FormFile),
    /// Any other field: its value (UTF-8, at most 4 KiB).
    Text(String),
}

/// A file part of a form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormFile {
    /// The file name the part declares.
    pub name: String,
    /// The content type the part declares.
    pub content_type: Option<String>,
    pub size: u64,
}

/// Where a file to store comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSource {
    /// The request body.
    Body,
    /// A file part of the request's form, by its index ([`Query::Form`]).
    Part(u32),
}

/// A file to store ([`Query::Store`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFile {
    pub path: String,
    pub source: FileSource,
    /// The content type the client declared. The host keeps it unless it
    /// says no more than "bytes" (none, `application/octet-stream`, a form
    /// encoding); then it takes the one the path's extension suggests.
    pub content_type: Option<String>,
}

/// What storing a file did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreStatus {
    /// The path was new.
    Created,
    /// The path held other content, which this replaced.
    Replaced,
    /// The path held this content already.
    Unchanged,
}

/// A file stored ([`Answer::Stored`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    pub path: String,
    pub size: u64,
    /// Lowercase hex.
    pub sha256: String,
    pub status: StoreStatus,
}

/// What a plugin can ask of the host: data, and in a files repository
/// changes to its files. Package ids are canonical, versions normalized.
/// Everything the caller may not read (package selectors, group members it
/// cannot see) is left out, exactly as for an unknown package or file.
///
/// A package format asks for packages ([`Query::Versions`] …
/// [`Query::Search`]), a files format for files ([`Query::File`] …
/// [`Query::Remove`]): a query of the other kind fails the request.
/// [`Query::Form`], [`Query::Store`] and [`Query::Remove`] change the
/// repository: each is asked alone in its round, at most once per request
/// for `Form` and `Store`, and only by a request authorized for them (write
/// for `Form` and `Store`, delete for `Remove`) in a hosted repository, with
/// an API token or a workload identity. When one fails (403 not allowed, 405
/// not hosted or read-only, 409 the path exists and the repository does not
/// allow redeploying it, 413 too large) the host answers with its own
/// status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// Every version of a package, ascending.
    Versions(String),
    /// Every version of a package with its metadata, ascending.
    Packages(String),
    /// [`Query::Packages`] with every version's publish time
    /// ([`PackageInfo::published`]), even where that costs more: a proxy
    /// asks its upstream with [`UpstreamOp::Dating`] instead of
    /// [`UpstreamOp::Metadata`].
    DatedPackages(String),
    /// One version with its metadata.
    Package(PackageRef),
    /// Some versions of a package with their metadata, ascending; versions
    /// it does not have are left out.
    PackagesOf(PackageVersions),
    /// The manifest stored with one version.
    Manifest(PackageRef),
    /// The packages matching a search.
    Search(SearchQuery),
    /// A package's tags ([`Tag`]). A hosted repository's are the ones set
    /// with [`Change::Tag`], a proxy's its upstream's
    /// ([`UpstreamOp::Tags`]), a group's those of its first member, by
    /// priority, that serves the package and has tags for it.
    Tags(String),
    /// The file stored at a path. A proxy answers with its cached copy,
    /// re-validated with its upstream once it is due; a group with its first
    /// member, by priority, that has the path.
    File(String),
    /// [`Query::File`], and a proxy (a group's proxy members too) that has
    /// not cached the path asks its upstream for it ([`UpstreamOp::File`])
    /// and caches what it gets.
    FetchFile(String),
    /// A page of a directory. A proxy lists the files it has cached, a group
    /// the merged entries of its members (the first member's file of a
    /// name). A subdirectory is listed when the caller may see a file in it.
    Directory(DirectoryQuery),
    /// Receive the request's `multipart/form-data` body: its file parts are
    /// staged (each within the repository's upload limit, at most 100), its
    /// other fields read.
    Form,
    /// Store files, all of them or none. A path that holds a file is replaced
    /// only when the repository allows redeploying and the caller may delete;
    /// the same content again is accepted as it is.
    Store(Vec<NewFile>),
    /// Delete the file at a path.
    Remove(String),
    /// What an images format asks of the image store ([`crate::images`]).
    Image(ImageQuery),
}

impl Query {
    /// Whether the query changes the repository (it is asked alone in its
    /// round).
    pub fn is_change(&self) -> bool {
        match self {
            Query::Form | Query::Store(_) | Query::Remove(_) => true,
            Query::Image(query) => query.is_change(),
            _ => false,
        }
    }

    /// Whether the query is about images.
    pub fn is_images(&self) -> bool {
        matches!(self, Query::Image(_))
    }

    /// Whether the query is about files rather than packages.
    pub fn is_files(&self) -> bool {
        matches!(
            self,
            Query::File(_)
                | Query::FetchFile(_)
                | Query::Directory(_)
                | Query::Form
                | Query::Store(_)
                | Query::Remove(_)
        )
    }
}

/// A name for one version of a package (npm's dist-tags: `latest`, `next`).
/// A tag names one version; a version may have several tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub name: String,
    /// Normalized.
    pub version: String,
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
    /// Why the version should not be used any more, when it was deprecated
    /// ([`Change::Deprecate`]).
    pub deprecated: Option<String>,
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
    /// The answer to [`Query::Packages`], [`Query::DatedPackages`] and
    /// [`Query::PackagesOf`].
    Packages(Vec<PackageInfo>),
    Package(Option<PackageInfo>),
    Manifest(Option<Vec<u8>>),
    Search(SearchResult),
    /// The answer to [`Query::Tags`], by name.
    Tags(Vec<Tag>),
    /// The answer to [`Query::File`] and to [`Query::FetchFile`].
    File(Option<FileInfo>),
    /// `None`: the directory does not exist (a directory other than the root
    /// without an entry the caller may see, asked for without `after`).
    Directory(Option<DirectoryPage>),
    Form(Vec<FormPart>),
    /// What became of each file, in the order of [`Query::Store`].
    Stored(Vec<StoredFile>),
    /// Whether there was a file to delete.
    Removed(bool),
    /// The answer to [`Query::Image`].
    Image(ImageAnswer),
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
    /// The body is a document carrying the package (npm's publish: a JSON
    /// document with the tarball in base64): the host streams it through
    /// [`FormatPlugin::unpack_upload`], parses the package with
    /// [`FormatPlugin::parse_upload`] and, once it is stored, applies
    /// [`FormatPlugin::published`]'s changes.
    ///
    /// [`FormatPlugin::unpack_upload`]: crate::FormatPlugin::unpack_upload
    /// [`FormatPlugin::parse_upload`]: crate::FormatPlugin::parse_upload
    /// [`FormatPlugin::published`]: crate::FormatPlugin::published
    Document,
}

/// A publish, and the response when it succeeds. When it fails the host
/// answers with its own status (400 invalid package, 403 not allowed, 409
/// version exists, 413 too large).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRequest {
    pub upload: Upload,
    /// The canonical id the package must have (the one its URL names):
    /// another is refused with 400. `None`: any.
    pub id: Option<String>,
    pub done: Response,
}

/// What [`FormatPlugin::unpack_upload`] found in an [`Upload::Document`].
///
/// [`FormatPlugin::unpack_upload`]: crate::FormatPlugin::unpack_upload
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unpacked {
    /// A package, written out; `document` is the rest of the body, handed
    /// to [`FormatPlugin::parse_upload`] and [`FormatPlugin::published`].
    ///
    /// [`FormatPlugin::parse_upload`]: crate::FormatPlugin::parse_upload
    /// [`FormatPlugin::published`]: crate::FormatPlugin::published
    Package { document: Vec<u8> },
    /// No package: the body is a document of another kind (npm's
    /// deprecations and dist-tag edits are the same request). The host
    /// drops what was staged and asks [`FormatPlugin::handle`] again, with
    /// the body as [`Request::body`].
    ///
    /// [`FormatPlugin::handle`]: crate::FormatPlugin::handle
    Document(Vec<u8>),
}

/// What a request's body is for ([`BodyRequest`]): what the caller needs
/// for the host to read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyUse {
    /// A login's ([`AuthRequest::Password`], [`AuthRequest::StartWebLogin`]):
    /// read for any caller, at most 64 KiB, and what the plugin answers then
    /// must be [`Action::Auth`].
    Login,
    /// A query sent as a body (npm's audits): the caller needs read.
    Read,
    /// A change: the caller needs the permission the request's method takes
    /// (PUT/POST write, DELETE delete).
    Change,
}

/// A request whose body the plugin needs to decide what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyRequest {
    /// The largest body accepted: a larger one is answered 413. The host
    /// caps it at 64 MiB.
    pub limit: u64,
    pub used_for: BodyUse,
}

/// A package [`FormatPlugin::unpack_upload`] wrote, with what came with it.
///
/// [`FormatPlugin::unpack_upload`]: crate::FormatPlugin::unpack_upload
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uploaded<'a> {
    /// The rest of the document ([`Unpacked::Package`]).
    pub document: &'a [u8],
    /// The username of the account publishing, when it is a user's.
    pub publisher: Option<&'a str>,
}

/// One change to a repository's packages ([`ChangeSet`]). Ids are
/// canonical, versions normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Hide a version from searches and "latest" (delete permission).
    Unlist(PackageRef),
    /// Show an unlisted version again (write permission).
    Relist(PackageRef),
    /// Remove a version, its bytes and its tags (delete permission).
    Delete(PackageRef),
    /// Mark a version deprecated with `message`, or (`None`) no longer
    /// (write permission).
    Deprecate {
        target: PackageRef,
        message: Option<String>,
    },
    /// Point tag `tag` of package `id` at `version`, which must exist
    /// (write permission).
    Tag {
        id: String,
        tag: String,
        version: String,
    },
    /// Remove tag `tag` of package `id` (write permission).
    Untag { id: String, tag: String },
}

/// Changes the host makes in order, and the response when every one
/// succeeded. The first that fails answers instead (403, 404 for a version
/// the caller cannot see, 400), and those before it stay made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSet {
    pub changes: Vec<Change>,
    pub done: Response,
}

/// What only the host can do about who the caller is: log a client in,
/// out, or tell it who it is. Its outcome comes back through
/// [`FormatPlugin::auth_response`]; refusals the host answers itself (401,
/// 429, 503).
///
/// [`FormatPlugin::auth_response`]: crate::FormatPlugin::auth_response
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthRequest {
    /// Sign in with a password; the outcome is a new API token
    /// ([`AuthOutcome::Token`]). Any caller may ask.
    Password { username: String, password: String },
    /// Start a login the user approves in the browser
    /// ([`AuthOutcome::WebLoginStarted`]). Any caller may ask; 404 when the
    /// server serves no web UI.
    StartWebLogin { hostname: Option<String> },
    /// Whether the web login `secret` was approved: [`AuthOutcome::Token`]
    /// once, [`AuthOutcome::WebLoginPending`] before,
    /// [`AuthOutcome::WebLoginUnknown`] when refused, expired or collected.
    PollWebLogin { secret: String },
    /// Revoke the caller's own API token `token` ([`AuthOutcome::LoggedOut`]).
    Logout { token: String },
    /// Who the caller is ([`AuthOutcome::Identity`]).
    Whoami,
}

/// What came of an [`AuthRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// A new API token, for `username`.
    Token {
        token: String,
        username: String,
    },
    /// The page the user approves the login on, and the login's secret
    /// (what the client polls with).
    WebLoginStarted {
        login_url: String,
        secret: String,
    },
    WebLoginPending,
    WebLoginUnknown,
    LoggedOut,
    Identity {
        username: String,
    },
}

/// A request the host sends on to the upstream of the repository (a proxy)
/// or of a group's first proxy member the caller may read: npm's audits.
/// The upstream's status, content type and body are the response. A hosted
/// repository has no upstream: 404.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    /// The path below the upstream's `remote_url`, starting with `/`
    /// (with a query, if any).
    pub path: String,
    pub content_type: String,
    /// Sent as a POST.
    pub body: Vec<u8>,
}

/// An unlist, relist or delete, and the response when it succeeds (the host
/// answers 404 for an unknown version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeRequest {
    pub target: PackageRef,
    pub done: Response,
}

/// What a request is ([`FormatPlugin::handle`]), or what to do once the data
/// it asked for is loaded ([`FormatPlugin::render`]).
///
/// [`FormatPlugin::handle`]: crate::FormatPlugin::handle
/// [`FormatPlugin::render`]: crate::FormatPlugin::render
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Answer with this response.
    Respond(Response),
    /// Load this data, then call `render` with everything loaded so far (the
    /// host bounds the rounds and the number of queries).
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
    /// Make these changes ([`ChangeSet`]): never for a GET or HEAD.
    Change(ChangeSet),
    /// Read the request body, then call `handle` again with it
    /// ([`Request::body`]).
    ReadBody(BodyRequest),
    /// Log in, out, or say who the caller is ([`AuthRequest`]).
    Auth(AuthRequest),
    /// Send the request on to the upstream ([`Forward`]; read permission).
    Forward(Forward),
    /// Serve the file at this path (read requests), found as
    /// [`Query::FetchFile`] finds it, or 404. The host streams it with its
    /// validators (`ETag`, its SHA-256; `Last-Modified`), answers conditional
    /// requests and one range, sets its content type and the repository's
    /// content disposition, and counts the download.
    ServeFile(String),
    /// Images formats: serve a blob of the image that a
    /// [`ImageQuery::Blob`] of this request found (read requests). The host
    /// streams it with its `Docker-Content-Digest` and `ETag`, answers one
    /// `Range`, and records the pull.
    ServeBlob { image: String, digest: String },
    /// Images formats: serve a manifest of the image that a
    /// [`ImageQuery::Manifest`] of this request found (read requests), as
    /// its media type, with its `Docker-Content-Digest` and `ETag`, and
    /// record the pull.
    ServeManifest { image: String, reference: Reference },
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
    /// TTL and falls back to the last good one when a refresh fails. It
    /// also keeps the origins the documents fetched to resolve it name:
    /// every other operation may fetch from them (see [`Fetch`]).
    Index,
    /// The versions the upstream lists of a package (canonical id).
    Versions(String),
    /// The URL of a version's package. The host downloads it (from an
    /// origin a [`Fetch`] may reach, and from no other), checks it with
    /// `parse_package` against the version asked for, and stores it.
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
    /// The tags the upstream gives a package (canonical id).
    Tags(String),
    /// The URL of the file at a path (files formats). The host downloads it,
    /// following redirects (its credentials go to the remote's origin only),
    /// caches it as the file, and re-validates it with a conditional request
    /// once the repository's maximum age has passed.
    File(String),
    /// Images formats: the name the upstream knows an image by, which a
    /// proxy caches it under (Docker Hub's `library/` namespace). The other
    /// image operations get this name.
    ImageName(String),
    /// Images formats: where to ask for a manifest of an image
    /// ([`UpstreamAnswer::ImageUrl`]). The host sends a `HEAD` to
    /// re-validate a tag it cached and a `GET` for the manifest, checks it
    /// against its digest (the reference's, else the upstream's
    /// `Docker-Content-Digest`), reads it with `parse_manifest`, and caches
    /// it.
    ImageManifest { image: String, reference: Reference },
    /// Images formats: where to ask for a blob of an image
    /// ([`UpstreamAnswer::ImageUrl`]). The host downloads it, checks it
    /// against its digest and caches it.
    ImageBlob { image: String, digest: String },
    /// Images formats: up to `n` of the upstream's tags of an image after
    /// `last`, in byte order ([`UpstreamAnswer::ImageTags`]).
    ImageTags {
        image: String,
        last: Option<String>,
        n: u32,
    },
    /// Images formats: the upstream's referrers of a manifest
    /// ([`UpstreamAnswer::ImageReferrers`]).
    ImageReferrers { image: String, digest: String },
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
/// The host sends it only where the upstream points: to the origin (scheme,
/// host and port) of [`Remote::url`], or to an origin that an absolute
/// `http`/`https` URL names in a document the host fetched for the same
/// operation (in an earlier round), or while resolving [`UpstreamOp::Index`].
/// What the plugin answers names no origin, its index included. A fetch
/// anywhere else is not sent, and comes back [`Fetched::Failed`]. So a
/// NuGet service index may put its resources on other hosts, and a Helm
/// index its charts, but a plugin reaches no host its upstream does not
/// point at. A host the upstream's documents name is reachable, though,
/// whatever names it (a project URL in a package's metadata included).
///
/// The host sends the repository's credentials only to the origin of
/// [`Remote::url`], bounds the response's size and time, inflates a
/// gzip-encoded body, and refuses link-local and cloud-metadata targets.
///
/// An images format's fetches go to the origin of [`Remote::url`] only; the
/// host answers an upstream registry's Bearer challenge with a token from
/// the registry's token service, and does not keep what it fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    pub url: String,
    pub freshness: Freshness,
    /// The `Accept` header to send, if any (npm's abbreviated metadata, an
    /// images format's manifest media types).
    pub accept: Option<String>,
    /// Images formats: the scope of the token to ask the upstream's token
    /// service for when it answers 401 with a Bearer challenge naming none.
    pub scope: Option<String>,
}

impl Fetch {
    /// A fetch of `url` without an `Accept` header.
    pub fn new(url: impl Into<String>, freshness: Freshness) -> Self {
        Fetch {
            url: url.into(),
            freshness,
            accept: None,
            scope: None,
        }
    }

    /// The fetch with an `Accept` header.
    pub fn accepting(mut self, accept: &str) -> Self {
        self.accept = Some(accept.to_string());
        self
    }
}

/// How a [`Fetch`] went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// A 2xx, with its body.
    Found(Vec<u8>),
    /// A 404.
    NotFound,
    /// Anything else: a transport error, another status, a body over the
    /// size limit, a URL the host does not send to (see [`Fetch`]).
    Failed(String),
}

/// A fetch with how it went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    pub fetch: Fetch,
    pub outcome: Fetched,
    /// Images formats: the status of the upstream's answer, when one came.
    pub status: Option<u16>,
    /// Images formats: the `link` headers of the upstream's answer (a page
    /// of a listing names the next one there).
    pub headers: Vec<(String, String)>,
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

/// Where an upstream keeps a version's package, and the digests it
/// publishes for it: the host refuses a package that does not match them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageLocation {
    pub url: String,
    /// SHA-512, base64.
    pub sha512: Option<String>,
    /// SHA-1, lowercase hex.
    pub sha1: Option<String>,
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
    /// The answer to [`UpstreamOp::Index`]: a JSON object. The host keeps
    /// its own fields beside it, so the keys `remote_url` and
    /// `named_origins` are not the plugin's: an index using them is refused
    /// like one that is not an object.
    Index(String),
    /// `None`: the upstream does not know the package.
    Versions(Option<Vec<String>>),
    /// The package's URL, on an origin a [`Fetch`] may reach: a package
    /// anywhere else is not downloaded, and the host takes it for an
    /// upstream failure.
    Package(String),
    Manifest(Option<Vec<u8>>),
    /// The answer to [`UpstreamOp::Metadata`] and [`UpstreamOp::Dating`].
    Metadata(PackageMetadata),
    /// `None`: the upstream offers no search.
    Search(Option<UpstreamSearch>),
    /// [`UpstreamAnswer::Package`] with the digests the upstream publishes.
    Located(PackageLocation),
    /// The answer to [`UpstreamOp::Tags`]; `None`: the upstream does not know
    /// the package.
    Tags(Option<Vec<Tag>>),
    /// The file's URL, on an origin a [`Fetch`] may reach; `None`: the
    /// upstream cannot have the path.
    File(Option<String>),
    /// The answer to [`UpstreamOp::ImageName`].
    ImageName(String),
    /// The answer to [`UpstreamOp::ImageManifest`] and
    /// [`UpstreamOp::ImageBlob`].
    ImageUrl(ImageUrl),
    /// `None`: the upstream does not know the image.
    ImageTags(Option<TagPage>),
    /// `None`: the upstream offers no referrers API (the host lists the
    /// referrers its cache holds).
    ImageReferrers(Option<Vec<ManifestInfo>>),
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
