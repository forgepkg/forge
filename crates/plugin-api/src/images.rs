//! Images formats: what a format whose descriptor says
//! [`Storage::Images`](crate::Storage::Images) (Docker / OCI) and the host's
//! image store exchange.
//!
//! An image repository holds images by name (`team/app`): content-addressed
//! blobs and manifests linked into each image, tags that point at
//! manifests, and upload sessions. The format owns the client protocol: the
//! grammar of its paths, names, references and digests, what a manifest
//! names, its error answers and the URLs of an upstream registry. The host
//! owns the store, the registry's authentication (its token service) and
//! authorization, groups, proxies' caching and retention.
//!
//! A request reaches an images format in three steps:
//!
//! 1. [`FormatPlugin::image_path`] splits the request's path below the
//!    format's mount into the name the client wrote and the endpoint, and
//!    says what the request needs ([`Permission`]).
//! 2. The host resolves the name to a repository and an image (by path:
//!    `<repository>/<image>`; on a repository's own host: the whole name),
//!    authorizes the request, picks where a change lands (a group's writable
//!    member) and refuses what it must, as an [`ImageError`] the format
//!    renders ([`FormatPlugin::image_error`]).
//! 3. [`FormatPlugin::handle`] gets the request with the endpoint as its
//!    path and the resolved [`ImageName`] as [`Request::image`], and answers
//!    as for any format: a response, queries to load ([`ImageQuery`]), or an
//!    action ([`Action::ServeBlob`], [`Action::ServeManifest`]).
//!
//! Every answer to an image query is a result: a query that failed comes
//! back to [`FormatPlugin::render`] as its [`ImageError`], for the format to
//! answer in its protocol's words.
//!
//! Digests cross the contract in their canonical text form,
//! `sha256:<64 lowercase hex>` or `sha512:<128 lowercase hex>`, as the
//! format validated them; the host verifies content against them and
//! refuses any other form a format names.
//!
//! [`FormatPlugin::image_path`]: crate::FormatPlugin::image_path
//! [`FormatPlugin::image_error`]: crate::FormatPlugin::image_error
//! [`FormatPlugin::handle`]: crate::FormatPlugin::handle
//! [`FormatPlugin::render`]: crate::FormatPlugin::render
//! [`Request::image`]: crate::Request::image
//! [`Action::ServeBlob`]: crate::Action::ServeBlob
//! [`Action::ServeManifest`]: crate::Action::ServeManifest

/// What a request to an images format needs of the caller
/// ([`ImagePath::permission`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read the image: pull manifests, blobs, tags and referrers.
    Read,
    /// Change the image: push blobs and manifests, and every request of an
    /// upload session.
    Write,
    /// Delete from the image.
    Delete,
}

/// A request path an images format split ([`FormatPlugin::image_path`]).
///
/// [`FormatPlugin::image_path`]: crate::FormatPlugin::image_path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePath {
    /// The name the client wrote (`docker-hosted/team/app`, or `team/app`
    /// on a repository's own host), in the format's name grammar.
    pub name: String,
    /// The rest of the path (`/manifests/latest`): the endpoint, which
    /// [`FormatPlugin::handle`] gets as the request's path.
    ///
    /// [`FormatPlugin::handle`]: crate::FormatPlugin::handle
    pub endpoint: String,
    /// What the request needs.
    pub permission: Permission,
}

/// The image a request to an images format is for ([`Request::image`]):
/// the name the format split off its path, as the host resolved it.
///
/// [`Request::image`]: crate::Request::image
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageName {
    /// The image within the repository (`team/app`): what queries name.
    pub image: String,
    /// The name as the client wrote it (`docker-hosted/team/app`): what
    /// the format's `Location` headers name.
    pub name: String,
}

/// A manifest's reference: a tag or a digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Reference {
    Tag(String),
    Digest(String),
}

impl Reference {
    /// The tag or the digest.
    pub fn as_str(&self) -> &str {
        match self {
            Reference::Tag(tag) => tag,
            Reference::Digest(digest) => digest,
        }
    }
}

/// The inclusive byte range of an upload chunk (`Content-Range`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRange {
    pub start: u64,
    /// Inclusive.
    pub end: u64,
}

/// Where a blob may be mounted from instead of uploaded
/// ([`ImageQuery::StartUpload`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// The digest of the blob.
    pub digest: String,
    /// The name, as the client wrote it, of the image to mount it from; the
    /// host resolves it as a request's name and mounts only from an image
    /// the caller may read. `None`: the image itself (a client confirming
    /// it holds the blob).
    pub from: Option<String>,
}

/// What an images format asks of the host's image store. Each names the
/// image of the request ([`ImageName::image`]); the upload queries name the
/// upload session by the id the host gave it.
///
/// Reads run against the repository the request addressed: a group answers
/// from its members by priority (only those the caller may read; the
/// dependency-confusion guards apply), a proxy from its cache and its
/// upstream. Changes (the upload queries, [`ImageQuery::PutManifest`] and
/// the deletes) run against where the host lands them, the repository
/// itself or a group's writable member; each is asked alone in its round,
/// at most once per request for those reading the request's body
/// ([`ImageQuery::AppendUpload`], [`ImageQuery::FinishUpload`],
/// [`ImageQuery::PutManifest`]), and only by
/// a request authorized for [`Permission::Write`] (the deletes:
/// [`Permission::Delete`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageQuery {
    /// A manifest of the image ([`ImageAnswer::Manifest`]).
    Manifest { image: String, reference: Reference },
    /// A blob of the image ([`ImageAnswer::Blob`]). A manifest is content
    /// too: one the image holds answers when no blob of its digest does.
    Blob { image: String, digest: String },
    /// Up to `n` of the image's tags after `last`, in byte order
    /// ([`ImageAnswer::Tags`]).
    Tags {
        image: String,
        last: Option<String>,
        n: u32,
    },
    /// The manifests whose subject is `digest`, those of `artifact_type`
    /// only when one is given ([`ImageAnswer::Referrers`]).
    Referrers {
        image: String,
        digest: String,
        artifact_type: Option<String>,
    },
    /// Start an upload session, or mount a blob without one when it can be
    /// ([`ImageAnswer::Started`]).
    StartUpload { image: String, mount: Option<Mount> },
    /// How far an upload session got ([`ImageAnswer::Upload`]).
    UploadStatus(String),
    /// Append the request body to an upload session, at `range` when the
    /// client gave one ([`ImageAnswer::Upload`]).
    AppendUpload {
        id: String,
        range: Option<ChunkRange>,
    },
    /// Append the request body (it may be empty), then end the session and
    /// link its content into the image as `digest`, which it must match
    /// ([`ImageAnswer::Blob`]).
    FinishUpload {
        id: String,
        digest: String,
        range: Option<ChunkRange>,
    },
    /// End an upload session without a blob ([`ImageAnswer::Done`]).
    CancelUpload(String),
    /// Store the request body as a manifest of the image, under `reference`
    /// and `tags` ([`ImageAnswer::Stored`]). The host stages it (at most
    /// [`MAX_MANIFEST_BYTES`]), reads it with
    /// [`FormatPlugin::parse_manifest`], checks that what it names is in
    /// the image and that it matches a digest reference, and points the
    /// tags at it as the repository's tag immutability allows.
    ///
    /// [`FormatPlugin::parse_manifest`]: crate::FormatPlugin::parse_manifest
    PutManifest {
        image: String,
        reference: Reference,
        tags: Vec<String>,
    },
    /// Delete a tag, or a manifest by digest ([`ImageAnswer::Done`]).
    DeleteManifest { image: String, reference: Reference },
    /// Unlink a blob no manifest of the image names ([`ImageAnswer::Done`]).
    DeleteBlob { image: String, digest: String },
}

impl ImageQuery {
    /// Whether the query changes the repository (it is asked alone in its
    /// round).
    pub fn is_change(&self) -> bool {
        !matches!(
            self,
            ImageQuery::Manifest { .. }
                | ImageQuery::Blob { .. }
                | ImageQuery::Tags { .. }
                | ImageQuery::Referrers { .. }
        )
    }

    /// The image the query names, if it names one.
    pub fn image(&self) -> Option<&str> {
        match self {
            ImageQuery::Manifest { image, .. }
            | ImageQuery::Blob { image, .. }
            | ImageQuery::Tags { image, .. }
            | ImageQuery::Referrers { image, .. }
            | ImageQuery::StartUpload { image, .. }
            | ImageQuery::PutManifest { image, .. }
            | ImageQuery::DeleteManifest { image, .. }
            | ImageQuery::DeleteBlob { image, .. } => Some(image),
            ImageQuery::UploadStatus(_)
            | ImageQuery::AppendUpload { .. }
            | ImageQuery::FinishUpload { .. }
            | ImageQuery::CancelUpload(_) => None,
        }
    }
}

/// The largest manifest the host stores or proxies: the spec asks
/// registries to accept at least 4 MiB.
pub const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// The largest blob the host lends to
/// [`FormatPlugin::artifact_files`](crate::FormatPlugin::artifact_files),
/// as stored.
pub const MAX_FILES_BYTES: u64 = 16 * 1024 * 1024;

/// A stored manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestInfo {
    pub digest: String,
    pub media_type: String,
    pub size: u64,
    /// What [`ParsedManifest::artifact_type`] said.
    pub artifact_type: Option<String>,
    /// The digest of the manifest it refers to.
    pub subject: Option<String>,
    /// What [`ParsedManifest::summary`] said, completed with the config's
    /// part ([`FormatPlugin::config_summary`]) once the host held the config.
    ///
    /// [`FormatPlugin::config_summary`]: crate::FormatPlugin::config_summary
    pub summary: Option<String>,
}

/// A stored blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobInfo {
    pub digest: String,
    pub size: u64,
}

/// A page of an image's tags.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TagPage {
    /// In byte order.
    pub tags: Vec<String>,
    /// There are tags after these the page leaves out.
    pub more: bool,
}

/// A page of an upstream registry's catalog ([`crate::UpstreamOp::ImageCatalog`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogPage {
    /// Image names, in byte order.
    pub images: Vec<String>,
    /// There are images after these the page leaves out.
    pub more: bool,
}

/// An upload session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadState {
    /// Its id, for the session's URL.
    pub id: String,
    /// The bytes received so far.
    pub size: u64,
}

/// What [`ImageQuery::StartUpload`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Started {
    /// A session to upload the blob in.
    Session(UploadState),
    /// The blob is in the image, mounted without an upload.
    Mounted(BlobInfo),
}

/// A manifest [`ImageQuery::PutManifest`] stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredManifest {
    pub digest: String,
    /// The digest of the manifest it refers to.
    pub subject: Option<String>,
}

/// The answer to an [`ImageQuery`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageAnswer {
    Manifest(Result<Option<ManifestInfo>, ImageError>),
    /// The answer to [`ImageQuery::Blob`] and [`ImageQuery::FinishUpload`]
    /// (always `Some` once finished).
    Blob(Result<Option<BlobInfo>, ImageError>),
    /// `None`: the repository does not know the image.
    Tags(Result<Option<TagPage>, ImageError>),
    Referrers(Result<Vec<ManifestInfo>, ImageError>),
    Started(Result<Started, ImageError>),
    /// The answer to [`ImageQuery::UploadStatus`] and
    /// [`ImageQuery::AppendUpload`].
    Upload(Result<UploadState, ImageError>),
    Stored(Result<StoredManifest, ImageError>),
    /// The answer to [`ImageQuery::CancelUpload`] and the deletes.
    Done(Result<(), ImageError>),
}

/// Why the host refused a request to an images format, or a query failed:
/// what the format answers in its own words
/// ([`FormatPlugin::image_error`]). The text some carry is the host's,
/// for the client.
///
/// [`FormatPlugin::image_error`]: crate::FormatPlugin::image_error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageError {
    // ── The request ────────────────────────────────────────────────────────
    /// The path names no endpoint.
    NotAnEndpoint,
    /// The name is not one the host can resolve (`hint`: how to name one).
    NameInvalid { name: String, hint: Option<String> },
    /// No repository goes by the name (said only to a global admin).
    NameUnknown { name: String },
    /// Credentials are needed, or a registry token with the scope `name`
    /// and `permission` (401). The host adds its challenge.
    AuthenticationRequired { scope: Option<(String, Permission)> },
    /// The registry token presented is not valid (401).
    InvalidToken,
    /// The credentials presented are not valid (401).
    InvalidCredentials,
    /// The caller may not do this with `name` (403).
    Denied {
        name: String,
        permission: Permission,
    },
    /// What the host does not do: the catalog API, a token request it will
    /// not answer, a push to a repository that takes none.
    Unsupported { status: u16, message: String },
    /// The repository is offline.
    Offline,

    // ── The store ──────────────────────────────────────────────────────────
    /// The image has no blob of the digest.
    BlobUnknown { digest: String },
    /// The image has no such manifest or tag.
    ManifestUnknown { reference: String },
    /// The image has no such upload session.
    UploadUnknown,
    /// The content does not match its digest.
    DigestMismatch,
    /// A chunk does not continue the upload: it starts elsewhere (or
    /// another chunk landed first). `size`: the bytes received so far.
    ChunkOutOfOrder { size: u64 },
    /// A chunk is not as long as its range says. `size`: the bytes received
    /// so far.
    ChunkLength { size: u64 },
    /// The content is larger than the host takes.
    TooLarge { limit: u64 },
    /// The request body could not be read (the client aborted, or stalled).
    BodyUnreadable,
    /// [`FormatPlugin::parse_manifest`] refused the manifest: its text.
    ///
    /// [`FormatPlugin::parse_manifest`]: crate::FormatPlugin::parse_manifest
    ManifestInvalid(String),
    /// A manifest names a blob (or, `manifest`, a child manifest) the image
    /// does not hold.
    ManifestBlobUnknown { digest: String, manifest: bool },
    /// The tag exists and the repository's tags are immutable.
    TagImmutable { tag: String },
    /// A manifest of the image names the blob.
    BlobReferenced { digest: String },
    /// The workload identity behind the request may no longer change the
    /// repository.
    NoLongerAllowed,
    /// A proxy's upstream rate-limits it.
    RateLimited,
    /// The host cannot answer now (storage, an upstream, the staging area):
    /// what to tell the client. Worth a retry.
    Unavailable(String),
    /// The host failed; the details are in its log.
    Internal,
}

/// What a manifest names and says ([`FormatPlugin::parse_manifest`]).
///
/// [`FormatPlugin::parse_manifest`]: crate::FormatPlugin::parse_manifest
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedManifest {
    /// Its media type: what it is served as.
    pub media_type: String,
    /// The blobs it names (an image's config and layers), each once.
    pub blobs: Vec<ManifestBlob>,
    /// The digests of the manifests it names (an index's children), each
    /// once. A push needs them in the image.
    pub manifests: Vec<String>,
    /// The digest of the manifest it refers to (a signature's, an SBOM's).
    pub subject: Option<String>,
    /// What the referrers API reports it as.
    pub artifact_type: Option<String>,
    /// The blob whose content completes the summary (an image's config, for
    /// its platform; a chart's, for its metadata), when it is small enough
    /// to read: the host reads it once the image holds it and merges what
    /// [`FormatPlugin::config_summary`] makes of it into the summary.
    ///
    /// [`FormatPlugin::config_summary`]: crate::FormatPlugin::config_summary
    pub config: Option<ConfigBlob>,
    /// The blob holding the files the web UI shows of the artifact (a Helm
    /// chart's archive), whatever its size: the host lends it to
    /// [`FormatPlugin::artifact_files`] when it holds it and it is at most
    /// [`MAX_FILES_BYTES`]. A manifest that names one is a chart to the web
    /// UI, whose metadata is the summary's `chart` object.
    ///
    /// [`FormatPlugin::artifact_files`]: crate::FormatPlugin::artifact_files
    pub files: Option<BlobInfo>,
    /// A JSON object for display (platforms, sizes, annotations), stored
    /// with the manifest and handed back with it ([`ManifestInfo::summary`]).
    /// When it names a [`Self::config`], it names its digest under
    /// `config_digest`: a proxy completes the summaries naming a config it
    /// fetches later.
    pub summary: String,
}

/// A blob a manifest names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBlob {
    pub digest: String,
    pub size: u64,
    /// Whether a push needs it in the image: `false` for content that lives
    /// elsewhere by definition (a non-distributable layer).
    pub required: bool,
    /// Its content, when the format knows it (the OCI empty JSON, `{}`):
    /// the host links it into the image itself when a push names it.
    pub known: Option<Vec<u8>>,
}

/// The blob that completes a manifest's summary ([`ParsedManifest::config`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigBlob {
    pub digest: String,
    pub media_type: String,
    pub size: u64,
}

/// A text file of an artifact the web UI shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextFile {
    /// Its name in the artifact (`README.md`, `values.yaml`).
    pub name: String,
    /// Its text (invalid UTF-8 replaced), cut where the format bounds it.
    pub text: String,
    /// Whether the text was cut.
    pub truncated: bool,
}

/// What [`FormatPlugin::artifact_files`] read from an artifact.
///
/// [`FormatPlugin::artifact_files`]: crate::FormatPlugin::artifact_files
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArtifactFiles {
    /// Its README.
    pub readme: Option<TextFile>,
    /// Its default values (a Helm chart's `values.yaml`).
    pub values: Option<TextFile>,
}

/// An upstream registry request an images format names
/// ([`UpstreamAnswer::ImageUrl`]): a manifest's or a blob's.
///
/// [`UpstreamAnswer::ImageUrl`]: crate::UpstreamAnswer::ImageUrl
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageUrl {
    /// On the origin of the remote's URL.
    pub url: String,
    /// The `Accept` header to send (a manifest's media types).
    pub accept: Option<String>,
    /// The scope of the token to ask the upstream's token service for when
    /// it answers 401 with a Bearer challenge that names none.
    pub scope: Option<String>,
}
