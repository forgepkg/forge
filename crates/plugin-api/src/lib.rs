//! `forge-plugin-api`: the contract of a Forge format plugin.
//!
//! A format plugin teaches Forge one more package format: its identity rules
//! (ids, versions), how to read a package, and its client protocol. Forge
//! keeps everything else — storage, metadata, authentication and
//! authorization, hosted/group semantics, retention, the streaming of
//! package bytes — so a plugin is small and never sees a credential, a
//! storage key, or a whole package in memory.
//!
//! A format stores package versions, files under paths (raw), or images
//! (Docker / OCI): its [`Descriptor`] says which (`storage`). A files format
//! has no identity rules and no packages to read: it keeps the defaults of
//! those methods and implements the protocol over the host's file store
//! ([`Query::File`] … [`Query::Remove`], [`Action::ServeFile`]). An images
//! format implements it over the host's image store ([`images`]): it splits
//! request paths ([`FormatPlugin::image_path`]), reads manifests
//! ([`FormatPlugin::parse_manifest`]) and answers in its own words what the
//! host refused ([`FormatPlugin::image_error`]).
//!
//! A plugin is a crate under `crates/formats/<id>/` implementing
//! [`FormatPlugin`], describing itself with a [`Descriptor`], linked into
//! the server and called directly (NuGet, raw).

pub mod files;
pub mod images;
mod types;

#[cfg(feature = "testing")]
pub mod testing;

use std::cmp::Ordering;
use std::io::{Read, Seek};
use std::path::Path;

pub use types::*;

use images::{ArtifactFiles, ImageError, ImagePath, ParsedManifest};

/// A package the host staged, lent to [`FormatPlugin::parse_package`].
pub trait PackageSource: Read + Seek {}

impl<T: Read + Seek + ?Sized> PackageSource for T {}

/// A package format, as Forge calls it.
///
/// Every method is synchronous and may be called from any thread, in any
/// order, any number of times. The host runs the protocol methods
/// ([`Self::handle`], [`Self::render`]) and parsing off its async workers, so
/// they may take as long as they need; the rules ([`Self::canonical_id`]
/// through [`Self::compare_versions`], [`Self::manifest_summary`]) run inline
/// and must be quick.
///
/// A package format implements the rules and [`Self::parse_package`]. A
/// files format has neither ids nor versions nor packages: it keeps their
/// defaults, which refuse every id, version and package.
pub trait FormatPlugin: Send + Sync + 'static {
    /// What the format says about itself: its id, name, version, mount,
    /// repository kinds, storage and asset names. A `'static` value the
    /// crate defines next to its implementation (`pub const DESCRIPTOR`).
    fn descriptor(&self) -> &'static Descriptor;

    /// The canonical form of a package id, used for lookups and uniqueness
    /// (e.g. lowercased). The default keeps the id as it is.
    fn canonical_id(&self, id: &str) -> String {
        id.to_string()
    }

    /// Whether `id` (canonical) is a well-formed id. The host treats a query
    /// or an action naming any other id like one naming an unknown package
    /// (an empty answer, a 404). The default accepts none.
    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        Err(FormatError::InvalidId(format!(
            "{id:?}: this format has no packages"
        )))
    }

    /// The normalized form of a version, used for lookups and uniqueness.
    /// Prerelease versions must contain a `-` (the host filters on it). The
    /// default accepts none.
    fn normalize_version(&self, version: &str) -> Result<String, FormatError> {
        Err(FormatError::InvalidVersion(format!(
            "{version:?}: this format has no versions"
        )))
    }

    /// The order of two normalized versions. The default is byte order.
    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        a.cmp(b)
    }

    /// Read a package's identity, manifest and dependencies. `package` is
    /// positioned at its start. The default reads none.
    fn parse_package(&self, package: &mut dyn PackageSource) -> Result<ParsedPackage, FormatError> {
        let _ = package;
        Err(FormatError::InvalidPackage(
            "this format stores files, not packages".into(),
        ))
    }

    /// [`Self::parse_package`] of a package the host staged at `path`.
    fn parse_package_file(&self, path: &Path) -> Result<ParsedPackage, FormatError> {
        let mut file = std::fs::File::open(path)
            .map_err(|e| FormatError::Internal(format!("open the staged package: {e}")))?;
        self.parse_package(&mut file)
    }

    /// A JSON object summarizing `manifest`, stored with the version so that
    /// rendering never re-reads the manifest ([`PackageInfo::summary`]).
    /// `None` when there is nothing worth keeping. Every listing hands each
    /// version's summary back, so keep it small. The default keeps none.
    fn manifest_summary(&self, manifest: &[u8]) -> Option<String> {
        let _ = manifest;
        None
    }

    /// What a request is: a response right away, data to load first (then
    /// [`Self::render`]), or an action only the host can perform.
    ///
    /// The host has authenticated the caller and checked that it may perform
    /// the request's action on the repository (GET/HEAD read, PUT/POST
    /// write, DELETE delete) before it asks.
    fn handle(&self, repo: &Repository, req: &Request) -> Action;

    /// What to do once the data [`Self::handle`] (and earlier rounds of
    /// `render`) asked for is loaded: `data` holds every query so far with
    /// its answer. Anything `handle` may answer: a response, more data to
    /// load, or an action of the host's.
    fn render(&self, repo: &Repository, req: &Request, data: &[Loaded]) -> Action;

    /// The upstream side of the format's proxy repositories: what to fetch
    /// from `remote` for `op`, and what came of it. `fetched` holds every
    /// fetch of earlier rounds with its result, so a plugin stays stateless.
    ///
    /// The host does the rest of what a proxy is: it sends every request
    /// (only to origins the upstream points at, see [`Fetch`]; credentials
    /// only to the upstream's own origin; bounded in size and time, cached
    /// as [`Fetch::freshness`] says), downloads and verifies packages, and
    /// keeps the package delay, the not-found markers and the offline mode.
    /// Only a plugin whose descriptor lists the `proxy` kind is asked;
    /// the default says so.
    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        let _ = (remote, op, fetched);
        Err(FormatError::Internal(
            "this format has no proxy repositories".into(),
        ))
    }

    /// Images formats: split the path of a request below the format's mount
    /// (`/docker-hosted/team/app/manifests/latest`) into the name the
    /// client wrote and the endpoint, with what the request needs. The host
    /// resolves the name and authorizes the request with it before
    /// [`Self::handle`]; an error is answered with [`Self::image_error`].
    /// The default knows no endpoint.
    fn image_path(&self, method: &str, path: &str) -> Result<ImagePath, ImageError> {
        let _ = (method, path);
        Err(ImageError::NotAnEndpoint)
    }

    /// Images formats: the response to a request the host refused, or to
    /// what failed while it served it outside a query ([`ImageError`]).
    /// The host adds its own headers (a Bearer challenge). The default is
    /// a plain-text error.
    fn image_error(&self, error: &ImageError) -> Response {
        Response::text(500, &format!("{error:?}"))
    }

    /// Images formats: what a manifest names and says. `content_type` is
    /// the one it was pushed or fetched with, if any. The host stages a
    /// pushed manifest (at most [`images::MAX_MANIFEST_BYTES`]) and checks
    /// what it names before it commits it; a proxy's manifests are read the
    /// same way. The default reads none.
    fn parse_manifest(
        &self,
        manifest: &[u8],
        content_type: Option<&str>,
    ) -> Result<ParsedManifest, FormatError> {
        let _ = (manifest, content_type);
        Err(FormatError::MalformedManifest(
            "this format stores no images".into(),
        ))
    }

    /// Images formats: the part of a manifest's summary its config blob
    /// ([`ParsedManifest::config`], of `media_type`) holds, as a JSON object
    /// the host merges into the summary (an image's platform, a chart's
    /// metadata). The default has none.
    fn config_summary(&self, media_type: &str, config: &[u8]) -> Option<String> {
        let _ = (media_type, config);
        None
    }

    /// Images formats: the files the web UI shows of an artifact, read
    /// from the blob [`ParsedManifest::files`] names, which the host lends
    /// positioned at its start. The default reads none.
    fn artifact_files(&self, blob: &mut dyn PackageSource) -> ArtifactFiles {
        let _ = blob;
        ArtifactFiles::default()
    }
}
