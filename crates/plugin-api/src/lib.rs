//! `forge-plugin-api`: the contract of a Forge format plugin.
//!
//! A format plugin teaches Forge one more package format: its identity rules
//! (ids, versions), how to read a package, and its client protocol. Forge
//! keeps everything else — storage, metadata, authentication and
//! authorization, hosted/group semantics, retention, the streaming of
//! package bytes — so a plugin is small and never sees a credential, a
//! storage key, or a whole package in memory.
//!
//! A format stores package versions, or files under paths (raw): its
//! `plugin.toml` says which (`storage`). A files format has no identity
//! rules and no packages to read: it keeps the defaults of those methods and
//! implements the protocol over the host's file store ([`Query::File`] …
//! [`Query::Remove`], [`Action::ServeFile`]).
//!
//! A plugin is a crate under `crates/formats/<id>/` implementing
//! [`FormatPlugin`], with a `plugin.toml` naming it, linked into the server
//! and called directly (NuGet, raw).

pub mod files;
mod types;

#[cfg(feature = "testing")]
pub mod testing;

use std::cmp::Ordering;
use std::io::{Read, Seek};
use std::path::Path;

pub use types::*;

/// The `forge:format` contract version this crate implements: what a plugin
/// built against it declares as `api` in its `plugin.toml`.
pub const API: &str = "0.4.0";

/// The `plugin.toml` of the crate this is expanded in: how a built-in plugin
/// hands the server its id and name (`pub const PLUGIN_TOML: &str =
/// forge_plugin_api::plugin_toml!();`).
#[macro_export]
macro_rules! plugin_toml {
    () => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.toml"))
    };
}

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
    /// Only a plugin whose `plugin.toml` lists the `proxy` kind is asked;
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
}
