//! `forge-plugin-api`: the contract of a Forge format plugin.
//!
//! A format plugin teaches Forge one more package format: its identity rules
//! (ids, versions), how to read a package, and its client protocol. Forge
//! keeps everything else — storage, metadata, authentication and
//! authorization, hosted/group semantics, retention, the streaming of
//! package bytes — so a plugin is small and never sees a credential, a
//! storage key, or a whole package in memory.
//!
//! A plugin is a crate under `plugins/<id>/` implementing [`FormatPlugin`],
//! with a `plugin.toml` naming it. The same crate runs either way:
//!
//! * **built in** — linked into the server and called directly (Helm);
//! * **as a WebAssembly component** — built for `wasm32-wasip2` with this
//!   crate's `component` feature and `export_component!`, then loaded at
//!   startup into a sandbox, from a digest the operator pinned.
//!
//! The trait and its types mirror the `forge:format` WIT package
//! (`wit/format.wit`) one to one: a component exports exactly these
//! functions, and the host adapts a loaded component back into a
//! [`FormatPlugin`], so the server serves both kinds through one code path.

mod types;

#[cfg(feature = "component")]
pub mod component;

use std::cmp::Ordering;
use std::io::{Read, Seek};
use std::path::Path;

pub use types::*;

/// The `forge:format` WIT package version this crate implements: what a
/// plugin built against it declares as `api` in its `plugin.toml`.
pub const API: &str = "0.2.0";

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
pub trait FormatPlugin: Send + Sync + 'static {
    /// The canonical form of a package id, used for lookups and uniqueness
    /// (e.g. lowercased).
    fn canonical_id(&self, id: &str) -> String;

    /// Whether `id` (canonical) is a well-formed id. The host treats a query
    /// or an action naming any other id like one naming an unknown package
    /// (an empty answer, a 404).
    fn validate_id(&self, id: &str) -> Result<(), FormatError>;

    /// The normalized form of a version, used for lookups and uniqueness.
    /// Prerelease versions must contain a `-` (the host filters on it).
    fn normalize_version(&self, version: &str) -> Result<String, FormatError>;

    /// The order of two normalized versions.
    fn compare_versions(&self, a: &str, b: &str) -> Ordering;

    /// Read a package's identity, manifest and dependencies. `package` is
    /// positioned at its start.
    fn parse_package(&self, package: &mut dyn PackageSource) -> Result<ParsedPackage, FormatError>;

    /// [`Self::parse_package`] of a package the host staged at `path`.
    fn parse_package_file(&self, path: &Path) -> Result<ParsedPackage, FormatError> {
        let mut file = std::fs::File::open(path)
            .map_err(|e| FormatError::Internal(format!("open the staged package: {e}")))?;
        self.parse_package(&mut file)
    }

    /// A JSON object summarizing `manifest`, stored with the version so that
    /// rendering never re-reads the manifest ([`PackageInfo::summary`]).
    /// `None` when there is nothing worth keeping.
    fn manifest_summary(&self, manifest: &[u8]) -> Option<String>;

    /// What a request is: a response right away, data to load first (then
    /// [`Self::render`]), or an action only the host can perform.
    ///
    /// The host has authenticated the caller and checked that it may perform
    /// the request's action on the repository (GET/HEAD read, PUT/POST
    /// write, DELETE delete) before it asks.
    fn handle(&self, repo: &Repository, req: &Request) -> Action;

    /// The response to a request, from the data [`Self::handle`] (and earlier
    /// rounds of `render`) asked for — or more data to load.
    fn render(&self, repo: &Repository, req: &Request, data: &[Loaded]) -> Rendered;
}

/// Conversions between the types of this crate and the bindings of
/// `wit/format.wit`, for both sides of the component boundary: the
/// `wit-bindgen` guest bindings (module `component`) and the host's Wasmtime
/// bindings. Both generators name every type, field and case the same, so
/// one definition serves both. Expanded once per bindings module:
/// `forge_plugin_api::__wit_conversions!(crate::bindings);`.
#[doc(hidden)]
#[macro_export]
macro_rules! __wit_conversions {
    ($($root:tt)*) => {
        const _: () = {
            use $crate as api;
            use $crate::__private::{into, opt, vec};
            use $($root)*::forge::format::types as t;
            use $($root)*::exports::forge::format::format as f;
            use $($root)*::exports::forge::format::protocol as p;

            $crate::__record!(t, Dependency { id: into, range: into });
            $crate::__record!(t, DependencyGroup { target: into, dependencies: vec });
            $crate::__variant!(t, FormatError {} {
                InvalidPackage: into,
                MissingManifest: into,
                MalformedManifest: into,
                InvalidVersion: into,
                InvalidId: into,
                Internal: into,
            });
            $crate::__record!(f, ParsedPackage {
                id: into,
                original_id: into,
                version: into,
                version_original: into,
                listed: into,
                manifest: into,
                dependencies: vec,
            });
            $crate::__variant!(p, RepositoryKind { Hosted, Proxy, Group } {});
            $crate::__record!(p, Repository { name: into, kind: into, base_url: into });
            $crate::__record!(p, Request { method: into, path: into, query: into, headers: into });
            $crate::__record!(p, Response { status: into, headers: into, body: into });
            $crate::__record!(p, PackageRef { id: into, version: into });
            $crate::__record!(p, PackageVersions { id: into, versions: into });
            $crate::__record!(p, SearchQuery {
                text: into,
                skip: into,
                take: into,
                prerelease: into,
                semver2: into,
                upstream: into,
            });
            $crate::__variant!(p, Query {} {
                Versions: into,
                Packages: into,
                Package: into,
                PackagesOf: into,
                Manifest: into,
                Search: into,
            });
            $crate::__record!(p, VersionInfo {
                original_id: into,
                version: into,
                version_original: into,
                listed: into,
            });
            $crate::__record!(p, PackageInfo {
                original_id: into,
                version: into,
                version_original: into,
                listed: into,
                published: into,
                sha256: into,
                sha512: into,
                size: into,
                summary: into,
            });
            $crate::__record!(p, SearchHit {
                original_id: into,
                latest_version: into,
                versions: vec,
                summary: into,
                total_downloads: into,
            });
            $crate::__record!(p, SearchResult { total: into, hits: vec });
            $crate::__variant!(p, Answer {} {
                Versions: vec,
                Packages: vec,
                Package: opt,
                Manifest: into,
                Search: into,
            });
            $crate::__record!(p, Loaded { query: into, answer: into });
            $crate::__variant!(p, Upload { Body, FirstPart } { MultipartField: into });
            $crate::__record!(p, PublishRequest { upload: into, done: into });
            $crate::__record!(p, ChangeRequest { target: into, done: into });
            $crate::__variant!(p, Action {} {
                Respond: into,
                Load: vec,
                Download: into,
                Publish: into,
                Unlist: into,
                Relist: into,
                Delete: into,
            });
            $crate::__variant!(p, Rendered {} { Respond: into, Load: vec });
        };
    };
}

/// `From` both ways between `api::$ty` and `$m::$ty`, a record.
#[doc(hidden)]
#[macro_export]
macro_rules! __record {
    ($m:ident, $ty:ident { $($field:ident: $how:ident),* $(,)? }) => {
        impl From<api::$ty> for $m::$ty {
            fn from(x: api::$ty) -> Self {
                $m::$ty { $($field: $how(x.$field)),* }
            }
        }
        impl From<$m::$ty> for api::$ty {
            fn from(x: $m::$ty) -> Self {
                api::$ty { $($field: $how(x.$field)),* }
            }
        }
    };
}

/// `From` both ways between `api::$ty` and `$m::$ty`, a variant: its cases
/// without a payload, then its cases with one.
#[doc(hidden)]
#[macro_export]
macro_rules! __variant {
    ($m:ident, $ty:ident { $($unit:ident),* $(,)? } { $($case:ident: $how:ident),* $(,)? }) => {
        impl From<api::$ty> for $m::$ty {
            fn from(x: api::$ty) -> Self {
                match x {
                    $(api::$ty::$unit => $m::$ty::$unit,)*
                    $(api::$ty::$case(v) => $m::$ty::$case($how(v)),)*
                }
            }
        }
        impl From<$m::$ty> for api::$ty {
            fn from(x: $m::$ty) -> Self {
                match x {
                    $($m::$ty::$unit => api::$ty::$unit,)*
                    $($m::$ty::$case(v) => api::$ty::$case($how(v)),)*
                }
            }
        }
    };
}

#[doc(hidden)]
pub mod __private {
    //! What [`__wit_conversions!`](crate::__wit_conversions) expands to.

    /// A field or payload converted as a whole.
    pub fn into<A, B: From<A>>(a: A) -> B {
        B::from(a)
    }

    /// A list converted element by element.
    pub fn vec<A, B: From<A>>(v: Vec<A>) -> Vec<B> {
        v.into_iter().map(B::from).collect()
    }

    /// An option converted inside.
    pub fn opt<A, B: From<A>>(o: Option<A>) -> Option<B> {
        o.map(B::from)
    }
}
