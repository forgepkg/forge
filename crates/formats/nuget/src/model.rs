//! NuGet's limits, errors and parsed-package types.
//!
//! They mirror the format-neutral types Forge stores, and convert into the
//! plugin contract's at the [`forge_plugin_api::FormatPlugin`] boundary.

use thiserror::Error;

/// What a `.nupkg` declares about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedNupkg {
    /// The lowercased id.
    pub id: String,
    /// The id exactly as the `.nuspec` writes it.
    pub original_id: String,
    /// The normalized version.
    pub version: String,
    /// The version exactly as the `.nuspec` writes it.
    pub version_original: String,
    /// Whether the version is listed.
    pub listed: bool,
    /// The raw `.nuspec` bytes.
    pub nuspec_bytes: Vec<u8>,
    /// The dependency groups.
    pub deps: Vec<DependencyGroup>,
}

/// The dependencies of one target framework (`None`: any framework). Its
/// JSON shape is the one Forge stores in manifest summaries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DependencyGroup {
    /// The target framework moniker, or `None` for the framework-agnostic group.
    pub target_framework: Option<String>,
    /// Dependencies in this group.
    pub dependencies: Vec<Dependency>,
}

/// A single dependency on another package.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Dependency {
    /// The dependency's package id.
    pub id: String,
    /// The version range, verbatim; `None` when the `.nuspec` gives none.
    pub range: Option<String>,
}

/// Why a package, a manifest, an id or a version was refused.
#[derive(Debug, Error)]
pub enum FormatError {
    /// The bytes are not a valid package.
    #[error("invalid package: {0}")]
    InvalidPackage(String),
    /// A required manifest entry (the `.nuspec`) was missing.
    #[error("missing manifest: {0}")]
    MissingManifest(String),
    /// The manifest was present but could not be parsed.
    #[error("malformed manifest: {0}")]
    MalformedManifest(String),
    /// A version string could not be normalized.
    #[error("invalid version {value:?}: {reason}")]
    InvalidVersion {
        /// The offending raw version string.
        value: String,
        /// Human-readable explanation.
        reason: String,
    },
    /// Underlying I/O failure while reading the package.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<FormatError> for forge_plugin_api::FormatError {
    fn from(e: FormatError) -> Self {
        use forge_plugin_api::FormatError as E;
        match e {
            FormatError::InvalidPackage(m) => E::InvalidPackage(m),
            FormatError::MissingManifest(m) => E::MissingManifest(m),
            FormatError::MalformedManifest(m) => E::MalformedManifest(m),
            FormatError::InvalidVersion { value, reason } => {
                E::InvalidVersion(format!("{value:?}: {reason}"))
            }
            FormatError::Io(e) => E::Internal(format!("io error: {e}")),
        }
    }
}

impl From<DependencyGroup> for forge_plugin_api::DependencyGroup {
    fn from(g: DependencyGroup) -> Self {
        forge_plugin_api::DependencyGroup {
            target: g.target_framework,
            dependencies: g
                .dependencies
                .into_iter()
                .map(|d| forge_plugin_api::Dependency {
                    id: d.id,
                    range: d.range,
                })
                .collect(),
        }
    }
}

impl From<ParsedNupkg> for forge_plugin_api::ParsedPackage {
    fn from(p: ParsedNupkg) -> Self {
        forge_plugin_api::ParsedPackage {
            id: p.id,
            original_id: p.original_id,
            version: p.version,
            version_original: p.version_original,
            listed: p.listed,
            manifest: p.nuspec_bytes,
            dependencies: p.deps.into_iter().map(Into::into).collect(),
        }
    }
}

/// Zip-bomb / resource-exhaustion defenses applied while reading a `.nupkg`.
///
/// A `.nupkg` is an OPC (Open Packaging Conventions) zip. Forge only ever
/// decompresses the single `.nuspec` manifest out of it; every other entry is
/// stored and served as opaque archive bytes, so its size or compression ratio
/// cannot exhaust Forge's memory or disk. The caps therefore split into:
///
/// * **archive shape** — the entry count and the central-directory size, read
///   from the end-of-central-directory records *before* the central directory
///   is read, plus a sanity bound on the total declared uncompressed size
///   (large native packages — CUDA, libtorch, … — routinely hold single
///   entries of hundreds of MiB and must pass). The directory is read one
///   header at a time and nothing is kept per entry, so these bound the time
///   reading it takes, not memory: packages that bundle web assets hold tens
///   of thousands of files;
/// * **manifest** — size and compression ratio of the `.nuspec`, the only
///   entry that is ever decompressed.
///
/// Configurable through the server's `[nuget]` section; [`Default`] carries
/// the documented defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NupkgLimits {
    /// Maximum number of entries in the archive.
    pub max_entries: usize,
    /// Maximum size of the zip central directory (the per-entry metadata,
    /// read once to check every entry and find the manifest), as declared by
    /// the end-of-central-directory record.
    pub max_central_directory_bytes: u64,
    /// Maximum total declared uncompressed size across all entries. Nothing
    /// but the `.nuspec` is decompressed, so this only rejects absurd archives.
    pub max_total_uncompressed: u64,
    /// Maximum size of the `.nuspec` manifest, the only entry read into memory
    /// (also the bound on an upstream `.nuspec` a proxy verifies).
    pub max_nuspec_bytes: u64,
    /// Maximum compression ratio (uncompressed / compressed) of the `.nuspec`
    /// entry. Guards against a highly compressible manifest bomb.
    pub max_nuspec_compression_ratio: u64,
}

impl Default for NupkgLimits {
    fn default() -> Self {
        NupkgLimits {
            max_entries: 1_000_000,
            max_central_directory_bytes: 256 * 1024 * 1024, // 256 MiB
            max_total_uncompressed: 16 * 1024 * 1024 * 1024, // 16 GiB
            max_nuspec_bytes: 1024 * 1024,                  // 1 MiB
            max_nuspec_compression_ratio: 200,
        }
    }
}

/// Errors specific to reading a `.nupkg` archive. These convert into the
/// format-neutral [`FormatError`] consumed by the rest of the system.
#[derive(Debug, Error)]
pub enum NupkgError {
    /// The bytes are not a valid zip archive.
    #[error("not a valid zip archive: {0}")]
    InvalidZip(String),
    /// An archive resource limit was exceeded (possible zip bomb).
    #[error("archive exceeds safety limits: {0}")]
    LimitExceeded(String),
    /// An entry uses encryption or an unsupported compression method.
    #[error("unsupported zip entry: {0}")]
    UnsupportedEntry(String),
    /// No `*.nuspec` manifest was found in the archive.
    #[error("no .nuspec manifest found in package")]
    MissingNuspec,
    /// The `.nuspec` manifest could not be parsed.
    #[error("malformed .nuspec: {0}")]
    MalformedNuspec(String),
    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<NupkgError> for FormatError {
    fn from(e: NupkgError) -> Self {
        match e {
            NupkgError::InvalidZip(m) => FormatError::InvalidPackage(m),
            NupkgError::LimitExceeded(m) => FormatError::InvalidPackage(format!("limit: {m}")),
            NupkgError::UnsupportedEntry(m) => {
                FormatError::InvalidPackage(format!("unsupported entry: {m}"))
            }
            NupkgError::MissingNuspec => {
                FormatError::MissingManifest(".nuspec not found in package".into())
            }
            NupkgError::MalformedNuspec(m) => FormatError::MalformedManifest(m),
            NupkgError::Io(e) => FormatError::Io(e),
        }
    }
}
