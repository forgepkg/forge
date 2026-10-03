//! NuGet-specific limits and error types used while parsing `.nupkg` archives.

use forge_core::domain::FormatError;
use thiserror::Error;

/// Zip-bomb / resource-exhaustion defenses applied while reading a `.nupkg`.
///
/// A `.nupkg` is an OPC (Open Packaging Conventions) zip. Forge only ever
/// decompresses the single `.nuspec` manifest out of it; every other entry is
/// stored and served as opaque archive bytes, so its size or compression ratio
/// cannot exhaust Forge's memory or disk. The caps therefore split into:
///
/// * **archive shape** — the entry count and the central-directory size, read
///   from the end-of-central-directory records *before* the zip reader parses
///   the central directory, plus a sanity bound on the total declared
///   uncompressed size (large native packages — CUDA, libtorch, … — routinely
///   hold single entries of hundreds of MiB and must pass);
/// * **manifest** — size and compression ratio of the `.nuspec`, the only
///   entry that is ever decompressed.
///
/// Configurable through the server's `[nuget]` section; [`Default`] carries
/// the documented defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NupkgLimits {
    /// Maximum number of entries in the archive.
    pub max_entries: usize,
    /// Maximum size of the zip central directory (the per-entry metadata the
    /// zip reader loads into memory), as declared by the end-of-central-
    /// directory record.
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
            max_entries: 10_000,
            max_central_directory_bytes: 16 * 1024 * 1024, // 16 MiB
            max_total_uncompressed: 16 * 1024 * 1024 * 1024, // 16 GiB
            max_nuspec_bytes: 1024 * 1024,                 // 1 MiB
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
