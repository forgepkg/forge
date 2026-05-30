//! NuGet-specific limits and error types used while parsing `.nupkg` archives.

use forge_core::domain::FormatError;
use thiserror::Error;

/// Zip-bomb / resource-exhaustion defenses applied while reading a `.nupkg`.
///
/// A `.nupkg` is an OPC (Open Packaging Conventions) zip. We only ever read a
/// single small XML manifest out of it, so these caps are generous for real
/// packages yet reject pathological archives.
#[derive(Debug, Clone, Copy)]
pub struct NupkgLimits {
    /// Maximum number of entries in the archive.
    pub max_entries: usize,
    /// Maximum uncompressed size of any single entry we decompress.
    pub max_entry_uncompressed: u64,
    /// Maximum total uncompressed size across all entries we decompress.
    pub max_total_uncompressed: u64,
    /// Maximum allowed compression ratio (uncompressed / compressed) for any
    /// single entry we decompress. Guards against highly compressible bombs.
    pub max_compression_ratio: u64,
    /// Maximum size of the `.nuspec` manifest we will read into memory.
    pub max_nuspec_bytes: u64,
}

impl Default for NupkgLimits {
    fn default() -> Self {
        NupkgLimits {
            max_entries: 10_000,
            max_entry_uncompressed: 64 * 1024 * 1024, // 64 MiB
            max_total_uncompressed: 512 * 1024 * 1024, // 512 MiB
            max_compression_ratio: 200,
            max_nuspec_bytes: 16 * 1024 * 1024, // 16 MiB
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
