//! Format-agnostic domain types produced by parsing an uploaded package.
//!
//! These types are the boundary between a concrete [`crate::format::Format`]
//! implementation (e.g. NuGet, in `forge-format-nuget`) and the rest of the
//! system. A parser turns raw package bytes into a [`ParsedUpload`]; the server
//! and storage layers consume only these neutral types and never the
//! format-specific wire structures.

use std::fmt;

/// The outcome of parsing an uploaded package.
///
/// Identifiers come in two forms: the `*_original` fields preserve the exact
/// casing/spelling from the package, while the non-original fields hold the
/// normalized values used for lookups and uniqueness (e.g. lowercased id,
/// SemVer-normalized version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUpload {
    /// Normalized package id (lowercased for NuGet).
    pub id: String,
    /// Package id exactly as written in the package metadata.
    pub original_id: String,
    /// Normalized version string.
    pub version: String,
    /// Version exactly as written in the package metadata.
    pub version_original: String,
    /// Whether the package should be listed in search/metadata.
    pub listed: bool,
    /// Raw nuspec/manifest bytes, retained for republishing the metadata.
    pub nuspec_bytes: Vec<u8>,
    /// Dependencies, grouped by target framework.
    pub deps: Vec<DependencyGroup>,
}

/// A set of dependencies that apply to a single target framework.
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
    /// Dependency package id (as written; normalization is the consumer's job).
    pub id: String,
    /// Version range expression, or `None` for "any version".
    pub range: Option<String>,
}

/// Errors a [`crate::format::Format`] implementation may raise while parsing or
/// normalizing a package.
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    /// The uploaded bytes are not a valid package of this format.
    #[error("invalid package: {0}")]
    InvalidPackage(String),
    /// A required manifest entry (e.g. the nuspec) was missing.
    #[error("missing manifest: {0}")]
    MissingManifest(String),
    /// The manifest was present but could not be parsed.
    #[error("malformed manifest: {0}")]
    MalformedManifest(String),
    /// A version string could not be normalized.
    #[error("{}", invalid_version(.value, .reason))]
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

/// The text of [`FormatError::InvalidVersion`]: a format plugin's reason
/// names the version itself, so it comes without the value.
fn invalid_version(value: &str, reason: &str) -> String {
    if value.is_empty() {
        format!("invalid version: {reason}")
    } else {
        format!("invalid version {value:?}: {reason}")
    }
}

impl fmt::Display for ParsedUpload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.original_id, self.version_original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsed_upload_display_uses_original_id_and_version() {
        let pu = ParsedUpload {
            id: "newtonsoft.json".into(),
            original_id: "Newtonsoft.Json".into(),
            version: "13.0.3".into(),
            version_original: "13.0.3".into(),
            listed: true,
            nuspec_bytes: Vec::new(),
            deps: Vec::new(),
        };
        assert_eq!(pu.to_string(), "Newtonsoft.Json@13.0.3");
    }

    #[test]
    fn dependency_group_holds_dependencies() {
        let g = DependencyGroup {
            target_framework: Some("net8.0".into()),
            dependencies: vec![Dependency {
                id: "Serilog".into(),
                range: Some("[3.0.0, )".into()),
            }],
        };
        assert_eq!(g.dependencies.len(), 1);
        assert_eq!(g.dependencies[0].id, "Serilog");
        assert_eq!(g.target_framework.as_deref(), Some("net8.0"));
    }

    #[test]
    fn format_error_displays() {
        let e = FormatError::InvalidVersion {
            value: "not-a-version".into(),
            reason: "no numeric components".into(),
        };
        assert!(e.to_string().contains("not-a-version"));
    }
}
