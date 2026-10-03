//! The [`forge_core::format::Format`] implementation for NuGet.

use std::cmp::Ordering;

use forge_core::domain::{DependencyGroup, FormatError, ParsedUpload};
use forge_core::format::{Format, ReadSeek};

use crate::model::NupkgLimits;
use crate::nuspec;
use crate::version;

/// NuGet package format adapter.
///
/// Holds the zip-bomb [`NupkgLimits`] applied while parsing packages (published
/// or proxied) and upstream manifests; use [`NugetFormat::with_limits`] to
/// override the defaults (the server wires its `[nuget]` config section in).
#[derive(Debug, Clone)]
pub struct NugetFormat {
    limits: NupkgLimits,
}

impl NugetFormat {
    /// A NuGet format with default safety limits.
    pub fn new() -> Self {
        NugetFormat {
            limits: NupkgLimits::default(),
        }
    }

    /// A NuGet format with explicit archive limits.
    pub fn with_limits(limits: NupkgLimits) -> Self {
        NugetFormat { limits }
    }
}

impl Default for NugetFormat {
    fn default() -> Self {
        Self::new()
    }
}

impl Format for NugetFormat {
    fn id(&self) -> &'static str {
        "nuget"
    }

    fn parse_upload(&self, file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
        nuspec::parse_nupkg(file, &self.limits)
    }

    fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
        version::normalize(raw)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        version::compare(a, b)
    }

    fn lower_id(&self, id: &str) -> String {
        nuspec::lower_id(id)
    }

    fn manifest_identity(&self, manifest: &[u8]) -> Result<(String, String), FormatError> {
        nuspec::manifest_identity(manifest, &self.limits)
    }

    fn synthesize_manifest(
        &self,
        id: &str,
        version: &str,
        deps: &[DependencyGroup],
    ) -> Option<Vec<u8>> {
        Some(nuspec::synthesize_nuspec(id, version, deps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn is_object_safe_and_delegates() {
        let f: Arc<dyn Format> = Arc::new(NugetFormat::new());
        assert_eq!(f.id(), "nuget");
        assert_eq!(f.lower_id("Newtonsoft.JSON"), "newtonsoft.json");
        assert_eq!(f.normalize_version("1.0").unwrap(), "1.0.0");
        assert_eq!(f.compare_versions("1.0.0", "2.0.0"), Ordering::Less);
        assert_eq!(f.compare_versions("1.0.0-beta", "1.0.0"), Ordering::Less);
        assert_eq!(f.lower_id("Ünicode.Lib"), "ünicode.lib");
    }

    #[test]
    fn manifest_identity_and_synthesis_round_trip() {
        use forge_core::domain::Dependency;

        let f: Arc<dyn Format> = Arc::new(NugetFormat::new());
        let deps = vec![DependencyGroup {
            target_framework: Some("net8.0".into()),
            dependencies: vec![Dependency {
                id: "Newtonsoft.Json".into(),
                range: Some("[13.0.1, )".into()),
            }],
        }];
        let manifest = f
            .synthesize_manifest("Contoso.Lib", "1.0.0-Beta", &deps)
            .expect("nuget synthesizes manifests");
        assert_eq!(
            f.manifest_identity(&manifest).unwrap(),
            ("contoso.lib".to_string(), "1.0.0-beta".to_string())
        );
        assert_eq!(
            nuspec::dependency_groups_from_nuspec(&manifest).unwrap(),
            deps
        );
        assert!(f.manifest_identity(b"{\"not\": \"xml\"}").is_err());
    }

    #[test]
    fn manifest_identity_honours_the_nuspec_size_cap() {
        let f = NugetFormat::with_limits(NupkgLimits {
            max_nuspec_bytes: 64,
            ..NupkgLimits::default()
        });
        let manifest = nuspec::synthesize_nuspec("A", "1.0.0", &[]);
        assert!(manifest.len() > 64);
        let err = f.manifest_identity(&manifest).unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
    }
}
