//! Upstream protocols the host implements for proxy repositories of plugin
//! formats (`[proxy] upstream` in `plugin.toml`).
//!
//! `nuget-v3` is a NuGet V3 feed. Its proxy (`forge_core::repo::proxy`)
//! fetches the upstream's listings, manifests and packages itself; what it
//! needs to know of the format's manifests comes from here: verifying an
//! upstream `.nuspec`, synthesizing one for a version known only from an
//! upstream registration, and the summary of an upstream search hit. Until a
//! plugin can describe its own upstream protocol, these come from NuGet's
//! `.nuspec` reader.

use forge_core::domain::{DependencyGroup, FormatError};
use forge_format_nuget::{model, nuspec, NupkgLimits};

/// What a proxy needs to know of a format's manifests.
pub trait UpstreamManifests: Send + Sync {
    /// The summary (as the format's `manifest_summary` gives it) of one
    /// entry of an upstream's search results.
    fn search_hit_summary(&self, hit: &serde_json::Value) -> Option<serde_json::Value>;

    /// The `(canonical id, normalized version)` an upstream manifest
    /// declares.
    fn manifest_identity(&self, manifest: &[u8]) -> Result<(String, String), FormatError>;

    /// A minimal manifest declaring `id`, `version` and `deps`.
    fn synthesize_manifest(
        &self,
        id: &str,
        version: &str,
        deps: &[DependencyGroup],
    ) -> Option<Vec<u8>>;
}

/// The manifests of a NuGet V3 upstream: `.nuspec`s, read under `limits`.
#[derive(Debug, Clone, Default)]
pub struct NugetV3 {
    limits: NupkgLimits,
}

impl NugetV3 {
    /// NuGet V3 manifests read under `limits` (the server's `[nuget]`).
    pub fn new(limits: NupkgLimits) -> Self {
        NugetV3 { limits }
    }
}

fn format_error(e: model::FormatError) -> FormatError {
    match e {
        model::FormatError::InvalidPackage(m) => FormatError::InvalidPackage(m),
        model::FormatError::MissingManifest(m) => FormatError::MissingManifest(m),
        model::FormatError::MalformedManifest(m) => FormatError::MalformedManifest(m),
        model::FormatError::InvalidVersion { value, reason } => {
            FormatError::InvalidVersion { value, reason }
        }
        model::FormatError::Io(e) => FormatError::Io(e),
    }
}

impl UpstreamManifests for NugetV3 {
    fn search_hit_summary(&self, hit: &serde_json::Value) -> Option<serde_json::Value> {
        serde_json::to_value(nuspec::summary_from_search_hit(hit)).ok()
    }

    fn manifest_identity(&self, manifest: &[u8]) -> Result<(String, String), FormatError> {
        nuspec::manifest_identity(manifest, &self.limits).map_err(format_error)
    }

    fn synthesize_manifest(
        &self,
        id: &str,
        version: &str,
        deps: &[DependencyGroup],
    ) -> Option<Vec<u8>> {
        let deps: Vec<model::DependencyGroup> = deps
            .iter()
            .map(|g| model::DependencyGroup {
                target_framework: g.target_framework.clone(),
                dependencies: g
                    .dependencies
                    .iter()
                    .map(|d| model::Dependency {
                        id: d.id.clone(),
                        range: d.range.clone(),
                    })
                    .collect(),
            })
            .collect();
        Some(nuspec::synthesize_nuspec(id, version, &deps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_core::domain::Dependency;

    #[test]
    fn nuget_manifests_round_trip() {
        let nuget = NugetV3::default();
        let deps = vec![DependencyGroup {
            target_framework: Some("net8.0".into()),
            dependencies: vec![Dependency {
                id: "Newtonsoft.Json".into(),
                range: Some("[13.0.1, )".into()),
            }],
        }];
        let manifest = nuget
            .synthesize_manifest("Contoso.Lib", "1.0.0-Beta", &deps)
            .unwrap();
        assert_eq!(
            nuget.manifest_identity(&manifest).unwrap(),
            ("contoso.lib".to_string(), "1.0.0-beta".to_string())
        );
        assert!(nuget.manifest_identity(b"{\"not\": \"xml\"}").is_err());
        let summary = nuget
            .search_hit_summary(&serde_json::json!({ "description": " A lib ", "tags": ["x"] }))
            .unwrap();
        assert_eq!(summary["metadata"]["description"], "A lib");
    }

    #[test]
    fn the_nuspec_size_cap_applies() {
        let nuget = NugetV3::new(NupkgLimits {
            max_nuspec_bytes: 64,
            ..NupkgLimits::default()
        });
        let manifest = nuspec::synthesize_nuspec("A", "1.0.0", &[]);
        assert!(manifest.len() > 64);
        let err = nuget.manifest_identity(&manifest).unwrap_err();
        assert!(err.to_string().contains("limit"), "{err}");
    }
}
