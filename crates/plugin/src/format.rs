//! [`forge_core::Format`] for a format plugin.

use std::cmp::Ordering;
use std::path::Path;
use std::sync::Arc;

use forge_core::domain::{Dependency, DependencyGroup, FormatError, ParsedUpload};
use forge_core::format::{Format, ReadSeek};
use forge_plugin_api::{self as api, FormatPlugin};

use crate::manifest::{Assets, Upstream};
use crate::upstream::{NugetV3, UpstreamManifests};
use crate::Plugin;

/// A format plugin, built in or WebAssembly, as a [`Format`]: what the
/// hosted write path, the read ops and retention work with.
pub struct PluginFormat {
    id: &'static str,
    plugin: Arc<dyn FormatPlugin>,
    assets: Assets,
    /// What a proxy of the format needs of its manifests
    /// ([`crate::upstream`]).
    upstream: Option<Arc<dyn UpstreamManifests>>,
}

impl PluginFormat {
    /// Adapt `plugin`, with the upstream protocol its `plugin.toml` names.
    pub fn new(plugin: &Plugin) -> Self {
        let upstream: Option<Arc<dyn UpstreamManifests>> = match plugin.manifest().proxy {
            Some(Upstream::NugetV3) => Some(Arc::new(NugetV3::default())),
            None => None,
        };
        PluginFormat {
            id: plugin.id(),
            plugin: plugin.implementation().clone(),
            assets: plugin.manifest().assets.clone(),
            upstream,
        }
    }

    /// NuGet, the built-in plugin of `plugins/nuget`, reading archives and
    /// upstream manifests under `limits`.
    pub fn nuget(limits: forge_format_nuget::NupkgLimits) -> Self {
        let plugin = Plugin::builtin(
            forge_format_nuget::PLUGIN_TOML,
            forge_format_nuget::Nuget::with_limits(limits),
        )
        .expect("plugins/nuget/plugin.toml is valid");
        PluginFormat::new(&plugin).with_upstream(Arc::new(NugetV3::new(limits)))
    }

    /// Read upstream manifests with `upstream` instead.
    pub fn with_upstream(mut self, upstream: Arc<dyn UpstreamManifests>) -> Self {
        self.upstream = Some(upstream);
        self
    }
}

fn format_error(e: api::FormatError) -> FormatError {
    use api::FormatError as E;
    match e {
        E::InvalidPackage(m) | E::InvalidId(m) => FormatError::InvalidPackage(m),
        E::MissingManifest(m) => FormatError::MissingManifest(m),
        E::MalformedManifest(m) => FormatError::MalformedManifest(m),
        E::InvalidVersion(m) => FormatError::InvalidVersion {
            value: String::new(),
            reason: m,
        },
        E::Internal(m) => FormatError::Io(std::io::Error::other(m)),
    }
}

fn parsed_upload(parsed: api::ParsedPackage) -> ParsedUpload {
    ParsedUpload {
        id: parsed.id,
        original_id: parsed.original_id,
        version: parsed.version,
        version_original: parsed.version_original,
        listed: parsed.listed,
        nuspec_bytes: parsed.manifest,
        deps: parsed
            .dependencies
            .into_iter()
            .map(|g| DependencyGroup {
                target_framework: g.target,
                dependencies: g
                    .dependencies
                    .into_iter()
                    .map(|d| Dependency {
                        id: d.id,
                        range: d.range,
                    })
                    .collect(),
            })
            .collect(),
    }
}

impl Format for PluginFormat {
    fn id(&self) -> &'static str {
        self.id
    }

    fn package_asset_path(&self) -> &str {
        &self.assets.package
    }

    fn package_content_type(&self) -> &str {
        &self.assets.package_type
    }

    fn manifest_asset_path(&self) -> &str {
        &self.assets.manifest
    }

    fn manifest_content_type(&self) -> &str {
        &self.assets.manifest_type
    }

    fn parse_upload(&self, mut file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
        file.rewind()?;
        self.plugin
            .parse_package(&mut file)
            .map(parsed_upload)
            .map_err(format_error)
    }

    fn parse_upload_file(&self, path: &Path) -> Result<ParsedUpload, FormatError> {
        self.plugin
            .parse_package_file(path)
            .map(parsed_upload)
            .map_err(format_error)
    }

    fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
        self.plugin.normalize_version(raw).map_err(format_error)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        self.plugin.compare_versions(a, b)
    }

    fn lower_id(&self, id: &str) -> String {
        self.plugin.canonical_id(id)
    }

    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        self.plugin.validate_id(id).map_err(format_error)
    }

    fn search_hit_summary(&self, hit: &serde_json::Value) -> Option<serde_json::Value> {
        self.upstream.as_ref()?.search_hit_summary(hit)
    }

    fn manifest_identity(&self, manifest: &[u8]) -> Result<(String, String), FormatError> {
        match &self.upstream {
            Some(upstream) => upstream.manifest_identity(manifest),
            None => Err(FormatError::MalformedManifest(format!(
                "{} manifests cannot be verified",
                self.id
            ))),
        }
    }

    fn synthesize_manifest(
        &self,
        id: &str,
        version: &str,
        deps: &[DependencyGroup],
    ) -> Option<Vec<u8>> {
        self.upstream
            .as_ref()?
            .synthesize_manifest(id, version, deps)
    }

    fn manifest_summary(&self, manifest: &[u8]) -> Option<serde_json::Value> {
        let text = self.plugin.manifest_summary(manifest)?;
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(summary @ serde_json::Value::Object(_)) => Some(summary),
            _ => {
                tracing::warn!(
                    plugin = self.id,
                    "manifest-summary returned something other than a JSON object; not stored"
                );
                None
            }
        }
    }
}
