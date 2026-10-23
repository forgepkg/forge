//! [`forge_core::Format`] for a format plugin.

use std::cmp::Ordering;
use std::path::Path;
use std::sync::Arc;

use forge_core::domain::{Dependency, DependencyGroup, FormatError, ParsedUpload};
use forge_core::format::{Format, ReadSeek};
use forge_plugin_api::{self as api, FormatPlugin};

use crate::manifest::Assets;
use crate::Plugin;

/// The largest manifest summary, as JSON text, stored from a WebAssembly
/// plugin. Every listing hands each version's summary to the plugin, so a
/// plugin that summarizes without a bound lets a publisher make every
/// listing take gigabytes. Several times the 16 KiB a Helm chart's summary
/// is cut down to, and many times a typical summary.
///
/// A built-in plugin is Forge's own code and bounds its own summaries, or
/// needs them whole: NuGet's carries a package's dependency groups, and a
/// version served without them would install without its dependencies.
const MAX_SUMMARY: usize = 64 * 1024;

/// A format plugin, built in or WebAssembly, as a [`Format`]: what the
/// hosted write path, the read ops, the proxy read path and retention work
/// with.
pub struct PluginFormat {
    id: &'static str,
    plugin: Arc<dyn FormatPlugin>,
    assets: Assets,
    /// The largest manifest summary stored: [`MAX_SUMMARY`] for a
    /// WebAssembly plugin, none for a built-in one.
    max_summary: Option<usize>,
}

impl PluginFormat {
    /// Adapt `plugin`.
    pub fn new(plugin: &Plugin) -> Self {
        PluginFormat {
            id: plugin.id(),
            plugin: plugin.implementation().clone(),
            assets: plugin.manifest().assets.clone(),
            max_summary: (!plugin.is_builtin()).then_some(MAX_SUMMARY),
        }
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

    fn upstream(
        &self,
        remote: &api::Remote,
        op: &api::UpstreamOp,
        fetched: &[api::FetchResult],
    ) -> Result<api::UpstreamStep, FormatError> {
        self.plugin
            .upstream(remote, op, fetched)
            .map_err(format_error)
    }

    fn manifest_summary(&self, manifest: &[u8]) -> Option<serde_json::Value> {
        let text = self.plugin.manifest_summary(manifest)?;
        if let Some(max) = self.max_summary.filter(|max| text.len() > *max) {
            tracing::warn!(
                plugin = self.id,
                bytes = text.len(),
                max,
                "manifest-summary returned more than the host keeps; not stored"
            );
            return None;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Manifest, Origin};

    /// A plugin whose summary of a manifest is `{"description": <it>}`.
    struct Describes;

    impl FormatPlugin for Describes {
        fn canonical_id(&self, id: &str) -> String {
            id.to_string()
        }

        fn validate_id(&self, _id: &str) -> Result<(), api::FormatError> {
            Ok(())
        }

        fn normalize_version(&self, version: &str) -> Result<String, api::FormatError> {
            Ok(version.to_string())
        }

        fn compare_versions(&self, a: &str, b: &str) -> Ordering {
            a.cmp(b)
        }

        fn parse_package(
            &self,
            _package: &mut dyn api::PackageSource,
        ) -> Result<api::ParsedPackage, api::FormatError> {
            Err(api::FormatError::InvalidPackage("not a package".into()))
        }

        fn manifest_summary(&self, manifest: &[u8]) -> Option<String> {
            Some(
                serde_json::json!({ "description": String::from_utf8_lossy(manifest) }).to_string(),
            )
        }

        fn handle(&self, _repo: &api::Repository, _req: &api::Request) -> api::Action {
            api::Action::Respond(api::Response::text(404, "not found"))
        }

        fn render(
            &self,
            _repo: &api::Repository,
            _req: &api::Request,
            _data: &[api::Loaded],
        ) -> api::Rendered {
            api::Rendered::Respond(api::Response::text(404, "not found"))
        }
    }

    fn plugin_toml() -> String {
        format!(
            "[plugin]\nid = \"describes\"\nname = \"Describes\"\nversion = \"1.0.0\"\n\
             api = \"{}\"\ncomponent = \"describes.wasm\"\n",
            api::API
        )
    }

    #[test]
    fn a_webassembly_plugins_oversized_summary_is_not_stored() {
        let manifest = Manifest::parse(&plugin_toml()).unwrap();
        let wasm = Plugin::new(
            manifest,
            Origin::Wasm {
                sha256: "0".repeat(64),
            },
            Arc::new(Describes),
        );
        let format = PluginFormat::new(&wasm);
        // `{"description":"…"}` takes 18 bytes more than the description.
        let fits = "x".repeat(MAX_SUMMARY - 18);
        let summary = format.manifest_summary(fits.as_bytes()).unwrap();
        assert_eq!(summary["description"], serde_json::json!(fits));
        let over = "x".repeat(MAX_SUMMARY - 17);
        assert_eq!(format.manifest_summary(over.as_bytes()), None);

        // A built-in plugin bounds its own.
        let builtin = Plugin::builtin(&plugin_toml(), Describes).unwrap();
        let format = PluginFormat::new(&builtin);
        assert!(format.manifest_summary(over.as_bytes()).is_some());
    }
}
