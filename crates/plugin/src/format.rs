//! [`forge_core::Format`] for a format plugin.

use std::cmp::Ordering;
use std::path::Path;
use std::sync::Arc;

use forge_core::domain::{Dependency, DependencyGroup, FormatError, ParsedUpload};
use forge_core::format::{Format, ReadSeek};
use forge_plugin_api::{self as api, FormatPlugin};

use crate::manifest::Assets;
use crate::Plugin;

/// The longest version the host takes from a format plugin, in bytes: a
/// version to normalize as given, its normalized form, and a parsed
/// package's version as written and normalized. Versions are stored in the
/// `UNIQUE (repository_id, name, version)` indexes of `component` and
/// `proxy_cached_version`, and PostgreSQL refuses a B-tree index entry
/// larger than about 2,700 bytes: a plugin without a limit of its own let a
/// multi-kilobyte version through to that insert, so a push answered 500
/// instead of 400, and so did a proxy asked for such a version. 256 is above
/// every built-in plugin's own limit (NuGet's 64 characters, Helm's 128) and,
/// with [`MAX_ID_LENGTH`], keeps an entry far below PostgreSQL's.
const MAX_VERSION_LENGTH: usize = 256;

/// The longest package id the host takes from a format plugin, in bytes:
/// an id to validate, and a parsed package's id as written and canonical.
/// Ids share the indexes of [`MAX_VERSION_LENGTH`]. 512 is above every
/// built-in plugin's own limit (Helm's 250 ASCII characters, NuGet's 100
/// characters, at most 400 bytes in UTF-8).
const MAX_ID_LENGTH: usize = 512;

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

/// The start of `value`, to name an oversized one in an error.
fn start(value: &str) -> String {
    let start: String = value.chars().take(64).collect();
    format!("{start}…")
}

/// Refuses an id longer than [`MAX_ID_LENGTH`].
fn check_id(id: &str) -> Result<(), FormatError> {
    if id.len() > MAX_ID_LENGTH {
        return Err(FormatError::InvalidPackage(format!(
            "invalid package id {:?}: longer than {MAX_ID_LENGTH} bytes",
            start(id)
        )));
    }
    Ok(())
}

/// Refuses a version longer than [`MAX_VERSION_LENGTH`].
fn check_version(version: &str) -> Result<(), FormatError> {
    if version.len() > MAX_VERSION_LENGTH {
        return Err(FormatError::InvalidVersion {
            value: start(version),
            reason: format!("longer than {MAX_VERSION_LENGTH} bytes"),
        });
    }
    Ok(())
}

/// A package the plugin parsed, as the host stores it, unless its id or
/// version is longer than the host takes ([`MAX_ID_LENGTH`],
/// [`MAX_VERSION_LENGTH`]): a push of it is refused (400).
fn parsed_upload(parsed: api::ParsedPackage) -> Result<ParsedUpload, FormatError> {
    check_id(&parsed.id)?;
    check_id(&parsed.original_id)?;
    check_version(&parsed.version)?;
    check_version(&parsed.version_original)?;
    Ok(ParsedUpload {
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
    })
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
            .map_err(format_error)
            .and_then(parsed_upload)
    }

    fn parse_upload_file(&self, path: &Path) -> Result<ParsedUpload, FormatError> {
        self.plugin
            .parse_package_file(path)
            .map_err(format_error)
            .and_then(parsed_upload)
    }

    /// The plugin's normalized form of `raw`, refused when either is longer
    /// than [`MAX_VERSION_LENGTH`] (a read naming it answers 404).
    fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
        // Before the plugin, so an oversized version never reaches it.
        check_version(raw)?;
        let normalized = self.plugin.normalize_version(raw).map_err(format_error)?;
        check_version(&normalized)?;
        Ok(normalized)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        self.plugin.compare_versions(a, b)
    }

    fn lower_id(&self, id: &str) -> String {
        self.plugin.canonical_id(id)
    }

    /// Whether the plugin takes `id`, which is never longer than
    /// [`MAX_ID_LENGTH`].
    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        // Before the plugin, so an oversized id never reaches it.
        check_id(id)?;
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

    /// A format without limits of its own: every id is valid, every version
    /// normalizes to `normalized` (or to itself), and every package parses
    /// as `parsed`.
    struct Unlimited {
        normalized: Option<String>,
        parsed: api::ParsedPackage,
    }

    impl FormatPlugin for Unlimited {
        fn canonical_id(&self, id: &str) -> String {
            id.to_ascii_lowercase()
        }

        fn validate_id(&self, _id: &str) -> Result<(), api::FormatError> {
            Ok(())
        }

        fn normalize_version(&self, version: &str) -> Result<String, api::FormatError> {
            Ok(self
                .normalized
                .clone()
                .unwrap_or_else(|| version.to_string()))
        }

        fn compare_versions(&self, a: &str, b: &str) -> Ordering {
            a.cmp(b)
        }

        fn parse_package(
            &self,
            _package: &mut dyn api::PackageSource,
        ) -> Result<api::ParsedPackage, api::FormatError> {
            Ok(self.parsed.clone())
        }

        fn manifest_summary(&self, _manifest: &[u8]) -> Option<String> {
            None
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

    /// A package `id` at `version`, as written and normalized.
    fn package(id: &str, version: &str) -> api::ParsedPackage {
        api::ParsedPackage {
            id: id.to_ascii_lowercase(),
            original_id: id.to_string(),
            version: version.to_string(),
            version_original: version.to_string(),
            listed: true,
            manifest: Vec::new(),
            dependencies: Vec::new(),
        }
    }

    /// [`Unlimited`] as the host sees it.
    fn unlimited(normalized: Option<&str>, parsed: api::ParsedPackage) -> PluginFormat {
        let plugin = Plugin::builtin(
            "[plugin]\nid = \"unlimited\"\nname = \"Unlimited\"\nversion = \"0.1.0\"\napi = \"0.3.0\"\n",
            Unlimited {
                normalized: normalized.map(str::to_string),
                parsed,
            },
        )
        .unwrap();
        PluginFormat::new(&plugin)
    }

    #[test]
    fn versions_longer_than_the_host_takes_do_not_normalize() {
        let longest = "1".repeat(MAX_VERSION_LENGTH);
        let longer = "1".repeat(MAX_VERSION_LENGTH + 1);
        let format = unlimited(None, package("demo", "1.0.0"));
        assert_eq!(format.normalize_version(&longest).unwrap(), longest);
        for version in [longer.clone(), "1".repeat(4096)] {
            let err = format.normalize_version(&version).unwrap_err();
            assert!(matches!(err, FormatError::InvalidVersion { .. }), "{err}");
            assert!(err.to_string().len() < 200, "{err}");
        }
        // The normalized form too.
        let lengthened = unlimited(Some(&longer), package("demo", "1.0.0"));
        assert!(matches!(
            lengthened.normalize_version("1"),
            Err(FormatError::InvalidVersion { .. })
        ));
        let normalized = unlimited(Some(&longest), package("demo", "1.0.0"));
        assert_eq!(normalized.normalize_version("1").unwrap(), longest);
    }

    #[test]
    fn ids_longer_than_the_host_takes_are_invalid() {
        let format = unlimited(None, package("demo", "1.0.0"));
        assert!(format.validate_id(&"a".repeat(MAX_ID_LENGTH)).is_ok());
        // Bytes: 129 four-byte characters are longer.
        for id in ["a".repeat(MAX_ID_LENGTH + 1), "\u{1F600}".repeat(129)] {
            assert!(matches!(
                format.validate_id(&id),
                Err(FormatError::InvalidPackage(_))
            ));
        }
    }

    #[test]
    fn a_package_with_a_longer_id_or_version_is_refused() {
        let parse = |parsed: api::ParsedPackage| {
            unlimited(None, parsed).parse_upload(&mut std::io::Cursor::new(Vec::new()))
        };
        let longest_version = "1".repeat(MAX_VERSION_LENGTH);
        let longest_id = "A".repeat(MAX_ID_LENGTH);
        let parsed = parse(package(&longest_id, &longest_version)).unwrap();
        assert_eq!(parsed.id, longest_id.to_ascii_lowercase());
        assert_eq!(parsed.version, longest_version);

        let longer_version = format!("{longest_version}1");
        let longer_id = format!("{longest_id}A");
        let version_original = api::ParsedPackage {
            version_original: longer_version.clone(),
            ..package("demo", "1.0.0")
        };
        let original_id = api::ParsedPackage {
            original_id: longer_id.clone(),
            ..package("demo", "1.0.0")
        };
        for parsed in [package("demo", &longer_version), version_original] {
            assert!(matches!(
                parse(parsed),
                Err(FormatError::InvalidVersion { .. })
            ));
        }
        for parsed in [package(&longer_id, "1.0.0"), original_id] {
            assert!(matches!(parse(parsed), Err(FormatError::InvalidPackage(_))));
        }
    }

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
