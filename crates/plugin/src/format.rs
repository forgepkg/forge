//! [`forge_core::Format`] for a format plugin.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use forge_core::domain::{Dependency, DependencyGroup, FormatError, ParsedUpload};
use forge_core::format::{Format, ReadSeek};

use crate::bindings::forge::format::types;
use crate::executor::Pool;
use crate::host::StagedPackage;
use crate::{Plugin, PluginError};

/// Comparisons remembered per plugin: sorting a package's versions asks the
/// plugin once per pair, and the same packages are listed over and over.
const MAX_REMEMBERED_COMPARISONS: usize = 65_536;

/// A format plugin as a [`Format`].
///
/// The infallible methods ([`Format::lower_id`],
/// [`Format::compare_versions`]) cannot report a failed plugin call: they log
/// it and fall back to the input unchanged and to byte order, which the
/// fallible methods then refuse (an id that does not validate is a 404).
pub struct PluginFormat {
    plugin: Arc<Plugin>,
    comparisons: Mutex<HashMap<(String, String), Ordering>>,
}

impl PluginFormat {
    /// Adapt `plugin`.
    pub fn new(plugin: Arc<Plugin>) -> Self {
        PluginFormat {
            plugin,
            comparisons: Mutex::new(HashMap::new()),
        }
    }

    /// The plugin behind this format.
    pub fn plugin(&self) -> &Arc<Plugin> {
        &self.plugin
    }
}

fn failed(e: PluginError) -> FormatError {
    FormatError::Io(std::io::Error::other(e.to_string()))
}

fn format_error(e: types::FormatError) -> FormatError {
    use types::FormatError as E;
    match e {
        E::InvalidPackage(m) => FormatError::InvalidPackage(m),
        E::MissingManifest(m) => FormatError::MissingManifest(m),
        E::MalformedManifest(m) => FormatError::MalformedManifest(m),
        E::InvalidVersion(m) => FormatError::InvalidVersion {
            value: String::new(),
            reason: m,
        },
        E::InvalidId(m) => FormatError::InvalidPackage(m),
    }
}

impl Format for PluginFormat {
    fn id(&self) -> &'static str {
        self.plugin.id()
    }

    fn parse_upload(&self, file: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
        // The plugin reads a file it is lent; spool a reader into one.
        let mut spooled = tempfile::NamedTempFile::new()?;
        file.rewind()?;
        std::io::copy(file, &mut spooled)?;
        self.parse_upload_file(spooled.path())
    }

    fn parse_upload_file(&self, path: &Path) -> Result<ParsedUpload, FormatError> {
        let package = StagedPackage::new(std::fs::File::open(path)?)?;
        let parsed = self
            .plugin
            .call_blocking(Pool::Slow, "parse-package", move |store, plugin| {
                let lent = store.data_mut().lend(package)?;
                let borrowed = wasmtime::component::Resource::new_borrow(lent.rep());
                let result = plugin
                    .forge_format_format()
                    .call_parse_package(&mut *store, borrowed);
                store.data_mut().reclaim(lent);
                result
            })
            .map_err(failed)?
            .map_err(format_error)?;
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

    fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
        let raw = raw.to_string();
        self.plugin
            .call_blocking(Pool::Quick, "normalize-version", move |store, plugin| {
                plugin
                    .forge_format_format()
                    .call_normalize_version(store, &raw)
            })
            .map_err(failed)?
            .map_err(format_error)
    }

    fn compare_versions(&self, a: &str, b: &str) -> Ordering {
        let key = (a.to_string(), b.to_string());
        if let Some(order) = self
            .comparisons
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
        {
            return *order;
        }
        let (x, y) = key.clone();
        let order = match self.plugin.call_blocking(
            Pool::Quick,
            "compare-versions",
            move |store, plugin| {
                plugin
                    .forge_format_format()
                    .call_compare_versions(store, &x, &y)
            },
        ) {
            Ok(n) => n.cmp(&0),
            Err(_) => return a.cmp(b),
        };
        let mut remembered = self.comparisons.lock().unwrap_or_else(|p| p.into_inner());
        if remembered.len() >= MAX_REMEMBERED_COMPARISONS {
            remembered.clear();
        }
        remembered.insert(key, order);
        order
    }

    fn lower_id(&self, id: &str) -> String {
        let raw = id.to_string();
        self.plugin
            .call_blocking(Pool::Quick, "canonical-id", move |store, plugin| {
                plugin.forge_format_format().call_canonical_id(store, &raw)
            })
            .unwrap_or_else(|_| id.to_string())
    }

    fn validate_id(&self, id: &str) -> Result<(), FormatError> {
        let id = id.to_string();
        self.plugin
            .call_blocking(Pool::Quick, "validate-id", move |store, plugin| {
                plugin.forge_format_format().call_validate_id(store, &id)
            })
            .map_err(failed)?
            .map_err(format_error)
    }

    fn manifest_summary(&self, manifest: &[u8]) -> Option<serde_json::Value> {
        let manifest = manifest.to_vec();
        let text = self
            .plugin
            .call_blocking(Pool::Quick, "manifest-summary", move |store, plugin| {
                plugin
                    .forge_format_format()
                    .call_manifest_summary(store, &manifest)
            })
            .ok()??;
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(summary @ serde_json::Value::Object(_)) => Some(summary),
            _ => {
                tracing::warn!(
                    plugin = self.plugin.id(),
                    "manifest-summary returned something other than a JSON object; not stored"
                );
                None
            }
        }
    }
}
