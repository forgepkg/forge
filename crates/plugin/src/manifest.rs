//! `plugin.toml`: what a plugin declares about itself, next to its crate's
//! `Cargo.toml` (`plugins/<id>/plugin.toml`) and in an installed plugin
//! directory.
//!
//! ```toml
//! [plugin]
//! id = "helm"               # the format id repositories are created with
//! name = "Helm charts"
//! version = "0.1.0"         # the plugin's own version (informational)
//! api = "0.1.0"             # the forge:format contract it is built against
//! component = "helm.wasm"   # built as a component: its file, relative to
//!                           # the directory (unused when built in)
//!
//! [limits]                  # as a component; each capped by the host's maximum
//! memory_mib = 64
//! fuel = 2000000000
//! timeout_ms = 2000
//! ```

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use crate::PluginError;

/// The `forge:format` contract versions this host implements.
pub const SUPPORTED_APIS: &[&str] = &[forge_plugin_api::API];

/// Format ids a plugin can never take: the built-in format, and names the
/// server routes or reserves.
const RESERVED_IDS: &[&str] = &["nuget", "v3", "admin", "browse", "auth", "repository"];

/// A parsed and validated `plugin.toml`.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// The format id (`repository.format`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// The plugin's own version.
    pub version: String,
    /// The `forge:format` contract version it is built against.
    pub api: String,
    /// Optional one-line description.
    pub description: Option<String>,
    /// Path of the component, relative to the plugin directory (WebAssembly
    /// plugins).
    pub component: Option<PathBuf>,
    /// Requested limits as a component (`None` → the host default).
    pub limits: RequestedLimits,
}

/// The `[limits]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedLimits {
    /// Linear-memory ceiling per instance, in MiB.
    pub memory_mib: Option<u64>,
    /// Fuel (roughly, WebAssembly instructions) per call.
    pub fuel: Option<u64>,
    /// Wall-clock budget per call, in milliseconds.
    pub timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    plugin: RawPlugin,
    #[serde(default)]
    limits: RequestedLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlugin {
    id: String,
    name: String,
    version: String,
    api: String,
    component: Option<String>,
    description: Option<String>,
}

impl Manifest {
    /// Parse and validate the text of a `plugin.toml`.
    pub fn parse(text: &str) -> Result<Self, PluginError> {
        let raw: RawManifest =
            toml::from_str(text).map_err(|e| PluginError::Manifest(e.to_string()))?;
        let p = raw.plugin;
        validate_id(&p.id)?;
        if !SUPPORTED_APIS.contains(&p.api.as_str()) {
            return Err(PluginError::Manifest(format!(
                "api {:?} is not supported (this server implements {SUPPORTED_APIS:?})",
                p.api
            )));
        }
        // The component is a file inside the plugin directory: a plain
        // relative path, never `..`, absolute, or a drive/root prefix.
        let component = p.component.map(|raw| {
            let path = PathBuf::from(&raw);
            if raw.is_empty() || !path.components().all(|c| matches!(c, Component::Normal(_))) {
                return Err(PluginError::Manifest(format!(
                    "component {raw:?} must be a relative path inside the plugin directory"
                )));
            }
            Ok(path)
        });
        let component = component.transpose()?;
        if p.name.trim().is_empty() {
            return Err(PluginError::Manifest("name must not be empty".into()));
        }
        Ok(Manifest {
            id: p.id,
            name: p.name,
            version: p.version,
            api: p.api,
            description: p.description,
            component,
            limits: raw.limits,
        })
    }

    /// Read and parse `<dir>/plugin.toml`.
    pub fn load(dir: &Path) -> Result<Self, PluginError> {
        let path = dir.join("plugin.toml");
        let text = std::fs::read_to_string(&path)
            .map_err(|e| PluginError::Io(format!("read {}: {e}", path.display())))?;
        Self::parse(&text)
    }
}

/// A format id: 2–32 characters of lowercase ASCII letters, digits and `-`,
/// starting with a letter, and not one of the reserved names.
pub fn validate_id(id: &str) -> Result<(), PluginError> {
    let well_formed = (2..=32).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !well_formed {
        return Err(PluginError::Manifest(format!(
            "id {id:?} must be 2-32 lowercase letters, digits or '-', starting with a letter"
        )));
    }
    if RESERVED_IDS.contains(&id) {
        return Err(PluginError::Manifest(format!("id {id:?} is reserved")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
        [plugin]
        id = "helm"
        name = "Helm charts"
        version = "0.1.0"
        api = "0.1.0"
        component = "helm.wasm"

        [limits]
        memory_mib = 32
    "#;

    #[test]
    fn parses_a_manifest() {
        let m = Manifest::parse(GOOD).unwrap();
        assert_eq!(m.id, "helm");
        assert_eq!(m.component, Some(PathBuf::from("helm.wasm")));
        assert_eq!(m.limits.memory_mib, Some(32));
        assert_eq!(m.limits.fuel, None);
    }

    #[test]
    fn refuses_bad_ids_and_reserved_names() {
        for id in [
            "",
            "h",
            "Helm",
            "1helm",
            "helm_charts",
            "nuget",
            "v3",
            &"a".repeat(33),
        ] {
            let text = GOOD.replace("id = \"helm\"", &format!("id = {id:?}"));
            assert!(Manifest::parse(&text).is_err(), "{id:?} accepted");
        }
        assert!(validate_id("npm").is_ok());
        assert!(validate_id("go-modules").is_ok());
    }

    #[test]
    fn refuses_components_outside_the_directory() {
        for path in ["../helm.wasm", "/etc/passwd", "a/../../b.wasm", ""] {
            let text = GOOD.replace("\"helm.wasm\"", &format!("{path:?}"));
            assert!(Manifest::parse(&text).is_err(), "{path:?} accepted");
        }
        let text = GOOD.replace("\"helm.wasm\"", "\"lib/helm.wasm\"");
        assert!(Manifest::parse(&text).is_ok());
        // A built-in plugin needs none.
        let text = GOOD.replace("component = \"helm.wasm\"", "");
        assert_eq!(Manifest::parse(&text).unwrap().component, None);
    }

    #[test]
    fn refuses_unknown_apis_and_keys() {
        assert!(Manifest::parse(&GOOD.replace("api = \"0.1.0\"", "api = \"9.0.0\"")).is_err());
        assert!(Manifest::parse(&format!("{GOOD}\nunknown = 1\n")).is_err());
        assert!(Manifest::parse(&GOOD.replace("memory_mib", "memory_gib")).is_err());
    }
}
