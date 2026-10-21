//! `plugin.toml`: what a plugin declares about itself, next to its crate's
//! `Cargo.toml` (`plugins/<id>/plugin.toml`) and in an installed plugin
//! directory.
//!
//! ```toml
//! [plugin]
//! id = "helm"               # the format id repositories are created with
//! name = "Helm charts"
//! version = "0.1.0"         # the plugin's own version (informational)
//! api = "0.3.0"             # the forge:format contract it is built against
//! component = "helm.wasm"   # built as a component: its file, relative to
//!                           # the directory (unused when built in)
//! mount = "/repository"     # optional: served at {mount}/{repository}/…
//! kinds = ["hosted", "group"] # optional: the repository kinds it supports
//!                           # ("proxy" too, when it implements `upstream`)
//!
//! [assets]                  # optional: how its files are stored
//! package = "package"
//! package_type = "application/octet-stream"
//! manifest = "manifest"
//! manifest_type = "application/octet-stream"
//!
//! [limits]                  # as a component; each capped by the host's maximum
//! memory_mib = 64
//! fuel = 2000000000
//! timeout_ms = 2000
//! ```

use std::path::{Component, Path, PathBuf};

use forge_plugin_api::RepositoryKind;
use serde::Deserialize;

use crate::PluginError;

/// The `forge:format` contract versions this host implements.
pub const SUPPORTED_APIS: &[&str] = &[forge_plugin_api::API];

/// Format ids a plugin can never take: the built-in Docker registry's, and
/// names the server routes or reserves. (A built-in plugin's id, such as
/// NuGet's, is taken by that plugin: see the server's registry.)
const RESERVED_IDS: &[&str] = &[
    "docker",
    "v2",
    "v3",
    "admin",
    "browse",
    "auth",
    "repository",
];

/// Where a plugin's repositories are served unless it names a mount.
pub const DEFAULT_MOUNT: &str = "/repository";

/// Mounts a plugin can never take: the server's own routes, the web UI's
/// pages and the Docker registry.
const RESERVED_MOUNTS: &[&str] = &[
    "admin",
    "api",
    "assets",
    "auth",
    "browse",
    "healthz",
    "login",
    "manage",
    "packages",
    "readyz",
    "realms",
    "repos",
    "repositories",
    "tokens",
    "users",
    "v2",
    "version",
];

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
    /// Where repositories of the format are served: `{mount}/{repository}/…`.
    pub mount: String,
    /// The repository kinds the format supports. `proxy` means the plugin
    /// implements [`forge_plugin_api::FormatPlugin::upstream`].
    pub kinds: Vec<RepositoryKind>,
    /// How a version's files are stored.
    pub assets: Assets,
    /// Requested limits as a component (`None` → the host default).
    pub limits: RequestedLimits,
}

/// The `[assets]` table: the names (within a version) and content types of
/// a version's package and manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Assets {
    pub package: String,
    pub package_type: String,
    pub manifest: String,
    pub manifest_type: String,
}

impl Default for Assets {
    fn default() -> Self {
        Assets {
            package: "package".into(),
            package_type: "application/octet-stream".into(),
            manifest: "manifest".into(),
            manifest_type: "application/octet-stream".into(),
        }
    }
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
    assets: Assets,
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
    mount: Option<String>,
    kinds: Option<Vec<String>>,
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
        let mount = p.mount.unwrap_or_else(|| DEFAULT_MOUNT.to_string());
        validate_mount(&mount)?;
        let kinds = match p.kinds {
            None => vec![RepositoryKind::Hosted, RepositoryKind::Group],
            Some(kinds) => parse_kinds(&kinds)?,
        };
        validate_assets(&raw.assets)?;
        Ok(Manifest {
            id: p.id,
            name: p.name,
            version: p.version,
            api: p.api,
            description: p.description,
            component,
            mount,
            kinds,
            assets: raw.assets,
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

/// A mount: `/` and one path segment of 2–32 lowercase letters, digits and
/// `-`, starting with a letter, and not one of the reserved names.
pub fn validate_mount(mount: &str) -> Result<(), PluginError> {
    let name = mount.strip_prefix('/').unwrap_or("");
    let well_formed = (2..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !well_formed {
        return Err(PluginError::Manifest(format!(
            "mount {mount:?} must be '/' and 2-32 lowercase letters, digits or '-', \
             starting with a letter"
        )));
    }
    if RESERVED_MOUNTS.contains(&name) {
        return Err(PluginError::Manifest(format!(
            "mount {mount:?} is reserved"
        )));
    }
    Ok(())
}

/// The `kinds` of a manifest: some of `hosted`, `proxy` and `group`, each
/// once.
fn parse_kinds(kinds: &[String]) -> Result<Vec<RepositoryKind>, PluginError> {
    let mut parsed = Vec::new();
    for kind in kinds {
        let kind = match kind.as_str() {
            "hosted" => RepositoryKind::Hosted,
            "group" => RepositoryKind::Group,
            "proxy" => RepositoryKind::Proxy,
            other => {
                return Err(PluginError::Manifest(format!(
                    "unknown repository kind {other:?} (hosted, proxy, group)"
                )))
            }
        };
        if parsed.contains(&kind) {
            return Err(PluginError::Manifest(format!(
                "kind {kind:?} is listed twice"
            )));
        }
        parsed.push(kind);
    }
    if parsed.is_empty() {
        return Err(PluginError::Manifest("kinds must not be empty".into()));
    }
    Ok(parsed)
}

/// Asset names are plain file names; content types are `type/subtype`
/// (parameters allowed) in printable ASCII.
fn validate_assets(assets: &Assets) -> Result<(), PluginError> {
    for name in [&assets.package, &assets.manifest] {
        let ok = (1..=64).contains(&name.len())
            && !name.starts_with('.')
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !ok {
            return Err(PluginError::Manifest(format!(
                "asset name {name:?} must be 1-64 letters, digits, '.', '_' or '-', \
                 not starting with '.'"
            )));
        }
    }
    if assets.package == assets.manifest {
        return Err(PluginError::Manifest(
            "the package and the manifest need different asset names".into(),
        ));
    }
    for content_type in [&assets.package_type, &assets.manifest_type] {
        let essence = content_type.split(';').next().unwrap_or("").trim();
        let ok = content_type.len() <= 127
            && content_type
                .chars()
                .all(|c| c.is_ascii_graphic() || c == ' ')
            && essence
                .split_once('/')
                .is_some_and(|(t, s)| !t.is_empty() && !s.is_empty());
        if !ok {
            return Err(PluginError::Manifest(format!(
                "content type {content_type:?} must be type/subtype"
            )));
        }
    }
    Ok(())
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
        api = "0.3.0"
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
            "docker",
            "v2",
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
    fn mounts_kinds_and_assets_default_and_validate() {
        let m = Manifest::parse(GOOD).unwrap();
        assert_eq!(m.mount, DEFAULT_MOUNT);
        assert_eq!(m.kinds, [RepositoryKind::Hosted, RepositoryKind::Group]);
        assert_eq!(m.assets, Assets::default());

        let with = |plugin_keys: &str, tables: &str| {
            let text = GOOD.replace(
                "component = \"helm.wasm\"",
                &format!("component = \"helm.wasm\"\n{plugin_keys}"),
            );
            Manifest::parse(&format!("{text}\n{tables}"))
        };
        let m = with(
            "mount = \"/charts\"\nkinds = [\"hosted\"]",
            "[assets]\npackage = \"chart.tgz\"\nmanifest_type = \"application/yaml\"\n",
        )
        .unwrap();
        assert_eq!(m.mount, "/charts");
        assert_eq!(m.kinds, [RepositoryKind::Hosted]);
        assert_eq!(m.assets.package, "chart.tgz");
        assert_eq!(m.assets.manifest, "manifest");
        assert_eq!(m.assets.manifest_type, "application/yaml");

        for mount in [
            "charts", "/", "/c", "/Charts", "/a/b", "/admin", "/v2", "/manage",
        ] {
            assert!(
                with(&format!("mount = {mount:?}"), "").is_err(),
                "{mount:?} accepted"
            );
        }
        // A plugin with an upstream side serves proxies.
        let m = with("kinds = [\"hosted\", \"proxy\"]", "").unwrap();
        assert_eq!(m.kinds, [RepositoryKind::Hosted, RepositoryKind::Proxy]);
        // `[proxy]` (0.2's host-side upstream protocols) is gone.
        assert!(with("", "[proxy]\nupstream = \"nuget-v3\"\n").is_err());
        for kinds in ["[]", "[\"mirror\"]", "[\"hosted\", \"hosted\"]"] {
            assert!(
                with(&format!("kinds = {kinds}"), "").is_err(),
                "{kinds} accepted"
            );
        }
        for assets in [
            "package = \"\"",
            "package = \"../x\"",
            "package = \".hidden\"",
            "package = \"manifest\"",
            "package_type = \"binary\"",
            "manifest_type = \"text/\\u0001\"",
        ] {
            assert!(
                with("", &format!("[assets]\n{assets}\n")).is_err(),
                "{assets} accepted"
            );
        }
    }

    #[test]
    fn refuses_unknown_apis_and_keys() {
        assert!(Manifest::parse(&GOOD.replace("api = \"0.3.0\"", "api = \"9.0.0\"")).is_err());
        // 0.1.0 was a preview that no release shipped.
        assert!(Manifest::parse(&GOOD.replace("api = \"0.3.0\"", "api = \"0.2.0\"")).is_err());
        assert!(Manifest::parse(&format!("{GOOD}\nunknown = 1\n")).is_err());
        assert!(Manifest::parse(&GOOD.replace("memory_mib", "memory_gib")).is_err());
    }
}
