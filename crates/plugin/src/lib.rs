//! `forge-plugin`: the host side of format plugins.
//!
//! A format plugin teaches Forge a package format by implementing
//! [`FormatPlugin`] (crate `forge-plugin-api`): the format's identity rules,
//! its package parser and its client protocol. Forge keeps everything else —
//! storage, metadata, authentication and authorization, hosted/group
//! semantics, retention, the streaming of package bytes.
//!
//! A [`Plugin`] is one installed plugin, of either kind:
//!
//! * **built in** ([`Plugin::builtin`]): a crate under `plugins/<id>/`
//!   linked into the server, called directly;
//! * **WebAssembly** ([`Plugin::load`]): the same kind of crate built as a
//!   component, loaded from a plugin directory against the SHA-256 the
//!   operator pinned, and run in a sandbox ([`WasmPlugin`], which implements
//!   [`FormatPlugin`] by calling into the component).
//!
//! Either way the server holds an `Arc<dyn FormatPlugin>` and cannot tell the
//! two apart. [`PluginFormat`] adapts a plugin to [`forge_core::Format`], so
//! hosted publishing, reads, groups and retention work for it unchanged.

mod format;
pub mod manifest;
#[cfg(feature = "testing")]
pub mod testing;
pub mod wasm;

use std::path::Path;
use std::sync::Arc;

pub use forge_plugin_api as api;
pub use forge_plugin_api::FormatPlugin;
pub use format::PluginFormat;
pub use manifest::Manifest;
pub use wasm::{HostLimits, Limits, WasmPlugin};

/// Errors loading a plugin.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// The plugin directory or component could not be read.
    #[error("{0}")]
    Io(String),
    /// `plugin.toml` is missing a key, malformed, or asks for too much.
    #[error("invalid plugin.toml: {0}")]
    Manifest(String),
    /// The component's SHA-256 is not the pinned one.
    #[error("component digest {actual} does not match the pinned {expected}")]
    Digest {
        /// The pinned digest.
        expected: String,
        /// The component's digest.
        actual: String,
    },
    /// The component does not compile or does not implement the world.
    #[error("invalid component: {0}")]
    Component(String),
    /// A call into a component trapped, ran out of fuel or time, or its
    /// instance could not be created.
    #[error("plugin call failed: {0}")]
    Trap(String),
}

/// Where a plugin's code comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Linked into the server.
    Builtin,
    /// A WebAssembly component.
    Wasm {
        /// The component's SHA-256 (lowercase hex).
        sha256: String,
    },
}

/// An installed format plugin: its `plugin.toml` and its implementation.
pub struct Plugin {
    manifest: Manifest,
    /// The format id, leaked once per plugin so [`forge_core::Format::id`]
    /// can hand out a `&'static str`.
    id: &'static str,
    origin: Origin,
    implementation: Arc<dyn FormatPlugin>,
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("id", &self.id)
            .field("version", &self.manifest.version)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl Plugin {
    /// A plugin built into the server: `plugin_toml` is its crate's
    /// `plugin.toml` ([`forge_plugin_api::plugin_toml!`]), `implementation`
    /// the format.
    pub fn builtin(
        plugin_toml: &str,
        implementation: impl FormatPlugin,
    ) -> Result<Arc<Self>, PluginError> {
        let manifest = Manifest::parse(plugin_toml)?;
        Ok(Self::new(
            manifest,
            Origin::Builtin,
            Arc::new(implementation),
        ))
    }

    /// Load the WebAssembly plugin in `dir`: read `plugin.toml`, check the
    /// component against `expected_sha256` (hex, optionally `sha256:`-prefixed;
    /// an operator pins every plugin), resolve its limits against `host`, and
    /// compile it.
    pub fn load(
        dir: &Path,
        expected_sha256: &str,
        host: &HostLimits,
    ) -> Result<Arc<Self>, PluginError> {
        let manifest = Manifest::load(dir)?;
        let Some(component) = &manifest.component else {
            return Err(PluginError::Manifest(
                "a WebAssembly plugin names its `component`".into(),
            ));
        };
        let path = dir.join(component);
        let bytes = std::fs::read(&path)
            .map_err(|e| PluginError::Io(format!("read {}: {e}", path.display())))?;
        Self::from_parts(manifest, &bytes, expected_sha256, host)
    }

    /// [`Self::load`] from a manifest and the component's bytes.
    pub fn from_parts(
        manifest: Manifest,
        component: &[u8],
        expected_sha256: &str,
        host: &HostLimits,
    ) -> Result<Arc<Self>, PluginError> {
        let wasm = WasmPlugin::new(&manifest, component, expected_sha256, host)?;
        let origin = Origin::Wasm {
            sha256: wasm.sha256().to_string(),
        };
        Ok(Self::new(manifest, origin, Arc::new(wasm)))
    }

    fn new(manifest: Manifest, origin: Origin, implementation: Arc<dyn FormatPlugin>) -> Arc<Self> {
        Arc::new(Plugin {
            id: Box::leak(manifest.id.clone().into_boxed_str()),
            manifest,
            origin,
            implementation,
        })
    }

    /// The format id.
    pub fn id(&self) -> &'static str {
        self.id
    }

    /// The parsed `plugin.toml`.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Where the plugin's code comes from.
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Whether the plugin is linked into the server.
    pub fn is_builtin(&self) -> bool {
        self.origin == Origin::Builtin
    }

    /// The component's SHA-256 (WebAssembly plugins only).
    pub fn sha256(&self) -> Option<&str> {
        match &self.origin {
            Origin::Builtin => None,
            Origin::Wasm { sha256 } => Some(sha256),
        }
    }

    /// The format, as the plugin implements it.
    pub fn implementation(&self) -> &Arc<dyn FormatPlugin> {
        &self.implementation
    }
}
