//! `forge-plugin`: the host side of format plugins.
//!
//! A format plugin teaches Forge a package format by implementing
//! [`FormatPlugin`] (crate `forge-plugin-api`): the format's identity rules,
//! its package parser and its client protocol. Forge keeps everything else —
//! storage, metadata, authentication and authorization, hosted/group
//! semantics, retention, the streaming of package bytes.
//!
//! A [`Plugin`] is one installed plugin: a crate under `crates/formats/<id>/`
//! linked into the server ([`Plugin::builtin`]) and called directly. The
//! server holds it as an `Arc<dyn FormatPlugin>`; [`PluginFormat`] adapts it
//! to [`forge_core::Format`], so hosted publishing, reads, groups and
//! retention work for it unchanged.

mod format;
pub mod manifest;

use std::sync::Arc;

pub use forge_plugin_api as api;
pub use forge_plugin_api::FormatPlugin;
pub use format::PluginFormat;
pub use manifest::Manifest;

/// Errors installing a plugin.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// `plugin.toml` is missing a key, malformed, or asks for too much.
    #[error("invalid plugin.toml: {0}")]
    Manifest(String),
}

/// An installed format plugin: its `plugin.toml` and its implementation.
pub struct Plugin {
    manifest: Manifest,
    /// The format id, leaked once per plugin so [`forge_core::Format::id`]
    /// can hand out a `&'static str`.
    id: &'static str,
    implementation: Arc<dyn FormatPlugin>,
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("id", &self.id)
            .field("version", &self.manifest.version)
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
        Ok(Arc::new(Plugin {
            id: Box::leak(manifest.id.clone().into_boxed_str()),
            manifest,
            implementation: Arc::new(implementation),
        }))
    }

    /// The format id.
    pub fn id(&self) -> &'static str {
        self.id
    }

    /// The parsed `plugin.toml`.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The format, as the plugin implements it.
    pub fn implementation(&self) -> &Arc<dyn FormatPlugin> {
        &self.implementation
    }
}
