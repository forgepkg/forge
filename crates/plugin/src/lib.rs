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

pub mod descriptor;
mod format;

use std::sync::Arc;

pub use forge_plugin_api as api;
pub use forge_plugin_api::{Descriptor, FormatPlugin};
pub use format::{PluginFormat, UploadFormat};

/// An installed format plugin: its implementation, which describes itself
/// ([`FormatPlugin::descriptor`]).
pub struct Plugin {
    implementation: Arc<dyn FormatPlugin>,
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("id", &self.id())
            .field("version", &self.descriptor().version)
            .finish_non_exhaustive()
    }
}

impl Plugin {
    /// A plugin built into the server.
    pub fn builtin(implementation: impl FormatPlugin) -> Arc<Self> {
        Arc::new(Plugin {
            implementation: Arc::new(implementation),
        })
    }

    /// The format id.
    pub fn id(&self) -> &'static str {
        self.descriptor().id
    }

    /// What the format says about itself.
    pub fn descriptor(&self) -> &'static Descriptor {
        self.implementation.descriptor()
    }

    /// The format, as the plugin implements it.
    pub fn implementation(&self) -> &Arc<dyn FormatPlugin> {
        &self.implementation
    }
}
