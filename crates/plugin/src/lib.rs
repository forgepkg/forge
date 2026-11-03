//! `forge-plugin`: the host side of format plugins.
//!
//! A format plugin teaches Forge a package format by implementing
//! [`FormatPlugin`] (crate `forge-plugin-api`): the format's identity rules,
//! its package parser and its client protocol. Forge keeps everything else —
//! storage, metadata, authentication and authorization, hosted/group
//! semantics, retention, the streaming of package bytes.
//!
//! Every plugin is a crate under `crates/formats/<id>/` linked into the
//! server and called directly. The server holds each as an
//! `Arc<dyn FormatPlugin>`; [`PluginFormat`] adapts it to
//! [`forge_core::Format`], so hosted publishing, reads, groups and retention
//! work for it unchanged, and [`descriptor::check`] checks what the plugins
//! say about themselves.

pub mod descriptor;
mod format;

pub use forge_plugin_api as api;
pub use forge_plugin_api::{Descriptor, FormatPlugin};
pub use format::{PluginFormat, UploadFormat};
