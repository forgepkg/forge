//! `GET /admin/formats` — the package formats this server can create
//! repositories of: the format plugins (Docker / OCI, NuGet, npm, raw files,
//! apt),
//! each as its descriptor describes it.

use axum::extract::State;
use axum::response::{IntoResponse, Json, Response};
use forge_plugin::api::Storage;
use serde::Serialize;

use crate::state::AppState;

/// One installed format.
#[derive(Debug, Serialize)]
pub struct FormatView {
    /// The format id (`repository.format`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// The repository kinds it supports.
    pub kinds: Vec<&'static str>,
    /// What its repositories hold: `packages` (versions of packages),
    /// `files` (files under paths: raw) or `images` (Docker).
    pub storage: &'static str,
    /// The plugin's version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The plugin's description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The upload limit of its hosted repositories without one of their own
    /// (for docker, per blob).
    pub default_max_upload_bytes: u64,
    /// The largest upload limit a repository may be given (what a push can
    /// stage); `None` when it is unbounded.
    pub max_upload_bytes_limit: Option<u64>,
    /// The settings of the format's own its repositories carry
    /// (`options` of a repository).
    pub options: Vec<OptionView>,
    /// Its hosted repositories keep indexes signed with keys of their own
    /// (`/admin/repositories/{name}/signing-keys`): apt.
    pub signed_indexes: bool,
}

/// A setting of a format's own.
#[derive(Debug, Serialize)]
pub struct OptionView {
    pub name: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    /// The repository kinds that take it.
    pub kinds: Vec<&'static str>,
    /// Whether every repository of those kinds sets it.
    pub required: bool,
    pub example: &'static str,
}

/// `GET /admin/formats`: NuGet first, then the images formats (Docker),
/// then the other formats (raw files among them), each group by id.
pub async fn list(State(state): State<AppState>) -> Response {
    let kinds = |id: &str| state.formats.kinds(id).unwrap_or_default();
    let ceiling = state.config.max_repository_upload_bytes();
    let view = |plugin: &forge_plugin::Plugin| {
        let descriptor = plugin.descriptor();
        FormatView {
            id: plugin.id().to_string(),
            name: descriptor.name.to_string(),
            kinds: kinds(plugin.id()),
            storage: descriptor.storage.as_str(),
            version: Some(descriptor.version.to_string()),
            description: Some(descriptor.description.to_string()),
            default_max_upload_bytes: state.config.default_upload_limit(descriptor.storage),
            max_upload_bytes_limit: ceiling,
            options: descriptor
                .options
                .iter()
                .map(|option| OptionView {
                    name: option.name,
                    label: option.label,
                    description: option.description,
                    kinds: option.kinds.iter().map(|k| k.as_str()).collect(),
                    required: option.required,
                    example: option.example,
                })
                .collect(),
            signed_indexes: descriptor.indexes,
        }
    };
    let mut plugins: Vec<_> = state.formats.plugins().collect();
    plugins.sort_by_key(|p| {
        let group = match p.descriptor().storage {
            _ if p.id() == "nuget" => 0,
            Storage::Images => 1,
            Storage::Packages | Storage::Files => 2,
        };
        (group, p.id())
    });
    let formats: Vec<FormatView> = plugins.into_iter().map(|p| view(p)).collect();
    Json(formats).into_response()
}
