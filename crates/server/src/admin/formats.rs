//! `GET /admin/formats` — the package formats this server can create
//! repositories of: the built-in format plugins (NuGet, Helm), Docker, raw
//! files, and every loaded WebAssembly plugin.

use axum::extract::State;
use axum::response::{IntoResponse, Json, Response};
use forge_db::model::{DOCKER_FORMAT, RAW_FORMAT};
use serde::Serialize;

use crate::state::AppState;

/// One installed format.
#[derive(Debug, Serialize)]
pub struct FormatView {
    /// The format id (`repository.format`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Whether the format is built into the server (Docker, raw and the
    /// built-in plugins) rather than loaded as a WebAssembly plugin.
    pub builtin: bool,
    /// The repository kinds it supports.
    pub kinds: Vec<&'static str>,
    /// Where its repositories are served: `{mount}/{repository}` (for
    /// Docker, `/v2/{repository}/{image}`, or a repository's own host).
    pub mount: String,
    /// The plugin's version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The plugin's description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// SHA-256 of the plugin's component (WebAssembly plugins only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The upload limit of its hosted repositories without one of their own
    /// (for docker, per blob).
    pub default_max_upload_bytes: u64,
    /// The largest upload limit a repository may be given (what a push can
    /// stage); `None` when it is unbounded.
    pub max_upload_bytes_limit: Option<u64>,
}

/// `GET /admin/formats`: NuGet first, then Docker, then the other formats
/// (the other plugins and raw files) by id.
pub async fn list(State(state): State<AppState>) -> Response {
    let kinds = |id: &str| state.formats.kinds(id).unwrap_or_default();
    let ceiling = state.config.max_repository_upload_bytes();
    let view = |plugin: &forge_plugin::Plugin| {
        let manifest = plugin.manifest();
        FormatView {
            id: plugin.id().to_string(),
            name: manifest.name.clone(),
            builtin: plugin.is_builtin(),
            kinds: kinds(plugin.id()),
            mount: manifest.mount.clone(),
            version: Some(manifest.version.clone()),
            description: manifest.description.clone(),
            sha256: plugin.sha256().map(str::to_string),
            default_max_upload_bytes: state.config.default_upload_limit(plugin.id()),
            max_upload_bytes_limit: ceiling,
        }
    };
    let mut plugins: Vec<_> = state.formats.plugins().collect();
    plugins.sort_by_key(|p| p.id());
    let (nuget, others): (Vec<_>, Vec<_>) = plugins.into_iter().partition(|p| p.id() == "nuget");
    let mut formats: Vec<FormatView> = nuget.into_iter().map(|p| view(p)).collect();
    formats.push(FormatView {
        id: DOCKER_FORMAT.to_string(),
        name: "Docker / OCI".into(),
        builtin: true,
        kinds: kinds(DOCKER_FORMAT),
        mount: "/v2".into(),
        version: None,
        description: None,
        sha256: None,
        default_max_upload_bytes: state.config.default_upload_limit(DOCKER_FORMAT),
        max_upload_bytes_limit: ceiling,
    });
    let mut others: Vec<FormatView> = others.into_iter().map(|p| view(p)).collect();
    others.push(FormatView {
        id: RAW_FORMAT.to_string(),
        name: "Raw files".into(),
        builtin: true,
        kinds: kinds(RAW_FORMAT),
        mount: crate::raw::MOUNT.into(),
        version: None,
        description: Some("Arbitrary files under arbitrary paths".into()),
        sha256: None,
        default_max_upload_bytes: state.config.default_upload_limit(RAW_FORMAT),
        max_upload_bytes_limit: ceiling,
    });
    others.sort_by(|a, b| a.id.cmp(&b.id));
    formats.extend(others);
    Json(formats).into_response()
}
