//! `GET /admin/formats` — the package formats this server can create
//! repositories of: NuGet, the built-in format plugins, and every loaded
//! WebAssembly plugin.

use axum::extract::State;
use axum::response::{IntoResponse, Json, Response};
use serde::Serialize;

use crate::state::AppState;

/// One installed format.
#[derive(Debug, Serialize)]
pub struct FormatView {
    /// The format id (`repository.format`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Whether the format is built into the server (NuGet and the built-in
    /// plugins) rather than loaded as a WebAssembly plugin.
    pub builtin: bool,
    /// The repository kinds it supports.
    pub kinds: Vec<&'static str>,
    /// Where its repositories are served: `{mount}/{repository}`.
    pub mount: &'static str,
    /// Plugin version (plugins only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Plugin description (plugins only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// SHA-256 of the plugin's component (WebAssembly plugins only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// `GET /admin/formats`
pub async fn list(State(state): State<AppState>) -> Response {
    let mut formats = vec![FormatView {
        id: state.formats.nuget().id().to_string(),
        name: "NuGet".into(),
        builtin: true,
        kinds: vec!["hosted", "proxy", "group"],
        mount: "/v3",
        version: None,
        description: None,
        sha256: None,
    }];
    formats.extend(state.formats.plugins().map(|plugin| {
        let manifest = plugin.manifest();
        FormatView {
            id: plugin.id().to_string(),
            name: manifest.name.clone(),
            builtin: plugin.is_builtin(),
            kinds: vec!["hosted", "group"],
            mount: crate::plugins::MOUNT,
            version: Some(manifest.version.clone()),
            description: manifest.description.clone(),
            sha256: plugin.sha256().map(str::to_string),
        }
    }));
    Json(formats).into_response()
}
