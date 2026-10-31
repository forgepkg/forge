//! The addresses the server is reached under (#312), as **Admin → System**
//! shows them:
//!
//! * `GET /admin/addresses` → `{"public_base_url": "https://forge.example.com",
//!   "alias_base_urls": ["https://nexus.example.com"]}`: `server.public_base_url`
//!   and `server.alias_base_urls`, normalized ([`crate::base_urls`]). They are
//!   set in `forge.toml` (or `FORGE_SERVER__*`), so this is read-only.

use axum::extract::State;
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;

use crate::state::AppState;

/// `GET /admin/addresses`
pub async fn get(State(state): State<AppState>) -> Response {
    let aliases: Vec<&str> = state
        .base_urls
        .aliases()
        .iter()
        .map(|alias| alias.url.as_str())
        .collect();
    Json(json!({
        "public_base_url": state.base_urls.public(),
        "alias_base_urls": aliases,
    }))
    .into_response()
}
