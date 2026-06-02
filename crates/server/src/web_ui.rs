//! Static SPA serving (plan §12.6 Phase 1, §1/§2).
//!
//! The Rust `server` serves the **built TanStack Start SPA** so the UI and the
//! API live on a **single origin** — no CORS, no Node proxy in front of the Rust
//! API. The browser calls `/admin/*`, `/browse/*`, `/v3/*` directly.
//!
//! The asset layer is a [`tower_http::services::ServeDir`] over the configured
//! `web.assets_dir`, with `index.html` as the **SPA history fallback**: any path
//! that is not a real file resolves to `index.html` so the client-side router
//! (TanStack Router) can handle deep links like `/repositories/foo`.
//!
//! ## Route precedence (critical)
//! This fallback is mounted **last** in [`crate::app::build_router`], after the
//! `/admin`, `/browse`, and `/v3` routers. axum only routes to a `fallback`
//! when no other route matches, so a request to `/admin/...` (or `/v3/...`,
//! `/browse/...`) is always handled by its API router and never shadowed by the
//! SPA. Only genuine UI paths fall through to the SPA.

use std::path::PathBuf;

use tower_http::services::{ServeDir, ServeFile};

use crate::config::WebConfig;

/// Build the static SPA file service from [`WebConfig`].
///
/// Returns a [`ServeDir`] (with an `index.html` not-found fallback) ready to be
/// installed as the application router's `fallback_service`. Because it is the
/// router *fallback*, it only handles requests that matched no API route.
///
/// * Real files are served as themselves (`/assets/app-*.js`).
/// * Unknown paths fall back to `index.html` (SPA history fallback) so the
///   client-side router (TanStack Router) resolves deep links.
/// * `/` serves `index.html` (ServeDir appends the directory index by default).
///
/// We use [`ServeDir::fallback`] (not `not_found_service`): `fallback` serves
/// the fallback's response **verbatim** (so a found `index.html` returns `200`),
/// whereas `not_found_service` forces the status to `404` — wrong for an SPA
/// history fallback where unknown client routes must return `200 index.html`.
///
/// The caller is responsible for only installing this when `web.enabled` is
/// true. If `index.html` is missing (UI not built), the fallback yields a 404 —
/// the API still works.
pub fn spa_service(cfg: &WebConfig) -> ServeDir<ServeFile> {
    let assets_dir = PathBuf::from(&cfg.assets_dir);
    let index = assets_dir.join("index.html");
    ServeDir::new(&assets_dir).fallback(ServeFile::new(index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::fs;
    use tower::ServiceExt;

    #[tokio::test]
    async fn serves_index_for_root_and_unknown_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("index.html"), "INDEX").unwrap();
        fs::create_dir_all(dir.path().join("assets")).unwrap();
        fs::write(dir.path().join("assets").join("a.js"), "ASSET").unwrap();

        let cfg = WebConfig {
            enabled: true,
            assets_dir: dir.path().to_string_lossy().to_string(),
        };
        let svc = spa_service(&cfg);

        // GET / -> index.html
        let res = svc
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "root status");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"INDEX");

        // GET /assets/a.js -> the asset
        let res = svc
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/assets/a.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ASSET");

        // GET /deep/link -> index.html (SPA fallback)
        let res = svc
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/deep/link")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "deep link status");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"INDEX");
    }
}
