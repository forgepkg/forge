//! Static SPA serving (plan §12.6 Phase 1, §1/§2).
//!
//! The Rust `server` serves the **built TanStack Start SPA** so the UI and the
//! API live on a **single origin** — no CORS, no Node proxy in front of the Rust
//! API. The browser calls `/admin/*`, `/browse/*`, `/v3/*` directly.
//!
//! The asset layer is a [`tower_http::services::ServeDir`] over the configured
//! `web.assets_dir`, with `index.html` as the **SPA history fallback**: any path
//! that is not a real file resolves to `index.html` so the client-side router
//! (TanStack Router) can handle deep links like `/repos/foo`. The one exception
//! is the hashed-asset directory `/assets/*`: a missing file there is a plain
//! **404**, never `index.html` (a stale tab asking for the previous deploy's
//! chunk must get an error it can recover from, not HTML parsed as
//! JavaScript).
//!
//! ## Caching
//! * `index.html` (also when served as the SPA fallback) and every other
//!   non-hashed file: `Cache-Control: no-cache`, so a deploy is picked up on
//!   the next navigation.
//! * `/assets/*` (content-hashed by Vite): `public, max-age=31536000,
//!   immutable`; a miss there is `no-cache` so a 404 is never pinned.
//!
//! ## Route precedence (critical)
//! This fallback is mounted **last** in [`crate::app::build_router`], after the
//! `/admin`, `/browse`, and `/v3` routers. axum only routes to a `fallback`
//! when no other route matches, so a request to `/admin/...` (or `/v3/...`,
//! `/browse/...`) is always handled by its API router and never shadowed by the
//! SPA. Only genuine UI paths fall through to the SPA.
//!
//! The admin **UI** therefore lives under [`UI_ADMIN_PREFIX`] (`/manage/*`),
//! not `/admin/*`: a UI route sharing the API's paths would answer a refresh,
//! bookmark or deep link with raw JSON (or a 404/405). Links saved before the
//! move keep working through [`legacy_admin_ui_redirect`].

use std::path::PathBuf;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

use crate::config::WebConfig;

/// Path prefix of the admin UI in the SPA (the admin REST API keeps `/admin`).
pub const UI_ADMIN_PREFIX: &str = "/manage";

/// Vite's content-hashed output directory (`build.assetsDir`), as a URL prefix.
const ASSETS_PREFIX: &str = "/assets/";

/// `Cache-Control` for `index.html` and every other non-hashed file:
/// revalidate on every use so a new deploy is seen immediately.
const NO_CACHE: HeaderValue = HeaderValue::from_static("no-cache");

/// `Cache-Control` for a content-hashed `/assets/*` file: its URL changes with
/// its content, so it can be cached for a year without revalidation.
const IMMUTABLE: HeaderValue = HeaderValue::from_static("public, max-age=31536000, immutable");

/// The two file services behind [`spa_service`].
#[derive(Clone)]
struct Spa {
    /// Real files only; a miss is a plain 404 (used for `/assets/*`).
    files: ServeDir,
    /// Real files, with `index.html` as the SPA history fallback.
    shell: ServeDir<ServeFile>,
}

/// Build the static SPA file service from [`WebConfig`].
///
/// Returns a [`Router`] ready to be installed as the application router's
/// `fallback_service`. Because it is the router *fallback*, it only handles
/// requests that matched no API route.
///
/// * Real files are served as themselves (`/assets/app-*.js`).
/// * A missing file under `/assets/` is a **404** (no SPA fallback).
/// * Every other unknown path falls back to `index.html` (SPA history
///   fallback) so the client-side router (TanStack Router) resolves deep
///   links.
/// * `/` serves `index.html` (ServeDir appends the directory index by default).
/// * `Cache-Control` is set as described in the [module docs](self).
///
/// We use [`ServeDir::fallback`] (not `not_found_service`): `fallback` serves
/// the fallback's response **verbatim** (so a found `index.html` returns `200`),
/// whereas `not_found_service` forces the status to `404` — wrong for an SPA
/// history fallback where unknown client routes must return `200 index.html`.
///
/// The caller is responsible for only installing this when `web.enabled` is
/// true. If `index.html` is missing (UI not built), the fallback yields a 404 —
/// the API still works.
pub fn spa_service(cfg: &WebConfig) -> Router {
    let assets_dir = PathBuf::from(&cfg.assets_dir);
    let index = assets_dir.join("index.html");
    let spa = Spa {
        files: ServeDir::new(&assets_dir),
        shell: ServeDir::new(&assets_dir).fallback(ServeFile::new(index)),
    };
    Router::new().fallback(serve_spa).with_state(spa)
}

/// Serve one SPA request: hashed assets without a fallback, everything else
/// through the `index.html` history fallback, each with its `Cache-Control`.
async fn serve_spa(State(spa): State<Spa>, req: Request) -> Response {
    if req.uri().path().starts_with(ASSETS_PREFIX) {
        let mut res = match spa.files.oneshot(req).await {
            Ok(res) => res.into_response(),
            Err(never) => match never {},
        };
        // Only a hit is immutable; a 404 must not be cached for a year.
        let status = res.status();
        let cache = if status.is_success() || status == StatusCode::NOT_MODIFIED {
            IMMUTABLE
        } else {
            NO_CACHE
        };
        res.headers_mut().insert(header::CACHE_CONTROL, cache);
        res
    } else {
        let mut res = match spa.shell.oneshot(req).await {
            Ok(res) => res.into_response(),
            Err(never) => match never {},
        };
        res.headers_mut().insert(header::CACHE_CONTROL, NO_CACHE);
        res
    }
}

/// Middleware: 302-redirect a **browser navigation** to a former admin-UI path
/// (`/admin`, `/admin/repositories/foo`, ...) to its [`UI_ADMIN_PREFIX`]
/// equivalent (`/manage`, `/manage/repositories/foo`), keeping the query
/// string, so bookmarks and links from before the UI moved keep working.
///
/// Only top-level document loads are redirected (see
/// [`is_document_navigation`]): API clients — including the SPA's own
/// `fetch` calls (`Accept: application/json`, `Sec-Fetch-Dest: empty`) — and
/// every path the UI never used (`/admin/me`, `/admin/realms/order`,
/// `/admin/users/{id}/tokens`, ...) reach the admin API unchanged. Installed
/// only when the SPA is served.
pub async fn legacy_admin_ui_redirect(req: Request, next: Next) -> Response {
    match legacy_redirect_location(&req) {
        Some(location) => (
            StatusCode::FOUND,
            [
                (header::LOCATION, location),
                (
                    header::VARY,
                    HeaderValue::from_static("Accept, Sec-Fetch-Dest"),
                ),
            ],
        )
            .into_response(),
        None => next.run(req).await,
    }
}

/// The `Location` for a legacy admin-UI navigation, or `None` to pass the
/// request on.
fn legacy_redirect_location(req: &Request) -> Option<HeaderValue> {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return None;
    }
    let target = legacy_ui_path(req.uri().path())?;
    if !is_document_navigation(req.headers()) {
        return None;
    }
    let location = match req.uri().query() {
        Some(query) => format!("{target}?{query}"),
        None => target,
    };
    HeaderValue::from_str(&location).ok()
}

/// Map a path the admin UI used before it moved to [`UI_ADMIN_PREFIX`] to its
/// new equivalent; `None` for any other path (including every API-only path
/// under `/admin`).
///
/// The former UI routes were `/admin`, `/admin/repositories[/new|/{name}
/// [/members]]`, `/admin/users[/{id}]` and `/admin/realms[/new|/{id}]`. The
/// remaining path is reused verbatim (still percent-encoded), so the target is
/// always a same-origin path under `/manage`.
pub fn legacy_ui_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/admin")?;
    if rest.is_empty() || rest == "/" {
        return Some(UI_ADMIN_PREFIX.to_string());
    }
    // `/administrator` is not under `/admin`.
    let rest = rest.strip_prefix('/')?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.iter().any(|s| s.is_empty() || s.contains('\\')) {
        return None;
    }
    let was_ui = match segments.as_slice() {
        ["repositories"] | ["repositories", _] | ["repositories", _, "members"] => true,
        ["users"] | ["users", _] => true,
        ["realms"] => true,
        // `PUT /admin/realms/order` is API-only.
        ["realms", id] => *id != "order",
        _ => false,
    };
    was_ui.then(|| format!("{UI_ADMIN_PREFIX}/{rest}"))
}

/// Whether a request is a browser's top-level document navigation (address
/// bar, bookmark, link, refresh) rather than an API call.
///
/// `Sec-Fetch-Dest` is authoritative when present (every current browser
/// sends it): only `document` counts. Without it, an `Accept` header that
/// ranks `text/html` above JSON and wildcards counts (a browser's
/// `text/html,…,*/*;q=0.8`; not curl's `*/*` or an API client's
/// `application/json`).
fn is_document_navigation(headers: &HeaderMap) -> bool {
    if let Some(dest) = headers.get("sec-fetch-dest") {
        return dest.as_bytes().eq_ignore_ascii_case(b"document");
    }
    accept_prefers_html(headers)
}

/// Whether the `Accept` header gives `text/html` a higher quality than
/// `application/json` (or a wildcard that would match it).
fn accept_prefers_html(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let mut html = 0.0_f32;
    let mut other = 0.0_f32;
    for item in accept.split(',') {
        let mut parts = item.split(';');
        let media = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let q = parts
            .find_map(|param| {
                let (key, value) = param.split_once('=')?;
                key.trim()
                    .eq_ignore_ascii_case("q")
                    .then(|| value.trim().parse::<f32>().ok())
                    .flatten()
            })
            .unwrap_or(1.0);
        match media.as_str() {
            "text/html" | "application/xhtml+xml" => html = html.max(q),
            "application/json" | "application/*" | "*/*" => other = other.max(q),
            _ => {}
        }
    }
    html > 0.0 && html > other
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::fs;
    use tower::ServiceExt;

    fn fake_spa() -> (tempfile::TempDir, Router) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("index.html"), "INDEX").unwrap();
        fs::create_dir_all(dir.path().join("assets")).unwrap();
        fs::write(dir.path().join("assets").join("a.js"), "ASSET").unwrap();
        let cfg = WebConfig {
            enabled: true,
            assets_dir: dir.path().to_string_lossy().to_string(),
        };
        let svc = spa_service(&cfg);
        (dir, svc)
    }

    async fn get(svc: &Router, uri: &str) -> (StatusCode, Option<String>, Vec<u8>) {
        let res = svc
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let cache = res
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap().to_string());
        let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, cache, body)
    }

    #[tokio::test]
    async fn serves_index_for_root_and_unknown_paths() {
        let (_dir, svc) = fake_spa();

        // GET / -> index.html, never cached without revalidation.
        let (status, cache, body) = get(&svc, "/").await;
        assert_eq!(status, StatusCode::OK, "root status");
        assert_eq!(body, b"INDEX");
        assert_eq!(cache.as_deref(), Some("no-cache"));

        // GET /assets/a.js -> the asset, cacheable forever (content-hashed).
        let (status, cache, body) = get(&svc, "/assets/a.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"ASSET");
        assert_eq!(
            cache.as_deref(),
            Some("public, max-age=31536000, immutable")
        );

        // GET /deep/link -> index.html (SPA fallback), no-cache.
        let (status, cache, body) = get(&svc, "/deep/link").await;
        assert_eq!(status, StatusCode::OK, "deep link status");
        assert_eq!(body, b"INDEX");
        assert_eq!(cache.as_deref(), Some("no-cache"));
    }

    #[tokio::test]
    async fn missing_asset_is_404_not_index() {
        let (_dir, svc) = fake_spa();
        let (status, cache, body) = get(&svc, "/assets/gone-1234.js").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_ne!(body, b"INDEX");
        assert_eq!(cache.as_deref(), Some("no-cache"), "a miss is never pinned");
    }

    #[test]
    fn legacy_ui_paths_map_to_manage() {
        let cases = [
            ("/admin", "/manage"),
            ("/admin/", "/manage"),
            ("/admin/repositories", "/manage/repositories"),
            ("/admin/repositories/", "/manage/repositories"),
            ("/admin/repositories/new", "/manage/repositories/new"),
            ("/admin/repositories/nuget", "/manage/repositories/nuget"),
            (
                "/admin/repositories/all/members",
                "/manage/repositories/all/members",
            ),
            ("/admin/users", "/manage/users"),
            ("/admin/users/5", "/manage/users/5"),
            ("/admin/realms", "/manage/realms"),
            ("/admin/realms/new", "/manage/realms/new"),
            ("/admin/realms/3", "/manage/realms/3"),
        ];
        for (from, to) in cases {
            assert_eq!(legacy_ui_path(from).as_deref(), Some(to), "{from}");
        }
    }

    #[test]
    fn api_only_paths_are_not_mapped() {
        for path in [
            "/admin/me",
            "/admin/me/tokens",
            "/admin/realms/order",
            "/admin/users/5/tokens",
            "/admin/users/5/roles",
            "/admin/repositories/nuget/retention",
            "/admin/repositories/nuget/packages/a/1.0.0",
            "/admin/roles",
            "/admin/tokens/3",
            "/admin/crypto/keys",
            "/admin//repositories",
            "/administrator",
            "/manage/repositories",
            "/v3/nuget/index.json",
        ] {
            assert_eq!(legacy_ui_path(path), None, "{path}");
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn document_navigation_detection() {
        // A browser navigation (Chrome/Firefox send both headers).
        assert!(is_document_navigation(&headers(&[
            ("sec-fetch-dest", "document"),
            (
                "accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            ),
        ])));
        // Sec-Fetch-Dest is authoritative: a fetch() is never a navigation.
        assert!(!is_document_navigation(&headers(&[
            ("sec-fetch-dest", "empty"),
            ("accept", "text/html"),
        ])));
        // Without Sec-Fetch-Dest, Accept must rank HTML first.
        assert!(is_document_navigation(&headers(&[(
            "accept",
            "text/html,*/*;q=0.8"
        )])));
        assert!(is_document_navigation(&headers(&[(
            "accept",
            "text/html;q=0.9, application/json;q=0.5"
        )])));
        assert!(!is_document_navigation(&headers(&[(
            "accept",
            "application/json"
        )])));
        assert!(!is_document_navigation(&headers(&[("accept", "*/*")])));
        assert!(!is_document_navigation(&headers(&[(
            "accept",
            "text/html, application/json"
        )])));
        assert!(!is_document_navigation(&headers(&[(
            "accept",
            "text/html;q=0"
        )])));
        assert!(!is_document_navigation(&HeaderMap::new()));
    }
}
