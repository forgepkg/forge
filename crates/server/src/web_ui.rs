//! Static SPA serving.
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
//! ## Content Security Policy
//! Every SPA response carries [`spa_content_security_policy`]: scripts only
//! from this origin plus the inline theme bootstrap in `index.html`, allowed
//! by its SHA-256 hash (computed from the built `index.html` when the service
//! is built, so it always matches the file actually served). No `eval`, no
//! plugins, no `<base>` rewriting, no framing, and fetches only to this
//! origin — so markup that ever reaches the DOM cannot run script.
//!
//! ## Route precedence (critical)
//! This fallback is mounted **last** in [`crate::app::build_router`], after the
//! `/admin`, `/browse`, and `/v3` routers. axum only routes to a `fallback`
//! when no other route matches, so a request to `/admin/...` (or `/v3/...`,
//! `/browse/...`) is always handled by its API router and never shadowed by the
//! SPA. Only genuine UI paths fall through to the SPA.
//!
//! A path under those prefixes that no API route matches still reaches the
//! fallback (`Router::nest` does not carry a nested router's own fallback),
//! so the fallback answers it **404** itself ([`API_PREFIXES`]): a script
//! calling a mistyped or removed endpoint, or an old tab calling a renamed
//! one, gets an error, not `200` with `index.html`.
//!
//! The admin **UI** therefore lives under [`UI_ADMIN_PREFIX`] (`/manage/*`),
//! not `/admin/*`: a UI route sharing the API's paths would answer a refresh,
//! bookmark or deep link with raw JSON (or a 404/405).

use std::path::PathBuf;

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

use crate::config::WebConfig;

/// Path prefix of the admin UI in the SPA (the admin REST API keeps `/admin`).
pub const UI_ADMIN_PREFIX: &str = "/manage";

/// The API and feed prefixes. No SPA route lives under them, so a path there
/// that no API route matched answers 404 instead of `index.html`.
pub const API_PREFIXES: [&str; 6] = ["/admin", "/api", "/auth", "/browse", "/raw", "/v3"];

/// Whether `path` is `prefix` itself or lies under it (`/admin`, `/admin/x`;
/// not `/administrator`).
pub fn is_under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

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
    /// `Content-Security-Policy` for every SPA response.
    csp: HeaderValue,
}

/// Build the static SPA file service from [`WebConfig`].
///
/// Returns a [`Router`] ready to be installed as the application router's
/// `fallback_service`. Because it is the router *fallback*, it only handles
/// requests that matched no API route.
///
/// * Real files are served as themselves (`/assets/app-*.js`).
/// * A missing file under `/assets/` is a **404** (no SPA fallback), and so
///   is every path under [`API_PREFIXES`].
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
    // A missing index.html (UI not built) only drops the inline-script hashes;
    // the fallback then 404s anyway.
    let index_html = std::fs::read_to_string(&index).unwrap_or_default();
    let csp = HeaderValue::from_str(&spa_content_security_policy(&index_html))
        .expect("CSP is built from ASCII only");
    let spa = Spa {
        files: ServeDir::new(&assets_dir),
        shell: ServeDir::new(&assets_dir).fallback(ServeFile::new(index)),
        csp,
    };
    Router::new().fallback(serve_spa).with_state(spa)
}

/// Serve one SPA request: hashed assets without a fallback, everything else
/// through the `index.html` history fallback, each with its `Cache-Control`.
async fn serve_spa(State(spa): State<Spa>, req: Request) -> Response {
    let path = req.uri().path();
    if API_PREFIXES.iter().any(|prefix| is_under(path, prefix)) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    if path.starts_with(ASSETS_PREFIX) {
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
        res.headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, spa.csp);
        res
    } else {
        let mut res = match spa.shell.oneshot(req).await {
            Ok(res) => res.into_response(),
            Err(never) => match never {},
        };
        res.headers_mut().insert(header::CACHE_CONTROL, NO_CACHE);
        res.headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, spa.csp);
        res
    }
}

/// The SPA's `Content-Security-Policy`, allowing the inline (`src`-less)
/// scripts of `index_html` by their SHA-256 hashes and nothing else inline.
///
/// Styles keep `'unsafe-inline'`: the UI libraries set `style` attributes,
/// and CSS cannot run script. Everything else is same-origin only.
pub fn spa_content_security_policy(index_html: &str) -> String {
    // The HTML parser turns CRLF and a lone CR into LF before a script's text
    // is hashed, so an index.html with CRLF line endings (a Windows checkout)
    // must be hashed the same way.
    let index_html = index_html.replace("\r\n", "\n").replace('\r', "\n");
    let mut script_src = String::from("'self'");
    for script in inline_scripts(&index_html) {
        let digest = Sha256::digest(script.as_bytes());
        script_src.push_str(" 'sha256-");
        script_src.push_str(&base64::engine::general_purpose::STANDARD.encode(digest));
        script_src.push('\'');
    }
    format!(
        "default-src 'self'; script-src {script_src}; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; \
         base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
}

/// The bodies of the inline `<script>` elements (those without a `src`
/// attribute) of an HTML document, exactly as the browser hashes them.
fn inline_scripts(html: &str) -> Vec<&str> {
    let lower = html.to_ascii_lowercase();
    let mut scripts = Vec::new();
    let mut from = 0;
    while let Some(start) = lower[from..].find("<script").map(|i| from + i) {
        let Some(open_end) = lower[start..].find('>').map(|i| start + i) else {
            break;
        };
        let Some(close) = lower[open_end..].find("</script").map(|i| open_end + i) else {
            break;
        };
        let attributes = &lower[start + "<script".len()..open_end];
        let has_src = attributes
            .split(|c: char| c.is_ascii_whitespace())
            .any(|attr| attr == "src" || attr.starts_with("src="));
        if !has_src {
            scripts.push(&html[open_end + 1..close]);
        }
        from = close;
    }
    scripts
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
    async fn spa_responses_carry_a_script_restricting_csp() {
        let (_dir, svc) = fake_spa();
        for uri in ["/", "/deep/link", "/assets/a.js"] {
            let res = svc
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let csp = res
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap_or_else(|| panic!("{uri}: no CSP"))
                .to_str()
                .unwrap()
                .to_string();
            assert!(csp.contains("script-src 'self'"), "{uri}: {csp}");
            assert!(!csp.contains("unsafe-eval"), "{uri}: {csp}");
            assert!(csp.contains("object-src 'none'"), "{uri}: {csp}");
            assert!(csp.contains("frame-ancestors 'none'"), "{uri}: {csp}");
        }
    }

    #[test]
    fn csp_hashes_exactly_the_inline_theme_script_of_the_real_index_html() {
        let html = include_str!("../../../web/index.html");
        let scripts = inline_scripts(html);
        assert_eq!(scripts.len(), 1, "one inline script (the theme bootstrap)");
        assert!(scripts[0].contains("forge.theme"));
        let expected =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(scripts[0].as_bytes()));
        let csp = spa_content_security_policy(html);
        assert!(csp.contains(&format!("'sha256-{expected}'")), "{csp}");
        let script_src = csp
            .split(';')
            .map(str::trim)
            .find(|d| d.starts_with("script-src"))
            .unwrap();
        assert!(!script_src.contains("unsafe-inline"), "{script_src}");
    }

    #[test]
    fn csp_hashes_scripts_with_the_line_endings_the_browser_sees() {
        let lf = "<script>\nlet a = 1;\nlet b = 2;\n</script>";
        let crlf = "<script>\r\nlet a = 1;\r\nlet b = 2;\r\n</script>";
        let cr = "<script>\rlet a = 1;\rlet b = 2;\r</script>";
        let expected = spa_content_security_policy(lf);
        assert_eq!(spa_content_security_policy(crlf), expected);
        assert_eq!(spa_content_security_policy(cr), expected);
    }

    #[test]
    fn inline_script_extraction_skips_external_scripts() {
        let html = "<head><SCRIPT>a()</SCRIPT><script type=\"module\" src=\"/x.js\"></script>\
                    <script async src='/y.js'></script><script data-srcx=\"1\">b()</script></head>";
        assert_eq!(inline_scripts(html), vec!["a()", "b()"]);
        assert!(inline_scripts("<script>unterminated").is_empty());
    }

    #[tokio::test]
    async fn missing_asset_is_404_not_index() {
        let (_dir, svc) = fake_spa();
        let (status, cache, body) = get(&svc, "/assets/gone-1234.js").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_ne!(body, b"INDEX");
        assert_eq!(cache.as_deref(), Some("no-cache"), "a miss is never pinned");
    }
}
