//! An npm registry as an import's source: Nexus' `…/repository/<name>`,
//! Verdaccio, Artifactory or another Forge. Where to ask and how to read the
//! answers is the npm format's ([`forge_format_npm::import`], with the
//! packument reader npm proxies use); this sends the requests, through the
//! shared [`UpstreamHttp`] client (timeouts, size caps, no cloud-metadata
//! targets), with the credentials, as Basic authentication.
//!
//! Every request goes to the registry's URL, the one the import was given:
//! a tarball too ([`NpmRegistry::tarball_url`]), whatever host its
//! `dist.tarball` names.
//! So the credentials go to that origin alone.

use forge_core::net::upstream::{Origin, RequestClass, UpstreamAuth, UpstreamError, UpstreamHttp};
use forge_crypto::{ExposeSecret, PlaintextSecret};
use forge_format_npm::import::{self as npm, Package, SearchPage};
use forge_format_npm::proxy::{ABBREVIATED_ACCEPT, FULL_ACCEPT};
use forge_format_npm::PackageName;
use reqwest::StatusCode;

use super::SourceError;

/// Pages of a search for a scope read at most.
const MAX_SCOPE_PAGES: u32 = 1000;

/// An npm registry.
pub struct NpmRegistry {
    http: UpstreamHttp,
    /// Without a trailing `/`.
    url: String,
    username: Option<String>,
    password: Option<PlaintextSecret>,
    /// The `Server` header the registry answered [`Self::ping`] with.
    server: Option<String>,
}

/// A status by which a registry says it does not serve a listing: Verdaccio
/// refuses a search without text (400); a registry that dropped `/-/all`
/// may answer 405, 410 or 501 rather than 404.
fn not_served(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::GONE
            | StatusCode::NOT_IMPLEMENTED
    )
}

impl NpmRegistry {
    /// The registry at `url`, read with the credentials when given.
    pub fn new(
        http: UpstreamHttp,
        url: &str,
        username: Option<String>,
        password: Option<PlaintextSecret>,
    ) -> Self {
        NpmRegistry {
            http,
            url: url.trim_end_matches('/').to_string(),
            username,
            password,
            server: None,
        }
    }

    /// The `Server` header the registry answered [`Self::ping`] with.
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// The Basic credentials, for the registry's origin only.
    fn auth(&self) -> Option<UpstreamAuth<'_>> {
        match (&self.username, &self.password) {
            (Some(username), Some(password)) => Some(UpstreamAuth {
                origin: Origin::of(&self.url),
                username,
                password: password.expose_secret(),
                bearer: false,
            }),
            _ => None,
        }
    }

    /// `GET /-/ping`: an unreachable registry, or one that refuses the
    /// credentials, is an error. One that does not serve the ping is let
    /// through: its listing, or its packages, say more. Records the
    /// `Server` header.
    pub async fn ping(&mut self) -> Result<(), SourceError> {
        let url = format!("{}/-/ping", self.url);
        let response = self
            .http
            .get(&url, RequestClass::Metadata, self.auth().as_ref())
            .await
            .map_err(|e| SourceError::of(e, &url))?;
        self.server = response
            .headers()
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let status = response.status();
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
            || status.is_server_error()
        {
            return Err(SourceError::status(status, &url));
        }
        Ok(())
    }

    /// A metadata document (`Ok(None)`: the registry does not have it, or
    /// does not serve it), streamed into a spool rather than held whole.
    async fn document(
        &self,
        url: &str,
        accept: &str,
    ) -> Result<Option<forge_core::net::upstream::SpooledBody>, SourceError> {
        match self
            .http
            .get_metadata_body(url, self.auth().as_ref(), Some(accept))
            .await
        {
            Ok(body) => Ok(body),
            Err(UpstreamError::Status { status, .. }) if not_served(status) => Ok(None),
            Err(e) => Err(SourceError::of(e, url)),
        }
    }

    /// A page of the registry's search for `text` (empty: every package),
    /// `size` packages after the first `from`. `None` when the registry
    /// offers no such search.
    pub async fn search(
        &self,
        text: &str,
        from: u32,
        size: u32,
    ) -> Result<Option<SearchPage>, SourceError> {
        let url = npm::search_url(&self.url, text, from, size);
        let Some(body) = self.document(&url, FULL_ACCEPT).await? else {
            return Ok(None);
        };
        read(body, move |reader| {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(reader, &mut bytes).map_err(|e| e.to_string())?;
            npm::read_search(&bytes)
        })
        .await
        .map(Some)
    }

    /// Every package `/-/all` lists, sorted; `None` when the registry does
    /// not serve it.
    pub async fn all(&self) -> Result<Option<Vec<String>>, SourceError> {
        let url = format!("{}{}", self.url, npm::ALL_PATH);
        let Some(body) = self.document(&url, FULL_ACCEPT).await? else {
            return Ok(None);
        };
        read(body, |reader| npm::read_all(reader)).await.map(Some)
    }

    /// The packages of `scope` (`@acme`) the registry's search finds, read
    /// page by page up to an empty page (or the same page again: a search
    /// that ignores `from`).
    pub async fn search_scope(&self, scope: &str) -> Result<Vec<String>, SourceError> {
        let prefix = format!("{scope}/");
        let mut found: Vec<String> = Vec::new();
        let mut last: Vec<String> = Vec::new();
        // A registry may answer fewer than it was asked for: the next page
        // starts after what it answered.
        let mut from = 0u32;
        for _ in 0..MAX_SCOPE_PAGES {
            let Some(page) = self.search(scope, from, npm::MAX_SEARCH_SIZE).await? else {
                break;
            };
            if page.names.is_empty() || page.names == last {
                break;
            }
            from = from.saturating_add(u32::try_from(page.names.len()).unwrap_or(u32::MAX));
            for name in &page.names {
                if name.starts_with(&prefix) && !found.contains(name) {
                    found.push(name.clone());
                }
            }
            last = page.names;
        }
        found.sort();
        Ok(found)
    }

    /// The package `name`, from its full packument; `None` when the registry
    /// does not have it. A full packument larger than Forge reads
    /// (`proxy.max_metadata_bytes`) is read abbreviated, without its publish
    /// times.
    pub async fn package(&self, name: &str) -> Result<Option<Package>, SourceError> {
        let name = PackageName::parse(name)
            .map_err(|e| SourceError::Invalid(format!("{name:?} is no package name: {e}")))?;
        let url = npm::packument_url(&self.url, &name);
        let body = match self
            .http
            .get_metadata_body(&url, self.auth().as_ref(), Some(FULL_ACCEPT))
            .await
        {
            Ok(body) => body,
            Err(UpstreamError::TooLarge { .. }) => {
                tracing::warn!(package = %name, "import: the full packument is too large; reading it abbreviated, without publish times");
                self.http
                    .get_metadata_body(&url, self.auth().as_ref(), Some(ABBREVIATED_ACCEPT))
                    .await
                    .map_err(|e| SourceError::of(e, &url))?
            }
            Err(e) => return Err(SourceError::of(e, &url)),
        };
        let Some(body) = body else {
            return Ok(None);
        };
        read(body, move |reader| npm::read_package(reader, &name))
            .await
            .map(Some)
    }

    /// Where the import downloads the tarball `file` of `name`.
    pub fn tarball_url(&self, name: &str, file: &str) -> Option<String> {
        let name = PackageName::parse(name).ok()?;
        Some(npm::tarball_url(&self.url, &name, file))
    }

    /// GET a tarball (streamed by the caller), at the registry's origin.
    pub async fn download(&self, url: &str) -> Result<reqwest::Response, SourceError> {
        if Origin::of(url) != Origin::of(&self.url) {
            return Err(SourceError::Invalid(format!(
                "{url} is not at the registry's origin"
            )));
        }
        let response = self
            .http
            .get(url, RequestClass::Download, self.auth().as_ref())
            .await
            .map_err(|e| SourceError::of(e, url))?;
        if !response.status().is_success() {
            return Err(SourceError::status(response.status(), url));
        }
        Ok(response)
    }
}

/// Read a spooled document with `parse`, on the blocking pool.
async fn read<T: Send + 'static>(
    body: forge_core::net::upstream::SpooledBody,
    parse: impl FnOnce(&mut dyn std::io::Read) -> Result<T, String> + Send + 'static,
) -> Result<T, SourceError> {
    tokio::task::spawn_blocking(move || {
        let mut reader = body.into_reader().map_err(|e| e.to_string())?;
        parse(&mut reader)
    })
    .await
    .map_err(|e| SourceError::Invalid(format!("reading the registry's answer: {e}")))?
    .map_err(SourceError::Invalid)
}
