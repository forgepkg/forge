//! Proxy repositories: a pull-through cache of an upstream registry
//! (Docker Hub, GHCR, Quay, MCR or any distribution-spec registry).
//!
//! * Blobs and digest-addressed manifests are immutable: once fetched (and
//!   verified against their digest) they are served from the CAS for good.
//! * A tag is re-validated after the repository's metadata TTL with a `HEAD`
//!   (which Docker Hub does not count against its pull rate limit); while
//!   the upstream is unreachable, or the repository is offline, the cached
//!   tag is served.
//! * Multi-arch indexes are cached as they are; their child manifests are
//!   fetched when a client asks for them.
//! * Docker Hub's implicit `library/` namespace applies to one-component
//!   names (`nginx` is `library/nginx`), locally as well, so both spellings
//!   share one cache.
//!
//! Upstream requests go through the shared [`UpstreamHttp`] client (metadata
//! guard, timeouts, redirects without credentials). Docker's token flow is
//! followed: a `401` with a `Bearer` challenge sends the upstream credentials
//! to the token realm that challenge names, and the token is cached until it
//! expires.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use bytes::Bytes;
use forge_core::net::upstream::{Origin, RequestClass};
use forge_core::repo::proxy::{upstream_credentials, Credentials};
use forge_db::model::Repository;
use forge_db::oci_dao::{self, LinkOutcome};
use futures_util::{StreamExt, TryStreamExt};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::Method;

use crate::digest::Digest;
use crate::error::{Code, OciError, OciResult};
use crate::manifest::{self, media, MAX_MANIFEST_BYTES};
use crate::pull::{BlobHit, ManifestHit, ReferrerDescriptor};
use crate::push::require_linked;
use crate::reference::{self, Reference};
use crate::service::{Registry, Target};

/// Hosts of Docker Hub's registry, whose one-component names live in
/// `library/`.
const DOCKER_HUB_HOSTS: &[&str] = &[
    "registry-1.docker.io",
    "index.docker.io",
    "docker.io",
    "registry.hub.docker.com",
];

/// How long a tag is served without asking the upstream, unless the
/// repository sets `metadata_ttl_seconds`.
const DEFAULT_TAG_TTL_SECS: i64 = 600;

/// How long an upstream "not found" is remembered, unless the repository
/// sets `not_found_ttl_seconds`.
const DEFAULT_NOT_FOUND_TTL_SECS: u64 = 60;

/// Largest blob read as a possible image config.
const MAX_CONFIG_BYTES: i64 = 1024 * 1024;

/// Largest upstream tag list or referrers document read.
const MAX_LISTING_BYTES: usize = 16 * 1024 * 1024;

/// Cached upstream registry tokens: key → (token, expiry).
static TOKENS: LazyLock<Mutex<HashMap<String, (String, Instant)>>> =
    LazyLock::new(Default::default);

/// In-flight first-time blob downloads, so concurrent pulls of one layer
/// share a single upstream fetch per process.
static GATES: LazyLock<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(Default::default);

fn gate(key: String) -> Arc<tokio::sync::Mutex<()>> {
    let mut gates = GATES.lock().unwrap_or_else(|p| p.into_inner());
    gates.retain(|_, weak| weak.strong_count() > 0);
    if let Some(existing) = gates.get(&key).and_then(Weak::upgrade) {
        return existing;
    }
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    gates.insert(key, Arc::downgrade(&gate));
    gate
}

fn cached_token(key: &str) -> Option<String> {
    let tokens = TOKENS.lock().unwrap_or_else(|p| p.into_inner());
    tokens
        .get(key)
        .filter(|(_, expiry)| *expiry > Instant::now())
        .map(|(token, _)| token.clone())
}

fn cache_token(key: String, token: String, ttl: Duration) {
    let mut tokens = TOKENS.lock().unwrap_or_else(|p| p.into_inner());
    if tokens.len() > 4096 {
        let now = Instant::now();
        tokens.retain(|_, (_, expiry)| *expiry > now);
    }
    tokens.insert(key, (token, Instant::now() + ttl));
}

/// The upstream base URL of a proxy: `remote_url` without a trailing `/`
/// (and without a `/v2` suffix an admin may have pasted).
pub(crate) fn upstream_base(remote_url: &str) -> String {
    let base = remote_url.trim_end_matches('/');
    base.strip_suffix("/v2").unwrap_or(base).to_string()
}

fn is_docker_hub(remote_url: &str) -> bool {
    url::Url::parse(remote_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|h| DOCKER_HUB_HOSTS.contains(&h.as_str()))
}

/// The image name a proxy stores and asks its upstream for.
pub(crate) fn proxied_image(repo: &Repository, image: &str) -> String {
    match &repo.remote_url {
        Some(remote) if is_docker_hub(remote) && !image.contains('/') => format!("library/{image}"),
        _ => image.to_string(),
    }
}

/// A parsed `WWW-Authenticate` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Challenge {
    Bearer {
        realm: String,
        service: Option<String>,
        scope: Option<String>,
    },
    Basic,
}

fn parse_challenge(value: &str) -> Option<Challenge> {
    let (scheme, params) = value.trim().split_once(' ').unwrap_or((value.trim(), ""));
    if scheme.eq_ignore_ascii_case("basic") {
        return Some(Challenge::Basic);
    }
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut map = HashMap::new();
    let mut rest = params.trim();
    while !rest.is_empty() {
        let (key, after) = rest.split_once('=')?;
        let key = key
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_ascii_lowercase();
        let after = after.trim_start();
        let (val, remaining) = if let Some(quoted) = after.strip_prefix('"') {
            let end = quoted.find('"')?;
            (&quoted[..end], &quoted[end + 1..])
        } else {
            let end = after.find(',').unwrap_or(after.len());
            (&after[..end], &after[end..])
        };
        map.insert(key, val.to_string());
        rest = remaining.trim_start().trim_start_matches(',').trim_start();
    }
    Some(Challenge::Bearer {
        realm: map.remove("realm")?,
        service: map.remove("service"),
        scope: map.remove("scope"),
    })
}

/// Read at most `limit` bytes of an upstream body.
async fn read_limited(response: reqwest::Response, limit: usize) -> OciResult<Bytes> {
    if response.content_length().is_some_and(|l| l > limit as u64) {
        return Err(OciError::unavailable("the upstream response is too large"));
    }
    let mut stream = response.bytes_stream();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| upstream_unreachable(&e))?;
        if out.len() + chunk.len() > limit {
            return Err(OciError::unavailable("the upstream response is too large"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

fn upstream_unreachable(e: &dyn std::fmt::Display) -> OciError {
    tracing::warn!(error = %e, "registry proxy: upstream request failed");
    OciError::unavailable("the upstream registry is unreachable")
}

/// The error a non-success upstream status turns into.
fn upstream_status(status: reqwest::StatusCode) -> OciError {
    match status.as_u16() {
        429 => OciError::new(
            StatusCode::TOO_MANY_REQUESTS,
            Code::TooManyRequests,
            "the upstream registry rate-limits this proxy; retry later",
        ),
        401 | 403 => {
            tracing::warn!(%status, "registry proxy: upstream refused the request");
            OciError::unavailable("the upstream registry refused the proxy's credentials")
        }
        _ => {
            tracing::warn!(%status, "registry proxy: upstream answered with an error");
            OciError::unavailable("the upstream registry answered with an error")
        }
    }
}

/// One proxy repository's upstream, for one request.
struct Upstream<'a> {
    reg: &'a Registry,
    repo: &'a Repository,
    base: String,
    creds: Option<Credentials>,
}

impl Upstream<'_> {
    fn token_key(&self, scope: &str) -> String {
        format!("{}:{}:{scope}", self.repo.id, self.base)
    }

    async fn attempt(
        &self,
        method: Method,
        url: &str,
        accept: Option<&str>,
        class: RequestClass,
        bearer: Option<&str>,
        basic: bool,
    ) -> OciResult<reqwest::Response> {
        let mut headers = HeaderMap::new();
        if let Some(accept) = accept {
            if let Ok(v) = HeaderValue::from_str(accept) {
                headers.insert(ACCEPT, v);
            }
        }
        if let Some(token) = bearer {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(AUTHORIZATION, v);
            }
        }
        let auth = if basic {
            self.creds.as_ref().map(Credentials::auth)
        } else {
            None
        };
        self.reg
            .inner
            .http
            .send(method, url, class, headers, auth.as_ref())
            .await
            .map_err(|e| upstream_unreachable(&e))
    }

    /// Send a request for `path` (`/v2/…`), answering the upstream's
    /// authentication challenge once.
    async fn send(
        &self,
        method: Method,
        path: &str,
        scope: &str,
        accept: Option<&str>,
        class: RequestClass,
    ) -> OciResult<reqwest::Response> {
        let url = format!("{}{path}", self.base);
        let key = self.token_key(scope);
        let cached = cached_token(&key);
        let response = self
            .attempt(
                method.clone(),
                &url,
                accept,
                class,
                cached.as_deref(),
                false,
            )
            .await?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let challenge = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_challenge);
        match challenge {
            Some(Challenge::Bearer {
                realm,
                service,
                scope: challenged,
            }) => {
                let scope = challenged.unwrap_or_else(|| scope.to_string());
                let token = self.fetch_token(&realm, service.as_deref(), &scope).await?;
                cache_token(key, token.0.clone(), token.1);
                self.attempt(method, &url, accept, class, Some(&token.0), false)
                    .await
            }
            Some(Challenge::Basic) if self.creds.is_some() => {
                self.attempt(method, &url, accept, class, None, true).await
            }
            _ => Ok(response),
        }
    }

    /// A token from the realm an upstream challenge named. The upstream's
    /// credentials go to that realm (Docker Hub: `auth.docker.io`), but only
    /// over https when the upstream itself is https.
    async fn fetch_token(
        &self,
        realm: &str,
        service: Option<&str>,
        scope: &str,
    ) -> OciResult<(String, Duration)> {
        let parsed = url::Url::parse(realm)
            .map_err(|_| OciError::unavailable("the upstream named an invalid token realm"))?;
        let upstream_https = self.base.starts_with("https://");
        if !matches!(parsed.scheme(), "https" | "http")
            || (upstream_https && parsed.scheme() != "https")
        {
            return Err(OciError::unavailable(
                "the upstream named a token realm Forge will not send credentials to",
            ));
        }
        let mut url = parsed.clone();
        {
            let mut q = url.query_pairs_mut();
            if let Some(service) = service {
                q.append_pair("service", service);
            }
            q.append_pair("scope", scope);
        }
        let auth = match (&self.creds, Origin::of(realm)) {
            (Some(creds), Some(origin)) => Some(creds.auth_for(origin)),
            _ => None,
        };
        let response = self
            .reg
            .inner
            .http
            .send(
                Method::GET,
                url.as_str(),
                RequestClass::Metadata,
                HeaderMap::new(),
                auth.as_ref(),
            )
            .await
            .map_err(|e| upstream_unreachable(&e))?;
        if !response.status().is_success() {
            return Err(upstream_status(response.status()));
        }
        let body = read_limited(response, 1024 * 1024).await?;
        #[derive(serde::Deserialize)]
        struct TokenResponse {
            token: Option<String>,
            access_token: Option<String>,
            expires_in: Option<u64>,
        }
        let parsed: TokenResponse = serde_json::from_slice(&body)
            .map_err(|_| OciError::unavailable("the upstream token service answered nonsense"))?;
        let token = parsed
            .token
            .or(parsed.access_token)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| OciError::unavailable("the upstream token service sent no token"))?;
        let ttl = parsed.expires_in.unwrap_or(60).saturating_sub(10).max(10);
        Ok((token, Duration::from_secs(ttl)))
    }
}

impl Registry {
    async fn upstream<'a>(&'a self, repo: &'a Repository) -> OciResult<Upstream<'a>> {
        let remote = repo
            .remote_url
            .as_deref()
            .ok_or_else(|| OciError::internal("proxy", "proxy repository without remote_url"))?;
        let creds = upstream_credentials(&self.inner.pool, self.inner.envelope.as_ref(), repo)
            .await
            .map_err(|e| OciError::internal("proxy credentials", e))?;
        Ok(Upstream {
            reg: self,
            repo,
            base: upstream_base(remote),
            creds,
        })
    }

    fn not_found_key(repo: &Repository, image: &str, reference: &str) -> String {
        format!("{}:{image}:{reference}", repo.id)
    }

    async fn negative_cached(&self, repo: &Repository, image: &str, reference: &str) -> bool {
        let key = Self::not_found_key(repo, image, reference);
        let hit: Result<bool, ()> = self
            .inner
            .cache
            .get_or_try_insert_local("oci:upstream-nf", &key, Duration::from_secs(1), || async {
                Err(())
            })
            .await;
        hit.unwrap_or(false)
    }

    async fn remember_not_found(&self, repo: &Repository, image: &str, reference: &str) {
        let ttl = repo
            .not_found_ttl_seconds
            .map(|s| s.max(0) as u64)
            .unwrap_or(DEFAULT_NOT_FOUND_TTL_SECS);
        if ttl == 0 {
            return;
        }
        let key = Self::not_found_key(repo, image, reference);
        let _: Result<bool, ()> = self
            .inner
            .cache
            .get_or_try_insert_local(
                "oci:upstream-nf",
                &key,
                Duration::from_secs(ttl),
                || async { Ok(true) },
            )
            .await;
    }

    pub(crate) async fn proxy_manifest(
        &self,
        repo: &Repository,
        image: &str,
        reference: &Reference,
    ) -> OciResult<Option<ManifestHit>> {
        let local = proxied_image(repo, image);
        let target = Target {
            repo: repo.clone(),
            image: local.clone(),
            name: local.clone(),
        };
        let pool = &self.inner.pool;
        let accept = media::ACCEPT_ALL.join(", ");
        let scope = format!("repository:{local}:pull");
        match reference {
            Reference::Digest(digest) => {
                if let Some(row) =
                    oci_dao::find_manifest(pool, repo.id, &local, digest.as_str()).await?
                {
                    return Ok(Some(ManifestHit::from_row(row)));
                }
                if !repo.online || self.negative_cached(repo, &local, digest.as_str()).await {
                    return Ok(None);
                }
                let upstream = self.upstream(repo).await?;
                let response = upstream
                    .send(
                        Method::GET,
                        &format!("/v2/{local}/manifests/{digest}"),
                        &scope,
                        Some(&accept),
                        RequestClass::Metadata,
                    )
                    .await?;
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    self.remember_not_found(repo, &local, digest.as_str()).await;
                    return Ok(None);
                }
                if !response.status().is_success() {
                    return Err(upstream_status(response.status()));
                }
                let content_type = content_type(&response);
                let body = read_limited(response, MAX_MANIFEST_BYTES).await?;
                if Digest::of(digest.algorithm(), &body) != *digest {
                    tracing::warn!(repo = %repo.name, image = %local, %digest, "registry proxy: upstream manifest does not match its digest");
                    return Err(OciError::unavailable(
                        "the upstream served a manifest that does not match its digest",
                    ));
                }
                let parsed = manifest::parse(&body, content_type.as_deref()).map_err(|_| {
                    OciError::unavailable("the upstream served an invalid manifest")
                })?;
                let row = self
                    .store_proxied_manifest(&target, digest, &parsed, &body, None)
                    .await?;
                let mut hit = ManifestHit::from_row(row);
                hit.bytes = Some(body);
                Ok(Some(hit))
            }
            Reference::Tag(tag) => {
                let cached = oci_dao::find_tag(pool, repo.id, &local, tag).await?;
                if !repo.online {
                    return Ok(cached.map(|c| ManifestHit::from_row(c.manifest)));
                }
                let ttl = repo
                    .metadata_ttl_seconds
                    .map(i64::from)
                    .unwrap_or(DEFAULT_TAG_TTL_SECS);
                if let Some(c) = &cached {
                    let now = forge_db::db_now(pool).await?;
                    if (now - c.checked_at).num_seconds() < ttl {
                        return Ok(Some(ManifestHit::from_row(c.manifest.clone())));
                    }
                } else if self.negative_cached(repo, &local, tag).await {
                    return Ok(None);
                }
                match self
                    .revalidate_tag(repo, &target, tag, &scope, &accept, cached.as_ref())
                    .await
                {
                    Ok(found) => Ok(found),
                    Err(e) => match cached {
                        Some(c) => {
                            tracing::warn!(
                                repo = %repo.name, image = %local, %tag, error = %e.message,
                                "registry proxy: upstream unavailable; serving the cached tag"
                            );
                            Ok(Some(ManifestHit::from_row(c.manifest)))
                        }
                        None => Err(e),
                    },
                }
            }
        }
    }

    /// Ask the upstream what `tag` points at now; refresh the cache.
    async fn revalidate_tag(
        &self,
        repo: &Repository,
        target: &Target,
        tag: &str,
        scope: &str,
        accept: &str,
        cached: Option<&oci_dao::TaggedManifest>,
    ) -> OciResult<Option<ManifestHit>> {
        let local = &target.image;
        let upstream = self.upstream(repo).await?;
        let path = format!("/v2/{local}/manifests/{tag}");
        if let Some(c) = cached {
            let head = upstream
                .send(
                    Method::HEAD,
                    &path,
                    scope,
                    Some(accept),
                    RequestClass::Metadata,
                )
                .await?;
            if head.status() == reqwest::StatusCode::NOT_FOUND {
                self.remember_not_found(repo, local, tag).await;
                return Ok(None);
            }
            if head.status().is_success() {
                let same = head
                    .headers()
                    .get("docker-content-digest")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|d| d == c.manifest.digest);
                if same {
                    oci_dao::mark_tag_checked(&self.inner.pool, repo.id, local, tag).await?;
                    return Ok(Some(ManifestHit::from_row(c.manifest.clone())));
                }
            } else if head.status().is_server_error()
                || matches!(head.status().as_u16(), 401 | 403 | 429)
            {
                return Err(upstream_status(head.status()));
            }
            // A changed digest, or a HEAD the upstream does not answer
            // usefully: fetch the manifest.
        }
        let response = upstream
            .send(
                Method::GET,
                &path,
                scope,
                Some(accept),
                RequestClass::Metadata,
            )
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            self.remember_not_found(repo, local, tag).await;
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(upstream_status(response.status()));
        }
        let declared = response
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .and_then(|d| Digest::parse(d).ok());
        let content_type = content_type(&response);
        let body = read_limited(response, MAX_MANIFEST_BYTES).await?;
        if let Some(declared) = &declared {
            if Digest::of(declared.algorithm(), &body) != *declared {
                tracing::warn!(repo = %repo.name, image = %local, %tag, "registry proxy: upstream manifest does not match its Docker-Content-Digest");
                return Err(OciError::unavailable(
                    "the upstream served a manifest that does not match its digest",
                ));
            }
        }
        let digest = Digest::sha256_of(&body);
        let parsed = manifest::parse(&body, content_type.as_deref())
            .map_err(|_| OciError::unavailable("the upstream served an invalid manifest"))?;
        let row = self
            .store_proxied_manifest(target, &digest, &parsed, &body, Some(tag))
            .await?;
        let mut hit = ManifestHit::from_row(row);
        hit.bytes = Some(body);
        Ok(Some(hit))
    }

    pub(crate) async fn proxy_blob(
        &self,
        repo: &Repository,
        image: &str,
        digest: &Digest,
    ) -> OciResult<Option<BlobHit>> {
        let local = proxied_image(repo, image);
        if let Some(hit) = self.hosted_blob(repo, &local, digest).await? {
            return Ok(Some(hit));
        }
        if !repo.online || self.negative_cached(repo, &local, digest.as_str()).await {
            return Ok(None);
        }
        let gate = gate(format!("{}:{local}:{digest}", repo.id));
        let _held = gate.lock().await;
        if let Some(hit) = self.hosted_blob(repo, &local, digest).await? {
            return Ok(Some(hit));
        }
        let upstream = self.upstream(repo).await?;
        let scope = format!("repository:{local}:pull");
        let path = format!("/v2/{local}/blobs/{digest}");
        let pool = &self.inner.pool;

        // Content the CAS already holds (a layer shared with another image)
        // is linked once the upstream confirms this image has it, without
        // downloading it again.
        if digest.algorithm() == crate::digest::Algorithm::Sha256 {
            if let Some((_, size)) = oci_dao::committed_blob(pool, digest.hex()).await? {
                let head = upstream
                    .send(Method::HEAD, &path, &scope, None, RequestClass::Metadata)
                    .await?;
                if head.status().is_success() {
                    let mut tx = pool.begin().await?;
                    match oci_dao::insert_link_existing(
                        &mut tx,
                        repo.id,
                        &local,
                        digest.as_str(),
                        digest.hex(),
                        size,
                    )
                    .await?
                    {
                        LinkOutcome::BlobUnavailable => tx.rollback().await?,
                        _ => {
                            tx.commit().await?;
                            let hit = self.hosted_blob(repo, &local, digest).await?;
                            if let Some(hit) = &hit {
                                self.backfill_platform(
                                    repo,
                                    &local,
                                    digest,
                                    hit.size,
                                    Some(&hit.s3_key),
                                    None,
                                )
                                .await;
                            }
                            return Ok(hit);
                        }
                    }
                } else if head.status() == reqwest::StatusCode::NOT_FOUND {
                    self.remember_not_found(repo, &local, digest.as_str()).await;
                    return Ok(None);
                }
            }
        }

        let response = upstream
            .send(Method::GET, &path, &scope, None, RequestClass::Download)
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            self.remember_not_found(repo, &local, digest.as_str()).await;
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(upstream_status(response.status()));
        }
        let max = self.inner.config.max_blob_bytes;
        if response.content_length().is_some_and(|l| l > max) {
            return Err(OciError::too_large(max));
        }
        let body = response.bytes_stream().map_err(std::io::Error::other);
        let staged = self
            .inner
            .cas
            .stage(tokio_util::io::StreamReader::new(body), max)
            .await?;
        if !digest.matches(&staged.sha256, &staged.sha512_base64) {
            tracing::warn!(repo = %repo.name, image = %local, %digest, "registry proxy: upstream blob does not match its digest");
            return Err(OciError::unavailable(
                "the upstream served a blob that does not match its digest",
            ));
        }
        // A small blob may be an image config (read while it is at hand).
        let small = if staged.size <= MAX_CONFIG_BYTES as u64 {
            tokio::fs::read(&staged.temp_path).await.ok()
        } else {
            None
        };
        let stored = self.inner.cas.commit(staged).await?;
        let mut tx = pool.begin().await?;
        oci_dao::insert_link_ingested(
            &mut tx,
            repo.id,
            &local,
            digest.as_str(),
            &stored.sha256,
            stored.size as i64,
            stored.ingest_token,
        )
        .await
        .map_err(OciError::from)
        .and_then(require_linked)?;
        tx.commit().await?;
        if let Some(bytes) = small {
            self.backfill_platform(repo, &local, digest, bytes.len() as i64, None, Some(bytes))
                .await;
        }
        self.hosted_blob(repo, &local, digest).await
    }

    /// A proxy caches a manifest before its config: once the config blob
    /// `digest` is cached, its platform completes the summaries of the
    /// image's manifests that name it. Best effort.
    async fn backfill_platform(
        &self,
        repo: &Repository,
        image: &str,
        digest: &Digest,
        size: i64,
        s3_key: Option<&str>,
        bytes: Option<Vec<u8>>,
    ) {
        if size > MAX_CONFIG_BYTES {
            return;
        }
        let pool = &self.inner.pool;
        match oci_dao::config_needs_platform(pool, repo.id, image, digest.as_str()).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                tracing::warn!(error = %e, "registry proxy: platform lookup failed");
                return;
            }
        }
        let bytes = match (bytes, s3_key) {
            (Some(bytes), _) => bytes,
            (None, Some(key)) => match self.read_manifest_bytes(key, size).await {
                Ok(bytes) => bytes.to_vec(),
                Err(_) => return,
            },
            (None, None) => return,
        };
        let Some(platform) = manifest::config_platform(&bytes) else {
            return;
        };
        if let Err(e) =
            oci_dao::set_config_platform(pool, repo.id, image, digest.as_str(), &platform.label())
                .await
        {
            tracing::warn!(error = %e, "registry proxy: recording an image platform failed");
        }
    }

    pub(crate) async fn proxy_tags(
        &self,
        repo: &Repository,
        image: &str,
        last: Option<&str>,
        limit: usize,
    ) -> OciResult<Option<Vec<String>>> {
        let local = proxied_image(repo, image);
        if repo.online {
            match self.upstream_tags(repo, &local, last, limit).await {
                Ok(Some(tags)) => return Ok(Some(tags)),
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    repo = %repo.name, image = %local, error = %e.message,
                    "registry proxy: upstream tag list unavailable; listing cached tags"
                ),
            }
        }
        self.local_tags(repo, &local, last, limit).await
    }

    async fn upstream_tags(
        &self,
        repo: &Repository,
        local: &str,
        last: Option<&str>,
        limit: usize,
    ) -> OciResult<Option<Vec<String>>> {
        let upstream = self.upstream(repo).await?;
        let query = {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query.append_pair("n", &limit.to_string());
            if let Some(last) = last {
                query.append_pair("last", last);
            }
            query.finish()
        };
        let response = upstream
            .send(
                Method::GET,
                &format!("/v2/{local}/tags/list?{query}"),
                &format!("repository:{local}:pull"),
                None,
                RequestClass::Metadata,
            )
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(upstream_status(response.status()));
        }
        #[derive(serde::Deserialize)]
        struct TagList {
            #[serde(default)]
            tags: Option<Vec<String>>,
        }
        let body = read_limited(response, MAX_LISTING_BYTES).await?;
        let list: TagList = serde_json::from_slice(&body)
            .map_err(|_| OciError::unavailable("the upstream served an invalid tag list"))?;
        let mut tags: Vec<String> = list
            .tags
            .unwrap_or_default()
            .into_iter()
            .filter(|t| reference::valid_tag(t))
            .filter(|t| last.is_none_or(|l| t.as_bytes() > l.as_bytes()))
            .collect();
        tags.sort_unstable();
        tags.dedup();
        tags.truncate(limit);
        Ok(Some(tags))
    }

    pub(crate) async fn proxy_referrers(
        &self,
        repo: &Repository,
        image: &str,
        subject: &Digest,
    ) -> OciResult<Vec<ReferrerDescriptor>> {
        let local = proxied_image(repo, image);
        if repo.online {
            match self.upstream_referrers(repo, &local, subject).await {
                Ok(Some(referrers)) => return Ok(referrers),
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    repo = %repo.name, image = %local, error = %e.message,
                    "registry proxy: upstream referrers unavailable; listing cached ones"
                ),
            }
        }
        self.local_referrers(repo, &local, subject).await
    }

    async fn upstream_referrers(
        &self,
        repo: &Repository,
        local: &str,
        subject: &Digest,
    ) -> OciResult<Option<Vec<ReferrerDescriptor>>> {
        let upstream = self.upstream(repo).await?;
        let response = upstream
            .send(
                Method::GET,
                &format!("/v2/{local}/referrers/{subject}"),
                &format!("repository:{local}:pull"),
                Some(media::OCI_INDEX),
                RequestClass::Metadata,
            )
            .await?;
        if !response.status().is_success() {
            // 404: the upstream has no referrers API (clients fall back to
            // the tag scheme, which a proxy serves like any tag).
            return Ok(None);
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Desc {
            media_type: Option<String>,
            digest: String,
            size: i64,
            artifact_type: Option<String>,
            annotations: Option<serde_json::Value>,
        }
        #[derive(serde::Deserialize)]
        struct Index {
            #[serde(default)]
            manifests: Vec<Desc>,
        }
        let body = read_limited(response, MAX_LISTING_BYTES).await?;
        let index: Index = serde_json::from_slice(&body)
            .map_err(|_| OciError::unavailable("the upstream served an invalid referrers list"))?;
        Ok(Some(
            index
                .manifests
                .into_iter()
                .filter(|d| Digest::parse(&d.digest).is_ok() && d.size >= 0)
                .map(|d| ReferrerDescriptor {
                    media_type: d.media_type.unwrap_or_else(|| media::OCI_MANIFEST.into()),
                    digest: d.digest,
                    size: d.size,
                    artifact_type: d.artifact_type,
                    annotations: d.annotations,
                })
                .collect(),
        ))
    }
}

fn content_type(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges() {
        assert_eq!(
            parse_challenge(
                r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull""#
            ),
            Some(Challenge::Bearer {
                realm: "https://auth.docker.io/token".into(),
                service: Some("registry.docker.io".into()),
                scope: Some("repository:library/nginx:pull".into()),
            })
        );
        assert_eq!(
            parse_challenge(r#"bearer realm="https://ghcr.io/token", service="ghcr.io""#),
            Some(Challenge::Bearer {
                realm: "https://ghcr.io/token".into(),
                service: Some("ghcr.io".into()),
                scope: None,
            })
        );
        assert_eq!(
            parse_challenge(r#"Basic realm="x""#),
            Some(Challenge::Basic)
        );
        assert_eq!(parse_challenge("Negotiate"), None);
        assert_eq!(parse_challenge("Bearer service=\"x\""), None);
    }

    #[test]
    fn docker_hub_library_names() {
        let mut repo = test_repo();
        repo.remote_url = Some("https://registry-1.docker.io".into());
        assert_eq!(proxied_image(&repo, "nginx"), "library/nginx");
        assert_eq!(proxied_image(&repo, "bitnami/nginx"), "bitnami/nginx");
        repo.remote_url = Some("https://ghcr.io".into());
        assert_eq!(proxied_image(&repo, "nginx"), "nginx");
        assert_eq!(upstream_base("https://ghcr.io/v2/"), "https://ghcr.io");
        assert_eq!(
            upstream_base("https://r.example/prefix/"),
            "https://r.example/prefix"
        );
    }

    fn test_repo() -> Repository {
        Repository {
            id: 1,
            name: "hub".into(),
            format: "docker".into(),
            kind: "proxy".into(),
            anonymous_read: false,
            online: true,
            config: serde_json::json!({}),
            remote_url: None,
            package_delay_seconds: 0,
            upstream_username: None,
            upstream_password: None,
            upstream_password_enc: None,
            metadata_ttl_seconds: None,
            not_found_ttl_seconds: None,
            allow_redeploy: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }
}
