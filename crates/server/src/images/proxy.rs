//! Proxy repositories: a pull-through cache of an upstream registry
//! (Docker Hub, GHCR, Quay, MCR or any distribution-spec registry).
//!
//! * Blobs and digest-addressed manifests are immutable: once fetched (and
//!   verified against their digest) they are served from the CAS for good.
//!   A layer is served while it is fetched ([`super::download`]).
//! * A tag is re-validated after the repository's metadata TTL with a `HEAD`
//!   (which Docker Hub does not count against its pull rate limit); while
//!   the upstream is unreachable, or the repository is offline, the cached
//!   tag is served.
//! * Multi-arch indexes are cached as they are; their child manifests are
//!   fetched when a client asks for them.
//! * The images format names what to ask the upstream for
//!   ([`UpstreamOp`]): the name the upstream knows an image by (Docker Hub's
//!   `library/` namespace, so both spellings share one cache), a manifest's
//!   and a blob's URL, and it reads the upstream's tag lists and referrers.
//!
//! Upstream requests go through the shared [`UpstreamHttp`] client (metadata
//! guard, timeouts, redirects without credentials), to the origin of the
//! repository's `remote_url` only. Docker's token flow is followed: a `401`
//! with a `Bearer` challenge sends the upstream credentials to the token
//! realm that challenge names, and the token is cached until it expires.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use forge_core::net::upstream::{Origin, RequestClass, UpstreamHttp};
use forge_core::repo::proxy::{upstream_credentials, Credentials};
use forge_db::model::Repository;
use forge_db::oci_dao::{self, LinkOutcome};
use forge_plugin::api::images::ImageError;
use forge_plugin::api::images::{ImageUrl, ManifestInfo, Reference, TagPage, MAX_MANIFEST_BYTES};
use forge_plugin::api::{
    FetchResult, Fetched, FormatError, Remote, UpstreamAnswer, UpstreamOp, UpstreamStep,
};
use forge_storage::{BlobRef, StagedBlob};
use forge_telemetry::proxy::{Kind as LookupKind, Lookup, Outcome};
use futures_util::{StreamExt, TryStreamExt};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::Method;
use tracing::Instrument;

use super::digest::ContentDigest;
use super::dispatch::Target;
use super::download::Download;
use super::pull::{BlobHit, ManifestHit};
use super::push::{merge, require_linked};
use super::{Failure, ImgResult, Registry};

/// Record a proxy `lookup` that answered `result`: what its path marked,
/// else a hit for something found and "not found" for nothing. A failure is
/// the upstream's when the path was talking to it, else Forge's.
fn finish<T>(lookup: Lookup, result: &ImgResult<Option<T>>) {
    let marked = lookup.marked();
    let outcome = match result {
        Ok(Some(_)) => marked.unwrap_or(Outcome::Hit),
        Ok(None) => marked.unwrap_or(Outcome::NotFound),
        Err(_) if marked == Some(Outcome::UpstreamError) => Outcome::UpstreamError,
        Err(_) => Outcome::Error,
    };
    lookup.finish(outcome);
}

/// How long a tag is served without asking the upstream, unless the
/// repository sets `metadata_ttl_seconds`.
const DEFAULT_TAG_TTL_SECS: i64 = 600;

/// How long an upstream "not found" is remembered, unless the repository
/// sets `not_found_ttl_seconds`.
const DEFAULT_NOT_FOUND_TTL_SECS: u64 = 60;

/// Largest blob read as a possible config.
const MAX_CONFIG_BYTES: i64 = 1024 * 1024;

/// Largest upstream tag list or referrers document read.
const MAX_LISTING_BYTES: usize = 16 * 1024 * 1024;

/// The most rounds of one upstream conversation of the images format: an
/// upstream's tag list may take a page per round.
const MAX_UPSTREAM_ROUNDS: usize = 12;

/// Cached upstream registry tokens: key → (token, expiry). Bounded: the key
/// names an image a client chose, and the token and its lifetime are the
/// upstream's word.
static TOKENS: LazyLock<Mutex<HashMap<String, (String, Instant)>>> =
    LazyLock::new(Default::default);

/// The most upstream tokens kept per process.
const MAX_CACHED_TOKENS: usize = 4096;

/// The largest upstream token kept; a longer one is used for its request
/// only. Registry tokens are a few KiB at most.
const MAX_CACHED_TOKEN_BYTES: usize = 8 * 1024;

/// The longest an upstream token is kept, whatever its `expires_in`.
const MAX_TOKEN_TTL: Duration = Duration::from_secs(600);

/// In-flight first-time blob downloads, so concurrent pulls of one layer
/// share a single upstream fetch per process: a config is fetched and
/// stored under its gate, a layer's download ([`Download`]) started under it.
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
    if token.len() > MAX_CACHED_TOKEN_BYTES {
        return;
    }
    let now = Instant::now();
    let mut tokens = TOKENS.lock().unwrap_or_else(|p| p.into_inner());
    if tokens.len() >= MAX_CACHED_TOKENS && !tokens.contains_key(&key) {
        tokens.retain(|_, (_, expiry)| *expiry > now);
        if tokens.len() >= MAX_CACHED_TOKENS {
            // Full of live tokens: drop the one that expires first.
            let soonest = tokens
                .iter()
                .min_by_key(|(_, (_, expiry))| *expiry)
                .map(|(key, _)| key.clone());
            if let Some(soonest) = soonest {
                tokens.remove(&soonest);
            }
        }
    }
    tokens.insert(key, (token, now + ttl.min(MAX_TOKEN_TTL)));
}

/// Inside a transaction that caches what `repo`'s upstream served: lock the
/// repository row and make sure the proxy still points at the upstream the
/// content came from ([`oci_dao::lock_proxy_upstream`]). A proxy repointed
/// meanwhile purged its cache, and content of the previous upstream must
/// not land in it after that: the client is asked to retry.
pub(crate) async fn still_upstream(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repo: &Repository,
) -> ImgResult<()> {
    if oci_dao::lock_proxy_upstream(tx, repo.id, repo.remote_url.as_deref()).await? {
        Ok(())
    } else {
        Err(Failure::unavailable(
            "the proxy was pointed at another upstream while this was fetched; retry",
        ))
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
pub(crate) async fn read_limited(response: reqwest::Response, limit: usize) -> ImgResult<Bytes> {
    if response.content_length().is_some_and(|l| l > limit as u64) {
        return Err(Failure::unavailable("the upstream response is too large"));
    }
    let mut stream = response.bytes_stream();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| upstream_unreachable(&e))?;
        if out.len() + chunk.len() > limit {
            return Err(Failure::unavailable("the upstream response is too large"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

pub(crate) fn upstream_unreachable(e: &dyn std::fmt::Display) -> Failure {
    tracing::warn!(error = %e, "registry proxy: upstream request failed");
    Failure::unavailable("the upstream registry is unreachable")
}

/// The error a non-success upstream status turns into.
fn upstream_status(status: reqwest::StatusCode) -> Failure {
    match status.as_u16() {
        429 => Failure::new(ImageError::RateLimited),
        401 | 403 => {
            tracing::warn!(%status, "registry proxy: upstream refused the request");
            Failure::unavailable("the upstream registry refused the proxy's credentials")
        }
        _ => {
            tracing::warn!(%status, "registry proxy: upstream answered with an error");
            Failure::unavailable("the upstream registry answered with an error")
        }
    }
}

/// An upstream registry (a proxy repository's, or an import's source), for
/// one request.
pub(crate) struct Upstream {
    pub(crate) http: UpstreamHttp,
    /// Who the cached tokens belong to: a proxy repository's id, an import.
    pub(crate) owner: String,
    /// The upstream's URL, as configured: requests go to its origin only.
    pub(crate) remote: String,
    pub(crate) creds: Option<Arc<Credentials>>,
}

impl Upstream {
    fn token_key(&self, scope: &str) -> String {
        format!("{}:{}:{scope}", self.owner, self.remote)
    }

    /// What the images format sees of the upstream.
    pub(crate) fn as_remote(&self) -> Remote {
        Remote {
            url: self.remote.clone(),
            index: None,
            options: Vec::new(),
        }
    }

    async fn attempt(
        &self,
        method: Method,
        url: &str,
        accept: Option<&str>,
        class: RequestClass,
        bearer: Option<&str>,
        basic: bool,
    ) -> ImgResult<reqwest::Response> {
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
            self.creds.as_ref().map(|creds| creds.auth())
        } else {
            None
        };
        self.http
            .send(method, url, class, headers, auth.as_ref())
            .await
            .map_err(|e| upstream_unreachable(&e))
    }

    /// Send a request to `url`, answering the upstream's authentication
    /// challenge once, with a token for its scope (else `scope`). Only to
    /// the origin of the upstream's URL: the images format names no other.
    pub(crate) async fn send(
        &self,
        method: Method,
        url: &str,
        scope: Option<&str>,
        accept: Option<&str>,
        class: RequestClass,
    ) -> ImgResult<reqwest::Response> {
        let origin = Origin::of(&self.remote);
        if origin.is_none() || Origin::of(url) != origin {
            tracing::warn!(%url, remote = %self.remote, "images format named an URL off its upstream; not sent");
            return Err(Failure::internal(
                "upstream request",
                format!("{url} is not on the upstream's origin"),
            ));
        }
        let scope = scope.unwrap_or_default();
        let key = self.token_key(scope);
        let cached = cached_token(&key);
        let response = self
            .attempt(method.clone(), url, accept, class, cached.as_deref(), false)
            .await?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        // Only the upstream itself names where its credentials go: a 401
        // from a host it redirected to (a CDN, an object store) is answered
        // as the failure it is, never followed to the realm it names.
        if Origin::of(response.url().as_str()) != origin {
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
                self.attempt(method, url, accept, class, Some(&token.0), false)
                    .await
            }
            Some(Challenge::Basic) if self.creds.is_some() => {
                self.attempt(method, url, accept, class, None, true).await
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
    ) -> ImgResult<(String, Duration)> {
        let parsed = url::Url::parse(realm)
            .map_err(|_| Failure::unavailable("the upstream named an invalid token realm"))?;
        let upstream_https = self.remote.starts_with("https://");
        if !matches!(parsed.scheme(), "https" | "http")
            || (upstream_https && parsed.scheme() != "https")
        {
            return Err(Failure::unavailable(
                "the upstream named a token realm Forge will not send credentials to",
            ));
        }
        let mut url = parsed.clone();
        {
            let mut q = url.query_pairs_mut();
            if let Some(service) = service {
                q.append_pair("service", service);
            }
            if !scope.is_empty() {
                q.append_pair("scope", scope);
            }
        }
        let auth = match (&self.creds, Origin::of(realm)) {
            (Some(creds), Some(origin)) => Some(creds.auth_for(origin)),
            _ => None,
        };
        let response = self
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
            .map_err(|_| Failure::unavailable("the upstream token service answered nonsense"))?;
        let token = parsed
            .token
            .or(parsed.access_token)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Failure::unavailable("the upstream token service sent no token"))?;
        let ttl = parsed
            .expires_in
            .unwrap_or(60)
            .min(MAX_TOKEN_TTL.as_secs())
            .saturating_sub(10)
            .max(10);
        Ok((token, Duration::from_secs(ttl)))
    }

    /// Send the request the images format named for a manifest or a blob.
    pub(crate) async fn send_url(
        &self,
        method: Method,
        url: &ImageUrl,
        class: RequestClass,
    ) -> ImgResult<reqwest::Response> {
        self.send(
            method,
            &url.url,
            url.scope.as_deref(),
            url.accept.as_deref(),
            class,
        )
        .await
    }

    /// Run an upstream conversation of the images format: what it answers
    /// at once, or after the fetches it asks for (sent to the upstream's
    /// origin, with its token exchange, not kept).
    pub(crate) async fn converse(
        &self,
        reg: &Registry,
        op: &UpstreamOp,
    ) -> ImgResult<UpstreamAnswer> {
        let remote = self.as_remote();
        let mut fetched: Vec<FetchResult> = Vec::new();
        for _ in 0..MAX_UPSTREAM_ROUNDS {
            let step = reg
                .plugin()
                .upstream(&remote, op, &fetched)
                .map_err(|e| format_failure("upstream", e))?;
            let wanted = match step {
                UpstreamStep::Done(answer) => return Ok(answer),
                UpstreamStep::Fetch(wanted) => wanted,
            };
            if wanted.is_empty() {
                return Err(Failure::internal(
                    "upstream",
                    "the images format asked for no fetch",
                ));
            }
            for fetch in wanted {
                let response = self
                    .send(
                        Method::GET,
                        &fetch.url,
                        fetch.scope.as_deref(),
                        fetch.accept.as_deref(),
                        RequestClass::Metadata,
                    )
                    .await;
                let result = match response {
                    Ok(response) => {
                        let status = response.status();
                        let headers: Vec<(String, String)> = response
                            .headers()
                            .get_all(reqwest::header::LINK)
                            .iter()
                            .filter_map(|v| v.to_str().ok())
                            .map(|v| ("link".to_string(), v.to_string()))
                            .collect();
                        let outcome = if status == reqwest::StatusCode::NOT_FOUND {
                            Fetched::NotFound
                        } else if !status.is_success() {
                            Fetched::Failed(upstream_status(status).message())
                        } else {
                            match read_limited(response, MAX_LISTING_BYTES).await {
                                Ok(body) => Fetched::Found(body.to_vec()),
                                Err(failure) => Fetched::Failed(failure.message()),
                            }
                        };
                        FetchResult {
                            fetch,
                            outcome,
                            status: Some(status.as_u16()),
                            headers,
                        }
                    }
                    Err(failure) => FetchResult {
                        fetch,
                        outcome: Fetched::Failed(failure.message()),
                        status: None,
                        headers: Vec::new(),
                    },
                };
                fetched.push(result);
            }
        }
        Err(Failure::internal(
            "upstream",
            format!("the images format needed more than {MAX_UPSTREAM_ROUNDS} rounds"),
        ))
    }
}

/// A format error of the upstream side: a reference it does not take (an
/// import's tag), else the format's bug.
fn format_failure(context: &str, e: FormatError) -> Failure {
    match e {
        FormatError::InvalidVersion(m) | FormatError::InvalidId(m) => {
            Failure::new(ImageError::ManifestInvalid(m))
        }
        other => Failure::internal(context, other),
    }
}

impl Registry {
    pub(crate) async fn upstream(&self, repo: &Repository) -> ImgResult<Upstream> {
        let remote = repo
            .remote_url
            .as_deref()
            .ok_or_else(|| Failure::internal("proxy", "proxy repository without remote_url"))?;
        let creds = upstream_credentials(&self.inner.pool, &self.inner.envelope, repo)
            .await
            .map_err(|e| Failure::internal("proxy credentials", e))?;
        Ok(Upstream {
            http: self.inner.http.for_repository(&repo.name),
            owner: repo.id.to_string(),
            remote: remote.to_string(),
            creds: creds.map(Arc::new),
        })
    }

    /// The images format's answer to an operation it answers without
    /// fetching anything (a name, a URL), for the upstream at `remote`.
    pub(crate) fn upstream_answer(
        &self,
        remote: &str,
        op: &UpstreamOp,
    ) -> ImgResult<UpstreamAnswer> {
        let remote = Remote {
            url: remote.to_string(),
            index: None,
            options: Vec::new(),
        };
        match self.plugin().upstream(&remote, op, &[]) {
            Ok(UpstreamStep::Done(answer)) => Ok(answer),
            Ok(UpstreamStep::Fetch(_)) => Err(Failure::internal(
                "upstream",
                "the images format asked for a fetch to name a URL",
            )),
            Err(e) => Err(format_failure("upstream", e)),
        }
    }

    /// Where the upstream at `remote` has the manifest or blob `op` names.
    pub(crate) fn image_url(&self, remote: &str, op: &UpstreamOp) -> ImgResult<ImageUrl> {
        match self.upstream_answer(remote, op)? {
            UpstreamAnswer::ImageUrl(url) => Ok(url),
            other => Err(Failure::internal(
                "upstream",
                format!("the images format answered {other:?} for a URL"),
            )),
        }
    }

    /// The image name a proxy stores and asks its upstream for.
    pub(crate) fn proxied_image(&self, repo: &Repository, image: &str) -> String {
        let Some(remote) = &repo.remote_url else {
            return image.to_string();
        };
        match self.upstream_answer(remote, &UpstreamOp::ImageName(image.to_string())) {
            Ok(UpstreamAnswer::ImageName(name)) => name,
            _ => image.to_string(),
        }
    }

    /// Keyed by the repository's `updated_at` too, so an administrator's
    /// cache invalidation (which bumps it) forgets the upstream's "not found"
    /// answers on every instance.
    fn not_found_key(repo: &Repository, image: &str, reference: &str) -> String {
        format!(
            "{}:{}:{image}:{reference}",
            repo.id,
            repo.updated_at.timestamp_micros()
        )
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
    ) -> ImgResult<Option<ManifestHit>> {
        let mut lookup = Lookup::start(&repo.name, LookupKind::Manifest);
        let span = lookup.span();
        let result = self
            .proxied_manifest(repo, image, reference, &mut lookup)
            .instrument(span)
            .await;
        finish(lookup, &result);
        result
    }

    /// [`Self::proxy_manifest`], marking what it finds on `lookup`.
    async fn proxied_manifest(
        &self,
        repo: &Repository,
        image: &str,
        reference: &Reference,
        lookup: &mut Lookup,
    ) -> ImgResult<Option<ManifestHit>> {
        let local = self.proxied_image(repo, image);
        let target = Target {
            repo: repo.clone(),
            image: local.clone(),
            name: local.clone(),
        };
        let pool = &self.inner.pool;
        match reference {
            Reference::Digest(digest) => {
                if let Some(row) = oci_dao::find_manifest(pool, repo.id, &local, digest).await? {
                    return Ok(Some(ManifestHit::from_row(row)));
                }
                if !repo.online {
                    lookup.mark(Outcome::Offline);
                    return Ok(None);
                }
                if self.negative_cached(repo, &local, digest).await {
                    lookup.mark(Outcome::NegativeCached);
                    return Ok(None);
                }
                let digest = ContentDigest::named(digest)?;
                let upstream = self.upstream(repo).await?;
                let url = self.image_url(
                    &upstream.remote,
                    &UpstreamOp::ImageManifest {
                        image: local.clone(),
                        reference: reference.clone(),
                    },
                )?;
                lookup.mark(Outcome::UpstreamError);
                let response = upstream
                    .send_url(Method::GET, &url, RequestClass::Metadata)
                    .await?;
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    lookup.mark(Outcome::NotFound);
                    self.remember_not_found(repo, &local, digest.as_str()).await;
                    return Ok(None);
                }
                if !response.status().is_success() {
                    return Err(upstream_status(response.status()));
                }
                let content_type = content_type(&response);
                let body = read_limited(response, MAX_MANIFEST_BYTES).await?;
                upstream.http.count_bytes(body.len() as u64);
                if !digest.matches_bytes(&body) {
                    tracing::warn!(repo = %repo.name, image = %local, %digest, "registry proxy: upstream manifest does not match its digest");
                    return Err(Failure::unavailable(
                        "the upstream served a manifest that does not match its digest",
                    ));
                }
                let parsed = self
                    .parse_manifest(&body, content_type.as_deref())
                    .map_err(|_| Failure::unavailable("the upstream served an invalid manifest"))?;
                lookup.mark(Outcome::Fetched);
                let row = self
                    .store_proxied_manifest(&target, &digest, &parsed, &body, None)
                    .await?;
                let mut hit = ManifestHit::from_row(row);
                hit.bytes = Some(body);
                Ok(Some(hit))
            }
            Reference::Tag(tag) => {
                let cached = oci_dao::find_tag(pool, repo.id, &local, tag).await?;
                if !repo.online {
                    if cached.is_none() {
                        lookup.mark(Outcome::Offline);
                    }
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
                    lookup.mark(Outcome::NegativeCached);
                    return Ok(None);
                }
                match self
                    .revalidate_tag(repo, &target, reference, tag, cached.as_ref(), lookup)
                    .await
                {
                    Ok(found) => Ok(found),
                    Err(e) => match cached {
                        Some(c) => {
                            lookup.mark(Outcome::StaleServed);
                            tracing::warn!(
                                repo = %repo.name, image = %local, %tag, error = %e.message(),
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
        reference: &Reference,
        tag: &str,
        cached: Option<&oci_dao::TaggedManifest>,
        lookup: &mut Lookup,
    ) -> ImgResult<Option<ManifestHit>> {
        let local = &target.image;
        let upstream = self.upstream(repo).await?;
        lookup.mark(Outcome::UpstreamError);
        let url = self.image_url(
            &upstream.remote,
            &UpstreamOp::ImageManifest {
                image: local.clone(),
                reference: reference.clone(),
            },
        )?;
        if let Some(c) = cached {
            let head = upstream
                .send_url(Method::HEAD, &url, RequestClass::Metadata)
                .await?;
            if head.status() == reqwest::StatusCode::NOT_FOUND {
                lookup.mark(Outcome::NotFound);
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
                    lookup.mark(Outcome::Hit);
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
            .send_url(Method::GET, &url, RequestClass::Metadata)
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            lookup.mark(Outcome::NotFound);
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
            .and_then(ContentDigest::parse);
        let content_type = content_type(&response);
        let body = read_limited(response, MAX_MANIFEST_BYTES).await?;
        upstream.http.count_bytes(body.len() as u64);
        if let Some(declared) = &declared {
            if !declared.matches_bytes(&body) {
                tracing::warn!(repo = %repo.name, image = %local, %tag, "registry proxy: upstream manifest does not match its Docker-Content-Digest");
                return Err(Failure::unavailable(
                    "the upstream served a manifest that does not match its digest",
                ));
            }
        }
        let digest = ContentDigest::sha256_of(&body);
        let parsed = self
            .parse_manifest(&body, content_type.as_deref())
            .map_err(|_| Failure::unavailable("the upstream served an invalid manifest"))?;
        lookup.mark(Outcome::Fetched);
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
        digest: &ContentDigest,
    ) -> ImgResult<Option<BlobHit>> {
        let mut lookup = Lookup::start(&repo.name, LookupKind::Blob);
        let span = lookup.span();
        let result = self
            .proxied_blob(repo, image, digest, &mut lookup)
            .instrument(span)
            .await;
        finish(lookup, &result);
        result
    }

    /// [`Self::proxy_blob`], marking what it finds on `lookup`.
    async fn proxied_blob(
        &self,
        repo: &Repository,
        image: &str,
        digest: &ContentDigest,
        lookup: &mut Lookup,
    ) -> ImgResult<Option<BlobHit>> {
        let local = self.proxied_image(repo, image);
        if let Some(hit) = self.hosted_blob(repo, &local, digest).await? {
            return Ok(Some(hit));
        }
        if !repo.online {
            lookup.mark(Outcome::Offline);
            return Ok(None);
        }
        if self.negative_cached(repo, &local, digest.as_str()).await {
            lookup.mark(Outcome::NegativeCached);
            return Ok(None);
        }
        let key = Download::key(repo, &local, digest);
        let gate = gate(key.clone());
        let _held = gate.lock().await;
        if let Some(hit) = self.hosted_blob(repo, &local, digest).await? {
            return Ok(Some(hit));
        }
        // Being downloaded: served from that download.
        if let Some(download) = Download::joinable(&key) {
            return Ok(Some(BlobHit::downloading(repo, &local, digest, download)));
        }
        let upstream = self.upstream(repo).await?;
        let url = self.image_url(
            &upstream.remote,
            &UpstreamOp::ImageBlob {
                image: local.clone(),
                digest: digest.to_string(),
            },
        )?;
        let pool = &self.inner.pool;

        // A layer another image of this proxy already holds (served by this
        // upstream and verified when it was fetched) is linked once the
        // upstream confirms this image has it, without downloading it again.
        // Anything else in the CAS is fetched and verified like a new blob:
        // the upstream's HEAD must never reach content it did not serve.
        if let Some(sha256) = digest.sha256_hex() {
            if let Some((_, size)) =
                oci_dao::blob_linked_in_repository(pool, repo.id, sha256).await?
            {
                lookup.mark(Outcome::UpstreamError);
                let head = upstream
                    .send_url(Method::HEAD, &url, RequestClass::Metadata)
                    .await?;
                // Linked from the cache once the upstream confirms it.
                lookup.mark(Outcome::Hit);
                if head.status().is_success() {
                    let mut tx = forge_db::begin(pool).await?;
                    still_upstream(&mut tx, repo).await?;
                    match oci_dao::insert_link_existing(
                        &mut tx,
                        repo.id,
                        &local,
                        digest.as_str(),
                        sha256,
                        size,
                    )
                    .await?
                    {
                        LinkOutcome::BlobUnavailable => tx.rollback().await?,
                        _ => {
                            tx.commit().await?;
                            let hit = self.hosted_blob(repo, &local, digest).await?;
                            if let Some(hit) = &hit {
                                self.complete_summaries(
                                    repo,
                                    &local,
                                    digest,
                                    hit.size,
                                    Some(hit.blob()),
                                    None,
                                )
                                .await;
                            }
                            return Ok(hit);
                        }
                    }
                } else if head.status() == reqwest::StatusCode::NOT_FOUND {
                    lookup.mark(Outcome::NotFound);
                    self.remember_not_found(repo, &local, digest.as_str()).await;
                    return Ok(None);
                }
            }
        }

        lookup.mark(Outcome::UpstreamError);
        let response = upstream
            .send_url(Method::GET, &url, RequestClass::Download)
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            lookup.mark(Outcome::NotFound);
            self.remember_not_found(repo, &local, digest.as_str()).await;
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(upstream_status(response.status()));
        }
        let max = self.inner.config.max_blob_bytes;
        if response.content_length().is_some_and(|l| l > max) {
            return Err(Failure::new(ImageError::TooLarge { limit: max }));
        }
        // A layer of a declared size is served while it downloads. What may
        // be a config is stored first, and read whole below.
        if let Some(size) = response
            .content_length()
            .filter(|&size| size > MAX_CONFIG_BYTES as u64)
        {
            lookup.mark(Outcome::Fetched);
            let download =
                self.start_download(repo, &local, digest, size, response, upstream.http.clone())?;
            return Ok(Some(BlobHit::downloading(repo, &local, digest, download)));
        }
        let body = response.bytes_stream().map_err(std::io::Error::other);
        let staged = self
            .inner
            .cas
            .stage(tokio_util::io::StreamReader::new(body), max)
            .await?;
        upstream.http.count_bytes(staged.size);
        if !digest.matches(&staged.sha256, &staged.sha512_base64) {
            tracing::warn!(repo = %repo.name, image = %local, %digest, "registry proxy: upstream blob does not match its digest");
            return Err(Failure::unavailable(
                "the upstream served a blob that does not match its digest",
            ));
        }
        lookup.mark(Outcome::Fetched);
        // A small blob may be a config (read while it is at hand).
        let small = if staged.size <= MAX_CONFIG_BYTES as u64 {
            tokio::fs::read(&staged.temp_path).await.ok()
        } else {
            None
        };
        self.store_fetched(repo, &local, digest, staged).await?;
        if let Some(bytes) = small {
            self.complete_summaries(repo, &local, digest, bytes.len() as i64, None, Some(bytes))
                .await;
        }
        self.hosted_blob(repo, &local, digest).await
    }

    /// Store a blob `repo`'s upstream served for `image`, verified against
    /// its digest, and link it into the image.
    pub(crate) async fn store_fetched(
        &self,
        repo: &Repository,
        image: &str,
        digest: &ContentDigest,
        staged: StagedBlob,
    ) -> ImgResult<()> {
        let stored = self.inner.cas.commit(staged).await?;
        let mut tx = forge_db::begin(&self.inner.pool).await?;
        still_upstream(&mut tx, repo).await?;
        oci_dao::insert_link_ingested(
            &mut tx,
            repo.id,
            image,
            digest.as_str(),
            &stored.sha256,
            stored.size as i64,
            stored.ingest_token,
        )
        .await
        .map_err(Failure::from)
        .and_then(require_linked)?;
        tx.commit().await?;
        Ok(())
    }

    /// A proxy caches a manifest before its config: once the config blob
    /// `digest` is cached, what it holds (an image's platform, a chart's
    /// metadata) completes the summaries of the image's manifests that name
    /// it as their config. Best effort.
    async fn complete_summaries(
        &self,
        repo: &Repository,
        image: &str,
        digest: &ContentDigest,
        size: i64,
        stored: Option<BlobRef<'_>>,
        bytes: Option<Vec<u8>>,
    ) {
        if size > MAX_CONFIG_BYTES {
            return;
        }
        let pool = &self.inner.pool;
        let media_type =
            match oci_dao::config_media_type(pool, repo.id, image, digest.as_str()).await {
                Ok(Some(media_type)) => media_type,
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(error = %e, "registry proxy: summary lookup failed");
                    return;
                }
            };
        let bytes = match (bytes, stored) {
            (Some(bytes), _) => bytes,
            (None, Some(blob)) => match self.read_manifest_bytes(blob).await {
                Ok(bytes) => bytes.to_vec(),
                Err(_) => return,
            },
            (None, None) => return,
        };
        let Some(part) = self.config_summary_part(&media_type, &bytes) else {
            return;
        };
        let keys: Vec<String> = part.keys().cloned().collect();
        let mut merged = serde_json::json!({});
        merge(&mut merged, part);
        if let Err(e) =
            oci_dao::complete_config_summary(pool, repo.id, image, digest.as_str(), &merged, &keys)
                .await
        {
            tracing::warn!(error = %e, "registry proxy: completing manifest summaries failed");
        }
    }

    pub(crate) async fn proxy_tags(
        &self,
        repo: &Repository,
        image: &str,
        last: Option<&str>,
        limit: usize,
    ) -> ImgResult<Option<TagPage>> {
        let local = self.proxied_image(repo, image);
        if repo.online {
            match self.upstream_tags(repo, &local, last, limit).await {
                Ok(Some(tags)) => return Ok(Some(tags)),
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    repo = %repo.name, image = %local, error = %e.message(),
                    "registry proxy: upstream tag list unavailable; listing cached tags"
                ),
            }
        }
        self.local_tags(repo, &local, last, limit).await
    }

    /// Up to `limit` of the upstream's tags of `local` after `last`, as the
    /// images format reads them.
    async fn upstream_tags(
        &self,
        repo: &Repository,
        local: &str,
        last: Option<&str>,
        limit: usize,
    ) -> ImgResult<Option<TagPage>> {
        let upstream = self.upstream(repo).await?;
        let op = UpstreamOp::ImageTags {
            image: local.to_string(),
            last: last.map(str::to_string),
            n: u32::try_from(limit).unwrap_or(u32::MAX),
        };
        match upstream.converse(self, &op).await? {
            UpstreamAnswer::ImageTags(page) => Ok(page),
            UpstreamAnswer::Failed(reason) => Err(Failure::unavailable(reason)),
            other => Err(Failure::internal(
                "upstream tags",
                format!("the images format answered {other:?}"),
            )),
        }
    }

    pub(crate) async fn proxy_referrers(
        &self,
        repo: &Repository,
        image: &str,
        subject: &ContentDigest,
    ) -> ImgResult<Vec<ManifestInfo>> {
        let local = self.proxied_image(repo, image);
        if repo.online {
            match self.upstream_referrers(repo, &local, subject).await {
                Ok(Some(referrers)) => return Ok(referrers),
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    repo = %repo.name, image = %local, error = %e.message(),
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
        subject: &ContentDigest,
    ) -> ImgResult<Option<Vec<ManifestInfo>>> {
        let upstream = self.upstream(repo).await?;
        let op = UpstreamOp::ImageReferrers {
            image: local.to_string(),
            digest: subject.to_string(),
        };
        match upstream.converse(self, &op).await? {
            UpstreamAnswer::ImageReferrers(found) => Ok(found),
            UpstreamAnswer::Failed(reason) => Err(Failure::unavailable(reason)),
            other => Err(Failure::internal(
                "upstream referrers",
                format!("the images format answered {other:?}"),
            )),
        }
    }
}

pub(crate) fn content_type(response: &reqwest::Response) -> Option<String> {
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
    fn the_upstream_token_cache_stays_bounded() {
        let key = |i: usize| format!("bounded-test:{i}");
        let forever = Duration::from_secs(u64::MAX / 2);
        for i in 0..MAX_CACHED_TOKENS + 100 {
            cache_token(key(i), "token".into(), forever);
        }
        let tokens = TOKENS.lock().unwrap();
        assert!(tokens.len() <= MAX_CACHED_TOKENS);
        let (_, expiry) = tokens.get(&key(MAX_CACHED_TOKENS + 99)).unwrap();
        assert!(*expiry <= Instant::now() + MAX_TOKEN_TTL, "lifetime capped");
        drop(tokens);
        let huge = "x".repeat(MAX_CACHED_TOKEN_BYTES + 1);
        cache_token(key(usize::MAX), huge, Duration::from_secs(60));
        assert_eq!(cached_token(&key(usize::MAX)), None, "not kept");
    }

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
}
