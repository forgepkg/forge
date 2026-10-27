//! Proxy repositories of the file store: files fetched from the upstream on
//! first request, cached content-addressed, and re-validated against the
//! upstream once they are older than the repository's `max_age_seconds`.
//!
//! * The format's plugin names the upstream URL of a path (its upstream
//!   side's `file` operation; raw's is `<remote_url>/<path>`, each segment
//!   percent-encoded), on an origin the upstream points at. Redirects are
//!   followed (GitHub release assets redirect to
//!   `objects.githubusercontent.com`), every hop through the upstream
//!   client's cloud-metadata guard; the upstream credentials go to the
//!   origin of `remote_url` only.
//! * Re-validation is a conditional GET (`If-None-Match` with the upstream's
//!   `ETag`, `If-Modified-Since` with its `Last-Modified`): a `304` keeps
//!   the copy, new content replaces it. A `max_age_seconds` of `0` never
//!   re-validates. While the upstream is down (or answers an error), the
//!   cached copy is served; a file the upstream no longer has is served
//!   from the cache too, until it is deleted or retention evicts it.
//! * A miss is remembered for `not_found_ttl_seconds` (per instance, keyed
//!   by the repository's `updated_at`, which *Invalidate cache* bumps).
//! * Concurrent first fetches of one file share one upstream request per
//!   instance.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, PoisonError, Weak};
use std::time::Duration;

use axum::http::StatusCode;
use forge_core::net::upstream::{RequestClass, UpstreamAuth};
use forge_core::repo::proxy::{upstream_credentials, Credentials, DEFAULT_NOT_FOUND_TTL_SECONDS};
use forge_db::model::Repository;
use forge_db::oci_dao;
use forge_db::raw_dao::{self, NewRawFile, RawFile, Redeploy};
use forge_telemetry::proxy::{Kind as LookupKind, Lookup, Outcome};
use futures_util::TryStreamExt;
use reqwest::header::{CONTENT_TYPE, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use tracing::Instrument;

use super::store::{content_type, ingest};
use super::{FileError, Files};

/// The gate of one file's upstream requests, by `(repository id, path)`.
type Gates = HashMap<(i64, String), Weak<tokio::sync::Mutex<()>>>;

/// In-flight upstream requests, so concurrent requests for one file share
/// a single upstream fetch per process.
static GATES: LazyLock<Mutex<Gates>> = LazyLock::new(Default::default);

fn gate(repository_id: i64, path: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut gates = GATES.lock().unwrap_or_else(PoisonError::into_inner);
    if gates.len() >= 1024 {
        gates.retain(|_, weak| weak.strong_count() > 0);
    }
    let key = (repository_id, path.to_string());
    if let Some(existing) = gates.get(&key).and_then(Weak::upgrade) {
        return existing;
    }
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    gates.insert(key, Arc::downgrade(&gate));
    gate
}

fn header_text(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 1024)
        .map(str::to_string)
}

impl Files<'_> {
    /// Keyed by the repository's `updated_at` too, so an administrator's
    /// cache invalidation (which bumps it) forgets the misses on every
    /// instance.
    fn not_found_key(repo: &Repository, path: &str) -> String {
        format!("{}:{}:{path}", repo.id, repo.updated_at.timestamp_micros())
    }

    async fn negative_cached(&self, repo: &Repository, path: &str) -> bool {
        let key = Self::not_found_key(repo, path);
        let hit: Result<bool, ()> = self
            .state
            .cache
            .get_or_try_insert_local(
                "files:upstream-nf",
                &key,
                Duration::from_secs(1),
                || async { Err(()) },
            )
            .await;
        hit.unwrap_or(false)
    }

    async fn remember_not_found(&self, repo: &Repository, path: &str) {
        let ttl = repo
            .not_found_ttl_seconds
            .map(i64::from)
            .unwrap_or(DEFAULT_NOT_FOUND_TTL_SECONDS)
            .max(0) as u64;
        if ttl == 0 {
            return;
        }
        let key = Self::not_found_key(repo, path);
        let _: Result<bool, ()> = self
            .state
            .cache
            .get_or_try_insert_local(
                "files:upstream-nf",
                &key,
                Duration::from_secs(ttl),
                || async { Ok(true) },
            )
            .await;
    }

    async fn credentials(&self, repo: &Repository) -> Result<Option<Credentials>, FileError> {
        upstream_credentials(&self.state.pool, &self.state.envelope, repo)
            .await
            .map_err(|e| FileError::Internal(format!("proxy credentials: {e}")))
    }

    /// The upstream URL of `path`, as the format's plugin names it; `None`
    /// when the upstream cannot have it.
    async fn upstream_url(
        &self,
        repo: &Repository,
        path: &str,
    ) -> Result<Option<String>, FileError> {
        let format = self
            .state
            .formats
            .for_repository(repo)
            .map_err(|e| FileError::Unavailable(e.to_string()))?;
        self.state
            .proxy_repo(format)
            .file_url(repo, path)
            .await
            .map_err(|e| {
                tracing::warn!(repo = %repo.name, %path, error = %e, "file proxy: the upstream URL could not be resolved");
                FileError::BadGateway(format!("the upstream could not be reached: {e}"))
            })
    }

    /// GET `url` (the upstream's `path`), conditionally on `cached`'s
    /// validators.
    async fn upstream_get(
        &self,
        repo: &Repository,
        path: &str,
        url: &str,
        cached: Option<&RawFile>,
    ) -> Result<reqwest::Response, FileError> {
        let credentials = self.credentials(repo).await?;
        let auth: Option<UpstreamAuth<'_>> = credentials.as_ref().map(Credentials::auth);
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(cached) = cached {
            let mut put = |name, value: &Option<String>| {
                if let Some(value) = value
                    .as_deref()
                    .and_then(|v| reqwest::header::HeaderValue::from_str(v).ok())
                {
                    headers.insert(name, value);
                }
            };
            put(IF_NONE_MATCH, &cached.upstream_etag);
            put(IF_MODIFIED_SINCE, &cached.upstream_last_modified);
        }
        self.state
            .upstream
            .for_repository(&repo.name)
            .send(
                reqwest::Method::GET,
                url,
                RequestClass::Download,
                headers,
                auth.as_ref(),
            )
            .await
            .map_err(|e| {
                tracing::warn!(repo = %repo.name, %path, error = %e, "file proxy: upstream request failed");
                FileError::BadGateway(format!("the upstream could not be reached: {e}"))
            })
    }

    /// Cache a successful upstream response as `path`.
    async fn store_response(
        &self,
        repo: &Repository,
        path: &str,
        response: reqwest::Response,
    ) -> Result<RawFile, FileError> {
        let limit = self.state.upstream.config().max_package_bytes;
        if response.content_length().is_some_and(|len| len > limit) {
            return Err(FileError::BadGateway(format!(
                "the upstream file is larger than proxy.max_package_bytes ({limit} bytes)"
            )));
        }
        let headers = response.headers().clone();
        let etag = header_text(&headers, ETAG);
        let last_modified = header_text(&headers, LAST_MODIFIED);
        let declared = header_text(&headers, CONTENT_TYPE);
        let body = response.bytes_stream().map_err(std::io::Error::other);
        let ingested = ingest(self, body, limit).await.map_err(|e| match e {
            FileError::TooLarge(limit) => FileError::BadGateway(format!(
                "the upstream file is larger than proxy.max_package_bytes ({limit} bytes)"
            )),
            FileError::BadRequest(msg) => {
                FileError::BadGateway(format!("the upstream download failed: {msg}"))
            }
            other => other,
        })?;
        let stored = &ingested.stored;
        forge_telemetry::proxy::upstream_bytes(&repo.name, stored.size);
        let content_type = content_type(declared.as_deref(), path);
        let mut tx = forge_db::begin(&self.state.pool).await?;
        if !oci_dao::lock_proxy_upstream(&mut tx, repo.id, repo.remote_url.as_deref()).await? {
            return Err(FileError::Unavailable(
                "the proxy was pointed at another upstream while this was fetched; retry".into(),
            ));
        }
        raw_dao::store(
            &mut tx,
            repo.id,
            &NewRawFile {
                path,
                sha256: &stored.sha256,
                size: i64::try_from(stored.size).map_err(|_| FileError::TooLarge(stored.size))?,
                content_type: &content_type,
                sha512_base64: &stored.sha512_base64,
                sha1: &ingested.sha1,
                md5: &ingested.md5,
                upstream_etag: etag.as_deref(),
                upstream_last_modified: last_modified.as_deref(),
                checked: true,
            },
            stored.ingest_token,
            Redeploy::Allow,
            self.state.config.outbox.grace(),
        )
        .await?;
        tx.commit().await?;
        raw_dao::find(&self.state.pool, repo.id, path)
            .await?
            .ok_or(FileError::NotFound)
    }

    /// The cached `file` of proxy `repo`, re-validated first when it is due.
    pub async fn fresh(&self, repo: &Repository, file: RawFile) -> RawFile {
        let mut lookup = Lookup::start(&repo.name, LookupKind::File);
        let span = lookup.span();
        let file = self
            .fresh_file(repo, file, &mut lookup)
            .instrument(span)
            .await;
        let outcome = lookup.marked().unwrap_or(Outcome::Hit);
        lookup.finish(outcome);
        file
    }

    /// [`Self::fresh`], marking what it does on `lookup`.
    async fn fresh_file(&self, repo: &Repository, file: RawFile, lookup: &mut Lookup) -> RawFile {
        let max_age = repo.max_age_seconds();
        if max_age == 0 || !repo.online || !is_due(&file, max_age) {
            return file;
        }
        let gate = gate(repo.id, &file.path);
        let _held = gate.lock().await;
        // Another request may have re-validated it meanwhile.
        let file = match raw_dao::find(&self.state.pool, repo.id, &file.path).await {
            Ok(Some(current)) if !is_due(&current, max_age) => return current,
            Ok(Some(current)) => current,
            _ => file,
        };
        match self.revalidate(repo, &file, lookup).await {
            Ok(current) => current,
            Err(error) => {
                lookup.mark(Outcome::StaleServed);
                tracing::warn!(repo = %repo.name, path = %file.path, error = %error.message(), "file proxy: re-validation failed; serving the cached copy");
                file
            }
        }
    }

    async fn revalidate(
        &self,
        repo: &Repository,
        file: &RawFile,
        lookup: &mut Lookup,
    ) -> Result<RawFile, FileError> {
        let Some(url) = self.upstream_url(repo, &file.path).await? else {
            // The upstream cannot have it (any more): the cached copy stands.
            raw_dao::mark_checked(&self.state.pool, file.id, None, None).await?;
            return Ok(file.clone());
        };
        let response = self
            .upstream_get(repo, &file.path, &url, Some(file))
            .await?;
        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            let headers = response.headers();
            raw_dao::mark_checked(
                &self.state.pool,
                file.id,
                header_text(headers, ETAG).as_deref(),
                header_text(headers, LAST_MODIFIED).as_deref(),
            )
            .await?;
            return Ok(file.clone());
        }
        if status.is_success() {
            lookup.mark(Outcome::Fetched);
            return self.store_response(repo, &file.path, response).await;
        }
        if matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
            lookup.mark(Outcome::StaleServed);
            tracing::warn!(repo = %repo.name, path = %file.path, "file proxy: the upstream no longer has a cached file; serving the cached copy");
            raw_dao::mark_checked(&self.state.pool, file.id, None, None).await?;
            return Ok(file.clone());
        }
        Err(FileError::BadGateway(format!(
            "the upstream answered {status}"
        )))
    }

    /// Fetch `path` from the upstream of proxy `repo` and cache it. `None`
    /// when the upstream does not have it (or the proxy is offline).
    pub async fn fetch(&self, repo: &Repository, path: &str) -> Result<Option<RawFile>, FileError> {
        let mut lookup = Lookup::start(&repo.name, LookupKind::File);
        let span = lookup.span();
        let result = self
            .fetch_file(repo, path, &mut lookup)
            .instrument(span)
            .await;
        let marked = lookup.marked();
        let outcome = match &result {
            Ok(Some(_)) => marked.unwrap_or(Outcome::Hit),
            Ok(None) => marked.unwrap_or(Outcome::NotFound),
            Err(FileError::BadGateway(_)) => Outcome::UpstreamError,
            Err(_) => Outcome::Error,
        };
        lookup.finish(outcome);
        result
    }

    /// [`Self::fetch`], marking what it finds on `lookup`.
    async fn fetch_file(
        &self,
        repo: &Repository,
        path: &str,
        lookup: &mut Lookup,
    ) -> Result<Option<RawFile>, FileError> {
        if !repo.online {
            lookup.mark(Outcome::Offline);
            return Ok(None);
        }
        if self.negative_cached(repo, path).await {
            lookup.mark(Outcome::NegativeCached);
            return Ok(None);
        }
        let gate = gate(repo.id, path);
        let _held = gate.lock().await;
        if let Some(file) = raw_dao::find(&self.state.pool, repo.id, path).await? {
            return Ok(Some(file));
        }
        if self.negative_cached(repo, path).await {
            lookup.mark(Outcome::NegativeCached);
            return Ok(None);
        }
        let Some(url) = self.upstream_url(repo, path).await? else {
            self.remember_not_found(repo, path).await;
            return Ok(None);
        };
        let response = self.upstream_get(repo, path, &url, None).await?;
        let status = response.status();
        if matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
            self.remember_not_found(repo, path).await;
            return Ok(None);
        }
        if !status.is_success() {
            tracing::warn!(repo = %repo.name, %path, %status, "file proxy: upstream error");
            return Err(FileError::BadGateway(format!(
                "the upstream answered {status}"
            )));
        }
        lookup.mark(Outcome::Fetched);
        self.store_response(repo, path, response).await.map(Some)
    }
}

/// Whether a cached file is due for re-validation after `max_age` seconds.
fn is_due(file: &RawFile, max_age: u64) -> bool {
    let max_age = chrono::Duration::seconds(i64::try_from(max_age).unwrap_or(i64::MAX / 1000));
    file.checked_at
        .is_none_or(|checked| chrono::Utc::now() - checked >= max_age)
}
