//! Pulls: manifests, blobs, tag lists and referrers, read from hosted,
//! proxy and group repositories alike, and serving a manifest or a blob the
//! format asked for.

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use forge_db::model::{RepoKind, Repository};
use forge_db::oci_dao::{self, ManifestRow};
use forge_plugin::api::images::{BlobInfo, ManifestInfo, Reference, TagPage, MAX_MANIFEST_BYTES};
use forge_storage::BlobRef;
use futures_util::future::BoxFuture;

use super::digest::ContentDigest;
use super::dispatch::Caller;
use super::{header_value, Failure, ImgResult, Registry};

/// A manifest found for a pull.
#[derive(Debug, Clone)]
pub(crate) struct ManifestHit {
    /// The stored row.
    pub manifest_id: i64,
    pub digest: String,
    pub media_type: String,
    pub size: i64,
    pub artifact_type: Option<String>,
    pub subject_digest: Option<String>,
    pub summary: serde_json::Value,
    pub blob_sha256: String,
    pub s3_key: String,
    /// The bytes, when they are already in memory (a proxy just fetched
    /// them).
    pub bytes: Option<Bytes>,
}

impl ManifestHit {
    /// The stored manifest as a blob of the store.
    pub fn blob(&self) -> BlobRef<'_> {
        BlobRef {
            sha256: &self.blob_sha256,
            s3_key: &self.s3_key,
            size: self.size.max(0) as u64,
        }
    }

    pub fn from_row(row: ManifestRow) -> Self {
        ManifestHit {
            manifest_id: row.id,
            digest: row.digest,
            media_type: row.media_type,
            size: row.size,
            artifact_type: row.artifact_type,
            subject_digest: row.subject_digest,
            summary: row.summary,
            blob_sha256: row.blob_sha256,
            s3_key: row.s3_key,
            bytes: None,
        }
    }

    /// What the format learns of it.
    pub fn info(&self) -> ManifestInfo {
        ManifestInfo {
            digest: self.digest.clone(),
            media_type: self.media_type.clone(),
            size: self.size.max(0) as u64,
            artifact_type: self.artifact_type.clone(),
            subject: self.subject_digest.clone(),
            summary: self
                .summary
                .as_object()
                .filter(|s| !s.is_empty())
                .map(|_| self.summary.to_string()),
        }
    }
}

/// A blob found for a pull.
#[derive(Debug, Clone)]
pub(crate) struct BlobHit {
    pub repository_id: i64,
    pub image: String,
    pub digest: String,
    pub size: i64,
    pub blob_sha256: String,
    pub s3_key: String,
    /// Whether it is an `oci_blob_link` (touched on use) rather than a
    /// manifest read as a blob.
    pub linked: bool,
}

impl BlobHit {
    /// The blob of the store.
    pub fn blob(&self) -> BlobRef<'_> {
        BlobRef {
            sha256: &self.blob_sha256,
            s3_key: &self.s3_key,
            size: self.size.max(0) as u64,
        }
    }

    /// What the format learns of it.
    pub fn info(&self) -> BlobInfo {
        BlobInfo {
            digest: self.digest.clone(),
            size: self.size.max(0) as u64,
        }
    }
}

impl Registry {
    // ── Source dispatch ─────────────────────────────────────────────────────

    /// A manifest of `image` in `repo`, by kind.
    pub(crate) fn manifest_from<'a>(
        &'a self,
        caller: &'a Caller,
        repo: &'a Repository,
        image: &'a str,
        reference: &'a Reference,
        depth: u32,
    ) -> BoxFuture<'a, ImgResult<Option<ManifestHit>>> {
        Box::pin(async move {
            match repo.kind() {
                RepoKind::Hosted => self.hosted_manifest(repo, image, reference).await,
                RepoKind::Proxy => self.proxy_manifest(repo, image, reference).await,
                RepoKind::Group => {
                    self.group_manifest(caller, repo, image, reference, depth)
                        .await
                }
            }
        })
    }

    /// A blob of `image` in `repo`, by kind.
    pub(crate) fn blob_from<'a>(
        &'a self,
        caller: &'a Caller,
        repo: &'a Repository,
        image: &'a str,
        digest: &'a ContentDigest,
        depth: u32,
    ) -> BoxFuture<'a, ImgResult<Option<BlobHit>>> {
        Box::pin(async move {
            match repo.kind() {
                RepoKind::Hosted => self.hosted_blob(repo, image, digest).await,
                RepoKind::Proxy => self.proxy_blob(repo, image, digest).await,
                RepoKind::Group => self.group_blob(caller, repo, image, digest, depth).await,
            }
        })
    }

    /// Up to `limit` tags of `image` after `last`, in byte order. `None` when
    /// the source does not know the image.
    pub(crate) fn tags_from<'a>(
        &'a self,
        caller: &'a Caller,
        repo: &'a Repository,
        image: &'a str,
        last: Option<&'a str>,
        limit: usize,
        depth: u32,
    ) -> BoxFuture<'a, ImgResult<Option<TagPage>>> {
        Box::pin(async move {
            match repo.kind() {
                RepoKind::Hosted => self.local_tags(repo, image, last, limit).await,
                RepoKind::Proxy => self.proxy_tags(repo, image, last, limit).await,
                RepoKind::Group => {
                    self.group_tags(caller, repo, image, last, limit, depth)
                        .await
                }
            }
        })
    }

    /// The referrers of `subject` in `image` of `repo`.
    pub(crate) fn referrers_from<'a>(
        &'a self,
        caller: &'a Caller,
        repo: &'a Repository,
        image: &'a str,
        subject: &'a ContentDigest,
        depth: u32,
    ) -> BoxFuture<'a, ImgResult<Vec<ManifestInfo>>> {
        Box::pin(async move {
            match repo.kind() {
                RepoKind::Hosted => self.local_referrers(repo, image, subject).await,
                RepoKind::Proxy => self.proxy_referrers(repo, image, subject).await,
                RepoKind::Group => {
                    self.group_referrers(caller, repo, image, subject, depth)
                        .await
                }
            }
        })
    }

    // ── Hosted (and cached proxy) content ───────────────────────────────────

    pub(crate) async fn hosted_manifest(
        &self,
        repo: &Repository,
        image: &str,
        reference: &Reference,
    ) -> ImgResult<Option<ManifestHit>> {
        let pool = &self.inner.pool;
        let row = match reference {
            Reference::Tag(tag) => oci_dao::find_tag(pool, repo.id, image, tag)
                .await?
                .map(|t| t.manifest),
            Reference::Digest(digest) => {
                oci_dao::find_manifest(pool, repo.id, image, digest).await?
            }
        };
        Ok(row.map(ManifestHit::from_row))
    }

    pub(crate) async fn hosted_blob(
        &self,
        repo: &Repository,
        image: &str,
        digest: &ContentDigest,
    ) -> ImgResult<Option<BlobHit>> {
        let pool = &self.inner.pool;
        if let Some(link) = oci_dao::find_link(pool, repo.id, image, digest.as_str()).await? {
            return Ok(Some(BlobHit {
                repository_id: repo.id,
                image: image.to_string(),
                digest: link.digest,
                size: link.size,
                blob_sha256: link.blob_sha256,
                s3_key: link.s3_key,
                linked: true,
            }));
        }
        // A manifest is content too: some clients read one through the blob
        // endpoint.
        Ok(
            oci_dao::find_manifest(pool, repo.id, image, digest.as_str())
                .await?
                .map(|m| BlobHit {
                    repository_id: repo.id,
                    image: image.to_string(),
                    digest: m.digest,
                    size: m.size,
                    blob_sha256: m.blob_sha256,
                    s3_key: m.s3_key,
                    linked: false,
                }),
        )
    }

    pub(crate) async fn local_tags(
        &self,
        repo: &Repository,
        image: &str,
        last: Option<&str>,
        limit: usize,
    ) -> ImgResult<Option<TagPage>> {
        let pool = &self.inner.pool;
        let asked = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        let mut tags = oci_dao::list_tags(pool, repo.id, image, last, asked).await?;
        if tags.is_empty() && last.is_none() && !oci_dao::image_exists(pool, repo.id, image).await?
        {
            return Ok(None);
        }
        let more = tags.len() > limit;
        tags.truncate(limit);
        Ok(Some(TagPage { tags, more }))
    }

    pub(crate) async fn local_referrers(
        &self,
        repo: &Repository,
        image: &str,
        subject: &ContentDigest,
    ) -> ImgResult<Vec<ManifestInfo>> {
        let rows =
            oci_dao::list_referrers(&self.inner.pool, repo.id, image, subject.as_str()).await?;
        Ok(rows
            .into_iter()
            .map(|row| ManifestHit::from_row(row).info())
            .collect())
    }

    /// Read a stored manifest's (or a config's) bytes, through the local
    /// blob cache.
    pub(crate) async fn read_manifest_bytes(&self, blob: BlobRef<'_>) -> ImgResult<Bytes> {
        let too_large = || {
            Failure::internal(
                "manifest read",
                format!("stored manifest {} is too large", blob.s3_key),
            )
        };
        if usize::try_from(blob.size).map_or(true, |size| size > MAX_MANIFEST_BYTES) {
            return Err(too_large());
        }
        let bytes = self
            .inner
            .store
            .read_all(blob)
            .await
            .map_err(|e| Failure::storage_read("manifest read", e))?;
        if bytes.len() as u64 != blob.size {
            return Err(Failure::internal(
                "manifest read",
                format!(
                    "stored manifest {} has {} bytes, expected {}",
                    blob.s3_key,
                    bytes.len(),
                    blob.size
                ),
            ));
        }
        Ok(Bytes::from(bytes))
    }

    // ── Serving ─────────────────────────────────────────────────────────────

    /// Serve a manifest the format asked for, as its media type.
    pub(crate) async fn serve_manifest(
        &self,
        hit: &ManifestHit,
        head: bool,
    ) -> ImgResult<Response> {
        let mut response = if head {
            Response::new(Body::empty())
        } else {
            let bytes = match hit.bytes.clone() {
                Some(bytes) => bytes,
                None => self.read_manifest_bytes(hit.blob()).await?,
            };
            Response::new(Body::from(bytes))
        };
        // A HEAD is a pull too: containerd (Kubernetes, nerdctl, BuildKit)
        // resolves a tag with a HEAD and fetches nothing more while it holds
        // the digest, and `tag_not_pulled_for_days` must not delete such a
        // tag. Throttled to one write an hour per manifest.
        if let Err(e) = oci_dao::touch_manifest(&self.inner.pool, hit.manifest_id).await {
            tracing::warn!(error = %e, "registry: recording a manifest pull failed");
        }
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, header_value(&hit.media_type));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(hit.size));
        headers.insert("docker-content-digest", header_value(&hit.digest));
        headers.insert(header::ETAG, header_value(&format!("\"{}\"", hit.digest)));
        Ok(response)
    }

    /// Serve a blob the format asked for, with one `Range`, and record the
    /// pull of its link.
    pub(crate) async fn serve_blob(
        &self,
        hit: &BlobHit,
        head: bool,
        headers: &HeaderMap,
    ) -> ImgResult<Response> {
        if hit.linked {
            if let Err(e) = oci_dao::touch_link(
                &self.inner.pool,
                hit.repository_id,
                &hit.image,
                &hit.digest,
                self.inner.config.link_touch_interval(),
            )
            .await
            {
                tracing::warn!(error = %e, "registry: recording a blob pull failed");
            }
        }
        let size = hit.size.max(0) as u64;
        let range = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
            Some(spec) if size > 0 => match parse_range(spec, size) {
                Some(range) => Some(range),
                None => {
                    return Ok((
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        [(header::CONTENT_RANGE, format!("bytes */{size}"))],
                    )
                        .into_response())
                }
            },
            _ => None,
        };
        let (status, length, body) = match (head, range) {
            (true, Some((start, end))) => {
                (StatusCode::PARTIAL_CONTENT, end - start + 1, Body::empty())
            }
            (true, None) => (StatusCode::OK, size, Body::empty()),
            (false, range) => {
                // Through the local blob cache, like package downloads.
                let stream = self
                    .inner
                    .store
                    .open(hit.blob(), range.map(|(start, end)| start..end + 1))
                    .await
                    .map_err(|e| Failure::storage_read("blob read", e))?;
                match range {
                    Some((start, end)) => (
                        StatusCode::PARTIAL_CONTENT,
                        end - start + 1,
                        Body::from_stream(stream),
                    ),
                    None => (StatusCode::OK, size, Body::from_stream(stream)),
                }
            }
        };
        let mut response = (status, body).into_response();
        let out = response.headers_mut();
        out.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        out.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
        out.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        out.insert("docker-content-digest", header_value(&hit.digest));
        out.insert(header::ETAG, header_value(&format!("\"{}\"", hit.digest)));
        if let Some((start, end)) = range {
            out.insert(
                header::CONTENT_RANGE,
                header_value(&format!("bytes {start}-{end}/{size}")),
            );
        }
        Ok(response)
    }
}

/// One `bytes=` range of a `size`-byte object, as inclusive offsets. `None`
/// when unsatisfiable or malformed (multiple ranges are not supported).
pub(crate) fn parse_range(spec: &str, size: u64) -> Option<(u64, u64)> {
    let spec = spec.trim().strip_prefix("bytes=")?;
    if spec.contains(',') || size == 0 {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    let (start, end) = match (start.trim(), end.trim()) {
        ("", suffix) => {
            let suffix: u64 = suffix.parse().ok()?;
            if suffix == 0 {
                return None;
            }
            (size.saturating_sub(suffix), size - 1)
        }
        (start, "") => (start.parse().ok()?, size - 1),
        (start, end) => (start.parse().ok()?, end.parse::<u64>().ok()?.min(size - 1)),
    };
    (start <= end && start < size).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-9", 100), Some((0, 9)));
        assert_eq!(parse_range("bytes=90-", 100), Some((90, 99)));
        assert_eq!(parse_range("bytes=-10", 100), Some((90, 99)));
        assert_eq!(parse_range("bytes=50-500", 100), Some((50, 99)));
        assert_eq!(parse_range("bytes=100-", 100), None);
        assert_eq!(parse_range("bytes=9-0", 100), None);
        assert_eq!(parse_range("bytes=0-1,5-6", 100), None);
        assert_eq!(parse_range("items=0-1", 100), None);
        assert_eq!(parse_range("bytes=-0", 100), None);
    }
}
