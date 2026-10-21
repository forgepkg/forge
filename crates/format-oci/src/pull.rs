//! Pulls: manifests, blobs, tag lists and referrers, served from hosted,
//! proxy and group repositories alike.

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use forge_db::model::{RepoKind, Repository};
use forge_db::oci_dao::{self, ManifestRow};
use forge_storage::BlobRef;
use futures_util::future::BoxFuture;

use crate::digest::{Digest, DigestError};
use crate::error::{Code, OciError, OciResult};
use crate::manifest::{media, MAX_MANIFEST_BYTES};
use crate::reference::{Reference, ReferenceError};
use crate::service::{location, Caller, Registry, RequestCtx};

/// Tags returned by one `tags/list` page when the client sets no `n`.
const DEFAULT_TAG_PAGE: usize = 10_000;

/// A manifest found for a pull.
#[derive(Debug, Clone)]
pub(crate) struct ManifestHit {
    /// The stored row.
    pub manifest_id: i64,
    pub digest: String,
    pub media_type: String,
    pub size: i64,
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
            blob_sha256: row.blob_sha256,
            s3_key: row.s3_key,
            bytes: None,
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
}

/// A referrer descriptor.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReferrerDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
}

impl ReferrerDescriptor {
    pub fn from_row(row: &ManifestRow) -> Self {
        ReferrerDescriptor {
            media_type: row.media_type.clone(),
            digest: row.digest.clone(),
            size: row.size,
            artifact_type: row.artifact_type.clone(),
            annotations: row
                .summary
                .get("annotations")
                .filter(|a| a.as_object().is_some_and(|o| !o.is_empty()))
                .cloned(),
        }
    }
}

pub(crate) fn parse_digest(raw: &str) -> OciResult<Digest> {
    Digest::parse(raw).map_err(|e| match e {
        DigestError::Invalid(_) => OciError::digest_invalid(format!("invalid digest {raw:?}")),
        DigestError::Unsupported(_) => OciError::new(
            StatusCode::BAD_REQUEST,
            Code::DigestInvalid,
            format!("unsupported digest algorithm in {raw:?}: use sha256 or sha512"),
        ),
    })
}

pub(crate) fn parse_reference(raw: &str) -> OciResult<Reference> {
    Reference::parse(raw).map_err(|e| match e {
        ReferenceError::InvalidTag => OciError::manifest_invalid(format!("invalid tag {raw:?}"))
            .with_detail(serde_json::json!({ "reference": raw })),
        ReferenceError::Digest(_) => parse_digest(raw)
            .err()
            .unwrap_or_else(|| OciError::digest_invalid(format!("invalid digest {raw:?}"))),
    })
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
    ) -> BoxFuture<'a, OciResult<Option<ManifestHit>>> {
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
        digest: &'a Digest,
        depth: u32,
    ) -> BoxFuture<'a, OciResult<Option<BlobHit>>> {
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
    ) -> BoxFuture<'a, OciResult<Option<Vec<String>>>> {
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
        subject: &'a Digest,
        depth: u32,
    ) -> BoxFuture<'a, OciResult<Vec<ReferrerDescriptor>>> {
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
    ) -> OciResult<Option<ManifestHit>> {
        let pool = &self.inner.pool;
        let row = match reference {
            Reference::Tag(tag) => oci_dao::find_tag(pool, repo.id, image, tag)
                .await?
                .map(|t| t.manifest),
            Reference::Digest(digest) => {
                oci_dao::find_manifest(pool, repo.id, image, digest.as_str()).await?
            }
        };
        Ok(row.map(ManifestHit::from_row))
    }

    pub(crate) async fn hosted_blob(
        &self,
        repo: &Repository,
        image: &str,
        digest: &Digest,
    ) -> OciResult<Option<BlobHit>> {
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
    ) -> OciResult<Option<Vec<String>>> {
        let pool = &self.inner.pool;
        let tags = oci_dao::list_tags(pool, repo.id, image, last, limit as i64).await?;
        if tags.is_empty() && last.is_none() && !oci_dao::image_exists(pool, repo.id, image).await?
        {
            return Ok(None);
        }
        Ok(Some(tags))
    }

    pub(crate) async fn local_referrers(
        &self,
        repo: &Repository,
        image: &str,
        subject: &Digest,
    ) -> OciResult<Vec<ReferrerDescriptor>> {
        let rows =
            oci_dao::list_referrers(&self.inner.pool, repo.id, image, subject.as_str()).await?;
        Ok(rows.iter().map(ReferrerDescriptor::from_row).collect())
    }

    /// Read a stored manifest's (or image config's) bytes, through the
    /// local blob cache.
    pub(crate) async fn read_manifest_bytes(&self, blob: BlobRef<'_>) -> OciResult<Bytes> {
        let too_large = || {
            OciError::internal(
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
            .map_err(|e| OciError::internal("manifest read", e))?;
        if bytes.len() as u64 != blob.size {
            return Err(OciError::internal(
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

    // ── Handlers ────────────────────────────────────────────────────────────

    pub(crate) async fn get_manifest(
        &self,
        ctx: &RequestCtx,
        reference: &str,
        head: bool,
        _headers: &HeaderMap,
    ) -> OciResult<Response> {
        let reference = parse_reference(reference).map_err(|e| {
            // A malformed reference names nothing that can exist.
            if e.code == Code::ManifestInvalid {
                OciError::manifest_unknown(reference)
            } else {
                e
            }
        })?;
        let t = &ctx.target;
        let hit = self
            .manifest_from(&ctx.caller, &t.repo, &t.image, &reference, 0)
            .await?
            .ok_or_else(|| OciError::manifest_unknown(reference.as_str()))?;
        let mut response = if head {
            Response::new(Body::empty())
        } else {
            let bytes = match hit.bytes.clone() {
                Some(bytes) => bytes,
                None => self.read_manifest_bytes(hit.blob()).await?,
            };
            if let Err(e) = oci_dao::touch_manifest(&self.inner.pool, hit.manifest_id).await {
                tracing::warn!(error = %e, "registry: recording a manifest pull failed");
            }
            Response::new(Body::from(bytes))
        };
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, header_value(&hit.media_type));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(hit.size));
        headers.insert("docker-content-digest", header_value(&hit.digest));
        headers.insert(header::ETAG, header_value(&format!("\"{}\"", hit.digest)));
        Ok(response)
    }

    pub(crate) async fn get_blob(
        &self,
        ctx: &RequestCtx,
        digest: &str,
        head: bool,
        headers: &HeaderMap,
    ) -> OciResult<Response> {
        let digest = parse_digest(digest)?;
        let t = &ctx.target;
        let hit = self
            .blob_from(&ctx.caller, &t.repo, &t.image, &digest, 0)
            .await?
            .ok_or_else(|| OciError::blob_unknown(digest.as_str()))?;
        if hit.linked {
            if let Err(e) =
                oci_dao::touch_link(&self.inner.pool, hit.repository_id, &hit.image, &hit.digest)
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
                    .map_err(|e| OciError::internal("blob read", e))?;
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

    pub(crate) async fn tags_list(&self, ctx: &RequestCtx, query: &str) -> OciResult<Response> {
        let mut n: Option<usize> = None;
        let mut last: Option<String> = None;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "n" => {
                    n = Some(value.parse().map_err(|_| {
                        OciError::new(
                            StatusCode::BAD_REQUEST,
                            Code::Unsupported,
                            format!("invalid n {value:?}"),
                        )
                    })?)
                }
                "last" => last = Some(value.into_owned()),
                _ => {}
            }
        }
        let page = n.unwrap_or(DEFAULT_TAG_PAGE).min(DEFAULT_TAG_PAGE);
        let t = &ctx.target;
        let tags = if page == 0 {
            Some(Vec::new())
        } else {
            self.tags_from(&ctx.caller, &t.repo, &t.image, last.as_deref(), page + 1, 0)
                .await?
        };
        let Some(mut tags) = tags else {
            return Err(OciError::name_unknown(&t.name));
        };
        let more = tags.len() > page;
        tags.truncate(page);
        let body = serde_json::json!({ "name": t.name, "tags": tags });
        let mut response = (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response();
        if more {
            if let Some(last) = tags.last() {
                let next: String = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("n", &page.to_string())
                    .append_pair("last", last)
                    .finish();
                let link = format!("<{}?{next}>; rel=\"next\"", location(&t.name, "tags/list"));
                response
                    .headers_mut()
                    .insert(header::LINK, header_value(&link));
            }
        }
        Ok(response)
    }

    pub(crate) async fn referrers(
        &self,
        ctx: &RequestCtx,
        digest: &str,
        query: &str,
    ) -> OciResult<Response> {
        let subject = parse_digest(digest)?;
        let artifact_type = url::form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == "artifactType")
            .map(|(_, v)| v.into_owned());
        let t = &ctx.target;
        let mut referrers = self
            .referrers_from(&ctx.caller, &t.repo, &t.image, &subject, 0)
            .await?;
        if let Some(filter) = &artifact_type {
            referrers.retain(|r| r.artifact_type.as_deref() == Some(filter.as_str()));
        }
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": media::OCI_INDEX,
            "manifests": referrers,
        });
        let mut response = (
            StatusCode::OK,
            [(header::CONTENT_TYPE, media::OCI_INDEX)],
            body.to_string(),
        )
            .into_response();
        if artifact_type.is_some() {
            response.headers_mut().insert(
                "oci-filters-applied",
                HeaderValue::from_static("artifactType"),
            );
        }
        Ok(response)
    }
}

/// A header value from text Forge produced or validated.
pub(crate) fn header_value(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static("invalid"))
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
