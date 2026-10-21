//! Pushes and deletes: blob uploads (monolithic, chunked, cross-repository
//! mounts), manifests and tags.
//!
//! Upload chunks are CAS blobs held by `oci_upload_part` rows, so a session
//! survives on any instance. When an upload consists of one chunk (what
//! docker, podman and containerd send) that chunk already is the blob and is
//! linked as is; only multi-chunk uploads are assembled into a new blob.

use std::io::Cursor;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use forge_core::authz::Action;
use forge_core::repo::{PackageMutation, PublishAuthorizationContext, WriteError};
use forge_db::model::{RepoKind, Repository};
use forge_db::oci_dao::{self, LinkOutcome, NewManifest, TagWrite, UploadRow};
use forge_storage::BlobRef;
use futures_util::{StreamExt, TryStreamExt};
use tokio_util::io::StreamReader;
use uuid::Uuid;

use crate::digest::Digest;
use crate::error::{Code, OciError, OciResult};
use crate::manifest::{
    self, config_platform, is_image_config, media, ManifestError, ManifestKind, ParsedManifest,
    EMPTY_JSON, EMPTY_JSON_DIGEST, MAX_MANIFEST_BYTES,
};
use crate::pull::{header_value, parse_digest, parse_reference};
use crate::reference::{self, Reference};
use crate::service::{location, Decision, Registry, RequestCtx, Target};

/// Config blobs larger than this are not read for the platform summary.
const MAX_CONFIG_SUMMARY_BYTES: i64 = 1024 * 1024;

/// Refuse to commit a link whose blob turned out to be gone or being
/// deleted: dropping the transaction rolls the link row back, so no link
/// ever exists without its reference.
pub(crate) fn require_linked(outcome: LinkOutcome) -> OciResult<()> {
    match outcome {
        LinkOutcome::BlobUnavailable => Err(OciError::unavailable(
            "the blob is being removed from storage; retry the upload",
        )),
        LinkOutcome::Inserted | LinkOutcome::AlreadyLinked => Ok(()),
    }
}

/// A request body as an `AsyncRead`.
fn body_reader(body: Body) -> impl tokio::io::AsyncRead + Unpin + Send {
    StreamReader::new(body.into_data_stream().map_err(std::io::Error::other))
}

/// Read a whole (small) request body, refusing more than `limit` bytes.
async fn read_body(body: Body, limit: usize) -> OciResult<Bytes> {
    let mut stream = body.into_data_stream();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            OciError::new(
                StatusCode::BAD_REQUEST,
                Code::ManifestInvalid,
                format!("reading the body: {e}"),
            )
        })?;
        if out.len() + chunk.len() > limit {
            return Err(OciError::too_large(limit as u64));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

/// An upload session id from the URL.
fn upload_id(raw: &str) -> OciResult<Uuid> {
    Uuid::parse_str(raw).map_err(|_| OciError::upload_unknown())
}

/// `Range` of an upload: the inclusive end of the bytes received.
fn upload_range(size: i64) -> HeaderValue {
    header_value(&format!("0-{}", (size - 1).max(0)))
}

/// The 202 answer of an upload session in progress.
fn upload_accepted(status: StatusCode, name: &str, upload: &UploadRow) -> Response {
    let mut response = status.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::LOCATION,
        header_value(&location(name, &format!("blobs/uploads/{}", upload.id))),
    );
    headers.insert(header::RANGE, upload_range(upload.size));
    headers.insert("docker-upload-uuid", header_value(&upload.id.to_string()));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(0));
    response
}

/// The 201 answer of a stored blob.
fn blob_created(name: &str, digest: &str) -> Response {
    let mut response = StatusCode::CREATED.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::LOCATION,
        header_value(&location(name, &format!("blobs/{digest}"))),
    );
    headers.insert("docker-content-digest", header_value(digest));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(0));
    response
}

/// `Content-Range: <start>-<end>` of a chunk (also accepting a `bytes`
/// prefix some clients add).
fn content_range(headers: &HeaderMap) -> OciResult<Option<(i64, i64)>> {
    let Some(value) = headers.get(header::CONTENT_RANGE) else {
        return Ok(None);
    };
    let invalid = || {
        OciError::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            Code::BlobUploadInvalid,
            "invalid Content-Range",
        )
    };
    let text = value.to_str().map_err(|_| invalid())?.trim();
    let text = text
        .strip_prefix("bytes=")
        .or_else(|| text.strip_prefix("bytes "))
        .unwrap_or(text);
    let text = text.split('/').next().unwrap_or(text);
    let (start, end) = text.split_once('-').ok_or_else(invalid)?;
    let start: i64 = start.trim().parse().map_err(|_| invalid())?;
    let end: i64 = end.trim().parse().map_err(|_| invalid())?;
    if start < 0 || end < start {
        return Err(invalid());
    }
    Ok(Some((start, end)))
}

impl Registry {
    fn grace(&self) -> chrono::Duration {
        self.inner.config.delete_grace
    }

    /// The largest blob a push to `repo` may carry: its own upload limit,
    /// else the registry's default.
    fn blob_limit(&self, repo: &Repository) -> u64 {
        repo.max_upload_bytes()
            .unwrap_or(self.inner.config.default_max_upload_bytes)
    }

    // ── Uploads ─────────────────────────────────────────────────────────────

    pub(crate) async fn start_upload(
        &self,
        ctx: &RequestCtx,
        req: Request<Body>,
    ) -> OciResult<Response> {
        let t = ctx.serving();
        let name = &ctx.target.name;
        let query = req.uri().query().unwrap_or_default().to_string();
        let params: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let param = |k: &str| {
            params
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };

        if let Some(mount) = param("mount") {
            let digest = parse_digest(&mount)?;
            if self.mount(ctx, &digest, param("from").as_deref()).await? {
                return Ok(blob_created(name, digest.as_str()));
            }
            // Not mountable: fall back to a regular upload session.
        }
        if let Some(digest) = param("digest") {
            // Monolithic upload: the body is the whole blob.
            let digest = parse_digest(&digest)?;
            let staged = self
                .inner
                .cas
                .stage(body_reader(req.into_body()), self.blob_limit(&t.repo))
                .await?;
            if !digest.matches(&staged.sha256, &staged.sha512_base64) {
                return Err(OciError::digest_invalid(
                    "the uploaded content does not match the digest",
                ));
            }
            let stored = self.inner.cas.commit(staged).await?;
            let mut tx = self.inner.pool.begin().await?;
            oci_dao::insert_link_ingested(
                &mut tx,
                t.repo.id,
                &t.image,
                digest.as_str(),
                &stored.sha256,
                stored.size as i64,
                stored.ingest_token,
            )
            .await
            .map_err(OciError::from)
            .and_then(require_linked)?;
            tx.commit().await?;
            return Ok(blob_created(name, digest.as_str()));
        }
        let id = Uuid::new_v4();
        oci_dao::create_upload(&self.inner.pool, id, t.repo.id, &t.image).await?;
        let upload = UploadRow {
            id,
            repository_id: t.repo.id,
            image: t.image.clone(),
            size: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        Ok(upload_accepted(StatusCode::ACCEPTED, name, &upload))
    }

    /// Link `digest` into the target image without uploading it: from the
    /// image `from` the caller may read, or (without `from`) when the image
    /// already has it. `false` when it cannot be mounted.
    async fn mount(
        &self,
        ctx: &RequestCtx,
        digest: &Digest,
        from: Option<&str>,
    ) -> OciResult<bool> {
        let t = ctx.serving();
        let pool = &self.inner.pool;
        if oci_dao::find_link(pool, t.repo.id, &t.image, digest.as_str())
            .await?
            .is_some()
        {
            return Ok(true);
        }
        let Some(from) = from.filter(|f| reference::valid_name(f)) else {
            return Ok(false);
        };
        let Ok(Some(source)) = self.resolve(&ctx.site, from).await else {
            return Ok(false);
        };
        if !matches!(source.repo.kind(), RepoKind::Hosted | RepoKind::Proxy)
            || self.decide(&ctx.caller, &source, Action::Read).await != Decision::Allow
        {
            return Ok(false);
        }
        let Some(link) =
            oci_dao::find_link(pool, source.repo.id, &source.image, digest.as_str()).await?
        else {
            return Ok(false);
        };
        let mut tx = pool.begin().await?;
        match oci_dao::insert_link_existing(
            &mut tx,
            t.repo.id,
            &t.image,
            digest.as_str(),
            &link.blob_sha256,
            link.size,
        )
        .await?
        {
            LinkOutcome::BlobUnavailable => {
                tx.rollback().await?;
                Ok(false)
            }
            LinkOutcome::Inserted | LinkOutcome::AlreadyLinked => {
                tx.commit().await?;
                Ok(true)
            }
        }
    }

    async fn upload_of(&self, ctx: &RequestCtx, id: &str) -> OciResult<UploadRow> {
        let t = ctx.serving();
        oci_dao::get_upload(&self.inner.pool, upload_id(id)?, t.repo.id, &t.image)
            .await?
            .ok_or_else(OciError::upload_unknown)
    }

    pub(crate) async fn upload_status(&self, ctx: &RequestCtx, id: &str) -> OciResult<Response> {
        let upload = self.upload_of(ctx, id).await?;
        Ok(upload_accepted(
            StatusCode::NO_CONTENT,
            &ctx.target.name,
            &upload,
        ))
    }

    pub(crate) async fn cancel_upload(&self, ctx: &RequestCtx, id: &str) -> OciResult<Response> {
        let upload = self.upload_of(ctx, id).await?;
        let mut tx = self.inner.pool.begin().await?;
        let deleted = oci_dao::delete_upload(&mut tx, upload.id, self.grace()).await?;
        tx.commit().await?;
        if !deleted {
            return Err(OciError::upload_unknown());
        }
        Ok(StatusCode::NO_CONTENT.into_response())
    }

    /// Store one chunk of an upload. `expected_start` is where the chunk
    /// must begin (the session's size when the request started); the whole
    /// blob may be at most `max` bytes.
    async fn append_chunk(
        &self,
        upload: &UploadRow,
        range: Option<(i64, i64)>,
        body: Body,
        max: u64,
    ) -> OciResult<UploadRow> {
        let out_of_order = |size: i64| {
            OciError::new(
                StatusCode::RANGE_NOT_SATISFIABLE,
                Code::BlobUploadInvalid,
                "the chunk does not continue the upload",
            )
            .with_header(header::RANGE, upload_range(size))
        };
        if let Some((start, _)) = range {
            if start != upload.size {
                return Err(out_of_order(upload.size));
            }
        }
        let remaining = max.saturating_sub(upload.size.max(0) as u64);
        let staged = self
            .inner
            .cas
            .stage(body_reader(body), remaining)
            .await
            .map_err(|e| match e {
                forge_storage::CasError::TooLarge { .. } => OciError::too_large(max),
                other => other.into(),
            })?;
        if let Some((start, end)) = range {
            if staged.size as i64 != end - start + 1 {
                return Err(OciError::new(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    Code::BlobUploadInvalid,
                    "the chunk length does not match its Content-Range",
                )
                .with_header(header::RANGE, upload_range(upload.size)));
            }
        }
        if staged.size == 0 {
            return Ok(upload.clone());
        }
        let stored = self.inner.cas.commit(staged).await?;
        let mut tx = self.inner.pool.begin().await?;
        let Some(locked) =
            oci_dao::lock_upload(&mut tx, upload.id, upload.repository_id, &upload.image).await?
        else {
            return Err(OciError::upload_unknown());
        };
        if locked.size != upload.size {
            // Another chunk landed meanwhile.
            return Err(out_of_order(locked.size));
        }
        oci_dao::add_upload_part(
            &mut tx,
            &locked,
            stored.size as i64,
            &stored.sha256,
            &stored.sha512_base64,
            stored.ingest_token,
        )
        .await?;
        tx.commit().await?;
        Ok(UploadRow {
            size: locked.size + stored.size as i64,
            updated_at: chrono::Utc::now(),
            ..locked
        })
    }

    pub(crate) async fn patch_upload(
        &self,
        ctx: &RequestCtx,
        id: &str,
        req: Request<Body>,
    ) -> OciResult<Response> {
        let upload = self.upload_of(ctx, id).await?;
        let range = content_range(req.headers())?;
        let max = self.blob_limit(&ctx.serving().repo);
        let upload = self
            .append_chunk(&upload, range, req.into_body(), max)
            .await?;
        Ok(upload_accepted(
            StatusCode::ACCEPTED,
            &ctx.target.name,
            &upload,
        ))
    }

    pub(crate) async fn finish_upload(
        &self,
        ctx: &RequestCtx,
        id: &str,
        req: Request<Body>,
    ) -> OciResult<Response> {
        let t = ctx.serving();
        let upload = self.upload_of(ctx, id).await?;
        let digest = url::form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
            .find(|(k, _)| k == "digest")
            .map(|(_, v)| v.into_owned())
            .ok_or_else(|| OciError::digest_invalid("the digest query parameter is required"))?;
        let digest = parse_digest(&digest)?;
        let range = content_range(req.headers())?;
        let max = self.blob_limit(&t.repo);
        let upload = self
            .append_chunk(&upload, range, req.into_body(), max)
            .await?;
        let pool = &self.inner.pool;
        let parts = oci_dao::upload_parts(pool, upload.id).await?;

        let mismatch =
            || OciError::digest_invalid("the uploaded content does not match the digest");
        // The blob: the single chunk itself, or the chunks assembled.
        let mut tx;
        match parts.as_slice() {
            [part] => {
                if !digest.matches(&part.blob_sha256, &part.sha512_base64) {
                    self.drop_upload(upload.id).await;
                    return Err(mismatch());
                }
                tx = pool.begin().await?;
                if oci_dao::lock_upload(&mut tx, upload.id, t.repo.id, &t.image)
                    .await?
                    .is_none_or(|u| u.size != upload.size)
                {
                    return Err(OciError::upload_unknown());
                }
                // Linked before the chunk's reference is released, so the
                // blob never drops to zero references.
                if oci_dao::insert_link_existing(
                    &mut tx,
                    t.repo.id,
                    &t.image,
                    digest.as_str(),
                    &part.blob_sha256,
                    part.size,
                )
                .await?
                    == LinkOutcome::BlobUnavailable
                {
                    tx.rollback().await?;
                    return Err(OciError::internal(
                        "upload finish",
                        "the uploaded chunk vanished from the CAS",
                    ));
                }
                oci_dao::delete_upload(&mut tx, upload.id, self.grace()).await?;
            }
            parts => {
                let store = self.inner.store.clone();
                let keys: Vec<String> = parts.iter().map(|p| p.s3_key.clone()).collect();
                let chunks = futures_util::stream::iter(keys)
                    .then(move |key| {
                        let store = store.clone();
                        async move {
                            store
                                .get(&key)
                                .await
                                .map(|s| tokio_util::io::ReaderStream::new(s.into_async_read()))
                                .map_err(std::io::Error::other)
                        }
                    })
                    .try_flatten();
                let staged = self
                    .inner
                    .cas
                    .stage(StreamReader::new(Box::pin(chunks)), max)
                    .await?;
                if staged.size as i64 != upload.size
                    || !digest.matches(&staged.sha256, &staged.sha512_base64)
                {
                    self.drop_upload(upload.id).await;
                    return Err(mismatch());
                }
                let stored = self.inner.cas.commit(staged).await?;
                tx = pool.begin().await?;
                if oci_dao::lock_upload(&mut tx, upload.id, t.repo.id, &t.image)
                    .await?
                    .is_none_or(|u| u.size != upload.size)
                {
                    return Err(OciError::upload_unknown());
                }
                oci_dao::insert_link_ingested(
                    &mut tx,
                    t.repo.id,
                    &t.image,
                    digest.as_str(),
                    &stored.sha256,
                    stored.size as i64,
                    stored.ingest_token,
                )
                .await
                .map_err(OciError::from)
                .and_then(require_linked)?;
                oci_dao::delete_upload(&mut tx, upload.id, self.grace()).await?;
                tx.commit().await?;
                return Ok(blob_created(&ctx.target.name, digest.as_str()));
            }
        }
        tx.commit().await?;
        Ok(blob_created(&ctx.target.name, digest.as_str()))
    }

    /// End a failed upload session (best effort).
    async fn drop_upload(&self, id: Uuid) {
        let result = async {
            let mut tx = self.inner.pool.begin().await?;
            oci_dao::delete_upload(&mut tx, id, self.grace()).await?;
            tx.commit().await
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, upload = %id, "registry: dropping a failed upload failed");
        }
    }

    // ── Manifests ───────────────────────────────────────────────────────────

    pub(crate) async fn put_manifest(
        &self,
        ctx: &RequestCtx,
        reference: &str,
        req: Request<Body>,
    ) -> OciResult<Response> {
        let t = ctx.serving();
        let reference = parse_reference(reference)?;
        let mut tags: Vec<String> = Vec::new();
        if let Reference::Tag(tag) = &reference {
            tags.push(tag.clone());
        }
        for (key, value) in
            url::form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
        {
            if key == "tag" {
                if !reference::valid_tag(&value) {
                    return Err(OciError::manifest_invalid(format!("invalid tag {value:?}")));
                }
                if !tags.iter().any(|t| *t == value) {
                    tags.push(value.into_owned());
                }
            }
        }
        let content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = read_body(req.into_body(), MAX_MANIFEST_BYTES).await?;
        let parsed = manifest::parse(&body, content_type.as_deref()).map_err(manifest_error)?;
        let digest = match &reference {
            Reference::Digest(d) => {
                if Digest::of(d.algorithm(), &body) != *d {
                    return Err(OciError::digest_invalid(
                        "the manifest does not match the digest it was pushed as",
                    ));
                }
                d.clone()
            }
            Reference::Tag(_) => Digest::sha256_of(&body),
        };

        // What must exist before the manifest may: its blobs (except layers
        // that live elsewhere by definition) and, for an index, its children.
        let required_blobs: Vec<String> = parsed
            .blob_references()
            .into_iter()
            .filter(|d| !media::is_non_distributable(&d.media_type))
            .map(|d| d.digest.to_string())
            .collect();
        if required_blobs.iter().any(|d| d == EMPTY_JSON_DIGEST) {
            self.ensure_empty_json(t).await?;
        }
        let children: Vec<String> = parsed
            .manifest_references()
            .into_iter()
            .map(|d| d.digest.to_string())
            .collect();
        let summary = self.manifest_summary(t, &parsed).await;

        let staged = self
            .inner
            .cas
            .stage(Cursor::new(body.to_vec()), MAX_MANIFEST_BYTES as u64)
            .await?;
        let stored = self.inner.cas.commit(staged).await?;

        let mut tx = self.inner.pool.begin().await?;
        let linked = oci_dao::lock_links(&mut tx, t.repo.id, &t.image, &required_blobs).await?;
        if let Some(missing) = required_blobs.iter().find(|d| !linked.contains(d)) {
            return Err(OciError::new(
                StatusCode::BAD_REQUEST,
                Code::ManifestBlobUnknown,
                "the manifest references a blob unknown to this repository",
            )
            .with_detail(serde_json::json!({ "digest": missing })));
        }
        if !children.is_empty() {
            let present =
                oci_dao::existing_manifests(&mut tx, t.repo.id, &t.image, &children).await?;
            if let Some(missing) = children.iter().find(|d| !present.contains(d)) {
                return Err(OciError::new(
                    StatusCode::BAD_REQUEST,
                    Code::ManifestBlobUnknown,
                    "the index references a manifest unknown to this repository",
                )
                .with_detail(serde_json::json!({ "digest": missing })));
            }
        }
        let blob_refs: Vec<String> = parsed
            .blob_references()
            .into_iter()
            .map(|d| d.digest.to_string())
            .collect();
        let subject = parsed.subject.as_ref().map(|s| s.digest.to_string());
        let (manifest_id, _) = oci_dao::insert_manifest(
            &mut tx,
            NewManifest {
                repository_id: t.repo.id,
                image: &t.image,
                digest: digest.as_str(),
                blob_sha256: &stored.sha256,
                media_type: &parsed.media_type,
                artifact_type: parsed.artifact_type.as_deref(),
                subject_digest: subject.as_deref(),
                size: body.len() as i64,
                summary: &summary,
                blob_refs: &blob_refs,
                manifest_refs: &children,
            },
            stored.ingest_token,
        )
        .await?;
        let immutable = t.repo.immutable_tags();
        for tag in &tags {
            let may_move = !immutable || (tag == "latest" && t.repo.latest_mutable());
            match oci_dao::set_tag(&mut tx, t.repo.id, &t.image, tag, manifest_id, may_move).await?
            {
                TagWrite::Refused => {
                    return Err(OciError::denied(format!(
                        "tag {tag:?} already exists and tags are immutable in this repository"
                    ))
                    .with_detail(serde_json::json!({ "tag": tag })));
                }
                TagWrite::Created | TagWrite::Moved { .. } | TagWrite::Unchanged => {}
            }
        }
        if let Some(recorder) = &self.inner.recorder {
            let policy = recorder.for_repository(&t.repo);
            let context = PublishAuthorizationContext {
                principal: ctx.caller.principal,
                action: PackageMutation::Publish,
                package_id: t.image.clone(),
                package_version: tags.first().cloned().unwrap_or_else(|| digest.to_string()),
            };
            policy
                .record_in_transaction(&context, &mut tx)
                .await
                .map_err(|e| match e {
                    WriteError::ForbiddenPackage { .. } => {
                        OciError::denied("the workload identity may no longer publish here")
                    }
                    other => OciError::internal("publish record", other),
                })?;
        }
        tx.commit().await?;

        let mut response = StatusCode::CREATED.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::LOCATION,
            header_value(&location(&ctx.target.name, &format!("manifests/{digest}"))),
        );
        headers.insert("docker-content-digest", header_value(digest.as_str()));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(0));
        if let Some(subject) = subject {
            headers.insert("oci-subject", header_value(&subject));
        }
        // A push by digest with `?tag=` parameters names every tag it set.
        if matches!(reference, Reference::Digest(_)) {
            for tag in &tags {
                headers.append("oci-tag", header_value(tag));
            }
        }
        Ok(response)
    }

    /// Make sure the OCI empty JSON blob (`{}`) is linked into the image:
    /// clients commonly reference it as an artifact's config without
    /// uploading it.
    async fn ensure_empty_json(&self, t: &Target) -> OciResult<()> {
        let pool = &self.inner.pool;
        if oci_dao::find_link(pool, t.repo.id, &t.image, EMPTY_JSON_DIGEST)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let stored = self
            .inner
            .cas
            .store(Cursor::new(EMPTY_JSON.to_vec()), EMPTY_JSON.len() as u64)
            .await?;
        let mut tx = pool.begin().await?;
        oci_dao::insert_link_ingested(
            &mut tx,
            t.repo.id,
            &t.image,
            EMPTY_JSON_DIGEST,
            &stored.sha256,
            stored.size as i64,
            stored.ingest_token,
        )
        .await
        .map_err(OciError::from)
        .and_then(require_linked)?;
        tx.commit().await?;
        Ok(())
    }

    /// Display data of a manifest: platforms, layer total, annotations.
    pub(crate) async fn manifest_summary(
        &self,
        t: &Target,
        parsed: &ParsedManifest,
    ) -> serde_json::Value {
        let mut summary = serde_json::Map::new();
        match parsed.kind {
            ManifestKind::Index => {
                let platforms: Vec<String> = parsed
                    .manifests
                    .iter()
                    .filter_map(|m| m.platform.as_ref())
                    .filter(|p| !p.architecture.is_empty() && p.architecture != "unknown")
                    .map(|p| p.label())
                    .collect();
                summary.insert("platforms".into(), serde_json::json!(platforms));
            }
            ManifestKind::Image => {
                summary.insert(
                    "layers_size".into(),
                    serde_json::json!(parsed.layers_size()),
                );
                summary.insert("layers".into(), serde_json::json!(parsed.layers.len()));
                if let Some(config) = &parsed.config {
                    summary.insert(
                        "config_media_type".into(),
                        serde_json::json!(config.media_type),
                    );
                    summary.insert(
                        "config_digest".into(),
                        serde_json::json!(config.digest.as_str()),
                    );
                    if is_image_config(&config.media_type)
                        && config.size <= MAX_CONFIG_SUMMARY_BYTES
                    {
                        if let Some(platform) = self.config_platform(t, &config.digest).await {
                            summary.insert("platform".into(), serde_json::json!(platform.label()));
                        }
                    }
                }
            }
        }
        if let Some(annotations) = &parsed.annotations {
            // Kept for the referrers API; bounded so one manifest cannot
            // bloat every listing.
            let value = serde_json::Value::Object(annotations.clone());
            if value.to_string().len() <= 16 * 1024 {
                summary.insert("annotations".into(), value);
            }
        }
        serde_json::Value::Object(summary)
    }

    /// The platform of an image config blob linked into the image.
    async fn config_platform(&self, t: &Target, digest: &Digest) -> Option<manifest::Platform> {
        let link = oci_dao::find_link(&self.inner.pool, t.repo.id, &t.image, digest.as_str())
            .await
            .ok()??;
        let bytes = self
            .read_manifest_bytes(BlobRef {
                sha256: &link.blob_sha256,
                s3_key: &link.s3_key,
                size: link.size.max(0) as u64,
            })
            .await
            .ok()?;
        config_platform(&bytes)
    }

    pub(crate) async fn delete_manifest(
        &self,
        ctx: &RequestCtx,
        reference: &str,
    ) -> OciResult<Response> {
        let t = ctx.serving();
        let reference = parse_reference(reference)?;
        let mut tx = self.inner.pool.begin().await?;
        let deleted = match &reference {
            Reference::Tag(tag) => oci_dao::delete_tag(&mut tx, t.repo.id, &t.image, tag).await?,
            Reference::Digest(digest) => {
                oci_dao::delete_manifest(
                    &mut tx,
                    t.repo.id,
                    &t.image,
                    digest.as_str(),
                    self.grace(),
                )
                .await?
            }
        };
        tx.commit().await?;
        if !deleted {
            return Err(OciError::manifest_unknown(reference.as_str()));
        }
        Ok(StatusCode::ACCEPTED.into_response())
    }

    pub(crate) async fn delete_blob(&self, ctx: &RequestCtx, digest: &str) -> OciResult<Response> {
        let t = ctx.serving();
        let digest = parse_digest(digest)?;
        let mut tx = self.inner.pool.begin().await?;
        if oci_dao::link_referenced(&mut *tx, t.repo.id, &t.image, digest.as_str()).await? {
            return Err(OciError::new(
                StatusCode::CONFLICT,
                Code::Denied,
                "the blob is referenced by a manifest of this image; delete the manifest first",
            )
            .with_detail(serde_json::json!({ "digest": digest.as_str() })));
        }
        let deleted =
            oci_dao::delete_link(&mut tx, t.repo.id, &t.image, digest.as_str(), self.grace())
                .await?;
        tx.commit().await?;
        if !deleted {
            return Err(OciError::blob_unknown(digest.as_str()));
        }
        Ok(StatusCode::ACCEPTED.into_response())
    }

    /// Store a manifest fetched from a proxy's upstream (no reference
    /// checks: its blobs are fetched on demand) and point `tag` at it.
    pub(crate) async fn store_proxied_manifest(
        &self,
        t: &Target,
        digest: &Digest,
        parsed: &ParsedManifest,
        body: &Bytes,
        tag: Option<&str>,
    ) -> OciResult<oci_dao::ManifestRow> {
        let children: Vec<String> = parsed
            .manifest_references()
            .into_iter()
            .map(|d| d.digest.to_string())
            .collect();
        let blob_refs: Vec<String> = parsed
            .blob_references()
            .into_iter()
            .map(|d| d.digest.to_string())
            .collect();
        let summary = self.manifest_summary(t, parsed).await;
        let staged = self
            .inner
            .cas
            .stage(Cursor::new(body.to_vec()), MAX_MANIFEST_BYTES as u64)
            .await?;
        let stored = self.inner.cas.commit(staged).await?;
        let subject = parsed.subject.as_ref().map(|s| s.digest.to_string());
        let mut tx = self.inner.pool.begin().await?;
        let (manifest_id, _) = oci_dao::insert_manifest(
            &mut tx,
            NewManifest {
                repository_id: t.repo.id,
                image: &t.image,
                digest: digest.as_str(),
                blob_sha256: &stored.sha256,
                media_type: &parsed.media_type,
                artifact_type: parsed.artifact_type.as_deref(),
                subject_digest: subject.as_deref(),
                size: body.len() as i64,
                summary: &summary,
                blob_refs: &blob_refs,
                manifest_refs: &children,
            },
            stored.ingest_token,
        )
        .await?;
        if let Some(tag) = tag {
            oci_dao::set_tag(&mut tx, t.repo.id, &t.image, tag, manifest_id, true).await?;
        }
        tx.commit().await?;
        oci_dao::find_manifest(&self.inner.pool, t.repo.id, &t.image, digest.as_str())
            .await?
            .ok_or_else(|| OciError::internal("proxy manifest", "stored manifest vanished"))
    }
}

/// A manifest parse failure as the client sees it.
fn manifest_error(e: ManifestError) -> OciError {
    match e {
        ManifestError::UnsupportedMediaType(m) => {
            OciError::manifest_invalid(format!("unsupported manifest media type {m:?}"))
        }
        other => OciError::manifest_invalid(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_ranges() {
        let mut h = HeaderMap::new();
        assert_eq!(content_range(&h).unwrap(), None);
        h.insert(header::CONTENT_RANGE, HeaderValue::from_static("0-99"));
        assert_eq!(content_range(&h).unwrap(), Some((0, 99)));
        h.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_static("bytes 100-199/*"),
        );
        assert_eq!(content_range(&h).unwrap(), Some((100, 199)));
        h.insert(header::CONTENT_RANGE, HeaderValue::from_static("9-1"));
        assert!(content_range(&h).is_err());
    }

    #[test]
    fn upload_ranges() {
        assert_eq!(upload_range(0), "0-0");
        assert_eq!(upload_range(1), "0-0");
        assert_eq!(upload_range(100), "0-99");
    }
}
