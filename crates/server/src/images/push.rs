//! Pushes and deletes: blob uploads (monolithic, chunked, cross-repository
//! mounts), manifests and tags.
//!
//! Upload chunks are CAS blobs held by `oci_upload_part` rows, so a session
//! survives on any instance. When an upload consists of one chunk (what
//! docker, podman and containerd send, and what a monolithic upload is) that
//! chunk already is the blob and is linked as is; only multi-chunk uploads
//! are assembled into a new blob.

use std::collections::HashSet;
use std::io::Cursor;

use axum::body::Body;
use bytes::Bytes;
use forge_core::auth::Principal;
use forge_core::authz::Level;
use forge_core::repo::{PackageMutation, PublishAuthorizationContext, WriteError};
use forge_db::model::{RepoKind, Repository};
use forge_db::oci_dao::{self, LinkOutcome, NewManifest, TagWrite, UploadRow};
use forge_plugin::api::images::{
    BlobInfo, ChunkRange, ImageError, ParsedManifest, Reference, Started, StoredManifest,
    UploadState, MAX_MANIFEST_BYTES,
};
use forge_plugin::api::FormatError;
use futures_util::{StreamExt, TryStreamExt};
use tokio_util::io::StreamReader;
use uuid::Uuid;

use super::digest::ContentDigest;
use super::dispatch::{Decision, RequestCtx, Target};
use super::{Failure, ImgResult, Registry, RequestBodyError};

/// A manifest [`Registry::commit_manifest`] stored.
pub(crate) struct CommittedManifest {
    pub id: i64,
    /// Whether the image did not hold the manifest before.
    pub created: bool,
    /// What became of each tag.
    pub tags: Vec<(String, TagWrite)>,
}

/// Refuse to commit a link whose blob turned out to be gone or being
/// deleted: dropping the transaction rolls the link row back, so no link
/// ever exists without its reference.
pub(crate) fn require_linked(outcome: LinkOutcome) -> ImgResult<()> {
    match outcome {
        LinkOutcome::BlobUnavailable => Err(Failure::unavailable(
            "the blob is being removed from storage; retry the upload",
        )),
        LinkOutcome::Inserted | LinkOutcome::AlreadyLinked => Ok(()),
    }
}

/// A request body as an `AsyncRead`. A body that cannot be read fails with a
/// [`RequestBodyError`] inside the I/O error, which is the client's.
fn body_reader(body: Body) -> impl tokio::io::AsyncRead + Unpin + Send {
    StreamReader::new(
        body.into_data_stream()
            .map_err(|e| std::io::Error::other(RequestBodyError(e))),
    )
}

/// Read a whole (small) request body, refusing more than `limit` bytes.
async fn read_body(body: Body, limit: usize) -> ImgResult<Bytes> {
    let mut stream = body.into_data_stream();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            tracing::debug!(error = %e, "registry: the manifest body could not be read");
            Failure::new(ImageError::BodyUnreadable)
        })?;
        if out.len() + chunk.len() > limit {
            return Err(Failure::new(ImageError::TooLarge {
                limit: limit as u64,
            }));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

/// An upload session id from the URL.
fn upload_id(raw: &str) -> ImgResult<Uuid> {
    Uuid::parse_str(raw).map_err(|_| Failure::new(ImageError::UploadUnknown))
}

/// An upload session as the format learns of it.
fn upload_state(upload: &UploadRow) -> UploadState {
    UploadState {
        id: upload.id.to_string(),
        size: upload.size.max(0) as u64,
    }
}

impl Registry {
    fn grace(&self) -> chrono::Duration {
        self.inner.config.delete_grace
    }

    /// The largest blob a push to `repo` may carry: its own upload limit,
    /// else the registry's default.
    pub(crate) fn blob_limit(&self, repo: &Repository) -> u64 {
        repo.max_upload_bytes()
            .unwrap_or(self.inner.config.default_max_upload_bytes)
    }

    // ── Uploads ─────────────────────────────────────────────────────────────

    /// Start an upload session in `t`, or mount `mount`'s digest there
    /// without one when it can be: from the image `mount` names (one the
    /// caller may read), or when the image holds the blob already.
    pub(crate) async fn start_upload(
        &self,
        ctx: &RequestCtx,
        t: &Target,
        mount: Option<(ContentDigest, Option<&str>)>,
    ) -> ImgResult<Started> {
        if let Some((digest, from)) = mount {
            if let Some(size) = self.mount(ctx, t, &digest, from).await? {
                return Ok(Started::Mounted(BlobInfo {
                    digest: digest.to_string(),
                    size: size.max(0) as u64,
                }));
            }
            // Not mountable: a regular upload session.
        }
        let id = Uuid::new_v4();
        oci_dao::create_upload(&self.inner.pool, id, t.repo.id, &t.image).await?;
        Ok(Started::Session(UploadState {
            id: id.to_string(),
            size: 0,
        }))
    }

    /// Link `digest` into the target image without uploading it: from the
    /// image `from` the caller may read, or (without `from`) when the image
    /// already has it. Its size; `None` when it cannot be mounted.
    async fn mount(
        &self,
        ctx: &RequestCtx,
        t: &Target,
        digest: &ContentDigest,
        from: Option<&str>,
    ) -> ImgResult<Option<i64>> {
        let pool = &self.inner.pool;
        if let Some(held) = oci_dao::find_link(pool, t.repo.id, &t.image, digest.as_str()).await? {
            // The client is about to name it in a manifest: record the use
            // now, or the sweeper may release it first.
            oci_dao::touch_link(
                pool,
                t.repo.id,
                &t.image,
                digest.as_str(),
                chrono::Duration::zero(),
            )
            .await?;
            return Ok(Some(held.size));
        }
        let Some(from) = from else {
            return Ok(None);
        };
        let Ok(Some(source)) = self.resolve(&ctx.site, from).await else {
            return Ok(None);
        };
        // What the source would serve: an offline hosted repository serves
        // nothing (an offline proxy still serves its cache).
        let serves = match source.repo.kind() {
            RepoKind::Hosted => source.repo.online,
            RepoKind::Proxy => true,
            RepoKind::Group => false,
        };
        if !serves || self.decide(&ctx.caller, &source, Level::Read).await != Decision::Allow {
            return Ok(None);
        }
        let Some(link) =
            oci_dao::find_link(pool, source.repo.id, &source.image, digest.as_str()).await?
        else {
            return Ok(None);
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
                Ok(None)
            }
            LinkOutcome::Inserted | LinkOutcome::AlreadyLinked => {
                tx.commit().await?;
                Ok(Some(link.size))
            }
        }
    }

    async fn upload_of(&self, t: &Target, id: &str) -> ImgResult<UploadRow> {
        oci_dao::get_upload(&self.inner.pool, upload_id(id)?, t.repo.id, &t.image)
            .await?
            .ok_or_else(|| Failure::new(ImageError::UploadUnknown))
    }

    pub(crate) async fn upload_status(&self, t: &Target, id: &str) -> ImgResult<UploadState> {
        let upload = self.upload_of(t, id).await?;
        Ok(upload_state(&upload))
    }

    pub(crate) async fn cancel_upload(&self, t: &Target, id: &str) -> ImgResult<()> {
        let upload = self.upload_of(t, id).await?;
        let mut tx = self.inner.pool.begin().await?;
        let deleted = oci_dao::delete_upload(&mut tx, upload.id, self.grace()).await?;
        tx.commit().await?;
        if !deleted {
            return Err(Failure::new(ImageError::UploadUnknown));
        }
        Ok(())
    }

    /// Store one chunk of an upload. The chunk must begin where the session
    /// ended when the request started; the whole blob may be at most `max`
    /// bytes.
    async fn append_chunk(
        &self,
        upload: &UploadRow,
        range: Option<ChunkRange>,
        body: Body,
        max: u64,
    ) -> ImgResult<UploadRow> {
        let size = upload.size.max(0) as u64;
        let out_of_order = |size: i64| {
            Failure::new(ImageError::ChunkOutOfOrder {
                size: size.max(0) as u64,
            })
        };
        if let Some(range) = range {
            if range.start != size {
                return Err(out_of_order(upload.size));
            }
        }
        let remaining = max.saturating_sub(size);
        let staged = self
            .inner
            .cas
            .stage(body_reader(body), remaining)
            .await
            .map_err(|e| match e {
                forge_storage::CasError::TooLarge { .. } => {
                    Failure::new(ImageError::TooLarge { limit: max })
                }
                other => other.into(),
            })?;
        if let Some(range) = range {
            if staged.size != range.end - range.start + 1 {
                return Err(Failure::new(ImageError::ChunkLength { size }));
            }
        }
        if staged.size == 0 {
            return Ok(upload.clone());
        }
        // The first chunk may be the whole blob (a monolithic upload, or a
        // layer streamed in one PATCH, as docker, podman and containerd
        // send it), so it joins the local blob cache like any pushed blob.
        // Later chunks are only read back once, to assemble the blob:
        // caching them would evict content that is downloaded.
        let stored = if upload.size == 0 {
            self.inner.cas.commit(staged).await?
        } else {
            self.inner.cas.commit_uncached(staged).await?
        };
        let mut tx = self.inner.pool.begin().await?;
        let Some(locked) =
            oci_dao::lock_upload(&mut tx, upload.id, upload.repository_id, &upload.image).await?
        else {
            return Err(Failure::new(ImageError::UploadUnknown));
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

    pub(crate) async fn append_upload(
        &self,
        t: &Target,
        id: &str,
        range: Option<ChunkRange>,
        body: Body,
    ) -> ImgResult<UploadState> {
        let upload = self.upload_of(t, id).await?;
        let max = self.blob_limit(&t.repo);
        let upload = self.append_chunk(&upload, range, body, max).await?;
        Ok(upload_state(&upload))
    }

    /// Append the last chunk, then end the session and link its content into
    /// the image as `digest`.
    pub(crate) async fn finish_upload(
        &self,
        t: &Target,
        id: &str,
        digest: &ContentDigest,
        range: Option<ChunkRange>,
        body: Body,
    ) -> ImgResult<BlobInfo> {
        let upload = self.upload_of(t, id).await?;
        let max = self.blob_limit(&t.repo);
        let upload = self.append_chunk(&upload, range, body, max).await?;
        let pool = &self.inner.pool;
        let parts = oci_dao::upload_parts(pool, upload.id).await?;
        let mismatch = || Failure::new(ImageError::DigestMismatch);
        let finished = BlobInfo {
            digest: digest.to_string(),
            size: upload.size.max(0) as u64,
        };

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
                    return Err(Failure::new(ImageError::UploadUnknown));
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
                    return Err(Failure::internal(
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
                // The first chunk joined the local blob cache in case it was
                // the whole blob (`append_chunk`). It is not, and nothing
                // reads it as it is again.
                if let (Some(cache), Some(first)) = (self.inner.store.cache(), parts.first()) {
                    cache.evict(&first.blob_sha256).await;
                }
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
                    return Err(Failure::new(ImageError::UploadUnknown));
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
                .map_err(Failure::from)
                .and_then(require_linked)?;
                oci_dao::delete_upload(&mut tx, upload.id, self.grace()).await?;
            }
        }
        tx.commit().await?;
        Ok(finished)
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

    /// What the images format reads in `manifest`.
    pub(crate) fn parse_manifest(
        &self,
        manifest: &[u8],
        content_type: Option<&str>,
    ) -> ImgResult<ParsedManifest> {
        self.plugin()
            .parse_manifest(manifest, content_type)
            .map_err(|e| match e {
                FormatError::Internal(m) => Failure::internal("manifest parse", m),
                FormatError::InvalidPackage(m)
                | FormatError::MissingManifest(m)
                | FormatError::MalformedManifest(m)
                | FormatError::InvalidVersion(m)
                | FormatError::InvalidId(m) => Failure::new(ImageError::ManifestInvalid(m)),
            })
    }

    /// Store the request body as a manifest of `t`, under `reference` and
    /// `tags`.
    pub(crate) async fn put_manifest(
        &self,
        principal: &Principal,
        t: &Target,
        reference: &Reference,
        tags: &[String],
        content_type: Option<String>,
        body: Body,
    ) -> ImgResult<StoredManifest> {
        let body = read_body(body, MAX_MANIFEST_BYTES).await?;
        let parsed = self.parse_manifest(&body, content_type.as_deref())?;
        let digest = match reference {
            Reference::Digest(d) => {
                let digest = ContentDigest::named(d)?;
                if !digest.matches_bytes(&body) {
                    return Err(Failure::new(ImageError::DigestMismatch));
                }
                digest
            }
            Reference::Tag(_) => ContentDigest::sha256_of(&body),
        };
        self.commit_manifest(t, principal, &digest, &body, &parsed, tags)
            .await?;
        Ok(StoredManifest {
            digest: digest.to_string(),
            subject: parsed.subject.clone(),
        })
    }

    /// Store a manifest whose bytes match `digest` and point `tags` at it,
    /// as a push does: every blob it needs must be linked into the image
    /// (the format names content it knows, such as the empty JSON, which is
    /// linked here) and, for an index, every child manifest must exist;
    /// tags follow the repository's immutability; the change runs past the
    /// publish policy of `principal`. A manifest the image already holds is
    /// left as it is (its tags are still set).
    pub(crate) async fn commit_manifest(
        &self,
        t: &Target,
        principal: &Principal,
        digest: &ContentDigest,
        body: &Bytes,
        parsed: &ParsedManifest,
        tags: &[String],
    ) -> ImgResult<CommittedManifest> {
        // What must exist before the manifest may: its blobs (except those
        // that live elsewhere by definition) and, for an index, its
        // children.
        let mut required_blobs: Vec<String> = Vec::new();
        for blob in parsed.blobs.iter().filter(|b| b.required) {
            if let Some(content) = &blob.known {
                self.ensure_known(t, &blob.digest, content).await?;
            }
            required_blobs.push(blob.digest.clone());
        }
        let children = &parsed.manifests;
        let summary = self.manifest_summary(t, parsed).await;

        let staged = self
            .inner
            .cas
            .stage(Cursor::new(body.to_vec()), MAX_MANIFEST_BYTES as u64)
            .await?;
        let stored = self.inner.cas.commit(staged).await?;

        let mut tx = self.inner.pool.begin().await?;
        let linked: HashSet<String> =
            oci_dao::lock_links(&mut tx, t.repo.id, &t.image, &required_blobs)
                .await?
                .into_iter()
                .collect();
        if let Some(missing) = required_blobs.iter().find(|d| !linked.contains(*d)) {
            return Err(Failure::new(ImageError::ManifestBlobUnknown {
                digest: missing.clone(),
                manifest: false,
            }));
        }
        if !children.is_empty() {
            let present: HashSet<String> =
                oci_dao::existing_manifests(&mut tx, t.repo.id, &t.image, children)
                    .await?
                    .into_iter()
                    .collect();
            if let Some(missing) = children.iter().find(|d| !present.contains(*d)) {
                return Err(Failure::new(ImageError::ManifestBlobUnknown {
                    digest: missing.clone(),
                    manifest: true,
                }));
            }
        }
        let blob_refs: Vec<String> = parsed.blobs.iter().map(|b| b.digest.clone()).collect();
        let (manifest_id, created) = oci_dao::insert_manifest(
            &mut tx,
            NewManifest {
                repository_id: t.repo.id,
                image: &t.image,
                digest: digest.as_str(),
                blob_sha256: &stored.sha256,
                media_type: &parsed.media_type,
                artifact_type: parsed.artifact_type.as_deref(),
                subject_digest: parsed.subject.as_deref(),
                size: body.len() as i64,
                summary: &summary,
                blob_refs: &blob_refs,
                manifest_refs: children,
            },
            stored.ingest_token,
        )
        .await?;
        let immutable = t.repo.immutable_tags();
        let mut written = Vec::with_capacity(tags.len());
        for tag in tags {
            let may_move = !immutable || (tag == "latest" && t.repo.latest_mutable());
            match oci_dao::set_tag(&mut tx, t.repo.id, &t.image, tag, manifest_id, may_move).await?
            {
                TagWrite::Refused => {
                    return Err(Failure::new(ImageError::TagImmutable { tag: tag.clone() }));
                }
                write @ (TagWrite::Created | TagWrite::Moved { .. } | TagWrite::Unchanged) => {
                    written.push((tag.clone(), write));
                }
            }
        }
        let version = tags.first().cloned().unwrap_or_else(|| digest.to_string());
        self.record_mutation(principal, t, PackageMutation::Publish, version, &mut tx)
            .await?;
        tx.commit().await?;
        Ok(CommittedManifest {
            id: manifest_id,
            created,
            tags: written,
        })
    }

    /// Make sure the blob `digest`, whose content the format knows, is linked
    /// into the image: clients commonly reference the OCI empty JSON (`{}`)
    /// as an artifact's config without uploading it.
    async fn ensure_known(&self, t: &Target, digest: &str, content: &[u8]) -> ImgResult<()> {
        let pool = &self.inner.pool;
        if oci_dao::find_link(pool, t.repo.id, &t.image, digest)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let digest = ContentDigest::named(digest)?;
        if !digest.matches_bytes(content) {
            return Err(Failure::internal(
                "known blob",
                format!("the images format named content that is not {digest}"),
            ));
        }
        let stored = self
            .inner
            .cas
            .store(Cursor::new(content.to_vec()), content.len() as u64)
            .await?;
        let mut tx = pool.begin().await?;
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
        .map_err(Failure::from)
        .and_then(require_linked)?;
        tx.commit().await?;
        Ok(())
    }

    /// The display summary of a manifest: what the format made of it, and
    /// the part its config holds once the image holds the config.
    pub(crate) async fn manifest_summary(
        &self,
        t: &Target,
        parsed: &ParsedManifest,
    ) -> serde_json::Value {
        let mut summary = match serde_json::from_str::<serde_json::Value>(&parsed.summary) {
            Ok(summary @ serde_json::Value::Object(_)) => summary,
            _ => {
                tracing::warn!("images format: a manifest summary that is not a JSON object");
                serde_json::json!({})
            }
        };
        if let Some(config) = &parsed.config {
            if let Some(part) = self
                .config_part(t, &config.digest, &config.media_type, config.size)
                .await
            {
                merge(&mut summary, part);
            }
        }
        summary
    }

    /// The part of a summary the config `digest` (of `media_type`) holds,
    /// if the image holds the config.
    pub(crate) async fn config_part(
        &self,
        t: &Target,
        digest: &str,
        media_type: &str,
        size: u64,
    ) -> Option<serde_json::Map<String, serde_json::Value>> {
        let link = oci_dao::find_link(&self.inner.pool, t.repo.id, &t.image, digest)
            .await
            .ok()??;
        if link.size.max(0) as u64 != size {
            return None;
        }
        let bytes = self
            .read_manifest_bytes(forge_storage::BlobRef {
                sha256: &link.blob_sha256,
                s3_key: &link.s3_key,
                size,
            })
            .await
            .ok()?;
        self.config_summary_part(media_type, &bytes)
    }

    /// What the format makes of a config's content, as a JSON object.
    pub(crate) fn config_summary_part(
        &self,
        media_type: &str,
        config: &[u8],
    ) -> Option<serde_json::Map<String, serde_json::Value>> {
        let part = self.plugin().config_summary(media_type, config)?;
        match serde_json::from_str(&part) {
            Ok(serde_json::Value::Object(part)) => Some(part),
            _ => {
                tracing::warn!("images format: a config summary that is not a JSON object");
                None
            }
        }
    }

    pub(crate) async fn delete_manifest(
        &self,
        principal: &Principal,
        t: &Target,
        reference: &Reference,
    ) -> ImgResult<()> {
        let mut tx = self.inner.pool.begin().await?;
        let deleted = match reference {
            Reference::Tag(tag) => oci_dao::delete_tag(&mut tx, t.repo.id, &t.image, tag).await?,
            Reference::Digest(digest) => {
                oci_dao::delete_manifest(&mut tx, t.repo.id, &t.image, digest, self.grace()).await?
            }
        };
        if !deleted {
            return Err(Failure::new(ImageError::ManifestUnknown {
                reference: reference.as_str().to_string(),
            }));
        }
        let version = reference.as_str().to_string();
        self.record_mutation(principal, t, PackageMutation::Delete, version, &mut tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn delete_blob(
        &self,
        principal: &Principal,
        t: &Target,
        digest: &ContentDigest,
    ) -> ImgResult<()> {
        let unknown = || {
            Failure::new(ImageError::BlobUnknown {
                digest: digest.to_string(),
            })
        };
        let mut tx = self.inner.pool.begin().await?;
        // Lock first, check after: a manifest naming the blob that commits
        // while this waits for the lock is seen by the check.
        if !oci_dao::lock_link(&mut tx, t.repo.id, &t.image, digest.as_str()).await? {
            return Err(unknown());
        }
        if oci_dao::link_referenced(&mut *tx, t.repo.id, &t.image, digest.as_str()).await? {
            return Err(Failure::new(ImageError::BlobReferenced {
                digest: digest.to_string(),
            }));
        }
        let deleted =
            oci_dao::delete_link(&mut tx, t.repo.id, &t.image, digest.as_str(), self.grace())
                .await?;
        if !deleted {
            return Err(unknown());
        }
        let version = digest.to_string();
        self.record_mutation(principal, t, PackageMutation::Delete, version, &mut tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Run a change of an image past the repository's publish policy in the
    /// change's transaction: a workload's pushes and deletes go to the
    /// trusted-publishing ledger, and fail when its realm or role changed
    /// since the request was authenticated.
    async fn record_mutation(
        &self,
        principal: &Principal,
        t: &Target,
        action: PackageMutation,
        version: String,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> ImgResult<()> {
        let Some(recorder) = &self.inner.recorder else {
            return Ok(());
        };
        let context = PublishAuthorizationContext {
            principal: *principal,
            action,
            package_id: t.image.clone(),
            package_version: version,
        };
        recorder
            .for_repository(&t.repo)
            .record_in_transaction(&context, tx)
            .await
            .map_err(|e| match e {
                WriteError::ForbiddenPackage { .. } => Failure::new(ImageError::NoLongerAllowed),
                other => Failure::internal("publish record", other),
            })
    }

    /// Store a manifest fetched from a proxy's upstream (no reference
    /// checks: its blobs are fetched on demand) and point `tag` at it.
    pub(crate) async fn store_proxied_manifest(
        &self,
        t: &Target,
        digest: &ContentDigest,
        parsed: &ParsedManifest,
        body: &Bytes,
        tag: Option<&str>,
    ) -> ImgResult<oci_dao::ManifestRow> {
        let blob_refs: Vec<String> = parsed.blobs.iter().map(|b| b.digest.clone()).collect();
        let summary = self.manifest_summary(t, parsed).await;
        let staged = self
            .inner
            .cas
            .stage(Cursor::new(body.to_vec()), MAX_MANIFEST_BYTES as u64)
            .await?;
        let stored = self.inner.cas.commit(staged).await?;
        let mut tx = self.inner.pool.begin().await?;
        super::proxy::still_upstream(&mut tx, &t.repo).await?;
        let (manifest_id, _) = oci_dao::insert_manifest(
            &mut tx,
            NewManifest {
                repository_id: t.repo.id,
                image: &t.image,
                digest: digest.as_str(),
                blob_sha256: &stored.sha256,
                media_type: &parsed.media_type,
                artifact_type: parsed.artifact_type.as_deref(),
                subject_digest: parsed.subject.as_deref(),
                size: body.len() as i64,
                summary: &summary,
                blob_refs: &blob_refs,
                manifest_refs: &parsed.manifests,
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
            .ok_or_else(|| Failure::internal("proxy manifest", "stored manifest vanished"))
    }
}

/// Add `part`'s keys to the JSON object `summary`.
pub(crate) fn merge(
    summary: &mut serde_json::Value,
    part: serde_json::Map<String, serde_json::Value>,
) {
    if let serde_json::Value::Object(summary) = summary {
        summary.extend(part);
    }
}
