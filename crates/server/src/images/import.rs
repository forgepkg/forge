//! Imports into a hosted repository from another registry's API (Nexus,
//! Harbor, a `distribution` registry, another Forge): what the source lists
//! (its catalog, tag lists and referrers, [`Registry::source_catalog`] and
//! its siblings), and a tag with everything it references, copied the way
//! `crane copy` copies it, and stored through the same checks as a push.
//!
//! * Digests are kept: a manifest is stored as the source served it, once
//!   its bytes matched the digest it was asked for (a tag's: the source's
//!   `Docker-Content-Digest`, when it sends one).
//! * An index's child manifests are copied first, each with its config and
//!   layers, so a multi-platform image arrives whole. A blob the image
//!   already links is not downloaded again; one another image of the same
//!   repository links is linked without a download.
//! * Every manifest is then stored by [`Registry::commit_manifest`], as a
//!   push stores it: its blobs and children must be present, tags follow the
//!   repository's immutability, the change runs past the publish policy of
//!   the administrator who started the import, and the caller must be
//!   allowed to push the image ([`Registry::rbac_allows`]).
//! * A referrer (a signature, an SBOM: a manifest with a `subject`) that the
//!   source holds by digest only is copied by [`Registry::import_referrer`]
//!   once its subject is in the image. A signature cosign stores under a
//!   `sha256-<digest>.sig` tag is a tag like any other.
//! * What the source recorded is kept: its publish time becomes the tag's
//!   push time and the new manifest's creation time (retention's age rules),
//!   its last download the manifest's last pull.
//!
//! The images format names the source's URLs and reads its manifests, as
//! for a proxy's upstream.

use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use forge_core::auth::Principal;
use forge_core::authz::Level;
use forge_core::net::upstream::RequestClass;
use forge_core::repo::proxy::Credentials;
use forge_db::model::{RepoKind, Repository};
use forge_db::oci_dao::{self, LinkOutcome, TagWrite};
use forge_plugin::api::images::{
    CatalogPage, ImageError, ManifestBlob, ManifestInfo, ParsedManifest, Reference, TagPage,
    MAX_MANIFEST_BYTES,
};
use forge_plugin::api::{UpstreamAnswer, UpstreamOp};
use futures_util::TryStreamExt;
use reqwest::Method;

use super::digest::ContentDigest;
use super::dispatch::Target;
use super::proxy::{content_type, read_limited, Upstream};
use super::push::require_linked;
use super::{Failure, ImgResult, Registry};

/// How deep indexes may nest below the copied manifest.
const MAX_DEPTH: usize = 4;

/// The registry an import copies from.
pub struct ImportSource {
    base: String,
    credentials: Option<Arc<Credentials>>,
    /// Who the source's cached tokens belong to (`import:<id>`).
    owner: String,
}

impl ImportSource {
    /// The registry API at `base_url`, with Basic `credentials` for it and
    /// for the token service its challenge names.
    pub fn new(base_url: &str, credentials: Option<Credentials>, owner: String) -> Self {
        ImportSource {
            base: base_url.to_string(),
            credentials: credentials.map(Arc::new),
            owner,
        }
    }

    fn upstream(&self, registry: &Registry) -> Upstream {
        Upstream {
            http: registry.inner.http.clone(),
            owner: self.owner.clone(),
            remote: self.base.clone(),
            creds: self.credentials.clone(),
        }
    }
}

impl Registry {
    /// Check that `source` answers the registry API (`GET /v2/`: 200, or 200
    /// once its token challenge is answered). Returns the `Server` header it
    /// answered with.
    pub async fn probe_source(&self, source: &ImportSource) -> ImgResult<Option<String>> {
        let upstream = source.upstream(self);
        let base = source.base.trim_end_matches('/');
        let url = format!("{}/v2/", base.strip_suffix("/v2").unwrap_or(base));
        let response = upstream
            .send(Method::GET, &url, None, None, RequestClass::Metadata)
            .await?;
        if !response.status().is_success() {
            return Err(source_status(response.status(), "/v2/"));
        }
        Ok(response
            .headers()
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string))
    }

    /// Up to `n` images of the source's catalog after `last`; `None` when it
    /// serves no catalog.
    pub async fn source_catalog(
        &self,
        source: &ImportSource,
        last: Option<&str>,
        n: u32,
    ) -> ImgResult<Option<CatalogPage>> {
        let op = UpstreamOp::ImageCatalog {
            last: last.map(str::to_string),
            n,
        };
        match source.upstream(self).converse(self, &op).await? {
            UpstreamAnswer::ImageCatalog(page) => Ok(page),
            UpstreamAnswer::Failed(reason) => Err(Failure::unavailable(reason)),
            other => Err(Failure::internal(
                "source catalog",
                format!("the images format answered {other:?}"),
            )),
        }
    }

    /// Up to `n` tags of `image` at the source after `last`; `None` when the
    /// source does not know the image.
    pub async fn source_tags(
        &self,
        source: &ImportSource,
        image: &str,
        last: Option<&str>,
        n: u32,
    ) -> ImgResult<Option<TagPage>> {
        let op = UpstreamOp::ImageTags {
            image: image.to_string(),
            last: last.map(str::to_string),
            n,
        };
        match source.upstream(self).converse(self, &op).await? {
            UpstreamAnswer::ImageTags(page) => Ok(page),
            UpstreamAnswer::Failed(reason) => Err(Failure::unavailable(reason)),
            other => Err(Failure::internal(
                "source tags",
                format!("the images format answered {other:?}"),
            )),
        }
    }

    /// The referrers the source lists for the manifest `digest` of `image`
    /// (its referrers API); `None` when it has no such API: a referrer is
    /// then reached through a tag (the referrers tag schema's
    /// `sha256-<digest>`, cosign's `sha256-<digest>.sig`), which an import
    /// copies like any other.
    pub async fn source_referrers(
        &self,
        source: &ImportSource,
        image: &str,
        digest: &str,
    ) -> ImgResult<Option<Vec<ManifestInfo>>> {
        let op = UpstreamOp::ImageReferrers {
            image: image.to_string(),
            digest: digest.to_string(),
        };
        match source.upstream(self).converse(self, &op).await? {
            UpstreamAnswer::ImageReferrers(found) => Ok(found),
            UpstreamAnswer::Failed(reason) => Err(Failure::unavailable(reason)),
            other => Err(Failure::internal(
                "source referrers",
                format!("the images format answered {other:?}"),
            )),
        }
    }
}

/// How an import writes an image.
#[derive(Debug, Clone)]
pub struct ImageImportOptions {
    /// The administrator the import runs as.
    pub principal: Principal,
    /// Move a tag that points at another manifest (where the repository's
    /// immutability allows it); otherwise it is a conflict.
    pub overwrite: bool,
    /// Decide what would happen, and write nothing.
    pub dry_run: bool,
    /// When the source published the tag.
    pub published_at: Option<DateTime<Utc>>,
    /// When the source last served it.
    pub downloaded_at: Option<DateTime<Utc>>,
    /// Who published it at the source, for the audit trail.
    pub uploader: Option<String>,
    /// Where it came from, for the audit trail.
    pub source: String,
}

/// What an import did with a tag or a referrer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageOutcome {
    /// Stored: the tag (or the referrer) is new.
    Created,
    /// The tag pointed at `previous` and was moved.
    Replaced { previous: String },
    /// The image already holds it; nothing was written.
    Identical,
    /// The tag points at `existing` and stays: the import does not
    /// overwrite, or the repository's tags are `immutable`.
    Conflict { existing: String, immutable: bool },
    /// Dry run: it would be stored (`replaces`: by moving the tag).
    Planned { replaces: bool },
    /// A manifest the source holds by digest only that refers to nothing
    /// the image holds: an untagged image, not a referrer. Not copied.
    NotReferrer,
}

/// A tag or referrer an import looked at.
#[derive(Debug, Clone)]
pub struct ImportedImage {
    /// The digest of its manifest at the source (`None` when the outcome was
    /// decided without fetching it).
    pub digest: Option<String>,
    pub outcome: ImageOutcome,
    /// Manifest and blob bytes downloaded for it.
    pub bytes_copied: u64,
}

/// A manifest fetched from the source and checked against its digest.
struct Fetched {
    digest: ContentDigest,
    body: Bytes,
    parsed: ParsedManifest,
}

impl Registry {
    /// Copy `image:tag` from `source` into the hosted repository `repo`.
    /// `expected` is the digest the source listed for the tag: when the
    /// tag already points there, nothing is fetched.
    pub async fn import_tag(
        &self,
        repo: &Repository,
        source: &ImportSource,
        image: &str,
        tag: &str,
        expected: Option<&str>,
        options: &ImageImportOptions,
    ) -> ImgResult<ImportedImage> {
        let t = self.import_target(repo, image, &options.principal).await?;
        let pool = &self.inner.pool;
        let existing = oci_dao::find_tag(pool, repo.id, image, tag)
            .await?
            .map(|tagged| tagged.manifest.digest);
        let may_move = !repo.immutable_tags() || (tag == "latest" && repo.latest_mutable());
        // With the digest the source listed, an unchanged tag (and any dry
        // run) is decided without fetching anything.
        if let Some(expected) = expected {
            let outcome = match &existing {
                Some(existing) if existing == expected => Some(ImageOutcome::Identical),
                Some(existing) if options.dry_run && (!options.overwrite || !may_move) => {
                    Some(ImageOutcome::Conflict {
                        existing: existing.clone(),
                        immutable: !may_move,
                    })
                }
                Some(_) if options.dry_run => Some(ImageOutcome::Planned { replaces: true }),
                None if options.dry_run => Some(ImageOutcome::Planned { replaces: false }),
                _ => None,
            };
            if let Some(outcome) = outcome {
                return Ok(ImportedImage {
                    digest: Some(expected.to_string()),
                    outcome,
                    bytes_copied: 0,
                });
            }
        }

        let upstream = source.upstream(self);
        let fetched = self
            .fetch_manifest(&upstream, image, &Reference::Tag(tag.to_string()), None)
            .await?;
        let digest = fetched.digest.to_string();
        let decided = |outcome| {
            Ok(ImportedImage {
                digest: Some(digest.clone()),
                outcome,
                bytes_copied: fetched.body.len() as u64,
            })
        };
        match &existing {
            Some(existing) if *existing == digest => return decided(ImageOutcome::Identical),
            Some(existing) if !options.overwrite || !may_move => {
                return decided(ImageOutcome::Conflict {
                    existing: existing.clone(),
                    immutable: !may_move,
                });
            }
            Some(_) if options.dry_run => {
                return decided(ImageOutcome::Planned { replaces: true });
            }
            None if options.dry_run => return decided(ImageOutcome::Planned { replaces: false }),
            _ => {}
        }

        let mut bytes = fetched.body.len() as u64;
        bytes += self
            .copy_references(&t, &upstream, &fetched, options, 0)
            .await?;
        let committed = self
            .commit_manifest(
                &t,
                &options.principal,
                &fetched.digest,
                &fetched.body,
                &fetched.parsed,
                &[tag.to_string()],
            )
            .await?;
        let tag_written = committed
            .tags
            .iter()
            .any(|(_, write)| matches!(write, TagWrite::Created | TagWrite::Moved { .. }));
        oci_dao::set_imported_times(
            pool,
            repo.id,
            image,
            committed.id,
            committed.created,
            tag_written.then_some(tag),
            options.published_at,
            options.downloaded_at,
        )
        .await?;
        let outcome = match existing {
            Some(previous) => ImageOutcome::Replaced { previous },
            None => ImageOutcome::Created,
        };
        audit(repo, image, tag, &digest, &outcome, options);
        Ok(ImportedImage {
            digest: Some(digest),
            outcome,
            bytes_copied: bytes,
        })
    }

    /// Copy the manifest `digest` of `image` from `source` when it is a
    /// referrer of a manifest the image holds (its `subject`): a signature
    /// or SBOM the source holds by digest only. Anything else is
    /// [`ImageOutcome::NotReferrer`] and is not copied. A dry run cannot
    /// tell whether the subject would be imported and plans every referrer.
    pub async fn import_referrer(
        &self,
        repo: &Repository,
        source: &ImportSource,
        image: &str,
        digest: &str,
        options: &ImageImportOptions,
    ) -> ImgResult<ImportedImage> {
        let t = self.import_target(repo, image, &options.principal).await?;
        let digest = ContentDigest::parse(digest).ok_or_else(|| {
            Failure::new(ImageError::ManifestInvalid(format!(
                "invalid digest {digest:?}"
            )))
        })?;
        let pool = &self.inner.pool;
        // Held already: a referrer copied before, or a manifest an imported
        // tag brought along (an index's child), which is no referrer.
        if let Some(held) = oci_dao::find_manifest(pool, repo.id, image, digest.as_str()).await? {
            return Ok(ImportedImage {
                digest: Some(digest.to_string()),
                outcome: if held.subject_digest.is_some() {
                    ImageOutcome::Identical
                } else {
                    ImageOutcome::NotReferrer
                },
                bytes_copied: 0,
            });
        }
        let upstream = source.upstream(self);
        let fetched = self
            .fetch_manifest(
                &upstream,
                image,
                &Reference::Digest(digest.to_string()),
                Some(&digest),
            )
            .await?;
        let mut bytes = fetched.body.len() as u64;
        let decided = |outcome| {
            Ok(ImportedImage {
                digest: Some(digest.to_string()),
                outcome,
                bytes_copied: bytes,
            })
        };
        let Some(subject) = &fetched.parsed.subject else {
            return decided(ImageOutcome::NotReferrer);
        };
        if options.dry_run {
            return decided(ImageOutcome::Planned { replaces: false });
        }
        if oci_dao::find_manifest(pool, repo.id, image, subject)
            .await?
            .is_none()
        {
            return decided(ImageOutcome::NotReferrer);
        }
        bytes += self
            .copy_references(&t, &upstream, &fetched, options, 0)
            .await?;
        let committed = self
            .commit_manifest(
                &t,
                &options.principal,
                &fetched.digest,
                &fetched.body,
                &fetched.parsed,
                &[],
            )
            .await?;
        oci_dao::set_imported_times(
            pool,
            repo.id,
            image,
            committed.id,
            committed.created,
            None,
            options.published_at,
            options.downloaded_at,
        )
        .await?;
        audit(
            repo,
            image,
            "",
            digest.as_str(),
            &ImageOutcome::Created,
            options,
        );
        Ok(ImportedImage {
            digest: Some(digest.to_string()),
            outcome: ImageOutcome::Created,
            bytes_copied: bytes,
        })
    }

    /// The image `image` of `repo` as an import target: a hosted repository
    /// of the images format the import's administrator may push the image
    /// to.
    async fn import_target(
        &self,
        repo: &Repository,
        image: &str,
        principal: &Principal,
    ) -> ImgResult<Target> {
        if !self.serves(repo) || repo.kind() != RepoKind::Hosted {
            return Err(Failure::unsupported(
                405,
                "images are imported into a hosted docker repository",
            ));
        }
        if self.plugin().validate_id(image).is_err() {
            return Err(Failure::new(ImageError::NameInvalid {
                name: image.to_string(),
                hint: None,
            }));
        }
        if !self.rbac_allows(principal, repo, image, Level::Write).await {
            return Err(Failure::new(ImageError::Denied {
                name: image.to_string(),
                permission: forge_plugin::api::images::Permission::Write,
            })
            .with_text(format!("the import may not push the image {image:?}")));
        }
        Ok(Target {
            repo: repo.clone(),
            image: image.to_string(),
            name: image.to_string(),
        })
    }

    /// Copy what `fetched` references into the image: its child manifests
    /// (each with what it references), then its blobs. Returns the bytes
    /// downloaded.
    async fn copy_references(
        &self,
        t: &Target,
        upstream: &Upstream,
        fetched: &Fetched,
        options: &ImageImportOptions,
        depth: usize,
    ) -> ImgResult<u64> {
        let pool = &self.inner.pool;
        let mut bytes = 0;
        for child in &fetched.parsed.manifests {
            if oci_dao::find_manifest(pool, t.repo.id, &t.image, child)
                .await?
                .is_some()
            {
                continue;
            }
            if depth >= MAX_DEPTH {
                return Err(Failure::new(ImageError::ManifestInvalid(
                    "the source's indexes nest too deep".into(),
                )));
            }
            let digest = ContentDigest::named(child)?;
            let child = self
                .fetch_manifest(
                    upstream,
                    &t.image,
                    &Reference::Digest(child.clone()),
                    Some(&digest),
                )
                .await?;
            bytes += child.body.len() as u64;
            bytes +=
                Box::pin(self.copy_references(t, upstream, &child, options, depth + 1)).await?;
            let committed = self
                .commit_manifest(
                    t,
                    &options.principal,
                    &child.digest,
                    &child.body,
                    &child.parsed,
                    &[],
                )
                .await?;
            oci_dao::set_imported_times(
                pool,
                t.repo.id,
                &t.image,
                committed.id,
                committed.created,
                None,
                options.published_at,
                options.downloaded_at,
            )
            .await?;
        }
        for blob in &fetched.parsed.blobs {
            // Content that lives elsewhere by definition, and content the
            // format knows (linked by `commit_manifest` itself).
            if !blob.required || blob.known.is_some() {
                continue;
            }
            bytes += self.copy_blob(t, upstream, blob).await?;
        }
        Ok(bytes)
    }

    /// Link the blob `blob` into the image, downloading it from the source
    /// unless the repository holds it already. Returns the bytes downloaded.
    async fn copy_blob(
        &self,
        t: &Target,
        upstream: &Upstream,
        blob: &ManifestBlob,
    ) -> ImgResult<u64> {
        let pool = &self.inner.pool;
        let digest = ContentDigest::named(&blob.digest)?;
        if oci_dao::find_link(pool, t.repo.id, &t.image, digest.as_str())
            .await?
            .is_some()
        {
            return Ok(0);
        }
        // Another image of this repository holds it: its content is the
        // digest's, and the repository's readers can already read it.
        if let Some(sha256) = digest.sha256_hex() {
            if let Some((_, size)) =
                oci_dao::blob_linked_in_repository(pool, t.repo.id, sha256).await?
            {
                let mut tx = forge_db::begin(pool).await?;
                match oci_dao::insert_link_existing(
                    &mut tx,
                    t.repo.id,
                    &t.image,
                    digest.as_str(),
                    sha256,
                    size,
                )
                .await?
                {
                    LinkOutcome::BlobUnavailable => tx.rollback().await?,
                    LinkOutcome::Inserted | LinkOutcome::AlreadyLinked => {
                        tx.commit().await?;
                        return Ok(0);
                    }
                }
            }
        }

        let url = self.image_url(
            &upstream.remote,
            &UpstreamOp::ImageBlob {
                image: t.image.clone(),
                digest: digest.to_string(),
            },
        )?;
        let response = upstream
            .send_url(Method::GET, &url, RequestClass::Download)
            .await?;
        if !response.status().is_success() {
            return Err(source_status(response.status(), digest.as_str()));
        }
        let max = self.blob_limit(&t.repo);
        if response.content_length().is_some_and(|l| l > max) {
            return Err(Failure::new(ImageError::TooLarge { limit: max }));
        }
        let body = response.bytes_stream().map_err(std::io::Error::other);
        let staged = self
            .inner
            .cas
            .stage(tokio_util::io::StreamReader::new(body), max)
            .await?;
        if !digest.matches(&staged.sha256, &staged.sha512_base64) {
            return Err(Failure::unavailable(format!(
                "the source served a blob that does not match its digest {digest}"
            )));
        }
        let size = staged.size;
        let stored = self.inner.cas.commit(staged).await?;
        let mut tx = forge_db::begin(pool).await?;
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
        Ok(size)
    }

    /// Fetch the manifest `reference` of `image` from the source and check
    /// its bytes: against `expected` (a digest reference), else against the
    /// source's `Docker-Content-Digest`. A tag's manifest is stored under
    /// its SHA-256 digest.
    async fn fetch_manifest(
        &self,
        upstream: &Upstream,
        image: &str,
        reference: &Reference,
        expected: Option<&ContentDigest>,
    ) -> ImgResult<Fetched> {
        let what = reference.as_str();
        let url = self.image_url(
            &upstream.remote,
            &UpstreamOp::ImageManifest {
                image: image.to_string(),
                reference: reference.clone(),
            },
        )?;
        let response = upstream
            .send_url(Method::GET, &url, RequestClass::Metadata)
            .await?;
        if !response.status().is_success() {
            return Err(source_status(response.status(), what));
        }
        let announced = response
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .and_then(ContentDigest::parse);
        let content_type = content_type(&response);
        let body = read_limited(response, MAX_MANIFEST_BYTES).await?;
        let mismatch = || {
            Failure::unavailable(format!(
                "the source served a manifest for {image}:{what} that does not match its digest"
            ))
        };
        let digest = match expected {
            Some(expected) => {
                if !expected.matches_bytes(&body) {
                    return Err(mismatch());
                }
                expected.clone()
            }
            None => {
                if let Some(announced) = &announced {
                    if !announced.matches_bytes(&body) {
                        return Err(mismatch());
                    }
                }
                ContentDigest::sha256_of(&body)
            }
        };
        let parsed = self
            .parse_manifest(&body, content_type.as_deref())
            .map_err(|e| {
                Failure::new(ImageError::ManifestInvalid(format!(
                    "the source's manifest {image}:{what}: {}",
                    e.message()
                )))
            })?;
        Ok(Fetched {
            digest,
            body,
            parsed,
        })
    }
}

/// The error of a source answer that is not a success.
fn source_status(status: reqwest::StatusCode, what: &str) -> Failure {
    match status.as_u16() {
        404 => Failure::new(ImageError::ManifestUnknown {
            reference: what.to_string(),
        })
        .with_text(format!("the source does not have {what}")),
        401 | 403 => Failure::unavailable(format!(
            "the source registry refused the import's credentials ({status}) for {what}"
        )),
        429 => Failure::new(ImageError::RateLimited)
            .with_text("the source registry rate-limits the import; retry later"),
        _ => Failure::unavailable(format!("the source registry answered {status} for {what}")),
    }
}

/// The audit line of an imported tag or referrer.
fn audit(
    repo: &Repository,
    image: &str,
    tag: &str,
    digest: &str,
    outcome: &ImageOutcome,
    options: &ImageImportOptions,
) {
    tracing::info!(
        target: "forge::audit",
        action = "import",
        repo = %repo.name,
        image,
        tag,
        digest,
        outcome = ?outcome,
        principal = %options.principal.audit_label(),
        source = %options.source,
        uploader = options.uploader.as_deref().unwrap_or(""),
        "image imported"
    );
}
