//! Imports into a hosted repository from another registry's API (a Nexus
//! hosted repository's): a tag with everything it references, copied the
//! way `crane copy` copies it, and stored through the same checks as a push.
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

use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use forge_core::auth::Principal;
use forge_core::authz::Action;
use forge_core::net::upstream::RequestClass;
use forge_core::repo::proxy::Credentials;
use forge_db::model::{RepoKind, Repository};
use forge_db::oci_dao::{self, LinkOutcome, TagWrite};
use futures_util::TryStreamExt;
use reqwest::Method;

use crate::digest::{Algorithm, Digest};
use crate::error::{Code, OciError, OciResult};
use crate::manifest::{self, media, Descriptor, ParsedManifest, EMPTY_JSON_DIGEST};
use crate::proxy::{content_type, read_limited, upstream_base, Upstream};
use crate::push::require_linked;
use crate::reference;
use crate::service::{Registry, Target};

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
    /// The registry API at `base_url` (`/v2` is appended), with Basic
    /// `credentials` for it and for the token service its challenge names.
    pub fn new(base_url: &str, credentials: Option<Credentials>, owner: String) -> Self {
        ImportSource {
            base: upstream_base(base_url),
            credentials: credentials.map(Arc::new),
            owner,
        }
    }

    fn upstream<'a>(&'a self, registry: &'a Registry) -> Upstream<'a> {
        Upstream {
            reg: registry,
            owner: self.owner.clone(),
            base: self.base.clone(),
            creds: self.credentials.clone(),
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
    digest: Digest,
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
    ) -> OciResult<ImportedImage> {
        let t = self.import_target(repo, image, &options.principal).await?;
        if !reference::valid_tag(tag) {
            return Err(OciError::manifest_invalid(format!("invalid tag {tag:?}")));
        }
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
        let fetched = self.fetch_manifest(&upstream, image, tag, None).await?;
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
    ) -> OciResult<ImportedImage> {
        let t = self.import_target(repo, image, &options.principal).await?;
        let digest = Digest::parse(digest)
            .map_err(|e| OciError::digest_invalid(format!("invalid digest {digest:?}: {e}")))?;
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
            .fetch_manifest(&upstream, image, digest.as_str(), Some(&digest))
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
        if oci_dao::find_manifest(pool, repo.id, image, subject.digest.as_str())
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

    /// The image `image` of `repo` as an import target: a hosted docker
    /// repository the import's administrator may push the image to.
    async fn import_target(
        &self,
        repo: &Repository,
        image: &str,
        principal: &Principal,
    ) -> OciResult<Target> {
        if !repo.is_docker() || repo.kind() != RepoKind::Hosted {
            return Err(OciError::unsupported(
                "images are imported into a hosted docker repository",
            ));
        }
        if !reference::valid_name(image) {
            return Err(OciError::name_invalid(image));
        }
        if !self
            .rbac_allows(principal, repo, image, Action::Write)
            .await
        {
            return Err(OciError::denied(format!(
                "the import may not push the image {image:?}"
            )));
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
        upstream: &Upstream<'_>,
        fetched: &Fetched,
        options: &ImageImportOptions,
        depth: usize,
    ) -> OciResult<u64> {
        let pool = &self.inner.pool;
        let mut bytes = 0;
        for child in fetched.parsed.manifest_references() {
            if oci_dao::find_manifest(pool, t.repo.id, &t.image, child.digest.as_str())
                .await?
                .is_some()
            {
                continue;
            }
            if depth >= MAX_DEPTH {
                return Err(OciError::manifest_invalid(
                    "the source's indexes nest too deep",
                ));
            }
            let child = self
                .fetch_manifest(
                    upstream,
                    &t.image,
                    child.digest.as_str(),
                    Some(&child.digest),
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
        for blob in fetched.parsed.blob_references() {
            // Non-distributable layers live elsewhere by definition; the
            // empty JSON blob is linked by `commit_manifest` itself.
            if media::is_non_distributable(&blob.media_type)
                || blob.digest.as_str() == EMPTY_JSON_DIGEST
            {
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
        upstream: &Upstream<'_>,
        blob: &Descriptor,
    ) -> OciResult<u64> {
        let pool = &self.inner.pool;
        let digest = &blob.digest;
        if oci_dao::find_link(pool, t.repo.id, &t.image, digest.as_str())
            .await?
            .is_some()
        {
            return Ok(0);
        }
        // Another image of this repository holds it: its content is the
        // digest's, and the repository's readers can already read it.
        if digest.algorithm() == Algorithm::Sha256 {
            if let Some((_, size)) =
                oci_dao::blob_linked_in_repository(pool, t.repo.id, digest.hex()).await?
            {
                let mut tx = pool.begin().await?;
                match oci_dao::insert_link_existing(
                    &mut tx,
                    t.repo.id,
                    &t.image,
                    digest.as_str(),
                    digest.hex(),
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

        let response = upstream
            .send(
                Method::GET,
                &format!("/v2/{}/blobs/{digest}", t.image),
                &format!("repository:{}:pull", t.image),
                None,
                RequestClass::Download,
            )
            .await?;
        if !response.status().is_success() {
            return Err(source_status(response.status(), digest.as_str()));
        }
        let max = self.blob_limit(&t.repo);
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
            return Err(OciError::unavailable(format!(
                "the source served a blob that does not match its digest {digest}"
            )));
        }
        let size = staged.size;
        let stored = self.inner.cas.commit(staged).await?;
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
        .map_err(OciError::from)
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
        upstream: &Upstream<'_>,
        image: &str,
        reference: &str,
        expected: Option<&Digest>,
    ) -> OciResult<Fetched> {
        let accept = media::ACCEPT_ALL.join(", ");
        let response = upstream
            .send(
                Method::GET,
                &format!("/v2/{image}/manifests/{reference}"),
                &format!("repository:{image}:pull"),
                Some(&accept),
                RequestClass::Metadata,
            )
            .await?;
        if !response.status().is_success() {
            return Err(source_status(response.status(), reference));
        }
        let announced = response
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Digest::parse(v).ok());
        let content_type = content_type(&response);
        let body = read_limited(response, manifest::MAX_MANIFEST_BYTES).await?;
        let mismatch = || {
            OciError::unavailable(format!(
                "the source served a manifest for {image}:{reference} that does not match its digest"
            ))
        };
        let digest = match expected {
            Some(expected) => {
                if Digest::of(expected.algorithm(), &body) != *expected {
                    return Err(mismatch());
                }
                expected.clone()
            }
            None => {
                if let Some(announced) = &announced {
                    if Digest::of(announced.algorithm(), &body) != *announced {
                        return Err(mismatch());
                    }
                }
                Digest::sha256_of(&body)
            }
        };
        let parsed = manifest::parse(&body, content_type.as_deref()).map_err(|e| {
            OciError::manifest_invalid(format!("the source's manifest {image}:{reference}: {e}"))
        })?;
        Ok(Fetched {
            digest,
            body,
            parsed,
        })
    }
}

/// The error of a source answer that is not a success.
fn source_status(status: reqwest::StatusCode, what: &str) -> OciError {
    match status.as_u16() {
        404 => OciError::new(
            axum::http::StatusCode::NOT_FOUND,
            Code::ManifestUnknown,
            format!("the source does not have {what}"),
        ),
        401 | 403 => OciError::unavailable(format!(
            "the source registry refused the import's credentials ({status}) for {what}"
        )),
        429 => OciError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            Code::TooManyRequests,
            "the source registry rate-limits the import; retry later",
        ),
        _ => OciError::unavailable(format!("the source registry answered {status} for {what}")),
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
