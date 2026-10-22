//! Data access for the Docker/OCI registry tables (migration 0033).
//!
//! Reference counting follows the rest of the CAS: every `oci_blob_link`,
//! `oci_manifest` and `oci_upload_part` row holds one `blob.ref_count`
//! reference, taken in the transaction that inserts the row and released
//! (via [`blob_dao::decref_and_maybe_enqueue_delete`]) only for rows the same
//! transaction's own `DELETE … RETURNING` removed, so two overlapping deletes
//! never both decrement.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::blob_dao;
use crate::model::Repository;

/// Links and manifests are "used" again at most this often, so pulls do not
/// write a row on every request.
const TOUCH_INTERVAL_SECS: f64 = 3600.0;

// ── Repositories ────────────────────────────────────────────────────────────

/// The docker repository that serves the host name `host` (host-based
/// routing, `config.host`), case-insensitively.
pub async fn find_repository_by_host(
    pool: &PgPool,
    host: &str,
) -> sqlx::Result<Option<Repository>> {
    sqlx::query_as!(
        Repository,
        r#"
        SELECT
            id, name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            upstream_password_enc, metadata_ttl_seconds, not_found_ttl_seconds,
            allow_redeploy, created_at, updated_at
        FROM repository
        WHERE format = 'docker' AND config ? 'host' AND lower(config->>'host') = lower($1)
        "#,
        host,
    )
    .fetch_optional(pool)
    .await
}

/// Whether `repository_id` holds any image (a manifest). Pass the
/// transaction that holds the repository row lock so the answer stays true
/// until commit.
pub async fn repository_has_images<'e, E>(executor: E, repository_id: i64) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar!(
        r#"
        SELECT EXISTS (SELECT 1 FROM oci_manifest WHERE repository_id = $1) AS "exists!"
        "#,
        repository_id,
    )
    .fetch_one(executor)
    .await
}

/// Remove every image row of `repository_id` (uploads, tags, manifests,
/// links), releasing one blob reference per removed row. Returns how many
/// references were released. The caller must hold the repository row
/// `FOR UPDATE` (as for `component_dao::hard_delete_all_components`), which
/// blocks new inserts until the repository itself is deleted.
pub async fn purge_repository(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    grace: chrono::Duration,
) -> sqlx::Result<u64> {
    let mut shas: Vec<String> = sqlx::query_scalar!(
        r#"
        DELETE FROM oci_upload_part p
        USING oci_upload u
        WHERE p.upload_id = u.id AND u.repository_id = $1
        RETURNING p.blob_sha256
        "#,
        repository_id,
    )
    .fetch_all(&mut **tx)
    .await?;
    sqlx::query!(
        "DELETE FROM oci_upload WHERE repository_id = $1",
        repository_id
    )
    .execute(&mut **tx)
    .await?;
    sqlx::query!(
        "DELETE FROM oci_tag WHERE repository_id = $1",
        repository_id
    )
    .execute(&mut **tx)
    .await?;
    shas.extend(
        sqlx::query_scalar!(
            "DELETE FROM oci_manifest WHERE repository_id = $1 RETURNING blob_sha256",
            repository_id,
        )
        .fetch_all(&mut **tx)
        .await?,
    );
    shas.extend(
        sqlx::query_scalar!(
            "DELETE FROM oci_blob_link WHERE repository_id = $1 RETURNING blob_sha256",
            repository_id,
        )
        .fetch_all(&mut **tx)
        .await?,
    );
    decref_all(tx, shas, grace).await
}

/// Decrement one reference per entry (duplicates included), in blob order so
/// overlapping writers lock blob rows consistently.
async fn decref_all(
    tx: &mut Transaction<'_, Postgres>,
    mut shas: Vec<String>,
    grace: chrono::Duration,
) -> sqlx::Result<u64> {
    shas.sort_unstable();
    for sha in &shas {
        blob_dao::decref_and_maybe_enqueue_delete(tx, sha, grace).await?;
    }
    Ok(shas.len() as u64)
}

// ── Blob links ──────────────────────────────────────────────────────────────

/// A blob linked into an image, with what serving it needs.
#[derive(Debug, Clone)]
pub struct LinkedBlob {
    pub digest: String,
    pub blob_sha256: String,
    pub size: i64,
    pub s3_key: String,
    pub last_used_at: DateTime<Utc>,
}

/// The blob `digest` of an image, if it is linked there.
pub async fn find_link(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
    digest: &str,
) -> sqlx::Result<Option<LinkedBlob>> {
    sqlx::query_as!(
        LinkedBlob,
        r#"
        SELECT l.digest, l.blob_sha256, l.size, b.s3_key, l.last_used_at
        FROM oci_blob_link l
        JOIN blob b ON b.sha256 = l.blob_sha256
        WHERE l.repository_id = $1 AND l.image = $2 AND l.digest = $3
          AND b.state = 'committed'
        "#,
        repository_id,
        image,
        digest,
    )
    .fetch_optional(pool)
    .await
}

/// Record a use of a link (at most hourly).
pub async fn touch_link(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
    digest: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE oci_blob_link
        SET last_used_at = now()
        WHERE repository_id = $1 AND image = $2 AND digest = $3
          AND last_used_at < now() - make_interval(secs => $4)
        "#,
        repository_id,
        image,
        digest,
        TOUCH_INTERVAL_SECS,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Outcome of linking a blob into an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOutcome {
    /// A new link; one reference taken.
    Inserted,
    /// The image already had it; nothing changed.
    AlreadyLinked,
    /// The CAS blob is gone or being deleted. The link row was inserted
    /// before this was known: the caller **must roll back**.
    BlobUnavailable,
}

/// Link a blob that was just committed to the CAS (`Cas::commit`) into an
/// image, consuming its ingest lease when the link is new. An image that
/// already has the blob is left alone; the lease is then released when the
/// caller drops the stored blob.
pub async fn insert_link_ingested(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    digest: &str,
    blob_sha256: &str,
    size: i64,
    ingest_token: Uuid,
) -> sqlx::Result<LinkOutcome> {
    if !insert_link_row(tx, repository_id, image, digest, blob_sha256, size).await? {
        return Ok(LinkOutcome::AlreadyLinked);
    }
    match blob_dao::commit_ingest_and_incref(tx, blob_sha256, ingest_token).await {
        Ok(()) => Ok(LinkOutcome::Inserted),
        Err(sqlx::Error::RowNotFound) => Ok(LinkOutcome::BlobUnavailable),
        Err(e) => Err(e),
    }
}

/// Link an already committed CAS blob (a cross-repository mount, a blob
/// found by content) into an image, without an ingest lease: the increment
/// requires a `committed` row and takes the blob row lock, so it serializes
/// with a deletion reservation exactly like a lease does.
pub async fn insert_link_existing(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    digest: &str,
    blob_sha256: &str,
    size: i64,
) -> sqlx::Result<LinkOutcome> {
    if !insert_link_row(tx, repository_id, image, digest, blob_sha256, size).await? {
        return Ok(LinkOutcome::AlreadyLinked);
    }
    let bumped = sqlx::query!(
        r#"
        UPDATE blob SET ref_count = ref_count + 1
        WHERE sha256 = $1 AND state = 'committed'
        "#,
        blob_sha256,
    )
    .execute(&mut **tx)
    .await?;
    if bumped.rows_affected() == 1 {
        Ok(LinkOutcome::Inserted)
    } else {
        Ok(LinkOutcome::BlobUnavailable)
    }
}

async fn insert_link_row(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    digest: &str,
    blob_sha256: &str,
    size: i64,
) -> sqlx::Result<bool> {
    let inserted = sqlx::query!(
        r#"
        INSERT INTO oci_blob_link (repository_id, image, digest, blob_sha256, size)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (repository_id, image, digest) DO NOTHING
        "#,
        repository_id,
        image,
        digest,
        blob_sha256,
        size,
    )
    .execute(&mut **tx)
    .await?;
    Ok(inserted.rows_affected() == 1)
}

/// A committed CAS blob by its SHA-256 that another image of the same
/// repository already links, with its object key and size. Only such a blob
/// may be linked on an upstream's word alone: a proxy's links hold content
/// its own upstream served and Forge verified, whereas the rest of the CAS
/// (other repositories' layers and manifests, packages of other formats)
/// never came from that upstream.
pub async fn blob_linked_in_repository(
    pool: &PgPool,
    repository_id: i64,
    sha256: &str,
) -> sqlx::Result<Option<(String, i64)>> {
    let row = sqlx::query!(
        r#"
        SELECT b.s3_key, b.size
        FROM oci_blob_link l
        JOIN blob b ON b.sha256 = l.blob_sha256
        WHERE l.blob_sha256 = $1 AND l.repository_id = $2 AND b.state = 'committed'
        LIMIT 1
        "#,
        sha256,
        repository_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| (r.s3_key, r.size)))
}

/// Remove a blob link, releasing its reference. `false` when it was not
/// linked.
pub async fn delete_link(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    digest: &str,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let sha = sqlx::query_scalar!(
        r#"
        DELETE FROM oci_blob_link
        WHERE repository_id = $1 AND image = $2 AND digest = $3
        RETURNING blob_sha256
        "#,
        repository_id,
        image,
        digest,
    )
    .fetch_optional(&mut **tx)
    .await?;
    match sha {
        Some(sha) => {
            blob_dao::decref_and_maybe_enqueue_delete(tx, &sha, grace).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Lock the links of `digests` in an image (`FOR SHARE`) and return the
/// digests that are linked. A manifest push holds these locks until it
/// commits, so the link sweeper (which takes `FOR UPDATE`) either removed a
/// link before (it is reported missing here) or sees the new manifest's
/// references after.
pub async fn lock_links(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    digests: &[String],
) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar!(
        r#"
        SELECT digest
        FROM oci_blob_link
        WHERE repository_id = $1 AND image = $2 AND digest = ANY($3)
        ORDER BY digest
        FOR SHARE
        "#,
        repository_id,
        image,
        digests,
    )
    .fetch_all(&mut **tx)
    .await
}

/// Lock a link of an image (`FOR UPDATE`) before deleting it: a manifest
/// push holds the links it names `FOR SHARE` ([`lock_links`]), so a
/// [`link_referenced`] check that follows (in a statement of its own) sees
/// every manifest that committed while this waited. `false` when the image
/// has no such link.
pub async fn lock_link(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    digest: &str,
) -> sqlx::Result<bool> {
    let locked = sqlx::query_scalar!(
        r#"
        SELECT 1 AS "one!"
        FROM oci_blob_link
        WHERE repository_id = $1 AND image = $2 AND digest = $3
        FOR UPDATE
        "#,
        repository_id,
        image,
        digest,
    )
    .fetch_optional(&mut **tx)
    .await?;
    Ok(locked.is_some())
}

/// Whether a manifest of the image names blob `digest`.
pub async fn link_referenced<'e, E>(
    executor: E,
    repository_id: i64,
    image: &str,
    digest: &str,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM oci_manifest m
            JOIN oci_manifest_ref r ON r.manifest_id = m.id
            WHERE m.repository_id = $1 AND m.image = $2
              AND r.kind = 'blob' AND r.digest = $3
        ) AS "exists!"
        "#,
        repository_id,
        image,
        digest,
    )
    .fetch_one(executor)
    .await
}

/// An unreferenced-link candidate of the sweeper.
#[derive(Debug, Clone)]
pub struct LinkKey {
    pub repository_id: i64,
    pub image: String,
    pub digest: String,
}

/// Links not used since `cutoff` that no manifest of their image names.
/// Candidates only: [`sweep_link`] re-checks each under a row lock.
pub async fn unreferenced_links(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<LinkKey>> {
    sqlx::query_as!(
        LinkKey,
        r#"
        SELECT l.repository_id, l.image, l.digest
        FROM oci_blob_link l
        WHERE l.last_used_at < $1
          AND NOT EXISTS (
              SELECT 1
              FROM oci_manifest m
              JOIN oci_manifest_ref r ON r.manifest_id = m.id
              WHERE m.repository_id = l.repository_id AND m.image = l.image
                AND r.kind = 'blob' AND r.digest = l.digest
          )
        ORDER BY l.last_used_at
        LIMIT $2
        "#,
        cutoff,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// Remove a link if it is still unused since `cutoff` and unreferenced. The
/// row is locked first and the reference check runs after, in a statement of
/// its own (a fresh snapshot), so a manifest that committed while this
/// waited for the lock is seen. Returns whether the link was removed.
pub async fn sweep_link(
    pool: &PgPool,
    key: &LinkKey,
    cutoff: DateTime<Utc>,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let mut tx = pool.begin().await?;
    let locked = sqlx::query_scalar!(
        r#"
        SELECT 1 AS "one!"
        FROM oci_blob_link
        WHERE repository_id = $1 AND image = $2 AND digest = $3 AND last_used_at < $4
        FOR UPDATE
        "#,
        key.repository_id,
        key.image,
        key.digest,
        cutoff,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if locked.is_none()
        || link_referenced(&mut *tx, key.repository_id, &key.image, &key.digest).await?
    {
        return Ok(false);
    }
    let removed = delete_link(&mut tx, key.repository_id, &key.image, &key.digest, grace).await?;
    tx.commit().await?;
    Ok(removed)
}

// ── Manifests and tags ──────────────────────────────────────────────────────

/// A stored manifest.
#[derive(Debug, Clone)]
pub struct ManifestRow {
    pub id: i64,
    pub image: String,
    pub digest: String,
    pub media_type: String,
    pub artifact_type: Option<String>,
    pub subject_digest: Option<String>,
    pub size: i64,
    pub blob_sha256: String,
    pub s3_key: String,
    pub summary: JsonValue,
    pub created_at: DateTime<Utc>,
    pub untagged_since: Option<DateTime<Utc>>,
    pub last_pulled_at: Option<DateTime<Utc>>,
}

/// The manifest `digest` of an image.
pub async fn find_manifest(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
    digest: &str,
) -> sqlx::Result<Option<ManifestRow>> {
    sqlx::query_as!(
        ManifestRow,
        r#"
        SELECT m.id, m.image, m.digest, m.media_type, m.artifact_type, m.subject_digest,
               m.size, m.blob_sha256, b.s3_key, m.summary, m.created_at,
               m.untagged_since, m.last_pulled_at
        FROM oci_manifest m
        JOIN blob b ON b.sha256 = m.blob_sha256
        WHERE m.repository_id = $1 AND m.image = $2 AND m.digest = $3
        "#,
        repository_id,
        image,
        digest,
    )
    .fetch_optional(pool)
    .await
}

/// A tag's manifest and when the tag was last confirmed upstream.
#[derive(Debug, Clone)]
pub struct TaggedManifest {
    pub manifest: ManifestRow,
    pub checked_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The manifest `tag` of an image points at.
pub async fn find_tag(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
    tag: &str,
) -> sqlx::Result<Option<TaggedManifest>> {
    let row = sqlx::query!(
        r#"
        SELECT m.id, m.image, m.digest, m.media_type, m.artifact_type, m.subject_digest,
               m.size, m.blob_sha256, b.s3_key, m.summary, m.created_at,
               m.untagged_since, m.last_pulled_at,
               t.checked_at, t.updated_at
        FROM oci_tag t
        JOIN oci_manifest m ON m.id = t.manifest_id
        JOIN blob b ON b.sha256 = m.blob_sha256
        WHERE t.repository_id = $1 AND t.image = $2 AND t.tag = $3
        "#,
        repository_id,
        image,
        tag,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| TaggedManifest {
        manifest: ManifestRow {
            id: r.id,
            image: r.image,
            digest: r.digest,
            media_type: r.media_type,
            artifact_type: r.artifact_type,
            subject_digest: r.subject_digest,
            size: r.size,
            blob_sha256: r.blob_sha256,
            s3_key: r.s3_key,
            summary: r.summary,
            created_at: r.created_at,
            untagged_since: r.untagged_since,
            last_pulled_at: r.last_pulled_at,
        },
        checked_at: r.checked_at,
        updated_at: r.updated_at,
    }))
}

/// Record that a proxy confirmed `tag` against its upstream just now.
pub async fn mark_tag_checked(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
    tag: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE oci_tag SET checked_at = now()
        WHERE repository_id = $1 AND image = $2 AND tag = $3
        "#,
        repository_id,
        image,
        tag,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Make a proxy's cached tags of `image`, or of every image (`None`), due for
/// revalidation: the next pull of each asks the upstream what it points at
/// now. Returns how many tags.
pub async fn expire_tags(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: Option<&str>,
) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        r#"
        UPDATE oci_tag SET checked_at = 'epoch'
        WHERE repository_id = $1 AND ($2::text IS NULL OR image = $2)
        "#,
        repository_id,
        image,
    )
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected())
}

/// Give what an import stored the times its source recorded: a manifest
/// the import created (`created`) is as old as `published_at`, a tag it
/// created or moved (`tag`) was pushed then, and the manifest was last
/// pulled at `downloaded_at` unless Forge saw a later pull.
#[allow(clippy::too_many_arguments)]
pub async fn set_imported_times(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
    manifest_id: i64,
    created: bool,
    tag: Option<&str>,
    published_at: Option<DateTime<Utc>>,
    downloaded_at: Option<DateTime<Utc>>,
) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query!(
        r#"
        UPDATE oci_manifest
        SET created_at = CASE WHEN $2 THEN coalesce($3, created_at) ELSE created_at END,
            last_pulled_at = greatest(last_pulled_at, $4)
        WHERE id = $1
        "#,
        manifest_id,
        created,
        published_at,
        downloaded_at,
    )
    .execute(&mut *tx)
    .await?;
    if let (Some(tag), Some(published_at)) = (tag, published_at) {
        sqlx::query!(
            r#"
            UPDATE oci_tag SET created_at = $5, updated_at = $5
            WHERE repository_id = $1 AND image = $2 AND tag = $3 AND manifest_id = $4
            "#,
            repository_id,
            image,
            tag,
            manifest_id,
            published_at,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

/// Record a pull of a manifest (at most hourly).
pub async fn touch_manifest(pool: &PgPool, manifest_id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE oci_manifest SET last_pulled_at = now()
        WHERE id = $1
          AND (last_pulled_at IS NULL OR last_pulled_at < now() - make_interval(secs => $2))
        "#,
        manifest_id,
        TOUCH_INTERVAL_SECS,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// A manifest to insert.
pub struct NewManifest<'a> {
    pub repository_id: i64,
    pub image: &'a str,
    pub digest: &'a str,
    pub blob_sha256: &'a str,
    pub media_type: &'a str,
    pub artifact_type: Option<&'a str>,
    pub subject_digest: Option<&'a str>,
    pub size: i64,
    pub summary: &'a JsonValue,
    /// Digests of the config and layers.
    pub blob_refs: &'a [String],
    /// Digests of an index's child manifests.
    pub manifest_refs: &'a [String],
}

/// Insert a manifest whose bytes were just committed to the CAS, consuming
/// the ingest lease. Returns its id and whether it is new; an existing
/// manifest of the same digest is left alone (no reference taken).
pub async fn insert_manifest(
    tx: &mut Transaction<'_, Postgres>,
    new: NewManifest<'_>,
    ingest_token: Uuid,
) -> sqlx::Result<(i64, bool)> {
    let inserted = sqlx::query_scalar!(
        r#"
        INSERT INTO oci_manifest
            (repository_id, image, digest, blob_sha256, media_type, artifact_type,
             subject_digest, size, summary, untagged_since)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
        ON CONFLICT (repository_id, image, digest) DO NOTHING
        RETURNING id
        "#,
        new.repository_id,
        new.image,
        new.digest,
        new.blob_sha256,
        new.media_type,
        new.artifact_type,
        new.subject_digest,
        new.size,
        new.summary,
    )
    .fetch_optional(&mut **tx)
    .await?;
    let Some(id) = inserted else {
        let id = sqlx::query_scalar!(
            r#"
            SELECT id FROM oci_manifest
            WHERE repository_id = $1 AND image = $2 AND digest = $3
            "#,
            new.repository_id,
            new.image,
            new.digest,
        )
        .fetch_one(&mut **tx)
        .await?;
        return Ok((id, false));
    };
    blob_dao::commit_ingest_and_incref(tx, new.blob_sha256, ingest_token).await?;
    sqlx::query!(
        r#"
        INSERT INTO oci_manifest_ref (manifest_id, kind, digest)
        SELECT $1::bigint, 'blob', d FROM unnest($2::text[]) AS d
        UNION
        SELECT $1::bigint, 'manifest', d FROM unnest($3::text[]) AS d
        ON CONFLICT DO NOTHING
        "#,
        id,
        new.blob_refs,
        new.manifest_refs,
    )
    .execute(&mut **tx)
    .await?;
    Ok((id, true))
}

/// Replace a manifest's display summary (e.g. once a proxy fetched its
/// config).
pub async fn set_manifest_summary(
    pool: &PgPool,
    manifest_id: i64,
    summary: &JsonValue,
) -> sqlx::Result<()> {
    sqlx::query!(
        "UPDATE oci_manifest SET summary = $2 WHERE id = $1",
        manifest_id,
        summary,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Record the platform of the image config `config_digest` on the image's
/// manifests that name it and have none yet (a proxy caches a manifest
/// before its config).
pub async fn set_config_platform(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
    config_digest: &str,
    platform: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE oci_manifest
        SET summary = summary || jsonb_build_object('platform', $4::text)
        WHERE repository_id = $1 AND image = $2
          AND summary->>'config_digest' = $3
          AND NOT summary ? 'platform'
        "#,
        repository_id,
        image,
        config_digest,
        platform,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Whether a manifest of the image names `config_digest` as its config and
/// has no platform recorded yet.
pub async fn config_needs_platform(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
    config_digest: &str,
) -> sqlx::Result<bool> {
    sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM oci_manifest
            WHERE repository_id = $1 AND image = $2
              AND summary->>'config_digest' = $3
              AND NOT summary ? 'platform'
        ) AS "exists!"
        "#,
        repository_id,
        image,
        config_digest,
    )
    .fetch_one(pool)
    .await
}

/// Which of `digests` are manifests of the image.
pub async fn existing_manifests(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    digests: &[String],
) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar!(
        r#"
        SELECT digest FROM oci_manifest
        WHERE repository_id = $1 AND image = $2 AND digest = ANY($3)
        ORDER BY digest
        FOR SHARE
        "#,
        repository_id,
        image,
        digests,
    )
    .fetch_all(&mut **tx)
    .await
}

/// Outcome of pointing a tag at a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagWrite {
    Created,
    /// The tag pointed at another manifest before.
    Moved {
        previous: i64,
    },
    /// The tag already pointed at this manifest.
    Unchanged,
    /// The tag points at another manifest and may not be moved; nothing
    /// changed.
    Refused,
}

/// Point `tag` at `manifest_id`. A tag pointing at another manifest is moved
/// only when `may_move` is true. The tag row is locked before it is read, so
/// the immutability decision and the `untagged_since` bookkeeping of the
/// manifest it leaves are exact under concurrent pushes.
pub async fn set_tag(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    tag: &str,
    manifest_id: i64,
    may_move: bool,
) -> sqlx::Result<TagWrite> {
    loop {
        let current = sqlx::query_scalar!(
            r#"
            SELECT manifest_id FROM oci_tag
            WHERE repository_id = $1 AND image = $2 AND tag = $3
            FOR UPDATE
            "#,
            repository_id,
            image,
            tag,
        )
        .fetch_optional(&mut **tx)
        .await?;
        let outcome = match current {
            Some(previous) if previous == manifest_id => {
                sqlx::query!(
                    r#"
                    UPDATE oci_tag SET checked_at = now()
                    WHERE repository_id = $1 AND image = $2 AND tag = $3
                    "#,
                    repository_id,
                    image,
                    tag,
                )
                .execute(&mut **tx)
                .await?;
                TagWrite::Unchanged
            }
            Some(_) if !may_move => return Ok(TagWrite::Refused),
            Some(previous) => {
                sqlx::query!(
                    r#"
                    UPDATE oci_tag
                    SET manifest_id = $4, updated_at = now(), checked_at = now()
                    WHERE repository_id = $1 AND image = $2 AND tag = $3
                    "#,
                    repository_id,
                    image,
                    tag,
                    manifest_id,
                )
                .execute(&mut **tx)
                .await?;
                TagWrite::Moved { previous }
            }
            None => {
                let inserted = sqlx::query!(
                    r#"
                    INSERT INTO oci_tag (repository_id, image, tag, manifest_id)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (repository_id, image, tag) DO NOTHING
                    "#,
                    repository_id,
                    image,
                    tag,
                    manifest_id,
                )
                .execute(&mut **tx)
                .await?;
                if inserted.rows_affected() == 0 {
                    // A concurrent push created it first: lock and decide again.
                    continue;
                }
                TagWrite::Created
            }
        };
        sqlx::query!(
            "UPDATE oci_manifest SET untagged_since = NULL WHERE id = $1",
            manifest_id,
        )
        .execute(&mut **tx)
        .await?;
        if let TagWrite::Moved { previous } = outcome {
            refresh_untagged(tx, previous).await?;
        }
        return Ok(outcome);
    }
}

/// Set a manifest's `untagged_since` from whether any tag still points at it.
async fn refresh_untagged(
    tx: &mut Transaction<'_, Postgres>,
    manifest_id: i64,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE oci_manifest
        SET untagged_since = CASE
                WHEN EXISTS (SELECT 1 FROM oci_tag WHERE manifest_id = $1) THEN NULL
                ELSE coalesce(untagged_since, now())
            END
        WHERE id = $1
        "#,
        manifest_id,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Delete a tag (its manifest stays). `false` when there was no such tag.
pub async fn delete_tag(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    tag: &str,
) -> sqlx::Result<bool> {
    let manifest_id = sqlx::query_scalar!(
        r#"
        DELETE FROM oci_tag
        WHERE repository_id = $1 AND image = $2 AND tag = $3
        RETURNING manifest_id
        "#,
        repository_id,
        image,
        tag,
    )
    .fetch_optional(&mut **tx)
    .await?;
    match manifest_id {
        Some(id) => {
            refresh_untagged(tx, id).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Delete a manifest and every tag pointing at it, releasing the manifest's
/// own reference. Its config and layers stay linked to the image until the
/// sweeper finds them unreferenced. `false` when there was no such manifest.
pub async fn delete_manifest(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    digest: &str,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let Some(id) = sqlx::query_scalar!(
        r#"
        SELECT id FROM oci_manifest
        WHERE repository_id = $1 AND image = $2 AND digest = $3
        FOR UPDATE
        "#,
        repository_id,
        image,
        digest,
    )
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(false);
    };
    delete_locked_manifest(tx, id, grace).await?;
    Ok(true)
}

/// Delete a manifest the caller has locked `FOR UPDATE`, with its tags.
pub async fn delete_locked_manifest(
    tx: &mut Transaction<'_, Postgres>,
    manifest_id: i64,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    sqlx::query!("DELETE FROM oci_tag WHERE manifest_id = $1", manifest_id)
        .execute(&mut **tx)
        .await?;
    let sha = sqlx::query_scalar!(
        "DELETE FROM oci_manifest WHERE id = $1 RETURNING blob_sha256",
        manifest_id,
    )
    .fetch_optional(&mut **tx)
    .await?;
    match sha {
        Some(sha) => {
            blob_dao::decref_and_maybe_enqueue_delete(tx, &sha, grace).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// One page of an image's tags in byte order, after `last`.
pub async fn list_tags(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
    last: Option<&str>,
    limit: i64,
) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar!(
        r#"
        SELECT tag FROM oci_tag
        WHERE repository_id = $1 AND image = $2
          AND ($3::text IS NULL OR tag COLLATE "C" > $3::text COLLATE "C")
        ORDER BY tag COLLATE "C"
        LIMIT $4
        "#,
        repository_id,
        image,
        last,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// Whether the image has any manifest, tag or blob (the spec's "repository
/// known").
pub async fn image_exists(pool: &PgPool, repository_id: i64, image: &str) -> sqlx::Result<bool> {
    sqlx::query_scalar!(
        r#"
        SELECT (EXISTS (SELECT 1 FROM oci_manifest WHERE repository_id = $1 AND image = $2)
             OR EXISTS (SELECT 1 FROM oci_blob_link WHERE repository_id = $1 AND image = $2))
            AS "exists!"
        "#,
        repository_id,
        image,
    )
    .fetch_one(pool)
    .await
}

/// Manifests of the image whose `subject` is `subject_digest`.
pub async fn list_referrers(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
    subject_digest: &str,
) -> sqlx::Result<Vec<ManifestRow>> {
    sqlx::query_as!(
        ManifestRow,
        r#"
        SELECT m.id, m.image, m.digest, m.media_type, m.artifact_type, m.subject_digest,
               m.size, m.blob_sha256, b.s3_key, m.summary, m.created_at,
               m.untagged_since, m.last_pulled_at
        FROM oci_manifest m
        JOIN blob b ON b.sha256 = m.blob_sha256
        WHERE m.repository_id = $1 AND m.image = $2 AND m.subject_digest = $3
        ORDER BY m.created_at, m.digest
        "#,
        repository_id,
        image,
        subject_digest,
    )
    .fetch_all(pool)
    .await
}

/// Which of `repository_ids` have any manifest of `image` (the group
/// dependency-confusion guard's "an owner has it").
pub async fn repositories_having_image(
    pool: &PgPool,
    repository_ids: &[i64],
    image: &str,
) -> sqlx::Result<Vec<i64>> {
    sqlx::query_scalar!(
        r#"
        SELECT DISTINCT repository_id FROM oci_manifest
        WHERE repository_id = ANY($1) AND image = $2
        "#,
        repository_ids,
        image,
    )
    .fetch_all(pool)
    .await
}

// ── Browsing ────────────────────────────────────────────────────────────────

/// An image of a repository, for listings.
#[derive(Debug, Clone)]
pub struct ImageSummary {
    pub image: String,
    pub tag_count: i64,
    pub manifest_count: i64,
    pub last_pushed_at: DateTime<Utc>,
}

/// The images of a repository whose name contains `query` (all when empty),
/// by name.
pub async fn list_images(
    pool: &PgPool,
    repository_id: i64,
    query: &str,
    offset: i64,
    limit: i64,
) -> sqlx::Result<Vec<ImageSummary>> {
    sqlx::query_as!(
        ImageSummary,
        r#"
        SELECT m.image,
               count(DISTINCT t.tag) AS "tag_count!",
               count(DISTINCT m.id) AS "manifest_count!",
               max(m.created_at) AS "last_pushed_at!"
        FROM oci_manifest m
        LEFT JOIN oci_tag t ON t.manifest_id = m.id
        WHERE m.repository_id = $1 AND strpos(m.image, $2) > 0
        GROUP BY m.image
        ORDER BY m.image
        OFFSET $3 LIMIT $4
        "#,
        repository_id,
        query,
        offset,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// How many images [`list_images`] would list in total.
pub async fn count_images(pool: &PgPool, repository_id: i64, query: &str) -> sqlx::Result<i64> {
    sqlx::query_scalar!(
        r#"
        SELECT count(DISTINCT image) AS "count!"
        FROM oci_manifest
        WHERE repository_id = $1 AND strpos(image, $2) > 0
        "#,
        repository_id,
        query,
    )
    .fetch_one(pool)
    .await
}

/// A manifest of an image with the tags pointing at it, for the detail
/// view.
#[derive(Debug, Clone)]
pub struct ManifestListing {
    pub digest: String,
    pub media_type: String,
    pub artifact_type: Option<String>,
    pub subject_digest: Option<String>,
    pub size: i64,
    pub summary: JsonValue,
    pub created_at: DateTime<Utc>,
    pub last_pulled_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    /// An index's child manifests.
    pub children: Vec<String>,
}

/// Every manifest of an image, newest first, with its tags.
pub async fn image_manifests(
    pool: &PgPool,
    repository_id: i64,
    image: &str,
) -> sqlx::Result<Vec<ManifestListing>> {
    sqlx::query_as!(
        ManifestListing,
        r#"
        SELECT m.digest, m.media_type, m.artifact_type, m.subject_digest, m.size,
               m.summary, m.created_at, m.last_pulled_at,
               coalesce(array_agg(t.tag ORDER BY t.tag) FILTER (WHERE t.tag IS NOT NULL),
                        '{}') AS "tags!",
               ARRAY(SELECT r.digest FROM oci_manifest_ref r
                     WHERE r.manifest_id = m.id AND r.kind = 'manifest'
                     ORDER BY r.digest) AS "children!"
        FROM oci_manifest m
        LEFT JOIN oci_tag t ON t.manifest_id = m.id
        WHERE m.repository_id = $1 AND m.image = $2
        GROUP BY m.id
        ORDER BY m.created_at DESC, m.digest
        "#,
        repository_id,
        image,
    )
    .fetch_all(pool)
    .await
}

// ── Upload sessions ─────────────────────────────────────────────────────────

/// A blob upload session.
#[derive(Debug, Clone)]
pub struct UploadRow {
    pub id: Uuid,
    pub repository_id: i64,
    pub image: String,
    pub size: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One chunk of an upload, with its CAS object.
#[derive(Debug, Clone)]
pub struct UploadPart {
    pub seq: i32,
    pub start_offset: i64,
    pub size: i64,
    pub blob_sha256: String,
    pub sha512_base64: String,
    pub s3_key: String,
}

/// Start an upload session.
pub async fn create_upload(
    pool: &PgPool,
    id: Uuid,
    repository_id: i64,
    image: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO oci_upload (id, repository_id, image) VALUES ($1, $2, $3)",
        id,
        repository_id,
        image,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// An upload session of the image.
pub async fn get_upload(
    pool: &PgPool,
    id: Uuid,
    repository_id: i64,
    image: &str,
) -> sqlx::Result<Option<UploadRow>> {
    sqlx::query_as!(
        UploadRow,
        r#"
        SELECT id, repository_id, image, size, created_at, updated_at
        FROM oci_upload
        WHERE id = $1 AND repository_id = $2 AND image = $3
        "#,
        id,
        repository_id,
        image,
    )
    .fetch_optional(pool)
    .await
}

/// Lock an upload session of the image (`FOR UPDATE`).
pub async fn lock_upload(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    repository_id: i64,
    image: &str,
) -> sqlx::Result<Option<UploadRow>> {
    sqlx::query_as!(
        UploadRow,
        r#"
        SELECT id, repository_id, image, size, created_at, updated_at
        FROM oci_upload
        WHERE id = $1 AND repository_id = $2 AND image = $3
        FOR UPDATE
        "#,
        id,
        repository_id,
        image,
    )
    .fetch_optional(&mut **tx)
    .await
}

/// Append a chunk just committed to the CAS to a locked upload at its
/// current end, consuming the ingest lease.
pub async fn add_upload_part(
    tx: &mut Transaction<'_, Postgres>,
    upload: &UploadRow,
    size: i64,
    blob_sha256: &str,
    sha512_base64: &str,
    ingest_token: Uuid,
) -> sqlx::Result<()> {
    blob_dao::commit_ingest_and_incref(tx, blob_sha256, ingest_token).await?;
    sqlx::query!(
        r#"
        INSERT INTO oci_upload_part
            (upload_id, seq, start_offset, size, blob_sha256, sha512_base64)
        SELECT $1, coalesce(max(seq) + 1, 0), $2, $3, $4, $5
        FROM oci_upload_part WHERE upload_id = $1
        "#,
        upload.id,
        upload.size,
        size,
        blob_sha256,
        sha512_base64,
    )
    .execute(&mut **tx)
    .await?;
    sqlx::query!(
        "UPDATE oci_upload SET size = size + $2, updated_at = now() WHERE id = $1",
        upload.id,
        size,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The chunks of an upload in order.
pub async fn upload_parts<'e, E>(executor: E, upload_id: Uuid) -> sqlx::Result<Vec<UploadPart>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        UploadPart,
        r#"
        SELECT p.seq, p.start_offset, p.size, p.blob_sha256, p.sha512_base64, b.s3_key
        FROM oci_upload_part p
        JOIN blob b ON b.sha256 = p.blob_sha256
        WHERE p.upload_id = $1
        ORDER BY p.seq
        "#,
        upload_id,
    )
    .fetch_all(executor)
    .await
}

/// End an upload session, releasing its chunks' references. `false` when it
/// did not exist.
pub async fn delete_upload(
    tx: &mut Transaction<'_, Postgres>,
    upload_id: Uuid,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let shas = sqlx::query_scalar!(
        "DELETE FROM oci_upload_part WHERE upload_id = $1 RETURNING blob_sha256",
        upload_id,
    )
    .fetch_all(&mut **tx)
    .await?;
    let deleted = sqlx::query!("DELETE FROM oci_upload WHERE id = $1", upload_id)
        .execute(&mut **tx)
        .await?;
    decref_all(tx, shas, grace).await?;
    Ok(deleted.rows_affected() == 1)
}

/// Upload sessions idle since `cutoff`.
pub async fn stale_uploads(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
    limit: i64,
) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar!(
        r#"
        SELECT id FROM oci_upload
        WHERE updated_at < $1
        ORDER BY updated_at
        LIMIT $2
        "#,
        cutoff,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// Expire one idle upload session: locked, re-checked and deleted with its
/// chunks. `false` when it was used again (or ended) meanwhile.
pub async fn expire_upload(
    pool: &PgPool,
    upload_id: Uuid,
    cutoff: DateTime<Utc>,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let mut tx = pool.begin().await?;
    let idle = sqlx::query_scalar!(
        r#"
        SELECT 1 AS "one!" FROM oci_upload
        WHERE id = $1 AND updated_at < $2
        FOR UPDATE
        "#,
        upload_id,
        cutoff,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if idle.is_none() {
        return Ok(false);
    }
    let deleted = delete_upload(&mut tx, upload_id, grace).await?;
    tx.commit().await?;
    Ok(deleted)
}

// ── Registry tokens ─────────────────────────────────────────────────────────

/// Whether the user a registry token names is still active — and the API
/// token it was minted from (if any) still live — with the user's current
/// admin flag. `None`: the token must no longer be honored.
pub async fn live_principal(
    pool: &PgPool,
    user_id: i64,
    token_id: Option<i64>,
) -> sqlx::Result<Option<bool>> {
    let row = sqlx::query!(
        r#"
        SELECT u.is_admin,
               ($2::bigint IS NULL OR EXISTS (
                   SELECT 1 FROM token t
                   WHERE t.id = $2 AND t.user_id = u.id AND t.revoked_at IS NULL
                     AND (t.expires_at IS NULL OR t.expires_at > now())
               )) AS "token_live!"
        FROM app_user u
        WHERE u.id = $1 AND u.active
        "#,
        user_id,
        token_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.filter(|r| r.token_live).map(|r| r.is_admin))
}

// ── Retention ───────────────────────────────────────────────────────────────

/// A tag, for retention.
#[derive(Debug, Clone)]
pub struct RetentionTag {
    pub image: String,
    pub tag: String,
    pub manifest_id: i64,
    pub digest: String,
    pub updated_at: DateTime<Utc>,
    pub last_pulled_at: Option<DateTime<Utc>>,
}

/// Every tag of a repository.
pub async fn retention_tags(pool: &PgPool, repository_id: i64) -> sqlx::Result<Vec<RetentionTag>> {
    sqlx::query_as!(
        RetentionTag,
        r#"
        SELECT t.image, t.tag, t.manifest_id, m.digest, t.updated_at, m.last_pulled_at
        FROM oci_tag t
        JOIN oci_manifest m ON m.id = t.manifest_id
        WHERE t.repository_id = $1
        ORDER BY t.image, t.tag
        "#,
        repository_id,
    )
    .fetch_all(pool)
    .await
}

/// A manifest, for retention.
#[derive(Debug, Clone)]
pub struct RetentionManifest {
    pub id: i64,
    pub image: String,
    pub digest: String,
    pub created_at: DateTime<Utc>,
    pub untagged_since: Option<DateTime<Utc>>,
    pub last_pulled_at: Option<DateTime<Utc>>,
    pub subject_digest: Option<String>,
    /// An index's child manifests.
    pub children: Vec<String>,
}

/// Every manifest of a repository.
pub async fn retention_manifests(
    pool: &PgPool,
    repository_id: i64,
) -> sqlx::Result<Vec<RetentionManifest>> {
    sqlx::query_as!(
        RetentionManifest,
        r#"
        SELECT m.id, m.image, m.digest, m.created_at, m.untagged_since, m.last_pulled_at,
               m.subject_digest,
               ARRAY(SELECT r.digest FROM oci_manifest_ref r
                     WHERE r.manifest_id = m.id AND r.kind = 'manifest'
                     ORDER BY r.digest) AS "children!"
        FROM oci_manifest m
        WHERE m.repository_id = $1
        ORDER BY m.image, m.id
        "#,
        repository_id,
    )
    .fetch_all(pool)
    .await
}

/// Delete `tag` only if it still points at `manifest_id` (retention decided
/// on that). `false`: it moved or is gone.
pub async fn delete_tag_if(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    image: &str,
    tag: &str,
    manifest_id: i64,
) -> sqlx::Result<bool> {
    let current = sqlx::query_scalar!(
        r#"
        SELECT manifest_id FROM oci_tag
        WHERE repository_id = $1 AND image = $2 AND tag = $3
        FOR UPDATE
        "#,
        repository_id,
        image,
        tag,
    )
    .fetch_optional(&mut **tx)
    .await?;
    if current != Some(manifest_id) {
        return Ok(false);
    }
    delete_tag(tx, repository_id, image, tag).await
}

/// Delete an untagged manifest that no other manifest of its image lists as
/// a child, re-checked under the row lock (a tag or an index pushed since
/// retention decided keeps it). `false`: kept.
pub async fn delete_untagged_manifest(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    manifest_id: i64,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let Some(row) = sqlx::query!(
        r#"
        SELECT image, digest FROM oci_manifest
        WHERE id = $1 AND repository_id = $2
        FOR UPDATE
        "#,
        manifest_id,
        repository_id,
    )
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(false);
    };
    let kept = sqlx::query_scalar!(
        r#"
        SELECT (EXISTS (SELECT 1 FROM oci_tag WHERE manifest_id = $1)
             OR EXISTS (
                 SELECT 1
                 FROM oci_manifest p
                 JOIN oci_manifest_ref r ON r.manifest_id = p.id
                 WHERE p.repository_id = $2 AND p.image = $3 AND p.id <> $1
                   AND r.kind = 'manifest' AND r.digest = $4
             )) AS "kept!"
        "#,
        manifest_id,
        repository_id,
        row.image,
        row.digest,
    )
    .fetch_one(&mut **tx)
    .await?;
    if kept {
        return Ok(false);
    }
    delete_locked_manifest(tx, manifest_id, grace).await
}
