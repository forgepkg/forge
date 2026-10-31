//! Raw (generic file) repositories: the `raw_file` table.
//!
//! A file is a path in a repository naming one CAS blob, and each row holds
//! exactly one `blob.ref_count` reference (see the schema): [`store`]
//! takes it with the ingest lease of the uploaded content, in the
//! transaction that inserts the row or points it at new content, and every
//! delete releases it in the transaction that removes the row.
//!
//! Paths are stored normalized and compared in byte order (`COLLATE "C"`):
//! the files under a directory `a/b/` are the range `["a/b/", "a/b0")` of the
//! `(repository_id, path)` index (`'0'` follows `'/'`), which is what
//! listings and directory deletes walk.

use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::blob_dao;

/// A stored file, with the S3 key of its blob.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RawFile {
    pub id: i64,
    pub repository_id: i64,
    pub path: String,
    pub blob_sha256: String,
    pub s3_key: String,
    pub size: i64,
    pub content_type: String,
    pub sha512_base64: String,
    pub sha1: String,
    pub md5: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_downloaded_at: Option<DateTime<Utc>>,
    pub upstream_etag: Option<String>,
    pub upstream_last_modified: Option<String>,
    pub checked_at: Option<DateTime<Utc>>,
    /// The file never changes at its path: a proxy never re-validates it,
    /// and a content-addressed index file outlives its index by a day.
    pub immutable: bool,
}

/// The bounds of the files under directory `prefix` (`""` for the root, else
/// ending in `/`): every path `p` with `lower <= p < upper` (no upper bound
/// for the root).
pub fn prefix_range(prefix: &str) -> (String, Option<String>) {
    match prefix.strip_suffix('/') {
        Some(dir) => (prefix.to_string(), Some(format!("{dir}0"))),
        None => (prefix.to_string(), None),
    }
}

/// The file at `path` of repository `repository_id`.
pub async fn find(pool: &PgPool, repository_id: i64, path: &str) -> sqlx::Result<Option<RawFile>> {
    sqlx::query_as!(
        RawFile,
        r#"
        SELECT f.id, f.repository_id, f.path, f.blob_sha256, b.s3_key, f.size,
               f.content_type, f.sha512_base64, f.sha1, f.md5, f.created_at,
               f.updated_at, f.last_downloaded_at, f.upstream_etag,
               f.upstream_last_modified, f.checked_at, f.immutable
        FROM raw_file f
        JOIN blob b ON b.sha256 = f.blob_sha256
        WHERE f.repository_id = $1 AND f.path = $2
        "#,
        repository_id,
        path,
    )
    .fetch_optional(pool)
    .await
}

/// Whether repository `repository_id` has a file under directory `prefix`
/// (`""`: any file).
pub async fn directory_exists(
    pool: &PgPool,
    repository_id: i64,
    prefix: &str,
) -> sqlx::Result<bool> {
    let (lower, upper) = prefix_range(prefix);
    sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM raw_file
            WHERE repository_id = $1 AND path >= $2 AND ($3::text IS NULL OR path < $3)
        ) AS "exists!"
        "#,
        repository_id,
        lower,
        upper,
    )
    .fetch_one(pool)
    .await
}

/// Whether `repository_id` has any file. Pass the transaction that holds the
/// repository row lock so the answer stays true until commit.
pub async fn repository_has_files<'e, E>(executor: E, repository_id: i64) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM raw_file WHERE repository_id = $1) AS "exists!""#,
        repository_id,
    )
    .fetch_one(executor)
    .await
}

/// A file to store: its path, the ingested content and what is served with
/// it.
#[derive(Debug, Clone)]
pub struct NewRawFile<'a> {
    pub path: &'a str,
    pub sha256: &'a str,
    pub size: i64,
    pub content_type: &'a str,
    pub sha512_base64: &'a str,
    pub sha1: &'a str,
    pub md5: &'a str,
    /// Proxies: the upstream's validators of the content, and whether the
    /// copy counts as just confirmed.
    pub upstream_etag: Option<&'a str>,
    pub upstream_last_modified: Option<&'a str>,
    pub checked: bool,
    /// The file never changes at its path ([`RawFile::immutable`]).
    pub immutable: bool,
}

/// Whether [`store`] may replace a file that exists with other content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redeploy {
    Allow,
    Deny,
}

/// What [`store`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOutcome {
    /// A new file (`raw_file.id`).
    Created(i64),
    /// The file existed and now holds the new content.
    Replaced(i64),
    /// The file already held this content: its metadata was refreshed, no
    /// reference taken (the ingest lease is left to lapse).
    Unchanged(i64),
    /// The file exists with other content and redeploying is denied.
    Exists,
}

/// Store `file` in `repository_id`, the content being the ingested blob of
/// `ingest_token`. A new path takes the content's reference; an existing one
/// is replaced only with [`Redeploy::Allow`] (its previous blob's reference
/// released), and is left alone when it already holds the same content.
///
/// The existing row is locked `FOR UPDATE` before it is inspected, so two
/// uploads of one path apply one after the other, and neither releases a
/// reference the other took.
pub async fn store(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    file: &NewRawFile<'_>,
    ingest_token: Uuid,
    redeploy: Redeploy,
    grace: chrono::Duration,
) -> sqlx::Result<StoreOutcome> {
    for _ in 0..3 {
        let inserted = sqlx::query_scalar!(
            r#"
            INSERT INTO raw_file (repository_id, path, blob_sha256, size, content_type,
                                  sha512_base64, sha1, md5, upstream_etag,
                                  upstream_last_modified, checked_at, immutable)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                    CASE WHEN $11 THEN now() END, $12)
            ON CONFLICT (repository_id, path) DO NOTHING
            RETURNING id
            "#,
            repository_id,
            file.path,
            file.sha256,
            file.size,
            file.content_type,
            file.sha512_base64,
            file.sha1,
            file.md5,
            file.upstream_etag,
            file.upstream_last_modified,
            file.checked,
            file.immutable,
        )
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(id) = inserted {
            blob_dao::commit_ingest_and_incref(tx, file.sha256, ingest_token).await?;
            return Ok(StoreOutcome::Created(id));
        }

        // The path exists (an insert in flight was waited for).
        let Some(existing) = sqlx::query!(
            r#"
            SELECT id, blob_sha256 FROM raw_file
            WHERE repository_id = $1 AND path = $2
            FOR UPDATE
            "#,
            repository_id,
            file.path,
        )
        .fetch_optional(&mut **tx)
        .await?
        else {
            // Deleted in between: insert again.
            continue;
        };

        if existing.blob_sha256 == file.sha256 {
            sqlx::query!(
                r#"
                UPDATE raw_file
                SET content_type = $2,
                    upstream_etag = $3,
                    upstream_last_modified = $4,
                    checked_at = CASE WHEN $5 THEN now() ELSE checked_at END,
                    immutable = $6
                WHERE id = $1
                "#,
                existing.id,
                file.content_type,
                file.upstream_etag,
                file.upstream_last_modified,
                file.checked,
                file.immutable,
            )
            .execute(&mut **tx)
            .await?;
            return Ok(StoreOutcome::Unchanged(existing.id));
        }
        if redeploy == Redeploy::Deny {
            return Ok(StoreOutcome::Exists);
        }

        sqlx::query!(
            r#"
            UPDATE raw_file
            SET blob_sha256 = $2, size = $3, content_type = $4, sha512_base64 = $5,
                sha1 = $6, md5 = $7, upstream_etag = $8, upstream_last_modified = $9,
                checked_at = CASE WHEN $10 THEN now() END,
                immutable = $11,
                updated_at = greatest(now(), updated_at + interval '1 microsecond')
            WHERE id = $1
            "#,
            existing.id,
            file.sha256,
            file.size,
            file.content_type,
            file.sha512_base64,
            file.sha1,
            file.md5,
            file.upstream_etag,
            file.upstream_last_modified,
            file.checked,
            file.immutable,
        )
        .execute(&mut **tx)
        .await?;
        // Blob rows are locked in hash order by every writer that touches
        // two at once.
        if file.sha256 < existing.blob_sha256.as_str() {
            blob_dao::commit_ingest_and_incref(tx, file.sha256, ingest_token).await?;
            blob_dao::decref_and_maybe_enqueue_delete(tx, &existing.blob_sha256, grace).await?;
        } else {
            blob_dao::decref_and_maybe_enqueue_delete(tx, &existing.blob_sha256, grace).await?;
            blob_dao::commit_ingest_and_incref(tx, file.sha256, ingest_token).await?;
        }
        return Ok(StoreOutcome::Replaced(existing.id));
    }
    Err(sqlx::Error::Protocol(format!(
        "raw file {:?} kept being deleted while it was stored",
        file.path
    )))
}

/// Delete the file at `path`, releasing its blob reference. Returns whether
/// there was one.
pub async fn delete(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    path: &str,
    grace: chrono::Duration,
) -> sqlx::Result<bool> {
    let deleted = sqlx::query_scalar!(
        "DELETE FROM raw_file WHERE repository_id = $1 AND path = $2 RETURNING blob_sha256",
        repository_id,
        path,
    )
    .fetch_optional(&mut **tx)
    .await?;
    match deleted {
        Some(sha) => {
            blob_dao::decref_and_maybe_enqueue_delete(tx, &sha, grace).await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Delete up to `limit` files under directory `prefix` (`""`: anywhere),
/// releasing their blob references. Returns how many were deleted; fewer
/// than `limit` means none are left.
pub async fn delete_under(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    prefix: &str,
    limit: i64,
    grace: chrono::Duration,
) -> sqlx::Result<u64> {
    let (lower, upper) = prefix_range(prefix);
    let shas = sqlx::query_scalar!(
        r#"
        DELETE FROM raw_file
        WHERE id IN (
            SELECT id FROM raw_file
            WHERE repository_id = $1 AND path >= $2 AND ($3::text IS NULL OR path < $3)
            ORDER BY path
            LIMIT $4
            FOR UPDATE
        )
        RETURNING blob_sha256
        "#,
        repository_id,
        lower,
        upper,
        limit,
    )
    .fetch_all(&mut **tx)
    .await?;
    decref_all(tx, shas, grace).await
}

/// Remove every file of `repository_id`, releasing one blob reference per
/// removed row. The caller holds the repository row `FOR UPDATE` (as for
/// `component_dao::hard_delete_all_components`), which blocks new inserts
/// until the repository itself is deleted.
pub async fn purge_repository(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    grace: chrono::Duration,
) -> sqlx::Result<u64> {
    let shas = sqlx::query_scalar!(
        "DELETE FROM raw_file WHERE repository_id = $1 RETURNING blob_sha256",
        repository_id,
    )
    .fetch_all(&mut **tx)
    .await?;
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

/// Record a download of file `id`: at most one write per hour per file.
pub async fn touch_downloaded(pool: &PgPool, id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE raw_file SET last_downloaded_at = now()
        WHERE id = $1
          AND (last_downloaded_at IS NULL OR last_downloaded_at < now() - interval '1 hour')
        "#,
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Proxies: the upstream confirmed file `id` (its content unchanged): it is
/// fresh again, with the upstream's current validators where it sent them.
pub async fn mark_checked(
    pool: &PgPool,
    id: i64,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE raw_file
        SET checked_at = now(),
            upstream_etag = coalesce($2, upstream_etag),
            upstream_last_modified = coalesce($3, upstream_last_modified)
        WHERE id = $1
        "#,
        id,
        etag,
        last_modified,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Proxies: make the cached files under `prefix` (`""`: all of them) due for
/// re-validation against the upstream on their next download. Returns how
/// many were fresh.
pub async fn expire_checks<'e, E>(
    executor: E,
    repository_id: i64,
    prefix: &str,
) -> sqlx::Result<u64>
where
    E: PgExecutor<'e>,
{
    let (lower, upper) = prefix_range(prefix);
    let result = sqlx::query!(
        r#"
        UPDATE raw_file SET checked_at = NULL
        WHERE repository_id = $1 AND path >= $2 AND ($3::text IS NULL OR path < $3)
          AND checked_at IS NOT NULL
        "#,
        repository_id,
        lower,
        upper,
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Proxies: make the cached file at `path` due for re-validation. Returns
/// whether it was fresh.
pub async fn expire_file_check<'e, E>(
    executor: E,
    repository_id: i64,
    path: &str,
) -> sqlx::Result<u64>
where
    E: PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"
        UPDATE raw_file SET checked_at = NULL
        WHERE repository_id = $1 AND path = $2 AND checked_at IS NOT NULL
        "#,
        repository_id,
        path,
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

// ── Listings ────────────────────────────────────────────────────────────────

/// One entry a directory listing walked to: a subdirectory (`file` is
/// `None`; `path` is its first file) or a file.
#[derive(Debug, Clone)]
pub struct WalkedEntry {
    pub path: String,
    pub file: Option<RawFile>,
}

/// The entries of directory `prefix` (`""` for the root, else ending in
/// `/`), in byte order of their names (a subdirectory `d` sorting as `d/`),
/// starting at the first path at or after `from` (a full path: `prefix` to
/// start at the beginning), at most `limit` of them.
///
/// It walks the index rather than the directory's files: each entry is one
/// probe for the next path, and a subdirectory's files are skipped in one
/// step (from `<prefix><dir>/` to `<prefix><dir>0`), so a page costs `limit`
/// probes however many files are below it.
pub async fn walk_directory(
    pool: &PgPool,
    repository_id: i64,
    prefix: &str,
    from: &str,
    limit: i64,
) -> sqlx::Result<Vec<WalkedEntry>> {
    let (lower, upper) = prefix_range(prefix);
    let from = if from < lower.as_str() {
        lower.as_str()
    } else {
        from
    };
    // `$3`: where an entry's name starts (1-based, in characters).
    let start = i32::try_from(prefix.chars().count() + 1).unwrap_or(i32::MAX);
    // The next path after a walked one: past every file of a subdirectory,
    // or right after a file (no path holds a control character).
    let next = r#"
        CASE WHEN strpos(substr(w.path, $3), '/') > 0
             THEN left(w.path, $3 - 1 + strpos(substr(w.path, $3), '/') - 1) || '0'
             ELSE w.path || chr(1) END
    "#;
    let bounded = upper.is_some();
    let upper_clause = if bounded { "AND f.path < $5" } else { "" };
    let sql = format!(
        r#"
        WITH RECURSIVE walk(path, step) AS (
            (SELECT f.path, 1 FROM raw_file f
             WHERE f.repository_id = $1 AND f.path >= $2 {upper_clause}
             ORDER BY f.path LIMIT 1)
          UNION ALL
            (SELECT n.path, w.step + 1 FROM walk w
             CROSS JOIN LATERAL (
                 SELECT f.path FROM raw_file f
                 WHERE f.repository_id = $1 AND f.path >= ({next}) {upper_clause}
                 ORDER BY f.path LIMIT 1
             ) n
             WHERE w.step < $4)
        )
        SELECT w.path AS walked_path,
               f.id, f.repository_id, f.path, f.blob_sha256, b.s3_key, f.size,
               f.content_type, f.sha512_base64, f.sha1, f.md5, f.created_at,
               f.updated_at, f.last_downloaded_at, f.upstream_etag,
               f.upstream_last_modified, f.checked_at, f.immutable
        FROM walk w
        LEFT JOIN raw_file f
               ON f.repository_id = $1 AND f.path = w.path
              AND strpos(substr(w.path, $3), '/') = 0
        LEFT JOIN blob b ON b.sha256 = f.blob_sha256
        ORDER BY w.step
        "#
    );
    // Assembled from the constant fragments above only.
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(repository_id)
        .bind(from)
        .bind(start)
        .bind(limit.max(1));
    if let Some(upper) = &upper {
        query = query.bind(upper);
    }
    let rows = query.fetch_all(pool).await?;
    use sqlx::Row;
    rows.into_iter()
        .map(|row| {
            let path: String = row.try_get("walked_path")?;
            let id: Option<i64> = row.try_get("id")?;
            let file = match id {
                Some(_) => Some(<RawFile as sqlx::FromRow<_>>::from_row(&row)?),
                None => None,
            };
            Ok(WalkedEntry { path, file })
        })
        .collect()
}

/// Up to `limit` paths under directory `prefix` after `after` (exclusive; a
/// full path), in byte order: what a listing reads to find out whether a
/// subdirectory holds a file the caller may see.
pub async fn paths_under(
    pool: &PgPool,
    repository_id: i64,
    prefix: &str,
    after: &str,
    limit: i64,
) -> sqlx::Result<Vec<String>> {
    let (lower, upper) = prefix_range(prefix);
    let after = if after < lower.as_str() { "" } else { after };
    sqlx::query_scalar!(
        r#"
        SELECT path FROM raw_file
        WHERE repository_id = $1 AND path >= $2 AND ($3::text IS NULL OR path < $3)
          AND path > $4
        ORDER BY path
        LIMIT $5
        "#,
        repository_id,
        lower,
        upper,
        after,
        limit,
    )
    .fetch_all(pool)
    .await
}

// ── Retention ───────────────────────────────────────────────────────────────

/// A file, for retention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionFile {
    pub id: i64,
    pub path: String,
    pub blob_sha256: String,
    pub size: i64,
    pub updated_at: DateTime<Utc>,
    pub last_downloaded_at: Option<DateTime<Utc>>,
}

/// Every file of a repository, by path.
pub async fn retention_files(
    pool: &PgPool,
    repository_id: i64,
) -> sqlx::Result<Vec<RetentionFile>> {
    sqlx::query_as!(
        RetentionFile,
        r#"
        SELECT id, path, blob_sha256, size, updated_at, last_downloaded_at
        FROM raw_file
        WHERE repository_id = $1
        ORDER BY path
        "#,
        repository_id,
    )
    .fetch_all(pool)
    .await
}

/// The logical size of a raw repository, counting every file entry.
pub async fn repository_size(pool: &PgPool, repository_id: i64) -> sqlx::Result<u64> {
    let bytes = sqlx::query_scalar!(
        r#"SELECT COALESCE(SUM(size), 0)::bigint AS "bytes!" FROM raw_file WHERE repository_id = $1"#,
        repository_id,
    )
    .fetch_one(pool)
    .await?;
    u64::try_from(bytes).map_err(|e| sqlx::Error::Protocol(e.to_string()))
}

/// The files directly in directory `prefix` (not in its subdirectories),
/// locked `FOR UPDATE`: what a retention batch re-evaluates before it
/// deletes any of them.
pub async fn lock_directory_for_retention(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    prefix: &str,
) -> sqlx::Result<Vec<RetentionFile>> {
    let (lower, upper) = prefix_range(prefix);
    let start = i32::try_from(prefix.chars().count() + 1).unwrap_or(i32::MAX);
    sqlx::query_as!(
        RetentionFile,
        r#"
        SELECT id, path, blob_sha256, size, updated_at, last_downloaded_at
        FROM raw_file
        WHERE repository_id = $1 AND path >= $2 AND ($3::text IS NULL OR path < $3)
          AND strpos(substr(path, $4), '/') = 0
        ORDER BY path
        FOR UPDATE
        "#,
        repository_id,
        lower,
        upper,
        start,
    )
    .fetch_all(&mut **tx)
    .await
}

/// A file retention deleted: the blob it released, its reference count
/// after, and whether that queued the blob's deletion.
#[derive(Debug, Clone)]
pub struct DeletedFile {
    pub blob_sha256: String,
    pub ref_count_after: Option<i64>,
    pub delete_enqueued: bool,
}

/// Delete file `id` of `repository_id`, releasing its blob reference.
/// `None` when it is gone already.
pub async fn delete_by_id(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    id: i64,
    grace: chrono::Duration,
) -> sqlx::Result<Option<DeletedFile>> {
    let Some(sha) = sqlx::query_scalar!(
        "DELETE FROM raw_file WHERE repository_id = $1 AND id = $2 RETURNING blob_sha256",
        repository_id,
        id,
    )
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(None);
    };
    let enqueued = blob_dao::decref_and_maybe_enqueue_delete(tx, &sha, grace).await?;
    let ref_count_after = sqlx::query_scalar!("SELECT ref_count FROM blob WHERE sha256 = $1", sha)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(Some(DeletedFile {
        blob_sha256: sha,
        ref_count_after,
        delete_enqueued: enqueued,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_is_a_range() {
        assert_eq!(prefix_range(""), (String::new(), None));
        assert_eq!(
            prefix_range("a/b/"),
            ("a/b/".to_string(), Some("a/b0".to_string()))
        );
        // Every path below `a/b/` sorts inside the range, its siblings outside.
        let (lower, upper) = prefix_range("a/b/");
        let upper = upper.unwrap();
        for inside in ["a/b/c", "a/b/c/d", "a/b/~", "a/b/\u{10ffff}"] {
            assert!(
                inside >= lower.as_str() && inside < upper.as_str(),
                "{inside}"
            );
        }
        for outside in ["a/b", "a/b!", "a/b-c", "a/b0", "a/ba", "a/c"] {
            assert!(
                !(outside >= lower.as_str() && outside < upper.as_str()),
                "{outside}"
            );
        }
    }
}
