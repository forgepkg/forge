//! Data access for imports into hosted repositories (`repository_import`,
//! `repository_import_item`): an import's job row, its scan cursor and lease,
//! and the items it found.
//!
//! An import runs on one instance at a time: the worker claims a queued (or
//! abandoned) import with `FOR UPDATE SKIP LOCKED` and holds it with a
//! `run_id` / `locked_until` lease it renews while it works, like the
//! retention worker. Every write the worker makes to the job row is fenced
//! on its `run_id`, so an instance whose lease expired cannot overwrite the
//! progress of the one that took over.
//!
//! The source's password is not read or written here: it is a secret column of
//! [`crate::secret_dao`] ([`crate::secret_dao::set_import_password`]).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::Value as JsonValue;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
use uuid::Uuid;

/// An import job, without its password.
#[derive(Debug, Clone, Serialize)]
pub struct RepositoryImport {
    pub id: i64,
    pub repository_id: i64,
    /// The source: a NuGet service index or a registry. For an import stored
    /// before 2.2, the Nexus server that `source_repository` names a
    /// repository of.
    pub url: String,
    /// The Nexus repository of an import stored before 2.2; `None` since.
    pub source_repository: Option<String>,
    /// The registry API of a Docker import stored before 2.2.
    pub registry_url: Option<String>,
    /// The package ids or images the import copies; `None`: whatever the
    /// source's search (or catalog) finds.
    pub names: Option<Vec<String>>,
    pub username: Option<String>,
    /// Whether a password is stored.
    pub has_password: bool,
    /// `skip`, `overwrite` or `fail`.
    pub on_conflict: String,
    pub concurrency: i32,
    pub dry_run: bool,
    /// `queued`, `running`, `cancelled`, `failed` or `completed`.
    pub state: String,
    /// `scan` or `copy`.
    pub phase: String,
    /// What the scan walks: `search`, `catalog` or `names`.
    pub scan_listing: String,
    #[serde(skip)]
    pub cursor: Option<String>,
    pub cancel_requested: bool,
    /// The `Server` header the source answered the preflight with.
    pub source_server: Option<String>,
    /// How many packages the feed's search found: what it reported in the
    /// preflight, or as many as the scan walked, whichever is more.
    pub source_total: Option<i64>,
    pub last_error: Option<String>,
    pub created_by: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

impl RepositoryImport {
    /// Whether the import waits for, or is held by, a worker.
    pub fn is_active(&self) -> bool {
        matches!(self.state.as_str(), "queued" | "running")
    }
}

/// A new import.
pub struct NewImport<'a> {
    pub repository_id: i64,
    pub url: &'a str,
    pub names: Option<&'a [String]>,
    pub username: Option<&'a str>,
    pub on_conflict: &'a str,
    pub concurrency: i32,
    pub dry_run: bool,
    /// Where the scan starts: `search`, `catalog` or `names`.
    pub scan_listing: &'a str,
    pub source_server: Option<&'a str>,
    pub source_total: Option<i64>,
    pub created_by: Option<i64>,
}

/// Insert a queued import and return its id. Fails with a unique violation
/// while the repository has another queued or running import.
pub async fn insert<'e, E>(executor: E, new: NewImport<'_>) -> sqlx::Result<i64>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar!(
        r#"
        INSERT INTO repository_import
            (repository_id, url, names, username, on_conflict, concurrency, dry_run,
             scan_listing, source_server, source_total, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id
        "#,
        new.repository_id,
        new.url,
        new.names,
        new.username,
        new.on_conflict,
        new.concurrency,
        new.dry_run,
        new.scan_listing,
        new.source_server,
        new.source_total,
        new.created_by,
    )
    .fetch_one(executor)
    .await
}

/// The import `id`.
pub async fn get<'e, E>(executor: E, id: i64) -> sqlx::Result<Option<RepositoryImport>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        RepositoryImport,
        r#"
        SELECT id, repository_id, url, source_repository, registry_url, names, username,
               (password_enc IS NOT NULL) AS "has_password!",
               on_conflict, concurrency, dry_run, state, phase, scan_listing, cursor,
               cancel_requested, source_server, source_total,
               last_error, created_by, created_at, started_at, finished_at, updated_at
        FROM repository_import
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(executor)
    .await
}

/// A repository's imports, newest first.
pub async fn list(
    pool: &PgPool,
    repository_id: i64,
    limit: i64,
) -> sqlx::Result<Vec<RepositoryImport>> {
    sqlx::query_as!(
        RepositoryImport,
        r#"
        SELECT id, repository_id, url, source_repository, registry_url, names, username,
               (password_enc IS NOT NULL) AS "has_password!",
               on_conflict, concurrency, dry_run, state, phase, scan_listing, cursor,
               cancel_requested, source_server, source_total,
               last_error, created_by, created_at, started_at, finished_at, updated_at
        FROM repository_import
        WHERE repository_id = $1
        ORDER BY id DESC
        LIMIT $2
        "#,
        repository_id,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// Item totals of one state.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct StateCount {
    /// Items in the state.
    pub items: i64,
    /// Their size at the source, where it says.
    pub size: i64,
    /// Bytes copied for them.
    pub bytes_copied: i64,
}

/// An import's items, counted by state.
pub async fn counts(pool: &PgPool, import_id: i64) -> sqlx::Result<HashMap<String, StateCount>> {
    let rows = sqlx::query!(
        r#"
        SELECT state,
               count(*) AS "items!",
               coalesce(sum(size), 0)::bigint AS "size!",
               coalesce(sum(bytes_copied), 0)::bigint AS "bytes_copied!"
        FROM repository_import_item
        WHERE import_id = $1
        GROUP BY state
        "#,
        import_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.state,
                StateCount {
                    items: r.items,
                    size: r.size,
                    bytes_copied: r.bytes_copied,
                },
            )
        })
        .collect())
}

// ── The worker's lease ──────────────────────────────────────────────────────

/// Claim the oldest import that is queued, or running under a lease that
/// expired (its instance died), and lease it until `now + lease` under a
/// fresh `run_id`.
pub async fn claim_next(
    tx: &mut Transaction<'_, Postgres>,
    now: DateTime<Utc>,
    lease: Duration,
) -> sqlx::Result<Option<(RepositoryImport, Uuid)>> {
    let run_id = Uuid::new_v4();
    let id = sqlx::query_scalar!(
        r#"
        WITH due AS (
            SELECT id FROM repository_import
            WHERE state IN ('queued', 'running')
              AND (locked_until IS NULL OR locked_until < $1)
            ORDER BY id
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE repository_import i
        SET state = 'running',
            run_id = $2,
            locked_until = $1 + make_interval(secs => $3),
            started_at = coalesce(i.started_at, $1),
            updated_at = $1
        FROM due
        WHERE i.id = due.id
        RETURNING i.id
        "#,
        now,
        run_id,
        lease.num_seconds() as f64,
    )
    .fetch_optional(&mut **tx)
    .await?;
    let Some(id) = id else {
        return Ok(None);
    };
    Ok(get(&mut **tx, id).await?.map(|import| (import, run_id)))
}

/// Extend the lease of `run_id` to `until`. `false` once the lease is lost.
pub async fn renew_lease(
    pool: &PgPool,
    id: i64,
    run_id: Uuid,
    until: DateTime<Utc>,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        UPDATE repository_import SET locked_until = $3
        WHERE id = $1 AND run_id = $2 AND state = 'running'
        "#,
        id,
        run_id,
        until,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Whether `run_id` still holds the import, and whether an administrator
/// asked to cancel it. `None` once the lease is lost.
pub async fn poll(pool: &PgPool, id: i64, run_id: Uuid) -> sqlx::Result<Option<bool>> {
    sqlx::query_scalar!(
        r#"
        SELECT cancel_requested FROM repository_import
        WHERE id = $1 AND run_id = $2 AND state = 'running'
        "#,
        id,
        run_id,
    )
    .fetch_optional(pool)
    .await
}

/// Record a scanned page: where the scan continues (`cursor`), whether it
/// moves on to copying, and, for a search, how many packages it has walked
/// (`walked`, which raises `source_total`). Fenced on `run_id`; returns
/// whether the lease was still held.
pub async fn save_scan_page(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    run_id: Uuid,
    cursor: Option<&str>,
    phase: &str,
    walked: Option<i64>,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        UPDATE repository_import
        SET cursor = $3, phase = $4,
            source_total = CASE WHEN $5::bigint IS NULL THEN source_total
                                ELSE greatest(coalesce(source_total, 0), $5) END,
            updated_at = now()
        WHERE id = $1 AND run_id = $2 AND state = 'running'
        "#,
        id,
        run_id,
        cursor,
        phase,
        walked,
    )
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// End the run of `run_id` in `state` (`completed`, `failed` or
/// `cancelled`) and release the lease. A completed import's password is
/// deleted; a cancelled or failed one keeps it, to be resumed. Returns
/// whether the lease was still held.
pub async fn finish(
    pool: &PgPool,
    id: i64,
    run_id: Uuid,
    state: &str,
    error: Option<&str>,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        UPDATE repository_import
        SET state = $3,
            last_error = $4,
            finished_at = now(),
            updated_at = now(),
            run_id = NULL,
            locked_until = NULL,
            cancel_requested = false,
            password_enc = CASE WHEN $3 = 'completed' THEN NULL ELSE password_enc END
        WHERE id = $1 AND run_id = $2 AND state = 'running'
        "#,
        id,
        run_id,
        state,
        error,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

// ── Administrator actions ───────────────────────────────────────────────────

/// Cancel an import: a queued one at once, a running one at its worker's
/// next check. Returns the import as it is now, `None` if there is none.
pub async fn cancel(pool: &PgPool, id: i64) -> sqlx::Result<Option<RepositoryImport>> {
    sqlx::query!(
        r#"
        UPDATE repository_import
        SET state = CASE WHEN state = 'queued' THEN 'cancelled' ELSE state END,
            finished_at = CASE WHEN state = 'queued' THEN now() ELSE finished_at END,
            cancel_requested = (state = 'running'),
            updated_at = now()
        WHERE id = $1 AND state IN ('queued', 'running')
        "#,
        id,
    )
    .execute(pool)
    .await?;
    get(pool, id).await
}

/// Queue a stopped import again, in `tx`: resume a cancelled or failed one
/// where it stopped and, with `retry`, put its failed items (all, or the
/// ids in `only`) back to pending. Returns how many items will be retried,
/// or `None` when the import is not stopped (or is gone, or another import
/// of the repository is active).
pub async fn requeue(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    retry: bool,
    only: Option<&[i64]>,
) -> sqlx::Result<Option<u64>> {
    let queued = sqlx::query!(
        r#"
        UPDATE repository_import i
        SET state = 'queued', run_id = NULL, locked_until = NULL, finished_at = NULL,
            last_error = NULL, cancel_requested = false, updated_at = now()
        WHERE id = $1 AND state IN ('cancelled', 'failed', 'completed')
          AND NOT EXISTS (
              SELECT 1 FROM repository_import o
              WHERE o.repository_id = i.repository_id AND o.id <> i.id
                AND o.state IN ('queued', 'running')
          )
        "#,
        id,
    )
    .execute(&mut **tx)
    .await?;
    if queued.rows_affected() == 0 {
        return Ok(None);
    }
    if !retry {
        return Ok(Some(0));
    }
    let retried = sqlx::query!(
        r#"
        UPDATE repository_import_item
        SET state = 'pending', detail = NULL, updated_at = now()
        WHERE import_id = $1 AND state = 'failed'
          AND ($2::bigint[] IS NULL OR id = ANY($2))
        "#,
        id,
        only,
    )
    .execute(&mut **tx)
    .await?;
    Ok(Some(retried.rows_affected()))
}

/// Delete a stopped import, its items and its password. `false` when it is
/// active or gone.
pub async fn delete(pool: &PgPool, id: i64) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"DELETE FROM repository_import WHERE id = $1 AND state NOT IN ('queued', 'running')"#,
        id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

// ── Items ───────────────────────────────────────────────────────────────────

/// One item of an import.
#[derive(Debug, Clone, Serialize)]
pub struct ImportItem {
    pub id: i64,
    #[serde(skip)]
    pub import_id: i64,
    /// `component` or `manifest`.
    pub kind: String,
    pub name: String,
    pub version: String,
    pub state: String,
    pub detail: Option<String>,
    pub size: Option<i64>,
    pub bytes_copied: i64,
    pub published_at: Option<DateTime<Utc>>,
    pub downloaded_at: Option<DateTime<Utc>>,
    pub uploader: Option<String>,
    #[serde(skip)]
    pub source: JsonValue,
    pub attempts: i32,
    pub updated_at: DateTime<Utc>,
}

/// An item found by the scan.
pub struct NewItem<'a> {
    pub kind: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub size: Option<i64>,
    pub published_at: Option<DateTime<Utc>>,
    pub downloaded_at: Option<DateTime<Utc>>,
    pub uploader: Option<&'a str>,
    pub source: &'a JsonValue,
}

/// Record the items of a scanned page as pending. An item already recorded
/// (a page scanned again after a restart) is left as it is.
pub async fn insert_items(
    tx: &mut Transaction<'_, Postgres>,
    import_id: i64,
    items: &[NewItem<'_>],
) -> sqlx::Result<()> {
    for item in items {
        sqlx::query!(
            r#"
            INSERT INTO repository_import_item
                (import_id, kind, name, version, size, published_at, downloaded_at,
                 uploader, source)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (import_id, kind, name, version) DO NOTHING
            "#,
            import_id,
            item.kind,
            item.name,
            item.version,
            item.size,
            item.published_at,
            item.downloaded_at,
            item.uploader,
            item.source,
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Up to `limit` pending items of `kind` after item `after_id`, in the order
/// they were found.
pub async fn pending_items(
    pool: &PgPool,
    import_id: i64,
    kind: &str,
    after_id: i64,
    limit: i64,
) -> sqlx::Result<Vec<ImportItem>> {
    sqlx::query_as!(
        ImportItem,
        r#"
        SELECT id, import_id, kind, name, version, state, detail, size, bytes_copied,
               published_at, downloaded_at, uploader, source, attempts, updated_at
        FROM repository_import_item
        WHERE import_id = $1 AND kind = $2 AND state = 'pending' AND id > $3
        ORDER BY id
        LIMIT $4
        "#,
        import_id,
        kind,
        after_id,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// Record what became of an item.
pub async fn finish_item(
    pool: &PgPool,
    item_id: i64,
    state: &str,
    detail: Option<&str>,
    bytes_copied: i64,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE repository_import_item
        SET state = $2, detail = $3, bytes_copied = bytes_copied + $4,
            attempts = attempts + 1, updated_at = now()
        WHERE id = $1
        "#,
        item_id,
        state,
        detail,
        bytes_copied,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Forget an item: a manifest the source holds by digest that turned out not
/// to be a referrer of an imported image.
pub async fn drop_item(pool: &PgPool, item_id: i64) -> sqlx::Result<()> {
    sqlx::query!("DELETE FROM repository_import_item WHERE id = $1", item_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// A page of an import's items, in the order they were found, optionally of
/// one state.
pub async fn list_items(
    pool: &PgPool,
    import_id: i64,
    state: Option<&str>,
    after_id: i64,
    limit: i64,
) -> sqlx::Result<Vec<ImportItem>> {
    sqlx::query_as!(
        ImportItem,
        r#"
        SELECT id, import_id, kind, name, version, state, detail, size, bytes_copied,
               published_at, downloaded_at, uploader, source, attempts, updated_at
        FROM repository_import_item
        WHERE import_id = $1 AND ($2::text IS NULL OR state = $2) AND id > $3
        ORDER BY id
        LIMIT $4
        "#,
        import_id,
        state,
        after_id,
        limit,
    )
    .fetch_all(pool)
    .await
}
