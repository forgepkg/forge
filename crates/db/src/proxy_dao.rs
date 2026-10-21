//! Data access for `proxy_cached_version` and `proxy_upstream_index`.

use serde_json::Value as JsonValue;
use sqlx::{PgPool, Postgres, Transaction};

use crate::model::{ProxyCachedVersion, ProxyUpstreamIndex};

/// All settable fields when creating a proxy cached-version row.
#[derive(Debug, Clone)]
pub struct NewProxyCachedVersion {
    pub repository_id: i64,
    pub name: String,
    pub version: String,
    pub listed: bool,
    pub downloaded: bool,
    pub not_found: bool,
}

/// Insert a cached-version marker, ignoring conflicts on the
/// `(repository_id, name, version)` unique key. Returns `true` if a new row was
/// inserted, `false` if it already existed.
pub async fn upsert_cached_version(
    pool: &PgPool,
    new: NewProxyCachedVersion,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"
        INSERT INTO proxy_cached_version (
            repository_id, name, version, listed, downloaded, not_found
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (repository_id, name, version) DO NOTHING
        "#,
        new.repository_id,
        new.name,
        new.version,
        new.listed,
        new.downloaded,
        new.not_found,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Record every upstream-listed `versions` of `name` in one round-trip.
///
/// A first sighting inserts a confirmed row stamped `first_seen_at = now()`.
/// The upstream listing is authoritative that each version exists, so an
/// existing row that is still **unconfirmed** (created by a download attempt
/// for a version the upstream did not have yet) or carries a **not-found
/// marker** is revived: the marker is cleared and the row confirmed — an
/// unconfirmed row also restarts `first_seen_at`, because this is the version's
/// first real sighting (a row planted early by a request must not shorten the
/// package-delay window). Already-confirmed rows keep their `first_seen_at` and
/// are not rewritten. Duplicates in `versions` are ignored. Returns the number
/// of rows inserted or revived.
pub async fn upsert_cached_versions(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    versions: &[String],
) -> sqlx::Result<u64> {
    if versions.is_empty() {
        return Ok(0);
    }
    let res = sqlx::query!(
        r#"
        INSERT INTO proxy_cached_version (
            repository_id, name, version, listed, downloaded, not_found, metadata_refreshed_at,
            confirmed
        )
        SELECT $1, $2, v, true, false, false, now(), true
        FROM (SELECT DISTINCT v FROM unnest($3::text[]) AS t(v)) AS d
        ON CONFLICT (repository_id, name, version) DO UPDATE
        SET not_found = false,
            not_found_at = NULL,
            first_seen_at = CASE
                WHEN proxy_cached_version.confirmed THEN proxy_cached_version.first_seen_at
                ELSE now()
            END,
            confirmed = true,
            upstream_missing = false,
            missing_since = NULL,
            metadata_refreshed_at = now()
        WHERE proxy_cached_version.not_found
           OR NOT proxy_cached_version.confirmed
           OR proxy_cached_version.upstream_missing
           OR proxy_cached_version.missing_since IS NOT NULL
        "#,
        repository_id,
        name,
        versions,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Reconcile `name`'s confirmed rows with a successful upstream listing of
/// `versions`: a version the listing no longer names is flagged
/// `upstream_missing` (no longer enumerated — it was deleted upstream), one it
/// names again is un-flagged, and the package-level negative-cache marker
/// (`version = '*'`) is dropped, since the package evidently exists. Returns
/// how many rows changed.
///
/// A version is flagged only once it is missing from a listing at least
/// `confirm_after_secs` (the metadata TTL) after the first listing that left
/// it out (`missing_since`): an upstream may serve a partial listing during
/// an incident, such as a Forge group with one member down, and one such
/// listing must not hide the versions for a whole TTL.
pub async fn reconcile_listing(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    versions: &[String],
    confirm_after_secs: i64,
) -> sqlx::Result<u64> {
    let mut tx = pool.begin().await?;
    let flagged = sqlx::query!(
        r#"
        WITH seen AS (
            SELECT id,
                   CASE WHEN version = ANY($3::text[]) THEN NULL
                        ELSE coalesce(missing_since, now()) END AS missing_since
            FROM proxy_cached_version
            WHERE repository_id = $1 AND name = $2 AND version <> '*' AND confirmed
        ), next AS (
            SELECT id, missing_since,
                   coalesce(missing_since <= now() - make_interval(secs => $4), false)
                       AS upstream_missing
            FROM seen
        )
        UPDATE proxy_cached_version p
        SET missing_since = next.missing_since,
            upstream_missing = next.upstream_missing
        FROM next
        WHERE p.id = next.id
          AND (p.missing_since IS DISTINCT FROM next.missing_since
               OR p.upstream_missing IS DISTINCT FROM next.upstream_missing)
        "#,
        repository_id,
        name,
        versions,
        confirm_after_secs as f64,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let cleared = clear_package_marker(&mut tx, repository_id, name).await?;
    tx.commit().await?;
    Ok(flagged + cleared)
}

/// Drop the package-level negative-cache marker (`version = '*'`) of `name`.
pub async fn clear_package_marker(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    name: &str,
) -> sqlx::Result<u64> {
    Ok(sqlx::query!(
        r#"DELETE FROM proxy_cached_version WHERE repository_id = $1 AND name = $2 AND version = '*'"#,
        repository_id,
        name,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected())
}

/// Guarantee a row exists for a version a client asked to download, so the
/// download singleflight can lock it. A new row is **unconfirmed**: it is never
/// enumerated until an upstream listing or a successful download confirms the
/// version (see [`upsert_cached_versions`], [`mark_downloaded`]), so a request
/// for a version that does not exist — or whose fetch fails — cannot create a
/// phantom version. An existing row is left untouched.
pub async fn insert_unconfirmed_cached_version(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO proxy_cached_version (
            repository_id, name, version, listed, downloaded, not_found, confirmed
        )
        VALUES ($1, $2, $3, true, false, false, false)
        ON CONFLICT (repository_id, name, version) DO NOTHING
        "#,
        repository_id,
        name,
        version,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete up to `limit` cached-version rows that neither an upstream listing
/// nor a successful download ever confirmed — rows a download attempt created
/// for a version the upstream never served — once their repository's
/// negative-cache window (`not_found_ttl_seconds`, else `default_ttl_seconds`)
/// has lapsed. Any reader can create such a row by requesting an arbitrary
/// version, so without this they would accumulate forever. Returns how many
/// rows were removed.
///
/// The `confirmed`/`downloaded` conditions are repeated on the outer `DELETE`
/// so a row a concurrent download confirms meanwhile is re-checked after its
/// lock is released and kept. A download that is still fetching holds no lock,
/// so its row can go; it is created again when that download finalizes
/// ([`lock_or_insert_cached_version`]).
pub async fn prune_unconfirmed(
    pool: &PgPool,
    default_ttl_seconds: i64,
    limit: i64,
) -> sqlx::Result<u64> {
    let result = sqlx::query!(
        r#"
        DELETE FROM proxy_cached_version
        WHERE id = ANY(ARRAY(
                SELECT v.id
                FROM proxy_cached_version v
                JOIN repository r ON r.id = v.repository_id
                WHERE NOT v.confirmed
                  AND NOT v.downloaded
                  AND COALESCE(v.not_found_at, v.first_seen_at)
                      < now() - make_interval(
                            secs => COALESCE(r.not_found_ttl_seconds::bigint, $1::bigint)::double precision
                        )
                LIMIT $2
            ))
          AND NOT confirmed
          AND NOT downloaded
        "#,
        default_ttl_seconds,
        limit,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Lock every cached-version row of a repository (`FOR UPDATE`, in id order),
/// waiting for an in-flight first download or cache eviction that holds one.
/// A repository delete takes these **before** the repository row: those
/// writers hold a cached version and then need the repository row (the
/// foreign-key lock of the component they insert), so taking the repository
/// row first deadlocks with them.
pub async fn lock_cached_versions<'e, E>(executor: E, repository_id: i64) -> sqlx::Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        r#"
        SELECT id FROM proxy_cached_version
        WHERE repository_id = $1
        ORDER BY id
        FOR UPDATE
        "#,
        repository_id,
    )
    .fetch_all(executor)
    .await?;
    Ok(())
}

/// Forget what a proxy learned from its previous upstream, inside the
/// transaction that changes its `remote_url`. Versions that were never
/// downloaded (listing rows and the not-found markers, including the
/// package-level `*` markers) are deleted, so the new upstream's listings start
/// fresh rows and its versions wait out the package delay from their own first
/// sighting. Downloaded versions stay cached, with their not-found and
/// missing-upstream flags cleared and their metadata due for a refresh from
/// the new upstream. Returns the number of deleted rows.
pub async fn reset_for_new_upstream(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
) -> sqlx::Result<u64> {
    let deleted = sqlx::query!(
        r#"
        DELETE FROM proxy_cached_version
        WHERE repository_id = $1 AND NOT downloaded
        "#,
        repository_id,
    )
    .execute(&mut **tx)
    .await?
    .rows_affected();
    sqlx::query!(
        r#"
        UPDATE proxy_cached_version
        SET not_found = false,
            not_found_at = NULL,
            upstream_missing = false,
            missing_since = NULL,
            metadata_refreshed_at = NULL
        WHERE repository_id = $1
        "#,
        repository_id,
    )
    .execute(&mut **tx)
    .await?;
    Ok(deleted)
}

/// Finalize a successful download of the row `id` inside the caller's
/// transaction: mark it downloaded, clear any not-found marker and confirm it.
/// A row confirmed only now (it was created by the download singleflight)
/// restarts `first_seen_at`, exactly like a first listing sighting. Returns the
/// row's resulting `first_seen_at` for the package-delay gate.
pub async fn mark_downloaded(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
) -> sqlx::Result<chrono::DateTime<chrono::Utc>> {
    sqlx::query_scalar!(
        r#"
        UPDATE proxy_cached_version
        SET downloaded = true,
            not_found = false,
            not_found_at = NULL,
            first_seen_at = CASE WHEN confirmed THEN first_seen_at ELSE now() END,
            confirmed = true
        WHERE id = $1
        RETURNING first_seen_at
        "#,
        id,
    )
    .fetch_one(&mut **tx)
    .await
}

/// Clear `downloaded` on the row `id` because its local copy is gone (e.g.
/// retention deleted the component), so the next fetch re-attaches fresh
/// assets. `first_seen_at` and the confirmation are kept: the version stays
/// listed and its package-delay window does not restart.
pub async fn mark_not_downloaded(pool: &PgPool, id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        r#"UPDATE proxy_cached_version SET downloaded = false WHERE id = $1 AND downloaded"#,
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Store the upstream listing state (`listed`, from the upstream registration)
/// of `name`'s `versions` in one round-trip and stamp
/// `metadata_refreshed_at`. `versions` and `listed` are parallel slices.
pub async fn set_listed(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    versions: &[String],
    listed: &[bool],
) -> sqlx::Result<u64> {
    if versions.is_empty() {
        return Ok(0);
    }
    let res = sqlx::query!(
        r#"
        UPDATE proxy_cached_version AS p
        SET listed = c.listed, metadata_refreshed_at = now()
        FROM unnest($3::text[], $4::bool[]) AS c(version, listed)
        WHERE p.repository_id = $1 AND p.name = $2 AND p.version = c.version
          AND p.listed IS DISTINCT FROM c.listed
        "#,
        repository_id,
        name,
        versions,
        listed,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Fetch a cached-version row by its unique key.
pub async fn get_cached_version(
    pool: &PgPool,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<Option<ProxyCachedVersion>> {
    sqlx::query_as!(
        ProxyCachedVersion,
        r#"
        SELECT
            id, repository_id, name, version, listed, first_seen_at,
            downloaded, metadata_refreshed_at, not_found, not_found_at
        FROM proxy_cached_version
        WHERE repository_id = $1 AND name = $2 AND version = $3
        "#,
        repository_id,
        name,
        version,
    )
    .fetch_optional(pool)
    .await
}

/// Singleflight helper: lock a cached-version row `FOR UPDATE` inside the
/// caller's transaction so only one worker proceeds to fetch/download the
/// artifact while others block on the row lock. Returns the locked row, or
/// `None` if it does not exist yet (caller should `upsert_cached_version` first,
/// then call this).
pub async fn lock_cached_version_for_update(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<Option<ProxyCachedVersion>> {
    sqlx::query_as!(
        ProxyCachedVersion,
        r#"
        SELECT
            id, repository_id, name, version, listed, first_seen_at,
            downloaded, metadata_refreshed_at, not_found, not_found_at
        FROM proxy_cached_version
        WHERE repository_id = $1 AND name = $2 AND version = $3
        FOR UPDATE
        "#,
        repository_id,
        name,
        version,
    )
    .fetch_optional(&mut **tx)
    .await
}

/// [`lock_cached_version_for_update`] for the download singleflight, which
/// holds no lock while it fetches: when the row is gone because
/// [`prune_unconfirmed`] deleted it meanwhile (it was still unconfirmed), it
/// is created again, unconfirmed (see [`insert_unconfirmed_cached_version`]),
/// and locked, so the download can still finish.
pub async fn lock_or_insert_cached_version(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: i64,
    name: &str,
    version: &str,
) -> sqlx::Result<ProxyCachedVersion> {
    if let Some(row) = lock_cached_version_for_update(tx, repository_id, name, version).await? {
        return Ok(row);
    }
    // `DO UPDATE` (a no-op) rather than `DO NOTHING`: it locks and returns a
    // row a concurrent caller created first, so one statement always yields
    // a locked row.
    sqlx::query_as!(
        ProxyCachedVersion,
        r#"
        INSERT INTO proxy_cached_version (
            repository_id, name, version, listed, downloaded, not_found, confirmed
        )
        VALUES ($1, $2, $3, true, false, false, false)
        ON CONFLICT (repository_id, name, version)
        DO UPDATE SET listed = proxy_cached_version.listed
        RETURNING
            id, repository_id, name, version, listed, first_seen_at,
            downloaded, metadata_refreshed_at, not_found, not_found_at
        "#,
        repository_id,
        name,
        version,
    )
    .fetch_one(&mut **tx)
    .await
}

/// Fetch the upstream service index for a proxy repository.
pub async fn get_upstream_index(
    pool: &PgPool,
    repository_id: i64,
) -> sqlx::Result<Option<ProxyUpstreamIndex>> {
    sqlx::query_as!(
        ProxyUpstreamIndex,
        r#"
        SELECT repository_id, resources, fetched_at, etag
        FROM proxy_upstream_index
        WHERE repository_id = $1
        "#,
        repository_id,
    )
    .fetch_optional(pool)
    .await
}

/// Insert or replace the upstream service index for a proxy repository.
/// `fetched_at` is set to `now()`.
pub async fn set_upstream_index(
    pool: &PgPool,
    repository_id: i64,
    resources: JsonValue,
    etag: Option<&str>,
) -> sqlx::Result<ProxyUpstreamIndex> {
    sqlx::query_as!(
        ProxyUpstreamIndex,
        r#"
        INSERT INTO proxy_upstream_index (repository_id, resources, fetched_at, etag)
        VALUES ($1, $2, now(), $3)
        ON CONFLICT (repository_id)
        DO UPDATE SET resources = EXCLUDED.resources,
                      fetched_at = EXCLUDED.fetched_at,
                      etag = EXCLUDED.etag
        RETURNING repository_id, resources, fetched_at, etag
        "#,
        repository_id,
        resources,
        etag,
    )
    .fetch_one(pool)
    .await
}
