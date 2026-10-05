//! Data access for `repository` and `group_member`.

use serde_json::Value as JsonValue;
use sqlx::{Acquire, PgPool};

use crate::model::Repository;

/// All settable fields when creating a repository row.
///
/// Server-managed columns (`id`, `created_at`, `updated_at`) are not included.
#[derive(Debug, Clone)]
pub struct NewRepository {
    pub name: String,
    pub format: String,
    pub kind: String,
    pub anonymous_read: bool,
    pub online: bool,
    pub config: JsonValue,
    pub remote_url: Option<String>,
    pub package_delay_seconds: i32,
    pub upstream_username: Option<String>,
    /// **Plaintext** upstream password — the legacy (crypto-disabled) write
    /// path only. With encryption at rest enabled (slice 12.5) callers insert
    /// with `None` here and store the secret afterwards via
    /// [`crate::secret_dao::set_upstream_password`], which seals it under the
    /// row-bound AAD (the row id does not exist before the INSERT).
    pub upstream_password: Option<String>,
    pub metadata_ttl_seconds: Option<i32>,
    pub not_found_ttl_seconds: Option<i32>,
    pub allow_redeploy: bool,
}

impl NewRepository {
    /// Convenience constructor for a hosted repository with default options.
    pub fn hosted(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            format: "nuget".to_string(),
            kind: "hosted".to_string(),
            anonymous_read: false,
            online: true,
            config: JsonValue::Object(Default::default()),
            remote_url: None,
            package_delay_seconds: 0,
            upstream_username: None,
            upstream_password: None,
            metadata_ttl_seconds: None,
            not_found_ttl_seconds: None,
            allow_redeploy: false,
        }
    }

    /// Convenience constructor for a group repository.
    pub fn group(name: impl Into<String>) -> Self {
        Self {
            kind: "group".to_string(),
            ..Self::hosted(name)
        }
    }

    /// Convenience constructor for a proxy repository with default options.
    pub fn proxy(name: impl Into<String>) -> Self {
        Self {
            kind: "proxy".to_string(),
            ..Self::hosted(name)
        }
    }
}

/// Insert a repository, returning the full persisted row.
/// Accepts any executor so it composes with other writes in one transaction.
pub async fn insert_repository<'e, E>(executor: E, new: NewRepository) -> sqlx::Result<Repository>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        Repository,
        r#"
        INSERT INTO repository (
            name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            metadata_ttl_seconds, not_found_ttl_seconds, allow_redeploy
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING
            id, name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            upstream_password_enc, metadata_ttl_seconds, not_found_ttl_seconds,
            allow_redeploy, created_at, updated_at
        "#,
        new.name,
        new.format,
        new.kind,
        new.anonymous_read,
        new.online,
        new.config,
        new.remote_url,
        new.package_delay_seconds,
        new.upstream_username,
        new.upstream_password,
        new.metadata_ttl_seconds,
        new.not_found_ttl_seconds,
        new.allow_redeploy,
    )
    .fetch_one(executor)
    .await
}

/// Find a repository by its unique name.
pub async fn find_repository_by_name(
    pool: &PgPool,
    name: &str,
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
        WHERE name = $1
        "#,
        name,
    )
    .fetch_optional(pool)
    .await
}

/// Find a repository by id.
pub async fn find_repository_by_id(pool: &PgPool, id: i64) -> sqlx::Result<Option<Repository>> {
    sqlx::query_as!(
        Repository,
        r#"
        SELECT
            id, name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            upstream_password_enc, metadata_ttl_seconds, not_found_ttl_seconds,
            allow_redeploy, created_at, updated_at
        FROM repository
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

/// List all repositories ordered by name.
pub async fn list_repositories(pool: &PgPool) -> sqlx::Result<Vec<Repository>> {
    sqlx::query_as!(
        Repository,
        r#"
        SELECT
            id, name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            upstream_password_enc, metadata_ttl_seconds, not_found_ttl_seconds,
            allow_redeploy, created_at, updated_at
        FROM repository
        ORDER BY name
        "#,
    )
    .fetch_all(pool)
    .await
}

/// The members of `group_id` flagged as owners of its package ids
/// (`group_member.owner`); empty when none is (every hosted member owns).
pub async fn group_owner_ids(pool: &PgPool, group_id: i64) -> sqlx::Result<Vec<i64>> {
    sqlx::query_scalar!(
        r#"SELECT member_id FROM group_member WHERE group_id = $1 AND owner ORDER BY member_id"#,
        group_id,
    )
    .fetch_all(pool)
    .await
}

/// Lock every membership of `member_id` (`FOR UPDATE`) and return the names
/// of the groups it is flagged as an owner in. Run it in the transaction that
/// deletes the repository, after [`lock_repository`]: a concurrent owner flag
/// then waits for the delete (and finds no membership) instead of landing
/// between this check and the cascade.
pub async fn lock_memberships_for_delete<'e, E>(
    executor: E,
    member_id: i64,
) -> sqlx::Result<Vec<String>>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query!(
        r#"
        SELECT g.name, gm.owner
        FROM group_member gm
        JOIN repository g ON g.id = gm.group_id
        WHERE gm.member_id = $1
        ORDER BY g.name
        FOR UPDATE OF gm
        "#,
        member_id,
    )
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .filter(|row| row.owner)
        .map(|row| row.name)
        .collect())
}

/// Flag (or unflag) `member_id` as an owner of `group_id`'s package ids.
/// Returns whether that membership exists.
pub async fn set_group_member_owner(
    pool: &PgPool,
    group_id: i64,
    member_id: i64,
    owner: bool,
) -> sqlx::Result<bool> {
    let result = sqlx::query!(
        r#"UPDATE group_member SET owner = $3 WHERE group_id = $1 AND member_id = $2"#,
        group_id,
        member_id,
        owner,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Return the members of a group joined to their repository rows, ordered by
/// `priority` **descending** so the highest-priority member (which wins ties per
/// spec §7) comes first.
pub async fn group_members(pool: &PgPool, group_id: i64) -> sqlx::Result<Vec<(Repository, i32)>> {
    let rows = sqlx::query!(
        r#"
        SELECT
            r.id, r.name, r.format, r.kind, r.anonymous_read, r.online, r.config,
            r.remote_url, r.package_delay_seconds, r.upstream_username, r.upstream_password,
            r.upstream_password_enc, r.metadata_ttl_seconds, r.not_found_ttl_seconds,
            r.allow_redeploy, r.created_at, r.updated_at,
            gm.priority
        FROM group_member gm
        JOIN repository r ON r.id = gm.member_id
        WHERE gm.group_id = $1
        ORDER BY gm.priority DESC
        "#,
        group_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            (
                Repository {
                    id: row.id,
                    name: row.name,
                    format: row.format,
                    kind: row.kind,
                    anonymous_read: row.anonymous_read,
                    online: row.online,
                    config: row.config,
                    remote_url: row.remote_url,
                    package_delay_seconds: row.package_delay_seconds,
                    upstream_username: row.upstream_username,
                    upstream_password: row.upstream_password,
                    upstream_password_enc: row.upstream_password_enc,
                    metadata_ttl_seconds: row.metadata_ttl_seconds,
                    not_found_ttl_seconds: row.not_found_ttl_seconds,
                    allow_redeploy: row.allow_redeploy,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                },
                row.priority,
            )
        })
        .collect())
}

/// Add a member to a group with the given priority (unique per group).
pub async fn add_group_member(
    pool: &PgPool,
    group_id: i64,
    member_id: i64,
    priority: i32,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO group_member (group_id, member_id, priority)
        VALUES ($1, $2, $3)
        "#,
        group_id,
        member_id,
        priority,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Outcome of a guarded group-member insert ([`add_group_member_checked`]).
///
/// The guard runs **before** the insert inside one transaction so a rejected
/// edge is never persisted. `Added` is the only success; the other variants are
/// fail-closed rejections the admin API maps to HTTP errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddMemberOutcome {
    /// The edge was inserted.
    Added,
    /// Adding `(group_id -> member_id)` would create a cycle in the group graph
    /// (`group_id` is reachable from `member_id`), so the edge was rejected.
    WouldCycle,
    /// Adding the edge would create a nesting path deeper than `max_depth`.
    TooDeep,
    /// An identical `(group_id, member_id)` edge (or `priority`) already exists.
    Duplicate,
}

/// Add a member to a group **with cycle + depth guards**, atomically.
///
/// Nested-group members are allowed (a member may itself be a group), but the
/// resulting graph must stay a DAG within a bounded depth. The whole check +
/// insert runs in **one transaction** that first takes a `SHARE ROW EXCLUSIVE`
/// lock on the `group_member` table. That mode conflicts with itself and with
/// the row-exclusive lock every INSERT/UPDATE/DELETE takes, so **all** group
/// graph mutations are serialized cluster-wide (reads are unaffected) without
/// any `pg_advisory_*` lock. A per-group row lock is not enough: concurrent
/// `A -> B` and `B -> A` lock *different* group rows, both walks run before
/// either insert commits, and both pass under `READ COMMITTED`, leaving a
/// cycle. With the table lock the second transaction's walk starts only after
/// the first committed, so it sees the new edge and rejects the cycle. Group
/// edits are rare admin operations, so the coarse lock is cheap.
///
/// The guard is a recursive CTE over `group_member`: starting from `member_id`
/// it walks `member -> member` edges (i.e. descends into nested groups). Adding
/// `(group_id -> member_id)` closes a cycle **iff `group_id` is reachable from
/// `member_id`**. Depth is bounded over the *whole* path through the new edge:
/// a second walk climbs from `group_id` to the groups that (transitively)
/// contain it, and the edge is rejected when the longest path above
/// `group_id`, plus the new edge, plus the deepest path below `member_id`
/// exceeds `max_depth`. Checking only below the member would let a chain grow
/// past the limit by nesting groups *under* an already-deep group. `max_depth`
/// counts edges on a path (a direct hosted/proxy member is depth 1).
///
/// Returns the [`AddMemberOutcome`]; a unique-constraint violation surfaces as
/// [`AddMemberOutcome::Duplicate`] rather than a raw `sqlx::Error`.
///
/// `owner` sets [`group_member.owner`](group_owner_ids) in the same insert, so
/// the member never serves the group's ids unflagged.
pub async fn add_group_member_checked(
    pool: &PgPool,
    group_id: i64,
    member_id: i64,
    priority: i32,
    owner: bool,
    max_depth: i32,
) -> sqlx::Result<AddMemberOutcome> {
    let mut tx = pool.begin().await?;
    let conn = tx.acquire().await?;

    // Serialize every group-graph mutation across instances (see above): the
    // cycle walk below must see all edges committed by concurrent editors.
    sqlx::query!(r#"LOCK TABLE group_member IN SHARE ROW EXCLUSIVE MODE"#)
        .execute(&mut *conn)
        .await?;
    // Keep the group row locked too, so it cannot be deleted mid-check.
    let _locked: i64 = sqlx::query_scalar!(
        r#"SELECT id FROM repository WHERE id = $1 FOR UPDATE"#,
        group_id,
    )
    .fetch_one(&mut *conn)
    .await?;

    // Reachability + depth walks. `reach` descends from the prospective member:
    // its `depth` counts the edges already below `member_id`. `up` climbs from
    // the group to every group that (transitively) contains it: its `depth`
    // counts the edges already above `group_id`. The longest path through the
    // new `(group -> member)` edge is `MAX(up.depth) + 1 + MAX(reach.depth)`.
    // Both walks stop one step past `max_depth` (enough to prove "too deep").
    // `path` only breaks an already-existing cycle defensively (a cycle should
    // not exist, but a raw DB write could have created one); cycle *creation* is
    // detected by `group_id` being reachable.
    let row = sqlx::query!(
        r#"
        WITH RECURSIVE reach(id, depth, path) AS (
            SELECT $1::bigint, 0, ARRAY[$1::bigint]
          UNION ALL
            SELECT gm.member_id, reach.depth + 1, reach.path || gm.member_id
            FROM group_member gm
            JOIN reach ON gm.group_id = reach.id
            WHERE NOT gm.member_id = ANY(reach.path)
              AND reach.depth < $3
        ),
        up(id, depth, path) AS (
            SELECT $2::bigint, 0, ARRAY[$2::bigint]
          UNION ALL
            SELECT gm.group_id, up.depth + 1, up.path || gm.group_id
            FROM group_member gm
            JOIN up ON gm.member_id = up.id
            WHERE NOT gm.group_id = ANY(up.path)
              AND up.depth < $3
        )
        SELECT
            EXISTS (SELECT 1 FROM reach WHERE id = $2)        AS "would_cycle!",
            (SELECT COALESCE(MAX(depth), 0) FROM up)
              + 1
              + (SELECT COALESCE(MAX(depth), 0) FROM reach) > $3 AS "too_deep!"
        "#,
        member_id,
        group_id,
        max_depth,
    )
    .fetch_one(&mut *conn)
    .await?;

    if row.would_cycle {
        // Drop the tx (rollback) without persisting anything.
        return Ok(AddMemberOutcome::WouldCycle);
    }
    if row.too_deep {
        return Ok(AddMemberOutcome::TooDeep);
    }

    let insert = sqlx::query!(
        r#"
        INSERT INTO group_member (group_id, member_id, priority, owner)
        VALUES ($1, $2, $3, $4)
        "#,
        group_id,
        member_id,
        priority,
        owner,
    )
    .execute(&mut *conn)
    .await;

    match insert {
        Ok(_) => {
            tx.commit().await?;
            Ok(AddMemberOutcome::Added)
        }
        Err(e) if is_unique_violation(&e) => Ok(AddMemberOutcome::Duplicate),
        Err(e) => Err(e),
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

/// Outcome of [`remove_group_member`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveMemberOutcome {
    /// The membership was deleted.
    Removed,
    /// There is no such membership.
    NotFound,
    /// The member is flagged as an owner of the group's ids and was kept:
    /// removing a group's last owner would silently return it to trusting
    /// every hosted member.
    Owner,
}

/// Remove a member from a group unless it is flagged as an owner. The owner
/// check is part of the `DELETE`, so a flag set concurrently is honoured
/// (the delete re-checks the row it waited for).
pub async fn remove_group_member(
    pool: &PgPool,
    group_id: i64,
    member_id: i64,
) -> sqlx::Result<RemoveMemberOutcome> {
    let res = sqlx::query!(
        r#"
        DELETE FROM group_member
        WHERE group_id = $1 AND member_id = $2 AND NOT owner
        "#,
        group_id,
        member_id,
    )
    .execute(pool)
    .await?;
    if res.rows_affected() > 0 {
        return Ok(RemoveMemberOutcome::Removed);
    }
    // Only picks the answer; nothing was deleted either way.
    let kept = sqlx::query_scalar!(
        r#"SELECT 1 AS "one!" FROM group_member WHERE group_id = $1 AND member_id = $2"#,
        group_id,
        member_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(if kept.is_some() {
        RemoveMemberOutcome::Owner
    } else {
        RemoveMemberOutcome::NotFound
    })
}

/// Mutable settings of an existing repository (admin update).
///
/// Identity columns (`id`, `format`, `kind`) and server-managed timestamps are
/// **not** updatable here — changing a repository's kind is structurally unsafe
/// (it would orphan components/members), so the admin API rejects it and a
/// kind change is a delete-then-recreate.
#[derive(Debug, Clone)]
pub struct RepositoryUpdate {
    pub name: String,
    pub anonymous_read: bool,
    pub online: bool,
    pub config: JsonValue,
    pub remote_url: Option<String>,
    pub package_delay_seconds: i32,
    pub upstream_username: Option<String>,
    /// **Plaintext** upstream password column value (legacy path). With
    /// encryption at rest enabled, callers pass `None` (the plaintext column
    /// must stay empty) and store the password via
    /// [`crate::secret_dao::set_upstream_password`] instead.
    pub upstream_password: Option<String>,
    /// Also set `upstream_password_enc` to NULL. Used when the stored password
    /// is cleared or replaced without the envelope service (a stale sealed blob
    /// would otherwise outlive it). When `false` the column is left unchanged.
    pub clear_upstream_password_enc: bool,
    pub metadata_ttl_seconds: Option<i32>,
    pub not_found_ttl_seconds: Option<i32>,
    pub allow_redeploy: bool,
}

/// Update the mutable settings of a repository by id. Returns the updated row,
/// or `None` if no repository has that id. `updated_at` is bumped to `now()`.
/// Accepts any executor so it composes with other writes in one transaction.
pub async fn update_repository<'e, E>(
    executor: E,
    id: i64,
    upd: RepositoryUpdate,
) -> sqlx::Result<Option<Repository>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        Repository,
        r#"
        UPDATE repository SET
            name = $2,
            anonymous_read = $3,
            online = $4,
            config = $5,
            remote_url = $6,
            package_delay_seconds = $7,
            upstream_username = $8,
            upstream_password = $9,
            metadata_ttl_seconds = $10,
            not_found_ttl_seconds = $11,
            allow_redeploy = $12,
            upstream_password_enc = CASE WHEN $13 THEN NULL ELSE upstream_password_enc END,
            updated_at = now()
        WHERE id = $1
        RETURNING
            id, name, format, kind, anonymous_read, online, config,
            remote_url, package_delay_seconds, upstream_username, upstream_password,
            upstream_password_enc, metadata_ttl_seconds, not_found_ttl_seconds,
            allow_redeploy, created_at, updated_at
        "#,
        id,
        upd.name,
        upd.anonymous_read,
        upd.online,
        upd.config,
        upd.remote_url,
        upd.package_delay_seconds,
        upd.upstream_username,
        upd.upstream_password,
        upd.metadata_ttl_seconds,
        upd.not_found_ttl_seconds,
        upd.allow_redeploy,
        upd.clear_upstream_password_enc,
    )
    .fetch_optional(executor)
    .await
}

/// Lock a repository row `FOR UPDATE` inside the caller's transaction.
/// Returns `false` when the row does not exist (or a concurrent delete removed
/// it first).
///
/// Taken before a repository delete inspects or purges its components: the
/// lock conflicts with the `FOR KEY SHARE` lock every `component` insert's
/// foreign-key check takes on the repository row, so no publish or proxy
/// cache fill can commit a new component between the check/purge and the
/// delete (an in-flight one is waited for and then seen by the check).
pub async fn lock_repository<'e, E>(executor: E, id: i64) -> sqlx::Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    let row = sqlx::query_scalar!(r#"SELECT id FROM repository WHERE id = $1 FOR UPDATE"#, id)
        .fetch_optional(executor)
        .await?;
    Ok(row.is_some())
}

/// Delete a repository by id. Returns whether a row was deleted.
///
/// Every dependent row cascades via `ON DELETE CASCADE` — `group_member` rows
/// naming it as group or member, proxy caches, retention state, grants, **and
/// its `component`/`asset` rows**. The cascade does not touch `blob` reference
/// counts, so callers must first remove components through
/// `component_dao::hard_delete_all_components` (or refuse when any remain),
/// in the same transaction and after [`lock_repository`]; otherwise the
/// cascaded assets' blobs keep their references forever and their S3 objects
/// are never reclaimed.
pub async fn delete_repository<'e, E>(executor: E, id: i64) -> sqlx::Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    let res = sqlx::query!(r#"DELETE FROM repository WHERE id = $1"#, id)
        .execute(executor)
        .await?;
    Ok(res.rows_affected() > 0)
}
