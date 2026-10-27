//! Auth-realm data access.
//!
//! The `auth_realm` table is the **authority** for the server's authentication
//! configuration: the password chain and the OIDC login runtime are rebuilt
//! from these rows (snapshot-cached per instance, short TTL + invalidation on
//! admin writes). Multi-instance correctness follows from re-reading the table
//! — there is no in-memory-only authoritative state and no advisory locks.
//!
//! `config` may contain secrets (OIDC `client_secret`, credential-forwarding
//! `key_pepper`). This module moves the jsonb around opaquely; redaction is the
//! API layer's job. Encryption at rest (`secrets_enc`) goes
//! through [`crate::secret_dao`]'s realm helpers, which call
//! [`update_realm_and_secrets`] here.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{PgExecutor, PgPool};

use crate::model::AuthRealm;

/// Insert payload for a realm.
#[derive(Debug, Clone)]
pub struct NewAuthRealm {
    /// `'local'` | `'oidc'` | `'credential_forwarding'` | `'workload_identity'`.
    pub kind: String,
    /// Unique slug/display name (DB CHECK enforces the shape).
    pub name: String,
    pub enabled: bool,
    /// Unique order; lower tries first. Use [`next_priority`] for "append".
    pub priority: i32,
    pub config: JsonValue,
}

/// Mutable fields of a realm. `kind` is immutable (a different mechanism is a
/// different realm); `config` is the **full** replacement document — the API
/// layer is responsible for merging write-only secrets into it first.
#[derive(Debug, Clone)]
pub struct AuthRealmUpdate {
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub config: JsonValue,
}

/// List all realms ordered by `priority` ascending (try-order).
pub async fn list_realms(pool: &PgPool) -> sqlx::Result<Vec<AuthRealm>> {
    sqlx::query_as!(
        AuthRealm,
        r#"
        SELECT id, kind, name, enabled, priority, config, secrets_enc, created_at, updated_at
        FROM auth_realm
        ORDER BY priority
        "#,
    )
    .fetch_all(pool)
    .await
}

/// List only the enabled realms, ordered by `priority` ascending.
pub async fn list_enabled_realms(pool: &PgPool) -> sqlx::Result<Vec<AuthRealm>> {
    sqlx::query_as!(
        AuthRealm,
        r#"
        SELECT id, kind, name, enabled, priority, config, secrets_enc, created_at, updated_at
        FROM auth_realm
        WHERE enabled
        ORDER BY priority
        "#,
    )
    .fetch_all(pool)
    .await
}

/// Find a realm by id.
pub async fn find_realm_by_id(pool: &PgPool, id: i64) -> sqlx::Result<Option<AuthRealm>> {
    sqlx::query_as!(
        AuthRealm,
        r#"
        SELECT id, kind, name, enabled, priority, config, secrets_enc, created_at, updated_at
        FROM auth_realm
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Find a realm by its unique name.
pub async fn find_realm_by_name(pool: &PgPool, name: &str) -> sqlx::Result<Option<AuthRealm>> {
    sqlx::query_as!(
        AuthRealm,
        r#"
        SELECT id, kind, name, enabled, priority, config, secrets_enc, created_at, updated_at
        FROM auth_realm
        WHERE name = $1
        "#,
        name,
    )
    .fetch_optional(pool)
    .await
}

/// Whether any realm of `kind` exists (enabled or not). Used by the one-shot
/// legacy-config import to avoid re-seeding a kind the operator already
/// manages.
pub async fn kind_exists(pool: &PgPool, kind: &str) -> sqlx::Result<bool> {
    sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM auth_realm WHERE kind = $1) AS "exists!""#,
        kind,
    )
    .fetch_one(pool)
    .await
}

/// The next free priority slot (max + 10, so manual inserts between rows stay
/// possible). `10` on an empty table — though the table is never empty in
/// practice (the schema seeds the `local` row).
pub async fn next_priority(pool: &PgPool) -> sqlx::Result<i32> {
    let max: Option<i32> = sqlx::query_scalar!(r#"SELECT max(priority) FROM auth_realm"#)
        .fetch_one(pool)
        .await?;
    Ok(max.map_or(10, |m| m.saturating_add(10)))
}

/// Insert a realm, returning the persisted row. A duplicate `name` or
/// `priority` surfaces as a unique violation for the caller to map to 409.
/// Accepts any executor so the encrypted-secrets insert composes in one
/// transaction.
pub async fn insert_realm<'e, E>(executor: E, new: NewAuthRealm) -> sqlx::Result<AuthRealm>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        AuthRealm,
        r#"
        INSERT INTO auth_realm (kind, name, enabled, priority, config)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, kind, name, enabled, priority, config, secrets_enc, created_at, updated_at
        "#,
        new.kind,
        new.name,
        new.enabled,
        new.priority,
        new.config,
    )
    .fetch_one(executor)
    .await
}

/// Update a realm's mutable fields by id. Returns the updated row, or `None`
/// when the id does not exist. Bumps `updated_at`.
pub async fn update_realm(
    pool: &PgPool,
    id: i64,
    upd: AuthRealmUpdate,
) -> sqlx::Result<Option<AuthRealm>> {
    sqlx::query_as!(
        AuthRealm,
        r#"
        UPDATE auth_realm SET
            name = $2,
            enabled = $3,
            priority = $4,
            config = $5,
            updated_at = now()
        WHERE id = $1
        RETURNING id, kind, name, enabled, priority, config, secrets_enc, created_at, updated_at
        "#,
        id,
        upd.name,
        upd.enabled,
        upd.priority,
        upd.config,
    )
    .fetch_optional(pool)
    .await
}

/// Update a realm's mutable fields **and** its encrypted-secrets column in one
/// statement (`secrets_enc = NULL` ⇒ secrets live as plaintext in `config`).
/// Used by the [`crate::secret_dao`] realm helpers; bumps `updated_at`.
pub async fn update_realm_and_secrets<'e, E>(
    executor: E,
    id: i64,
    upd: AuthRealmUpdate,
    secrets_enc: Option<&[u8]>,
) -> sqlx::Result<Option<AuthRealm>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        AuthRealm,
        r#"
        UPDATE auth_realm SET
            name = $2,
            enabled = $3,
            priority = $4,
            config = $5,
            secrets_enc = $6,
            updated_at = now()
        WHERE id = $1
        RETURNING id, kind, name, enabled, priority, config, secrets_enc, created_at, updated_at
        "#,
        id,
        upd.name,
        upd.enabled,
        upd.priority,
        upd.config,
        secrets_enc,
    )
    .fetch_optional(executor)
    .await
}

/// [`update_realm_and_secrets`] as a compare-and-set: the row is written only
/// while it is still `expected` (same `updated_at`, `config` and
/// `secrets_enc`, which also covers a re-seal sweep that leaves `updated_at`
/// alone). `None` when it changed or is gone.
pub async fn update_realm_and_secrets_if_unchanged<'e, E>(
    executor: E,
    expected: &AuthRealm,
    upd: AuthRealmUpdate,
    secrets_enc: Option<&[u8]>,
) -> sqlx::Result<Option<AuthRealm>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        AuthRealm,
        r#"
        UPDATE auth_realm SET
            name = $2,
            enabled = $3,
            priority = $4,
            config = $5,
            secrets_enc = $6,
            updated_at = now()
        WHERE id = $1
          AND updated_at = $7
          AND config = $8
          AND secrets_enc IS NOT DISTINCT FROM $9
        RETURNING id, kind, name, enabled, priority, config, secrets_enc, created_at, updated_at
        "#,
        expected.id,
        upd.name,
        upd.enabled,
        upd.priority,
        upd.config,
        secrets_enc,
        expected.updated_at,
        expected.config,
        expected.secrets_enc.as_deref(),
    )
    .fetch_optional(executor)
    .await
}

/// Delete a realm by id. Returns whether a row was deleted. (Refusing to
/// delete the built-in `local` realm is an API-layer rule, not enforced here.)
pub async fn delete_realm<'e, E>(executor: E, id: i64) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(r#"DELETE FROM auth_realm WHERE id = $1"#, id)
        .execute(executor)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Lock the realms people sign in with interactively (`local` and `oidc`)
/// `FOR UPDATE`, in id order, and return each one's `(id, enabled)`. An
/// admin change that disables or deletes one of them takes this first, so
/// two concurrent changes cannot each leave the other's realm as the last
/// one and then both remove theirs.
pub async fn lock_interactive_realms(
    conn: &mut sqlx::PgConnection,
) -> sqlx::Result<Vec<(i64, bool)>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, enabled FROM auth_realm
        WHERE kind IN ('local', 'oidc')
        ORDER BY id
        FOR UPDATE
        "#
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(|r| (r.id, r.enabled)).collect())
}

/// What [`reorder_realms`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReorderOutcome {
    /// Every realm got its new priority.
    Reordered,
    /// `order` does not list exactly the realms that exist (one was created
    /// or deleted since the caller read them); nothing changed.
    Changed,
}

/// Reassign priorities in one transaction. `order` is the full desired
/// try-order (every realm id, first = highest precedence); each row gets
/// `(index + 1) * 10`. The unique constraint is DEFERRABLE, so intermediate
/// duplicates inside the transaction are fine.
///
/// The table is locked `EXCLUSIVE` (reads go on) before anything else, and
/// `order` is compared with the realms that exist under that lock. Updating
/// the rows in the caller's order without it deadlocked against an admin
/// change that locks the interactive realms in id order
/// ([`lock_interactive_realms`]), and a realm created meanwhile could take a
/// priority the reorder assigns; both surfaced as a 500. Under the lock a
/// concurrent change either finishes first (and then shows up as
/// [`ReorderOutcome::Changed`]) or waits for this one.
pub async fn reorder_realms(pool: &PgPool, order: &[i64]) -> sqlx::Result<ReorderOutcome> {
    let mut tx = crate::begin(pool).await?;
    sqlx::query!(r#"LOCK TABLE auth_realm IN EXCLUSIVE MODE"#)
        .execute(&mut *tx)
        .await?;
    let existing = sqlx::query_scalar!(r#"SELECT id FROM auth_realm ORDER BY id"#)
        .fetch_all(&mut *tx)
        .await?;
    let mut given = order.to_vec();
    given.sort_unstable();
    if given != existing {
        return Ok(ReorderOutcome::Changed);
    }
    sqlx::query!(r#"SET CONSTRAINTS auth_realm_priority_key DEFERRED"#)
        .execute(&mut *tx)
        .await?;
    for (idx, id) in order.iter().enumerate() {
        let priority = ((idx + 1) * 10) as i32;
        sqlx::query!(
            r#"UPDATE auth_realm SET priority = $2, updated_at = now() WHERE id = $1"#,
            id,
            priority,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(ReorderOutcome::Reordered)
}

/// A cheap change marker for the per-instance snapshot cache: `(row count,
/// max(updated_at))`. Two reads with the same marker saw the same realm set
/// (updates bump `updated_at`; inserts/deletes change the count — a delete
/// alone could collide with an old max, hence the count too).
pub async fn change_marker(pool: &PgPool) -> sqlx::Result<(i64, Option<DateTime<Utc>>)> {
    let row = sqlx::query!(
        r#"SELECT count(*) AS "count!", max(updated_at) AS "max_updated" FROM auth_realm"#
    )
    .fetch_one(pool)
    .await?;
    Ok((row.count, row.max_updated))
}
