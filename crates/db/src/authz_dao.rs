//! Data access for fine-grained RBAC: reading a principal's effective grant
//! set and the small CRUD surface the admin API and the evaluator need.
//!
//! The hot path is [`load_user_effective`] / [`load_anonymous_effective`]: a
//! single indexed query joining `user_role → repository_privilege` (left-joined
//! to `content_selector`) that returns the principal's `is_admin` flag plus its
//! flat list of grants. The `forge-core` evaluator compiles these raw rows into
//! its in-memory `EffectiveSet`; this DAO stays free of any policy logic — it
//! only reads rows.
//!
//! Selectors are stored as jsonb string arrays (`content_selector.includes` /
//! `.excludes`); they are returned here as the raw [`serde_json::Value`] and
//! parsed into `Vec<String>` by [`SelectorRow::patterns`] so a malformed array
//! is rejected (fail-closed) rather than silently treated as match-all.
//!
//! Multi-instance correctness: these are plain reads; no advisory locks, no
//! in-memory-only state. Authoritative privilege data lives entirely in these
//! tables and the `forge-cache` layer sits in front of the resolved set with
//! explicit cross-node invalidation.

use serde_json::Value as JsonValue;
use sqlx::{PgExecutor, PgPool};

/// The fixed slug of the built-in admin role (allow-all short-circuit).
pub const ADMIN_ROLE: &str = "admin";
/// The fixed slug of the built-in anonymous role (applied to anonymous callers).
pub const ANONYMOUS_ROLE: &str = "anonymous";
/// The fixed slug of the built-in `authenticated` role (read and write on
/// every repository), for an administrator to assign.
pub const AUTHENTICATED_ROLE: &str = "authenticated";

/// Shared shape of the effective-set query rows (user + anonymous variants).
/// The two `sqlx::query!` calls generate distinct anonymous structs with the
/// same columns; [`into_query_row!`] converts each into this adapter so
/// [`map_grant_row`] is reused across both call sites.
struct EffectiveQueryRow {
    action: String,
    repository_id: Option<i64>,
    selector_id: Option<i64>,
    includes: Option<JsonValue>,
    excludes: Option<JsonValue>,
}

macro_rules! into_query_row {
    ($r:expr) => {
        EffectiveQueryRow {
            action: $r.action,
            repository_id: $r.repository_id,
            selector_id: $r.selector_id,
            includes: $r.includes,
            excludes: $r.excludes,
        }
    };
}

/// One grant row of a principal's effective set, as read from the DB.
///
/// This is the DB-layer mirror of `forge-core`'s `RawGrant`; the core crate maps
/// it into its own type (the two crates do not share a struct so the data-access
/// layer carries no policy semantics). `selector` is `None` for an unscoped
/// grant; otherwise it holds the raw include/exclude jsonb arrays.
#[derive(Debug, Clone)]
pub struct EffectiveGrantRow {
    /// The action verb (`read`/`write`/`delete`/`admin`).
    pub action: String,
    /// `repository.id`, or `None` for an ANY-repo grant.
    pub repository_id: Option<i64>,
    /// The attached content selector's raw patterns, or `None` if unscoped.
    pub selector: Option<SelectorRow>,
}

/// The raw include/exclude jsonb arrays of a `content_selector` row.
#[derive(Debug, Clone)]
pub struct SelectorRow {
    /// `content_selector.id` (for caching / admin display).
    pub id: i64,
    /// Raw `includes` jsonb (expected: array of glob strings).
    pub includes: JsonValue,
    /// Raw `excludes` jsonb (expected: array of glob strings).
    pub excludes: JsonValue,
}

impl SelectorRow {
    /// Parse the raw jsonb arrays into `(includes, excludes)` string vectors.
    ///
    /// A value that is not a JSON array of strings is an error: we refuse to
    /// guess. Callers treat a parse failure as deny (fail-closed) rather than as
    /// an empty/match-all selector.
    pub fn patterns(&self) -> Result<(Vec<String>, Vec<String>), SelectorParseError> {
        Ok((
            parse_string_array(&self.includes, self.id, "includes")?,
            parse_string_array(&self.excludes, self.id, "excludes")?,
        ))
    }
}

/// A `content_selector` jsonb array was not an array of strings.
#[derive(Debug, thiserror::Error)]
#[error("content_selector {selector_id} field {field:?} is not a JSON array of strings")]
pub struct SelectorParseError {
    /// `content_selector.id`.
    pub selector_id: i64,
    /// The offending field (`includes` / `excludes`).
    pub field: &'static str,
}

fn parse_string_array(
    value: &JsonValue,
    selector_id: i64,
    field: &'static str,
) -> Result<Vec<String>, SelectorParseError> {
    let arr = value
        .as_array()
        .ok_or(SelectorParseError { selector_id, field })?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .ok_or(SelectorParseError { selector_id, field })
        })
        .collect()
}

/// A principal's raw effective set as read from the DB: the admin flag plus the
/// flat grant list. The core evaluator compiles this into its `EffectiveSet`.
#[derive(Debug, Clone)]
pub struct EffectiveRows {
    /// Membership in the built-in `admin` role.
    pub is_admin: bool,
    /// All grants from all of the principal's roles (additive union).
    pub grants: Vec<EffectiveGrantRow>,
}

/// Load the effective set for an authenticated user (`app_user.id = user_id`).
///
/// `is_admin` is true iff the user holds the built-in `admin` role. The grants
/// are the union of every `repository_privilege` of every role the user holds,
/// each with its content selector (if any). A user with no roles yields an empty
/// set (fail-closed deny-all).
pub async fn load_user_effective(pool: &PgPool, user_id: i64) -> sqlx::Result<EffectiveRows> {
    let is_admin = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM user_role ur
            JOIN role r ON r.id = ur.role_id
            WHERE ur.user_id = $1 AND r.name = $2
        ) AS "exists!"
        "#,
        user_id,
        ADMIN_ROLE,
    )
    .fetch_one(pool)
    .await?;

    let rows = sqlx::query!(
        r#"
        SELECT
            rp.action            AS action,
            rp.repository_id     AS repository_id,
            cs.id                AS "selector_id?",
            cs.includes          AS "includes?",
            cs.excludes          AS "excludes?"
        FROM user_role ur
        JOIN repository_privilege rp ON rp.role_id = ur.role_id
        LEFT JOIN content_selector cs ON cs.id = rp.selector_id
        WHERE ur.user_id = $1
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await?;

    let grants = rows
        .into_iter()
        .map(|r| map_grant_row(into_query_row!(r)))
        .collect();
    Ok(EffectiveRows { is_admin, grants })
}

/// Load the effective set applied to anonymous callers: exactly the grants of
/// the built-in `anonymous` role. Anonymous principals are never admin.
///
/// On a fresh / un-migrated install the `anonymous` role has no grants, so this
/// returns an empty set (deny-all) — anonymous access is opened by granting the
/// `anonymous` role `read` on specific repos (the data migration converts each
/// repository's `anonymous_read` flag into exactly these grants).
pub async fn load_anonymous_effective(pool: &PgPool) -> sqlx::Result<EffectiveRows> {
    let rows = sqlx::query!(
        r#"
        SELECT
            rp.action            AS action,
            rp.repository_id     AS repository_id,
            cs.id                AS "selector_id?",
            cs.includes          AS "includes?",
            cs.excludes          AS "excludes?"
        FROM role r
        JOIN repository_privilege rp ON rp.role_id = r.id
        LEFT JOIN content_selector cs ON cs.id = rp.selector_id
        WHERE r.name = $1
        "#,
        ANONYMOUS_ROLE,
    )
    .fetch_all(pool)
    .await?;

    let grants = rows
        .into_iter()
        .map(|r| map_grant_row(into_query_row!(r)))
        .collect();
    Ok(EffectiveRows {
        is_admin: false,
        grants,
    })
}

/// Load the effective set granted by a **single role** (`role.id = role_id`).
///
/// Unlike [`load_user_effective`], this resolves a role directly — used by the
/// workload-identity (WIF) auth path, where a validated CI token
/// is mapped to exactly one forge role and authorized by that role's grants
/// (no `app_user` row, no `user_role` membership). `is_admin` is true iff the
/// role *is* the built-in `admin` role. A non-existent `role_id` yields an empty
/// set (fail-closed deny-all).
pub async fn load_role_effective(pool: &PgPool, role_id: i64) -> sqlx::Result<EffectiveRows> {
    let is_admin = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM role WHERE id = $1 AND name = $2
        ) AS "exists!"
        "#,
        role_id,
        ADMIN_ROLE,
    )
    .fetch_one(pool)
    .await?;

    let rows = sqlx::query!(
        r#"
        SELECT
            rp.action            AS "action!",
            rp.repository_id     AS repository_id,
            cs.id                AS "selector_id?",
            cs.includes          AS "includes?",
            cs.excludes          AS "excludes?"
        FROM repository_privilege rp
        LEFT JOIN content_selector cs ON cs.id = rp.selector_id
        WHERE rp.role_id = $1
        "#,
        role_id,
    )
    .fetch_all(pool)
    .await?;

    let grants = rows
        .into_iter()
        .map(|r| map_grant_row(into_query_row!(r)))
        .collect();
    Ok(EffectiveRows { is_admin, grants })
}

/// Map a raw effective-set query row into an [`EffectiveGrantRow`]. The selector
/// columns are present together (left-join) or all NULL (unscoped grant).
fn map_grant_row(r: EffectiveQueryRow) -> EffectiveGrantRow {
    let selector = match (r.selector_id, r.includes, r.excludes) {
        (Some(id), Some(includes), Some(excludes)) => Some(SelectorRow {
            id,
            includes,
            excludes,
        }),
        _ => None,
    };
    EffectiveGrantRow {
        action: r.action,
        repository_id: r.repository_id,
        selector,
    }
}

/// Load a token's raw `scope` jsonb by token id, for per-token privilege
/// scoping.
///
/// Returns `Ok(None)` when the token does not exist **or** its `scope` column is
/// NULL — both mean "no scoping" to the caller, which then uses the owner's full
/// effective set. The value is the raw [`serde_json::Value`]; the `forge-core`
/// evaluator parses it into a `TokenScope` (a parse failure there is fail-closed:
/// a malformed scope grants nothing).
///
/// This is read **outside** the per-user effective-set cache (the cache holds the
/// owner set, shared across the user's tokens); the scope is intersected in code
/// after the cache lookup so a token can only ever narrow its owner.
pub async fn load_token_scope(pool: &PgPool, token_id: i64) -> sqlx::Result<Option<JsonValue>> {
    let scope = sqlx::query_scalar!(r#"SELECT scope FROM token WHERE id = $1"#, token_id)
        .fetch_optional(pool)
        .await?
        // outer Option: row present? inner Option: column NULL? flatten both.
        .flatten();
    Ok(scope)
}

// --- role / selector lookups (used by the admin API + bootstrap) ------------

/// Look up a role id by its unique `name`. Returns `None` if absent. Accepts any
/// executor so it composes inside a transaction (e.g. bootstrap seeding).
pub async fn role_id_by_name<'e, E>(executor: E, name: &str) -> sqlx::Result<Option<i64>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar!(r#"SELECT id FROM role WHERE name = $1"#, name)
        .fetch_optional(executor)
        .await
}

/// Whether a user holds a given role (by role name), e.g. whether it is an
/// administrator ([`ADMIN_ROLE`]).
pub async fn user_has_role<'e, E>(executor: E, user_id: i64, role_name: &str) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM user_role ur
            JOIN role r ON r.id = ur.role_id
            WHERE ur.user_id = $1 AND r.name = $2
        ) AS "exists!"
        "#,
        user_id,
        role_name,
    )
    .fetch_one(executor)
    .await
}

/// Assign `role_id` to `user_id` (idempotent). Accepts any executor.
pub async fn assign_role<'e, E>(executor: E, user_id: i64, role_id: i64) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        r#"
        INSERT INTO user_role (user_id, role_id)
        VALUES ($1, $2)
        ON CONFLICT (user_id, role_id) DO NOTHING
        "#,
        user_id,
        role_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Remove a role assignment from a user (idempotent). Accepts any executor.
pub async fn unassign_role<'e, E>(executor: E, user_id: i64, role_id: i64) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        r#"DELETE FROM user_role WHERE user_id = $1 AND role_id = $2"#,
        user_id,
        role_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Make the built-in `admin` role membership of `user_id` match `is_admin`
/// (assign when true, remove when false) — used where an external identity
/// source is authoritative for admin (an OIDC realm with `admin_groups`, a
/// credential-forwarding realm with an `admin_group`), so a demotion there
/// takes effect here. Returns whether the membership changed (the caller
/// invalidates the user's cached effective set). A missing built-in role is a
/// no-op.
pub async fn sync_admin_role(pool: &PgPool, user_id: i64, is_admin: bool) -> sqlx::Result<bool> {
    let Some(role_id) = role_id_by_name(pool, ADMIN_ROLE).await? else {
        return Ok(false);
    };
    let changed = if is_admin {
        sqlx::query!(
            r#"
            INSERT INTO user_role (user_id, role_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id, role_id) DO NOTHING
            "#,
            user_id,
            role_id,
        )
        .execute(pool)
        .await?
        .rows_affected()
    } else {
        sqlx::query!(
            r#"DELETE FROM user_role WHERE user_id = $1 AND role_id = $2"#,
            user_id,
            role_id,
        )
        .execute(pool)
        .await?
        .rows_affected()
    };
    Ok(changed > 0)
}

/// The last-admin guard: whether taking `user_id`'s admin rights away
/// (deactivating, deleting, or unassigning its `admin` role) would leave no
/// active administrator. `true` iff `user_id` is an active admin and no other
/// active user is: a member of the built-in `admin` role.
///
/// Call it in the transaction that applies the change, and apply it only on
/// `false`. It first locks the built-in `admin` role row (`FOR NO KEY UPDATE`,
/// which the `FOR KEY SHARE` of a concurrent role assignment's foreign-key
/// check does not wait for) until that transaction ends, so guarded changes
/// run one at a time across instances. The count is a later statement, which
/// under `READ COMMITTED` sees what the previous lock holder committed: two
/// admins demoting each other at once cannot both pass. Changes that only add
/// admins need no lock.
pub async fn would_leave_no_admin(
    conn: &mut sqlx::PgConnection,
    user_id: i64,
) -> sqlx::Result<bool> {
    sqlx::query_scalar!(
        r#"SELECT id FROM role WHERE name = $1 FOR NO KEY UPDATE"#,
        ADMIN_ROLE,
    )
    .fetch_optional(&mut *conn)
    .await?;
    sqlx::query_scalar!(
        r#"
        WITH active_admin AS (
            SELECT u.id FROM app_user u
            WHERE u.active
              AND EXISTS (
                  SELECT 1 FROM user_role ur
                  JOIN role r ON r.id = ur.role_id
                  WHERE ur.user_id = u.id AND r.name = $2
              )
        )
        SELECT EXISTS (SELECT 1 FROM active_admin WHERE id = $1)
           AND NOT EXISTS (SELECT 1 FROM active_admin WHERE id <> $1) AS "last!"
        "#,
        user_id,
        ADMIN_ROLE,
    )
    .fetch_one(&mut *conn)
    .await
}

/// Insert a repository-privilege grant for a role. `repository_id = None` ⇒ ANY
/// repo; `selector_id = None` ⇒ unscoped. Idempotent via the unique index
/// (COALESCE-folded NULLs). Accepts any executor.
pub async fn add_grant<'e, E>(
    executor: E,
    role_id: i64,
    repository_id: Option<i64>,
    action: &str,
    selector_id: Option<i64>,
) -> sqlx::Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        r#"
        INSERT INTO repository_privilege (role_id, repository_id, action, selector_id)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (role_id, COALESCE(repository_id, 0), action, COALESCE(selector_id, 0))
        DO NOTHING
        "#,
        role_id,
        repository_id,
        action,
        selector_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Insert a content selector and return its id. `includes` / `excludes` are the
/// glob string lists (serialized to jsonb arrays). Accepts any executor.
pub async fn insert_content_selector<'e, E>(
    executor: E,
    name: &str,
    includes: &[String],
    excludes: &[String],
) -> sqlx::Result<i64>
where
    E: PgExecutor<'e>,
{
    let includes = serde_json::to_value(includes).expect("string vec serializes");
    let excludes = serde_json::to_value(excludes).expect("string vec serializes");
    sqlx::query_scalar!(
        r#"
        INSERT INTO content_selector (name, includes, excludes)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
        name,
        includes,
        excludes,
    )
    .fetch_one(executor)
    .await
}

// --- admin REST CRUD surface ------------------------------------------------

/// A `role` row, as returned to the admin API.
#[derive(Debug, Clone)]
pub struct Role {
    /// `role.id`.
    pub id: i64,
    /// URL-safe slug, unique.
    pub name: String,
    /// Human description.
    pub description: String,
    /// `true` for the seeded built-in roles (`admin`/`authenticated`/`anonymous`);
    /// they cannot be deleted and their grants are protected by the admin API.
    pub builtin: bool,
}

/// A `repository_privilege` grant row joined to its (optional) content selector,
/// as returned to the admin API when listing a role's grants.
#[derive(Debug, Clone)]
pub struct GrantRow {
    /// `repository_privilege.id`.
    pub id: i64,
    /// Owning role id.
    pub role_id: i64,
    /// `repository.id`, or `None` for an ANY-repo grant.
    pub repository_id: Option<i64>,
    /// Action verb (`read`/`write`/`delete`/`admin`).
    pub action: String,
    /// Attached content-selector id, or `None` if unscoped.
    pub selector_id: Option<i64>,
}

/// A `content_selector` row, as returned to the admin API.
#[derive(Debug, Clone)]
pub struct ContentSelector {
    /// `content_selector.id`.
    pub id: i64,
    /// Unique name.
    pub name: String,
    /// Human description.
    pub description: String,
    /// Raw `includes` jsonb (array of glob strings).
    pub includes: JsonValue,
    /// Raw `excludes` jsonb (array of glob strings).
    pub excludes: JsonValue,
}

/// List all roles, ordered by name. Built-in roles sort alongside custom ones.
pub async fn list_roles(pool: &PgPool) -> sqlx::Result<Vec<Role>> {
    let rows = sqlx::query!(r#"SELECT id, name, description, builtin FROM role ORDER BY name"#)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| Role {
            id: r.id,
            name: r.name,
            description: r.description,
            builtin: r.builtin,
        })
        .collect())
}

/// Fetch one role by id. `None` if absent.
pub async fn find_role_by_id(pool: &PgPool, id: i64) -> sqlx::Result<Option<Role>> {
    let row = sqlx::query!(
        r#"SELECT id, name, description, builtin FROM role WHERE id = $1"#,
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| Role {
        id: r.id,
        name: r.name,
        description: r.description,
        builtin: r.builtin,
    }))
}

/// Insert a new (non-builtin) role and return it. The unique-name violation is
/// surfaced to the caller (sqlx error code `23505`) so the admin API can map it
/// to a `409`.
pub async fn insert_role(pool: &PgPool, name: &str, description: &str) -> sqlx::Result<Role> {
    let row = sqlx::query!(
        r#"
        INSERT INTO role (name, description, builtin)
        VALUES ($1, $2, false)
        RETURNING id, name, description, builtin
        "#,
        name,
        description,
    )
    .fetch_one(pool)
    .await?;
    Ok(Role {
        id: row.id,
        name: row.name,
        description: row.description,
        builtin: row.builtin,
    })
}

/// Update a role's `description` (the only mutable field; `name`/`builtin` are
/// immutable). Bumps `updated_at`. Returns the updated row, or `None` if the id
/// does not exist.
pub async fn update_role_description(
    pool: &PgPool,
    id: i64,
    description: &str,
) -> sqlx::Result<Option<Role>> {
    let row = sqlx::query!(
        r#"
        UPDATE role SET description = $2, updated_at = now()
        WHERE id = $1
        RETURNING id, name, description, builtin
        "#,
        id,
        description,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| Role {
        id: r.id,
        name: r.name,
        description: r.description,
        builtin: r.builtin,
    }))
}

/// Delete a **non-builtin** role by id. Built-in roles are protected: the
/// `WHERE builtin = false` clause means a delete targeting a built-in role
/// affects zero rows and returns `false` (the admin API maps that to a 403/409;
/// it checks `builtin` first for a precise message). Returns `true` iff a row was
/// deleted. Grants and user assignments cascade (FK `ON DELETE CASCADE`).
pub async fn delete_role(pool: &PgPool, id: i64) -> sqlx::Result<bool> {
    let res = sqlx::query!(r#"DELETE FROM role WHERE id = $1 AND builtin = false"#, id,)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// List a role's grants (with selector ids), ordered for stable display.
pub async fn list_grants_for_role(pool: &PgPool, role_id: i64) -> sqlx::Result<Vec<GrantRow>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, role_id, repository_id, action, selector_id
        FROM repository_privilege
        WHERE role_id = $1
        ORDER BY id
        "#,
        role_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| GrantRow {
            id: r.id,
            role_id: r.role_id,
            repository_id: r.repository_id,
            action: r.action,
            selector_id: r.selector_id,
        })
        .collect())
}

/// Delete a single grant edge by its `repository_privilege.id`, scoped to its
/// owning role (so a mismatched (role, grant) pair affects nothing). Returns
/// `true` iff a row was removed.
pub async fn delete_grant(pool: &PgPool, role_id: i64, grant_id: i64) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        r#"DELETE FROM repository_privilege WHERE id = $1 AND role_id = $2"#,
        grant_id,
        role_id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// List all content selectors, ordered by name.
pub async fn list_content_selectors(pool: &PgPool) -> sqlx::Result<Vec<ContentSelector>> {
    let rows = sqlx::query!(
        r#"SELECT id, name, description, includes, excludes FROM content_selector ORDER BY name"#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| ContentSelector {
            id: r.id,
            name: r.name,
            description: r.description,
            includes: r.includes,
            excludes: r.excludes,
        })
        .collect())
}

/// Fetch one content selector by id. `None` if absent.
pub async fn find_content_selector_by_id(
    pool: &PgPool,
    id: i64,
) -> sqlx::Result<Option<ContentSelector>> {
    let row = sqlx::query!(
        r#"SELECT id, name, description, includes, excludes FROM content_selector WHERE id = $1"#,
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| ContentSelector {
        id: r.id,
        name: r.name,
        description: r.description,
        includes: r.includes,
        excludes: r.excludes,
    }))
}

/// Create a content selector (with description) and return the full row. The
/// existing [`insert_content_selector`] returns just the id for bootstrap use;
/// this is the admin-API variant returning the row and accepting a description.
pub async fn create_content_selector(
    pool: &PgPool,
    name: &str,
    description: &str,
    includes: &[String],
    excludes: &[String],
) -> sqlx::Result<ContentSelector> {
    let inc = serde_json::to_value(includes).expect("string vec serializes");
    let exc = serde_json::to_value(excludes).expect("string vec serializes");
    let row = sqlx::query!(
        r#"
        INSERT INTO content_selector (name, description, includes, excludes)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, description, includes, excludes
        "#,
        name,
        description,
        inc,
        exc,
    )
    .fetch_one(pool)
    .await?;
    Ok(ContentSelector {
        id: row.id,
        name: row.name,
        description: row.description,
        includes: row.includes,
        excludes: row.excludes,
    })
}

/// Update a content selector's `description` / `includes` / `excludes` (name is
/// immutable) with **PATCH semantics**: a `None` field keeps the stored value,
/// `Some` replaces it. Bumps `updated_at`. Returns the updated row, or `None`
/// if absent.
///
/// Keeping omitted lists matters for safety: an empty `includes` means
/// match-all, so resetting an omitted list to `[]` would silently widen every
/// grant that uses the selector.
pub async fn update_content_selector(
    pool: &PgPool,
    id: i64,
    description: Option<&str>,
    includes: Option<&[String]>,
    excludes: Option<&[String]>,
) -> sqlx::Result<Option<ContentSelector>> {
    let inc = includes.map(|v| serde_json::to_value(v).expect("string vec serializes"));
    let exc = excludes.map(|v| serde_json::to_value(v).expect("string vec serializes"));
    let row = sqlx::query!(
        r#"
        UPDATE content_selector
        SET description = COALESCE($2, description),
            includes    = COALESCE($3, includes),
            excludes    = COALESCE($4, excludes),
            updated_at  = now()
        WHERE id = $1
        RETURNING id, name, description, includes, excludes
        "#,
        id,
        description,
        inc,
        exc,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| ContentSelector {
        id: r.id,
        name: r.name,
        description: r.description,
        includes: r.includes,
        excludes: r.excludes,
    }))
}

/// Delete a content selector by id. Grants referencing it cascade
/// (`repository_privilege.selector_id` FK `ON DELETE CASCADE`), which removes the
/// selector-scoped grant entirely (correct: a grant whose selector is gone would
/// otherwise become unscoped / over-broad). Returns `true` iff a row was deleted.
pub async fn delete_content_selector(pool: &PgPool, id: i64) -> sqlx::Result<bool> {
    let res = sqlx::query!(r#"DELETE FROM content_selector WHERE id = $1"#, id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// How many grants and users a role holds, as the admin role views show it.
#[derive(Debug, Clone, Copy, Default)]
pub struct RoleCounts {
    /// `role.id`.
    pub role_id: i64,
    /// The role's `repository_privilege` rows.
    pub grants: i64,
    /// The users assigned the role (`user_role` rows).
    pub users: i64,
}

/// Count the grants and users of every role, or of the one role `role_id`.
pub async fn role_counts(pool: &PgPool, role_id: Option<i64>) -> sqlx::Result<Vec<RoleCounts>> {
    let rows = sqlx::query!(
        r#"
        SELECT
            r.id,
            (SELECT count(*) FROM repository_privilege rp WHERE rp.role_id = r.id) AS "grants!",
            (SELECT count(*) FROM user_role ur WHERE ur.role_id = r.id) AS "users!"
        FROM role r
        WHERE $1::bigint IS NULL OR r.id = $1
        "#,
        role_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| RoleCounts {
            role_id: r.id,
            grants: r.grants,
            users: r.users,
        })
        .collect())
}

/// A user holding a role, as the role's member list shows it.
#[derive(Debug, Clone)]
pub struct RoleMember {
    /// `app_user.id`.
    pub id: i64,
    /// Canonical username.
    pub username: String,
    /// How the account signs in (`local`, `oidc`, `upstream-basic`).
    pub auth_source: String,
    /// `false` for a deactivated account.
    pub active: bool,
}

/// List the users who hold a role, ordered by username.
pub async fn list_users_for_role(pool: &PgPool, role_id: i64) -> sqlx::Result<Vec<RoleMember>> {
    let rows = sqlx::query!(
        r#"
        SELECT u.id, u.username, u.auth_source, u.active
        FROM user_role ur
        JOIN app_user u ON u.id = ur.user_id
        WHERE ur.role_id = $1
        ORDER BY u.username
        "#,
        role_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| RoleMember {
            id: r.id,
            username: r.username,
            auth_source: r.auth_source,
            active: r.active,
        })
        .collect())
}

/// Every `(user id, role name)` assignment, ordered by role name: the roles
/// column of the admin user list, read in one query.
pub async fn list_user_role_names(pool: &PgPool) -> sqlx::Result<Vec<(i64, String)>> {
    let rows = sqlx::query!(
        r#"
        SELECT ur.user_id, r.name
        FROM user_role ur
        JOIN role r ON r.id = ur.role_id
        ORDER BY r.name
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| (r.user_id, r.name)).collect())
}

/// List the grants scoped by a content selector (every role's), ordered for
/// stable display: what deleting the selector removes.
pub async fn list_grants_for_selector(
    pool: &PgPool,
    selector_id: i64,
) -> sqlx::Result<Vec<GrantRow>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, role_id, repository_id, action, selector_id
        FROM repository_privilege
        WHERE selector_id = $1
        ORDER BY role_id, id
        "#,
        selector_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| GrantRow {
            id: r.id,
            role_id: r.role_id,
            repository_id: r.repository_id,
            action: r.action,
            selector_id: r.selector_id,
        })
        .collect())
}

/// List the roles a user holds, ordered by name.
pub async fn list_roles_for_user(pool: &PgPool, user_id: i64) -> sqlx::Result<Vec<Role>> {
    let rows = sqlx::query!(
        r#"
        SELECT r.id, r.name, r.description, r.builtin
        FROM user_role ur
        JOIN role r ON r.id = ur.role_id
        WHERE ur.user_id = $1
        ORDER BY r.name
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| Role {
            id: r.id,
            name: r.name,
            description: r.description,
            builtin: r.builtin,
        })
        .collect())
}

// --- install-wide settings ---------------------------------------------------

/// Read a `forge_setting` value by key. Returns `None` when the key is unset.
/// Accepts any executor so it composes inside a transaction.
pub async fn get_setting<'e, E>(executor: E, key: &str) -> sqlx::Result<Option<String>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar!(r#"SELECT value FROM forge_setting WHERE key = $1"#, key)
        .fetch_optional(executor)
        .await
}

/// Delete a `forge_setting` row by key. Returns whether it existed.
pub async fn delete_setting(pool: &PgPool, key: &str) -> sqlx::Result<bool> {
    let result = sqlx::query!(r#"DELETE FROM forge_setting WHERE key = $1"#, key)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Upsert a `forge_setting` value by key (e.g. one-shot import markers like
/// the `auth_realms_seeded` flag).
pub async fn set_setting(pool: &PgPool, key: &str, value: &str) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO forge_setting (key, value)
        VALUES ($1, $2)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
        "#,
        key,
        value,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a `forge_setting` value unless the key exists. Returns whether this
/// call inserted it (`false`: another writer was first; read theirs).
pub async fn insert_setting_if_absent(pool: &PgPool, key: &str, value: &str) -> sqlx::Result<bool> {
    let result = sqlx::query!(
        r#"
        INSERT INTO forge_setting (key, value)
        VALUES ($1, $2)
        ON CONFLICT (key) DO NOTHING
        "#,
        key,
        value,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Replace a `forge_setting` value only while it is still `expected`.
/// Returns whether it was replaced (`false` when it changed or is gone).
pub async fn replace_setting<'e, E>(
    executor: E,
    key: &str,
    expected: &str,
    value: &str,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let result = sqlx::query!(
        r#"
        UPDATE forge_setting SET value = $3, updated_at = now()
        WHERE key = $1 AND value = $2
        "#,
        key,
        expected,
        value,
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Delete the unscoped `(anonymous role, repository, read)` grant — the grant
/// migration 0007 synthesized from `repository.anonymous_read` — for
/// `repository_id`. Returns whether a row was removed.
///
/// Called in the same transaction that turns a repository's `anonymous_read`
/// off: the seam honours the flag *and* the grant, so leaving the synthesized
/// grant behind would keep the repository anonymously readable. Selector-scoped
/// anonymous grants are not touched (migration 0007 never creates those; they
/// can only come from an explicit RBAC edit).
pub async fn delete_anonymous_read_grant<'e, E>(
    executor: E,
    repository_id: i64,
) -> sqlx::Result<bool>
where
    E: PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        DELETE FROM repository_privilege rp
        USING role r
        WHERE rp.role_id = r.id
          AND r.name = $2
          AND rp.repository_id = $1
          AND rp.action = 'read'
          AND rp.selector_id IS NULL
        "#,
        repository_id,
        ANONYMOUS_ROLE,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn selector_row_parses_string_arrays() {
        let row = SelectorRow {
            id: 1,
            includes: json!(["company.*", "internal.tools.?"]),
            excludes: json!(["company.secret*"]),
        };
        let (inc, exc) = row.patterns().expect("parse");
        assert_eq!(inc, vec!["company.*", "internal.tools.?"]);
        assert_eq!(exc, vec!["company.secret*"]);
    }

    #[test]
    fn selector_row_empty_includes_is_ok() {
        let row = SelectorRow {
            id: 2,
            includes: json!([]),
            excludes: json!([]),
        };
        let (inc, exc) = row.patterns().expect("parse");
        assert!(inc.is_empty());
        assert!(exc.is_empty());
    }

    #[test]
    fn selector_row_non_array_is_error() {
        let row = SelectorRow {
            id: 3,
            includes: json!("not-an-array"),
            excludes: json!([]),
        };
        let err = row.patterns().unwrap_err();
        assert_eq!(err.selector_id, 3);
        assert_eq!(err.field, "includes");
    }

    #[test]
    fn selector_row_non_string_element_is_error() {
        let row = SelectorRow {
            id: 4,
            includes: json!(["ok", 42]),
            excludes: json!([]),
        };
        let err = row.patterns().unwrap_err();
        assert_eq!(err.field, "includes");
    }
}
