//! Data access for fine-grained RBAC (slice 12.4): reading a principal's
//! effective grant set and the small CRUD surface the admin API (later phase)
//! and the evaluator need.
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
//! tables and the `forge-cache` layer (later phase) sits in front of the
//! resolved set with explicit cross-node invalidation.

use serde_json::Value as JsonValue;
use sqlx::{PgExecutor, PgPool};

/// The fixed slug of the built-in admin role (allow-all short-circuit).
pub const ADMIN_ROLE: &str = "admin";
/// The fixed slug of the built-in anonymous role (applied to anonymous callers).
pub const ANONYMOUS_ROLE: &str = "anonymous";
/// The fixed slug of the built-in legacy-open-access role.
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
///
/// Note: this reads **role-derived** privileges only. The slice-1 `is_admin`
/// column on `app_user` is intentionally *not* consulted here — the dual-read
/// fallback during the migration window is layered on by the caller (later
/// phase), keeping this query a clean single-source read.
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
/// `anonymous` role `read` on specific repos (the data migration converts the
/// slice-1 `anonymous_read` flag into exactly these grants).
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

/// Whether a user holds a given role (by role name). Used by the dual-read admin
/// check and tests.
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
