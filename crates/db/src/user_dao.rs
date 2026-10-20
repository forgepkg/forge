//! Data access for `app_user`.

use std::collections::HashSet;

use sqlx::PgPool;

use crate::model::AppUser;
use crate::username::{canonical_password_username, canonical_username};

/// The canonical form of a username used as a lookup key, or `None` when it
/// can never name an account (empty, control characters, oversized).
fn lookup_key(username: &str) -> Option<String> {
    canonical_username(username).ok()
}

/// All settable fields when creating a user row.
///
/// `password_hash` is `None` for users with no local password (upstream-basic /
/// oidc). `auth_source` defaults conceptually to `'local'`; callers provisioning
/// a non-local user set it explicitly along with `external_subject`. The DB
/// CHECK enforces that a `'local'` user has a non-null `password_hash`.
#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub password_hash: Option<String>,
    pub is_admin: bool,
    pub active: bool,
    pub auth_source: String,
    pub external_subject: Option<String>,
}

impl NewUser {
    /// Convenience constructor for a slice-1 local (argon2 password) user.
    pub fn local(username: String, password_hash: String, is_admin: bool, active: bool) -> Self {
        Self {
            username,
            password_hash: Some(password_hash),
            is_admin,
            active,
            auth_source: "local".to_string(),
            external_subject: None,
        }
    }
}

/// Insert a user, returning the persisted row.
///
/// The username is stored in its canonical form
/// ([`crate::username::canonical_username`]); an invalid one is refused with
/// [`sqlx::Error::InvalidArgument`] (callers validate first to answer 400).
/// An account with a local password must also have a name a password login
/// accepts ([`canonical_password_username`]: no `:`).
pub async fn insert_user(pool: &PgPool, new: NewUser) -> sqlx::Result<AppUser> {
    let username = if new.password_hash.is_some() {
        canonical_password_username(&new.username)
    } else {
        canonical_username(&new.username)
    }
    .map_err(|e| sqlx::Error::InvalidArgument(e.to_string()))?;
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user
            (username, password_hash, is_admin, active, auth_source, external_subject)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        "#,
        username,
        new.password_hash,
        new.is_admin,
        new.active,
        new.auth_source,
        new.external_subject,
    )
    .fetch_one(pool)
    .await
}

/// Provision (or refresh) a user authenticated by the `upstream-basic` provider
/// (slice 12.3, phase 5).
///
/// Called by the auth chain after the upstream **definitively accepts** a
/// credential. Idempotent and **never touches a non-upstream account**:
///
/// * **New username** → insert a fresh user with `auth_source = 'upstream-basic'`,
///   `password_hash = NULL` (no local password — the DB CHECK only requires one
///   for `'local'` users), `external_subject = username`, `active = true`,
///   `realm_id` = the vouching realm, and `is_admin = suggested_is_admin`.
/// * **Existing `'upstream-basic'` username of the same realm** (or, for the
///   realm-less static wiring, of no realm) → stamp `last_auth_source_at =
///   now()`, and — only when `admin_authoritative` (the realm maps an admin
///   group and the groups were freshly fetched) — set `is_admin` to the
///   upstream's current verdict, so revocation upstream demotes here too.
///   Without an authoritative reading the stored admin flag is left alone.
/// * **Existing username owned by anything else** (a `'local'` or `'oidc'`
///   account, an upstream user of a different realm, or an **orphan** whose
///   realm was deleted — `realm_orphaned`, migration 0023) → **no row** is
///   returned: an upstream login must never be mapped onto (or take over) an
///   account it did not create. A missing realm is never a wildcard. The
///   caller denies.
///
/// The unique constraint on `username` makes the `ON CONFLICT` path race-safe
/// across instances. The username is canonicalized first; an invalid one, or
/// one containing `:` (the upstream verified the part before the colon, see
/// [`canonical_password_username`]), provisions nothing (`None` ⇒ deny).
pub async fn provision_upstream_user(
    pool: &PgPool,
    username: &str,
    suggested_is_admin: bool,
    admin_authoritative: bool,
    realm_id: Option<i64>,
) -> sqlx::Result<Option<AppUser>> {
    Ok(provision_upstream_user_tracked(
        pool,
        username,
        suggested_is_admin,
        admin_authoritative,
        realm_id,
    )
    .await?
    .map(|(user, _)| user))
}

/// [`provision_upstream_user`], also reporting whether this call created the
/// account (`true`) rather than refreshing an existing one. Takes any
/// executor so the caller can create the user and its initial roles in one
/// transaction.
pub async fn provision_upstream_user_tracked<'e, E>(
    executor: E,
    username: &str,
    suggested_is_admin: bool,
    admin_authoritative: bool,
    realm_id: Option<i64>,
) -> sqlx::Result<Option<(AppUser, bool)>>
where
    E: sqlx::PgExecutor<'e>,
{
    let Ok(username) = canonical_password_username(username) else {
        return Ok(None);
    };
    let row = sqlx::query!(
        r#"
        INSERT INTO app_user
            (username, password_hash, is_admin, active, auth_source,
             external_subject, last_auth_source_at, realm_id)
        VALUES ($1, NULL, $2, true, 'upstream-basic', $1, now(), $4)
        ON CONFLICT (username) DO UPDATE SET
            is_admin = CASE WHEN $3 THEN EXCLUDED.is_admin ELSE app_user.is_admin END,
            last_auth_source_at = now(),
            -- Touch updated_at only when the admin flag actually changes.
            updated_at = CASE
                WHEN $3 AND EXCLUDED.is_admin <> app_user.is_admin THEN now()
                ELSE app_user.updated_at
            END
        WHERE app_user.auth_source = 'upstream-basic'
          AND NOT app_user.realm_orphaned
          AND app_user.realm_id IS NOT DISTINCT FROM EXCLUDED.realm_id
        RETURNING
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at,
            (xmax = 0) AS "inserted!"
        "#,
        username,
        suggested_is_admin,
        admin_authoritative,
        realm_id,
    )
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|r| {
        (
            AppUser {
                id: r.id,
                username: r.username,
                password_hash: r.password_hash,
                is_admin: r.is_admin,
                active: r.active,
                auth_source: r.auth_source,
                external_subject: r.external_subject,
                created_at: r.created_at,
                updated_at: r.updated_at,
            },
            r.inserted,
        )
    }))
}

/// Find the `'upstream-basic'` user an upstream realm vouched for: the username
/// must belong to an upstream-provisioned account of exactly that realm (no
/// realm on either side only for the realm-less static wiring) that is not an
/// orphan of a deleted realm. Local and OIDC accounts of the same name are
/// never returned (`None` ⇒ deny).
pub async fn find_upstream_user(
    pool: &PgPool,
    username: &str,
    realm_id: Option<i64>,
) -> sqlx::Result<Option<AppUser>> {
    let Some(username) = lookup_key(username) else {
        return Ok(None);
    };
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        FROM app_user
        WHERE username = $1
          AND auth_source = 'upstream-basic'
          AND NOT realm_orphaned
          AND realm_id IS NOT DISTINCT FROM $2::bigint
        "#,
        username,
        realm_id,
    )
    .fetch_optional(pool)
    .await
}

/// Find a user by their unique username (compared in canonical form, so
/// `Alice`, `alice` and ` alice ` find the same account).
pub async fn find_user_by_username(pool: &PgPool, username: &str) -> sqlx::Result<Option<AppUser>> {
    let Some(username) = lookup_key(username) else {
        return Ok(None);
    };
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        FROM app_user
        WHERE username = $1
        "#,
        username,
    )
    .fetch_optional(pool)
    .await
}

/// Find a user by id.
pub async fn find_user_by_id(pool: &PgPool, id: i64) -> sqlx::Result<Option<AppUser>> {
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        FROM app_user
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

/// List all users ordered by username (admin listing).
pub async fn list_users(pool: &PgPool) -> sqlx::Result<Vec<AppUser>> {
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        FROM app_user
        ORDER BY username
        "#,
    )
    .fetch_all(pool)
    .await
}

/// Set a user's `is_admin` flag (bumping `updated_at` only when it changes) and
/// return the resulting row.
///
/// Used by OIDC login to **recompute** admin on every sign-in from the IdP's
/// group/role claim (slice 12.2 §3.6): a user added to or removed from the admin
/// group gains/loses admin on their next login.
pub async fn update_is_admin<'e, E>(executor: E, id: i64, is_admin: bool) -> sqlx::Result<AppUser>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        AppUser,
        r#"
        UPDATE app_user
        SET is_admin = $2,
            updated_at = CASE WHEN is_admin <> $2 THEN now() ELSE updated_at END
        WHERE id = $1
        RETURNING
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        "#,
        id,
        is_admin,
    )
    .fetch_one(executor)
    .await
}

/// Set a user's `active` flag (bumping `updated_at` only when it changes) and
/// return the resulting row, or `None` when no such user exists.
///
/// The admin deactivate/activate path. `active = false` is honored by every
/// authentication path (tokens, passwords, sessions, OIDC and upstream
/// logins), and no provisioning path ever flips it back: the upstream-basic
/// upsert ([`provision_upstream_user`]) and OIDC resolution leave an existing
/// row's `active` alone.
pub async fn set_active<'e, E>(executor: E, id: i64, active: bool) -> sqlx::Result<Option<AppUser>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        AppUser,
        r#"
        UPDATE app_user
        SET active = $2,
            updated_at = CASE WHEN active <> $2 THEN now() ELSE updated_at END
        WHERE id = $1
        RETURNING
            id, username, password_hash, is_admin, active,
            auth_source, external_subject, created_at, updated_at
        "#,
        id,
        active,
    )
    .fetch_optional(executor)
    .await
}

/// Delete a user by id (cascading their tokens). Returns whether a row went.
pub async fn delete_user<'e, E>(executor: E, id: i64) -> sqlx::Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    let res = sqlx::query!(r#"DELETE FROM app_user WHERE id = $1"#, id)
        .execute(executor)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Record which auth realm vouches for this user. For credential-forwarding
/// accounts this is an authorization input: only that realm may sign the
/// account in (see [`provision_upstream_user`]). A no-op write when the value
/// is unchanged.
pub async fn set_user_realm(pool: &PgPool, user_id: i64, realm_id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE app_user
        SET realm_id = $2
        WHERE id = $1 AND realm_id IS DISTINCT FROM $2
        "#,
        user_id,
        realm_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// `forge_setting` key prefix of the bootstrap admin's "created once" markers
/// (the server's `BOOTSTRAP_ADMIN_CREATED_KEY`, followed by `:` and the
/// username).
const BOOTSTRAP_MARKER_PREFIX: &str = "bootstrap_admin_created:";

/// An account renamed by [`canonicalize_stored_usernames`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsernameRepair {
    pub id: i64,
    pub from: String,
    pub to: String,
}

/// Bring every stored username, and the bootstrap admin's markers, into the
/// canonical form ([`canonical_username`]) that every lookup uses. Runs after
/// the migrations ([`crate::migrate`]); a read-only scan when nothing needs
/// fixing.
///
/// Migration 0021 canonicalized existing names in SQL, where `lower()` follows
/// the database's collation (under a `C` ctype it lowercases ASCII only, so
/// `Jürgen` became `jürgen` but `JÜRGEN` became `jÜrgen`) and `btrim` trims
/// only ASCII spaces. Lookups match the Rust form exactly, so such an account
/// could no longer sign in.
///
/// An account whose name is already canonical keeps it. Among the others that
/// map to the same canonical name the oldest takes it while it is free, and
/// the rest become `<canonical>#<id>` (with a further `#<n>` if even that is
/// taken), as in 0021. Names without a canonical form (control characters,
/// oversized) are left alone: they cannot sign in either way.
pub async fn canonicalize_stored_usernames(pool: &PgPool) -> sqlx::Result<Vec<UsernameRepair>> {
    if !needs_canonicalizing(pool).await? {
        return Ok(Vec::new());
    }
    let mut tx = pool.begin().await?;
    // Keep concurrent writers (and another instance doing the same repair)
    // out until the renames commit.
    sqlx::query!("LOCK TABLE app_user IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    let rows = sqlx::query!("SELECT id, username FROM app_user ORDER BY id")
        .fetch_all(&mut *tx)
        .await?;
    let repairs = plan_username_repairs(rows.into_iter().map(|r| (r.id, r.username)).collect());
    // Two passes so neither unique index sees a transient duplicate.
    for r in &repairs {
        sqlx::query!(
            "UPDATE app_user SET username = '~canonicalizing~' || id WHERE id = $1",
            r.id
        )
        .execute(&mut *tx)
        .await?;
    }
    for r in &repairs {
        sqlx::query!(
            "UPDATE app_user SET username = $2, updated_at = now() WHERE id = $1",
            r.id,
            r.to
        )
        .execute(&mut *tx)
        .await?;
    }

    let markers = sqlx::query_scalar!(
        "SELECT key FROM forge_setting WHERE starts_with(key, $1)",
        BOOTSTRAP_MARKER_PREFIX
    )
    .fetch_all(&mut *tx)
    .await?;
    for key in markers {
        let Some(canonical) = canonical_marker(&key) else {
            continue;
        };
        sqlx::query!(
            "INSERT INTO forge_setting (key, value)
             SELECT $2, value FROM forge_setting WHERE key = $1
             ON CONFLICT (key) DO NOTHING",
            key,
            canonical
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!("DELETE FROM forge_setting WHERE key = $1", key)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(repairs)
}

/// Whether any username or bootstrap marker is not in canonical form.
async fn needs_canonicalizing(pool: &PgPool) -> sqlx::Result<bool> {
    let usernames = sqlx::query_scalar!("SELECT username FROM app_user")
        .fetch_all(pool)
        .await?;
    if usernames
        .iter()
        .any(|u| canonical_username(u).is_ok_and(|c| &c != u))
    {
        return Ok(true);
    }
    let markers = sqlx::query_scalar!(
        "SELECT key FROM forge_setting WHERE starts_with(key, $1)",
        BOOTSTRAP_MARKER_PREFIX
    )
    .fetch_all(pool)
    .await?;
    Ok(markers.iter().any(|k| canonical_marker(k).is_some()))
}

/// The canonical spelling of a bootstrap marker key, when it differs.
fn canonical_marker(key: &str) -> Option<String> {
    let name = key.strip_prefix(BOOTSTRAP_MARKER_PREFIX)?;
    let canonical = canonical_username(name).ok()?;
    (canonical != name).then(|| format!("{BOOTSTRAP_MARKER_PREFIX}{canonical}"))
}

/// The renames [`canonicalize_stored_usernames`] applies to `rows`
/// (`(id, username)`, in id order).
fn plan_username_repairs(rows: Vec<(i64, String)>) -> Vec<UsernameRepair> {
    // Names that stay as they are: the canonical ones, and those that have no
    // canonical form. A target is always canonical, so it never equals a name
    // that is being vacated.
    let mut taken: HashSet<String> = rows
        .iter()
        .filter(|(_, u)| canonical_username(u).map_or(true, |c| &c == u))
        .map(|(_, u)| u.clone())
        .collect();
    let mut repairs = Vec::new();
    for (id, username) in rows {
        let Ok(canonical) = canonical_username(&username) else {
            continue;
        };
        if canonical == username {
            continue;
        }
        let mut to = canonical.clone();
        let mut n = 1u32;
        while taken.contains(&to) {
            to = if n == 1 {
                format!("{canonical}#{id}")
            } else {
                format!("{canonical}#{id}#{n}")
            };
            n += 1;
        }
        taken.insert(to.clone());
        repairs.push(UsernameRepair {
            id,
            from: username,
            to,
        });
    }
    repairs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(rows: &[(i64, &str)]) -> Vec<(i64, String)> {
        plan_username_repairs(rows.iter().map(|(id, u)| (*id, u.to_string())).collect())
            .into_iter()
            .map(|r| (r.id, r.to))
            .collect()
    }

    #[test]
    fn repairs_what_a_c_collation_left_uppercase() {
        // 0021 under a "C" ctype lowercased ASCII only.
        assert_eq!(
            plan(&[(1, "jÜrgen"), (2, "alice"), (3, "Ölaf")]),
            vec![(1, "jürgen".into()), (3, "ölaf".into())]
        );
    }

    #[test]
    fn an_account_holding_the_canonical_name_keeps_it() {
        assert_eq!(
            plan(&[(1, "Özdemir"), (2, "özdemir")]),
            vec![(1, "özdemir#1".into())]
        );
        // Among non-canonical ones the oldest wins.
        assert_eq!(
            plan(&[(4, "bob\u{a0}"), (7, "BOB")]),
            vec![(4, "bob".into()), (7, "bob#7".into())]
        );
    }

    #[test]
    fn suffixes_never_collide_with_existing_names() {
        assert_eq!(
            plan(&[(2, "alice"), (3, "alice#5"), (5, "Alice")]),
            vec![(5, "alice#5#2".into())]
        );
    }

    #[test]
    fn names_without_a_canonical_form_are_left_alone() {
        assert!(plan(&[(1, "bad\nname"), (2, "ok")]).is_empty());
    }
}
