//! Data access for `app_user`.

use std::collections::HashSet;

use sqlx::PgPool;

use crate::model::AppUser;
use crate::username::{
    canonical_account_username, canonical_forwarded_username, canonical_username,
};

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
    pub active: bool,
    pub auth_source: String,
    pub external_subject: Option<String>,
}

impl NewUser {
    /// Convenience constructor for a local (argon2 password) user.
    pub fn local(username: String, password_hash: String, active: bool) -> Self {
        Self {
            username,
            password_hash: Some(password_hash),
            active,
            auth_source: "local".to_string(),
            external_subject: None,
        }
    }
}

/// Insert a user, returning the persisted row.
///
/// The username is stored in its canonical form
/// ([`crate::username::canonical_username`]); an invalid or
/// [reserved](crate::username::RESERVED_USERNAMES) one is refused with
/// [`sqlx::Error::InvalidArgument`] (callers validate first to answer 400).
/// An account with a local password must also have a name a password login
/// accepts ([`crate::username::canonical_password_username`]: no `:`).
/// Every account but a credential-forwarding one (`upstream-basic`) must be
/// named by a UPN ([`crate::username::canonical_account_username`]); that one
/// keeps the name its upstream accepted
/// ([`crate::username::canonical_forwarded_username`]).
///
/// An administrator is a member of the built-in `admin` role: assign it
/// separately ([`crate::authz_dao::assign_role`]), in the same transaction
/// when the account must not exist without it.
pub async fn insert_user<'e, E>(executor: E, new: NewUser) -> sqlx::Result<AppUser>
where
    E: sqlx::PgExecutor<'e>,
{
    let username = if new.auth_source == "upstream-basic" {
        canonical_forwarded_username(&new.username)
    } else {
        canonical_account_username(&new.username, new.password_hash.is_some())
    }
    .map_err(|e| sqlx::Error::InvalidArgument(e.to_string()))?;
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user
            (username, password_hash, active, auth_source, external_subject)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING
            id, username, password_hash, active,
            auth_source, external_subject, created_at, updated_at
        "#,
        username,
        new.password_hash,
        new.active,
        new.auth_source,
        new.external_subject,
    )
    .fetch_one(executor)
    .await
}

/// Provision (or refresh) a user authenticated by the `upstream-basic` provider.
///
/// Called by the auth chain after the upstream **definitively accepts** a
/// credential. Idempotent and **never touches a non-upstream account**:
///
/// * **New username** → insert a fresh user with `auth_source = 'upstream-basic'`,
///   `password_hash = NULL` (no local password — the DB CHECK only requires one
///   for `'local'` users), `external_subject = username`, `active = true`, and
///   `realm_id` = the vouching realm.
/// * **Existing `'upstream-basic'` username of the same realm** (or, for the
///   realm-less static wiring, of no realm) → stamp `last_auth_source_at =
///   now()`.
/// * **Existing username owned by anything else** (a `'local'` or `'oidc'`
///   account, an upstream user of a different realm, or an **orphan** whose
///   realm was deleted — `realm_orphaned`, migration 0023) → **no row** is
///   returned: an upstream login must never be mapped onto (or take over) an
///   account it did not create. A missing realm is never a wildcard. The
///   caller denies.
///
/// The upstream's admin verdict is the caller's to apply, as membership in the
/// built-in `admin` role. The unique constraint on `username` makes the
/// `ON CONFLICT` path race-safe across instances. The username is
/// canonicalized first; an invalid one, a
/// [reserved](crate::username::RESERVED_USERNAMES) one, or one containing `:`
/// (the upstream verified the part before the colon, see
/// [`crate::username::canonical_password_username`]), provisions nothing
/// (`None` ⇒ deny). It need not be a UPN: the account keeps the name the
/// upstream accepted ([`crate::username::canonical_forwarded_username`]).
pub async fn provision_upstream_user(
    pool: &PgPool,
    username: &str,
    realm_id: Option<i64>,
) -> sqlx::Result<Option<AppUser>> {
    let Ok(username) = canonical_forwarded_username(username) else {
        return Ok(None);
    };
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user
            (username, password_hash, active, auth_source,
             external_subject, last_auth_source_at, realm_id)
        VALUES ($1, NULL, true, 'upstream-basic', $1, now(), $2)
        ON CONFLICT (username) DO UPDATE SET
            last_auth_source_at = now()
        WHERE app_user.auth_source = 'upstream-basic'
          AND NOT app_user.realm_orphaned
          AND app_user.realm_id IS NOT DISTINCT FROM EXCLUDED.realm_id
        RETURNING
            id, username, password_hash, active,
            auth_source, external_subject, created_at, updated_at
        "#,
        username,
        realm_id,
    )
    .fetch_optional(pool)
    .await
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
            id, username, password_hash, active,
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
            id, username, password_hash, active,
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
            id, username, password_hash, active,
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
            id, username, password_hash, active,
            auth_source, external_subject, created_at, updated_at
        FROM app_user
        ORDER BY username
        "#,
    )
    .fetch_all(pool)
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
            id, username, password_hash, active,
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

/// The `credential_forwarding` realm config key that opts the realm in to
/// keeping a password hash of the logins its upstream accepts (migration 0035).
pub const CAPTURE_PASSWORD_HASH_KEY: &str = "capture_password_hash";

/// Keep `hash` — the argon2id PHC string of a password the upstream of realm
/// `realm_id` just accepted for `user_id` — as the account's captured password
/// (migration 0035). Returns whether it was stored.
///
/// Stored only while the realm opts in (`capture_password_hash`) and the
/// account is still that realm's upstream account, and the realm row is
/// share-locked for the write: a concurrent edit that turns the option off
/// (and clears the hashes, [`clear_captured_password_hashes`]) either waits
/// for this write and then clears it, or commits first and this writes
/// nothing. A login that read the realm before the edit cannot leave a hash
/// behind.
pub async fn store_captured_password_hash(
    pool: &PgPool,
    user_id: i64,
    realm_id: i64,
    hash: &str,
) -> sqlx::Result<bool> {
    let res = sqlx::query(
        r#"
        WITH realm AS (
            SELECT id FROM auth_realm
            WHERE id = $2
              AND kind = 'credential_forwarding'
              AND config @> jsonb_build_object($4::text, true)
            FOR SHARE
        )
        UPDATE app_user u
        SET captured_password_hash = $3,
            captured_password_at   = now()
        FROM realm
        WHERE u.id = $1
          AND u.realm_id = realm.id
          AND u.auth_source = 'upstream-basic'
          AND u.password_hash IS NULL
          AND NOT u.realm_orphaned
        "#,
    )
    .bind(user_id)
    .bind(realm_id)
    .bind(hash)
    .bind(CAPTURE_PASSWORD_HASH_KEY)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// The captured password of the upstream account `username` of `realm_id`
/// (not an orphan of a deleted realm), for a realm that signs its accounts in
/// with their captured passwords instead of asking the upstream
/// (`captured_password_only`). `None` when there is no such account or it
/// keeps no password.
pub async fn find_captured_password_hash(
    pool: &PgPool,
    username: &str,
    realm_id: i64,
) -> sqlx::Result<Option<String>> {
    let Some(username) = lookup_key(username) else {
        return Ok(None);
    };
    Ok(sqlx::query_scalar(
        r#"
        SELECT captured_password_hash
        FROM app_user
        WHERE username = $1
          AND auth_source = 'upstream-basic'
          AND NOT realm_orphaned
          AND realm_id = $2
        "#,
    )
    .bind(username)
    .bind(realm_id)
    .fetch_optional(pool)
    .await?
    .flatten())
}

/// Delete the captured passwords of every account of `realm_id`: the realm no
/// longer opts in. Returns how many were deleted.
pub async fn clear_captured_password_hashes<'e, E>(executor: E, realm_id: i64) -> sqlx::Result<u64>
where
    E: sqlx::PgExecutor<'e>,
{
    let res = sqlx::query(
        r#"
        UPDATE app_user
        SET captured_password_hash = NULL,
            captured_password_at   = NULL
        WHERE realm_id = $1
          AND captured_password_hash IS NOT NULL
        "#,
    )
    .bind(realm_id)
    .execute(executor)
    .await?;
    Ok(res.rows_affected())
}

/// When each account that carries a captured password last had it refreshed
/// (`(user id, captured_password_at)`), for the admin user listing.
pub async fn captured_password_times(
    pool: &PgPool,
) -> sqlx::Result<Vec<(i64, chrono::DateTime<chrono::Utc>)>> {
    sqlx::query_as(
        r#"
        SELECT id, captured_password_at
        FROM app_user
        WHERE captured_password_at IS NOT NULL
        "#,
    )
    .fetch_all(pool)
    .await
}

/// When the captured password of `user_id` was last refreshed; `None` when
/// the account carries none.
pub async fn captured_password_at(
    pool: &PgPool,
    user_id: i64,
) -> sqlx::Result<Option<chrono::DateTime<chrono::Utc>>> {
    Ok(sqlx::query_scalar(
        r#"
        SELECT captured_password_at
        FROM app_user
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .flatten())
}

/// How many accounts of a credential-forwarding realm there are, and how many
/// of them carry a captured password (see [`convert_realm_users_to_local`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturedPasswordCounts {
    pub accounts: i64,
    pub captured: i64,
}

/// [`CapturedPasswordCounts`] of the (non-orphaned) upstream accounts of
/// `realm_id`.
pub async fn captured_password_counts(
    pool: &PgPool,
    realm_id: i64,
) -> sqlx::Result<CapturedPasswordCounts> {
    let (accounts, captured): (i64, i64) = sqlx::query_as(
        r#"
        SELECT count(*), count(captured_password_hash)
        FROM app_user
        WHERE realm_id = $1
          AND auth_source = 'upstream-basic'
          AND NOT realm_orphaned
        "#,
    )
    .bind(realm_id)
    .fetch_one(pool)
    .await?;
    Ok(CapturedPasswordCounts { accounts, captured })
}

/// An account [`convert_to_local`] or [`convert_realm_users_to_local`]
/// switched to a local password.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct ConvertedUser {
    pub id: i64,
    pub username: String,
}

/// Switch the upstream account `user_id` to a local one whose password is its
/// captured password: `password_hash` takes the captured hash, the account
/// leaves its realm (`auth_source = 'local'`, no realm, not orphaned) and
/// keeps its id, roles, tokens and admin and active flags. From then on the
/// local-password realm owns the name, so the password is never forwarded
/// upstream again. `None` when there is no such upstream account or it has no
/// captured password; an orphan of a deleted realm is converted all the same.
pub async fn convert_to_local<'e, E>(
    executor: E,
    user_id: i64,
) -> sqlx::Result<Option<ConvertedUser>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        r#"
        UPDATE app_user
        SET password_hash          = captured_password_hash,
            captured_password_hash = NULL,
            captured_password_at   = NULL,
            auth_source            = 'local',
            external_subject       = NULL,
            realm_id               = NULL,
            realm_orphaned         = false,
            updated_at             = now()
        WHERE id = $1
          AND auth_source = 'upstream-basic'
          AND captured_password_hash IS NOT NULL
        RETURNING id, username
        "#,
    )
    .bind(user_id)
    .fetch_optional(executor)
    .await
}

/// [`convert_to_local`] for every account of `realm_id` that carries a
/// captured password; the others are left as they are.
pub async fn convert_realm_users_to_local<'e, E>(
    executor: E,
    realm_id: i64,
) -> sqlx::Result<Vec<ConvertedUser>>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        r#"
        UPDATE app_user
        SET password_hash          = captured_password_hash,
            captured_password_hash = NULL,
            captured_password_at   = NULL,
            auth_source            = 'local',
            external_subject       = NULL,
            realm_id               = NULL,
            realm_orphaned         = false,
            updated_at             = now()
        WHERE realm_id = $1
          AND auth_source = 'upstream-basic'
          AND NOT realm_orphaned
          AND captured_password_hash IS NOT NULL
        RETURNING id, username
        "#,
    )
    .bind(realm_id)
    .fetch_all(executor)
    .await
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
