//! Data access for `app_user`.

use sqlx::PgPool;

use crate::model::AppUser;
use crate::username::{canonical_account_username, canonical_username};

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
/// CHECK enforces that a `'local'` user has a non-null `password_hash`, except
/// an invited one ([`crate::invitation_dao::insert_invited_user`]).
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
/// ([`crate::username::canonical_username`]) and must be a UPN
/// ([`crate::username::canonical_account_username`]); an invalid, non-UPN or
/// [reserved](crate::username::RESERVED_USERNAMES) one is refused with
/// [`sqlx::Error::InvalidArgument`] (callers validate first to answer 400).
/// An account with a local password must also have a name a password login
/// accepts ([`crate::username::canonical_password_username`]: no `:`).
///
/// An administrator is a member of the built-in `admin` role: assign it
/// separately ([`crate::authz_dao::assign_role`]), in the same transaction
/// when the account must not exist without it.
pub async fn insert_user<'e, E>(executor: E, new: NewUser) -> sqlx::Result<AppUser>
where
    E: sqlx::PgExecutor<'e>,
{
    let with_password = new.password_hash.is_some() || new.auth_source == "upstream-basic";
    let username = canonical_account_username(&new.username, with_password)
        .map_err(|e| sqlx::Error::InvalidArgument(e.to_string()))?;
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user
            (username, password_hash, active, auth_source, external_subject)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING
            id, username, password_hash, active,
            auth_source, external_subject, kind, created_at, updated_at
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

/// Create an account of the credential-forwarding realm `realm_id`: no local
/// password (`auth_source = 'upstream-basic'`), signed in by forwarding its
/// password, with the local part of `username` as the name sent upstream
/// (`external_subject`, [`crate::username::upn_local_part`]).
///
/// Credential-forwarding realms create no accounts on their own: an
/// administrator creates each one. The username is a UPN, refused like
/// [`insert_user`]'s otherwise.
pub async fn insert_forwarded_user<'e, E>(
    executor: E,
    username: &str,
    realm_id: i64,
    active: bool,
) -> sqlx::Result<AppUser>
where
    E: sqlx::PgExecutor<'e>,
{
    let username = canonical_account_username(username, true)
        .map_err(|e| sqlx::Error::InvalidArgument(e.to_string()))?;
    let subject = crate::username::upn_local_part(&username)
        .unwrap_or(&username)
        .to_string();
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user
            (username, password_hash, active, auth_source, external_subject, realm_id)
        VALUES ($1, NULL, $2, 'upstream-basic', $3, $4)
        RETURNING
            id, username, password_hash, active,
            auth_source, external_subject, kind, created_at, updated_at
        "#,
        username,
        active,
        subject,
        realm_id,
    )
    .fetch_one(executor)
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
            auth_source, external_subject, kind, created_at, updated_at
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

/// Create an account of the trusted-header realm `realm_id`: no password
/// (`auth_source = 'trusted-header'`), signed in by the realm when the header
/// of the proxy in front names it. An administrator creates it, or the realm
/// on the account's first request when it provisions accounts. The username
/// is a UPN, refused like [`insert_user`]'s otherwise; a name another account
/// holds is a unique violation.
pub async fn insert_trusted_header_user<'e, E>(
    executor: E,
    username: &str,
    realm_id: i64,
) -> sqlx::Result<AppUser>
where
    E: sqlx::PgExecutor<'e>,
{
    let username = canonical_account_username(username, false)
        .map_err(|e| sqlx::Error::InvalidArgument(e.to_string()))?;
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user (username, password_hash, active, auth_source, realm_id)
        VALUES ($1, NULL, true, 'trusted-header', $2)
        RETURNING
            id, username, password_hash, active,
            auth_source, external_subject, kind, created_at, updated_at
        "#,
        username,
        realm_id,
    )
    .fetch_one(executor)
    .await
}

/// Find the account the trusted-header realm `realm_id` names `username`: a
/// `'trusted-header'` account or a service account
/// ([`insert_service_account`]) of exactly that realm, that is not an orphan
/// of a deleted realm. A same-named account of another source or realm is
/// never returned (`None` ⇒ deny).
pub async fn find_trusted_header_user(
    pool: &PgPool,
    username: &str,
    realm_id: i64,
) -> sqlx::Result<Option<AppUser>> {
    let Some(username) = lookup_key(username) else {
        return Ok(None);
    };
    sqlx::query_as!(
        AppUser,
        r#"
        SELECT
            id, username, password_hash, active,
            auth_source, external_subject, kind, created_at, updated_at
        FROM app_user
        WHERE username = $1
          AND auth_source IN ('trusted-header', 'service')
          AND NOT realm_orphaned
          AND realm_id = $2
        "#,
        username,
        realm_id,
    )
    .fetch_optional(pool)
    .await
}

/// `app_user.kind` of a service account: an account for a machine or a
/// network rather than a person, which nobody signs in to.
pub const SERVICE_ACCOUNT_KIND: &str = "service";

/// Create a service account (#508): an account for a machine or a network
/// (a CI pipeline, a build agent, a network the load balancer admits) that
/// nobody signs in to. It has no password, invitation or email
/// (`auth_source = 'service'`, DB CHECK `app_user_service_account_check`),
/// and authenticates with the API tokens an administrator issues for it, or
/// through the trusted-header realm `realm_id` when it belongs to one, which
/// alone may name it ([`find_trusted_header_user`]). `description` says what
/// it is for and who owns it.
///
/// The username is a UPN in the name space of every account, refused like
/// [`insert_user`]'s otherwise; a name another account holds is a unique
/// violation. A realm that is not a trusted-header one is a check violation.
pub async fn insert_service_account<'e, E>(
    executor: E,
    username: &str,
    description: Option<&str>,
    realm_id: Option<i64>,
) -> sqlx::Result<AppUser>
where
    E: sqlx::PgExecutor<'e>,
{
    let username = canonical_account_username(username, false)
        .map_err(|e| sqlx::Error::InvalidArgument(e.to_string()))?;
    sqlx::query_as!(
        AppUser,
        r#"
        INSERT INTO app_user
            (username, password_hash, active, auth_source, kind, description, realm_id)
        VALUES ($1, NULL, true, 'service', 'service', $2, $3)
        RETURNING
            id, username, password_hash, active,
            auth_source, external_subject, kind, created_at, updated_at
        "#,
        username,
        description,
        realm_id,
    )
    .fetch_one(executor)
    .await
}

/// Set what the service account `user_id` is for; `None` clears it. Returns
/// whether such a service account exists.
pub async fn set_service_account_description<'e, E>(
    executor: E,
    user_id: i64,
    description: Option<&str>,
) -> sqlx::Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        UPDATE app_user
        SET description = $2,
            updated_at = now()
        WHERE id = $1 AND kind = 'service'
        "#,
        user_id,
        description,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Move the service account `user_id` to the trusted-header realm `realm_id`
/// (`None`: to no realm, so only its tokens authenticate it). The realm it
/// belonged to stops naming it at once; an orphan of a deleted realm is
/// adopted. Returns whether such a service account exists; a realm that is
/// not a trusted-header one is a check violation.
pub async fn set_service_account_realm<'e, E>(
    executor: E,
    user_id: i64,
    realm_id: Option<i64>,
) -> sqlx::Result<bool>
where
    E: sqlx::PgExecutor<'e>,
{
    let res = sqlx::query!(
        r#"
        UPDATE app_user
        SET realm_id = $2,
            realm_orphaned = false,
            updated_at = now()
        WHERE id = $1 AND kind = 'service'
        "#,
        user_id,
        realm_id,
    )
    .execute(executor)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// What the admin views show of an account besides its [`AppUser`] row.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AccountDetails {
    pub id: i64,
    /// What a service account is for and who owns it.
    pub description: Option<String>,
    /// The realm the account belongs to, unless it was deleted.
    pub realm_id: Option<i64>,
    pub realm: Option<String>,
    /// When the account last authenticated: the latest use of one of its
    /// API tokens, or the last request a trusted-header realm named it in
    /// ([`touch_last_authenticated`]).
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The [`AccountDetails`] of every account, or of `user_id` alone.
pub async fn account_details(
    pool: &PgPool,
    user_id: Option<i64>,
) -> sqlx::Result<Vec<AccountDetails>> {
    sqlx::query_as(
        r#"
        SELECT u.id, u.description, r.id AS realm_id, r.name AS realm,
               GREATEST(u.last_auth_source_at, max(t.last_used_at)) AS last_used_at
        FROM app_user u
        LEFT JOIN auth_realm r ON r.id = u.realm_id
        LEFT JOIN token t ON t.user_id = u.id
        WHERE $1::bigint IS NULL OR u.id = $1
        GROUP BY u.id, r.id
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Record that a trusted-header realm just authenticated `user_id`
/// (`app_user.last_auth_source_at`): written only when the last write is
/// older than `min_age_secs`, so the requests of a busy account do not all
/// write its row.
pub async fn touch_last_authenticated(
    pool: &PgPool,
    user_id: i64,
    min_age_secs: i64,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        UPDATE app_user
        SET last_auth_source_at = now()
        WHERE id = $1
          AND (last_auth_source_at IS NULL
               OR last_auth_source_at < now() - make_interval(secs => $2))
        "#,
        user_id,
        min_age_secs as f64,
    )
    .execute(pool)
    .await?;
    Ok(())
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
            auth_source, external_subject, kind, created_at, updated_at
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
            auth_source, external_subject, kind, created_at, updated_at
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
            auth_source, external_subject, kind, created_at, updated_at
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
/// logins), and no login ever flips it back: credential forwarding signs in
/// existing accounts only ([`find_upstream_user`]) and OIDC resolution leaves
/// an existing row's `active` alone.
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
            auth_source, external_subject, kind, created_at, updated_at
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
/// account in (see [`find_upstream_user`]). A no-op write when the value
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
/// keeping a password hash of the logins its upstream accepts.
pub const CAPTURE_PASSWORD_HASH_KEY: &str = "capture_password_hash";

/// Keep `hash` — the argon2id PHC string of a password the upstream of realm
/// `realm_id` just accepted for `user_id` — as the account's captured password
/// (`app_user.captured_password_hash`). Returns whether it was stored.
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
