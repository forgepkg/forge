//! Short-lived workload API keys (`workload_api_key`): the trusted-publishing
//! token exchange stores one row per redeemed CI token.
//!
//! Only SHA-256 digests are stored. The unique `(issuer_sha256, jti_sha256)`
//! index makes [`insert`] the one-time redemption of a CI token.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool, Row};

use crate::trusted_publisher_dao::{self, TrustedPublisherMatch};

/// A key to store for a freshly verified, exchanged CI token.
#[derive(Debug, Clone)]
pub struct NewWorkloadApiKey<'a> {
    pub key_sha256: &'a [u8; 32],
    pub realm_id: i64,
    pub role_id: i64,
    /// Whether the token matched an issuer-wide rule: the key holds its role
    /// capped at `read`, as the token did.
    pub issuer_wide: bool,
    pub issuer_sha256: &'a [u8; 32],
    pub config_sha256: &'a [u8; 32],
    pub subject_sha256: &'a [u8; 32],
    pub jti_sha256: &'a [u8; 32],
    pub token_issued_at: DateTime<Utc>,
    pub token_expires_at: DateTime<Utc>,
    /// The clock skew the token's `exp` was accepted with (its realm's
    /// `clock_skew_seconds`, at most [`MAX_TOKEN_LEEWAY_SECONDS`]).
    pub token_leeway_seconds: u64,
    pub matched_publishers: &'a [TrustedPublisherMatch],
    /// The key's lifetime from now, in seconds (> 0).
    pub ttl_seconds: i64,
}

/// The most clock skew any realm accepts a CI token's `exp` with.
pub const MAX_TOKEN_LEEWAY_SECONDS: u64 = 5 * 60;

/// How long [`reap_expired`] keeps a redemption past the latest moment its
/// token can still be redeemed (`token_expires_at` plus
/// [`MAX_TOKEN_LEEWAY_SECONDS`]), for instances whose clocks run behind the
/// database's.
pub const REAP_MARGIN_SECONDS: u64 = 10 * 60;

/// What [`insert`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redemption {
    /// The key was stored; it expires then.
    Issued { id: i64, expires_at: DateTime<Utc> },
    /// The CI token was exchanged before.
    Replayed,
    /// By the database's clock the CI token has expired (past its leeway),
    /// whatever the instance that verified it believes.
    TokenExpired,
}

/// A live (unexpired) workload key: the principal snapshot it authorizes as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadApiKey {
    pub id: i64,
    pub key_sha256: [u8; 32],
    pub realm_id: i64,
    pub role_id: i64,
    pub issuer_wide: bool,
    pub issuer_sha256: [u8; 32],
    pub config_sha256: [u8; 32],
    pub subject_sha256: [u8; 32],
    pub jti_sha256: [u8; 32],
    pub token_issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub matched_publishers: Vec<TrustedPublisherMatch>,
}

/// Store a key, redeeming its CI token: [`Redemption::Issued`] with the
/// key's expiry, [`Redemption::Replayed`] when that token (`issuer_sha256`,
/// `jti_sha256`) was already exchanged, or [`Redemption::TokenExpired`] when
/// the token is past `token_expires_at` plus its leeway by the database's
/// clock. Expiries are decided on the database clock, like every other one
/// the server checks against `now()`: the redemption row is reaped on it
/// ([`reap_expired`]), so a token must not be redeemable on an instance clock
/// that runs behind it. The caller holds the realm row
/// (`trusted_publish_audit_dao::lock_identity_snapshot`), so a realm change
/// either waits for this key and then revokes it ([`revoke_realm`]) or lands
/// first and the key is never issued.
pub async fn insert(
    conn: &mut PgConnection,
    new: NewWorkloadApiKey<'_>,
) -> sqlx::Result<Redemption> {
    let leeway = new.token_leeway_seconds.min(MAX_TOKEN_LEEWAY_SECONDS);
    let live: bool = sqlx::query_scalar("SELECT $1 + make_interval(secs => $2) >= now()")
        .bind(new.token_expires_at)
        .bind(leeway as f64)
        .fetch_one(&mut *conn)
        .await?;
    if !live {
        return Ok(Redemption::TokenExpired);
    }
    // Runtime query rather than a macro keeps the new migration independently
    // buildable before CI refreshes the checked-in SQLx metadata cache.
    let row = sqlx::query(
        r#"
        INSERT INTO workload_api_key (
            key_sha256, realm_id, role_id, issuer_sha256, config_sha256,
            subject_sha256, jti_sha256, token_issued_at, token_expires_at,
            expires_at, issuer_wide
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                now() + make_interval(secs => $10), $11)
        ON CONFLICT (issuer_sha256, jti_sha256) DO NOTHING
        RETURNING id, expires_at
        "#,
    )
    .bind(new.key_sha256.as_slice())
    .bind(new.realm_id)
    .bind(new.role_id)
    .bind(new.issuer_sha256.as_slice())
    .bind(new.config_sha256.as_slice())
    .bind(new.subject_sha256.as_slice())
    .bind(new.jti_sha256.as_slice())
    .bind(new.token_issued_at)
    .bind(new.token_expires_at)
    .bind(new.ttl_seconds as f64)
    .bind(new.issuer_wide)
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        Some(row) => {
            let id: i64 = row.try_get("id")?;
            trusted_publisher_dao::store_key_matches(conn, id, new.matched_publishers).await?;
            Ok(Redemption::Issued {
                id,
                expires_at: row.try_get("expires_at")?,
            })
        }
        None => Ok(Redemption::Replayed),
    }
}

/// End every live key of `realm_id` now, in the transaction that edits,
/// disables or deletes the realm (after its row is written, so a concurrent
/// exchange holding the row is waited for and its key is ended too). The
/// rows stay: until its CI token expires, each is the record that the token
/// was redeemed. Ended keys never come back, whatever the realm becomes.
pub async fn revoke_realm(conn: &mut PgConnection, realm_id: i64) -> sqlx::Result<u64> {
    // `clock_timestamp()`, not the transaction's `now()`: a key committed
    // after this transaction began has a later `created_at`, and the CHECK
    // wants the expiry after it.
    let res = sqlx::query(
        r#"
        UPDATE workload_api_key
        SET expires_at = greatest(clock_timestamp(), created_at + interval '1 microsecond')
        WHERE realm_id = $1 AND expires_at > now()
        "#,
    )
    .bind(realm_id)
    .execute(conn)
    .await?;
    Ok(res.rows_affected())
}

/// The unexpired key whose SHA-256 is `key_sha256`, if any.
pub async fn find_live(
    pool: &PgPool,
    key_sha256: &[u8; 32],
) -> sqlx::Result<Option<WorkloadApiKey>> {
    let row = sqlx::query(
        r#"
        SELECT id, key_sha256, realm_id, role_id, issuer_wide, issuer_sha256,
               config_sha256, subject_sha256, jti_sha256, token_issued_at, expires_at
        FROM workload_api_key
        WHERE key_sha256 = $1 AND expires_at > now()
        "#,
    )
    .bind(key_sha256.as_slice())
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let id: i64 = row.try_get("id")?;
    let mut conn = pool.acquire().await?;
    let matched_publishers = trusted_publisher_dao::load_key_matches(&mut conn, id).await?;
    Ok(Some(WorkloadApiKey {
        id,
        key_sha256: digest(&row, "key_sha256")?,
        realm_id: row.try_get("realm_id")?,
        role_id: row.try_get("role_id")?,
        issuer_wide: row.try_get("issuer_wide")?,
        issuer_sha256: digest(&row, "issuer_sha256")?,
        config_sha256: digest(&row, "config_sha256")?,
        subject_sha256: digest(&row, "subject_sha256")?,
        jti_sha256: digest(&row, "jti_sha256")?,
        token_issued_at: row.try_get("token_issued_at")?,
        expires_at: row.try_get("expires_at")?,
        matched_publishers,
    }))
}

/// Whether the key `id` has not ended (expired or revoked). A key whose row
/// is gone (reaped) has ended.
pub async fn is_live(pool: &PgPool, id: i64) -> sqlx::Result<bool> {
    sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM workload_api_key WHERE id = $1 AND expires_at > now()
        )
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
}

/// Delete the rows whose key **and** CI token have both expired: until the
/// token's own expiry the row is the record that it was already redeemed.
/// A row stays [`REAP_MARGIN_SECONDS`] past the latest moment [`insert`]
/// accepts its token (`token_expires_at` plus [`MAX_TOKEN_LEEWAY_SECONDS`]).
pub async fn reap_expired(pool: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query(
        r#"
        DELETE FROM workload_api_key
        WHERE expires_at <= now()
          AND token_expires_at + make_interval(secs => $1) <= now()
        "#,
    )
    .bind((MAX_TOKEN_LEEWAY_SECONDS + REAP_MARGIN_SECONDS) as f64)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// A 32-byte digest column (the table's CHECKs guarantee the length).
fn digest(row: &sqlx::postgres::PgRow, column: &str) -> sqlx::Result<[u8; 32]> {
    let bytes: Vec<u8> = row.try_get(column)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| sqlx::Error::ColumnDecode {
            index: column.to_string(),
            source: format!("expected 32 bytes, got {}", bytes.len()).into(),
        })
}
