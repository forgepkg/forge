//! Short-lived workload API keys (migration 0034): the trusted-publishing
//! token exchange stores one row per redeemed CI token.
//!
//! Only SHA-256 digests are stored. The unique `(issuer_sha256, jti_sha256)`
//! index makes [`insert`] the one-time redemption of a CI token.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

/// A key to store for a freshly verified, exchanged CI token.
#[derive(Debug, Clone)]
pub struct NewWorkloadApiKey<'a> {
    pub key_sha256: &'a [u8; 32],
    pub realm_id: i64,
    pub role_id: i64,
    pub issuer_sha256: &'a [u8; 32],
    pub config_sha256: &'a [u8; 32],
    pub subject_sha256: &'a [u8; 32],
    pub jti_sha256: &'a [u8; 32],
    pub token_issued_at: DateTime<Utc>,
    pub token_expires_at: DateTime<Utc>,
    /// The key's lifetime from now, in seconds (> 0).
    pub ttl_seconds: i64,
}

/// A live (unexpired) workload key: the principal snapshot it authorizes as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadApiKey {
    pub id: i64,
    pub key_sha256: [u8; 32],
    pub realm_id: i64,
    pub role_id: i64,
    pub issuer_sha256: [u8; 32],
    pub config_sha256: [u8; 32],
    pub subject_sha256: [u8; 32],
    pub jti_sha256: [u8; 32],
    pub token_issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Store a key, redeeming its CI token. Returns the key's expiry, or `None`
/// when that token (`issuer_sha256`, `jti_sha256`) was already exchanged.
/// The expiry is computed from the database clock, like every other expiry
/// the server checks against `now()`.
pub async fn insert(
    pool: &PgPool,
    new: NewWorkloadApiKey<'_>,
) -> sqlx::Result<Option<DateTime<Utc>>> {
    // Runtime query rather than a macro keeps the new migration independently
    // buildable before CI refreshes the checked-in SQLx metadata cache.
    let row = sqlx::query(
        r#"
        INSERT INTO workload_api_key (
            key_sha256, realm_id, role_id, issuer_sha256, config_sha256,
            subject_sha256, jti_sha256, token_issued_at, token_expires_at,
            expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                now() + make_interval(secs => $10))
        ON CONFLICT (issuer_sha256, jti_sha256) DO NOTHING
        RETURNING expires_at
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
    .fetch_optional(pool)
    .await?;
    row.map(|row| row.try_get("expires_at")).transpose()
}

/// The unexpired key whose SHA-256 is `key_sha256`, if any.
pub async fn find_live(
    pool: &PgPool,
    key_sha256: &[u8; 32],
) -> sqlx::Result<Option<WorkloadApiKey>> {
    let row = sqlx::query(
        r#"
        SELECT id, key_sha256, realm_id, role_id, issuer_sha256, config_sha256,
               subject_sha256, jti_sha256, token_issued_at, expires_at
        FROM workload_api_key
        WHERE key_sha256 = $1 AND expires_at > now()
        "#,
    )
    .bind(key_sha256.as_slice())
    .fetch_optional(pool)
    .await?;
    row.map(|row| {
        Ok(WorkloadApiKey {
            id: row.try_get("id")?,
            key_sha256: digest(&row, "key_sha256")?,
            realm_id: row.try_get("realm_id")?,
            role_id: row.try_get("role_id")?,
            issuer_sha256: digest(&row, "issuer_sha256")?,
            config_sha256: digest(&row, "config_sha256")?,
            subject_sha256: digest(&row, "subject_sha256")?,
            jti_sha256: digest(&row, "jti_sha256")?,
            token_issued_at: row.try_get("token_issued_at")?,
            expires_at: row.try_get("expires_at")?,
        })
    })
    .transpose()
}

/// Delete the rows whose key **and** CI token have both expired: until the
/// token's own expiry the row is the record that it was already redeemed.
pub async fn reap_expired(pool: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query(
        r#"
        DELETE FROM workload_api_key
        WHERE expires_at <= now() AND token_expires_at <= now()
        "#,
    )
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
