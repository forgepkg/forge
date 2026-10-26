//! Append-only trusted-publishing provenance.
//!
//! Rows are inserted in the same transaction as the component/assets they
//! describe. A trigger rejects UPDATE and DELETE at the database boundary;
//! this module deliberately exposes no mutation API other than insert.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};

/// Human-readable identity metadata snapshotted from the still-active realm
/// and role while both rows are locked in the package transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPublishIdentitySnapshot {
    pub realm_name: String,
    pub issuer: String,
    /// Complete live realm config, re-normalized and hashed by the server while
    /// this row remains locked to fence stale authorization snapshots.
    pub realm_config: serde_json::Value,
    pub role_name: String,
}

/// A verified workload publication ready to append to the audit ledger.
#[derive(Debug, Clone)]
pub struct NewTrustedPublishAudit<'a> {
    pub repository_id: i64,
    pub repository_name: &'a str,
    pub package_name: &'a str,
    pub package_version: &'a str,
    pub realm_id: i64,
    pub realm_name: &'a str,
    pub issuer: &'a str,
    pub role_id: i64,
    pub role_name: &'a str,
    pub subject_sha256: &'a [u8; 32],
    pub jti_sha256: Option<&'a [u8; 32]>,
    pub token_issued_at: DateTime<Utc>,
    /// `publish` | `unlist` | `relist` | `delete`.
    pub action: &'a str,
    pub trusted_publisher_id: Option<i64>,
    pub trusted_publisher_name: Option<&'a str>,
}

/// Lock and snapshot the active workload realm and mapped role. Returning
/// `None` means authentication/authorization configuration was revoked or
/// changed before the package transaction and the publish must fail closed.
pub async fn lock_identity_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    realm_id: i64,
    role_id: i64,
) -> sqlx::Result<Option<TrustedPublishIdentitySnapshot>> {
    let row = sqlx::query(
        r#"
        SELECT ar.name AS realm_name, ar.config ->> 'issuer' AS issuer,
               ar.config AS realm_config,
               r.name AS role_name
        FROM auth_realm ar
        CROSS JOIN role r
        WHERE ar.id = $1
          AND ar.enabled
          AND ar.kind = 'workload_identity'
          AND ar.config ->> 'issuer' IS NOT NULL
          AND r.id = $2
        FOR SHARE OF ar, r
        "#,
    )
    .bind(realm_id)
    .bind(role_id)
    .fetch_optional(&mut **tx)
    .await?;

    row.map(|row| {
        Ok(TrustedPublishIdentitySnapshot {
            realm_name: row.try_get("realm_name")?,
            issuer: row.try_get("issuer")?,
            realm_config: row.try_get("realm_config")?,
            role_name: row.try_get("role_name")?,
        })
    })
    .transpose()
}

/// Append one row to the immutable ledger inside the caller's package
/// transaction. If this insert fails, the package transaction fails too.
pub async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    row: NewTrustedPublishAudit<'_>,
) -> sqlx::Result<()> {
    // Runtime query rather than a macro keeps the new migration independently
    // buildable before CI refreshes the checked-in SQLx metadata cache.
    sqlx::query(
        r#"
        INSERT INTO trusted_publish_audit (
            repository_id, repository_name, package_name, package_version,
            realm_id, realm_name, issuer, role_id, role_name,
            subject_sha256, jti_sha256, token_issued_at, action
            , trusted_publisher_id, trusted_publisher_name
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        "#,
    )
    .bind(row.repository_id)
    .bind(row.repository_name)
    .bind(row.package_name)
    .bind(row.package_version)
    .bind(row.realm_id)
    .bind(row.realm_name)
    .bind(row.issuer)
    .bind(row.role_id)
    .bind(row.role_name)
    .bind(row.subject_sha256.as_slice())
    .bind(row.jti_sha256.map(|digest| digest.as_slice()))
    .bind(row.token_issued_at)
    .bind(row.action)
    .bind(row.trusted_publisher_id)
    .bind(row.trusted_publisher_name)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
