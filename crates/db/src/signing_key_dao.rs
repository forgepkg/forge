//! `repository_signing_key`: the OpenPGP keys that sign a repository's
//! indexes (apt), each secret key sealed with the secret encryption and
//! AAD-bound to `('repository_signing_key', 'secret_key_enc', <row id>)` and
//! the key's fingerprint, so a sealed key copied to another row (or another
//! key's row) does not open.

use chrono::{DateTime, Utc};
use forge_crypto::envelope::AeadBinding;
use forge_crypto::service::EnvelopeService;
use forge_crypto::PlaintextSecret;
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};

use crate::secret_dao::{reseal_if_due, SecretDbError};

/// Owning table of a sealed signing key (AAD component).
pub const TABLE: &str = "repository_signing_key";
/// Owning column of a sealed signing key (AAD component).
pub const COLUMN: &str = "secret_key_enc";

fn binding(id: i64, fingerprint: &str) -> AeadBinding<'_> {
    AeadBinding {
        table: TABLE,
        column: COLUMN,
        row_pk: id,
        destination: Some(fingerprint),
    }
}

/// A key of a repository.
#[derive(Debug, Clone)]
pub struct SigningKeyRow {
    pub id: i64,
    pub repository_id: i64,
    pub fingerprint: String,
    pub algorithm: String,
    pub user_id: String,
    pub public_key: String,
    pub secret_key_enc: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// What is stored of a new key.
#[derive(Debug, Clone, Copy)]
pub struct NewSigningKey<'a> {
    pub fingerprint: &'a str,
    pub algorithm: &'a str,
    pub user_id: &'a str,
    pub public_key: &'a str,
}

/// The keys of `repository_id`, oldest first.
pub async fn list<'e, E>(executor: E, repository_id: i64) -> sqlx::Result<Vec<SigningKeyRow>>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as!(
        SigningKeyRow,
        r#"
        SELECT id, repository_id, fingerprint, algorithm, user_id, public_key,
               secret_key_enc, created_at
        FROM repository_signing_key
        WHERE repository_id = $1
        ORDER BY created_at, id
        "#,
        repository_id,
    )
    .fetch_all(executor)
    .await
}

/// Store `key` for `repository_id` with its secret key (the armored key),
/// sealed for the new row. `None` when the repository has the key already.
pub async fn insert(
    tx: &mut Transaction<'_, Postgres>,
    envelope: &EnvelopeService,
    repository_id: i64,
    key: &NewSigningKey<'_>,
    secret: &PlaintextSecret,
) -> Result<Option<i64>, SecretDbError> {
    let Some(id) = sqlx::query_scalar!(
        r#"
        INSERT INTO repository_signing_key
            (repository_id, fingerprint, algorithm, user_id, public_key)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (repository_id, fingerprint) DO NOTHING
        RETURNING id
        "#,
        repository_id,
        key.fingerprint,
        key.algorithm,
        key.user_id,
        key.public_key,
    )
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(None);
    };
    let sealed = envelope.seal(secret, binding(id, key.fingerprint)).await?;
    sqlx::query!(
        "UPDATE repository_signing_key SET secret_key_enc = $2 WHERE id = $1",
        id,
        &sealed,
    )
    .execute(&mut **tx)
    .await?;
    Ok(Some(id))
}

/// The secret key of `row` (the armored key it was stored with).
pub async fn open(
    envelope: &EnvelopeService,
    row: &SigningKeyRow,
) -> Result<PlaintextSecret, SecretDbError> {
    let blob = row
        .secret_key_enc
        .as_deref()
        .ok_or(SecretDbError::RepoNotFound(row.repository_id))?;
    Ok(envelope
        .open(blob, binding(row.id, &row.fingerprint))
        .await?)
}

/// Delete the key `fingerprint` of `repository_id`, unless it is the
/// repository's last. `Ok(None)`: no such key; `Ok(Some(false))`: the last
/// key, kept.
pub async fn delete(
    pool: &PgPool,
    repository_id: i64,
    fingerprint: &str,
) -> sqlx::Result<Option<bool>> {
    let mut tx = crate::begin(pool).await?;
    // Every key of the repository, locked: two deletes cannot both see a
    // second key.
    let keys = sqlx::query_scalar!(
        r#"
        SELECT fingerprint FROM repository_signing_key
        WHERE repository_id = $1
        ORDER BY id
        FOR UPDATE
        "#,
        repository_id,
    )
    .fetch_all(&mut *tx)
    .await?;
    if !keys.iter().any(|k| k == fingerprint) {
        return Ok(None);
    }
    if keys.len() < 2 {
        return Ok(Some(false));
    }
    sqlx::query!(
        "DELETE FROM repository_signing_key WHERE repository_id = $1 AND fingerprint = $2",
        repository_id,
        fingerprint,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(true))
}

/// Re-seal every signing key sealed under a DEK other than the active one
/// (the DEK-rotation sweep). Returns how many were re-sealed.
pub async fn reseal(pool: &PgPool, envelope: &EnvelopeService) -> Result<usize, SecretDbError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, fingerprint, secret_key_enc AS "secret_key_enc!"
        FROM repository_signing_key WHERE secret_key_enc IS NOT NULL
        ORDER BY id
        "#,
    )
    .fetch_all(pool)
    .await?;
    let mut resealed = 0;
    for row in rows {
        let Some(new_blob) = reseal_if_due(
            envelope,
            &row.secret_key_enc,
            binding(row.id, &row.fingerprint),
        )
        .await?
        else {
            continue;
        };
        let res = sqlx::query!(
            r#"
            WITH dek AS (
                SELECT 1 FROM encryption_key
                WHERE layer = 'dek' AND scope = $4 AND version = $5 AND state <> 'revoked'
                FOR SHARE
            )
            UPDATE repository_signing_key SET secret_key_enc = $2
            WHERE id = $1 AND secret_key_enc = $3 AND EXISTS (SELECT 1 FROM dek)
            "#,
            row.id,
            &new_blob,
            &row.secret_key_enc,
            envelope.scope(),
            EnvelopeService::blob_dek_version(&new_blob)?,
        )
        .execute(pool)
        .await?;
        resealed += usize::try_from(res.rows_affected()).unwrap_or(0);
    }
    Ok(resealed)
}
