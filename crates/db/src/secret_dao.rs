//! Encrypted secret columns: transparent encrypt-on-write / decrypt-on-read for
//! `repository.upstream_password_enc` (slice 12.5, plan §2.4), plus the
//! plaintext **backfill** job and the DEK-rotation **re-encrypt sweep**
//! (plan §2.7/§2.8).
//!
//! Callers see [`PlaintextSecret`] only; the envelope blob never leaves this
//! module's helpers undecrypted except as the opaque `bytea` column value. The
//! AAD binds each ciphertext to `('repository', 'upstream_password_enc',
//! <row id>)`, so a blob copied into another row (or a future secret column)
//! fails to decrypt.
//!
//! This module is the seam future secret columns (§12.2 OIDC `client_secret`,
//! §12.3 `key_pepper`) adopt: one `(table, column)` constant pair + the same
//! set/get/backfill/sweep helpers per column.

use forge_crypto::envelope::AeadBinding;
use forge_crypto::service::EnvelopeService;
use forge_crypto::store::KeyLayer;
use forge_crypto::{CryptoError, PlaintextSecret};
use sqlx::PgPool;

/// Owning table of the encrypted upstream password (AAD component).
pub const UPSTREAM_PASSWORD_TABLE: &str = "repository";
/// Owning column of the encrypted upstream password (AAD component).
pub const UPSTREAM_PASSWORD_COLUMN: &str = "upstream_password_enc";

/// The AAD binding for `repository.upstream_password_enc` of one row.
fn binding(repo_id: i64) -> AeadBinding<'static> {
    AeadBinding {
        table: UPSTREAM_PASSWORD_TABLE,
        column: UPSTREAM_PASSWORD_COLUMN,
        row_pk: repo_id,
    }
}

/// Errors from the encrypted-column helpers: the database, the envelope
/// service, or a missing row.
#[derive(Debug, thiserror::Error)]
pub enum SecretDbError {
    /// Underlying database failure.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// Envelope seal/open/key failure (never carries plaintext).
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The referenced repository row does not exist.
    #[error("repository {0} not found")]
    RepoNotFound(i64),
}

/// Store (or clear) a repository's upstream password, **encrypted** under the
/// active DEK with the row-bound AAD. The plaintext `upstream_password` column
/// is cleared in the same statement: once a secret is written through the
/// envelope, plaintext never reappears for that row (the column itself is
/// dropped by a later migration once every deployment has backfilled).
pub async fn set_upstream_password(
    pool: &PgPool,
    envelope: &EnvelopeService,
    repo_id: i64,
    secret: Option<&PlaintextSecret>,
) -> Result<(), SecretDbError> {
    let blob = match secret {
        Some(pt) => Some(envelope.seal(pt, binding(repo_id)).await?),
        None => None,
    };
    let res = sqlx::query!(
        r#"
        UPDATE repository
        SET upstream_password_enc = $2, upstream_password = NULL
        WHERE id = $1
        "#,
        repo_id,
        blob.as_deref(),
    )
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(SecretDbError::RepoNotFound(repo_id));
    }
    Ok(())
}

/// Read a repository's upstream password, decrypting the envelope blob.
///
/// Pre-cutover compatibility: a row that has not been backfilled yet (plaintext
/// column set, `_enc` still NULL) falls back to the plaintext value so the
/// proxy keeps authenticating while the backfill job catches up. Returns
/// `None` when the repository stores no password at all.
pub async fn get_upstream_password(
    pool: &PgPool,
    envelope: &EnvelopeService,
    repo_id: i64,
) -> Result<Option<PlaintextSecret>, SecretDbError> {
    let row = sqlx::query!(
        r#"
        SELECT upstream_password_enc, upstream_password
        FROM repository
        WHERE id = $1
        "#,
        repo_id,
    )
    .fetch_optional(pool)
    .await?
    .ok_or(SecretDbError::RepoNotFound(repo_id))?;

    match row.upstream_password_enc {
        Some(blob) => Ok(Some(envelope.open(&blob, binding(repo_id)).await?)),
        None => Ok(row.upstream_password.map(PlaintextSecret::from)),
    }
}

/// One batch of the plaintext → encrypted **backfill** (plan §2.8 step 3):
/// wrap up to `batch` rows whose plaintext column is set and whose `_enc`
/// column is still NULL. Returns how many rows were encrypted; `0` means the
/// backfill is complete. Idempotent and resumable — processed rows leave the
/// predicate, and the guarded UPDATE makes a concurrent/repeated run a no-op
/// per row. The plaintext column is intentionally NOT cleared here: the
/// verified cutover migration drops it later (two-step column rewrite).
pub async fn backfill_upstream_passwords(
    pool: &PgPool,
    envelope: &EnvelopeService,
    batch: i64,
) -> Result<usize, SecretDbError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, upstream_password AS "upstream_password!"
        FROM repository
        WHERE upstream_password IS NOT NULL AND upstream_password_enc IS NULL
        ORDER BY id
        LIMIT $1
        "#,
        batch,
    )
    .fetch_all(pool)
    .await?;

    let mut done = 0;
    for row in rows {
        let secret = PlaintextSecret::from(row.upstream_password);
        let blob = envelope.seal(&secret, binding(row.id)).await?;
        let res = sqlx::query!(
            r#"
            UPDATE repository
            SET upstream_password_enc = $2
            WHERE id = $1 AND upstream_password IS NOT NULL
              AND upstream_password_enc IS NULL
            "#,
            row.id,
            &blob,
        )
        .execute(pool)
        .await?;
        done += usize::try_from(res.rows_affected()).unwrap_or(0);
    }
    Ok(done)
}

/// Result of one [`reseal_upstream_passwords_batch`] call.
#[derive(Debug, Clone, Copy)]
pub struct SweepBatch {
    /// Keyset cursor: pass as `after_id` of the next call. `None` ⇒ the scan
    /// reached the end of the table.
    pub next_after_id: Option<i64>,
    /// Rows whose blob was re-encrypted under the active DEK.
    pub resealed: usize,
}

/// One keyset-paginated batch of the **DEK-rotation re-encrypt sweep** (plan
/// §2.7): re-seal every `upstream_password_enc` blob that references a
/// non-active DEK. Each row is one guarded UPDATE (last-writer-wins with a
/// concurrent admin password change — both old and new DEKs decrypt during the
/// window, so any interleaving stays readable).
pub async fn reseal_upstream_passwords_batch(
    pool: &PgPool,
    envelope: &EnvelopeService,
    after_id: i64,
    batch: i64,
) -> Result<SweepBatch, SecretDbError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, upstream_password_enc AS "upstream_password_enc!"
        FROM repository
        WHERE upstream_password_enc IS NOT NULL AND id > $1
        ORDER BY id
        LIMIT $2
        "#,
        after_id,
        batch,
    )
    .fetch_all(pool)
    .await?;

    let next_after_id = if rows.len() == usize::try_from(batch).unwrap_or(usize::MAX) {
        rows.last().map(|r| r.id)
    } else {
        None
    };

    let mut resealed = 0;
    for row in rows {
        if !envelope.needs_reseal(&row.upstream_password_enc).await? {
            continue;
        }
        let new_blob = envelope
            .reseal(&row.upstream_password_enc, binding(row.id))
            .await?;
        // Guarded on the old blob value so a racing password change (or a
        // racing sweep on another instance) is never overwritten.
        let res = sqlx::query!(
            r#"
            UPDATE repository
            SET upstream_password_enc = $2
            WHERE id = $1 AND upstream_password_enc = $3
            "#,
            row.id,
            &new_blob,
            &row.upstream_password_enc,
        )
        .execute(pool)
        .await?;
        resealed += usize::try_from(res.rows_affected()).unwrap_or(0);
    }
    Ok(SweepBatch {
        next_after_id,
        resealed,
    })
}

/// Every DEK version still referenced by stored ciphertext, across all
/// encrypted columns (today: `repository.upstream_password_enc`; future secret
/// columns add their scan here). Used by the sweep to decide which `retiring`
/// DEKs are safe to revoke.
pub async fn referenced_dek_versions(
    pool: &PgPool,
) -> Result<std::collections::HashSet<i32>, SecretDbError> {
    let mut versions = std::collections::HashSet::new();
    let mut after_id = 0i64;
    loop {
        let rows = sqlx::query!(
            r#"
            SELECT id, upstream_password_enc AS "upstream_password_enc!"
            FROM repository
            WHERE upstream_password_enc IS NOT NULL AND id > $1
            ORDER BY id
            LIMIT 500
            "#,
            after_id,
        )
        .fetch_all(pool)
        .await?;
        let Some(last) = rows.last() else { break };
        after_id = last.id;
        for row in &rows {
            versions.insert(EnvelopeService::blob_dek_version(
                &row.upstream_password_enc,
            )?);
        }
        if rows.len() < 500 {
            break;
        }
    }
    Ok(versions)
}

/// Whether any repository row still carries a plaintext password that has not
/// been backfilled (operator visibility before the cutover migration ships).
pub async fn plaintext_passwords_pending(pool: &PgPool) -> Result<bool, SecretDbError> {
    let row = sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM repository
            WHERE upstream_password IS NOT NULL AND upstream_password_enc IS NULL
        ) AS "pending!"
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.pending)
}

/// Revoke every `retiring` DEK that no stored ciphertext references anymore
/// (the tail of the DEK-rotation sweep). Returns how many DEKs were revoked.
pub async fn revoke_unreferenced_deks(
    pool: &PgPool,
    envelope: &EnvelopeService,
) -> Result<usize, SecretDbError> {
    let referenced = referenced_dek_versions(pool).await?;
    let mut revoked = 0;
    for dek in envelope.list_keys(KeyLayer::Dek).await? {
        if dek.state == forge_crypto::store::KeyState::Retiring
            && !referenced.contains(&dek.version)
        {
            envelope.revoke_key(KeyLayer::Dek, dek.version).await?;
            revoked += 1;
        }
    }
    Ok(revoked)
}
