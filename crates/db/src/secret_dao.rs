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
//! This module is the seam secret columns adopt: one `(table, column)`
//! constant pair + the same set/get/backfill/sweep helpers per column. Auth
//! realm secrets (OIDC `client_secret`, credential-forwarding `key_pepper`,
//! review P1.5) use it too: the secret keys of a realm `config` are sealed as
//! one JSON object into `auth_realm.secrets_enc`, AAD-bound to
//! `('auth_realm', 'secrets_enc', <row id>)`, and stripped from the plaintext
//! `config` (see [`insert_realm_with_secrets`] / [`realm_config`]).

use forge_crypto::envelope::AeadBinding;
use forge_crypto::service::EnvelopeService;
use forge_crypto::store::KeyLayer;
use forge_crypto::{CryptoError, ExposeSecret, PlaintextSecret};
use serde_json::{Map, Value as JsonValue};
use sqlx::PgPool;

use crate::auth_realm_dao::{self, AuthRealmUpdate, NewAuthRealm};
use crate::model::AuthRealm;

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
    /// A realm's secrets are encrypted but no envelope service is configured
    /// (or the decrypted document is malformed): fail closed.
    #[error("auth realm {0} secrets unavailable: {1}")]
    RealmSecrets(i64, &'static str),
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
/// encrypted columns (`repository.upstream_password_enc`,
/// `auth_realm.secrets_enc`; future secret columns add their scan here). Used
/// by the sweep to decide which `retiring` DEKs are safe to revoke.
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
    let realm_blobs = sqlx::query_scalar!(
        r#"SELECT secrets_enc AS "secrets_enc!" FROM auth_realm WHERE secrets_enc IS NOT NULL"#,
    )
    .fetch_all(pool)
    .await?;
    for blob in &realm_blobs {
        versions.insert(EnvelopeService::blob_dek_version(blob)?);
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

// ── auth realm secrets (review P1.5) ─────────────────────────────────────────

/// Owning table of encrypted realm secrets (AAD component).
pub const REALM_SECRETS_TABLE: &str = "auth_realm";
/// Owning column of encrypted realm secrets (AAD component).
pub const REALM_SECRETS_COLUMN: &str = "secrets_enc";

/// The AAD binding for `auth_realm.secrets_enc` of one row.
fn realm_binding(realm_id: i64) -> AeadBinding<'static> {
    AeadBinding {
        table: REALM_SECRETS_TABLE,
        column: REALM_SECRETS_COLUMN,
        row_pk: realm_id,
    }
}

/// Split `secret_keys` out of a realm `config`: returns the config without
/// them plus the non-blank secret values (blank / non-string values are
/// dropped from both — they carry no secret).
pub fn split_realm_secrets(
    config: &JsonValue,
    secret_keys: &[&str],
) -> (JsonValue, Map<String, JsonValue>) {
    let mut stripped = config.clone();
    let mut secrets = Map::new();
    if let JsonValue::Object(map) = &mut stripped {
        for key in secret_keys {
            if let Some(JsonValue::String(v)) = map.remove(*key) {
                if !v.is_empty() {
                    secrets.insert((*key).to_string(), JsonValue::String(v));
                }
            }
        }
    }
    (stripped, secrets)
}

/// The **logical** config of a realm row: the plaintext `config` with the
/// decrypted `secrets_enc` keys merged in (encrypted values win over any
/// legacy plaintext copy). A row without `secrets_enc` is returned as-is
/// (legacy plaintext / encryption disabled). Encrypted secrets without an
/// envelope service fail closed.
pub async fn realm_config(
    envelope: Option<&EnvelopeService>,
    realm: &AuthRealm,
) -> Result<JsonValue, SecretDbError> {
    let Some(blob) = realm.secrets_enc.as_deref() else {
        return Ok(realm.config.clone());
    };
    let envelope = envelope.ok_or(SecretDbError::RealmSecrets(
        realm.id,
        "secrets are encrypted but secret encryption is not configured",
    ))?;
    let plaintext = envelope.open(blob, realm_binding(realm.id)).await?;
    let secrets: Map<String, JsonValue> = serde_json::from_str(plaintext.expose_secret())
        .map_err(|_| SecretDbError::RealmSecrets(realm.id, "malformed secrets document"))?;
    let mut config = realm.config.clone();
    match &mut config {
        JsonValue::Object(map) => map.extend(secrets),
        _ => config = JsonValue::Object(secrets),
    }
    Ok(config)
}

/// Seal a realm's secrets object for row `realm_id`.
async fn seal_realm_secrets(
    envelope: &EnvelopeService,
    realm_id: i64,
    secrets: &Map<String, JsonValue>,
) -> Result<Vec<u8>, SecretDbError> {
    let doc = PlaintextSecret::from(JsonValue::Object(secrets.clone()).to_string());
    Ok(envelope.seal(&doc, realm_binding(realm_id)).await?)
}

/// Insert a realm whose `new.config` is the full logical document. With an
/// envelope, the `secret_keys` are stripped from the stored `config` and sealed
/// into `secrets_enc` in the same transaction (the row id is part of the AAD,
/// so the insert comes first); without one the config is stored as-is.
pub async fn insert_realm_with_secrets(
    pool: &PgPool,
    envelope: Option<&EnvelopeService>,
    mut new: NewAuthRealm,
    secret_keys: &[&str],
) -> Result<AuthRealm, SecretDbError> {
    let Some(envelope) = envelope else {
        return Ok(auth_realm_dao::insert_realm(pool, new).await?);
    };
    let (stripped, secrets) = split_realm_secrets(&new.config, secret_keys);
    if secrets.is_empty() {
        return Ok(auth_realm_dao::insert_realm(pool, new).await?);
    }
    new.config = stripped;
    let mut tx = pool.begin().await?;
    let row = auth_realm_dao::insert_realm(&mut *tx, new).await?;
    let blob = seal_realm_secrets(envelope, row.id, &secrets).await?;
    let row = auth_realm_dao::update_realm_and_secrets(
        &mut *tx,
        row.id,
        AuthRealmUpdate {
            name: row.name.clone(),
            enabled: row.enabled,
            priority: row.priority,
            config: row.config.clone(),
        },
        Some(&blob),
    )
    .await?
    .ok_or(SecretDbError::RealmSecrets(
        row.id,
        "row vanished mid-insert",
    ))?;
    tx.commit().await?;
    Ok(row)
}

/// Update a realm whose `upd.config` is the full logical document. With an
/// envelope the secrets are (re-)encrypted into `secrets_enc` and stripped from
/// `config`; without one they are stored in plaintext and `secrets_enc` is
/// cleared (behaves as before encryption existed). Returns `None` when the id
/// does not exist.
pub async fn update_realm_with_secrets(
    pool: &PgPool,
    envelope: Option<&EnvelopeService>,
    id: i64,
    mut upd: AuthRealmUpdate,
    secret_keys: &[&str],
) -> Result<Option<AuthRealm>, SecretDbError> {
    let blob = match envelope {
        None => None,
        Some(envelope) => {
            let (stripped, secrets) = split_realm_secrets(&upd.config, secret_keys);
            upd.config = stripped;
            if secrets.is_empty() {
                None
            } else {
                Some(seal_realm_secrets(envelope, id, &secrets).await?)
            }
        }
    };
    Ok(auth_realm_dao::update_realm_and_secrets(pool, id, upd, blob.as_deref()).await?)
}

/// Plaintext → encrypted **backfill** for realm secrets: every realm whose
/// plaintext `config` still carries one of its `secret_keys_for(kind)` keys is
/// re-stored through [`update_realm_with_secrets`] (keys move into
/// `secrets_enc`). Idempotent; returns how many realms were re-encrypted.
pub async fn backfill_realm_secrets(
    pool: &PgPool,
    envelope: &EnvelopeService,
    secret_keys_for: impl Fn(&str) -> &'static [&'static str],
) -> Result<usize, SecretDbError> {
    let mut done = 0;
    for realm in auth_realm_dao::list_realms(pool).await? {
        let keys = secret_keys_for(&realm.kind);
        if split_realm_secrets(&realm.config, keys).1.is_empty() {
            continue;
        }
        let config = realm_config(Some(envelope), &realm).await?;
        let upd = AuthRealmUpdate {
            name: realm.name.clone(),
            enabled: realm.enabled,
            priority: realm.priority,
            config,
        };
        if update_realm_with_secrets(pool, Some(envelope), realm.id, upd, keys)
            .await?
            .is_some()
        {
            done += 1;
        }
    }
    Ok(done)
}

/// DEK-rotation re-encrypt sweep over `auth_realm.secrets_enc` (the table is
/// small, so no pagination). Guarded on the old blob like the repository
/// sweep. Returns how many rows were resealed.
pub async fn reseal_realm_secrets(
    pool: &PgPool,
    envelope: &EnvelopeService,
) -> Result<usize, SecretDbError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, secrets_enc AS "secrets_enc!"
        FROM auth_realm
        WHERE secrets_enc IS NOT NULL
        ORDER BY id
        "#,
    )
    .fetch_all(pool)
    .await?;
    let mut resealed = 0;
    for row in rows {
        if !envelope.needs_reseal(&row.secrets_enc).await? {
            continue;
        }
        let new_blob = envelope
            .reseal(&row.secrets_enc, realm_binding(row.id))
            .await?;
        let res = sqlx::query!(
            r#"
            UPDATE auth_realm
            SET secrets_enc = $2
            WHERE id = $1 AND secrets_enc = $3
            "#,
            row.id,
            &new_blob,
            &row.secrets_enc,
        )
        .execute(pool)
        .await?;
        resealed += usize::try_from(res.rows_affected()).unwrap_or(0);
    }
    Ok(resealed)
}
