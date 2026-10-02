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
//!
//! ## DEK revocation vs. concurrent writers
//!
//! A retiring DEK is revoked only when no stored ciphertext references it **at
//! commit time** ([`revoke_unreferenced_deks`]): the revoker locks the retiring
//! DEK rows `FOR UPDATE`, then scans the secret columns in later statements
//! (fresh READ COMMITTED snapshots), then flips the state. Every ciphertext
//! write in this module holds a `FOR SHARE` lock on the DEK row its blob was
//! sealed under, in the same statement/transaction as the write, and refuses
//! to write if that DEK is revoked. A writer that started first therefore
//! makes the revoker wait and then see its blob; a writer that comes second
//! waits for the revoker and then finds the DEK revoked (error, nothing
//! written) — ciphertext can never reference a revoked DEK.

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
/// envelope, plaintext never reappears for that row.
///
/// Accepts any executor so the admin API can commit it atomically with the
/// repository metadata it belongs to (a new `remote_url` must never become
/// visible with the previous host's credentials). The write holds a
/// `FOR SHARE` lock on the sealing DEK (see the module docs) and fails with
/// [`CryptoError::KeyRevoked`] if that DEK was revoked concurrently.
pub async fn set_upstream_password<'e, E>(
    executor: E,
    envelope: &EnvelopeService,
    repo_id: i64,
    secret: Option<&PlaintextSecret>,
) -> Result<(), SecretDbError>
where
    E: sqlx::PgExecutor<'e>,
{
    let blob = match secret {
        Some(pt) => Some(envelope.seal(pt, binding(repo_id)).await?),
        None => None,
    };
    let dek_version = blob
        .as_deref()
        .map(EnvelopeService::blob_dek_version)
        .transpose()?;
    // One statement (the executor may be a bare pool): lock the sealing DEK
    // row, write only while it is usable, and report which guard failed.
    let row = sqlx::query!(
        r#"
        WITH dek AS (
            SELECT 1 AS usable FROM encryption_key
            WHERE layer = 'dek' AND scope = $3 AND version = $4 AND state <> 'revoked'
            FOR SHARE
        ), upd AS (
            UPDATE repository
            SET upstream_password_enc = $2, upstream_password = NULL
            WHERE id = $1 AND ($4::int4 IS NULL OR EXISTS (SELECT 1 FROM dek))
            RETURNING id
        )
        SELECT
            EXISTS (SELECT 1 FROM upd) AS "updated!",
            ($4::int4 IS NULL OR EXISTS (SELECT 1 FROM dek)) AS "dek_usable!"
        "#,
        repo_id,
        blob.as_deref(),
        envelope.scope(),
        dek_version,
    )
    .fetch_one(executor)
    .await?;
    if !row.dek_usable {
        return Err(revoked_dek(dek_version));
    }
    if !row.updated {
        return Err(SecretDbError::RepoNotFound(repo_id));
    }
    Ok(())
}

/// The error for a write whose sealing DEK was revoked concurrently.
fn revoked_dek(version: Option<i32>) -> SecretDbError {
    SecretDbError::Crypto(CryptoError::KeyRevoked {
        layer: "dek",
        version: version.unwrap_or_default(),
    })
}

/// Inside a writer's transaction: take a `FOR SHARE` lock on the DEK row
/// `blob` was sealed under, failing if that DEK is revoked (see the module
/// docs). The lock is held until the transaction ends, i.e. until the write
/// is committed and visible to the revocation scan.
async fn lock_sealing_dek(
    conn: &mut sqlx::PgConnection,
    envelope: &EnvelopeService,
    blob: &[u8],
) -> Result<(), SecretDbError> {
    let version = EnvelopeService::blob_dek_version(blob)?;
    let usable = sqlx::query_scalar!(
        r#"
        SELECT 1 AS "one!" FROM encryption_key
        WHERE layer = 'dek' AND scope = $1 AND version = $2 AND state <> 'revoked'
        FOR SHARE
        "#,
        envelope.scope(),
        version,
    )
    .fetch_optional(&mut *conn)
    .await?;
    match usable {
        Some(_) => Ok(()),
        None => Err(revoked_dek(Some(version))),
    }
}

/// Read a repository's upstream password, decrypting the envelope blob.
///
/// Backfill compatibility: a row that has not been backfilled yet (plaintext
/// column set, `_enc` still NULL — e.g. written before encryption was enabled)
/// falls back to the plaintext value so the proxy keeps authenticating until
/// the backfill pass moves it. Returns `None` when the repository stores no
/// password at all.
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

/// One batch of the plaintext → encrypted **backfill** (plan §2.8 step 3).
///
/// 1. Rows that already carry `_enc` **and** a leftover plaintext copy (rows
///    backfilled by 0.1.0, which kept the plaintext) lose the plaintext: the
///    envelope is the authoritative value on every read path.
/// 2. Up to `batch` rows whose plaintext column is set and whose `_enc` column
///    is still NULL are sealed; the plaintext is NULLed **in the same guarded
///    UPDATE** (guarded on the exact plaintext read and `_enc IS NULL`, and on
///    the sealing DEK still being usable), so a row is never left with both
///    values and a concurrent admin write is never overwritten.
///
/// Returns how many rows were changed; `0` means no plaintext is left.
/// Idempotent and resumable — processed rows leave both predicates.
pub async fn backfill_upstream_passwords(
    pool: &PgPool,
    envelope: &EnvelopeService,
    batch: i64,
) -> Result<usize, SecretDbError> {
    let cleared = sqlx::query!(
        r#"
        UPDATE repository
        SET upstream_password = NULL
        WHERE id IN (
            SELECT id FROM repository
            WHERE upstream_password IS NOT NULL AND upstream_password_enc IS NOT NULL
            ORDER BY id
            LIMIT $1
        )
          AND upstream_password IS NOT NULL AND upstream_password_enc IS NOT NULL
        "#,
        batch,
    )
    .execute(pool)
    .await?
    .rows_affected();

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

    let mut done = usize::try_from(cleared).unwrap_or(0);
    for row in rows {
        let secret = PlaintextSecret::from(row.upstream_password.clone());
        let blob = envelope.seal(&secret, binding(row.id)).await?;
        let dek_version = EnvelopeService::blob_dek_version(&blob)?;
        let res = sqlx::query!(
            r#"
            WITH dek AS (
                SELECT 1 FROM encryption_key
                WHERE layer = 'dek' AND scope = $4 AND version = $5 AND state <> 'revoked'
                FOR SHARE
            )
            UPDATE repository
            SET upstream_password_enc = $2, upstream_password = NULL
            WHERE id = $1 AND upstream_password = $3
              AND upstream_password_enc IS NULL
              AND EXISTS (SELECT 1 FROM dek)
            "#,
            row.id,
            &blob,
            row.upstream_password,
            envelope.scope(),
            dek_version,
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
        // racing sweep on another instance) is never overwritten, and on the
        // sealing DEK still being usable (module docs).
        let res = sqlx::query!(
            r#"
            WITH dek AS (
                SELECT 1 FROM encryption_key
                WHERE layer = 'dek' AND scope = $4 AND version = $5 AND state <> 'revoked'
                FOR SHARE
            )
            UPDATE repository
            SET upstream_password_enc = $2
            WHERE id = $1 AND upstream_password_enc = $3
              AND EXISTS (SELECT 1 FROM dek)
            "#,
            row.id,
            &new_blob,
            &row.upstream_password_enc,
            envelope.scope(),
            EnvelopeService::blob_dek_version(&new_blob)?,
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
    let mut conn = pool.acquire().await?;
    scan_referenced_dek_versions(&mut *conn).await
}

/// [`referenced_dek_versions`] on one connection (inside the revocation
/// transaction, each statement sees everything committed before it).
async fn scan_referenced_dek_versions(
    conn: &mut sqlx::PgConnection,
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
        .fetch_all(&mut *conn)
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
    .fetch_all(&mut *conn)
    .await?;
    for blob in &realm_blobs {
        versions.insert(EnvelopeService::blob_dek_version(blob)?);
    }
    Ok(versions)
}

/// Whether any repository row still carries a plaintext upstream password —
/// not yet backfilled, or a leftover copy next to its envelope (operator
/// visibility: with encryption enabled this must reach `false` once the
/// backfill pass has run).
pub async fn plaintext_passwords_pending(pool: &PgPool) -> Result<bool, SecretDbError> {
    let row = sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM repository WHERE upstream_password IS NOT NULL
        ) AS "pending!"
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.pending)
}

/// Whether any auth realm still carries one of its secret keys
/// (`secret_keys_for(kind)`) in its plaintext `config` (the realm half of the
/// operator's "plaintext backfill pending" signal).
pub async fn plaintext_realm_secrets_pending(
    pool: &PgPool,
    secret_keys_for: impl Fn(&str) -> &'static [&'static str],
) -> Result<bool, SecretDbError> {
    Ok(auth_realm_dao::list_realms(pool)
        .await?
        .iter()
        .any(|realm| {
            !split_realm_secrets(&realm.config, secret_keys_for(&realm.kind))
                .1
                .is_empty()
        }))
}

/// Revoke every `retiring` DEK that no stored ciphertext references anymore
/// (the tail of the DEK-rotation sweep). Returns how many DEKs were revoked.
///
/// The reference check holds **at commit time** (module docs): one
/// transaction locks the retiring DEK rows `FOR UPDATE` — waiting for every
/// in-flight ciphertext writer holding one of them `FOR SHARE` — then scans the
/// secret columns and flips only the unreferenced rows. Writers that arrive
/// after the lock wait for this transaction and then refuse the revoked DEK.
pub async fn revoke_unreferenced_deks(
    pool: &PgPool,
    envelope: &EnvelopeService,
) -> Result<usize, SecretDbError> {
    let mut tx = pool.begin().await?;
    let retiring = sqlx::query!(
        r#"
        SELECT id, version
        FROM encryption_key
        WHERE layer = 'dek' AND scope = $1 AND state = 'retiring'
        ORDER BY version
        FOR UPDATE
        "#,
        envelope.scope(),
    )
    .fetch_all(&mut *tx)
    .await?;
    if retiring.is_empty() {
        tx.commit().await?;
        return Ok(0);
    }
    let referenced = scan_referenced_dek_versions(&mut *tx).await?;
    let (ids, versions): (Vec<i64>, Vec<i32>) = retiring
        .iter()
        .filter(|dek| !referenced.contains(&dek.version))
        .map(|dek| (dek.id, dek.version))
        .unzip();
    if !ids.is_empty() {
        sqlx::query!(
            r#"
            UPDATE encryption_key
            SET state = 'revoked', rotated_at = COALESCE(rotated_at, now())
            WHERE id = ANY($1) AND state = 'retiring'
            "#,
            &ids,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    for version in &versions {
        envelope.forget_unwrapped(KeyLayer::Dek, *version).await;
    }
    Ok(versions.len())
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
    lock_sealing_dek(&mut *tx, envelope, &blob).await?;
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
    let (Some(envelope), Some(sealed)) = (envelope, blob.as_deref()) else {
        return Ok(auth_realm_dao::update_realm_and_secrets(pool, id, upd, blob.as_deref()).await?);
    };
    // Ciphertext write: hold the sealing DEK `FOR SHARE` until commit.
    let mut tx = pool.begin().await?;
    lock_sealing_dek(&mut *tx, envelope, sealed).await?;
    let row = auth_realm_dao::update_realm_and_secrets(&mut *tx, id, upd, Some(sealed)).await?;
    tx.commit().await?;
    Ok(row)
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
/// small, so no pagination). Guarded on the old blob and the sealing DEK like
/// the repository sweep. Returns how many rows were resealed.
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
            WITH dek AS (
                SELECT 1 FROM encryption_key
                WHERE layer = 'dek' AND scope = $4 AND version = $5 AND state <> 'revoked'
                FOR SHARE
            )
            UPDATE auth_realm
            SET secrets_enc = $2
            WHERE id = $1 AND secrets_enc = $3
              AND EXISTS (SELECT 1 FROM dek)
            "#,
            row.id,
            &new_blob,
            &row.secrets_enc,
            envelope.scope(),
            EnvelopeService::blob_dek_version(&new_blob)?,
        )
        .execute(pool)
        .await?;
        resealed += usize::try_from(res.rows_affected()).unwrap_or(0);
    }
    Ok(resealed)
}
