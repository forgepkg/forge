//! Encrypted secret columns: transparent encrypt-on-write / decrypt-on-read for
//! `repository.upstream_password_enc` (slice 12.5, plan §2.4), plus the
//! plaintext **backfill** job and the DEK-rotation **re-encrypt sweep**
//! (plan §2.7/§2.8).
//!
//! Callers see [`PlaintextSecret`] only; the envelope blob never leaves this
//! module's helpers undecrypted except as the opaque `bytea` column value. The
//! AAD binds each ciphertext to `('repository', 'upstream_password_enc',
//! <row id>)` and to the **origin of the row's `remote_url`**, so a blob
//! copied into another row (or a future secret column) fails to decrypt, and
//! so does one whose row was repointed at another host by a write that
//! bypassed the admin API (which drops or replaces the password when the
//! origin changes): the password is never sent anywhere else.
//!
//! Blobs sealed by pre-release builds carry the row-only binding. They are
//! opened only while `crypto.accept_row_bound_secrets` is on
//! ([`EnvelopeService::accepts_row_bound_secrets`]): then readers accept them
//! and the re-encrypt sweeps ([`reseal_upstream_passwords_batch`],
//! [`reseal_realm_secrets`]) re-seal them under the destination binding, at
//! startup and on every rotation pass. Off (the default), such a blob does
//! not decrypt, so an old blob replayed into a repointed row is refused too.
//!
//! This module is the seam secret columns adopt: one `(table, column)`
//! constant pair + the same set/get/backfill/sweep helpers per column. Auth
//! realm secrets (OIDC `client_secret`, credential-forwarding `key_pepper`,
//! review P1.5) use it too: the secret keys of a realm `config` are sealed as
//! one JSON object into `auth_realm.secrets_enc`, AAD-bound to
//! `('auth_realm', 'secrets_enc', <row id>)` plus the config fields the
//! secret belongs to ([`realm_secret_binding_keys`]: an OIDC realm's issuer
//! and client id), and stripped from the plaintext `config` (see
//! [`insert_realm_with_secrets`] / [`realm_config`]).
//!
//! Secrets kept in `forge_setting` ([`SECRET_SETTINGS`]: the generated
//! registry-token key) are text values, `sealed:<base64 envelope>` with the
//! envelope service and `plain:<secret>` without it, AAD-bound to
//! `('forge_setting', 'value', 0)` plus the setting's key. They take part in
//! the backfill, the re-encrypt sweep and the DEK reference scan like the
//! secret columns ([`store_secret_setting`], [`open_secret_setting`]).
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

/// Where a repository's upstream password may be sent: the origin of its
/// `remote_url` (`scheme://host[:port]`, as the proxy attaches credentials
/// only to that origin), the raw value if it does not parse, or `""` without
/// one.
pub fn upstream_destination(remote_url: Option<&str>) -> String {
    match remote_url {
        Some(raw) => match url::Url::parse(raw) {
            Ok(url) => url.origin().ascii_serialization(),
            Err(_) => raw.to_string(),
        },
        None => String::new(),
    }
}

/// The AAD binding for `repository.upstream_password_enc` of one row whose
/// [`upstream_destination`] is `destination`.
fn binding(repo_id: i64, destination: &str) -> AeadBinding<'_> {
    AeadBinding {
        table: UPSTREAM_PASSWORD_TABLE,
        column: UPSTREAM_PASSWORD_COLUMN,
        row_pk: repo_id,
        destination: Some(destination),
    }
}

/// Open `blob` under `binding`, or, for a blob a pre-release build sealed and
/// only while `crypto.accept_row_bound_secrets` is on, under the same row's
/// row-only binding. The flag says the blob still has to be re-sealed under
/// `binding`.
async fn open_bound(
    envelope: &EnvelopeService,
    blob: &[u8],
    binding: AeadBinding<'_>,
) -> Result<(PlaintextSecret, bool), CryptoError> {
    match envelope.open(blob, binding).await {
        Ok(plaintext) => Ok((plaintext, false)),
        Err(CryptoError::DecryptFailed) if envelope.accepts_row_bound_secrets() => envelope
            .open(blob, binding.row_only())
            .await
            .map(|plaintext| (plaintext, true)),
        Err(e) => Err(e),
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
    /// The repository's `remote_url` changed while its password was being
    /// sealed for the previous one; nothing was written.
    #[error("repository {0} changed its remote_url concurrently")]
    DestinationChanged(i64),
    /// A realm's secrets are encrypted but no envelope service is configured
    /// (or the decrypted document is malformed): fail closed.
    #[error("auth realm {0} secrets unavailable: {1}")]
    RealmSecrets(i64, &'static str),
    /// A secret setting's value is neither `plain:` nor a readable `sealed:`
    /// envelope: it can never be opened.
    #[error("setting {0} is malformed")]
    MalformedSetting(String),
    /// A secret setting is sealed but no envelope service is configured:
    /// fail closed (and never overwrite it with a plaintext value).
    #[error("setting {0} is sealed but secret encryption is not configured")]
    SettingSealedWithoutEnvelope(String),
}

/// Store (or clear) a repository's upstream password, **encrypted** under the
/// active DEK with the AAD bound to the row and its current `remote_url`
/// origin. The plaintext `upstream_password` column is cleared in the same
/// statement: once a secret is written through the envelope, plaintext never
/// reappears for that row.
///
/// Takes a connection (a transaction's, from the admin API) so it can commit
/// atomically with the repository metadata it belongs to (a new `remote_url`
/// must never become visible with the previous host's credentials); the
/// `remote_url` that transaction wrote is the one bound.
/// The write holds a `FOR SHARE` lock on the sealing DEK (see the module
/// docs) and fails with [`CryptoError::KeyRevoked`] if that DEK was revoked
/// concurrently, or with [`SecretDbError::DestinationChanged`] if the
/// `remote_url` changed in between.
pub async fn set_upstream_password(
    conn: &mut sqlx::PgConnection,
    envelope: &EnvelopeService,
    repo_id: i64,
    secret: Option<&PlaintextSecret>,
) -> Result<(), SecretDbError> {
    let remote_url = sqlx::query_scalar!(
        r#"SELECT remote_url FROM repository WHERE id = $1"#,
        repo_id,
    )
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(SecretDbError::RepoNotFound(repo_id))?;
    let destination = upstream_destination(remote_url.as_deref());
    let blob = match secret {
        Some(pt) => Some(envelope.seal(pt, binding(repo_id, &destination)).await?),
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
              AND remote_url IS NOT DISTINCT FROM $5
            RETURNING id
        )
        SELECT
            EXISTS (SELECT 1 FROM upd) AS "updated!",
            ($4::int4 IS NULL OR EXISTS (SELECT 1 FROM dek)) AS "dek_usable!",
            EXISTS (SELECT 1 FROM repository WHERE id = $1) AS "exists!"
        "#,
        repo_id,
        blob.as_deref(),
        envelope.scope(),
        dek_version,
        remote_url,
    )
    .fetch_one(&mut *conn)
    .await?;
    if !row.dek_usable {
        return Err(revoked_dek(dek_version));
    }
    if !row.exists {
        return Err(SecretDbError::RepoNotFound(repo_id));
    }
    if !row.updated {
        return Err(SecretDbError::DestinationChanged(repo_id));
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

/// A repository's upstream password with the `remote_url` read in the same
/// row: the URL whose origin the password is bound to, and so the only place
/// it may be sent.
pub struct UpstreamPassword {
    /// The decrypted (or legacy plaintext) password.
    pub secret: PlaintextSecret,
    /// The row's `remote_url` at the time of the read.
    pub remote_url: Option<String>,
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
    Ok(get_upstream_credential(pool, envelope, repo_id)
        .await?
        .map(|password| password.secret))
}

/// [`get_upstream_password`] together with the `remote_url` it is bound to.
/// A blob whose row now names another origin does not decrypt
/// ([`CryptoError::DecryptFailed`]).
pub async fn get_upstream_credential(
    pool: &PgPool,
    envelope: &EnvelopeService,
    repo_id: i64,
) -> Result<Option<UpstreamPassword>, SecretDbError> {
    let row = sqlx::query!(
        r#"
        SELECT upstream_password_enc, upstream_password, remote_url
        FROM repository
        WHERE id = $1
        "#,
        repo_id,
    )
    .fetch_optional(pool)
    .await?
    .ok_or(SecretDbError::RepoNotFound(repo_id))?;

    let secret = match row.upstream_password_enc {
        Some(blob) => {
            let destination = upstream_destination(row.remote_url.as_deref());
            let (secret, _) = open_bound(envelope, &blob, binding(repo_id, &destination)).await?;
            secret
        }
        None => match row.upstream_password {
            Some(plaintext) => PlaintextSecret::from(plaintext),
            None => return Ok(None),
        },
    };
    Ok(Some(UpstreamPassword {
        secret,
        remote_url: row.remote_url,
    }))
}

/// One batch of the plaintext → encrypted **backfill** (plan §2.8 step 3).
///
/// 1. Rows that already carry `_enc` **and** a leftover plaintext copy (rows
///    backfilled by pre-release builds, which kept the plaintext) lose the
///    plaintext: the envelope is the authoritative value on every read path.
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
    // Rows that carry both copies (left by builds that kept the plaintext
    // after sealing it). The plaintext is dropped only once the ciphertext is
    // known to hold the same password; when it holds another one, or does
    // not decrypt at all, the plaintext is the newer (or the only
    // recoverable) copy, so it is sealed afresh and replaces the ciphertext.
    let both = sqlx::query!(
        r#"
        SELECT id,
               upstream_password AS "upstream_password!",
               upstream_password_enc AS "upstream_password_enc!",
               remote_url
        FROM repository
        WHERE upstream_password IS NOT NULL AND upstream_password_enc IS NOT NULL
        ORDER BY id
        LIMIT $1
        "#,
        batch,
    )
    .fetch_all(pool)
    .await?;
    let mut cleared: u64 = 0;
    for row in both {
        let destination = upstream_destination(row.remote_url.as_deref());
        // A blob still under the row-only binding counts as a mismatch: it is
        // re-sealed from the plaintext copy under the destination binding.
        let matches = match envelope
            .open(&row.upstream_password_enc, binding(row.id, &destination))
            .await
        {
            Ok(opened) => opened.expose_secret() == row.upstream_password.as_str(),
            Err(err) => {
                tracing::warn!(
                    repository_id = row.id,
                    error = %err,
                    "stored upstream password ciphertext does not decrypt; re-sealing it from the plaintext copy"
                );
                false
            }
        };
        let res = if matches {
            sqlx::query!(
                r#"
                UPDATE repository SET upstream_password = NULL
                WHERE id = $1 AND upstream_password = $2 AND upstream_password_enc = $3
                "#,
                row.id,
                row.upstream_password,
                row.upstream_password_enc,
            )
            .execute(pool)
            .await?
        } else {
            let secret = PlaintextSecret::from(row.upstream_password.clone());
            let blob = envelope
                .seal(&secret, binding(row.id, &destination))
                .await?;
            let dek_version = EnvelopeService::blob_dek_version(&blob)?;
            sqlx::query!(
                r#"
                WITH dek AS (
                    SELECT 1 FROM encryption_key
                    WHERE layer = 'dek' AND scope = $5 AND version = $6 AND state <> 'revoked'
                    FOR SHARE
                )
                UPDATE repository
                SET upstream_password_enc = $2, upstream_password = NULL
                WHERE id = $1 AND upstream_password = $3 AND upstream_password_enc = $4
                  AND remote_url IS NOT DISTINCT FROM $7
                  AND EXISTS (SELECT 1 FROM dek)
                "#,
                row.id,
                &blob,
                row.upstream_password,
                row.upstream_password_enc,
                envelope.scope(),
                dek_version,
                row.remote_url,
            )
            .execute(pool)
            .await?
        };
        cleared += res.rows_affected();
    }

    let rows = sqlx::query!(
        r#"
        SELECT id, upstream_password AS "upstream_password!", remote_url
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
        let destination = upstream_destination(row.remote_url.as_deref());
        let blob = envelope
            .seal(&secret, binding(row.id, &destination))
            .await?;
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
              AND remote_url IS NOT DISTINCT FROM $6
              AND EXISTS (SELECT 1 FROM dek)
            "#,
            row.id,
            &blob,
            row.upstream_password,
            envelope.scope(),
            dek_version,
            row.remote_url,
        )
        .execute(pool)
        .await?;
        done += usize::try_from(res.rows_affected()).unwrap_or(0);
    }
    Ok(done)
}

/// The re-sealed blob for a sweep, or `None` when `blob` is already sealed
/// under `binding` with the active DEK. A blob that does not decrypt under
/// `binding` (nor, when accepted, its row-only form) is logged and skipped.
async fn reseal_if_due(
    envelope: &EnvelopeService,
    blob: &[u8],
    binding: AeadBinding<'_>,
) -> Result<Option<Vec<u8>>, SecretDbError> {
    let (plaintext, legacy) = match open_bound(envelope, blob, binding).await {
        Ok(opened) => opened,
        Err(CryptoError::DecryptFailed) => {
            tracing::warn!(
                table = binding.table,
                row = binding.row_pk,
                accept_row_bound_secrets = envelope.accepts_row_bound_secrets(),
                "sealed secret does not decrypt for its row's current destination; left as is \
                 (enter the secret again through the admin API, or, for a secret a pre-release \
                 build sealed, start once with crypto.accept_row_bound_secrets = true)"
            );
            return Ok(None);
        }
        Err(e) if is_blob_error(&e) => {
            tracing::warn!(
                table = binding.table,
                row = binding.row_pk,
                error = %e,
                "sealed secret is unreadable; left as is (enter the secret again through the \
                 admin API)"
            );
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    };
    if !legacy && !envelope.needs_reseal(blob).await? {
        return Ok(None);
    }
    Ok(Some(envelope.seal(&plaintext, binding).await?))
}

/// Whether `e` concerns one stored blob (malformed, sealed under an unknown or
/// revoked data key, unreadable) rather than the key hierarchy as a whole. A
/// pass over many rows warns about such a row and leaves it, instead of
/// failing for every other row, and every instance's startup with it.
fn is_blob_error(e: &CryptoError) -> bool {
    match e {
        CryptoError::DecryptFailed
        | CryptoError::MalformedEnvelope(_)
        | CryptoError::UnsupportedFormatVersion(_)
        | CryptoError::UnsupportedAlgorithm(_)
        | CryptoError::NotUtf8 => true,
        CryptoError::KeyNotFound { layer, .. } | CryptoError::KeyRevoked { layer, .. } => {
            *layer == "dek"
        }
        _ => false,
    }
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
/// non-active DEK, or (with `crypto.accept_row_bound_secrets`) that a
/// pre-release build sealed under the row-only binding (it is re-sealed for
/// the row's current origin). Each row is one guarded UPDATE (last-writer-wins
/// with a concurrent admin password change — both old and new DEKs decrypt
/// during the window, so any interleaving stays readable). A blob that does
/// not decrypt (its row was repointed outside the API) is logged and left
/// alone, so it cannot stall the sweep for every other row.
pub async fn reseal_upstream_passwords_batch(
    pool: &PgPool,
    envelope: &EnvelopeService,
    after_id: i64,
    batch: i64,
) -> Result<SweepBatch, SecretDbError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, upstream_password_enc AS "upstream_password_enc!", remote_url
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
        let destination = upstream_destination(row.remote_url.as_deref());
        let bound = binding(row.id, &destination);
        let Some(new_blob) = reseal_if_due(envelope, &row.upstream_password_enc, bound).await?
        else {
            continue;
        };
        // Guarded on the old blob value and the URL it was bound to, so a
        // racing password change (or a racing sweep on another instance) is
        // never overwritten, and on the sealing DEK still being usable
        // (module docs).
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
              AND remote_url IS NOT DISTINCT FROM $6
              AND EXISTS (SELECT 1 FROM dek)
            "#,
            row.id,
            &new_blob,
            &row.upstream_password_enc,
            envelope.scope(),
            EnvelopeService::blob_dek_version(&new_blob)?,
            row.remote_url,
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
/// `auth_realm.secrets_enc`, the sealed [`SECRET_SETTINGS`]; future secret
/// columns add their scan here). Used
/// by the sweep to decide which `retiring` DEKs are safe to revoke.
pub async fn referenced_dek_versions(
    pool: &PgPool,
) -> Result<std::collections::HashSet<i32>, SecretDbError> {
    let mut conn = pool.acquire().await?;
    scan_referenced_dek_versions(&mut conn).await
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
            match EnvelopeService::blob_dek_version(&row.upstream_password_enc) {
                Ok(version) => {
                    versions.insert(version);
                }
                // No key version to protect can be read from it; one bad row
                // must not stop every key's revocation.
                Err(e) => {
                    tracing::warn!(repository_id = row.id, error = %e, "unreadable upstream password envelope; skipped");
                }
            }
        }
        if rows.len() < 500 {
            break;
        }
    }
    let realm_blobs = sqlx::query!(
        r#"SELECT id, secrets_enc AS "secrets_enc!" FROM auth_realm WHERE secrets_enc IS NOT NULL"#,
    )
    .fetch_all(&mut *conn)
    .await?;
    for row in &realm_blobs {
        match EnvelopeService::blob_dek_version(&row.secrets_enc) {
            Ok(version) => {
                versions.insert(version);
            }
            Err(e) => {
                tracing::warn!(realm_id = row.id, error = %e, "unreadable realm secrets envelope; skipped");
            }
        }
    }
    for (key, value) in sealed_settings(&mut *conn).await? {
        match sealed_setting_blob(&key, &value)
            .and_then(|blob| Ok(EnvelopeService::blob_dek_version(&blob)?))
        {
            Ok(version) => {
                versions.insert(version);
            }
            Err(e) => {
                tracing::warn!(setting = %key, error = %e, "unreadable sealed setting; skipped");
            }
        }
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

/// Whether any secret is stored sealed (an upstream password, realm secrets
/// or a [`SECRET_SETTINGS`] value): such a database needs the envelope
/// service to be usable.
pub async fn sealed_secrets_present(pool: &PgPool) -> Result<bool, SecretDbError> {
    let row = sqlx::query!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM repository WHERE upstream_password_enc IS NOT NULL
        ) OR EXISTS (
            SELECT 1 FROM auth_realm WHERE secrets_enc IS NOT NULL
        ) AS "present!"
        "#,
    )
    .fetch_one(pool)
    .await?;
    if row.present {
        return Ok(true);
    }
    let mut conn = pool.acquire().await?;
    Ok(!sealed_settings(&mut conn).await?.is_empty())
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
    let referenced = scan_referenced_dek_versions(&mut tx).await?;
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

/// Config keys a realm kind's secrets belong to: the secret is the
/// credential for that party, so changing any of them makes the stored secret
/// unusable (the admin API then requires a new one, and the ciphertext is
/// bound to them).
pub fn realm_secret_binding_keys(kind: &str) -> &'static [&'static str] {
    match kind {
        // The client secret is the IdP's credential for this client.
        "oidc" => &["issuer", "client_id"],
        _ => &[],
    }
}

/// The destination a realm's sealed secrets are bound to: its
/// [`realm_secret_binding_keys`] values, as a JSON array (`[]` for a kind
/// without any).
fn realm_destination(kind: &str, config: &JsonValue) -> String {
    let values = realm_secret_binding_keys(kind)
        .iter()
        .map(|key| config.get(*key).cloned().unwrap_or(JsonValue::Null))
        .collect();
    JsonValue::Array(values).to_string()
}

/// The AAD binding for `auth_realm.secrets_enc` of one row.
fn realm_binding(realm_id: i64, destination: &str) -> AeadBinding<'_> {
    AeadBinding {
        table: REALM_SECRETS_TABLE,
        column: REALM_SECRETS_COLUMN,
        row_pk: realm_id,
        destination: Some(destination),
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
    let destination = realm_destination(&realm.kind, &realm.config);
    let (plaintext, _) = open_bound(envelope, blob, realm_binding(realm.id, &destination)).await?;
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
    kind: &str,
    config: &JsonValue,
    secrets: &Map<String, JsonValue>,
) -> Result<Vec<u8>, SecretDbError> {
    let doc = PlaintextSecret::from(JsonValue::Object(secrets.clone()).to_string());
    let destination = realm_destination(kind, config);
    Ok(envelope
        .seal(&doc, realm_binding(realm_id, &destination))
        .await?)
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
    let blob = seal_realm_secrets(envelope, row.id, &row.kind, &row.config, &secrets).await?;
    lock_sealing_dek(&mut tx, envelope, &blob).await?;
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
                // The kind never changes, so the destination is taken from
                // the config this update writes.
                let Some(kind) =
                    sqlx::query_scalar!(r#"SELECT kind FROM auth_realm WHERE id = $1"#, id)
                        .fetch_optional(pool)
                        .await?
                else {
                    return Ok(None);
                };
                Some(seal_realm_secrets(envelope, id, &kind, &upd.config, &secrets).await?)
            }
        }
    };
    let (Some(envelope), Some(sealed)) = (envelope, blob.as_deref()) else {
        return Ok(auth_realm_dao::update_realm_and_secrets(pool, id, upd, blob.as_deref()).await?);
    };
    // Ciphertext write: hold the sealing DEK `FOR SHARE` until commit.
    let mut tx = pool.begin().await?;
    lock_sealing_dek(&mut tx, envelope, sealed).await?;
    let row = auth_realm_dao::update_realm_and_secrets(&mut *tx, id, upd, Some(sealed)).await?;
    tx.commit().await?;
    Ok(row)
}

/// [`update_realm_with_secrets`] as a compare-and-set in the caller's
/// transaction: the row is written only while it is still `expected`
/// ([`auth_realm_dao::update_realm_and_secrets_if_unchanged`]). `None` when it
/// changed or is gone; nothing is written then.
pub async fn update_realm_with_secrets_if_unchanged(
    conn: &mut sqlx::PgConnection,
    envelope: Option<&EnvelopeService>,
    expected: &AuthRealm,
    mut upd: AuthRealmUpdate,
    secret_keys: &[&str],
) -> Result<Option<AuthRealm>, SecretDbError> {
    let mut blob = None;
    if let Some(envelope) = envelope {
        let (stripped, secrets) = split_realm_secrets(&upd.config, secret_keys);
        upd.config = stripped;
        if !secrets.is_empty() {
            let sealed =
                seal_realm_secrets(envelope, expected.id, &expected.kind, &upd.config, &secrets)
                    .await?;
            // Ciphertext write: hold the sealing DEK `FOR SHARE` until commit.
            lock_sealing_dek(conn, envelope, &sealed).await?;
            blob = Some(sealed);
        }
    }
    Ok(auth_realm_dao::update_realm_and_secrets_if_unchanged(
        &mut *conn,
        expected,
        upd,
        blob.as_deref(),
    )
    .await?)
}

/// Plaintext → encrypted **backfill** for realm secrets: every realm whose
/// plaintext `config` still carries one of its `secret_keys_for(kind)` keys is
/// re-stored with those keys moved into `secrets_enc`.
///
/// Each realm is written only while it is still the row read here
/// ([`update_realm_with_secrets_if_unchanged`]), so a concurrent admin edit is
/// never undone; a row that changed is left for the next pass. When the row's
/// `secrets_enc` does not decrypt, the plaintext copy is the only recoverable
/// one: it is sealed afresh and replaces the ciphertext, as the
/// upstream-password backfill does. Idempotent; returns how many realms were
/// re-encrypted.
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
        let config = match realm_config(Some(envelope), &realm).await {
            Ok(config) => config,
            Err(SecretDbError::Crypto(e)) if is_blob_error(&e) => {
                tracing::warn!(
                    realm_id = realm.id,
                    error = %e,
                    "stored realm secrets are unreadable; re-sealing them from the plaintext copy"
                );
                realm.config.clone()
            }
            Err(SecretDbError::RealmSecrets(_, why)) => {
                tracing::warn!(
                    realm_id = realm.id,
                    why,
                    "stored realm secrets are unreadable; re-sealing them from the plaintext copy"
                );
                realm.config.clone()
            }
            Err(e) => return Err(e),
        };
        let upd = AuthRealmUpdate {
            name: realm.name.clone(),
            enabled: realm.enabled,
            priority: realm.priority,
            config,
        };
        let mut tx = pool.begin().await?;
        let written =
            update_realm_with_secrets_if_unchanged(&mut tx, Some(envelope), &realm, upd, keys)
                .await?;
        tx.commit().await?;
        if written.is_some() {
            done += 1;
        }
    }
    Ok(done)
}

/// DEK-rotation re-encrypt sweep over `auth_realm.secrets_enc` (the table is
/// small, so no pagination): re-seals blobs under a non-active DEK and (with
/// `crypto.accept_row_bound_secrets`) blobs a pre-release build sealed under
/// the row-only binding. Guarded on the old
/// blob, the config it is bound to and the sealing DEK like the repository
/// sweep. Returns how many rows were resealed.
pub async fn reseal_realm_secrets(
    pool: &PgPool,
    envelope: &EnvelopeService,
) -> Result<usize, SecretDbError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, kind, config, secrets_enc AS "secrets_enc!"
        FROM auth_realm
        WHERE secrets_enc IS NOT NULL
        ORDER BY id
        "#,
    )
    .fetch_all(pool)
    .await?;
    let mut resealed = 0;
    for row in rows {
        let destination = realm_destination(&row.kind, &row.config);
        let bound = realm_binding(row.id, &destination);
        let Some(new_blob) = reseal_if_due(envelope, &row.secrets_enc, bound).await? else {
            continue;
        };
        let res = sqlx::query!(
            r#"
            WITH dek AS (
                SELECT 1 FROM encryption_key
                WHERE layer = 'dek' AND scope = $4 AND version = $5 AND state <> 'revoked'
                FOR SHARE
            )
            UPDATE auth_realm
            SET secrets_enc = $2
            WHERE id = $1 AND secrets_enc = $3 AND config = $6
              AND EXISTS (SELECT 1 FROM dek)
            "#,
            row.id,
            &new_blob,
            &row.secrets_enc,
            envelope.scope(),
            EnvelopeService::blob_dek_version(&new_blob)?,
            &row.config,
        )
        .execute(pool)
        .await?;
        resealed += usize::try_from(res.rows_affected()).unwrap_or(0);
    }
    Ok(resealed)
}

// ── secrets in `forge_setting` ───────────────────────────────────────────────

/// `forge_setting` key of the generated registry-token signing key.
pub const REGISTRY_TOKEN_KEY_SETTING: &str = "docker_token_key";

/// The `forge_setting` keys whose values are secrets (module docs).
pub const SECRET_SETTINGS: &[&str] = &[REGISTRY_TOKEN_KEY_SETTING];

/// Prefix of a sealed secret setting: `sealed:<base64 envelope>`.
const SEALED_SETTING: &str = "sealed:";
/// Prefix of a plaintext secret setting: `plain:<secret>`.
const PLAIN_SETTING: &str = "plain:";

/// The AAD binding of the secret setting `key`.
fn setting_binding(key: &str) -> AeadBinding<'_> {
    AeadBinding {
        table: "forge_setting",
        column: "value",
        row_pk: 0,
        destination: Some(key),
    }
}

/// The envelope of a `sealed:` setting value.
fn sealed_setting_blob(key: &str, value: &str) -> Result<Vec<u8>, SecretDbError> {
    use base64::Engine;
    value
        .strip_prefix(SEALED_SETTING)
        .and_then(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
        })
        .ok_or_else(|| SecretDbError::MalformedSetting(key.to_string()))
}

/// The [`SECRET_SETTINGS`] stored sealed: `(key, value)`.
async fn sealed_settings(
    conn: &mut sqlx::PgConnection,
) -> Result<Vec<(String, String)>, SecretDbError> {
    Ok(sqlx::query_as(
        "SELECT key, value FROM forge_setting WHERE key = ANY($1) AND value LIKE 'sealed:%'",
    )
    .bind(SECRET_SETTINGS)
    .fetch_all(conn)
    .await?)
}

/// Open the stored `value` of the secret setting `key`. A `sealed:` value
/// needs `envelope`.
pub async fn open_secret_setting(
    envelope: Option<&EnvelopeService>,
    key: &str,
    value: &str,
) -> Result<PlaintextSecret, SecretDbError> {
    if let Some(plain) = value.strip_prefix(PLAIN_SETTING) {
        return Ok(PlaintextSecret::from(plain.to_string()));
    }
    let blob = sealed_setting_blob(key, value)?;
    let envelope =
        envelope.ok_or_else(|| SecretDbError::SettingSealedWithoutEnvelope(key.to_string()))?;
    Ok(envelope.open(&blob, setting_binding(key)).await?)
}

/// Whether `e`, from [`open_secret_setting`], says the stored value can
/// never be opened (malformed, or sealed under a data key that does not open
/// it), as opposed to the database, the key store or the configuration
/// failing, which a retry or a fix can cure.
pub fn is_unreadable_setting(e: &SecretDbError) -> bool {
    match e {
        SecretDbError::MalformedSetting(_) => true,
        SecretDbError::Crypto(e) => is_blob_error(e),
        _ => false,
    }
}

/// Store `secret` as the secret setting `key`: sealed with `envelope`, else
/// `plain:`. With `expected`, only while the stored value is still that
/// (compare-and-swap); without, only while the key is unset. Returns the
/// stored value, or `None` when another writer got there first.
///
/// A sealed write holds `FOR SHARE` on its DEK (module docs). A plaintext
/// value never replaces a sealed one.
pub async fn store_secret_setting(
    pool: &PgPool,
    envelope: Option<&EnvelopeService>,
    key: &str,
    secret: &PlaintextSecret,
    expected: Option<&str>,
) -> Result<Option<String>, SecretDbError> {
    match envelope {
        Some(envelope) => {
            let blob = envelope.seal(secret, setting_binding(key)).await?;
            write_sealed_setting(pool, envelope, key, &blob, expected).await
        }
        None if expected.is_some_and(|v| v.starts_with(SEALED_SETTING)) => {
            Err(SecretDbError::SettingSealedWithoutEnvelope(key.to_string()))
        }
        None => {
            let value = format!("{PLAIN_SETTING}{}", secret.expose_secret());
            let mut tx = pool.begin().await?;
            let written = write_setting(&mut tx, key, &value, expected).await?;
            tx.commit().await?;
            Ok(written.then_some(value))
        }
    }
}

/// [`store_secret_setting`] of an envelope `blob` sealed for `key`, holding
/// `FOR SHARE` on its DEK.
async fn write_sealed_setting(
    pool: &PgPool,
    envelope: &EnvelopeService,
    key: &str,
    blob: &[u8],
    expected: Option<&str>,
) -> Result<Option<String>, SecretDbError> {
    use base64::Engine;
    let value = format!(
        "{SEALED_SETTING}{}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    );
    let mut tx = pool.begin().await?;
    lock_sealing_dek(&mut tx, envelope, blob).await?;
    let written = write_setting(&mut tx, key, &value, expected).await?;
    tx.commit().await?;
    Ok(written.then_some(value))
}

/// Write a setting: replace it while it is still `expected`, or insert it
/// while it is unset. Returns whether it was written.
async fn write_setting(
    conn: &mut sqlx::PgConnection,
    key: &str,
    value: &str,
    expected: Option<&str>,
) -> Result<bool, SecretDbError> {
    Ok(match expected {
        Some(expected) => {
            crate::authz_dao::replace_setting(&mut *conn, key, expected, value).await?
        }
        None => {
            sqlx::query(
                "INSERT INTO forge_setting (key, value) VALUES ($1, $2) \
                 ON CONFLICT (key) DO NOTHING",
            )
            .bind(key)
            .bind(value)
            .execute(&mut *conn)
            .await?
            .rows_affected()
                > 0
        }
    })
}

/// Seal every [`SECRET_SETTINGS`] value still stored `plain:` (written
/// before `[crypto]` was enabled). Returns how many were sealed.
pub async fn backfill_secret_settings(
    pool: &PgPool,
    envelope: &EnvelopeService,
) -> Result<usize, SecretDbError> {
    let mut sealed = 0;
    for key in SECRET_SETTINGS {
        let Some(value) = crate::authz_dao::get_setting(pool, key).await? else {
            continue;
        };
        let Some(plain) = value.strip_prefix(PLAIN_SETTING) else {
            continue;
        };
        let secret = PlaintextSecret::from(plain.to_string());
        if store_secret_setting(pool, Some(envelope), key, &secret, Some(&value))
            .await?
            .is_some()
        {
            sealed += 1;
        }
    }
    Ok(sealed)
}

/// Whether any [`SECRET_SETTINGS`] value is still stored `plain:` (the
/// settings' half of the operator's "plaintext backfill pending" signal).
pub async fn plaintext_settings_pending(pool: &PgPool) -> Result<bool, SecretDbError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM forge_setting \
         WHERE key = ANY($1) AND value LIKE 'plain:%')",
    )
    .bind(SECRET_SETTINGS)
    .fetch_one(pool)
    .await?)
}

/// The DEK re-encrypt sweep over the sealed [`SECRET_SETTINGS`]: re-seal a
/// value under the active DEK when its own is not. Returns how many were
/// re-sealed. A value that does not open is left as it is (logged).
pub async fn reseal_secret_settings(
    pool: &PgPool,
    envelope: &EnvelopeService,
) -> Result<usize, SecretDbError> {
    let mut conn = pool.acquire().await?;
    let sealed = sealed_settings(&mut conn).await?;
    drop(conn);
    let mut resealed = 0;
    for (key, value) in sealed {
        let blob = match sealed_setting_blob(&key, &value) {
            Ok(blob) => blob,
            Err(error) => {
                tracing::warn!(setting = %key, %error, "sealed setting is unreadable; left as is");
                continue;
            }
        };
        let Some(new_blob) = reseal_if_due(envelope, &blob, setting_binding(&key)).await? else {
            continue;
        };
        // Guarded on the old value, so a racing replacement (or a racing
        // sweep on another instance) is never overwritten.
        match write_sealed_setting(pool, envelope, &key, &new_blob, Some(&value)).await {
            Ok(Some(_)) => resealed += 1,
            Ok(None) => {}
            // The active DEK was retired and revoked meanwhile: the next
            // pass re-seals under its successor.
            Err(SecretDbError::Crypto(CryptoError::KeyRevoked { .. })) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(resealed)
}
