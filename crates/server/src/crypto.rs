//! Secret-encryption wiring: build the envelope service from config, bootstrap
//! the key hierarchy at startup, and run the cluster-coordinated
//! rotation/backfill worker.
//!
//! ## Enable story
//!
//! Encryption is **opt-in** via the `[crypto]` config section (TOML +
//! `FORGE_CRYPTO__*` env). Absent/disabled ⇒ secrets are stored in plaintext.
//! Enabled ⇒
//!
//! 1. startup builds the root provider (env/file) and **refuses to boot** on a
//!    missing/short root key (fail closed, never silently plaintext);
//! 2. [`bootstrap`] idempotently creates the active KEK + DEK (atomic
//!    create-if-absent in the key store — two instances starting together
//!    create exactly one) and runs a first backfill pass so existing plaintext
//!    `upstream_password` rows and auth-realm secrets are wrapped immediately;
//! 3. the [`spawn_worker`] loop keeps the system converged: plaintext
//!    backfill, the DEK re-encrypt sweep, retire/revoke bookkeeping, age-based
//!    DEK/KEK rotation, and the root re-wrap sweep (after an operator swaps
//!    the root key).
//!
//! ## Cluster coordination
//!
//! The worker pass **and** the admin `POST /admin/crypto/rotate/*` endpoints
//! run under one Postgres **session advisory lock** ([`ROTATION_LOCK_KEY`],
//! [`try_rotation_lock`]) held on a dedicated connection, so exactly one
//! rotation runs cluster-wide at a time (deliberately different from the
//! lease-based workers because a rotation pass spans several tables). A worker
//! tick that finds the lock taken skips its pass; an admin request gets 409.
//! Every step inside is idempotent and resumable, so a crashed pass is simply
//! finished by the next holder. The lock is the first line of defence only:
//! the key store's compare-and-swap re-wraps and commit-time-checked
//! revocations (`forge-crypto` / `forge-db`) keep the hierarchy consistent
//! even when rotations do overlap (e.g. a mixed-version rolling deploy, or the
//! unlocked startup bootstrap).

use std::sync::Arc;

use anyhow::Context;
use forge_crypto::kms::StaticRootProvider;
use forge_crypto::service::{EnvelopeService, EnvelopeServiceConfig};
use forge_crypto::store::{KeyLayer, KeyRecord, KeyState};
use forge_crypto::Algorithm;
use forge_db::encryption_key_dao::PgKeyStore;
use forge_db::secret_dao;
use sqlx::PgPool;
use tokio::task::JoinHandle;

use crate::config::{Config, CryptoConfig};

/// Advisory-lock key serializing rotation passes (worker + admin endpoints,
/// `pg_try_advisory_lock`). The value is arbitrary but fixed: ASCII
/// `"forge125"` as a big-endian i64, namespacing it away from other forge
/// advisory-lock users.
pub const ROTATION_LOCK_KEY: i64 = 0x666f_7267_6531_3235;

/// The cluster-wide rotation lock, held: a session advisory lock on a
/// dedicated pooled connection (session locks belong to a connection, so lock
/// and unlock must run on the same one, never through the pool's round-robin).
///
/// Call [`RotationLock::release`] when done. If the guard is dropped without it
/// (an error path, or an admin request whose client disconnected and whose
/// handler future was cancelled), the connection is **closed** instead of
/// returned to the pool, which releases the lock server-side — a pooled
/// connection must never keep holding it.
pub struct RotationLock {
    conn: sqlx::pool::PoolConnection<sqlx::Postgres>,
    released: bool,
}

impl RotationLock {
    /// Unlock and hand the connection back to the pool. On an unlock failure
    /// the connection is closed instead (which also releases the lock).
    pub async fn release(mut self) {
        match sqlx::query(r#"SELECT pg_advisory_unlock($1)"#)
            .bind(ROTATION_LOCK_KEY)
            .execute(&mut *self.conn)
            .await
        {
            Ok(_) => self.released = true,
            Err(e) => {
                tracing::warn!(error = %e, "crypto rotation advisory unlock failed (released on close)");
            }
        }
    }
}

impl Drop for RotationLock {
    fn drop(&mut self) {
        if !self.released {
            self.conn.close_on_drop();
        }
    }
}

/// Try to take the cluster-wide rotation lock without waiting. `Ok(None)` when
/// another instance (or request) holds it.
pub async fn try_rotation_lock(pool: &PgPool) -> anyhow::Result<Option<RotationLock>> {
    let conn = pool
        .acquire()
        .await
        .context("acquire advisory-lock connection")?;
    // Guard the connection *before* asking for the lock: if this future is
    // cancelled after the server granted it but before the reply was read,
    // the guard's drop closes the connection (releasing the lock) rather
    // than returning a lock-holding connection to the pool.
    let mut guard = RotationLock {
        conn,
        released: false,
    };
    let got: bool = sqlx::query_scalar(r#"SELECT pg_try_advisory_lock($1)"#)
        .bind(ROTATION_LOCK_KEY)
        .fetch_one(&mut *guard.conn)
        .await
        .context("try advisory lock")?;
    if !got {
        // Not held: the connection goes straight back to the pool.
        guard.released = true;
        return Ok(None);
    }
    Ok(Some(guard))
}

/// Refuse to run without an envelope service while the database holds sealed
/// secrets. Such an instance would serve 500 for every proxy with
/// credentials, skip the OIDC and credential-forwarding realms whose secrets
/// are sealed, and store new secrets in plaintext; that is what a deployment
/// gets when a manifest drops `FORGE_CRYPTO__ROOT__PROVIDER`.
pub async fn refuse_sealed_secrets_without_envelope(pool: &PgPool) -> anyhow::Result<()> {
    let sealed = secret_dao::sealed_secrets_present(pool)
        .await
        .context("check for sealed secrets")?;
    if sealed {
        anyhow::bail!(
            "the database holds encrypted secrets but secret encryption is not configured \
             (no [crypto] section / FORGE_CRYPTO__ROOT__PROVIDER): restore the crypto \
             configuration and its root key; turning encryption off once secrets are \
             sealed is not supported"
        );
    }
    Ok(())
}

/// Build the [`EnvelopeService`] from the `[crypto]` config, or `None` when
/// the section is absent/disabled. Errors (unknown provider, missing or
/// malformed root key) must abort startup — an operator who configured
/// encryption never gets a silently-plaintext instance.
pub fn build_envelope(
    config: &Config,
    pool: &PgPool,
) -> anyhow::Result<Option<Arc<EnvelopeService>>> {
    let Some(crypto) = config.crypto.as_ref().filter(|c| c.enabled) else {
        tracing::info!("secret encryption at rest is disabled (no [crypto] config)");
        return Ok(None);
    };

    let algorithm = Algorithm::parse(&crypto.algorithm)
        .map_err(|e| anyhow::anyhow!("crypto.algorithm: {e}"))?;

    let root = match crypto.root.provider.as_str() {
        "env" => StaticRootProvider::from_env(
            algorithm,
            &crypto.root.root_key_env,
            crypto.root.root_key_env_previous.as_deref(),
        )
        .context("load root key from env")?,
        "file" => {
            let path = crypto
                .root
                .root_key_path
                .as_deref()
                .context("crypto.root.root_key_path is required (validated config?)")?;
            StaticRootProvider::from_file(
                algorithm,
                std::path::Path::new(path),
                crypto
                    .root
                    .root_key_path_previous
                    .as_deref()
                    .map(std::path::Path::new),
            )
            .context("load root key from file")?
        }
        other => anyhow::bail!("unsupported crypto.root.provider {other:?} (validated config?)"),
    };

    let service = EnvelopeService::new(
        Arc::new(PgKeyStore::new(pool.clone())),
        Arc::new(root),
        EnvelopeServiceConfig {
            algorithm,
            scope: "default".to_string(),
            unwrapped_key_ttl: std::time::Duration::from_secs(crypto.cache.unwrapped_key_ttl_secs),
            unwrapped_key_max: crypto.cache.unwrapped_key_max,
        },
    );
    tracing::info!(
        provider = %crypto.root.provider,
        algorithm = %algorithm,
        "secret encryption at rest enabled"
    );
    Ok(Some(Arc::new(service)))
}

/// Startup bootstrap: ensure the active KEK + DEK exist and run a first
/// backfill pass so plaintext rows (written before encryption was enabled) are
/// wrapped — and their plaintext cleared — right away (the worker keeps
/// backfilling if this instance loses the race / more rows appear).
/// Also verifies every KEK is unwrappable under the configured root(s) so a
/// botched root rotation surfaces at boot, not at the first secret read.
pub async fn bootstrap(
    pool: &PgPool,
    envelope: &Arc<EnvelopeService>,
    crypto: &CryptoConfig,
) -> anyhow::Result<()> {
    envelope
        .ensure_active_keys()
        .await
        .context("bootstrap encryption keys")?;

    // Readiness check: every non-revoked KEK's recorded root version must be
    // reachable, otherwise decryption of some DEKs would fail later.
    // `rewrap_keks` doubles as the check — it unwraps with the recorded
    // version and re-wraps under the current root (no-op when already current).
    envelope
        .rewrap_keks()
        .await
        .context("verify/re-wrap KEKs under the configured root")?;

    let batch = crypto.rotation.sweep_batch_size.max(1);
    let mut total = 0usize;
    loop {
        let done = secret_dao::backfill_upstream_passwords(pool, envelope, batch)
            .await
            .context("backfill plaintext upstream passwords")?;
        total += done;
        if done < usize::try_from(batch).unwrap_or(usize::MAX) {
            break;
        }
    }
    if total > 0 {
        tracing::info!(
            rows = total,
            "moved plaintext upstream passwords into envelopes (plaintext cleared)"
        );
    }
    let realms = secret_dao::backfill_realm_secrets(pool, envelope, crate::auth::secret_keys)
        .await
        .context("backfill plaintext realm secrets")?;
    if realms > 0 {
        tracing::info!(realms, "encrypted plaintext auth-realm secrets at rest");
    }
    let settings = secret_dao::backfill_secret_settings(pool, envelope)
        .await
        .context("backfill plaintext secret settings")?;
    if settings > 0 {
        tracing::info!(settings, "encrypted plaintext secret settings at rest");
    }
    let imports = secret_dao::backfill_import_passwords(pool, envelope)
        .await
        .context("backfill plaintext import passwords")?;
    if imports > 0 {
        tracing::info!(
            imports,
            "encrypted plaintext Nexus import passwords at rest"
        );
    }
    if secret_dao::backfill_email_secrets(pool, envelope)
        .await
        .context("backfill plaintext email settings secrets")?
    {
        tracing::info!("encrypted the plaintext email settings secrets at rest");
    }

    // Secrets sealed by earlier builds are bound to their row only: re-seal
    // them for the destination they are sent to (the rotation worker repeats
    // this, but it may be disabled). Rows already converged cost one open.
    let resealed = reseal_all(pool, envelope, batch)
        .await
        .context("re-seal secrets for their destination")?;
    if resealed > 0 {
        tracing::info!(
            rows = resealed,
            "re-sealed secrets for the destination they are sent to"
        );
    }
    Ok(())
}

/// Run the re-encrypt sweeps (upstream passwords, realm secrets, secret
/// settings, import passwords, email settings secrets) to the end; returns
/// how many rows were re-sealed.
async fn reseal_all(
    pool: &PgPool,
    envelope: &EnvelopeService,
    batch: i64,
) -> Result<usize, secret_dao::SecretDbError> {
    let mut resealed = 0;
    let mut after_id = 0i64;
    loop {
        let swept =
            secret_dao::reseal_upstream_passwords_batch(pool, envelope, after_id, batch).await?;
        resealed += swept.resealed;
        match swept.next_after_id {
            Some(id) => after_id = id,
            None => break,
        }
    }
    resealed += secret_dao::reseal_realm_secrets(pool, envelope).await?;
    resealed += secret_dao::reseal_secret_settings(pool, envelope).await?;
    resealed += secret_dao::reseal_import_passwords(pool, envelope).await?;
    resealed += secret_dao::reseal_email_secrets(pool, envelope).await?;
    Ok(resealed)
}

/// Spawn the rotation/backfill worker loop. Each tick tries the cluster-wide
/// advisory lock and, when held, runs one full [`rotation_pass`]. Returns
/// `None` when the worker is disabled by config.
pub fn spawn_worker(
    pool: PgPool,
    envelope: Arc<EnvelopeService>,
    crypto: &CryptoConfig,
) -> Option<JoinHandle<()>> {
    if !crypto.rotation.enabled {
        tracing::info!("crypto rotation worker disabled (FORGE_CRYPTO__ROTATION__ENABLED=false)");
        return None;
    }
    let interval = crypto.poll_interval();
    let cfg = crypto.rotation.clone();
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = locked_rotation_pass(&pool, &envelope, &cfg).await {
                tracing::error!(error = %e, "crypto rotation pass failed");
            }
        }
    }))
}

/// Take the advisory lock (skip the pass when another instance or an admin
/// rotation holds it) and run [`rotation_pass`], releasing the lock afterwards.
async fn locked_rotation_pass(
    pool: &PgPool,
    envelope: &Arc<EnvelopeService>,
    cfg: &crate::config::CryptoRotationConfig,
) -> anyhow::Result<()> {
    let Some(lock) = try_rotation_lock(pool).await? else {
        tracing::debug!("another instance holds the crypto rotation lock; skipping pass");
        return Ok(());
    };
    let result = rotation_pass(pool, envelope, cfg).await;
    lock.release().await;
    result
}

/// One idempotent convergence pass. Order matters:
/// 1. **age-based rotation** first, so the sweeps below converge on the new
///    keys within the same pass;
/// 2. **root re-wrap** (no-op unless the operator rotated the root);
/// 3. **DEK re-wrap under the active KEK** (no-op unless a KEK rotated);
/// 4. **plaintext backfill** (no-op once every row is wrapped);
/// 5. **DEK re-encrypt sweep** over secret ciphertext;
/// 6. **revoke** now-unreferenced retiring DEKs/KEKs.
async fn rotation_pass(
    pool: &PgPool,
    envelope: &Arc<EnvelopeService>,
    cfg: &crate::config::CryptoRotationConfig,
) -> anyhow::Result<()> {
    // 1. Age-based rotation.
    if let Some(active) = active_key(envelope, KeyLayer::Dek).await? {
        if over_age(&active, cfg.dek_max_age_days) {
            tracing::info!(
                version = active.version,
                "active DEK exceeded max age; rotating"
            );
            envelope
                .rotate_dek()
                .await
                .context("age-based DEK rotation")?;
        }
    }
    if let Some(active) = active_key(envelope, KeyLayer::Kek).await? {
        if over_age(&active, cfg.kek_max_age_days) {
            tracing::info!(
                version = active.version,
                "active KEK exceeded max age; rotating"
            );
            envelope
                .rotate_kek()
                .await
                .context("age-based KEK rotation")?;
        }
    }

    // 2./3. Key-layer re-wrap sweeps (cheap no-ops when converged).
    envelope.rewrap_keks().await.context("root re-wrap sweep")?;
    envelope.rewrap_deks().await.context("KEK re-wrap sweep")?;

    // 4. Plaintext backfill (resumable; processed rows leave the predicate).
    let batch = cfg.sweep_batch_size.max(1);
    loop {
        let done = secret_dao::backfill_upstream_passwords(pool, envelope, batch)
            .await
            .context("plaintext backfill")?;
        if done < usize::try_from(batch).unwrap_or(usize::MAX) {
            break;
        }
    }
    secret_dao::backfill_realm_secrets(pool, envelope, crate::auth::secret_keys)
        .await
        .context("realm secrets backfill")?;
    secret_dao::backfill_secret_settings(pool, envelope)
        .await
        .context("secret settings backfill")?;
    secret_dao::backfill_import_passwords(pool, envelope)
        .await
        .context("import passwords backfill")?;
    secret_dao::backfill_email_secrets(pool, envelope)
        .await
        .context("email settings secrets backfill")?;

    // 5. DEK re-encrypt sweep (keyset-paginated over the secret columns).
    reseal_all(pool, envelope, batch)
        .await
        .context("DEK re-encrypt sweep")?;

    // 6. Revoke keys nothing references anymore.
    secret_dao::revoke_unreferenced_deks(pool, envelope)
        .await
        .context("revoke unreferenced DEKs")?;
    envelope
        .revoke_unreferenced_keks()
        .await
        .context("revoke unreferenced KEKs")?;
    Ok(())
}

async fn active_key(
    envelope: &Arc<EnvelopeService>,
    layer: KeyLayer,
) -> anyhow::Result<Option<KeyRecord>> {
    Ok(envelope
        .list_keys(layer)
        .await
        .context("list keys")?
        .into_iter()
        .find(|k| k.state == KeyState::Active))
}

/// Whether `key` left its rotation budget behind (`max_age_days <= 0` disables
/// age-based rotation for the layer).
fn over_age(key: &KeyRecord, max_age_days: i64) -> bool {
    max_age_days > 0 && chrono::Utc::now() - key.created_at > chrono::Duration::days(max_age_days)
}
