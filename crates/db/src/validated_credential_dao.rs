//! Data access for `validated_credential` (slice 12.3): the durable,
//! authoritative backing store of the validated-credential cache.
//!
//! NuGet clients send Basic credentials on *every* request, so forwarding each
//! one to the configured upstream is unacceptable. The
//! [`forge_cache::Cache`](../../cache) L1(+optional L2) layer absorbs the hot
//! path, but the **authoritative** validation verdict lives here in Postgres so
//! a cold instance with no Redis still avoids re-forwarding (the no
//! in-memory-only-authoritative-state rule).
//!
//! ## What is stored
//!
//! Never the plaintext password. The lookup key, `cred_hmac`, is
//! `HMAC-SHA256(pepper, provider_id | username | password)` (hex) computed in
//! `forge-core`; this DAO only ever sees the opaque hmac. A row carries the
//! boolean `verdict` (`true` = valid, `false` = rejected) and an `expires_at`
//! that bounds the trust window. Infrastructure errors / timeouts are
//! **fail-closed**: the caller writes *no* row, so the next attempt re-forwards.
//!
//! ## Singleflight (no advisory locks)
//!
//! A burst of identical NuGet requests across instances must forward upstream
//! **once**. We coalesce on a **row lock**, never `pg_advisory_*`:
//! [`begin_singleflight`] does `INSERT … ON CONFLICT DO NOTHING` on the unique
//! `(provider_id, username, cred_hmac)` triple to materialize an anchor row,
//! then `SELECT … FOR UPDATE` to take a row-level lock inside the caller's
//! transaction. The first caller holds the lock, forwards upstream, writes the
//! verdict, and commits; concurrent callers block on the lock and, once it is
//! released, read the freshly-written verdict. See [`upsert_verdict`].

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};

use crate::model::ValidatedCredential;

/// A validation verdict to persist: the lookup triple, the boolean decision,
/// and the absolute expiry that bounds its trust window.
#[derive(Debug, Clone)]
pub struct NewVerdict {
    pub provider_id: String,
    pub username: String,
    /// `HMAC-SHA256(pepper, provider_id | username | password)`, hex-encoded.
    /// **Never** the plaintext password.
    pub cred_hmac: String,
    /// `true` = credentials valid (positive cache), `false` = definitively
    /// rejected (negative cache).
    pub verdict: bool,
    /// Absolute expiry (positive/negative TTL applied by the caller).
    pub expires_at: DateTime<Utc>,
}

/// Read the (non-expired) verdict for a `(provider_id, username, cred_hmac)`
/// triple, or `None` if there is no row or it has expired.
///
/// Expired rows are treated as a miss (and swept lazily by [`sweep_expired`]);
/// the caller must re-forward upstream on a miss.
pub async fn get_verdict(
    pool: &PgPool,
    provider_id: &str,
    username: &str,
    cred_hmac: &str,
) -> sqlx::Result<Option<ValidatedCredential>> {
    sqlx::query_as!(
        ValidatedCredential,
        r#"
        SELECT id, provider_id, username, cred_hmac, verdict, expires_at, created_at
        FROM validated_credential
        WHERE provider_id = $1 AND username = $2 AND cred_hmac = $3
          AND expires_at > now()
        "#,
        provider_id,
        username,
        cred_hmac,
    )
    .fetch_optional(pool)
    .await
}

/// Insert-or-replace the verdict for a triple, refreshing `verdict` and
/// `expires_at` (and `created_at`) on conflict. Returns the persisted row.
///
/// Called by the singleflight winner after a *real* upstream success/reject.
/// An infrastructure error / timeout must **never** be persisted (fail-closed),
/// so callers only invoke this for a definitive `true`/`false` verdict.
pub async fn upsert_verdict(
    pool: &PgPool,
    new: NewVerdict,
) -> sqlx::Result<ValidatedCredential> {
    sqlx::query_as!(
        ValidatedCredential,
        r#"
        INSERT INTO validated_credential
            (provider_id, username, cred_hmac, verdict, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (provider_id, username, cred_hmac)
        DO UPDATE SET verdict    = EXCLUDED.verdict,
                      expires_at = EXCLUDED.expires_at,
                      created_at = now()
        RETURNING id, provider_id, username, cred_hmac, verdict, expires_at, created_at
        "#,
        new.provider_id,
        new.username,
        new.cred_hmac,
        new.verdict,
        new.expires_at,
    )
    .fetch_one(pool)
    .await
}

/// Singleflight anchor: materialize the row for `(provider_id, username,
/// cred_hmac)` (if absent) and take a row-level `FOR UPDATE` lock on it inside
/// `tx`, so concurrent identical credential checks forward upstream **once**.
///
/// Returns the locked row when one already carries a verdict (a peer won the
/// race and wrote it — the caller should re-read via [`get_verdict`] / use the
/// returned row instead of forwarding), or `None` when this caller is the
/// singleflight **winner** and must forward upstream then [`upsert_verdict`].
///
/// Coalescing is purely a ROW lock (no `pg_advisory_*`): the `INSERT … ON
/// CONFLICT DO NOTHING` is a no-op for the loser, and the subsequent `SELECT …
/// FOR UPDATE` blocks until the winner's transaction commits. To distinguish
/// "I am the winner" from "a peer already produced a fresh verdict", we insert a
/// sentinel anchor (an *expired* negative row) and treat a row that is still the
/// sentinel — i.e. expired — as "winner: go forward". A row with a future
/// `expires_at` means a peer wrote a real verdict while we waited.
pub async fn begin_singleflight(
    tx: &mut Transaction<'_, Postgres>,
    provider_id: &str,
    username: &str,
    cred_hmac: &str,
) -> sqlx::Result<Option<ValidatedCredential>> {
    // Materialize an expired sentinel anchor if no row exists yet. The sentinel
    // has `expires_at = -infinity`-ish (epoch) so it never counts as a valid
    // cached verdict; it exists only to give us a row to lock.
    sqlx::query!(
        r#"
        INSERT INTO validated_credential
            (provider_id, username, cred_hmac, verdict, expires_at)
        VALUES ($1, $2, $3, false, to_timestamp(0))
        ON CONFLICT (provider_id, username, cred_hmac) DO NOTHING
        "#,
        provider_id,
        username,
        cred_hmac,
    )
    .execute(&mut **tx)
    .await?;

    // Take the row lock. Whoever holds it is serialized against peers for this
    // triple. Blocks until any in-flight winner commits.
    let row = sqlx::query_as!(
        ValidatedCredential,
        r#"
        SELECT id, provider_id, username, cred_hmac, verdict, expires_at, created_at
        FROM validated_credential
        WHERE provider_id = $1 AND username = $2 AND cred_hmac = $3
        FOR UPDATE
        "#,
        provider_id,
        username,
        cred_hmac,
    )
    .fetch_one(&mut **tx)
    .await?;

    // A future expiry means a peer already wrote a real verdict while we waited
    // on the lock: hand it back so the caller can use it without forwarding. An
    // expired row is still the sentinel (or a stale verdict): this caller is the
    // winner and must forward upstream.
    if row.expires_at > Utc::now() {
        Ok(Some(row))
    } else {
        Ok(None)
    }
}

/// Finalize the singleflight: write the real verdict onto the anchor row that
/// the caller locked via [`begin_singleflight`], **inside the same
/// transaction**. The caller commits `tx` afterwards, which releases the row
/// lock and lets waiting peers read the verdict.
///
/// Using the same `tx` is essential: the row is `FOR UPDATE`-locked by this
/// transaction, so the write must go through it (a second connection would
/// deadlock against the held lock).
pub async fn finalize_singleflight(
    tx: &mut Transaction<'_, Postgres>,
    new: NewVerdict,
) -> sqlx::Result<ValidatedCredential> {
    sqlx::query_as!(
        ValidatedCredential,
        r#"
        INSERT INTO validated_credential
            (provider_id, username, cred_hmac, verdict, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (provider_id, username, cred_hmac)
        DO UPDATE SET verdict    = EXCLUDED.verdict,
                      expires_at = EXCLUDED.expires_at,
                      created_at = now()
        RETURNING id, provider_id, username, cred_hmac, verdict, expires_at, created_at
        "#,
        new.provider_id,
        new.username,
        new.cred_hmac,
        new.verdict,
        new.expires_at,
    )
    .fetch_one(&mut **tx)
    .await
}

/// Revoke every cached verdict for a username (optionally scoped to one
/// provider): the admin "force re-auth user X" / deactivate-user path. Returns
/// the number of rows deleted. The caller must also drop the matching cache
/// entries via the [`forge_cache`] invalidation backplane.
pub async fn revoke_by_username(
    pool: &PgPool,
    username: &str,
    provider_id: Option<&str>,
) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        r#"
        DELETE FROM validated_credential
        WHERE username = $1
          AND ($2::text IS NULL OR provider_id = $2)
        "#,
        username,
        provider_id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Delete all expired rows (the background sweeper). Returns the count removed.
pub async fn sweep_expired(pool: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        r#"DELETE FROM validated_credential WHERE expires_at <= now()"#,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
