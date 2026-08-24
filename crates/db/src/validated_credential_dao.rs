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
//!
//! ## Side tables
//!
//! * `validated_credential_tag` — the per-username revocation **fence**
//!   ([`lock_user_tag`] / [`revoke_by_username`]). Rows are transient lock
//!   anchors, not an audit trail: [`sweep_orphaned_tags`] reaps any row whose
//!   username has no verdicts left, so rejected/sprayed usernames never
//!   accumulate.
//! * `auth_success` — the durable successful-authentication log
//!   ([`record_auth_success`]), written only on a definitive upstream ACCEPT,
//!   unique per (username, auth method) and capped at the
//!   [`AUTH_SUCCESS_METHODS_KEPT`] most recently used methods per user. Used to
//!   decide when an upstream (e.g. Nexus) can be cut off.

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
pub async fn upsert_verdict(pool: &PgPool, new: NewVerdict) -> sqlx::Result<ValidatedCredential> {
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

/// Materialize and share-lock the durable revocation tag for `username`.
///
/// Production credential fills call this before taking the per-credential row
/// lock and before forwarding upstream. [`revoke_by_username`] advances the same
/// row under an exclusive lock, so revocation either happens before a fill (the
/// fill is a fresh post-revocation validation) or waits for it and then deletes
/// its verdict. There is no absent-row gap in which a stale fill can resurrect a
/// deleted verdict.
///
/// The row this creates is **transient**, not a durable record of the attempt:
/// once no verdict rows remain for the username (rejected/sprayed usernames
/// after their negative TTL, revoked users after the revocation's delete),
/// [`sweep_orphaned_tags`] reaps it, so unauthenticated spray cannot grow the
/// table without bound.
pub async fn lock_user_tag(
    tx: &mut Transaction<'_, Postgres>,
    username: &str,
) -> sqlx::Result<i64> {
    // The sweeper may delete the row between our INSERT … DO NOTHING (which
    // takes no lock when the row already exists) and the SELECT … FOR SHARE,
    // so re-materialize and retry on a vanished row instead of failing the
    // fill. Two rounds suffice: our second INSERT's uncommitted row cannot be
    // swept (the sweeper's FOR UPDATE SKIP LOCKED never sees/needs it).
    for _ in 0..2 {
        sqlx::query(
            r#"
            INSERT INTO validated_credential_tag (username)
            VALUES ($1)
            ON CONFLICT (username) DO NOTHING
            "#,
        )
        .bind(username)
        .execute(&mut **tx)
        .await?;

        let generation: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT generation
            FROM validated_credential_tag
            WHERE username = $1
            FOR SHARE
            "#,
        )
        .bind(username)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(generation) = generation {
            return Ok(generation);
        }
    }
    Err(sqlx::Error::RowNotFound)
}

/// How many auth methods (provider ids) [`record_auth_success`] retains per
/// username: only the most recently used ones survive the prune.
pub const AUTH_SUCCESS_METHODS_KEPT: i64 = 5;

/// One successful-authentication record: the latest (and first) time
/// `username` was definitively accepted through `auth_method` (a provider id).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthSuccess {
    pub username: String,
    pub auth_method: String,
    pub first_success_at: DateTime<Utc>,
    pub last_success_at: DateTime<Utc>,
}

/// Record that `username` was successfully validated through `auth_method`
/// (the provider id), inside the fill transaction, and prune the username down
/// to its [`AUTH_SUCCESS_METHODS_KEPT`] most recently used methods.
///
/// Called **only** on a definitive upstream ACCEPT — rejected attempts leave no
/// row here — and at most once per positive-TTL window per credential (the
/// fill is the only writer), so the hot cache path stays write-free. Two
/// concurrent winning fills for the same (username, method) serialize briefly
/// on the row at the end of their transactions, which is harmless.
pub async fn record_auth_success(
    tx: &mut Transaction<'_, Postgres>,
    username: &str,
    auth_method: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO auth_success (username, auth_method)
        VALUES ($1, $2)
        ON CONFLICT (username, auth_method)
        DO UPDATE SET last_success_at = now()
        "#,
    )
    .bind(username)
    .bind(auth_method)
    .execute(&mut **tx)
    .await?;

    // Keep only the most recently used methods for this username (the
    // `auth_method` tiebreak makes the survivor set deterministic when
    // timestamps collide).
    sqlx::query(
        r#"
        DELETE FROM auth_success
        WHERE username = $1
          AND auth_method NOT IN (
            SELECT auth_method FROM auth_success
            WHERE username = $1
            ORDER BY last_success_at DESC, auth_method
            LIMIT $2
          )
        "#,
    )
    .bind(username)
    .bind(AUTH_SUCCESS_METHODS_KEPT)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The retained successful-auth records for `username`, most recent first.
/// This is the "who still authenticates through which upstream?" read used to
/// decide when an upstream can be cut off.
pub async fn list_auth_successes(pool: &PgPool, username: &str) -> sqlx::Result<Vec<AuthSuccess>> {
    sqlx::query_as::<_, AuthSuccess>(
        r#"
        SELECT username, auth_method, first_success_at, last_success_at
        FROM auth_success
        WHERE username = $1
        ORDER BY last_success_at DESC, auth_method
        "#,
    )
    .bind(username)
    .fetch_all(pool)
    .await
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
    let mut tx = pool.begin().await?;

    // The upsert is the revocation's linearization point. It takes an exclusive
    // row lock and therefore waits for every pre-existing fill holding the
    // shared user-tag lock. New fills observe the advanced generation and run
    // only after this transaction commits.
    sqlx::query(
        r#"
        INSERT INTO validated_credential_tag (username, generation)
        VALUES ($1, 1)
        ON CONFLICT (username)
        DO UPDATE SET generation = validated_credential_tag.generation + 1,
                      updated_at = now()
        "#,
    )
    .bind(username)
    .execute(&mut *tx)
    .await?;

    let res = sqlx::query!(
        r#"
        DELETE FROM validated_credential
        WHERE username = $1
          AND ($2::text IS NULL OR provider_id = $2)
        "#,
        username,
        provider_id,
    )
    .execute(&mut *tx)
    .await?;
    let deleted = res.rows_affected();
    tx.commit().await?;
    Ok(deleted)
}

/// Delete all expired rows (the background sweeper). Returns the count removed.
pub async fn sweep_expired(pool: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query!(r#"DELETE FROM validated_credential WHERE expires_at <= now()"#,)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// Reap `validated_credential_tag` rows that no longer fence anything: no
/// verdict rows remain for the username (all expired-and-swept or revoked).
/// Returns the count removed.
///
/// This is what keeps the tag table bounded — rejected/sprayed usernames leave
/// a tag row plus a short-TTL negative verdict; once [`sweep_expired`] removes
/// the verdict, this removes the tag. Correctness of the fence never depends
/// on the row surviving: an absent row simply re-materializes as generation 0
/// on the next fill, and any fill currently share-locking its row is skipped
/// (`FOR UPDATE SKIP LOCKED`), so an in-flight fill's fence is never pulled
/// out from under it. `lock_user_tag` tolerates the between-statement window
/// by retrying.
pub async fn sweep_orphaned_tags(pool: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query(
        r#"
        DELETE FROM validated_credential_tag
        WHERE ctid IN (
            SELECT t.ctid
            FROM validated_credential_tag t
            WHERE NOT EXISTS (
                SELECT 1 FROM validated_credential v WHERE v.username = t.username
            )
            FOR UPDATE SKIP LOCKED
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
