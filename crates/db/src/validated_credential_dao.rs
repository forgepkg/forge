//! Data access for `validated_credential`: the durable, authoritative backing
//! store of the validated-credential cache.
//!
//! NuGet clients send Basic credentials on *every* request, so forwarding each
//! one to the configured upstream is unacceptable. The
//! [`forge_cache::Cache`](../../cache) in-process L1 layer absorbs the hot
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
//! ## Singleflight (no advisory locks, no lock held across the network)
//!
//! A burst of identical NuGet requests across instances must forward upstream
//! **once**, but a fill must never pin a pooled connection while the upstream
//! answers (an upstream stall or a password spray would otherwise drain the
//! pool and take every DB-backed request down with it). The singleflight is
//! therefore a short-lived **lease** recorded on the row itself, never a held
//! transaction and never `pg_advisory_*`:
//!
//! 1. [`claim_singleflight`] — one autocommit `INSERT … ON CONFLICT DO UPDATE …
//!    WHERE` on the unique `(provider_id, username, cred_hmac)` triple. It
//!    stamps a fresh `claim_token` + `claimed_until` lease onto the row unless a
//!    fresh verdict or a live peer claim is already there. Exactly one caller
//!    wins a given lease.
//! 2. The winner forwards upstream holding **no** connection, then
//!    [`finalize_claim`] writes the verdict in a second short transaction,
//!    *conditioned on still holding its `claim_token`*. A revocation that
//!    deleted the row meanwhile (or a peer that took over a lapsed lease)
//!    fences the stale result: nothing is written.
//! 3. A winner that cannot produce a definitive verdict (upstream outage)
//!    [`release_claim`]s, so peers take over at once instead of waiting out
//!    the lease.
//! 4. Losers poll [`claim_state`] (one indexed `SELECT`, no lock) until the
//!    verdict lands or the lease lapses, then claim it themselves — a crashed
//!    or cancelled winner delays its peers by at most one lease.
//!
//! A claim row is never a verdict on its own: it is written with an expired
//! `expires_at`, so [`get_verdict`] keeps ignoring it.
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

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

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
/// An unconditional write (no singleflight lease, no revocation fence): the
/// production fill path is [`claim_singleflight`] → [`finalize_claim`]. Any
/// lease on the row is cleared. An infrastructure error / timeout must
/// **never** be persisted (fail-closed), so callers only invoke this for a
/// definitive `true`/`false` verdict.
pub async fn upsert_verdict(pool: &PgPool, new: NewVerdict) -> sqlx::Result<ValidatedCredential> {
    sqlx::query_as!(
        ValidatedCredential,
        r#"
        INSERT INTO validated_credential
            (provider_id, username, cred_hmac, verdict, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (provider_id, username, cred_hmac)
        DO UPDATE SET verdict       = EXCLUDED.verdict,
                      expires_at    = EXCLUDED.expires_at,
                      created_at    = now(),
                      claim_token   = NULL,
                      claimed_until = NULL
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

/// Outcome of a [`claim_singleflight`] attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// This caller holds the lease identified by `token` and must forward
    /// upstream, then either [`finalize_claim`] (definitive verdict) or
    /// [`release_claim`] (no verdict).
    Won { token: Uuid },
    /// The row already carries a fresh verdict (a peer wrote it): use it, do
    /// not forward.
    Verdict(FreshVerdict),
    /// A peer holds a live lease: poll [`claim_state`] and retry.
    Busy,
}

/// A fresh (non-expired) verdict and how long it has left, measured on the
/// database clock, so a cache in front of the row never keeps it longer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshVerdict {
    /// `true` = the credential was accepted.
    pub verdict: bool,
    /// Time until the row's `expires_at`.
    pub remaining: Duration,
}

/// What a polling loser sees on the row (see [`claim_state`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimState {
    /// A fresh verdict landed.
    Fresh(FreshVerdict),
    /// A peer still holds a live lease.
    Claimed,
    /// Neither: the row is gone, expired, released or its lease lapsed — the
    /// caller may [`claim_singleflight`] it.
    Open,
}

/// Try to win the singleflight lease for `(provider_id, username, cred_hmac)`.
///
/// One autocommit statement — no transaction or row lock outlives it. The
/// upsert materializes an anchor row (an *expired* negative verdict, so it is
/// never served as a cached verdict) and stamps `claim_token = token`,
/// `claimed_until = now() + lease` onto it, but only when the row carries
/// neither a fresh verdict nor a live peer lease. Concurrent claimers serialize
/// on the unique index, so exactly one of them wins a lease; a lapsed lease
/// (crashed / cancelled winner) is simply re-claimed.
///
/// `lease` must outlast the winner's upstream forward plus its verdict write;
/// a winner that overruns may find its lease taken over and its verdict
/// fenced, which costs a duplicate forward but never correctness.
pub async fn claim_singleflight(
    pool: &PgPool,
    provider_id: &str,
    username: &str,
    cred_hmac: &str,
    lease: Duration,
) -> sqlx::Result<Claim> {
    let token = Uuid::new_v4();
    let won = sqlx::query_scalar!(
        r#"
        INSERT INTO validated_credential AS vc
            (provider_id, username, cred_hmac, verdict, expires_at,
             claim_token, claimed_until)
        VALUES ($1, $2, $3, false, to_timestamp(0),
                $4, now() + make_interval(secs => $5))
        ON CONFLICT (provider_id, username, cred_hmac) DO UPDATE
        SET claim_token   = EXCLUDED.claim_token,
            claimed_until = EXCLUDED.claimed_until
        WHERE vc.expires_at <= now()
          AND (vc.claimed_until IS NULL OR vc.claimed_until <= now())
        RETURNING vc.id
        "#,
        provider_id,
        username,
        cred_hmac,
        token,
        lease.as_secs_f64(),
    )
    .fetch_optional(pool)
    .await?;
    if won.is_some() {
        return Ok(Claim::Won { token });
    }
    Ok(
        match claim_state(pool, provider_id, username, cred_hmac).await? {
            ClaimState::Fresh(fresh) => Claim::Verdict(fresh),
            // `Open` here means the blocking row vanished or its lease lapsed
            // between the two statements; the caller's next poll re-claims it.
            ClaimState::Claimed | ClaimState::Open => Claim::Busy,
        },
    )
}

/// Read the singleflight state of a triple without locking anything: the
/// polling loser's view (see [`ClaimState`]).
pub async fn claim_state(
    pool: &PgPool,
    provider_id: &str,
    username: &str,
    cred_hmac: &str,
) -> sqlx::Result<ClaimState> {
    let row = sqlx::query!(
        r#"
        SELECT verdict,
               expires_at > now() AS "fresh!",
               GREATEST(EXTRACT(EPOCH FROM expires_at - now()), 0)::float8 AS "remaining_secs!",
               COALESCE(claimed_until > now(), false) AS "claimed!"
        FROM validated_credential
        WHERE provider_id = $1 AND username = $2 AND cred_hmac = $3
        "#,
        provider_id,
        username,
        cred_hmac,
    )
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some(r) if r.fresh => ClaimState::Fresh(FreshVerdict {
            verdict: r.verdict,
            remaining: Duration::from_secs_f64(r.remaining_secs),
        }),
        Some(r) if r.claimed => ClaimState::Claimed,
        _ => ClaimState::Open,
    })
}

/// Write the winner's definitive verdict — in a short transaction of its own,
/// **only if it still holds `token`** — and, for an accept, record the
/// `auth_success` cutoff-log row. Returns `false` (nothing written) when the
/// claim was fenced: a revocation deleted the row while the winner was
/// forwarding, or a peer took over a lapsed lease.
///
/// The transaction first share-locks the user's revocation tag
/// ([`lock_user_tag`]), so it linearizes with [`revoke_by_username`]: either
/// this write commits first and the revocation deletes it, or the revocation
/// commits first and its delete removes the claim row this write is
/// conditioned on. A stale validation can never resurrect a revoked verdict.
pub async fn finalize_claim(pool: &PgPool, new: NewVerdict, token: Uuid) -> sqlx::Result<bool> {
    let mut tx = crate::begin(pool).await?;
    lock_user_tag(&mut tx, &new.username).await?;
    let written = sqlx::query!(
        r#"
        UPDATE validated_credential
        SET verdict       = $4,
            expires_at    = $5,
            created_at    = now(),
            claim_token   = NULL,
            claimed_until = NULL
        WHERE provider_id = $1 AND username = $2 AND cred_hmac = $3
          AND claim_token = $6
        "#,
        new.provider_id,
        new.username,
        new.cred_hmac,
        new.verdict,
        new.expires_at,
        token,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if written == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    // Accepts only: a rejected attempt leaves no durable trace here.
    if new.verdict {
        record_auth_success(&mut tx, &new.username, &new.provider_id).await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// Give up a lease without a verdict (the upstream was unavailable, or the
/// winner was cancelled): delete the claim row so peers take over immediately
/// and an outage leaves nothing behind. A no-op when `token` no longer holds
/// the row, and it never deletes a fresh verdict.
pub async fn release_claim(
    pool: &PgPool,
    provider_id: &str,
    username: &str,
    cred_hmac: &str,
    token: Uuid,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"
        DELETE FROM validated_credential
        WHERE provider_id = $1 AND username = $2 AND cred_hmac = $3
          AND claim_token = $4
          AND expires_at <= now()
        "#,
        provider_id,
        username,
        cred_hmac,
        token,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Materialize and share-lock the durable revocation tag for `username`.
///
/// Production credential fills call this inside [`finalize_claim`]'s short
/// verdict-write transaction (never across the upstream forward).
/// [`revoke_by_username`] advances the same row under an exclusive lock, so a
/// revocation either commits before the verdict write (and its delete removes
/// the claim the write is conditioned on, fencing it) or waits for that write
/// and then deletes the verdict. There is no gap in which a stale fill can
/// resurrect a deleted verdict.
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

/// Revoke every cached verdict for a username (optionally scoped to one
/// provider): the admin "force re-auth user X" / deactivate-user path. Returns
/// the number of rows deleted (verdicts plus any in-flight singleflight
/// claims, whose winners are thereby fenced — see [`finalize_claim`]). The caller must also drop the matching cache
/// entries via the [`forge_cache`] invalidation backplane.
pub async fn revoke_by_username(
    pool: &PgPool,
    username: &str,
    provider_id: Option<&str>,
) -> sqlx::Result<u64> {
    let mut tx = crate::begin(pool).await?;

    // The upsert is the revocation's linearization point. It takes an exclusive
    // row lock and therefore waits for every in-progress verdict write holding
    // the shared user-tag lock (a short transaction — never an upstream
    // forward). Verdict writes that start later wait for this commit and then
    // find their claim row deleted below, so they write nothing.
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
///
/// A row carrying a **live** singleflight lease is kept: deleting it would
/// fence the in-flight winner (its verdict would be discarded) and let a peer
/// start a duplicate forward. Lapsed leases are swept like any expired row.
pub async fn sweep_expired(pool: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        r#"
        DELETE FROM validated_credential
        WHERE expires_at <= now()
          AND (claimed_until IS NULL OR claimed_until <= now())
        "#,
    )
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
