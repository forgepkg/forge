//! Postgres advisory locks.
//!
//! These are used where a short critical section must be serialized across
//! processes but does not map cleanly onto a single row (e.g. singleflight
//! around proxy upstream fetches). Where the plan calls for row-level locking
//! (`SELECT ... FOR UPDATE [SKIP LOCKED]`), prefer that instead — it is scoped
//! to a concrete row and cannot collide.

use sqlx::{Postgres, Transaction};

/// Acquire a transaction-scoped advisory lock on `key`, run `f`, and return its
/// result. The lock is held until the surrounding transaction commits or rolls
/// back (`pg_advisory_xact_lock` is released automatically at transaction end),
/// so callers must `commit()`/`rollback()` the transaction to release it.
///
/// `f` receives the same transaction so it can perform work while holding the
/// lock.
pub async fn with_advisory_xact_lock<'c, F, Fut, T>(
    tx: &mut Transaction<'c, Postgres>,
    key: i64,
    f: F,
) -> sqlx::Result<T>
where
    F: for<'t> FnOnce(&'t mut Transaction<'c, Postgres>) -> Fut,
    Fut: std::future::Future<Output = sqlx::Result<T>>,
{
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut **tx)
        .await?;
    f(tx).await
}

/// Hash text parts into a stable `i64` suitable for use as an advisory-lock key.
///
/// Uses FNV-1a over the parts joined with a `0x00` separator (so `["a","bc"]`
/// and `["ab","c"]` do not collide). The 64-bit FNV result is reinterpreted as
/// `i64` (advisory-lock keys are 64-bit signed in Postgres).
///
/// **Collision caveat:** this is a hash, not a perfect mapping — two distinct
/// part lists can in principle map to the same key and would then serialize
/// against each other unnecessarily (a correctness-safe but possibly
/// performance-reducing outcome). It never causes *missed* mutual exclusion.
/// Where exact, collision-free locking matters, lock the concrete row instead.
pub fn advisory_key(parts: &[&str]) -> i64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    let hash_byte = |b: u8, hash: &mut u64| {
        *hash ^= u64::from(b);
        *hash = hash.wrapping_mul(FNV_PRIME);
    };

    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            hash_byte(0x00, &mut hash);
        }
        for &b in part.as_bytes() {
            hash_byte(b, &mut hash);
        }
    }

    hash as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_key_is_stable() {
        assert_eq!(
            advisory_key(&["repo", "1.2.3"]),
            advisory_key(&["repo", "1.2.3"])
        );
    }

    #[test]
    fn advisory_key_separator_prevents_naive_collisions() {
        assert_ne!(advisory_key(&["a", "bc"]), advisory_key(&["ab", "c"]));
    }

    #[test]
    fn advisory_key_distinguishes_inputs() {
        assert_ne!(advisory_key(&["a"]), advisory_key(&["b"]));
    }
}
