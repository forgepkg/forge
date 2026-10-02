//! The `local-password` [`AuthProvider`] (slice 12.3, phase 2).
//!
//! This is the refactor of slice 1's password-basic path
//! ([`super::token::verify_password`]) into the pluggable [`AuthProvider`]
//! chain. Its behaviour is **byte-for-byte** the slice-1 logic:
//!
//! * Look up the user by username.
//! * An inactive user, an unknown user, or a user without a local
//!   `password_hash` (i.e. an `upstream-basic` / `oidc` provisioned account)
//!   can never authenticate here — they are [`AuthOutcome::Skip`] ("not my
//!   user"), so a later provider may still accept them.
//! * argon2id PHC verification runs on a blocking thread (CPU-bound), behind a
//!   process-wide [`PasswordHashLimiter`]: at most N verifications run at once
//!   (each holds ~19 MiB and a core for tens of milliseconds), and one that finds
//!   no free slot within the queue timeout answers [`AuthOutcome::Unavailable`]
//!   (an overload, not a wrong password: never counted towards the lockout).
//! * A present-but-wrong password is [`AuthOutcome::Rejected`] (terminal in
//!   the chain: the password is never forwarded upstream).
//! * The unknown-user and inactive-user `Skip` paths still run one argon2
//!   verification against a static dummy hash, so they cost the same time as a
//!   known local account (no timing-based enumeration of local accounts). A
//!   federated account (no local `password_hash`) skips at once — see
//!   [`LocalPasswordProvider::authenticate`] for that trade-off.
//! * A correct password yields [`AuthOutcome::Authenticated`] with a
//!   [`ProvenIdentity::local`].
//!
//! The provider only *vouches for* the username; mapping that identity back to
//! a concrete [`UserPrincipal`] (user id, admin flag) is the chain caller's job
//! (see [`super::chain`] mapping helpers). This keeps providers free of the
//! `UserPrincipal` shape and lets §12.4 reshape authz without touching them.
//!
//! ## Skip vs Rejected — why it matters for the chain
//! Slice 1's [`super::token::verify_password`] returned `None` for *both*
//! "unknown user" and "wrong password". In the chain those must differ:
//! * unknown / no-local-hash / inactive → **Skip** (a later provider, e.g.
//!   `upstream-basic`, may own this username);
//! * known local user, wrong password → **Rejected** (definitive "no"; the
//!   chain stops here — a username owned by a local account with a password is
//!   never forwarded to an upstream realm).
//!
//! When the chain is just `["local-password"]` this distinction is invisible on
//! the wire: both `Skip` (→ `NoCredentials` → anon policy) and `Rejected`
//! (→ 401) reproduce slice-1 behaviour, because slice 1's `BasicAuthSource`
//! turned a `None` password verify into `SourceOutcome::Invalid` only when the
//! basic header was present (creds were attempted), which is exactly what the
//! refactored `BasicAuthSource` still does. See the phase-2 tests.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use argon2::PasswordHasher;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use sqlx::PgPool;
use tokio::sync::Semaphore;

use super::provider::{AuthOutcome, AuthProvider, AuthSource, PasswordCredential, ProvenIdentity};

/// How long a verification waits for a free argon2 slot before giving up
/// (see [`PasswordHashLimiter`]).
pub const DEFAULT_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds how many argon2 password verifications run at once, process-wide.
///
/// Each verification holds ~19 MiB and a CPU core for tens of milliseconds on
/// the blocking pool, which itself allows hundreds of threads: unbounded, a
/// burst of password requests exhausts memory and CPU. A verification first
/// waits up to the queue timeout for a permit and fails with
/// [`LimiterSaturated`] if none frees up. The permit moves into the blocking
/// task, so the bound holds even when the waiting request is dropped
/// mid-verification.
#[derive(Debug, Clone)]
pub struct PasswordHashLimiter {
    permits: Arc<Semaphore>,
    queue_timeout: Duration,
}

/// No argon2 slot freed up within the limiter's queue timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimiterSaturated;

impl PasswordHashLimiter {
    /// Allow `max_concurrent` verifications at once (`0` selects
    /// [`Self::default_concurrency`]), each waiting at most `queue_timeout`
    /// for a slot.
    pub fn new(max_concurrent: usize, queue_timeout: Duration) -> Self {
        let n = match max_concurrent {
            0 => Self::default_concurrency(),
            n => n,
        };
        Self::from_semaphore(
            Arc::new(Semaphore::new(n.min(Semaphore::MAX_PERMITS))),
            queue_timeout,
        )
    }

    /// Gate verifications on an existing semaphore (a budget shared with other
    /// work, or a test holding its permits to simulate saturation).
    pub fn from_semaphore(permits: Arc<Semaphore>, queue_timeout: Duration) -> Self {
        Self {
            permits,
            queue_timeout,
        }
    }

    /// The default bound: the machine's available parallelism.
    pub fn default_concurrency() -> usize {
        std::thread::available_parallelism().map_or(4, |n| n.get())
    }

    /// The process-wide default limiter ([`Self::default_concurrency`] slots,
    /// [`DEFAULT_QUEUE_TIMEOUT`]), shared by every provider built without an
    /// explicit one.
    pub fn shared_default() -> Arc<Self> {
        static SHARED: OnceLock<Arc<PasswordHashLimiter>> = OnceLock::new();
        SHARED
            .get_or_init(|| Arc::new(Self::new(0, DEFAULT_QUEUE_TIMEOUT)))
            .clone()
    }

    /// Verify `candidate` against the PHC string `stored` on a blocking thread
    /// once a slot is free. An unparsable `stored` hash is `Ok(false)`.
    pub async fn verify(
        &self,
        stored: String,
        candidate: String,
    ) -> Result<bool, LimiterSaturated> {
        self.run(Some(stored), candidate).await
    }

    /// Burn one verification against the static dummy hash (timing
    /// equalization); never accepts.
    async fn verify_dummy(&self, candidate: String) -> Result<bool, LimiterSaturated> {
        self.run(None, candidate).await
    }

    async fn run(
        &self,
        stored: Option<String>,
        candidate: String,
    ) -> Result<bool, LimiterSaturated> {
        let permit =
            match tokio::time::timeout(self.queue_timeout, self.permits.clone().acquire_owned())
                .await
            {
                Ok(Ok(permit)) => permit,
                // Timed out (or the semaphore was closed).
                _ => return Err(LimiterSaturated),
            };
        Ok(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let stored: &str = match &stored {
                Some(stored) => stored,
                None => dummy_hash(),
            };
            let parsed = match PasswordHash::new(stored) {
                Ok(p) => p,
                Err(_) => return false,
            };
            Argon2::default()
                .verify_password(candidate.as_bytes(), &parsed)
                .is_ok()
        })
        .await
        .unwrap_or(false))
    }
}

/// Slice-1 local argon2id password authentication, as an [`AuthProvider`].
pub struct LocalPasswordProvider {
    pool: PgPool,
    limiter: Arc<PasswordHashLimiter>,
}

impl LocalPasswordProvider {
    /// The stable provider id (matches the config chain spelling).
    pub const ID: &'static str = "local-password";

    /// Build the provider over the given pool, verifying through the
    /// process-wide [`PasswordHashLimiter::shared_default`].
    pub fn new(pool: PgPool) -> Self {
        Self::with_limiter(pool, PasswordHashLimiter::shared_default())
    }

    /// Build the provider with an explicit verification limiter (the server
    /// shares one configured limiter across every realm-built provider).
    pub fn with_limiter(pool: PgPool, limiter: Arc<PasswordHashLimiter>) -> Self {
        Self { pool, limiter }
    }

    /// Burn one argon2 verification on the dummy hash, then report `Skip`: the
    /// caller learns "not ours" in the same time a wrong password would take.
    /// A saturated limiter answers `Unavailable`, exactly as it does for a real
    /// account, so an overload does not reveal which usernames exist either.
    async fn skip_after_dummy_verify(&self, candidate: &str) -> AuthOutcome {
        match self.limiter.verify_dummy(candidate.to_string()).await {
            Ok(_) => AuthOutcome::Skip,
            Err(LimiterSaturated) => saturated(),
        }
    }
}

fn saturated() -> AuthOutcome {
    tracing::warn!("local-password: no argon2 slot freed up within the queue timeout");
    AuthOutcome::Unavailable
}

/// A throwaway argon2id PHC hash (default parameters, random password) used to
/// equalize the cost of the `Skip` paths with a real verification. Built once.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        Argon2::default()
            .hash_password(b"forge-timing-equalizer")
            .map(|h| h.to_string())
            .unwrap_or_default()
    })
}

#[async_trait::async_trait]
impl AuthProvider for LocalPasswordProvider {
    fn id(&self) -> &str {
        Self::ID
    }

    fn source(&self) -> AuthSource {
        AuthSource::Local
    }

    /// One deliberate timing difference: a **federated** account (an
    /// `app_user` without a local `password_hash`, provisioned by
    /// `upstream-basic` or `oidc`) skips at once, without the dummy argon2.
    /// NuGet sends Basic credentials on every request, and for a
    /// credential-forwarded user the forwarding provider behind this one
    /// answers from its verdict cache; a dummy hash in front of it would make
    /// every such request cost a full argon2 verification. The price is that
    /// response timing can reveal "this username is a federated account".
    /// Unknown usernames and inactive local accounts still pay the dummy
    /// verification, so local password accounts stay indistinguishable from
    /// names that do not exist.
    async fn authenticate(&self, cred: &PasswordCredential<'_>) -> AuthOutcome {
        let user = match forge_db::user_dao::find_user_by_username(&self.pool, cred.username).await
        {
            Ok(Some(u)) => u,
            // Unknown user → not ours; a later provider may own this username.
            Ok(None) => return self.skip_after_dummy_verify(cred.password).await,
            Err(e) => {
                // A DB error is an infrastructure failure: fail closed, never
                // grant — but let the chain decide the wire verdict.
                tracing::warn!(error = %e, "local-password user lookup failed");
                return AuthOutcome::Unavailable;
            }
        };

        // Users with no local password (auth_source upstream-basic / oidc) can
        // never authenticate via the local store — this username is not ours.
        // No dummy verification (see the trade-off above).
        let Some(stored) = user.password_hash.clone() else {
            return AuthOutcome::Skip;
        };

        // Inactive users never authenticate locally. Slice 1 returned `None`
        // here; in the chain this is Skip (the account exists but isn't ours to
        // accept — and an inactive user shouldn't be forwarded upstream either,
        // but that is the upstream provider's own active-check concern).
        if !user.active {
            return self.skip_after_dummy_verify(cred.password).await;
        }

        match self.limiter.verify(stored, cred.password.to_string()).await {
            Ok(true) => AuthOutcome::Authenticated(ProvenIdentity::local(user.username)),
            // Known local user, wrong password → definitive rejection.
            Ok(false) => AuthOutcome::Rejected,
            // Overloaded: no verdict on this password. The source being local,
            // the chain stops here rather than forwarding it upstream.
            Err(LimiterSaturated) => saturated(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_hash_is_a_valid_default_argon2id_phc() {
        let parsed = PasswordHash::new(dummy_hash()).expect("valid PHC string");
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        // Same parameters as a freshly created user's hash, so the timing matches.
        let real = Argon2::default().hash_password(b"x").unwrap();
        assert_eq!(parsed.params, real.params);
    }

    #[tokio::test]
    async fn dummy_verify_never_accepts() {
        let limiter = PasswordHashLimiter::new(1, DEFAULT_QUEUE_TIMEOUT);
        assert_eq!(
            limiter
                .verify(dummy_hash().to_string(), "forge".into())
                .await,
            Ok(false)
        );
        assert_eq!(limiter.verify_dummy("anything".into()).await, Ok(false));
    }

    #[tokio::test]
    async fn verify_checks_the_password() {
        let stored = Argon2::default()
            .hash_password(b"right")
            .unwrap()
            .to_string();
        let limiter = PasswordHashLimiter::new(2, DEFAULT_QUEUE_TIMEOUT);
        assert_eq!(
            limiter.verify(stored.clone(), "right".into()).await,
            Ok(true)
        );
        assert_eq!(limiter.verify(stored, "wrong".into()).await, Ok(false));
        assert_eq!(
            limiter.verify("not a phc".into(), "x".into()).await,
            Ok(false)
        );
    }

    #[tokio::test]
    async fn saturated_limiter_gives_up_after_the_queue_timeout() {
        // M4: no argon2 runs beyond the permits, and a waiter gives up after
        // the queue timeout with a distinct outcome (not a wrong password).
        let permits = Arc::new(Semaphore::new(1));
        let limiter =
            PasswordHashLimiter::from_semaphore(permits.clone(), Duration::from_millis(50));
        let held = permits.clone().acquire_owned().await.unwrap();
        assert_eq!(
            limiter.verify(dummy_hash().to_string(), "x".into()).await,
            Err(LimiterSaturated)
        );
        assert_eq!(
            limiter.verify_dummy("x".into()).await,
            Err(LimiterSaturated)
        );
        drop(held);
        assert_eq!(limiter.verify_dummy("x".into()).await, Ok(false));
        assert_eq!(permits.available_permits(), 1, "permit returned after use");
    }

    #[test]
    fn zero_concurrency_selects_available_parallelism() {
        let limiter = PasswordHashLimiter::new(0, DEFAULT_QUEUE_TIMEOUT);
        assert_eq!(
            limiter.permits.available_permits(),
            PasswordHashLimiter::default_concurrency()
        );
        assert!(PasswordHashLimiter::default_concurrency() >= 1);
    }
}
