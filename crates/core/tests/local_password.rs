//! Integration tests for the slice-12.3 **phase 2** `local-password` provider
//! and the refactored [`BasicAuthSource`], against a real Postgres
//! testcontainer.
//!
//! The point of phase 2 is a **zero-behavior-change** refactor: slice 1's
//! inline argon2id password check is now [`LocalPasswordProvider`] invoked
//! through the [`Chain`], but the observable auth behaviour — token-as-basic
//! first, gated password fallback, invalid-creds → 401 — is unchanged. These
//! tests assert both the provider's outcomes directly and that the slice-1
//! `BasicAuthSource` semantics are preserved end-to-end.
//!
//! Requires Docker.

mod common;

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use argon2::Argon2;
use argon2::PasswordHasher;
use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use forge_core::auth::chain::{Chain, ChainOutcome};
use forge_core::auth::local_password::{LocalPasswordProvider, PasswordHashLimiter};
use forge_core::auth::login_throttle::{LoginThrottle, MAX_USERNAME_BYTES};
use forge_core::auth::provider::{AuthOutcome, AuthProvider, AuthSource, PasswordCredential};
use forge_core::auth::token::{
    generate_token_secret, hash_token, BasicAuthSource, PrincipalSource, SourceOutcome,
    TokenHeaderSource,
};
use forge_core::auth::Principal;
use forge_db::token_dao::{self, NewToken};
use forge_db::user_dao::{self, NewUser};
use http::{header::AUTHORIZATION, HeaderMap, HeaderValue};
use sqlx::PgPool;

fn ip() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}

/// argon2id PHC hash of `password` (mirrors the bootstrap-admin hashing).
fn hash(password: &str) -> String {
    Argon2::default()
        .hash_password(password.as_bytes())
        .expect("hash")
        .to_string()
}

/// Insert a local (argon2 password) user with a unique username.
async fn insert_local(pool: &PgPool, password: &str, active: bool) -> String {
    let username = format!("alice-{}@example.com", common::unique());
    user_dao::insert_user(
        pool,
        NewUser::local(username.clone(), hash(password), active),
    )
    .await
    .expect("insert local user");
    username
}

/// Make `username` an administrator: a member of the built-in `admin` role.
async fn make_admin(pool: &PgPool, username: &str) {
    let user = user_dao::find_user_by_username(pool, username)
        .await
        .unwrap()
        .unwrap();
    assert!(forge_db::authz_dao::sync_admin_role(pool, user.id, true)
        .await
        .unwrap());
}

fn cred<'a>(username: &'a str, password: &'a str) -> PasswordCredential<'a> {
    PasswordCredential {
        username,
        password,
        client_ip: ip(),
    }
}

fn basic_header(username: &str, secret: &str) -> HeaderMap {
    let enc = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"));
    let mut h = HeaderMap::new();
    h.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {enc}")).unwrap(),
    );
    h
}

// ── LocalPasswordProvider direct outcomes ───────────────────────────────────

#[tokio::test]
async fn local_provider_authenticates_correct_password() {
    let pool = common::pool().await;
    let username = insert_local(&pool, "s3cr3t", true).await;
    let provider = LocalPasswordProvider::new(pool.clone());

    let out = provider.authenticate(&cred(&username, "s3cr3t")).await;
    match out {
        AuthOutcome::Authenticated(id) => {
            assert_eq!(id.username, username);
            assert_eq!(id.source, AuthSource::Local);
            assert!(id.external_subject.is_none());
            assert!(id.groups.is_empty());
            assert!(!id.suggested_is_admin);
        }
        other => panic!("expected Authenticated, got {other:?}"),
    }
    assert_eq!(provider.id(), "local-password");
    assert_eq!(provider.source(), AuthSource::Local);
}

#[tokio::test]
async fn local_provider_rejects_wrong_password() {
    // A known local user with a wrong password is a definitive Rejected, not a
    // Skip — the account exists, the credential is simply wrong.
    let pool = common::pool().await;
    let username = insert_local(&pool, "right", true).await;
    let provider = LocalPasswordProvider::new(pool.clone());

    assert_eq!(
        provider.authenticate(&cred(&username, "wrong")).await,
        AuthOutcome::Rejected
    );
}

#[tokio::test]
async fn local_provider_skips_unknown_user() {
    // Unknown username → not ours → Skip (a later provider may own it).
    let pool = common::pool().await;
    let provider = LocalPasswordProvider::new(pool.clone());
    assert_eq!(
        provider
            .authenticate(&cred(&format!("ghost-{}", common::unique()), "pw"))
            .await,
        AuthOutcome::Skip
    );
}

#[tokio::test]
async fn local_provider_rejects_inactive_user() {
    // A deactivated local account never authenticates, and its name is still
    // a local password account's: a definitive Rejected (never a Skip that
    // would hand the password to a later provider), whatever the password.
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", false).await;
    for forwarding_follows in [false, true] {
        let provider =
            LocalPasswordProvider::new(pool.clone()).forwarding_follows(forwarding_follows);
        for password in ["pw", "a-guess"] {
            assert_eq!(
                provider.authenticate(&cred(&username, password)).await,
                AuthOutcome::Rejected,
                "{password} (forwarding follows: {forwarding_follows})"
            );
        }
    }
}

#[tokio::test]
async fn local_provider_skips_user_without_local_password() {
    // An upstream-basic / oidc provisioned user has no local password_hash and
    // must never be acceptable by the local provider — it's not ours.
    let pool = common::pool().await;
    let username = format!("upstream-{}", common::unique());
    user_dao::insert_user(
        &pool,
        NewUser {
            username: username.clone(),
            password_hash: None,
            active: true,
            auth_source: "upstream-basic".to_string(),
            external_subject: Some(username.clone()),
        },
    )
    .await
    .expect("insert upstream user");

    let provider = LocalPasswordProvider::new(pool.clone());
    assert_eq!(
        provider.authenticate(&cred(&username, "anything")).await,
        AuthOutcome::Skip
    );
}

#[tokio::test]
async fn local_provider_admin_flag_is_not_in_identity() {
    // The provider only vouches for the username; admin-ness is resolved by the
    // mapping step from the app_user row, not carried in ProvenIdentity.
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", true).await;
    make_admin(&pool, &username).await;
    let provider = LocalPasswordProvider::new(pool.clone());
    match provider.authenticate(&cred(&username, "pw")).await {
        AuthOutcome::Authenticated(id) => assert!(!id.suggested_is_admin),
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

// ── Chain (local-only) → mapping to a concrete principal ─────────────────────

#[tokio::test]
async fn chain_local_only_maps_to_principal() {
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", true).await;
    let user = user_dao::find_user_by_username(&pool, &username)
        .await
        .unwrap()
        .unwrap();

    let chain = Chain::new(vec![Box::new(LocalPasswordProvider::new(pool.clone()))]);
    match chain.authenticate(&cred(&username, "pw")).await {
        ChainOutcome::Authenticated {
            identity,
            provider_id,
        } => {
            assert_eq!(provider_id, "local-password");
            let principal = forge_core::auth::map_identity_to_principal(&pool, &identity)
                .await
                .expect("map")
                .expect("active user exists");
            assert_eq!(principal.user_id, user.id);
            // Password auth never carries a token id.
            assert!(principal.token_id.is_none());
        }
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

// ── BasicAuthSource end-to-end: slice-1 behavior is preserved ────────────────

#[tokio::test]
async fn basic_password_authenticates_when_enabled() {
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", true).await;
    let src = BasicAuthSource::new(pool.clone(), /* allow_password_basic */ true);

    match src.resolve(&basic_header(&username, "pw"), ip()).await {
        SourceOutcome::Authenticated(Principal::User { .. }) => {}
        other => panic!("expected Authenticated User, got {other:?}"),
    }
}

#[tokio::test]
async fn basic_password_disabled_does_not_authenticate() {
    // allow_password_basic = false → password path is entirely off; a valid
    // password is treated as an invalid basic credential (slice-1 behaviour).
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", true).await;
    let src = BasicAuthSource::new(pool.clone(), false);

    assert_eq!(
        src.resolve(&basic_header(&username, "pw"), ip()).await,
        SourceOutcome::Invalid
    );
}

#[tokio::test]
async fn basic_wrong_password_is_invalid_not_anonymous() {
    let pool = common::pool().await;
    let username = insert_local(&pool, "right", true).await;
    let src = BasicAuthSource::new(pool.clone(), true);

    assert_eq!(
        src.resolve(&basic_header(&username, "wrong"), ip()).await,
        SourceOutcome::Invalid
    );
}

#[tokio::test]
async fn basic_unknown_user_is_invalid() {
    let pool = common::pool().await;
    let src = BasicAuthSource::new(pool.clone(), true);
    assert_eq!(
        src.resolve(
            &basic_header(&format!("ghost-{}", common::unique()), "pw"),
            ip()
        )
        .await,
        SourceOutcome::Invalid
    );
}

#[tokio::test]
async fn basic_token_in_basic_wins_before_password_chain() {
    // A token presented as the basic secret authenticates via the token path,
    // which runs *ahead* of the password chain — unchanged from slice 1.
    let pool = common::pool().await;
    // Make a user + a token for them.
    let username = insert_local(&pool, "pw", true).await;
    let user = user_dao::find_user_by_username(&pool, &username)
        .await
        .unwrap()
        .unwrap();
    let secret = generate_token_secret();
    token_dao::insert_token(
        &pool,
        NewToken {
            user_id: user.id,
            name: format!("tok-{}", common::unique()),
            token_hash: hash_token(&secret),
            expires_at: None,
            minted_with_forwarded_credential: false,
        },
    )
    .await
    .expect("insert token");

    // Even with password-basic OFF, the token-as-basic path still works.
    let src = BasicAuthSource::new(pool.clone(), false);
    match src.resolve(&basic_header(&username, &secret), ip()).await {
        SourceOutcome::Authenticated(Principal::User {
            user_id, token_id, ..
        }) => {
            assert_eq!(user_id, user.id);
            assert!(token_id.is_some());
        }
        other => panic!("expected token-authenticated User, got {other:?}"),
    }
}

#[tokio::test]
async fn basic_no_authorization_header_is_no_credentials() {
    let pool = common::pool().await;
    let src = BasicAuthSource::new(pool.clone(), true);
    assert_eq!(
        src.resolve(&HeaderMap::new(), ip()).await,
        SourceOutcome::NoCredentials
    );
}

#[tokio::test]
async fn basic_revoked_token_is_invalid_and_never_tried_as_a_password() {
    // A revoked token used as the basic secret is not a valid token, and a
    // token Forge issued is never run through the password chain (#71).
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", true).await;
    let user = user_dao::find_user_by_username(&pool, &username)
        .await
        .unwrap()
        .unwrap();
    let secret = generate_token_secret();
    let token = token_dao::insert_token(
        &pool,
        NewToken {
            user_id: user.id,
            name: format!("tok-{}", common::unique()),
            token_hash: hash_token(&secret),
            expires_at: Some(Utc::now() + ChronoDuration::hours(1)),
            minted_with_forwarded_credential: false,
        },
    )
    .await
    .expect("insert token");
    token_dao::revoke_token(&pool, token.id)
        .await
        .expect("revoke");

    let src = BasicAuthSource::new(pool.clone(), true);
    // The revoked secret is neither a valid token nor the user's password.
    assert_eq!(
        src.resolve(&basic_header(&username, &secret), ip()).await,
        SourceOutcome::Invalid
    );
}

/// A chain wired explicitly via `with_chain` reproduces `new(.., true)`.
#[tokio::test]
async fn basic_with_explicit_chain_matches_default() {
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", true).await;
    let chain = Arc::new(Chain::new(vec![Box::new(LocalPasswordProvider::new(
        pool.clone(),
    ))]));
    let src = BasicAuthSource::with_chain(pool.clone(), Some(chain));
    assert!(matches!(
        src.resolve(&basic_header(&username, "pw"), ip()).await,
        SourceOutcome::Authenticated(_)
    ));

    // None chain disables the password path entirely.
    let src_off = BasicAuthSource::with_chain(pool.clone(), None);
    assert_eq!(
        src_off.resolve(&basic_header(&username, "pw"), ip()).await,
        SourceOutcome::Invalid
    );
}

// ── Hardening: argon2 bound, federated skip, lockout races, username bound ──

/// A limiter whose semaphore has no permits: any argon2 verification gives up
/// after a short queue timeout, so a test can tell which paths hash at all.
fn saturated_limiter() -> Arc<PasswordHashLimiter> {
    Arc::new(PasswordHashLimiter::from_semaphore(
        Arc::new(tokio::sync::Semaphore::new(0)),
        Duration::from_millis(50),
    ))
}

/// A provider that counts its calls, optionally sleeping first, and answers a
/// fixed outcome.
struct CountingProvider {
    source: AuthSource,
    outcome: AuthOutcome,
    delay: Duration,
    calls: Arc<AtomicUsize>,
}

impl CountingProvider {
    fn new(source: AuthSource, outcome: AuthOutcome, delay: Duration) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                source,
                outcome,
                delay,
                calls: calls.clone(),
            },
            calls,
        )
    }
}

#[async_trait::async_trait]
impl AuthProvider for CountingProvider {
    fn id(&self) -> &str {
        "counting"
    }
    fn source(&self) -> AuthSource {
        self.source
    }
    async fn authenticate(&self, _cred: &PasswordCredential<'_>) -> AuthOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.outcome.clone()
    }
}

#[tokio::test]
async fn foreign_names_cost_the_same_as_each_other() {
    // M4(a) + review: names the local store does not own — unknown usernames
    // and federated accounts (no local hash) — are treated alike. Ahead of a
    // credential-forwarding provider both skip at once (no argon2 slot
    // needed, so even a saturated limiter answers Skip); in a local-only
    // chain both pay the dummy verification (they need a slot, so here they
    // come back Unavailable). Inactive local accounts always pay it.
    let pool = common::pool().await;
    let federated = format!("federated-{}", common::unique());
    user_dao::insert_user(
        &pool,
        NewUser {
            username: federated.clone(),
            password_hash: None,
            active: true,
            auth_source: "upstream-basic".to_string(),
            external_subject: Some(federated.clone()),
        },
    )
    .await
    .expect("insert federated user");
    let inactive = insert_local(&pool, "pw", false).await;
    let ghost = format!("ghost-{}", common::unique());

    let forwarding = LocalPasswordProvider::with_limiter(pool.clone(), saturated_limiter())
        .forwarding_follows(true);
    for name in [&federated, &ghost] {
        assert_eq!(
            forwarding.authenticate(&cred(name, "pw")).await,
            AuthOutcome::Skip,
            "{name}"
        );
    }
    assert_eq!(
        forwarding.authenticate(&cred(&inactive, "pw")).await,
        AuthOutcome::Unavailable
    );

    let local_only = LocalPasswordProvider::with_limiter(pool.clone(), saturated_limiter());
    for name in [&federated, &ghost, &inactive] {
        assert_eq!(
            local_only.authenticate(&cred(name, "pw")).await,
            AuthOutcome::Unavailable,
            "{name}"
        );
    }
}

/// Review 2026-10-20 L2: in a local → credential-forwarding chain, a
/// deactivated local account's password (its owner's, or an attacker's
/// guesses) is never forwarded, even to an upstream that would vouch for the
/// name. It is a failed attempt like any wrong password.
#[tokio::test]
async fn inactive_local_account_is_never_forwarded() {
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", false).await;
    let (upstream, upstream_calls) = CountingProvider::new(
        AuthSource::UpstreamBasic,
        AuthOutcome::Authenticated(forge_core::auth::ProvenIdentity {
            source: AuthSource::UpstreamBasic,
            external_subject: Some(username.clone()),
            auto_provision: true,
            ..forge_core::auth::ProvenIdentity::local(username.clone())
        }),
        Duration::ZERO,
    );
    let chain = Arc::new(Chain::new(vec![
        Box::new(LocalPasswordProvider::new(pool.clone()).forwarding_follows(true)),
        Box::new(upstream),
    ]));
    for password in ["pw", "a-guess"] {
        assert_eq!(
            chain.authenticate(&cred(&username, password)).await,
            ChainOutcome::Rejected,
            "{password}"
        );
    }

    let throttle = Arc::new(LoginThrottle::new(5, Duration::from_secs(60)));
    let src =
        BasicAuthSource::with_chain(pool.clone(), Some(chain)).with_throttle(throttle.clone());
    assert_eq!(
        src.resolve(&basic_header(&username, "pw"), ip()).await,
        SourceOutcome::Invalid
    );
    assert_eq!(throttle.tracked(), 1, "counted like a wrong password");
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst),
        0,
        "an inactive local account's password never reaches the upstream"
    );
}

#[tokio::test]
async fn argon2_overload_is_unavailable_never_counted_nor_forwarded() {
    // M4(b): with every argon2 slot busy, a local account's correct password
    // is neither a failure (no lockout) nor forwarded to a later provider.
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", true).await;
    let (upstream, upstream_calls) = CountingProvider::new(
        AuthSource::UpstreamBasic,
        AuthOutcome::Rejected,
        Duration::ZERO,
    );
    let chain = Arc::new(Chain::new(vec![
        Box::new(LocalPasswordProvider::with_limiter(
            pool.clone(),
            saturated_limiter(),
        )),
        Box::new(upstream),
    ]));
    assert_eq!(
        chain.authenticate(&cred(&username, "pw")).await,
        ChainOutcome::Unavailable
    );

    let throttle = Arc::new(LoginThrottle::new(2, Duration::from_secs(60)));
    let src =
        BasicAuthSource::with_chain(pool.clone(), Some(chain)).with_throttle(throttle.clone());
    for _ in 0..5 {
        assert_eq!(
            src.resolve(&basic_header(&username, "pw"), ip()).await,
            SourceOutcome::Invalid
        );
    }
    assert!(
        !throttle.is_locked(ip(), &username),
        "an overload is not a failed password"
    );
    assert_eq!(throttle.tracked(), 0);
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst),
        0,
        "a local account's password never reaches the upstream"
    );
}

/// Review 2026-10-20 L3: a token lookup that fails (pool exhausted, short
/// acquire timeout) has not ruled out a live token. It is `Unavailable` (503),
/// not "not a token": the secret never runs through the password chain, whose
/// credential-forwarding realm would send it upstream.
#[tokio::test]
async fn token_lookup_error_is_unavailable_and_never_reaches_the_password_chain() {
    // A closed pool fails every query, like an exhausted one.
    let pool = common::pool().await;
    pool.close().await;
    let secret = generate_token_secret();
    assert!(forge_core::auth::verify_token(&pool, &secret)
        .await
        .is_err());

    let mut headers = HeaderMap::new();
    headers.insert(
        TokenHeaderSource::HEADER,
        HeaderValue::from_str(&secret).unwrap(),
    );
    assert_eq!(
        TokenHeaderSource::new(pool.clone())
            .resolve(&headers, ip())
            .await,
        SourceOutcome::Unavailable
    );

    let (upstream, upstream_calls) = CountingProvider::new(
        AuthSource::UpstreamBasic,
        AuthOutcome::Rejected,
        Duration::ZERO,
    );
    let chain = Arc::new(Chain::new(vec![Box::new(upstream)]));
    let throttle = Arc::new(LoginThrottle::default());
    let src = BasicAuthSource::with_chain(pool, Some(chain)).with_throttle(throttle.clone());
    assert_eq!(
        src.resolve(&basic_header("nuget-user", &secret), ip())
            .await,
        SourceOutcome::Unavailable
    );
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst),
        0,
        "an unchecked token is never forwarded as a password"
    );
    assert_eq!(throttle.tracked(), 0, "nor counted as a failed password");
}

#[tokio::test]
async fn concurrent_wrong_passwords_cannot_outrun_the_lockout() {
    // M4(c): a burst of concurrent guesses used to pass the lockout check
    // before the first failure was recorded. Attempts are now reserved up
    // front, so only the budget (3) ever reaches the chain.
    let pool = common::pool().await;
    let (provider, calls) = CountingProvider::new(
        AuthSource::Local,
        AuthOutcome::Rejected,
        Duration::from_millis(200),
    );
    let chain = Arc::new(Chain::new(vec![Box::new(provider)]));
    let throttle = Arc::new(LoginThrottle::new(3, Duration::from_secs(60)));
    let src = Arc::new(
        BasicAuthSource::with_chain(pool.clone(), Some(chain)).with_throttle(throttle.clone()),
    );
    let username = format!("burst-{}", common::unique());
    let headers = basic_header(&username, "guess");

    let tasks: Vec<_> = (0..12)
        .map(|_| {
            let src = src.clone();
            let headers = headers.clone();
            tokio::spawn(async move { src.resolve(&headers, ip()).await })
        })
        .collect();
    for task in tasks {
        assert_eq!(task.await.unwrap(), SourceOutcome::Invalid);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "only the lockout budget reaches the chain"
    );
    assert!(throttle.is_locked(ip(), &username));
}

#[tokio::test]
async fn concurrent_correct_passwords_are_serialized_not_locked_out() {
    // The reservation must not refuse a client that legitimately sends more
    // parallel requests than the budget (a NuGet restore over Basic): the
    // extra attempts wait for a slot and then succeed.
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", true).await;
    let (provider, calls) = CountingProvider::new(
        AuthSource::Local,
        AuthOutcome::Authenticated(forge_core::auth::ProvenIdentity::local(username.clone())),
        Duration::from_millis(100),
    );
    let chain = Arc::new(Chain::new(vec![Box::new(provider)]));
    let throttle = Arc::new(LoginThrottle::new(2, Duration::from_secs(60)));
    let src = Arc::new(
        BasicAuthSource::with_chain(pool.clone(), Some(chain)).with_throttle(throttle.clone()),
    );
    let tasks: Vec<_> = (0..6)
        .map(|_| {
            let src = src.clone();
            let headers = basic_header(&username, "pw");
            tokio::spawn(async move { src.resolve(&headers, ip()).await })
        })
        .collect();
    for task in tasks {
        assert!(matches!(
            task.await.unwrap(),
            SourceOutcome::Authenticated(Principal::User { .. })
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 6);
    assert_eq!(throttle.tracked(), 0, "successes leave nothing behind");
}

#[tokio::test]
async fn oversized_basic_username_is_invalid_and_never_tracked() {
    // B3: an oversized Basic username is refused before the token lookup, the
    // chain and the lockout map; one at the limit is processed normally.
    let pool = common::pool().await;
    let (provider, calls) =
        CountingProvider::new(AuthSource::Local, AuthOutcome::Rejected, Duration::ZERO);
    let chain = Arc::new(Chain::new(vec![Box::new(provider)]));
    let throttle = Arc::new(LoginThrottle::default());
    let src =
        BasicAuthSource::with_chain(pool.clone(), Some(chain)).with_throttle(throttle.clone());

    let huge = "u".repeat(MAX_USERNAME_BYTES + 1);
    for _ in 0..3 {
        assert_eq!(
            src.resolve(&basic_header(&huge, "pw"), ip()).await,
            SourceOutcome::Invalid
        );
    }
    assert_eq!(
        throttle.tracked(),
        0,
        "oversized usernames never enter the map"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let at_limit = "u".repeat(MAX_USERNAME_BYTES);
    assert_eq!(
        src.resolve(&basic_header(&at_limit, "pw"), ip()).await,
        SourceOutcome::Invalid
    );
    assert_eq!(throttle.tracked(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// #70: Forge's own database failing is "temporarily unavailable" (503), not
/// "invalid credentials", so NuGet clients and CI jobs retry instead of asking
/// for new credentials. An upstream outage still answers like a wrong
/// password (upstream health stays in the logs).
#[tokio::test]
async fn database_failures_on_the_password_path_are_unavailable() {
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", true).await;

    // The local provider on a failing database (a closed pool fails every
    // query, like an exhausted one).
    let closed = common::pool().await;
    closed.close().await;
    assert_eq!(
        LocalPasswordProvider::new(closed)
            .authenticate(&cred(&username, "pw"))
            .await,
        AuthOutcome::Failed
    );

    // A provider whose store failed stops the chain.
    let (failed, _) = CountingProvider::new(
        AuthSource::UpstreamBasic,
        AuthOutcome::Failed,
        Duration::ZERO,
    );
    let (later, later_calls) = CountingProvider::new(
        AuthSource::UpstreamBasic,
        AuthOutcome::Rejected,
        Duration::ZERO,
    );
    let chain = Arc::new(Chain::new(vec![Box::new(failed), Box::new(later)]));
    assert_eq!(
        chain.authenticate(&cred("someone", "pw")).await,
        ChainOutcome::Failed
    );
    assert_eq!(later_calls.load(Ordering::SeqCst), 0);
    let throttle = Arc::new(LoginThrottle::new(2, Duration::from_secs(60)));
    let src =
        BasicAuthSource::with_chain(pool.clone(), Some(chain)).with_throttle(throttle.clone());
    for _ in 0..3 {
        assert_eq!(
            src.resolve(&basic_header("someone", "pw"), ip()).await,
            SourceOutcome::Unavailable
        );
    }
    assert!(
        !throttle.is_locked(ip(), "someone"),
        "an outage is not a failed password"
    );

    // An upstream outage answers like a wrong password.
    let (down, _) = CountingProvider::new(
        AuthSource::UpstreamBasic,
        AuthOutcome::Unavailable,
        Duration::ZERO,
    );
    let src = BasicAuthSource::with_chain(
        pool.clone(),
        Some(Arc::new(Chain::new(vec![Box::new(down)]))),
    );
    assert_eq!(
        src.resolve(&basic_header("someone", "pw"), ip()).await,
        SourceOutcome::Invalid
    );

    // Realms that cannot be read.
    struct Unreadable;
    #[async_trait::async_trait]
    impl forge_core::auth::ChainSource for Unreadable {
        async fn password_chain(
            &self,
        ) -> Result<Option<Arc<Chain>>, forge_core::auth::ChainUnavailable> {
            Err(forge_core::auth::ChainUnavailable)
        }
    }
    let src = BasicAuthSource::with_source(pool.clone(), Arc::new(Unreadable));
    assert_eq!(
        src.resolve(&basic_header(&username, "pw"), ip()).await,
        SourceOutcome::Unavailable
    );
}
