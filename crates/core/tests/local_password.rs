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
use std::sync::Arc;

use argon2::PasswordHasher;
use argon2::Argon2;
use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use forge_core::auth::chain::{Chain, ChainOutcome};
use forge_core::auth::local_password::LocalPasswordProvider;
use forge_core::auth::provider::{AuthOutcome, AuthProvider, AuthSource, PasswordCredential};
use forge_core::auth::token::{
    generate_token_secret, hash_token, BasicAuthSource, PrincipalSource, SourceOutcome,
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
async fn insert_local(pool: &PgPool, password: &str, is_admin: bool, active: bool) -> String {
    let username = format!("alice-{}", common::unique());
    user_dao::insert_user(
        pool,
        NewUser::local(username.clone(), hash(password), is_admin, active),
    )
    .await
    .expect("insert local user");
    username
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
    let username = insert_local(&pool, "s3cr3t", false, true).await;
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
    let username = insert_local(&pool, "right", false, true).await;
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
async fn local_provider_skips_inactive_user() {
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", false, false).await;
    let provider = LocalPasswordProvider::new(pool.clone());
    assert_eq!(
        provider.authenticate(&cred(&username, "pw")).await,
        AuthOutcome::Skip
    );
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
            is_admin: false,
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
    let username = insert_local(&pool, "pw", true, true).await;
    let provider = LocalPasswordProvider::new(pool.clone());
    match provider.authenticate(&cred(&username, "pw")).await {
        AuthOutcome::Authenticated(id) => assert!(!id.suggested_is_admin),
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

// ── Chain (local-only) → mapping to a concrete principal ─────────────────────

#[tokio::test]
async fn chain_local_only_maps_to_principal_with_admin_flag() {
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", true, true).await;
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
            assert!(principal.is_admin);
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
    let username = insert_local(&pool, "pw", false, true).await;
    let src = BasicAuthSource::new(pool.clone(), /* allow_password_basic */ true);

    match src.resolve(&basic_header(&username, "pw"), ip()).await {
        SourceOutcome::Authenticated(Principal::User { is_admin, .. }) => assert!(!is_admin),
        other => panic!("expected Authenticated User, got {other:?}"),
    }
}

#[tokio::test]
async fn basic_password_disabled_does_not_authenticate() {
    // allow_password_basic = false → password path is entirely off; a valid
    // password is treated as an invalid basic credential (slice-1 behaviour).
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", false, true).await;
    let src = BasicAuthSource::new(pool.clone(), false);

    assert_eq!(
        src.resolve(&basic_header(&username, "pw"), ip()).await,
        SourceOutcome::Invalid
    );
}

#[tokio::test]
async fn basic_wrong_password_is_invalid_not_anonymous() {
    let pool = common::pool().await;
    let username = insert_local(&pool, "right", false, true).await;
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
    let username = insert_local(&pool, "pw", false, true).await;
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
async fn basic_revoked_token_falls_through_to_password_chain() {
    // A revoked token used as the basic secret is not a valid token; the secret
    // then runs as a password. If it isn't a valid password either → Invalid.
    let pool = common::pool().await;
    let username = insert_local(&pool, "pw", false, true).await;
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
    let username = insert_local(&pool, "pw", false, true).await;
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
