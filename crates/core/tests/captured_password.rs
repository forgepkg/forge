//! Keeping a password hash of credential-forwarding logins
//! (`capture_password_hash`) and signing in with it once the realm stops
//! forwarding (`captured_password_only`), against an in-process mock upstream
//! (`wiremock`) and a real Postgres (migration 0035).

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{DateTime, Utc};
use forge_cache::Cache;
use forge_core::auth::provider::{AuthOutcome, AuthProvider, PasswordCredential};
use forge_core::auth::{
    provision_and_map, CapturedPasswordProvider, Chain, ChainOutcome, CredKeyPepper,
    PasswordHashLimiter, UpstreamBasicConfig, UpstreamBasicProvider, ValidatedCredentialCache,
};
use forge_core::net::ssrf::credential_forward_client;
use sqlx::PgPool;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{pool, unique};

fn ip() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}

fn cred<'a>(username: &'a str, password: &'a str) -> PasswordCredential<'a> {
    PasswordCredential {
        username,
        password,
        client_ip: ip(),
    }
}

/// A credential-forwarding realm row with the given config (disabled: only
/// the providers built here use it).
async fn realm(pool: &PgPool, config: serde_json::Value) -> i64 {
    forge_db::auth_realm_dao::insert_realm(
        pool,
        forge_db::auth_realm_dao::NewAuthRealm {
            kind: "credential_forwarding".into(),
            name: format!("keep-{}", unique()),
            enabled: false,
            priority: 6_000_000 + (unique() % 1_000_000) as i32,
            config,
        },
    )
    .await
    .unwrap()
    .id
}

fn cache(pool: &PgPool, tag: &str) -> ValidatedCredentialCache {
    ValidatedCredentialCache::new(
        Cache::l1_only(256),
        pool.clone(),
        CredKeyPepper::new(format!("captured-password-test-{tag}").into_bytes()),
        Duration::from_secs(60),
        Duration::from_secs(30),
    )
}

/// The forwarding provider of realm `realm_id`, asking `url`.
fn forwarding(pool: &PgPool, realm_id: i64, url: String, capture: bool) -> UpstreamBasicProvider {
    let config = UpstreamBasicConfig {
        url,
        method: "GET".to_string(),
        success_status: vec![200],
        reject_status: vec![401, 403],
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        required_groups: Vec::new(),
        groups_path: String::new(),
        identity_path: String::new(),
        admin_group: String::new(),
        provider_id: format!("realm:test-{realm_id}"),
        auto_provision: true,
        realm_id: Some(realm_id),
        capture_password_hash: capture,
    };
    let client = credential_forward_client(config.connect_timeout).expect("forwarding client");
    UpstreamBasicProvider::new(config, client, cache(pool, &realm_id.to_string()))
}

async fn upstream(status: u16, calls: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(status))
        .expect(calls)
        .mount(&server)
        .await;
    server
}

/// Sign `username` in through `chain` and provision the account.
async fn sign_in(pool: &PgPool, chain: &Chain, username: &str, password: &str) -> Option<i64> {
    match chain.authenticate(&cred(username, password)).await {
        ChainOutcome::Authenticated { identity, .. } => provision_and_map(pool, &identity)
            .await
            .unwrap()
            .map(|p| p.user_id),
        _ => None,
    }
}

async fn kept(pool: &PgPool, user_id: i64) -> (Option<String>, Option<DateTime<Utc>>) {
    sqlx::query_as(
        "SELECT captured_password_hash, captured_password_at FROM app_user WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn verifies(phc: &str, password: &str) -> bool {
    Argon2::default()
        .verify_password(password.as_bytes(), &PasswordHash::new(phc).unwrap())
        .is_ok()
}

#[tokio::test]
async fn an_accepted_password_is_kept_once_per_upstream_check() {
    let pool = pool().await;
    let realm_id = realm(&pool, serde_json::json!({ "capture_password_hash": true })).await;
    // One upstream call: the second sign-in is a cache hit.
    let server = upstream(200, 1).await;
    let chain = Chain::new(vec![Box::new(forwarding(
        &pool,
        realm_id,
        format!("{}/status", server.uri()),
        true,
    ))]);
    let username = format!("keep-{}", unique());

    let id = sign_in(&pool, &chain, &username, "s3cret")
        .await
        .expect("signed in");
    let (hash, at) = kept(&pool, id).await;
    let hash = hash.expect("hash kept");
    assert!(hash.starts_with("$argon2id$"), "an argon2id PHC string");
    assert!(verifies(&hash, "s3cret"));
    assert!(!verifies(&hash, "other"));

    // A cache hit asks no upstream and keeps no new hash.
    assert_eq!(sign_in(&pool, &chain, &username, "s3cret").await, Some(id));
    assert_eq!(kept(&pool, id).await, (Some(hash), at));

    // Still not a local password: the local store keeps skipping the account.
    let user = forge_db::user_dao::find_user_by_id(&pool, id)
        .await
        .unwrap()
        .unwrap();
    assert!(user.password_hash.is_none());
    assert_eq!(user.auth_source, "upstream-basic");
}

#[tokio::test]
async fn nothing_is_kept_unless_the_realm_opts_in() {
    let pool = pool().await;
    let server = upstream(200, 2).await;
    let url = format!("{}/status", server.uri());

    // The provider would hash, but the realm row does not opt in (e.g. an
    // edit turned it off after this instance built its provider).
    let realm_off = realm(&pool, serde_json::json!({})).await;
    let chain = Chain::new(vec![Box::new(forwarding(
        &pool,
        realm_off,
        url.clone(),
        true,
    ))]);
    let a = format!("keep-off-{}", unique());
    let id = sign_in(&pool, &chain, &a, "pw").await.expect("signed in");
    assert_eq!(kept(&pool, id).await, (None, None));

    // The realm opts in, the provider was built without the option.
    let realm_on = realm(&pool, serde_json::json!({ "capture_password_hash": true })).await;
    let chain = Chain::new(vec![Box::new(forwarding(&pool, realm_on, url, false))]);
    let b = format!("keep-off-{}", unique());
    let id = sign_in(&pool, &chain, &b, "pw").await.expect("signed in");
    assert_eq!(kept(&pool, id).await, (None, None));
}

#[tokio::test]
async fn a_rejected_password_is_never_kept() {
    let pool = pool().await;
    let realm_id = realm(&pool, serde_json::json!({ "capture_password_hash": true })).await;
    let ok = upstream(200, 1).await;
    let username = format!("keep-rej-{}", unique());
    let chain = Chain::new(vec![Box::new(forwarding(
        &pool,
        realm_id,
        format!("{}/status", ok.uri()),
        true,
    ))]);
    let id = sign_in(&pool, &chain, &username, "right")
        .await
        .expect("signed in");
    let before = kept(&pool, id).await;

    let rejecting = upstream(401, 1).await;
    let chain = Chain::new(vec![Box::new(forwarding(
        &pool,
        realm_id,
        format!("{}/status", rejecting.uri()),
        true,
    ))]);
    assert_eq!(sign_in(&pool, &chain, &username, "wrong").await, None);
    assert_eq!(kept(&pool, id).await, before, "the kept hash is untouched");
}

#[tokio::test]
async fn a_realm_that_stops_forwarding_signs_in_with_the_kept_hash() {
    let pool = pool().await;
    let realm_id = realm(&pool, serde_json::json!({ "capture_password_hash": true })).await;
    let server = upstream(200, 1).await;
    let chain = Chain::new(vec![Box::new(forwarding(
        &pool,
        realm_id,
        format!("{}/status", server.uri()),
        true,
    ))]);
    let alice = format!("keep-only-{}", unique());
    let alice_id = sign_in(&pool, &chain, &alice, "alice-pw")
        .await
        .expect("signed in");

    // A second account of the realm that keeps no hash.
    let bob = format!("keep-only-{}", unique());
    forge_db::user_dao::provision_upstream_user(&pool, &bob, Some(realm_id))
        .await
        .unwrap()
        .expect("provisioned");

    // The upstream is gone; the realm checks the kept hashes instead.
    drop(server);
    let provider = CapturedPasswordProvider::new(
        format!("realm:test-only-{realm_id}"),
        realm_id,
        pool.clone(),
        cache(&pool, &format!("only-{realm_id}")),
        Arc::new(PasswordHashLimiter::new(2, Duration::from_secs(5))),
    );

    let AuthOutcome::Authenticated(identity) =
        provider.authenticate(&cred(&alice, "alice-pw")).await
    else {
        panic!("the kept password signs in");
    };
    assert_eq!(identity.realm_id, Some(realm_id));
    assert!(!identity.auto_provision);
    assert!(
        identity.captured_password_hash.is_none(),
        "nothing new is kept"
    );
    let principal = provision_and_map(&pool, &identity)
        .await
        .unwrap()
        .expect("mapped");
    assert_eq!(principal.user_id, alice_id);

    assert_eq!(
        provider.authenticate(&cred(&alice, "wrong")).await,
        AuthOutcome::Rejected
    );
    assert_eq!(
        provider.authenticate(&cred(&bob, "anything")).await,
        AuthOutcome::Rejected,
        "an account without a kept hash cannot sign in"
    );
    assert_eq!(
        provider
            .authenticate(&cred(&format!("nobody-{}", unique()), "x"))
            .await,
        AuthOutcome::Rejected
    );

    // Another realm's provider never accepts this realm's account.
    let other = realm(&pool, serde_json::json!({ "capture_password_hash": true })).await;
    let foreign = CapturedPasswordProvider::new(
        format!("realm:test-only-{other}"),
        other,
        pool.clone(),
        cache(&pool, &format!("only-{other}")),
        Arc::new(PasswordHashLimiter::new(2, Duration::from_secs(5))),
    );
    assert_eq!(
        foreign.authenticate(&cred(&alice, "alice-pw")).await,
        AuthOutcome::Rejected
    );
}
