//! Integration tests for the slice-12.3 `upstream-basic` AuthProvider (Phase 4)
//! against an in-process mock HTTP upstream (`wiremock`) + a real Postgres
//! testcontainer backing the validated-credential cache.
//!
//! These exercise the plan §3 Phase-4 behaviours:
//!   * 200 → `Authenticated`, positive cached;
//!   * 401/403 → `Rejected`, negative cached;
//!   * a second identical credential → **no** second upstream call (cache hit);
//!   * positive TTL expiry → a second upstream call happens;
//!   * 5xx / unexpected status → `Unavailable`, **nothing cached** (re-forwards);
//!   * `required_groups` unmet → `Rejected` despite a 200;
//!   * `admin_group` present in the body → `suggested_is_admin = true`;
//!   * an unreachable upstream makes the forward fail → `Unavailable`
//!     (fail-closed), nothing cached.
//!
//! Requires Docker (Postgres testcontainer) on the host.

mod common;

use std::net::IpAddr;
use std::time::Duration;

use forge_cache::Cache;
use forge_core::auth::provider::{AuthOutcome, AuthProvider, AuthSource, PasswordCredential};
use forge_core::auth::{
    CredKeyPepper, UpstreamBasicConfig, UpstreamBasicProvider, ValidatedCredentialCache,
};
use forge_core::net::ssrf::outbound_client;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{pool, unique};

/// A process-unique username for the given prefix (collision-free across tests).
fn unique_user(prefix: &str) -> String {
    format!("{prefix}-{}", unique())
}

fn pepper() -> CredKeyPepper {
    CredKeyPepper::new(b"upstream-basic-test-pepper".to_vec())
}

fn ip() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}

/// Build a provider whose SSRF-guarded client allows private ranges (so it can
/// reach the loopback wiremock server) and whose cache uses an L1-only cache
/// over the shared Postgres pool (the authoritative store).
async fn make_provider(
    config: UpstreamBasicConfig,
    positive_ttl: Duration,
) -> UpstreamBasicProvider {
    let pool = pool().await;
    let cache = ValidatedCredentialCache::new(
        Cache::l1_only(256),
        pool,
        pepper(),
        positive_ttl,
        Duration::from_secs(30),
    );
    let client = outbound_client().expect("outbound client");
    UpstreamBasicProvider::new(config, client, cache)
}

/// A baseline config pointed at `url`, with a unique-ish username space provided
/// by the caller. Defaults: GET, 200=success, 401/403=reject, generous timeouts.
fn config_for(url: String) -> UpstreamBasicConfig {
    UpstreamBasicConfig {
        url,
        method: "GET".to_string(),
        success_status: vec![200],
        reject_status: vec![401, 403],
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        required_groups: Vec::new(),
        groups_path: String::new(),
        admin_group: String::new(),
        provider_id: forge_core::auth::UPSTREAM_BASIC_ID.to_string(),
        auto_provision: true,
        realm_id: None,
    }
}

fn cred<'a>(username: &'a str, password: &'a str) -> PasswordCredential<'a> {
    PasswordCredential {
        username,
        password,
        client_ip: ip(),
    }
}

#[tokio::test]
async fn success_authenticates_and_caches() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200))
        // Expect EXACTLY one upstream call across both requests: the second is a
        // cache hit.
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/status", server.uri());
    let provider = make_provider(config_for(url), Duration::from_secs(300)).await;
    let user = unique_user("up-ok");

    let out = provider.authenticate(&cred(&user, "pw")).await;
    match out {
        AuthOutcome::Authenticated(id) => {
            assert_eq!(id.username, user);
            assert_eq!(id.source, AuthSource::UpstreamBasic);
            assert_eq!(id.external_subject.as_deref(), Some(user.as_str()));
            assert!(!id.suggested_is_admin);
        }
        other => panic!("expected Authenticated, got {other:?}"),
    }

    // Second identical request: served from cache, no second upstream call.
    let out2 = provider.authenticate(&cred(&user, "pw")).await;
    assert!(matches!(out2, AuthOutcome::Authenticated(_)));
    // `server` drops at end of test and verifies `.expect(1)`.
}

#[tokio::test]
async fn rejection_is_rejected_and_cached() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1) // negative cached → second call is a cache hit.
        .mount(&server)
        .await;

    let url = format!("{}/status", server.uri());
    let provider = make_provider(config_for(url), Duration::from_secs(300)).await;
    let user = unique_user("up-reject");

    assert_eq!(
        provider.authenticate(&cred(&user, "bad")).await,
        AuthOutcome::Rejected
    );
    // Negative cache hit: no second upstream call.
    assert_eq!(
        provider.authenticate(&cred(&user, "bad")).await,
        AuthOutcome::Rejected
    );
}

#[tokio::test]
async fn positive_ttl_expiry_reforwards() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(200))
        // Two calls: the tiny TTL forces a re-forward on the second request.
        .expect(2)
        .mount(&server)
        .await;

    let url = format!("{}/status", server.uri());
    // 0s positive TTL → the cached verdict is already expired on the next read.
    let provider = make_provider(config_for(url), Duration::from_secs(0)).await;
    let user = unique_user("up-ttl");

    assert!(matches!(
        provider.authenticate(&cred(&user, "pw")).await,
        AuthOutcome::Authenticated(_)
    ));
    // Let the absolute expiry pass (TTL was 0; be robust to clock granularity).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(matches!(
        provider.authenticate(&cred(&user, "pw")).await,
        AuthOutcome::Authenticated(_)
    ));
}

#[tokio::test]
async fn server_error_is_unavailable_and_not_cached() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/status"))
        .respond_with(ResponseTemplate::new(503))
        // Two calls: an outage is never cached, so the second request re-forwards.
        .expect(2)
        .mount(&server)
        .await;

    let url = format!("{}/status", server.uri());
    let provider = make_provider(config_for(url), Duration::from_secs(300)).await;
    let user = unique_user("up-503");

    assert_eq!(
        provider.authenticate(&cred(&user, "pw")).await,
        AuthOutcome::Unavailable
    );
    // Fail-closed: nothing cached, so this re-forwards (and is the 2nd mock hit).
    assert_eq!(
        provider.authenticate(&cred(&user, "pw")).await,
        AuthOutcome::Unavailable
    );
}

#[tokio::test]
async fn required_group_unmet_is_rejected_despite_200() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "user": { "roles": ["dev", "qa"] }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = config_for(format!("{}/whoami", server.uri()));
    config.groups_path = "user.roles".to_string();
    config.required_groups = vec!["nuget-users".to_string()];

    let provider = make_provider(config, Duration::from_secs(300)).await;
    let user = unique_user("up-gate");

    // Valid password, but the user lacks the required group → definitive reject.
    assert_eq!(
        provider.authenticate(&cred(&user, "pw")).await,
        AuthOutcome::Rejected
    );
    // Cached negative → no second upstream call.
    assert_eq!(
        provider.authenticate(&cred(&user, "pw")).await,
        AuthOutcome::Rejected
    );
}

#[tokio::test]
async fn required_group_met_authenticates() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "user": { "roles": ["nuget-users", "dev"] }
        })))
        .mount(&server)
        .await;

    let mut config = config_for(format!("{}/whoami", server.uri()));
    config.groups_path = "user.roles".to_string();
    config.required_groups = vec!["nuget-users".to_string()];

    let provider = make_provider(config, Duration::from_secs(300)).await;
    let user = unique_user("up-gate-ok");

    match provider.authenticate(&cred(&user, "pw")).await {
        AuthOutcome::Authenticated(id) => {
            assert!(id.groups.contains(&"nuget-users".to_string()));
        }
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

#[tokio::test]
async fn admin_group_sets_suggested_is_admin() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "roles": ["nx-admin"]
        })))
        .mount(&server)
        .await;

    let mut config = config_for(format!("{}/whoami", server.uri()));
    config.groups_path = "roles".to_string();
    config.admin_group = "nx-admin".to_string();

    let provider = make_provider(config, Duration::from_secs(300)).await;
    let user = unique_user("up-admin");

    match provider.authenticate(&cred(&user, "pw")).await {
        AuthOutcome::Authenticated(id) => {
            assert!(id.suggested_is_admin, "nx-admin maps to admin");
        }
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

#[tokio::test]
async fn unreachable_upstream_is_unavailable() {
    // An upstream that refuses connections (an unbound port on loopback):
    // forward errors → Unavailable (fail-closed), nothing cached. (The slice-1
    // SSRF private-range test lived here; 12.7 §3.6 dropped that restriction —
    // only the scheme is checked, and scheme rejection is covered by the ssrf
    // module's unit tests + config validation.)
    let config = config_for("http://127.0.0.1:1/status".to_string());
    let provider = make_provider(config, Duration::from_secs(300)).await;
    let user = unique_user("up-unreachable");

    assert_eq!(
        provider.authenticate(&cred(&user, "pw")).await,
        AuthOutcome::Unavailable
    );
}
