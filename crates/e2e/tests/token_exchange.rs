//! E2E: the trusted-publishing token exchange (`POST /api/v2/token`) and the
//! reserved workload Basic username `oidc` (issue #169).
//!
//! Drives the real server against Postgres plus the in-process mock OIDC
//! issuer, as `wif.rs` does:
//!
//! 1. a CI token is exchanged for a `forge_wif.` key that publishes (with only
//!    `X-NuGet-ApiKey`) and restores (Basic `oidc:<key>`, Bearer), and the
//!    publish is audited under the original token's subject, `jti` and `iat`;
//! 2. each token is exchanged once, a token without `jti` never, and the
//!    request is validated (scheme, `username`, `tokenType`, key-for-key);
//! 3. a key dies with its expiry, any realm edit, and the realm's disabling;
//! 4. Basic `oidc:` only ever carries a workload credential: a user token, a
//!    random secret or a foreign JWT is refused and never forwarded upstream,
//!    and no account can be named `oidc`;
//! 5. the real `dotnet` client pushes with only the key (direct publish URL,
//!    `--no-service-endpoint`) and restores through a group with
//!    `NuGetPackageSourceCredentials_<name>=Username=oidc;Password=<key>`.
//!
//! Requires Docker.

#![cfg(feature = "forge-e2e")]

use forge_e2e::{make_nupkg, start_stack, MockBasicUpstream, MockOidc, StackBuilder, TestServer};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Command;

const AUD: &str = "forge-ci";

/// A GitLab-shaped job: the claims the `gitlab-ci` realm's rule matches.
fn job_claims(idp: &MockOidc) -> Value {
    idp.wif_claims(
        "project_path:acme/app:ref_type:branch:ref:main",
        AUD,
        json!({
            "job_project_id": "1001",
            "job_namespace_id": "2001",
            "project_path": "acme/app",
            "ref": "main",
            "ref_type": "branch",
            "ref_protected": true
        }),
    )
}

/// Hosted `ci-hosted` in group `ci-group`; role `ci-pub` reads both and
/// writes the hosted one; realm `gitlab-ci` maps the job to `ci-pub`.
async fn setup(srv: &TestServer, idp: &MockOidc, extra_config: Value) -> i64 {
    for repo in [
        json!({"name": "ci-hosted", "kind": "hosted", "anonymous_read": false}),
        json!({"name": "ci-group", "kind": "group", "anonymous_read": false}),
    ] {
        assert_eq!(srv.create_repo(repo).await.status(), StatusCode::CREATED);
    }
    assert!(srv
        .add_member("ci-group", "ci-hosted", 10)
        .await
        .status()
        .is_success());
    let role = srv.create_role("ci-pub").await;
    for (repo, action) in [
        ("ci-hosted", "read"),
        ("ci-hosted", "write"),
        ("ci-group", "read"),
    ] {
        assert_eq!(
            srv.add_grant(role, Some(repo), action, None).await.status(),
            StatusCode::CREATED
        );
    }
    let mut config = json!({
        "issuer": idp.issuer(),
        "allow_http_issuer": true,
        "allowed_audiences": [AUD],
        "rules": [{
            "role": "ci-pub",
            "conditions": [
                {"claim": "job_project_id", "any_of": ["1001"]},
                {"claim": "ref_protected", "any_of": ["true"]}
            ],
        }],
    });
    if let (Some(config), Some(extra)) = (config.as_object_mut(), extra_config.as_object()) {
        for (k, v) in extra {
            config.insert(k.clone(), v.clone());
        }
    }
    let (u, p) = srv.admin_basic();
    let created = srv
        .client()
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"kind": "workload_identity", "name": "gitlab-ci", "config": config}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    created.json::<Value>().await.unwrap()["id"]
        .as_i64()
        .unwrap()
}

/// `POST /api/v2/token` with `token` as the Bearer and `body` as JSON.
async fn exchange(srv: &TestServer, token: &str, body: Value) -> reqwest::Response {
    srv.client()
        .post(format!("{}/api/v2/token", srv.base_url))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// Exchange `token` the way `NuGet/login` does, returning the API key.
async fn exchange_ok(srv: &TestServer, token: &str) -> String {
    let response = exchange(
        srv,
        token,
        json!({"username": "oidc", "tokenType": "ApiKey"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("private, no-store")
    );
    let body: Value = response.json().await.unwrap();
    let key = body["apiKey"].as_str().unwrap().to_string();
    assert!(key.starts_with("forge_wif."), "{key}");
    let expires = chrono::DateTime::parse_from_rfc3339(body["expires"].as_str().unwrap())
        .unwrap()
        .timestamp();
    let in_an_hour = chrono::Utc::now().timestamp() + 3600;
    assert!(
        (in_an_hour - 120..=in_an_hour + 120).contains(&expires),
        "the default key lifetime is an hour: {body}"
    );
    key
}

async fn read_index(
    srv: &TestServer,
    repo: &str,
    req: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
) -> StatusCode {
    req(srv
        .client()
        .get(format!("{}/v3/{repo}/index.json", srv.base_url)))
    .send()
    .await
    .unwrap()
    .status()
}

async fn push_with_api_key(srv: &TestServer, key: &str, id: &str, version: &str) -> StatusCode {
    let part = reqwest::multipart::Part::bytes(make_nupkg(id, version))
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    srv.client()
        .put(format!("{}/v3/ci-hosted/package", srv.base_url))
        .header("X-NuGet-ApiKey", key)
        .multipart(reqwest::multipart::Form::new().part("package", part))
        .send()
        .await
        .unwrap()
        .status()
}

fn sha256(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

#[tokio::test]
async fn exchanged_key_publishes_restores_and_is_audited_as_the_token() {
    let idp = MockOidc::start_workload_only("unused-wif-client").await;
    let srv = start_stack().await;
    setup(&srv, &idp, json!({})).await;
    let claims = job_claims(&idp);
    let token = idp.sign_token(claims.clone()).await;

    let key = exchange_ok(&srv, &token).await;
    assert_eq!(
        push_with_api_key(&srv, &key, "Acme.Exchanged", "1.0.0").await,
        StatusCode::CREATED,
        "the key alone (X-NuGet-ApiKey) publishes"
    );
    for repo in ["ci-hosted", "ci-group"] {
        assert_eq!(
            read_index(&srv, repo, |r| r.basic_auth("oidc", Some(&key))).await,
            StatusCode::OK,
            "Basic oidc:<key> restores from {repo}"
        );
        assert_eq!(
            read_index(&srv, repo, |r| r.bearer_auth(&key)).await,
            StatusCode::OK,
            "Bearer <key> restores from {repo}"
        );
    }
    let versions: Value = srv
        .client()
        .get(format!(
            "{}/v3/ci-group/flat/acme.exchanged/index.json",
            srv.base_url
        ))
        .basic_auth("OIDC", Some(&key))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(versions["versions"], json!(["1.0.0"]));

    // The ledger names the workload exactly as the exchanged token did.
    let (subject, jti, issued_at): (Vec<u8>, Option<Vec<u8>>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as(
            "SELECT subject_sha256, jti_sha256, token_issued_at FROM trusted_publish_audit \
             WHERE package_name = 'acme.exchanged'",
        )
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    let issuer = idp.issuer().trim_end_matches('/');
    let mut subject_digest = Sha256::new();
    subject_digest.update(issuer.as_bytes());
    subject_digest.update([0]);
    subject_digest.update(claims["sub"].as_str().unwrap().as_bytes());
    assert_eq!(subject, subject_digest.finalize().to_vec());
    assert_eq!(jti, Some(sha256(claims["jti"].as_str().unwrap())));
    assert_eq!(issued_at.timestamp(), claims["iat"].as_i64().unwrap());

    // Only digests are stored: never the key or the token.
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workload_api_key WHERE key_sha256 = $1 AND jti_sha256 = $2",
    )
    .bind(sha256(&key))
    .bind(sha256(claims["jti"].as_str().unwrap()))
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(stored, 1);
}

#[tokio::test]
async fn each_token_is_exchanged_once_and_requests_are_validated() {
    let idp = MockOidc::start_workload_only("unused-wif-client").await;
    let srv = start_stack().await;
    setup(&srv, &idp, json!({"api_key_ttl_seconds": 600})).await;

    let token = idp.sign_token(job_claims(&idp)).await;
    // The request body is optional; the realm's TTL applies.
    let first = srv
        .client()
        .post(format!("{}/api/v2/token", srv.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let body: Value = first.json().await.unwrap();
    let expires = chrono::DateTime::parse_from_rfc3339(body["expires"].as_str().unwrap())
        .unwrap()
        .timestamp();
    assert!(
        (expires - chrono::Utc::now().timestamp() - 600).abs() < 120,
        "{body}"
    );

    let replay = exchange(&srv, &token, json!({"tokenType": "ApiKey"})).await;
    assert_eq!(
        replay.status(),
        StatusCode::UNAUTHORIZED,
        "one redemption per token"
    );
    // The token itself still authenticates directly until it expires.
    assert_eq!(
        read_index(&srv, "ci-hosted", |r| r.basic_auth("oidc", Some(&token))).await,
        StatusCode::OK
    );

    // No jti, no exchange: it could be replayed until it expires.
    let mut without_jti = job_claims(&idp);
    without_jti.as_object_mut().unwrap().remove("jti");
    let without_jti = idp.sign_token(without_jti).await;
    assert_eq!(
        exchange(&srv, &without_jti, json!({})).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let fresh = idp.sign_token(job_claims(&idp)).await;
    assert_eq!(
        exchange(&srv, &fresh, json!({"username": "my-nuget-profile"}))
            .await
            .status(),
        StatusCode::BAD_REQUEST,
        "the username, if given, is the workload username"
    );
    assert_eq!(
        exchange(&srv, &fresh, json!({"tokenType": "Bearer"}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let garbage = srv
        .client()
        .post(format!("{}/api/v2/token", srv.base_url))
        .bearer_auth(&fresh)
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(garbage.status(), StatusCode::BAD_REQUEST);
    // None of the refusals above consumed the token.
    let key = exchange_ok_any(&srv, &fresh).await;

    // A key never renews itself, and a password or no credential is no token.
    assert_eq!(
        exchange(&srv, &key, json!({})).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let unauthenticated = srv
        .client()
        .post(format!("{}/api/v2/token", srv.base_url))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let (u, p) = srv.admin_basic();
    let password = srv
        .client()
        .post(format!("{}/api/v2/token", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(password.status(), StatusCode::UNAUTHORIZED);

    // A JWT of an issuer no realm trusts is not a workload token.
    let stranger = MockOidc::start_workload_only("stranger").await;
    let foreign = stranger.sign_token(job_claims(&stranger)).await;
    assert_eq!(
        exchange(&srv, &foreign, json!({})).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

/// [`exchange_ok`] for a realm whose key lifetime is not the default.
async fn exchange_ok_any(srv: &TestServer, token: &str) -> String {
    let response = exchange(
        srv,
        token,
        json!({"username": "oidc", "tokenType": "ApiKey"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    response.json::<Value>().await.unwrap()["apiKey"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn a_registry_token_dies_with_its_workload_key() {
    let idp = MockOidc::start_workload_only("unused-wif-client").await;
    let srv = start_stack().await;
    let realm_id = setup(&srv, &idp, json!({})).await;
    let created = srv
        .create_repo(json!({"name": "ci-images", "kind": "hosted", "format": "docker"}))
        .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let role: i64 = sqlx::query_scalar("SELECT id FROM role WHERE name = 'ci-pub'")
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(
        srv.add_grant(role, Some("ci-images"), "read", None)
            .await
            .status(),
        StatusCode::CREATED
    );

    // `docker login -u oidc -p <key>`, then a pull of an image not pushed
    // yet: 404 while the token stands, 401 once it does not.
    let key = exchange_ok(&srv, &idp.sign_token(job_claims(&idp)).await).await;
    let response = srv
        .client()
        .get(format!(
            "{}/v2/token?scope=repository:ci-images/app:pull",
            srv.base_url
        ))
        .basic_auth("oidc", Some(&key))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let token = response.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let pull = || async {
        srv.client()
            .get(format!("{}/v2/ci-images/app/tags/list", srv.base_url))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status()
    };
    assert_eq!(pull().await, StatusCode::NOT_FOUND);

    let (u, p) = srv.admin_basic();
    let set_enabled = |enabled: bool| {
        srv.client()
            .patch(format!("{}/admin/realms/{realm_id}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&json!({ "enabled": enabled }))
            .send()
    };
    // What a registry token rests on is re-checked every 10 seconds.
    let recheck = std::time::Duration::from_secs(11);
    assert_eq!(set_enabled(false).await.unwrap().status(), StatusCode::OK);
    tokio::time::sleep(recheck).await;
    assert_eq!(pull().await, StatusCode::UNAUTHORIZED, "realm disabled");
    assert_eq!(set_enabled(true).await.unwrap().status(), StatusCode::OK);
    tokio::time::sleep(recheck).await;
    assert_eq!(
        pull().await,
        StatusCode::UNAUTHORIZED,
        "the key it was minted from stays revoked"
    );
}

#[tokio::test]
async fn an_unreachable_issuer_answers_503_so_the_job_retries() {
    // The issuer goes away before any instance fetched its discovery
    // document or keys (a restart, a new replica): the token cannot be
    // checked, which is no verdict on it. Every path answers 503 with
    // `Retry-After`, never the 401 that makes NuGet and docker give up.
    let idp = MockOidc::start_workload_only("unused-wif-client").await;
    let srv = start_stack().await;
    setup(&srv, &idp, json!({})).await;
    let token = idp.sign_token(job_claims(&idp)).await;
    drop(idp);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let unavailable = |response: reqwest::Response, what: &str| {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{what}");
        assert!(
            response
                .headers()
                .contains_key(reqwest::header::RETRY_AFTER),
            "{what}"
        );
    };
    unavailable(
        exchange(
            &srv,
            &token,
            json!({"username": "oidc", "tokenType": "ApiKey"}),
        )
        .await,
        "token exchange",
    );
    unavailable(
        srv.client()
            .get(format!("{}/v3/ci-hosted/index.json", srv.base_url))
            .basic_auth("oidc", Some(&token))
            .send()
            .await
            .unwrap(),
        "feed with the CI token",
    );
    unavailable(
        srv.client()
            .get(format!("{}/v2/token", srv.base_url))
            .basic_auth("oidc", Some(&token))
            .send()
            .await
            .unwrap(),
        "registry token",
    );
}

#[tokio::test]
async fn a_realm_edit_on_one_instance_is_honoured_at_once_on_another() {
    // A realm edit drops the snapshot of the instance that took it only.
    // Its peer, still holding the old configuration, must neither refuse a
    // key the editing instance issues under the new one, nor refuse an
    // exchange because its own snapshot is behind the database.
    let idp = MockOidc::start_workload_only("unused-wif-client").await;
    let srv = start_stack().await;
    let realm_id = setup(&srv, &idp, json!({})).await;
    let peer = srv.spawn_peer().await;
    let with_key = |key: String| move |r: reqwest::RequestBuilder| r.basic_auth("oidc", Some(&key));
    let (u, p) = srv.admin_basic();
    let edit = |clock_skew_seconds: u64| {
        srv.client()
            .patch(format!("{}/admin/realms/{realm_id}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&json!({"config": {
                "issuer": idp.issuer(),
                "allow_http_issuer": true,
                "allowed_audiences": [AUD],
                "clock_skew_seconds": clock_skew_seconds,
                "rules": [{
                    "role": "ci-pub",
                    "conditions": [
                        {"claim": "job_project_id", "any_of": ["1001"]},
                        {"claim": "ref_protected", "any_of": ["true"]}
                    ],
                }],
            }}))
            .send()
    };

    // The peer builds its snapshot under the original configuration.
    let warm = exchange_ok(&peer, &idp.sign_token(job_claims(&idp)).await).await;
    assert_eq!(
        read_index(&peer, "ci-hosted", with_key(warm.clone())).await,
        StatusCode::OK
    );

    // Edited on the primary: an exchange on the peer is verified against
    // the stale snapshot first, which the database refuses.
    assert_eq!(edit(30).await.unwrap().status(), StatusCode::OK);
    let exchanged = exchange_ok(&peer, &idp.sign_token(job_claims(&idp)).await).await;
    assert_eq!(
        read_index(&peer, "ci-hosted", with_key(exchanged)).await,
        StatusCode::OK
    );
    assert_eq!(
        read_index(&peer, "ci-hosted", with_key(warm)).await,
        StatusCode::UNAUTHORIZED,
        "the key of the old configuration stays revoked"
    );

    // Edited again: a key the primary issues under the new configuration
    // works on the peer at once. (Past the one-second bound on rebuilds.)
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(edit(60).await.unwrap().status(), StatusCode::OK);
    let issued = exchange_ok(&srv, &idp.sign_token(job_claims(&idp)).await).await;
    assert_eq!(
        read_index(&peer, "ci-hosted", with_key(issued)).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_key_dies_with_its_expiry_and_any_realm_change() {
    let idp = MockOidc::start_workload_only("unused-wif-client").await;
    let srv = start_stack().await;
    let realm_id = setup(&srv, &idp, json!({})).await;
    let with_key = |key: String| move |r: reqwest::RequestBuilder| r.basic_auth("oidc", Some(&key));

    // Expiry.
    let expired = exchange_ok(&srv, &idp.sign_token(job_claims(&idp)).await).await;
    assert_eq!(
        read_index(&srv, "ci-hosted", with_key(expired.clone())).await,
        StatusCode::OK
    );
    sqlx::query(
        "UPDATE workload_api_key SET created_at = now() - interval '2 hours', \
         expires_at = now() - interval '1 hour' WHERE key_sha256 = $1",
    )
    .bind(sha256(&expired))
    .execute(&srv.pool)
    .await
    .unwrap();
    assert_eq!(
        read_index(&srv, "ci-hosted", with_key(expired)).await,
        StatusCode::UNAUTHORIZED
    );

    // Any edit of the trust policy revokes the realm's outstanding keys.
    let edited = exchange_ok(&srv, &idp.sign_token(job_claims(&idp)).await).await;
    assert_eq!(
        read_index(&srv, "ci-hosted", with_key(edited.clone())).await,
        StatusCode::OK
    );
    let (u, p) = srv.admin_basic();
    let patched = srv
        .client()
        .patch(format!("{}/admin/realms/{realm_id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"config": {
            "issuer": idp.issuer(),
            "allow_http_issuer": true,
            "allowed_audiences": [AUD],
            "clock_skew_seconds": 30,
            "rules": [{
                "role": "ci-pub",
                "conditions": [
                    {"claim": "job_project_id", "any_of": ["1001"]},
                    {"claim": "ref_protected", "any_of": ["true"]}
                ],
            }],
        }}))
        .send()
        .await
        .unwrap();
    assert_eq!(patched.status(), StatusCode::OK);
    assert_eq!(
        read_index(&srv, "ci-hosted", with_key(edited.clone())).await,
        StatusCode::UNAUTHORIZED,
        "a key issued under the old policy is revoked"
    );
    // Putting the old policy back does not bring the key back.
    let reverted = srv
        .client()
        .patch(format!("{}/admin/realms/{realm_id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"config": {
            "issuer": idp.issuer(),
            "allow_http_issuer": true,
            "allowed_audiences": [AUD],
            "rules": [{
                "role": "ci-pub",
                "conditions": [
                    {"claim": "job_project_id", "any_of": ["1001"]},
                    {"claim": "ref_protected", "any_of": ["true"]}
                ],
            }],
        }}))
        .send()
        .await
        .unwrap();
    assert_eq!(reverted.status(), StatusCode::OK);
    assert_eq!(
        read_index(&srv, "ci-hosted", with_key(edited)).await,
        StatusCode::UNAUTHORIZED,
        "a revoked key stays revoked"
    );
    assert_eq!(
        push_with_api_key(
            &srv,
            &exchange_ok(&srv, &idp.sign_token(job_claims(&idp)).await).await,
            "Acme.Fresh",
            "1.0.0"
        )
        .await,
        StatusCode::CREATED,
        "a key issued under the new policy works"
    );

    // Disabling the realm revokes its keys too.
    let disabled = exchange_ok(&srv, &idp.sign_token(job_claims(&idp)).await).await;
    let patched = srv
        .client()
        .patch(format!("{}/admin/realms/{realm_id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(patched.status(), StatusCode::OK);
    assert_eq!(
        read_index(&srv, "ci-hosted", with_key(disabled.clone())).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        push_with_api_key(&srv, &disabled, "Acme.Disabled", "1.0.0").await,
        StatusCode::UNAUTHORIZED
    );

    // Enabling it again does not bring them back.
    let patched = srv
        .client()
        .patch(format!("{}/admin/realms/{realm_id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(patched.status(), StatusCode::OK);
    assert_eq!(
        read_index(&srv, "ci-hosted", with_key(disabled.clone())).await,
        StatusCode::UNAUTHORIZED,
        "a key of a re-enabled realm stays revoked"
    );
    assert_eq!(
        push_with_api_key(&srv, &disabled, "Acme.Disabled", "1.0.0").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn basic_oidc_only_ever_carries_a_workload_credential() {
    // A forwarding realm that would accept `oidc` with any of the secrets
    // below: the requests must end before the password chain.
    let random_secret = "not-a-jwt-or-key";
    let upstream = MockBasicUpstream::start(vec![("oidc", random_secret, vec![])]).await;
    let block =
        upstream.upstream_basic_block(&["local-password", "upstream-basic"], 300, 30, &[], "");
    let srv = StackBuilder::default()
        .bootstrap_admin("root", "rootpw")
        .with_upstream_basic(block)
        .start()
        .await;
    let idp = MockOidc::start_workload_only("unused-wif-client").await;
    setup(&srv, &idp, json!({})).await;
    let reader = srv.create_role("plain-reader").await;
    assert_eq!(
        srv.add_grant(reader, Some("ci-hosted"), "read", None)
            .await
            .status(),
        StatusCode::CREATED
    );
    let alice = srv.create_user("alice", "alice-password").await;
    assert!(srv.assign_role(alice, reader).await.status().is_success());
    let user_token = srv.issue_token(alice, None).await;
    assert_eq!(
        read_index(&srv, "ci-hosted", |r| r
            .basic_auth("alice", Some(&user_token)))
        .await,
        StatusCode::OK,
        "the user token itself works under its owner's name"
    );

    let stranger = MockOidc::start_workload_only("stranger").await;
    let foreign_jwt = stranger.sign_token(job_claims(&stranger)).await;
    for (label, secret) in [
        ("a user API token", user_token.as_str()),
        ("a random secret", random_secret),
        ("a JWT of an untrusted issuer", foreign_jwt.as_str()),
        (
            "an unknown workload key",
            "forge_wif.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("nothing", ""),
    ] {
        for username in ["oidc", "OIDC"] {
            assert_eq!(
                read_index(&srv, "ci-hosted", |r| r.basic_auth(username, Some(secret))).await,
                StatusCode::UNAUTHORIZED,
                "Basic {username}:<{label}> is refused"
            );
        }
    }
    assert_eq!(
        upstream.hits(),
        0,
        "nothing sent as Basic oidc: is ever forwarded upstream"
    );
    // The browser login refuses the name as well, without forwarding it.
    let login = srv
        .client()
        .post(format!("{}/auth/login", srv.base_url))
        .json(&json!({"username": "oidc", "password": random_secret}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(upstream.hits(), 0);

    // The workload token itself still works under the reserved name.
    let token = idp.sign_token(job_claims(&idp)).await;
    assert_eq!(
        read_index(&srv, "ci-hosted", |r| r.basic_auth("oidc", Some(&token))).await,
        StatusCode::OK
    );

    // No account can take the name.
    let (u, p) = srv.admin_basic();
    for name in ["oidc", " OIDC "] {
        let created = srv
            .client()
            .post(format!("{}/admin/users", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&json!({"username": name, "password": "irrelevant-password"}))
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::BAD_REQUEST, "{name:?}");
    }
}

/// A `.nupkg` with no dependencies ([`make_nupkg`]'s pull in
/// `Newtonsoft.Json`, which a restore from this feed alone cannot find).
fn nupkg_without_dependencies(id: &str, version: &str) -> Vec<u8> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    let nuspec = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{id}</id>
    <version>{version}</version>
    <authors>test</authors>
    <description>token exchange e2e package</description>
  </metadata>
</package>"#
    );
    let content_types = r#"<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="nuspec" ContentType="application/octet" /></Types>"#;
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default();
    zip.start_file("[Content_Types].xml", options).unwrap();
    zip.write_all(content_types.as_bytes()).unwrap();
    zip.start_file(format!("{id}.nuspec"), options).unwrap();
    zip.write_all(nuspec.as_bytes()).unwrap();
    zip.finish().unwrap().into_inner()
}

/// The target framework of the SDK `dotnet` selects in `dir` (`net8.0` for
/// SDK 8.0.x), so the consumer project restores without downloading a
/// targeting pack. `None` when no SDK is installed.
fn dotnet_sdk_tfm(dir: &std::path::Path) -> Option<String> {
    let out = Command::new("dotnet")
        .arg("--version")
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let version = String::from_utf8(out.stdout).ok()?;
    let major = version.trim().split('.').next()?.parse::<u32>().ok()?;
    Some(format!("net{major}.0"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_dotnet_pushes_with_only_the_key_and_restores_through_a_group() {
    let temp = tempfile::tempdir().unwrap();
    let Some(tfm) = dotnet_sdk_tfm(temp.path()) else {
        eprintln!("dotnet SDK not present; skipping native token-exchange test");
        return;
    };
    let idp = MockOidc::start_workload_only("unused-wif-client").await;
    let srv = start_stack().await;
    setup(&srv, &idp, json!({})).await;
    let key = exchange_ok(&srv, &idp.sign_token(job_claims(&idp)).await).await;

    // Two directories, each with its own `nuget.config` holding sources only
    // (no credential is written to disk, and SDK 8's push has no
    // `--configfile`). The publish source is the package endpoint itself, so
    // `--no-service-endpoint` sends one PUT carrying the key and never fetches
    // the (private) service index; restore goes through the group.
    let publish_dir = temp.path().join("publish");
    let consumer_dir = temp.path().join("consumer");
    let write_config = |dir: &std::path::Path, key: &str, url: String| {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("nuget.config"),
            format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="{key}" value="{url}" allowInsecureConnections="true" />
  </packageSources>
</configuration>
"#
            ),
        )
        .unwrap();
    };
    write_config(
        &publish_dir,
        "forge_publish",
        format!("{}/v3/ci-hosted/package", srv.base_url),
    );
    write_config(
        &consumer_dir,
        "forge",
        format!("{}/v3/ci-group/index.json", srv.base_url),
    );
    let package = publish_dir.join("Acme.Native.1.0.0.nupkg");
    std::fs::write(&package, nupkg_without_dependencies("Acme.Native", "1.0.0")).unwrap();
    std::fs::write(
        consumer_dir.join("Consumer.csproj"),
        format!(
            r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>{tfm}</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Acme.Native" Version="1.0.0" />
  </ItemGroup>
</Project>
"#
        ),
    )
    .unwrap();

    let package_arg = package.to_string_lossy().into_owned();
    let push_key = key.clone();
    let push = tokio::task::spawn_blocking(move || {
        Command::new("dotnet")
            .args([
                "nuget",
                "push",
                &package_arg,
                "--source",
                "forge_publish",
                "--no-service-endpoint",
                "--api-key",
                &push_key,
            ])
            .current_dir(publish_dir)
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        push.status.success(),
        "dotnet nuget push with only the key failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr)
    );

    let dir = consumer_dir.clone();
    let credential = format!("Username=oidc;Password={key}");
    let restore = tokio::task::spawn_blocking(move || {
        Command::new("dotnet")
            .args(["restore", "--no-cache"])
            .env("NuGetPackageSourceCredentials_forge", credential)
            .env("NUGET_PACKAGES", dir.join("packages"))
            .current_dir(dir)
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        restore.status.success(),
        "dotnet restore through the group with Basic oidc:<key> failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&restore.stdout),
        String::from_utf8_lossy(&restore.stderr)
    );
    let dir = consumer_dir;
    assert!(dir.join("packages/acme.native/1.0.0").exists());
}
