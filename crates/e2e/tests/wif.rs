//! E2E: workload-identity federation (WIF) auth realm.
//!
//! Drives the **real** forge server over HTTP against a Postgres testcontainer
//! plus an in-process mock OIDC issuer (`MockOidc`: discovery + JWKS + arbitrary
//! token signing). A simulated CI job presents its `id_token` — as the
//! `X-NuGet-ApiKey`, an `Authorization: Bearer`, and the HTTP Basic password —
//! and pushes/restores against a NuGet repo it is authorized for by a mapped
//! forge role. Covers these scenarios:
//!
//! 1. a valid token (right `iss`/`aud`, matching claim rule) authenticates and
//!    its mapped role authorizes push + restore — via all three transports;
//! 2. wrong `aud`, expired, and bad-signature tokens are rejected (401) and do
//!    **not** fall through to the password path;
//! 3. a token matching no claim rule is denied (default deny);
//! 4. two issuers (two WIF realms) are routed independently by `iss`.
//!
//! Requires Docker.

#![cfg(feature = "forge-e2e")]

use base64::Engine;
use forge_e2e::{make_nupkg, start_stack, MockBasicUpstream, MockOidc, StackBuilder, TestServer};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Command;

const AUD: &str = "forge-ci";

/// Create an `auth_realm` of kind `workload_identity` via the admin API.
async fn create_wif_realm(srv: &TestServer, name: &str, config: Value) -> StatusCode {
    let (u, p) = srv.admin_basic();
    srv.client()
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"kind": "workload_identity", "name": name, "config": config}))
        .send()
        .await
        .unwrap()
        .status()
}

/// GET `/repository/{repo}/index.json` presenting `token` in the named transport.
async fn read_index(srv: &TestServer, repo: &str, transport: Transport, token: &str) -> StatusCode {
    let url = format!("{}/repository/{repo}/index.json", srv.base_url);
    let req = srv.client().get(url);
    transport.apply(req, token).send().await.unwrap().status()
}

/// PUT a `.nupkg` to `repo` presenting `token` in the named transport.
async fn push(
    srv: &TestServer,
    repo: &str,
    transport: Transport,
    token: &str,
    bytes: Vec<u8>,
) -> StatusCode {
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let form = reqwest::multipart::Form::new().part("package", part);
    let req = srv
        .client()
        .put(format!("{}/repository/{repo}/package", srv.base_url))
        .multipart(form);
    transport.apply(req, token).send().await.unwrap().status()
}

/// The three ways a workload can present its `id_token` to the NuGet wire API.
#[derive(Clone, Copy)]
enum Transport {
    ApiKey,
    Bearer,
    BasicPassword,
}

impl Transport {
    fn apply(self, req: reqwest::RequestBuilder, token: &str) -> reqwest::RequestBuilder {
        match self {
            Transport::ApiKey => req.header("X-NuGet-ApiKey", token),
            Transport::Bearer => req.bearer_auth(token),
            // The workload uses any username; the password carries the token.
            Transport::BasicPassword => req.basic_auth("ci", Some(token)),
        }
    }
}

/// Stand up a stack with a `gitlab-ci` WIF realm whose rule binds immutable
/// numeric project identity plus a protected ref to a role that can read+write
/// `ci-hosted`.
async fn setup(srv: &TestServer, idp: &MockOidc) {
    assert_eq!(
        srv.create_repo(json!({"name": "ci-hosted", "kind": "hosted", "anonymous_read": false}))
            .await
            .status(),
        201
    );
    // The forge role the WIF rule grants: write (with read) on the repo.
    let role = srv.create_role("ci-pub").await;
    assert_eq!(
        srv.add_grant(role, Some("ci-hosted"), "write", None)
            .await
            .status(),
        201
    );

    let status = create_wif_realm(
        srv,
        "gitlab-ci",
        json!({
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
        }),
    )
    .await;
    assert_eq!(status, 201, "WIF realm create should succeed");
}

#[tokio::test]
async fn valid_token_authorizes_push_and_restore_via_all_transports() {
    let idp = MockOidc::start("unused-wif-client").await;
    let srv = start_stack().await;
    setup(&srv, &idp).await;

    let token = idp
        .sign_token(idp.wif_claims(
            "project_path:acme/app:ref_type:branch:ref:main",
            AUD,
            json!({
                "job_project_id": "1001",
                "project_id": "1001",
                "namespace_id": "2001",
                "project_path": "acme/app",
                "ref": "main",
                "ref_type": "branch",
                "ref_protected": true
            }),
        ))
        .await;

    // Push with the api-key transport.
    assert_eq!(
        push(
            &srv,
            "ci-hosted",
            Transport::ApiKey,
            &token,
            make_nupkg("Acme.App", "1.0.0"),
        )
        .await,
        StatusCode::CREATED,
        "WIF token (X-NuGet-ApiKey) should authorize push"
    );

    // Restore (read the feed index) with bearer and basic-password transports.
    for transport in [Transport::Bearer, Transport::BasicPassword] {
        assert_eq!(
            read_index(&srv, "ci-hosted", transport, &token).await,
            StatusCode::OK,
            "WIF token should authorize restore on every transport"
        );
    }
}

#[tokio::test]
async fn wrong_audience_expired_and_bad_signature_are_rejected() {
    let idp = MockOidc::start("unused-wif-client").await;
    let srv = start_stack().await;
    setup(&srv, &idp).await;

    // Wrong audience.
    let wrong_aud = idp
        .sign_token(idp.wif_claims(
            "ci-job-1",
            "some-other-aud",
            json!({"job_project_id": "1001", "ref_protected": true}),
        ))
        .await;
    assert_eq!(
        read_index(&srv, "ci-hosted", Transport::ApiKey, &wrong_aud).await,
        StatusCode::UNAUTHORIZED,
        "wrong aud must be rejected"
    );

    // Expired token.
    let mut expired_claims = idp.wif_claims(
        "ci-job-1",
        AUD,
        json!({"job_project_id": "1001", "ref_protected": true}),
    );
    let past = chrono::Utc::now().timestamp() - 3600;
    expired_claims["exp"] = json!(past);
    expired_claims["nbf"] = json!(past - 10);
    expired_claims["iat"] = json!(past - 10);
    let expired = idp.sign_token(expired_claims).await;
    assert_eq!(
        read_index(&srv, "ci-hosted", Transport::Bearer, &expired).await,
        StatusCode::UNAUTHORIZED,
        "expired token must be rejected"
    );

    // Bad signature (signed by a key whose kid is not in the JWKS). Presented as
    // the Basic password: it must 401 — never be forwarded upstream as one.
    let bad_sig = idp
        .sign_token_unknown_key(idp.wif_claims(
            "ci-job-1",
            AUD,
            json!({"job_project_id": "1001", "ref_protected": true}),
        ))
        .await;
    assert_eq!(
        read_index(&srv, "ci-hosted", Transport::BasicPassword, &bad_sig).await,
        StatusCode::UNAUTHORIZED,
        "bad-signature token must be rejected (no password fall-through)"
    );
}

#[tokio::test]
async fn token_matching_no_rule_is_default_denied() {
    let idp = MockOidc::start("unused-wif-client").await;
    let srv = start_stack().await;
    setup(&srv, &idp).await;

    // Valid signature + aud, but a project_path no rule accepts ⇒ default deny.
    let token = idp
        .sign_token(idp.wif_claims(
            "ci-job-1",
            AUD,
            json!({"job_project_id": "9999", "ref_protected": true}),
        ))
        .await;
    assert_eq!(
        read_index(&srv, "ci-hosted", Transport::ApiKey, &token).await,
        StatusCode::UNAUTHORIZED,
        "a token matching no claim rule is denied"
    );
}

#[tokio::test]
async fn stale_realm_policy_snapshot_cannot_publish_after_config_change() {
    let idp = MockOidc::start("unused-wif-client").await;
    let srv = start_stack().await;
    setup(&srv, &idp).await;

    let token = idp
        .sign_token(idp.wif_claims(
            "ci-job-1",
            AUD,
            json!({"job_project_id": "1001", "ref_protected": true}),
        ))
        .await;

    // Authenticate once so this server keeps the original realm snapshot.
    assert_eq!(
        read_index(&srv, "ci-hosted", Transport::Bearer, &token).await,
        StatusCode::OK
    );

    // Simulate a peer/admin changing the policy without invalidating this
    // process's local snapshot. Authentication still sees the old rule, but the
    // package transaction must fence it against the locked current config.
    let changed_config = json!({
        "issuer": idp.issuer(),
        "allow_http_issuer": true,
        "allowed_audiences": [AUD],
        "rules": [{
            "role": "ci-pub",
            "conditions": [
                {"claim": "job_project_id", "any_of": ["9999"]},
                {"claim": "ref_protected", "any_of": ["true"]}
            ]
        }]
    });
    sqlx::query("UPDATE auth_realm SET config = $1 WHERE name = 'gitlab-ci'")
        .bind(changed_config)
        .execute(&srv.pool)
        .await
        .unwrap();

    assert_eq!(
        push(
            &srv,
            "ci-hosted",
            Transport::Bearer,
            &token,
            make_nupkg("Acme.StalePolicy", "1.0.0"),
        )
        .await,
        StatusCode::FORBIDDEN,
        "a principal minted from a stale realm policy must fail at package commit"
    );

    let repo = forge_db::repository_dao::find_repository_by_name(&srv.pool, "ci-hosted")
        .await
        .unwrap()
        .unwrap();
    assert!(forge_db::component_dao::find_component(
        &srv.pool,
        repo.id,
        "acme.stalepolicy",
        "1.0.0"
    )
    .await
    .unwrap()
    .is_none());
    let audit_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM trusted_publish_audit WHERE repository_id = $1")
            .bind(repo.id)
            .fetch_one(&srv.pool)
            .await
            .unwrap();
    assert_eq!(audit_count, 0, "denied stale policy must not be audited");
}

#[tokio::test]
async fn workload_unlist_and_relist_are_audited_and_fenced() {
    let idp = MockOidc::start("unused-wif-client").await;
    let srv = start_stack().await;
    setup(&srv, &idp).await;
    let role_id: i64 = sqlx::query_scalar("SELECT id FROM role WHERE name = 'ci-pub'")
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(
        srv.add_grant(role_id, Some("ci-hosted"), "delete", None)
            .await
            .status(),
        201
    );

    let token = idp
        .sign_token(idp.wif_claims(
            "ci-job-1",
            AUD,
            json!({"job_project_id": "1001", "ref_protected": true}),
        ))
        .await;
    for version in ["1.0.0", "2.0.0"] {
        assert_eq!(
            push(
                &srv,
                "ci-hosted",
                Transport::Bearer,
                &token,
                make_nupkg("Acme.Mutations", version),
            )
            .await,
            StatusCode::CREATED
        );
    }
    let mutate = |method: reqwest::Method, version: &'static str| {
        let url = format!(
            "{}/repository/ci-hosted/package/Acme.Mutations/{version}",
            srv.base_url
        );
        let req = srv.client().request(method, url).bearer_auth(&token);
        async move { req.send().await.unwrap().status() }
    };
    let actions = || async {
        sqlx::query_scalar::<_, String>(
            "SELECT action || ':' || package_version FROM trusted_publish_audit \
             WHERE package_name = 'acme.mutations' ORDER BY id",
        )
        .fetch_all(&srv.pool)
        .await
        .unwrap()
    };

    // Unlist and relist by a workload land in the same ledger as its publish.
    assert_eq!(
        mutate(reqwest::Method::DELETE, "1.0.0").await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(mutate(reqwest::Method::POST, "1.0.0").await, StatusCode::OK);
    assert_eq!(
        actions().await,
        [
            "publish:1.0.0",
            "publish:2.0.0",
            "unlist:1.0.0",
            "relist:1.0.0"
        ]
    );

    // A stale realm snapshot is fenced at the mutation's commit, exactly as
    // for a publish: no unlist, no ledger row.
    sqlx::query(
        "UPDATE auth_realm SET config = jsonb_set(config, '{rules,0,conditions,0,any_of}', \
         '[\"9999\"]') WHERE name = 'gitlab-ci'",
    )
    .execute(&srv.pool)
    .await
    .unwrap();
    assert_eq!(
        mutate(reqwest::Method::DELETE, "2.0.0").await,
        StatusCode::FORBIDDEN
    );
    let listed: bool = sqlx::query_scalar(
        "SELECT listed FROM component WHERE name = 'acme.mutations' AND version = '2.0.0'",
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert!(listed, "a fenced unlist must not change the version");
    assert_eq!(actions().await.len(), 4, "a fenced unlist is not audited");
}

#[tokio::test]
async fn jwt_for_malformed_enabled_wif_realm_never_falls_through_to_forwarding() {
    let issuer = "https://malformed-wif.example";
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(json!({"alg": "RS256", "kid": "k1"}).to_string());
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(json!({"iss": issuer, "sub": "workload-1"}).to_string());
    let token = format!("{header}.{payload}.signature");

    // If WIF declined this token, the forwarding realm would forward the
    // same password for `ci@example.com` as `ci`, which the upstream accepts.
    // The request must instead terminate at WIF.
    let upstream = MockBasicUpstream::start(vec![("ci", token.as_str(), vec![])]).await;
    let block =
        upstream.upstream_basic_block(&["local-password", "upstream-basic"], 300, 30, &[], "");
    let srv = StackBuilder::default()
        .bootstrap_admin("root@example.com", "rootpw")
        .with_upstream_basic(block)
        .start()
        .await;

    // Bypass the admin validator to model a legacy/corrupt row. Its issuer is
    // still readable, but empty audiences/rules make runtime construction fail.
    let broken_id: i64 = sqlx::query_scalar(
        r#"
        INSERT INTO auth_realm (kind, name, enabled, priority, config)
        VALUES ('workload_identity', 'broken-wif', true,
                (SELECT COALESCE(max(priority), 0) + 10 FROM auth_realm), $1)
        RETURNING id
        "#,
    )
    .bind(json!({"issuer": issuer, "allowed_audiences": [], "rules": []}))
    .fetch_one(&srv.pool)
    .await
    .unwrap();

    let malformed_patch = srv
        .client()
        .patch(format!("{}/admin/realms/{broken_id}", srv.base_url))
        .basic_auth("root@example.com", srv.admin_scoped_token.as_deref())
        .json(&json!({"name": "still-broken-wif"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        malformed_patch.status(),
        StatusCode::BAD_REQUEST,
        "a name-only update of malformed legacy WIF config must fail gracefully"
    );

    // Startup may already have built a realm snapshot while importing the
    // legacy forwarding config. A no-op admin realm update invalidates it so
    // the next request exercises the malformed row just inserted.
    let local_id: i64 = sqlx::query_scalar("SELECT id FROM auth_realm WHERE kind = 'local'")
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    let invalidate = srv
        .client()
        .patch(format!("{}/admin/realms/{local_id}", srv.base_url))
        .basic_auth("root@example.com", srv.admin_scoped_token.as_deref())
        .json(&json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(invalidate.status(), StatusCode::OK);

    let response = srv
        .client()
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth("ci@example.com", Some(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        upstream.hits(),
        0,
        "a JWT claimed by an invalid WIF realm must never be forwarded as a password"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_dotnet_push_uses_wif_for_private_index_and_package_put() {
    if !Command::new("dotnet")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
    {
        eprintln!("dotnet SDK not present; skipping native WIF smoke test");
        return;
    }

    let github = MockOidc::start_workload_only("unused-github-client").await;
    let srv = start_stack().await;
    assert_eq!(
        srv.create_repo(json!({"name": "native-wif", "kind": "hosted"}))
            .await
            .status(),
        StatusCode::CREATED
    );
    let role = srv.create_role("native-wif-publisher").await;
    let selector = srv
        .create_content_selector("native-wif-packages", &["native.trusted.*"], &[])
        .await;
    assert_eq!(
        srv.add_grant(role, Some("native-wif"), "write", Some(selector))
            .await
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        create_wif_realm(
            &srv,
            "native-github-actions",
            json!({
                "issuer": github.issuer(),
                "allow_http_issuer": true,
                "allowed_audiences": [AUD],
                "rules": [{
                    "role": "native-wif-publisher",
                    "conditions": [{"claim": "repository_id", "any_of": ["424242"]}]
                }]
            }),
        )
        .await,
        StatusCode::CREATED
    );
    let token = github
        .sign_token(github.wif_claims(
            "repo:acme/native:ref:refs/heads/main",
            AUD,
            json!({"repository_id": "424242", "ref": "refs/heads/main"}),
        ))
        .await;

    // RAII cleanup is security-relevant: the job-local config below contains
    // the bearer token in clear text and must not survive this test process.
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("Native.Trusted.Core.1.0.0.nupkg");
    std::fs::write(&package, make_nupkg("Native.Trusted.Core", "1.0.0")).unwrap();
    let config = temp.path().join("nuget.config");
    let source = format!("{}/repository/native-wif/index.json", srv.base_url);
    std::fs::write(
        &config,
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="forge-oidc" value="{source}" allowInsecureConnections="true" />
  </packageSources>
  <packageSourceCredentials>
    <forge-oidc>
      <add key="Username" value="oidc" />
      <add key="ClearTextPassword" value="{token}" />
    </forge-oidc>
  </packageSourceCredentials>
</configuration>
"#,
        ),
    )
    .unwrap();

    let package_arg = package.to_string_lossy().into_owned();
    let config_arg = config.to_string_lossy().into_owned();
    let token_arg = token.clone();
    let temp_for_command = temp.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        Command::new("dotnet")
            .args([
                "nuget",
                "push",
                &package_arg,
                "--source",
                "forge-oidc",
                "--api-key",
                &token_arg,
                "--configfile",
                &config_arg,
            ])
            .current_dir(temp_for_command)
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "native dotnet WIF push failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let repo = forge_db::repository_dao::find_repository_by_name(&srv.pool, "native-wif")
        .await
        .unwrap()
        .unwrap();
    assert!(
        forge_db::component_dao::find_component(&srv.pool, repo.id, "native.trusted.core", "1.0.0")
            .await
            .unwrap()
            .is_some(),
        "native client publish must commit the package"
    );
}

#[tokio::test]
async fn two_issuers_are_routed_independently() {
    let idp_a = MockOidc::start("client-a").await;
    let idp_b = MockOidc::start("client-b").await;
    let srv = start_stack().await;
    setup(&srv, &idp_a).await; // realm "gitlab-ci" → idp_a, role ci-pub on ci-hosted

    // A second issuer/realm mapping the SAME claim rule to a read-only role on a
    // different repo.
    assert_eq!(
        srv.create_repo(json!({"name": "gh-hosted", "kind": "hosted", "anonymous_read": false}))
            .await
            .status(),
        201
    );
    let reader = srv.create_role("gh-reader").await;
    assert_eq!(
        srv.add_grant(reader, Some("gh-hosted"), "read", None)
            .await
            .status(),
        201
    );
    assert_eq!(
        create_wif_realm(
            &srv,
            "github-ci",
            json!({
                "issuer": idp_b.issuer(),
                "allow_http_issuer": true,
                "allowed_audiences": [AUD],
                "rules": [{
                    "role": "gh-reader",
                    "conditions": [{"claim": "repository_id", "any_of": ["3001"]}],
                }],
            }),
        )
        .await,
        201
    );

    // idp_b's token reads gh-hosted (its realm) but NOT ci-hosted (issuer A's
    // realm grants no access to idp_b's principal).
    let token_b = idp_b
        .sign_token(idp_b.wif_claims(
            "repo:acme/app:ref:refs/heads/main",
            AUD,
            json!({"repository_id": "3001", "repository": "acme/app"}),
        ))
        .await;
    assert_eq!(
        read_index(&srv, "gh-hosted", Transport::ApiKey, &token_b).await,
        StatusCode::OK,
        "issuer B's token reads issuer B's repo"
    );
    assert_eq!(
        read_index(&srv, "ci-hosted", Transport::ApiKey, &token_b).await,
        StatusCode::FORBIDDEN,
        "issuer B's read-only role cannot write/read issuer A's repo"
    );
}

#[tokio::test]
async fn duplicate_enabled_wif_issuer_is_rejected() {
    let idp = MockOidc::start("unused-wif-client").await;
    let srv = start_stack().await;
    setup(&srv, &idp).await;

    let status = create_wif_realm(
        &srv,
        "duplicate-gitlab-ci",
        json!({
            "issuer": format!("{}/", idp.issuer()),
            "allow_http_issuer": true,
            "allowed_audiences": [AUD],
            "rules": [{
                "role": "ci-pub",
                "conditions": [{"claim": "job_project_id", "any_of": ["1001"]}]
            }]
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "one normalized issuer can belong to only one enabled WIF realm"
    );
}

#[tokio::test]
async fn github_actions_minimal_discovery_and_stable_claims_authenticate() {
    // GitHub's workload discovery intentionally omits authorization_endpoint
    // and token_endpoint. The WIF verifier must accept that minimal shape while
    // the interactive OIDC login path remains strict.
    let github = MockOidc::start_workload_only("unused-github-client").await;
    let srv = start_stack().await;
    assert_eq!(
        srv.create_repo(json!({"name": "github-hosted", "kind": "hosted"}))
            .await
            .status(),
        201
    );
    let role = srv.create_role("github-publisher").await;
    let selector = srv
        .create_content_selector("github-package-scope", &["acme.github.*"], &[])
        .await;
    assert_eq!(
        srv.add_grant(role, Some("github-hosted"), "read", None)
            .await
            .status(),
        201
    );
    assert_eq!(
        srv.add_grant(role, Some("github-hosted"), "write", Some(selector))
            .await
            .status(),
        201
    );
    assert_eq!(
        create_wif_realm(
            &srv,
            "github-actions",
            json!({
                "issuer": github.issuer(),
                "allow_http_issuer": true,
                "allowed_audiences": [AUD],
                "max_token_age_seconds": 900,
                "rules": [{
                    "role": "github-publisher",
                    "conditions": [
                        {"claim": "repository_id", "any_of": ["987654321"]},
                        {"claim": "repository_owner_id", "any_of": ["1234567"]},
                        {"claim": "ref", "any_of": ["refs/heads/main"]}
                    ]
                }]
            }),
        )
        .await,
        201
    );

    // Claim names and subject shape mirror GitHub Actions. Authorization uses
    // stable numeric IDs; the human-readable repository name is informational.
    let mut claims = github.wif_claims(
        "repo:acme/widgets:ref:refs/heads/main",
        AUD,
        json!({
            "repository": "acme/widgets",
            "repository_id": "987654321",
            "repository_owner": "acme",
            "repository_owner_id": "1234567",
            "ref": "refs/heads/main",
            "ref_type": "branch",
            "workflow_ref": "acme/widgets/.github/workflows/publish.yml@refs/heads/main"
        }),
    );
    claims["exp"] = json!(chrono::Utc::now().timestamp() + 600);
    let token = github.sign_token(claims).await;

    assert_eq!(
        push(
            &srv,
            "github-hosted",
            Transport::Bearer,
            &token,
            make_nupkg("Acme.GitHub.Core", "1.0.0"),
        )
        .await,
        StatusCode::CREATED
    );
    assert_eq!(
        read_index(&srv, "github-hosted", Transport::ApiKey, &token).await,
        StatusCode::OK,
        "the same direct workload token remains reusable until exp"
    );

    // Package scope is part of the trusted-publishing boundary: the same valid
    // workload token cannot publish an id outside its role's selector, and the
    // denial occurs before CAS promotion or component mutation.
    let denied_package = make_nupkg("Other.GitHub", "1.0.0");
    let denied_sha = hex::encode(Sha256::digest(&denied_package));
    assert_eq!(
        push(
            &srv,
            "github-hosted",
            Transport::ApiKey,
            &token,
            denied_package,
        )
        .await,
        StatusCode::FORBIDDEN
    );
    let repo = forge_db::repository_dao::find_repository_by_name(&srv.pool, "github-hosted")
        .await
        .unwrap()
        .unwrap();
    assert!(
        forge_db::component_dao::find_component(&srv.pool, repo.id, "other.github", "1.0.0")
            .await
            .unwrap()
            .is_none(),
        "out-of-scope WIF upload must not create a component"
    );
    let denied_blob_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM blob WHERE sha256 = $1)")
            .bind(denied_sha)
            .fetch_one(&srv.pool)
            .await
            .unwrap();
    assert!(
        !denied_blob_exists,
        "out-of-scope WIF upload must not promote a CAS blob"
    );

    // The accepted publish appended durable, human-interpretable provenance in
    // the package transaction; the denied attempt appended nothing.
    let audit = sqlx::query(
        r#"
        SELECT id, repository_name, package_name, package_version,
               realm_name, issuer, role_name,
               octet_length(subject_sha256) AS subject_len,
               octet_length(jti_sha256) AS jti_len
        FROM trusted_publish_audit
        WHERE repository_id = $1
        "#,
    )
    .bind(repo.id)
    .fetch_all(&srv.pool)
    .await
    .unwrap();
    assert_eq!(audit.len(), 1, "only the accepted publish is audited");
    use sqlx::Row;
    let audit_id: i64 = audit[0].get("id");
    assert_eq!(
        audit[0].get::<String, _>("repository_name"),
        "github-hosted"
    );
    assert_eq!(
        audit[0].get::<String, _>("package_name"),
        "acme.github.core"
    );
    assert_eq!(audit[0].get::<String, _>("package_version"), "1.0.0");
    assert_eq!(audit[0].get::<String, _>("realm_name"), "github-actions");
    assert_eq!(audit[0].get::<String, _>("issuer"), github.issuer());
    assert_eq!(audit[0].get::<String, _>("role_name"), "github-publisher");
    assert_eq!(audit[0].get::<i32, _>("subject_len"), 32);
    assert_eq!(audit[0].get::<i32, _>("jti_len"), 32);

    let mutation =
        sqlx::query("UPDATE trusted_publish_audit SET role_name = 'changed' WHERE id = $1")
            .bind(audit_id)
            .execute(&srv.pool)
            .await;
    assert!(
        mutation.is_err(),
        "trusted publishing provenance is append-only"
    );

    // Historical provenance must outlive every mutable authorization/config
    // row it snapshots. Delete the live realm, mapped role, and repository and
    // prove the immutable ledger remains independently readable with the names
    // captured at publish time (the ledger intentionally has no cascading FKs).
    sqlx::query("DELETE FROM auth_realm WHERE name = 'github-actions'")
        .execute(&srv.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM role WHERE name = 'github-publisher'")
        .execute(&srv.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM repository WHERE id = $1")
        .bind(repo.id)
        .execute(&srv.pool)
        .await
        .unwrap();

    let durable_snapshot: (String, String, String, String) = sqlx::query_as(
        r#"
        SELECT repository_name, realm_name, role_name, package_name
        FROM trusted_publish_audit
        WHERE id = $1
        "#,
    )
    .bind(audit_id)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(
        durable_snapshot,
        (
            "github-hosted".into(),
            "github-actions".into(),
            "github-publisher".into(),
            "acme.github.core".into(),
        ),
        "deleting live config must not erase or degrade publication provenance"
    );
}
