//! E2E: workload-identity federation (WIF) auth realm (slice 12.8, design
//! 2026-06-03 §4/§5).
//!
//! Drives the **real** forge server over HTTP against a Postgres testcontainer
//! plus an in-process mock OIDC issuer (`MockOidc`: discovery + JWKS + arbitrary
//! token signing). A simulated CI job presents its `id_token` — as the
//! `X-NuGet-ApiKey`, an `Authorization: Bearer`, and the HTTP Basic password —
//! and pushes/restores against a NuGet repo it is authorized for by a mapped
//! forge role. Covers the §5 12.8 scenarios:
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

use forge_e2e::{make_nupkg, start_stack, MockOidc, TestServer};
use reqwest::StatusCode;
use serde_json::{json, Value};

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

/// GET `/v3/{repo}/index.json` presenting `token` in the named transport.
async fn read_index(srv: &TestServer, repo: &str, transport: Transport, token: &str) -> StatusCode {
    let url = format!("{}/v3/{repo}/index.json", srv.base_url);
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
        .put(format!("{}/v3/{repo}/package", srv.base_url))
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

/// Stand up a stack with a `gitlab-ci` WIF realm whose rule maps
/// `project_path = acme/app` to a role that can read+write `ci-hosted`.
async fn setup(srv: &TestServer, idp: &MockOidc) {
    assert_eq!(
        srv.create_repo(json!({"name": "ci-hosted", "kind": "hosted", "anonymous_read": false}))
            .await
            .status(),
        201
    );
    // The forge role the WIF rule grants: read + write on the repo.
    let role = srv.create_role("ci-pub").await;
    assert_eq!(
        srv.add_grant(role, Some("ci-hosted"), "read", None)
            .await
            .status(),
        201
    );
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
                "conditions": [{"claim": "project_path", "any_of": ["acme/app"]}],
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
        .sign_token(idp.wif_claims("ci-job-1", AUD, json!({"project_path": "acme/app"})))
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
            json!({"project_path": "acme/app"}),
        ))
        .await;
    assert_eq!(
        read_index(&srv, "ci-hosted", Transport::ApiKey, &wrong_aud).await,
        StatusCode::UNAUTHORIZED,
        "wrong aud must be rejected"
    );

    // Expired token.
    let mut expired_claims = idp.wif_claims("ci-job-1", AUD, json!({"project_path": "acme/app"}));
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
            json!({"project_path": "acme/app"}),
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
        .sign_token(idp.wif_claims("ci-job-1", AUD, json!({"project_path": "acme/other"})))
        .await;
    assert_eq!(
        read_index(&srv, "ci-hosted", Transport::ApiKey, &token).await,
        StatusCode::UNAUTHORIZED,
        "a token matching no claim rule is denied"
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
                    "conditions": [{"claim": "project_path", "any_of": ["acme/app"]}],
                }],
            }),
        )
        .await,
        201
    );

    // idp_b's token reads gh-hosted (its realm) but NOT ci-hosted (issuer A's
    // realm grants no access to idp_b's principal).
    let token_b = idp_b
        .sign_token(idp_b.wif_claims("gh-job", AUD, json!({"project_path": "acme/app"})))
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
