//! Admin API coverage for repository-scoped trusted publishers.
//!
//! Requires Docker (Postgres + versitygw).

mod common;

use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::Digest as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BOUNDARY: &str = "TRUSTEDPUBLISHERBOUNDARY";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";

struct TestSigner {
    private_pem: String,
    kid: String,
    jwk: Value,
}

impl TestSigner {
    fn new() -> Self {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let private_pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .unwrap()
            .to_string();
        let kid = "trusted-publisher-test-key".to_string();
        let jwk = json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(public_key.n().to_bytes_be()),
            "e": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(public_key.e().to_bytes_be())
        });
        Self {
            private_pem,
            kid,
            jwk,
        }
    }

    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(self.private_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }
}

async fn issuer() -> (MockServer, TestSigner) {
    let server = MockServer::start().await;
    let signer = TestSigner::new();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": server.uri(),
            "jwks_uri": format!("{}/jwks", server.uri())
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [signer.jwk.clone()]
        })))
        .mount(&server)
        .await;
    (server, signer)
}

fn claims(issuer: &str, project: &str) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "iss": issuer,
        "aud": "https://forge.example.com",
        "sub": format!("repo:{project}:ref:refs/heads/main"),
        "iat": now,
        "exp": now + 600,
        "jti": format!("trusted-publisher-{}-{now}", common::unique()),
        "repository_id": project,
        "repository_owner_id": "2001"
    })
}

fn package_body(package: &[u8]) -> Vec<u8> {
    let mut body = format!("--{BOUNDARY}\r\n").into_bytes();
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"package\"; filename=\"package.nupkg\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(package);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn push(srv: &common::TestServer, repo: &str, api_key: &str, id: &str) -> reqwest::Response {
    srv.client()
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", api_key)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(package_body(&common::make_nupkg(id, "1.0.0")))
        .send()
        .await
        .unwrap()
}

async fn oci_registry_token(srv: &common::TestServer, name: &str, api_key: &str) -> String {
    let response = srv
        .client()
        .get(format!("{}/v2/token", srv.base_url))
        .query(&[
            ("service", "test.local"),
            ("scope", &format!("repository:{name}:pull,push")),
        ])
        .basic_auth("oidc", Some(api_key))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    response.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn exchange_workload_key(srv: &common::TestServer, token: String) -> String {
    let response = srv
        .client()
        .post(format!("{}/api/v2/token", srv.base_url))
        .bearer_auth(token)
        .json(&json!({"username": "oidc", "tokenType": "ApiKey"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    response.json::<Value>().await.unwrap()["apiKey"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn push_oci_image(
    srv: &common::TestServer,
    name: &str,
    token: &str,
    tag: &str,
    config: &[u8],
) -> reqwest::Response {
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(config)));
    let upload = srv
        .client()
        .post(format!("{}/v2/{name}/blobs/uploads/", srv.base_url))
        .query(&[("digest", &digest)])
        .bearer_auth(token)
        .header("content-type", "application/octet-stream")
        .body(config.to_vec())
        .send()
        .await
        .unwrap();
    if !upload.status().is_success() {
        return upload;
    }
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": digest, "size": config.len()},
        "layers": []
    });
    srv.client()
        .put(format!("{}/v2/{name}/manifests/{tag}", srv.base_url))
        .bearer_auth(token)
        .header("content-type", OCI_MANIFEST)
        .body(manifest.to_string())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn trusted_publishers_are_validated_and_crud_is_repository_scoped() {
    let srv = common::start().await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();

    let repo = format!("trusted-publishers-{}", common::unique());
    let response = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let role_name = format!("ci-reader-{}", common::unique());
    let realm_name = format!("trusted-publisher-test-{}", common::unique());
    let response = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"name": role_name}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let response = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "kind": "workload_identity",
            "name": realm_name,
            "enabled": true,
            "config": {
                "issuer": "https://token.actions.githubusercontent.com",
                "allowed_audiences": ["https://forge.example.com"],
                "rules": [{
                    "role": role_name,
                    "conditions": [
                        {"claim": "repository_id", "any_of": ["1001"]},
                        {"claim": "repository_owner_id", "any_of": ["2001"]}
                    ]
                }]
            }

        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201, "{}", response.text().await.unwrap());

    let collection = format!(
        "{}/admin/repositories/{repo}/trusted-publishers",
        srv.base_url
    );
    let invalid = client
        .post(&collection)
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "name": "missing-identity",
            "realm": realm_name,
            "packages": {"includes": ["Acme.*"], "excludes": []},
            "conditions": [{"claim": "event_name", "any_of": ["push"]}],
            "actions": ["write", "delete"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), 400);

    let body = json!({
        "name": "widgets-release",
        "description": "Protected release workflow",
        "realm": realm_name,
        "packages": {"includes": ["Acme.Widgets.*"], "excludes": []},
        "conditions": [
            {"claim": "repository_id", "any_of": ["1001"]},
            {"claim": "repository_owner_id", "any_of": ["2001"]},
            {"claim": "job_workflow_ref", "any_of": ["acme/widgets/.github/workflows/release.yml@refs/heads/main"]}
        ],
        "actions": ["write"]
    });
    let response = client
        .post(&collection)
        .basic_auth(&admin, Some(&password))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201, "{}", response.text().await.unwrap());
    let created: Value = response.json().await.unwrap();
    assert_eq!(created["realm"], json!(realm_name));
    assert_eq!(created["packages"]["includes"], json!(["Acme.Widgets.*"]));
    assert_eq!(created["actions"], json!(["write"]));
    let id = created["id"].as_i64().unwrap();

    let response = client
        .get(&collection)
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    let publishers: Vec<Value> = response.json().await.unwrap();
    assert_eq!(publishers, vec![created]);

    let response = client
        .put(format!("{collection}/{id}"))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "name": "widgets-release",
            "description": "Protected release workflow",
            "realm": realm_name,
            "packages": {"includes": ["Acme.Widgets.*"], "excludes": []},
            "conditions": body["conditions"],
            "actions": ["write", "delete"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let updated: Value = response.json().await.unwrap();
    assert_eq!(updated["actions"], json!(["delete", "write"]));

    let response = client
        .delete(format!("{collection}/{id}"))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
}

#[tokio::test]
async fn oci_registry_tokens_recheck_publisher_snapshots_and_keep_role_reads() {
    let (issuer, signer) = issuer().await;
    let srv = common::start().await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("trusted-oci-{}", common::unique());
    let image = format!("{repo}/app");
    let publishers = format!(
        "{}/admin/repositories/{repo}/trusted-publishers",
        srv.base_url
    );

    let response = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"name": repo, "kind": "hosted", "format": "docker"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    let role_name = format!("trusted-oci-reader-{}", common::unique());
    let role: Value = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"name": role_name}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_i64().unwrap();
    let response = client
        .put(format!("{}/admin/roles/{role_id}/grants", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"repository": repo, "level": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    let realm_name = format!("trusted-oci-wif-{}", common::unique());
    let response = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "kind": "workload_identity",
            "name": realm_name.clone(),
            "enabled": true,
            "config": {
                "issuer": issuer.uri(),
                "allow_http_issuer": true,
                "allowed_audiences": ["https://forge.example.com"],
                "rules": [{
                    "role": role_name,
                    "conditions": [
                        {"claim": "repository_id", "any_of": ["1001"]},
                        {"claim": "repository_owner_id", "any_of": ["2001"]}
                    ]
                }]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201, "{}", response.text().await.unwrap());

    let publisher_body = json!({
        "name": "oci-release",
        "realm": realm_name.clone(),
        "packages": {"includes": ["app"], "excludes": []},
        "conditions": [
            {"claim": "repository_id", "any_of": ["1001"]},
            {"claim": "repository_owner_id", "any_of": ["2001"]}
        ],
        "actions": ["write"]
    });
    let response = client
        .post(&publishers)
        .basic_auth(&admin, Some(&password))
        .json(&publisher_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201, "{}", response.text().await.unwrap());
    let publisher: Value = response.json().await.unwrap();
    let publisher_id = publisher["id"].as_i64().unwrap();

    let api_key = exchange_workload_key(&srv, signer.sign(&claims(&issuer.uri(), "1001"))).await;
    let registry_token = oci_registry_token(&srv, &image, &api_key).await;
    let token_payload = registry_token.split('.').nth(1).unwrap();
    let token_claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token_payload)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        token_claims["access"][0]["actions"],
        json!(["pull", "push"]),
        "{token_claims}"
    );
    assert_eq!(token_claims["fp"]["publishers"][0]["id"], publisher_id);
    let config =
        br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#;
    let pushed = push_oci_image(&srv, &image, &registry_token, "release", config).await;
    assert_eq!(pushed.status(), 201, "{}", pushed.text().await.unwrap());

    let mut updated = publisher_body.clone();
    updated["packages"]["includes"] = json!(["other"]);
    let response = client
        .put(format!("{publishers}/{publisher_id}"))
        .basic_auth(&admin, Some(&password))
        .json(&updated)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let after_edit = br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"variant":"after-edit"}"#;
    assert_eq!(
        push_oci_image(&srv, &image, &registry_token, "after-edit", after_edit)
            .await
            .status(),
        403
    );
    assert_eq!(
        client
            .get(format!("{}/v2/{image}/manifests/release", srv.base_url))
            .bearer_auth(&registry_token)
            .header("accept", OCI_MANIFEST)
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "the independent reader role remains effective"
    );

    let response = client
        .post(&publishers)
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "name": "oci-release-2",
            "realm": realm_name,
            "packages": {"includes": ["app"], "excludes": []},
            "conditions": publisher_body["conditions"],
            "actions": ["write"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let second_publisher: Value = response.json().await.unwrap();
    let api_key = exchange_workload_key(&srv, signer.sign(&claims(&issuer.uri(), "1001"))).await;
    let registry_token = oci_registry_token(&srv, &image, &api_key).await;
    let before_delete = br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"variant":"before-delete"}"#;
    assert_eq!(
        push_oci_image(
            &srv,
            &image,
            &registry_token,
            "before-delete",
            before_delete
        )
        .await
        .status(),
        201
    );

    let response = client
        .delete(format!(
            "{publishers}/{}",
            second_publisher["id"].as_i64().unwrap()
        ))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    let after_delete = br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]},"variant":"after-delete"}"#;
    assert_eq!(
        push_oci_image(&srv, &image, &registry_token, "after-delete", after_delete)
            .await
            .status(),
        403
    );
    assert_eq!(
        client
            .get(format!("{}/v2/{image}/manifests/release", srv.base_url))
            .bearer_auth(&registry_token)
            .header("accept", OCI_MANIFEST)
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "the independent reader role remains effective after deletion"
    );
}

#[tokio::test]
async fn reader_role_can_publish_only_live_publisher_packages() {
    let (issuer, signer) = issuer().await;
    let srv = common::start().await;
    let (admin, password) = srv.admin_basic();
    let client = srv.client();
    let repo = format!("trusted-write-{}", common::unique());

    let response = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let other_repo = format!("trusted-other-{}", common::unique());
    let response = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"name": other_repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    let role_name = format!("trusted-reader-{}", common::unique());
    let role: Value = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"name": role_name}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_i64().unwrap();
    let response = client
        .put(format!("{}/admin/roles/{role_id}/grants", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"repository": repo, "level": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let repository_id: i64 = sqlx::query_scalar("SELECT id FROM repository WHERE name = $1")
        .bind(&repo)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    let selector_id: i64 = sqlx::query_scalar(
        "INSERT INTO content_selector (name, includes, excludes) \
         VALUES ($1, $2, '[]'::jsonb) RETURNING id",
    )
    .bind(format!("trusted-role-selector-{}", common::unique()))
    .bind(json!(["Acme.Role.*"]))
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO repository_privilege (role_id, repository_id, level, selector_id) \
         VALUES ($1, $2, 'write', $3)",
    )
    .bind(role_id)
    .bind(repository_id)
    .bind(selector_id)
    .execute(&srv.pool)
    .await
    .unwrap();
    let response = client
        .put(format!("{}/admin/roles/{role_id}/grants", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"repository": other_repo, "level": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    let realm_name = format!("trusted-wif-{}", common::unique());
    let response = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({
            "kind": "workload_identity",
            "name": realm_name,
            "enabled": true,
            "config": {
                "issuer": issuer.uri(),
                "allow_http_issuer": true,
                "allowed_audiences": ["https://forge.example.com"],
                "rules": [{
                    "role": role_name,
                    "conditions": [
                        {"claim": "repository_id", "any_of": ["1001", "5005"]},
                        {"claim": "repository_owner_id", "any_of": ["2001"]}
                    ]
                }]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201, "{}", response.text().await.unwrap());

    let publishers = format!(
        "{}/admin/repositories/{repo}/trusted-publishers",
        srv.base_url
    );
    let publisher_body = json!({
        "name": "widgets-release",
        "realm": realm_name,
        "packages": {"includes": ["Acme.Widgets.*"], "excludes": []},
        "conditions": [
            {"claim": "repository_id", "any_of": ["1001", "3003"]},
            {"claim": "repository_owner_id", "any_of": ["2001"]}
        ],
        "actions": ["write"]
    });
    let response = client
        .post(&publishers)
        .basic_auth(&admin, Some(&password))
        .json(&publisher_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201, "{}", response.text().await.unwrap());
    let publisher: Value = response.json().await.unwrap();
    let publisher_id = publisher["id"].as_i64().unwrap();

    let sibling_body = json!({
        "name": "tools-release",
        "realm": realm_name,
        "packages": {"includes": ["Acme.Tools.*"], "excludes": []},
        "conditions": [
            {"claim": "repository_id", "any_of": ["5005"]},
            {"claim": "repository_owner_id", "any_of": ["2001"]}
        ],
        "actions": ["write", "delete"]
    });
    let response = client
        .post(&publishers)
        .basic_auth(&admin, Some(&password))
        .json(&sibling_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let sibling: Value = response.json().await.unwrap();
    let sibling_id = sibling["id"].as_i64().unwrap();
    let sibling_exchange_token = signer.sign(&claims(&issuer.uri(), "5005"));
    let response = client
        .post(format!("{}/api/v2/token", srv.base_url))
        .bearer_auth(&sibling_exchange_token)
        .json(&json!({"username": "oidc", "tokenType": "ApiKey"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let sibling_key: Value = response.json().await.unwrap();
    let sibling_api_key = sibling_key["apiKey"].as_str().unwrap();

    let direct_token = signer.sign(&claims(&issuer.uri(), "1001"));
    let allowed = format!("Acme.Widgets.Direct{}", common::unique());
    assert_eq!(
        push(&srv, &repo, &direct_token, &allowed).await.status(),
        201
    );
    let other_package = format!("Acme.Widgets.OtherRepo{}", common::unique());
    assert_eq!(
        push(&srv, &other_repo, &direct_token, &other_package)
            .await
            .status(),
        403
    );
    let denied = format!("Acme.Other.{}", common::unique());
    assert_eq!(
        push(&srv, &repo, &direct_token, &denied).await.status(),
        403
    );
    let unlist = client
        .delete(format!(
            "{}/v3/{repo}/package/{allowed}/1.0.0",
            srv.base_url
        ))
        .header("X-NuGet-ApiKey", &direct_token)
        .send()
        .await
        .unwrap();
    let unlist_status = unlist.status();
    let unlist_body = unlist.text().await.unwrap();
    assert_eq!(unlist_status, 403, "{unlist_body}");

    let exchange_token = signer.sign(&claims(&issuer.uri(), "1001"));
    let response = client
        .post(format!("{}/api/v2/token", srv.base_url))
        .bearer_auth(&exchange_token)
        .json(&json!({"username": "oidc", "tokenType": "ApiKey"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let key: Value = response.json().await.unwrap();
    let api_key = key["apiKey"].as_str().unwrap();
    let exchanged = format!("Acme.Widgets.Exchanged{}", common::unique());
    assert_eq!(push(&srv, &repo, api_key, &exchanged).await.status(), 201);

    let mut updated = publisher_body;
    updated["packages"]["includes"] = json!(["Acme.Other.*"]);
    let response = client
        .put(format!("{publishers}/{publisher_id}"))
        .basic_auth(&admin, Some(&password))
        .json(&updated)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let revoked = format!("Acme.Widgets.Revoked{}", common::unique());
    assert_eq!(push(&srv, &repo, api_key, &revoked).await.status(), 403);
    let role_package = format!("Acme.Role.Remains{}", common::unique());
    assert_eq!(
        push(&srv, &repo, api_key, &role_package).await.status(),
        201
    );
    let sibling_package = format!("Acme.Tools.Survives{}", common::unique());
    assert_eq!(
        push(&srv, &repo, sibling_api_key, &sibling_package)
            .await
            .status(),
        201
    );
    assert_eq!(
        client
            .delete(format!(
                "{}/v3/{repo}/package/{sibling_package}/1.0.0",
                srv.base_url
            ))
            .header("X-NuGet-ApiKey", sibling_api_key)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );

    let audit = sqlx::query(
        "SELECT trusted_publisher_id, trusted_publisher_name \
         FROM trusted_publish_audit WHERE repository_name = $1 ORDER BY id",
    )
    .bind(&repo)
    .fetch_all(&srv.pool)
    .await
    .unwrap();
    assert_eq!(audit.len(), 5);
    let mut audit_publishers = Vec::new();
    for row in audit {
        use sqlx::Row;
        let id: Option<i64> = row.try_get("trusted_publisher_id").unwrap();
        let name: Option<String> = row.try_get("trusted_publisher_name").unwrap();
        audit_publishers.push(id.zip(name));
    }
    assert!(audit_publishers.contains(&Some((publisher_id, "widgets-release".into()))));
    assert!(audit_publishers.contains(&Some((sibling_id, "tools-release".into()))));
    assert!(audit_publishers.contains(&None));

    let untrusted_token = signer.sign(&claims(&issuer.uri(), "3003"));
    let untrusted_package = format!("Acme.Widgets.NoRule{}", common::unique());
    assert_eq!(
        push(&srv, &repo, &untrusted_token, &untrusted_package)
            .await
            .status(),
        401
    );
}
