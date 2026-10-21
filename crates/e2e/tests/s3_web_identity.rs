//! E2E: short-lived S3 credentials (#60, `s3.credentials = "web_identity"`).
//! Forge exchanges a token file for temporary keys with STS
//! `AssumeRoleWithWebIdentity` against MinIO, whose STS trusts an OIDC issuer
//! under test control ([`MockOidc`]), and stores and serves packages with
//! them. A token MinIO refuses fails the startup bucket check with an error
//! that names the credential source. Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use std::path::Path;

use forge_e2e::minio::{self, Minio};
use forge_e2e::{make_nupkg, AnonMode, MockOidc, StackBuilder, S3_BUCKET};
use forge_storage::{BlobStore, ConditionalWrites, S3Config, S3Credentials, WebIdentity};
use serde_json::Value;

/// The `[s3]` keys for web identity against `minio`'s STS, after `extra`.
fn web_identity_toml(minio: &Minio, token_file: &Path, extra: &str) -> String {
    format!(
        "{extra}\ncredentials = \"web_identity\"\n\
         [s3.web_identity]\ntoken_file = {token_file:?}\nsts_endpoint = \"{}\"\n\
         duration_seconds = 900\n",
        minio.endpoint()
    )
}

#[tokio::test]
async fn packages_are_stored_with_temporary_keys_from_minio_sts() {
    let issuer = MockOidc::start_workload_only_on_host(minio::CLIENT_ID, minio::HOST_ALIAS).await;
    let minio = Minio::start(&issuer).await;
    let token_file = tempfile::NamedTempFile::new().unwrap();
    let token = minio::web_identity_token(&issuer, "readwrite").await;
    std::fs::write(token_file.path(), format!("{token}\n")).unwrap();

    // With a threshold of one byte every body goes through a multipart
    // upload, so those calls run with the temporary keys too. The stack's
    // start creates the bucket with them (MinIO has none yet).
    let srv = StackBuilder::default()
        .anon(AnonMode::All)
        .s3_endpoint(minio.endpoint())
        .s3_credentials(web_identity_toml(
            &minio,
            token_file.path(),
            "multipart_threshold = 1",
        ))
        .start()
        .await;

    let ready = srv
        .client()
        .get(format!("{}/readyz", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 200);
    let body: Value = ready.json().await.unwrap();
    assert_eq!(body["checks"]["object_store"], true, "{body}");

    let repo = "wi-hosted";
    let resp = srv
        .create_repo(serde_json::json!({"name": repo, "kind": "hosted", "anonymous_read": true}))
        .await;
    assert_eq!(resp.status(), 201, "create repo");
    srv.grant_anonymous_read(repo).await;
    let nupkg = make_nupkg("Forge.WebIdentity", "1.0.0");
    let push = srv.push_nupkg(repo, nupkg.clone()).await;
    assert_eq!(push.status(), 201, "push: {}", push.text().await.unwrap());

    let download = srv
        .client()
        .get(format!(
            "{}/v3/{repo}/flat/forge.webidentity/1.0.0/forge.webidentity.1.0.0.nupkg",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(download.bytes().await.unwrap().to_vec(), nupkg);
}

#[tokio::test]
async fn a_token_minio_refuses_fails_the_bucket_check() {
    let issuer = MockOidc::start_workload_only_on_host(minio::CLIENT_ID, minio::HOST_ALIAS).await;
    let minio = Minio::start(&issuer).await;
    let token_file = tempfile::NamedTempFile::new().unwrap();
    // Signed by a key the issuer does not publish.
    let forged = issuer
        .sign_token_unknown_key(issuer.wif_claims(
            "system:serviceaccount:forge:forge",
            minio::CLIENT_ID,
            serde_json::json!({ "policy": "readwrite" }),
        ))
        .await;
    std::fs::write(token_file.path(), &forged).unwrap();

    let store = BlobStore::new(S3Config {
        endpoint: minio.endpoint().to_string(),
        region: "us-east-1".into(),
        bucket: S3_BUCKET.into(),
        credentials: S3Credentials::WebIdentity(WebIdentity {
            role_arn: None,
            token_file: token_file.path().to_path_buf(),
            sts_endpoint: Some(minio.endpoint().to_string()),
            session_name: "forge".into(),
            duration_seconds: None,
        }),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: ConditionalWrites::Auto,
    });
    let err = forge_server::object_store::ensure_bucket(&store)
        .await
        .expect_err("MinIO refuses the token");
    let shown = format!("{err:#}");
    assert!(shown.contains("web_identity"), "{shown}");
    assert!(shown.contains(minio.endpoint()), "{shown}");
    assert!(
        shown.contains("STS AssumeRoleWithWebIdentity failed"),
        "{shown}"
    );
    assert!(!shown.contains(&forged), "the token leaked: {shown}");
}
