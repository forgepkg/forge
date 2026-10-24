//! E2E: short-lived S3 credentials (#60, `s3.credentials = "web_identity"`).
//! Forge exchanges a token file for temporary keys with STS
//! `AssumeRoleWithWebIdentity` against versitygw, whose STS trusts an OIDC
//! issuer under test control ([`MockOidc`]), and stores and serves packages
//! with them. A token the STS refuses fails the startup bucket check with an
//! error that names the credential source. Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use std::path::Path;

use forge_e2e::versitygw_sts::{self, VersitygwSts};
use forge_e2e::{make_nupkg, AnonMode, MockOidc, StackBuilder, S3_BUCKET};
use forge_storage::{BlobStore, ConditionalWrites, S3Config, S3Credentials, WebIdentity};
use serde_json::Value;

/// The `[s3]` keys for web identity against `sts`, after `extra`.
fn web_identity_toml(sts: &VersitygwSts, token_file: &Path, extra: &str) -> String {
    format!(
        "{extra}\ncredentials = \"web_identity\"\n\
         [s3.web_identity]\nrole_arn = \"{}\"\ntoken_file = {token_file:?}\n\
         sts_endpoint = \"{}\"\nduration_seconds = 900\n",
        sts.role_arn(),
        sts.sts_endpoint()
    )
}

#[tokio::test]
async fn packages_are_stored_with_temporary_keys_from_versitygw_sts() {
    let issuer =
        MockOidc::start_workload_only_on_host(versitygw_sts::CLIENT_ID, versitygw_sts::HOST_ALIAS)
            .await;
    let sts = VersitygwSts::start(&issuer).await;
    let token_file = tempfile::NamedTempFile::new().unwrap();
    let token = versitygw_sts::web_identity_token(&issuer).await;
    std::fs::write(token_file.path(), format!("{token}\n")).unwrap();

    // With a threshold of one byte every body goes through a multipart
    // upload, so those calls run with the temporary keys too. The stack's
    // start creates the bucket with them (versitygw has none yet).
    let srv = StackBuilder::default()
        .anon(AnonMode::All)
        .s3_endpoint(sts.s3_endpoint())
        .s3_credentials(web_identity_toml(
            &sts,
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
            "{}/repository/{repo}/flat/forge.webidentity/1.0.0/forge.webidentity.1.0.0.nupkg",
            srv.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(download.bytes().await.unwrap().to_vec(), nupkg);
}

#[tokio::test]
async fn a_token_the_sts_refuses_fails_the_bucket_check() {
    let issuer =
        MockOidc::start_workload_only_on_host(versitygw_sts::CLIENT_ID, versitygw_sts::HOST_ALIAS)
            .await;
    let sts = VersitygwSts::start(&issuer).await;
    let token_file = tempfile::NamedTempFile::new().unwrap();
    // Signed by a key the issuer does not publish.
    let forged = issuer
        .sign_token_unknown_key(issuer.wif_claims(
            "system:serviceaccount:forge:forge",
            versitygw_sts::CLIENT_ID,
            serde_json::json!({}),
        ))
        .await;
    std::fs::write(token_file.path(), &forged).unwrap();

    let store = BlobStore::new(S3Config {
        endpoint: sts.s3_endpoint().to_string(),
        region: "us-east-1".into(),
        bucket: S3_BUCKET.into(),
        credentials: S3Credentials::WebIdentity(WebIdentity {
            role_arn: Some(sts.role_arn().to_string()),
            token_file: token_file.path().to_path_buf(),
            sts_endpoint: Some(sts.sts_endpoint().to_string()),
            session_name: "forge".into(),
            duration_seconds: None,
        }),
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: ConditionalWrites::Auto,
    });
    let err = forge_server::object_store::ensure_bucket(&store)
        .await
        .expect_err("the STS refuses the token");
    let shown = format!("{err:#}");
    assert!(shown.contains("web_identity"), "{shown}");
    assert!(shown.contains(sts.role_arn()), "{shown}");
    assert!(shown.contains(sts.sts_endpoint()), "{shown}");
    assert!(
        shown.contains("STS AssumeRoleWithWebIdentity failed"),
        "{shown}"
    );
    // Refused for its signature, not for the role.
    assert!(shown.contains("InvalidIdentityToken"), "{shown}");
    assert!(!shown.contains(&forged), "the token leaked: {shown}");
}
