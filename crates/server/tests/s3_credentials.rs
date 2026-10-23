//! Short-lived S3 credentials (#60) at the server level: a web identity
//! token that STS refuses fails the startup bucket check and `/readyz`, and
//! the error names the credential source, never the token.

mod common;

use serde_json::Value;
use wiremock::matchers::{body_string_contains, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REFUSED: &str = "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
    <Error><Type>Sender</Type><Code>InvalidIdentityToken</Code>\
    <Message>Token has been revoked</Message></Error>\
    <RequestId>test</RequestId></ErrorResponse>";

#[tokio::test]
async fn a_refused_web_identity_token_fails_startup_and_readiness() {
    let sts = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
        .respond_with(ResponseTemplate::new(400).set_body_raw(REFUSED, "text/xml"))
        .mount(&sts)
        .await;
    let token_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(token_file.path(), "revoked-token-value").unwrap();

    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            s3_credentials: Some(format!(
                "credentials = \"web_identity\"\n\
                 [s3.web_identity]\n\
                 role_arn = \"arn:aws:iam::123456789012:role/forge\"\n\
                 token_file = {:?}\n\
                 sts_endpoint = \"{}\"\n",
                token_file.path(),
                sts.uri()
            )),
            ..Default::default()
        },
    )
    .await;

    // Startup's bucket check (`main` aborts on this error).
    let err = forge_server::object_store::ensure_bucket(&srv.state.blob_store)
        .await
        .expect_err("STS refuses the token");
    let shown = format!("{err:#}");
    for part in [
        "web_identity",
        "arn:aws:iam::123456789012:role/forge",
        &sts.uri(),
        "InvalidIdentityToken",
    ] {
        assert!(shown.contains(part), "{part} missing: {shown}");
    }
    assert!(!shown.contains("revoked-token-value"), "{shown}");

    let ready = srv
        .client()
        .get(format!("{}/readyz", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 503);
    let body: Value = ready.json().await.unwrap();
    assert_eq!(body["checks"]["database"], true);
    assert_eq!(body["checks"]["object_store"], false);
}
