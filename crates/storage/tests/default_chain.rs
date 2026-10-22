//! `s3.credentials = "default_chain"` when the credential endpoint the chain
//! uses cannot be reached (#208): IRSA's STS call and the container endpoint
//! of ECS / EKS Pod Identity that refuse the connection or answer 5xx count
//! as S3 being unavailable, as with `web_identity`; an endpoint that refuses
//! the credentials does not. No Docker needed.
//!
//! The default chain reads the process environment, so this binary holds a
//! single test that sets it up scenario by scenario.

use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use forge_storage::{
    BlobCache, BlobCacheConfig, BlobStore, CacheLimit, ConditionalWrites, S3Config, S3Credentials,
};

/// Serve `status` with `body` for every request; the URL to reach it.
async fn answering(status: StatusCode, body: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(move || async move { (status, body).into_response() });
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

/// Whether S3 counted as unavailable when the chain failed: with the blob
/// cache, that starts the server degraded instead of failing startup.
async fn unavailable(cache_dir: &std::path::Path) -> bool {
    let store = BlobStore::new(S3Config {
        // Never reached: the credentials fail first.
        endpoint: "http://127.0.0.1:1".into(),
        region: "eu-central-1".into(),
        bucket: "fake".into(),
        credentials: S3Credentials::DefaultChain,
        force_path_style: true,
        multipart_threshold: 8 * 1024 * 1024,
        conditional_writes: ConditionalWrites::Off,
    })
    .with_cache(
        BlobCache::open(BlobCacheConfig {
            path: cache_dir.to_path_buf(),
            max_bytes: CacheLimit::Bytes(1 << 20),
            min_free_bytes: Some(0),
            staging: None,
        })
        .unwrap(),
    );
    let err = tokio::time::timeout(Duration::from_secs(60), store.ensure_bucket())
        .await
        .expect("the chain gives up")
        .expect_err("no credentials");
    assert!(err.to_string().contains("default_chain"), "{err}");
    err.is_unavailable()
}

#[tokio::test]
async fn an_unreachable_credential_endpoint_counts_as_s3_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "a-service-account-token").unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir(&cache_dir).unwrap();

    // Nothing but the endpoints each scenario names.
    for var in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_STS",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    ] {
        std::env::remove_var(var);
    }
    let missing = dir.path().join("missing");
    std::env::set_var("AWS_CONFIG_FILE", &missing);
    std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &missing);
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");

    // The container endpoint (ECS task roles, EKS Pod Identity).
    let container = |url: String| std::env::set_var("AWS_CONTAINER_CREDENTIALS_FULL_URI", url);
    container("http://127.0.0.1:1/credentials".into());
    assert!(unavailable(&cache_dir).await, "connection refused");
    container(answering(StatusCode::SERVICE_UNAVAILABLE, "down").await);
    assert!(unavailable(&cache_dir).await, "5xx");
    container(answering(StatusCode::FORBIDDEN, "no").await);
    assert!(!unavailable(&cache_dir).await, "a refusal");
    std::env::remove_var("AWS_CONTAINER_CREDENTIALS_FULL_URI");

    // IRSA: the token file exchanged at STS.
    std::env::set_var("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/forge");
    std::env::set_var("AWS_WEB_IDENTITY_TOKEN_FILE", &token_file);
    let sts = |url: String| std::env::set_var("AWS_ENDPOINT_URL_STS", url);
    sts("http://127.0.0.1:1".into());
    assert!(unavailable(&cache_dir).await, "STS connection refused");
    sts(answering(StatusCode::INTERNAL_SERVER_ERROR, "").await);
    assert!(unavailable(&cache_dir).await, "STS 5xx");
    sts(answering(
        StatusCode::BAD_REQUEST,
        "<ErrorResponse><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code>\
         <Message>refused</Message></Error></ErrorResponse>",
    )
    .await);
    assert!(!unavailable(&cache_dir).await, "STS refuses the token");
}
