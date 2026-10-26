//! `s3.credentials = "web_identity"` against an in-process fake STS and fake
//! S3 (#60): the token file is exchanged for temporary keys, the keys are
//! cached while they are valid and fetched again before they expire (so
//! operations, and a multipart upload, keep working across an expiry), the
//! token file is read again on every fetch, and a refused token fails the S3
//! call with an error that names the credential source and never shows the
//! token. No Docker needed.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Form;
use forge_storage::{
    BlobCache, BlobCacheConfig, BlobStore, CacheLimit, ConditionalWrites, S3Config, S3Credentials,
    WebIdentity,
};
use tokio::io::AsyncReadExt;

const ROLE: &str = "arn:aws:iam::123456789012:role/forge";

/// Temporary keys the fake STS handed out.
struct Issued {
    secret_key: String,
    session_token: String,
    expires: Instant,
}

/// One `AssumeRoleWithWebIdentity` the fake STS received.
#[derive(Debug, Clone)]
struct StsCall {
    token: String,
    role_arn: Option<String>,
    session_name: Option<String>,
    duration_seconds: Option<String>,
}

#[derive(Default)]
struct Fake {
    /// Tokens STS accepts.
    valid_tokens: Mutex<Vec<String>>,
    /// Lifetime of the keys STS hands out.
    lifetime: Mutex<Duration>,
    sts_calls: Mutex<Vec<StsCall>>,
    issued: Mutex<HashMap<String, Issued>>,
    /// The access key of every S3 request, with what the request was.
    s3_requests: Mutex<Vec<(String, String)>>,
    objects: Mutex<HashMap<String, Vec<u8>>>,
    parts: Mutex<HashMap<i32, Vec<u8>>>,
    /// How long the fake S3 takes to answer an `UploadPart`.
    part_delay: Mutex<Duration>,
}

impl Fake {
    fn sts_calls(&self) -> Vec<StsCall> {
        self.sts_calls.lock().unwrap().clone()
    }

    fn s3_keys(&self, what: &str) -> Vec<String> {
        self.s3_requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, w)| w == what)
            .map(|(k, _)| k.clone())
            .collect()
    }
}

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

fn sts_error(status: StatusCode, code: &str) -> Response {
    let body = format!(
        "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
         <Error><Type>Sender</Type><Code>{code}</Code>\
         <Message>injected by the fake STS</Message></Error>\
         <RequestId>fake</RequestId></ErrorResponse>"
    );
    (status, [("content-type", "text/xml")], body).into_response()
}

/// `POST /` `Action=AssumeRoleWithWebIdentity`.
async fn fake_sts(
    State(fake): State<Arc<Fake>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if form.get("Action").map(String::as_str) != Some("AssumeRoleWithWebIdentity") {
        return sts_error(StatusCode::BAD_REQUEST, "InvalidAction");
    }
    let token = form.get("WebIdentityToken").cloned().unwrap_or_default();
    fake.sts_calls.lock().unwrap().push(StsCall {
        token: token.clone(),
        role_arn: form.get("RoleArn").cloned(),
        session_name: form.get("RoleSessionName").cloned(),
        duration_seconds: form.get("DurationSeconds").cloned(),
    });
    if !fake.valid_tokens.lock().unwrap().contains(&token) {
        return sts_error(StatusCode::BAD_REQUEST, "InvalidIdentityToken");
    }
    let lifetime = *fake.lifetime.lock().unwrap();
    let mut issued = fake.issued.lock().unwrap();
    let n = issued.len() + 1;
    let access_key = format!("ASIAFAKE{n:08}");
    let secret_key = format!("fake-secret-{n}");
    let session_token = format!("fake-session-{n}");
    let expiration = chrono::Utc::now() + lifetime;
    issued.insert(
        access_key.clone(),
        Issued {
            secret_key: secret_key.clone(),
            session_token: session_token.clone(),
            expires: Instant::now() + lifetime,
        },
    );
    let body = format!(
        "<AssumeRoleWithWebIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
         <AssumeRoleWithWebIdentityResult>\
         <Credentials><AccessKeyId>{access_key}</AccessKeyId>\
         <SecretAccessKey>{secret_key}</SecretAccessKey>\
         <SessionToken>{session_token}</SessionToken>\
         <Expiration>{}</Expiration></Credentials>\
         <SubjectFromWebIdentityToken>system:serviceaccount:forge:forge</SubjectFromWebIdentityToken>\
         <AssumedRoleUser><Arn>{ROLE}/forge</Arn><AssumedRoleId>AROAFAKE:forge</AssumedRoleId></AssumedRoleUser>\
         </AssumeRoleWithWebIdentityResult>\
         <ResponseMetadata><RequestId>fake</RequestId></ResponseMetadata>\
         </AssumeRoleWithWebIdentityResponse>",
        expiration.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
    );
    (StatusCode::OK, [("content-type", "text/xml")], body).into_response()
}

fn s3_error(status: StatusCode, code: &str) -> Response {
    let body = format!("<Error><Code>{code}</Code><Message>injected</Message></Error>");
    (status, [("content-type", "application/xml")], body).into_response()
}

/// The access key id of a SigV4 `Authorization` header.
fn access_key_of(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let credential = auth.split("Credential=").nth(1)?;
    Some(credential.split('/').next()?.to_string())
}

/// A path-style S3 bucket `fake` that accepts only keys the fake STS issued,
/// with their session token, while they are valid.
async fn fake_s3(
    State(fake): State<Arc<Fake>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(access_key) = access_key_of(&headers) else {
        return s3_error(StatusCode::FORBIDDEN, "AccessDenied");
    };
    {
        let issued = fake.issued.lock().unwrap();
        let Some(keys) = issued.get(&access_key) else {
            return s3_error(StatusCode::FORBIDDEN, "InvalidAccessKeyId");
        };
        assert!(!keys.secret_key.is_empty());
        let token = headers
            .get("x-amz-security-token")
            .and_then(|v| v.to_str().ok());
        // Static keys come without a session token.
        if token.unwrap_or_default() != keys.session_token {
            return s3_error(StatusCode::FORBIDDEN, "InvalidToken");
        }
        if Instant::now() >= keys.expires {
            return s3_error(StatusCode::BAD_REQUEST, "ExpiredToken");
        }
    }
    let query = uri.query().unwrap_or_default().to_string();
    let path = uri.path().trim_start_matches("/fake").to_string();
    let record = |what: &str| {
        fake.s3_requests
            .lock()
            .unwrap()
            .push((access_key.clone(), what.to_string()));
    };
    if method == Method::HEAD && (path.is_empty() || path == "/") {
        record("head_bucket");
        return StatusCode::OK.into_response();
    }
    if method == Method::HEAD {
        record("head_object");
        return match fake.objects.lock().unwrap().get(&path) {
            Some(bytes) => (
                StatusCode::OK,
                [("content-length", bytes.len().to_string())],
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    if method == Method::GET {
        record("get_object");
        return match fake.objects.lock().unwrap().get(&path) {
            Some(bytes) => (StatusCode::OK, bytes.clone()).into_response(),
            None => s3_error(StatusCode::NOT_FOUND, "NoSuchKey"),
        };
    }
    if method == Method::POST && query.contains("uploads") {
        record("create_multipart");
        fake.parts.lock().unwrap().clear();
        return (
            StatusCode::OK,
            [("content-type", "application/xml")],
            "<InitiateMultipartUploadResult><Bucket>fake</Bucket><Key>k</Key>\
             <UploadId>fake-upload</UploadId></InitiateMultipartUploadResult>",
        )
            .into_response();
    }
    if method == Method::PUT && query.contains("partNumber=") {
        record("upload_part");
        let number: i32 = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("partNumber="))
            .and_then(|n| n.parse().ok())
            .unwrap();
        let delay = *fake.part_delay.lock().unwrap();
        tokio::time::sleep(delay).await;
        fake.parts.lock().unwrap().insert(number, body.to_vec());
        return (StatusCode::OK, [("etag", format!("\"etag-{number}\""))]).into_response();
    }
    if method == Method::POST && query.contains("uploadId=") {
        record("complete_multipart");
        let mut parts: Vec<_> = fake.parts.lock().unwrap().drain().collect();
        parts.sort_by_key(|(n, _)| *n);
        let joined = parts.into_iter().flat_map(|(_, b)| b).collect();
        fake.objects.lock().unwrap().insert(path, joined);
        return (
            StatusCode::OK,
            [("content-type", "application/xml")],
            "<CompleteMultipartUploadResult><Bucket>fake</Bucket><Key>k</Key>\
             <ETag>\"etag\"</ETag></CompleteMultipartUploadResult>",
        )
            .into_response();
    }
    if method == Method::PUT {
        record("put_object");
        fake.objects.lock().unwrap().insert(path, body.to_vec());
        return StatusCode::OK.into_response();
    }
    if method == Method::DELETE {
        record("delete_object");
        fake.objects.lock().unwrap().remove(&path);
        return StatusCode::NO_CONTENT.into_response();
    }
    StatusCode::NOT_IMPLEMENTED.into_response()
}

struct Setup {
    fake: Arc<Fake>,
    s3: String,
    sts: String,
    token_file: tempfile::NamedTempFile,
}

/// The fakes, with STS accepting `token` (written to the token file) and
/// handing out keys valid for `lifetime`.
async fn setup(token: &str, lifetime: Duration) -> Setup {
    let fake = Arc::new(Fake::default());
    fake.valid_tokens.lock().unwrap().push(token.to_string());
    *fake.lifetime.lock().unwrap() = lifetime;
    let sts = serve(
        axum::Router::new()
            .route("/", axum::routing::post(fake_sts))
            .with_state(fake.clone()),
    )
    .await;
    let s3 = serve(
        axum::Router::new()
            .fallback(fake_s3)
            .layer(axum::extract::DefaultBodyLimit::disable())
            .with_state(fake.clone()),
    )
    .await;
    let token_file = tempfile::NamedTempFile::new().unwrap();
    // A trailing newline, as `echo` and Secret files write it.
    std::fs::write(token_file.path(), format!("{token}\n")).unwrap();
    Setup {
        fake,
        s3,
        sts,
        token_file,
    }
}

fn web_identity(setup: &Setup, role_arn: Option<&str>) -> WebIdentity {
    WebIdentity {
        role_arn: role_arn.map(str::to_string),
        token_file: setup.token_file.path().to_path_buf(),
        sts_endpoint: Some(setup.sts.clone()),
        session_name: "forge-test".into(),
        duration_seconds: Some(900),
    }
}

fn store(setup: &Setup, credentials: S3Credentials, multipart_threshold: u64) -> BlobStore {
    BlobStore::new(S3Config {
        endpoint: setup.s3.clone(),
        region: "eu-central-1".into(),
        bucket: "fake".into(),
        credentials,
        force_path_style: true,
        multipart_threshold,
        conditional_writes: ConditionalWrites::Off,
    })
}

async fn read_all(store: &BlobStore, key: &str) -> Vec<u8> {
    let mut got = Vec::new();
    store
        .get(key)
        .await
        .unwrap()
        .into_async_read()
        .read_to_end(&mut got)
        .await
        .unwrap();
    got
}

async fn file_with(bytes: &[u8]) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    tokio::fs::write(file.path(), bytes).await.unwrap();
    file
}

#[tokio::test]
async fn the_token_is_exchanged_once_and_the_keys_reused_while_valid() {
    let setup = setup("token-1", Duration::from_secs(3600)).await;
    let store = store(
        &setup,
        S3Credentials::WebIdentity(web_identity(&setup, Some(ROLE))),
        8 * 1024 * 1024,
    );

    store.ensure_bucket().await.unwrap();
    let body = file_with(b"hello web identity").await;
    assert!(store.put_if_absent("blobs/a", body.path()).await.unwrap());
    assert_eq!(read_all(&store, "blobs/a").await, b"hello web identity");
    store.ping().await.unwrap();

    let calls = setup.fake.sts_calls();
    assert_eq!(
        calls.len(),
        1,
        "one exchange for the whole session: {calls:?}"
    );
    let call = &calls[0];
    assert_eq!(call.token, "token-1", "the file's token, trimmed");
    assert_eq!(call.role_arn.as_deref(), Some(ROLE));
    assert_eq!(call.session_name.as_deref(), Some("forge-test"));
    assert_eq!(call.duration_seconds.as_deref(), Some("900"));
}

#[tokio::test]
async fn no_role_arn_is_sent_when_none_is_configured() {
    // MinIO's claim-based policies take no RoleArn.
    let setup = setup("token-1", Duration::from_secs(3600)).await;
    let store = store(
        &setup,
        S3Credentials::WebIdentity(web_identity(&setup, None)),
        8 * 1024 * 1024,
    );
    store.ping().await.unwrap();
    assert_eq!(setup.fake.sts_calls()[0].role_arn, None);
}

#[tokio::test]
async fn operations_keep_working_across_credential_expiry() {
    // Keys valid for one second: every one is about to expire when it is
    // issued, so each request needs new ones, and keys from a request before
    // the pause would be refused after it.
    let setup = setup("token-1", Duration::from_secs(1)).await;
    let store = store(
        &setup,
        S3Credentials::WebIdentity(web_identity(&setup, Some(ROLE))),
        8 * 1024 * 1024,
    );
    let body = file_with(b"across expiry").await;
    store.ensure_bucket().await.unwrap();
    assert!(store.put_if_absent("blobs/b", body.path()).await.unwrap());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(read_all(&store, "blobs/b").await, b"across expiry");
    assert!(!store.put_if_absent("blobs/b", body.path()).await.unwrap());
    store.delete("blobs/b").await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    store.ping().await.unwrap();

    // The fake S3 refused nothing; each request presented fresh keys.
    let calls = setup.fake.sts_calls().len();
    let requests = setup.fake.s3_requests.lock().unwrap().len();
    assert!(calls >= 2, "credentials were refreshed ({calls} fetches)");
    assert!(requests >= 6, "{requests} S3 requests");
}

#[tokio::test]
async fn a_multipart_upload_spanning_a_refresh_completes() {
    // Keys live long enough to sign and send an 8 MiB part (the fake checks
    // them once the whole part has arrived), even on a busy runner: hashing
    // it takes a debug build a few hundred milliseconds.
    let setup = setup("token-1", Duration::from_secs(3)).await;
    // Each part takes longer than the keys live: the keys the first part was
    // signed with have expired before the second part is sent.
    *setup.fake.part_delay.lock().unwrap() = Duration::from_millis(3200);
    let store = store(
        &setup,
        S3Credentials::WebIdentity(web_identity(&setup, Some(ROLE))),
        1,
    );
    // Three 8 MiB parts (the last one short).
    let body: Vec<u8> = (0..(17 * 1024 * 1024u32))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let file = file_with(&body).await;
    assert!(store.put_if_absent("blobs/big", file.path()).await.unwrap());

    let parts = setup.fake.s3_keys("upload_part");
    assert_eq!(parts.len(), 3, "{parts:?}");
    let complete = setup.fake.s3_keys("complete_multipart");
    assert_eq!(complete.len(), 1);
    let keys: std::collections::HashSet<_> = parts.iter().chain(&complete).collect();
    assert_eq!(keys.len(), 4, "every part signed with fresh keys: {keys:?}");
    assert_eq!(read_all(&store, "blobs/big").await, body);
}

#[tokio::test]
async fn every_fetch_reads_the_token_file_again() {
    let setup = setup("token-1", Duration::from_secs(1)).await;
    setup
        .fake
        .valid_tokens
        .lock()
        .unwrap()
        .push("token-2".into());
    let store = store(
        &setup,
        S3Credentials::WebIdentity(web_identity(&setup, Some(ROLE))),
        8 * 1024 * 1024,
    );
    store.ping().await.unwrap();
    // The kubelet rotates the projected token.
    std::fs::write(setup.token_file.path(), "token-2").unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    store.ping().await.unwrap();
    let tokens: Vec<String> = setup
        .fake
        .sts_calls()
        .into_iter()
        .map(|c| c.token)
        .collect();
    assert_eq!(tokens.first().map(String::as_str), Some("token-1"));
    assert_eq!(tokens.last().map(String::as_str), Some("token-2"));
}

#[tokio::test]
async fn a_rejected_token_fails_with_the_credential_source_named() {
    let setup = setup("the-accepted-token", Duration::from_secs(3600)).await;
    std::fs::write(setup.token_file.path(), "a-revoked-token-value").unwrap();
    let store = store(
        &setup,
        S3Credentials::WebIdentity(web_identity(&setup, Some(ROLE))),
        8 * 1024 * 1024,
    );
    let err = store
        .ensure_bucket()
        .await
        .expect_err("STS refuses the token");
    let shown = format!("{err} / {err:?}");
    assert!(!err.is_unavailable(), "a refusal is not an outage: {shown}");
    for part in ["web_identity", ROLE, &setup.sts, "InvalidIdentityToken"] {
        assert!(shown.contains(part), "{part} missing: {shown}");
    }
    assert!(!shown.contains("a-revoked-token-value"), "{shown}");
    let err = store.ping().await.expect_err("readiness fails too");
    assert!(err.to_string().contains("InvalidIdentityToken"), "{err}");
    assert!(
        setup.fake.s3_requests.lock().unwrap().is_empty(),
        "nothing reached S3"
    );
    assert_eq!(
        setup.fake.sts_calls().len(),
        2,
        "one exchange per call: the bucket check does not go on to create"
    );

    // A missing object is not mistaken for a missing token file.
    let missing = S3Credentials::WebIdentity(WebIdentity {
        token_file: Path::new("/nonexistent/forge/token").to_path_buf(),
        ..web_identity(&setup, Some(ROLE))
    });
    let err = store_with(&setup, missing)
        .head("blobs/x")
        .await
        .expect_err("no token file");
    assert!(
        err.to_string().contains("/nonexistent/forge/token"),
        "{err}"
    );
}

fn store_with(setup: &Setup, credentials: S3Credentials) -> BlobStore {
    store(setup, credentials, 8 * 1024 * 1024)
}

/// With the local blob cache, an STS that cannot be reached is an outage
/// (served from the cache, retried), while a refused token is not.
#[tokio::test]
async fn an_unreachable_sts_counts_as_s3_unavailable_with_the_cache() {
    let setup = setup("token-1", Duration::from_secs(3600)).await;
    let dir = tempfile::tempdir().unwrap();
    let cache = || {
        BlobCache::open(BlobCacheConfig {
            path: dir.path().to_path_buf(),
            max_bytes: CacheLimit::Bytes(1 << 20),
            min_free_bytes: Some(0),
            staging: None,
        })
        .unwrap()
    };

    let down = S3Credentials::WebIdentity(WebIdentity {
        // Nothing listens on port 1.
        sts_endpoint: Some("http://127.0.0.1:1".into()),
        ..web_identity(&setup, Some(ROLE))
    });
    let err = store_with(&setup, down)
        .with_cache(cache())
        .ensure_bucket()
        .await
        .expect_err("STS is down");
    assert!(err.is_unavailable(), "{err}");
    assert!(err.to_string().contains("web_identity"), "{err}");

    std::fs::write(setup.token_file.path(), "refused").unwrap();
    let refused = S3Credentials::WebIdentity(web_identity(&setup, Some(ROLE)));
    let err = store_with(&setup, refused)
        .with_cache(cache())
        .ensure_bucket()
        .await
        .expect_err("STS refuses");
    assert!(!err.is_unavailable(), "{err}");
}

#[tokio::test]
async fn static_keys_are_unchanged() {
    let setup = setup("unused", Duration::from_secs(3600)).await;
    // The fake S3 knows the static pair, without a session token.
    setup.fake.issued.lock().unwrap().insert(
        "AKIASTATIC".into(),
        Issued {
            secret_key: "static-secret".into(),
            session_token: String::new(),
            expires: Instant::now() + Duration::from_secs(3600),
        },
    );
    let store = store_with(
        &setup,
        S3Credentials::from_keys("AKIASTATIC", "static-secret"),
    );
    store.ping().await.unwrap();
    assert_eq!(setup.fake.s3_keys("head_bucket"), ["AKIASTATIC"]);
    assert!(
        setup.fake.sts_calls().is_empty(),
        "static keys never call STS"
    );
}
