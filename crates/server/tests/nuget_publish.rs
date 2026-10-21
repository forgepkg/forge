//! NuGet's publish endpoints end to end, now that the NuGet plugin
//! (`plugins/nuget`) routes them and the host's plugin dispatcher streams the
//! upload: multipart framing, the upload limit, unlist and relist, and the
//! answers for a method a path does not take.

mod common;

use common::{start_with, unique, ServerOpts, TestServer};
use reqwest::StatusCode;
use serde_json::{json, Value};

const BOUNDARY: &str = "TESTBOUNDARY1234";

async fn hosted_repo(srv: &TestServer) -> String {
    let (u, p) = srv.admin_basic();
    let repo = format!("nupub{}", unique());
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": repo, "kind": "hosted", "allow_redeploy": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    repo
}

/// A `multipart/form-data` body: `preamble`, then one part holding `package`.
fn multipart_body(preamble: &[u8], package: &[u8]) -> Vec<u8> {
    let mut body = preamble.to_vec();
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"package\"; filename=\"p.nupkg\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(package);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn push(srv: &TestServer, repo: &str, body: reqwest::Body) -> reqwest::Response {
    srv.client()
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", srv.admin_token().await)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(body)
        .send()
        .await
        .unwrap()
}

async fn versions(srv: &TestServer, repo: &str, lower: &str) -> (StatusCode, Value) {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!(
            "{}/v3/{repo}/flat/{lower}/index.json",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The multipart parser buffers everything before the first part in memory:
/// a body that does not reach its first part's headers within 64 KiB is
/// refused, and nothing is stored. A short preamble is fine.
#[tokio::test]
async fn push_with_an_oversized_multipart_preamble_is_refused() {
    let srv = common::start().await;
    let repo = hosted_repo(&srv).await;
    let id = format!("Pre.Amble{}", unique());
    let lower = id.to_lowercase();
    let nupkg = common::make_nupkg(&id, "1.0.0");

    let mut preamble = vec![b'x'; 1024 * 1024];
    preamble.extend_from_slice(b"\r\n");
    let resp = push(&srv, &repo, multipart_body(&preamble, &nupkg).into()).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.text().await.unwrap(),
        "multipart body: no package part within the first 64 KiB"
    );
    assert_eq!(versions(&srv, &repo, &lower).await.0, StatusCode::NOT_FOUND);

    let resp = push(&srv, &repo, multipart_body(b"preamble\r\n", &nupkg).into()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        versions(&srv, &repo, &lower).await,
        (StatusCode::OK, json!({"versions": ["1.0.0"]}))
    );
}

/// The preamble guard finds the boundary and the part headers when they are
/// split across chunks, down to one byte per chunk.
#[tokio::test]
async fn push_trickled_byte_by_byte_is_accepted() {
    let srv = common::start().await;
    let repo = hosted_repo(&srv).await;
    let id = format!("Trick.Le{}", unique());
    let lower = id.to_lowercase();
    let body = multipart_body(b"preamble\r\n", &common::make_nupkg(&id, "1.0.0"));
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        body.into_iter().map(|b| Ok(vec![b])).collect();

    let resp = push(
        &srv,
        &repo,
        reqwest::Body::wrap_stream(futures_util::stream::iter(chunks)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        versions(&srv, &repo, &lower).await,
        (StatusCode::OK, json!({"versions": ["1.0.0"]}))
    );
}

/// An upload past the repository's limit is refused with 413 and stores
/// nothing; the limit is set and cleared through the admin API, live.
#[tokio::test]
async fn push_over_the_repository_upload_limit_is_413() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let repo = hosted_repo(&srv).await;
    let set_limit = |limit: Value| {
        srv.client()
            .put(format!("{}/admin/repositories/{repo}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&json!({ "max_upload_bytes": limit }))
            .send()
    };
    let resp = set_limit(json!(4096)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: Value = resp.json().await.unwrap();
    assert_eq!(view["max_upload_bytes"], 4096);

    let id = format!("Too.Large{}", unique());
    let nupkg = common::make_nupkg_with_payload(&id, "1.0.0", 64 * 1024);
    let resp = push(&srv, &repo, multipart_body(b"", &nupkg).into()).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        resp.text().await.unwrap(),
        "upload exceeds limit of 4096 bytes"
    );
    assert_eq!(
        versions(&srv, &repo, &id.to_lowercase()).await.0,
        StatusCode::NOT_FOUND
    );

    // Cleared, the format's default (512 MiB) applies again.
    let resp = set_limit(Value::Null).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: Value = resp.json().await.unwrap();
    assert_eq!(view["max_upload_bytes"], Value::Null);
    let resp = push(&srv, &repo, multipart_body(b"", &nupkg).into()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// The deprecated `server.max_upload_bytes` is still the default of a
/// repository without a limit of its own, and a repository's limit
/// replaces it, larger or smaller.
#[tokio::test]
async fn the_deprecated_server_limit_is_only_a_default() {
    let srv = start_with(
        common::fresh_pool().await,
        ServerOpts {
            server_extra: Some("max_upload_bytes = 4096".into()),
            ..ServerOpts::default()
        },
    )
    .await;
    let (u, p) = srv.admin_basic();
    let id = format!("Legacy.Limit{}", unique());
    let nupkg = common::make_nupkg_with_payload(&id, "1.0.0", 64 * 1024);

    let defaulted = hosted_repo(&srv).await;
    let resp = push(&srv, &defaulted, multipart_body(b"", &nupkg).into()).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let own = format!("nupub{}", unique());
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({ "name": own, "kind": "hosted", "max_upload_bytes": 1048576 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = push(&srv, &own, multipart_body(b"", &nupkg).into()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// A repository upload limit is validated: hosted repositories only, more
/// than 0, and no larger than a push can be staged; `/admin/formats` names
/// the defaults and that ceiling.
#[tokio::test]
async fn repository_upload_limits_are_validated() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let create = |body: Value| {
        srv.client()
            .post(format!("{}/admin/repositories", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
    };
    let formats: Value = srv
        .client()
        .get(format!("{}/admin/formats", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nuget = &formats[0];
    assert_eq!(nuget["id"], "nuget");
    assert_eq!(nuget["default_max_upload_bytes"], 512 * 1024 * 1024);
    let docker = formats
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "docker")
        .unwrap();
    assert_eq!(docker["default_max_upload_bytes"], 1024 * 1024 * 1024);
    let ceiling = nuget["max_upload_bytes_limit"].as_u64().expect("bounded");
    assert_eq!(docker["max_upload_bytes_limit"], ceiling);

    for (body, message) in [
        (
            json!({ "name": format!("z{}", unique()), "kind": "hosted", "max_upload_bytes": 0 }),
            "greater than 0",
        ),
        (
            json!({ "name": format!("z{}", unique()), "kind": "hosted",
                    "max_upload_bytes": ceiling + 1 }),
            "server.max_staging_bytes",
        ),
        (
            json!({ "name": format!("z{}", unique()), "kind": "group", "max_upload_bytes": 4096 }),
            "only valid for hosted repositories",
        ),
    ] {
        let resp = create(body.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
        assert!(resp.text().await.unwrap().contains(message), "{body}");
    }
    let name = format!("z{}", unique());
    let resp = create(json!({ "name": name, "kind": "hosted", "max_upload_bytes": ceiling }))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let view: Value = resp.json().await.unwrap();
    assert_eq!(view["max_upload_bytes"], ceiling);
}

/// NuGet pushes are `multipart/form-data`; a bare body is refused.
#[tokio::test]
async fn push_that_is_not_multipart_is_400() {
    let srv = common::start().await;
    let repo = hosted_repo(&srv).await;
    let id = format!("Not.Multi{}", unique());
    let resp = srv
        .client()
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", srv.admin_token().await)
        .header("content-type", "application/octet-stream")
        .body(common::make_nupkg(&id, "1.0.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Pushing a version that exists, with redeploy off, is a conflict.
#[tokio::test]
async fn push_of_an_existing_version_is_409() {
    let srv = common::start().await;
    let repo = hosted_repo(&srv).await;
    let id = format!("Twi.Ce{}", unique());
    let nupkg = common::make_nupkg(&id, "1.0.0");

    let resp = push(&srv, &repo, multipart_body(b"", &nupkg).into()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = push(&srv, &repo, multipart_body(b"", &nupkg).into()).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        resp.text().await.unwrap(),
        format!("package {id} 1.0.0 already exists")
    );
}

async fn listed(srv: &TestServer, repo: &str, lower: &str) -> Value {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!(
            "{}/v3/{repo}/registration/{lower}/index.json",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    body["items"][0]["items"][0]["catalogEntry"]["listed"].clone()
}

async fn change(
    srv: &TestServer,
    key: &str,
    method: reqwest::Method,
    repo: &str,
    id: &str,
    version: &str,
) -> StatusCode {
    srv.client()
        .request(
            method,
            format!("{}/v3/{repo}/package/{id}/{version}", srv.base_url),
        )
        .header("X-NuGet-ApiKey", key)
        .send()
        .await
        .unwrap()
        .status()
}

/// `DELETE /package/{id}/{version}` unlists (204), `POST` relists (200); an
/// unknown version answers 404 to both. The registration follows.
#[tokio::test]
async fn unlist_and_relist() {
    use reqwest::Method;

    let srv = common::start().await;
    let key = srv.admin_token().await;
    let repo = hosted_repo(&srv).await;
    let id = format!("Un.List{}", unique());
    let lower = id.to_lowercase();
    let resp = push(
        &srv,
        &repo,
        multipart_body(b"", &common::make_nupkg(&id, "1.0.0")).into(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(listed(&srv, &repo, &lower).await, json!(true));

    let unlist = change(&srv, &key, Method::DELETE, &repo, &id, "1.0.0").await;
    assert_eq!(unlist, StatusCode::NO_CONTENT);
    assert_eq!(listed(&srv, &repo, &lower).await, json!(false));
    let unknown = change(&srv, &key, Method::DELETE, &repo, &id, "9.9.9").await;
    assert_eq!(unknown, StatusCode::NOT_FOUND);

    let relist = change(&srv, &key, Method::POST, &repo, &id, "1.0.0").await;
    assert_eq!(relist, StatusCode::OK);
    assert_eq!(listed(&srv, &repo, &lower).await, json!(true));
    let unknown = change(&srv, &key, Method::POST, &repo, &id, "9.9.9").await;
    assert_eq!(unknown, StatusCode::NOT_FOUND);

    // Unlisting keeps the version restorable.
    assert_eq!(
        versions(&srv, &repo, &lower).await,
        (StatusCode::OK, json!({"versions": ["1.0.0"]}))
    );
}

/// A path answers a method it does not take with 405 and its `Allow`
/// header; an unknown path is a 404.
#[tokio::test]
async fn a_method_a_path_does_not_take_is_405_with_allow() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let key = srv.admin_token().await;
    let repo = hosted_repo(&srv).await;
    let client = srv.client();

    let resp = client
        .post(format!("{}/v3/{repo}/index.json", srv.base_url))
        .header("X-NuGet-ApiKey", &key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(resp.headers()["allow"], "GET,HEAD");

    let resp = client
        .get(format!("{}/v3/{repo}/package", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(resp.headers()["allow"], "PUT");

    let resp = client
        .get(format!("{}/v3/{repo}/no/such/path", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
