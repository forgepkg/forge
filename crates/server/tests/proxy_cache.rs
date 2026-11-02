//! E2E: an administrator invalidates what a NuGet proxy cached from its
//! upstream (`POST /admin/repositories/{name}/proxy-cache/invalidate`), so a
//! package the upstream published after answering "not found" is served
//! before the not-found TTL runs out, and the upstream documents the proxy
//! stored for every instance are deleted (as they are when it is repointed
//! or deleted). Requires Docker (or `FORGE_TEST_DATABASE_URL` /
//! `FORGE_TEST_S3_ENDPOINT`).

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};

/// The upstream feed: a service index and a flat container listing `1.0.0`
/// of every id in [`Feed::published`], with an `ETag` it answers
/// `If-None-Match` with 304 for.
struct Feed {
    base: String,
    published: Mutex<HashSet<String>>,
    /// Service index requests.
    index_gets: AtomicUsize,
    /// The `If-None-Match` of every listing request, in order.
    listing_gets: Mutex<Vec<Option<String>>>,
}

async fn start_feed() -> Arc<Feed> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind feed");
    let feed = Arc::new(Feed {
        base: format!("http://{}", listener.local_addr().unwrap()),
        published: Mutex::new(HashSet::new()),
        index_gets: AtomicUsize::new(0),
        listing_gets: Mutex::default(),
    });
    let app = Router::new()
        .route("/index.json", get(feed_index))
        .route("/flat/{id}/index.json", get(feed_versions))
        .with_state(feed.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve feed");
    });
    feed
}

async fn feed_index(State(feed): State<Arc<Feed>>) -> Json<Value> {
    feed.index_gets.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "version": "3.0.0",
        "resources": [
            {"@id": format!("{}/flat/", feed.base), "@type": "PackageBaseAddress/3.0.0"},
        ],
    }))
}

async fn feed_versions(
    State(feed): State<Arc<Feed>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let asked = headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    feed.listing_gets.lock().unwrap().push(asked.clone());
    if !feed.published.lock().unwrap().contains(&id) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if asked.as_deref() == Some("\"1\"") {
        return (StatusCode::NOT_MODIFIED, [("etag", "\"1\"")]).into_response();
    }
    // The feed's URL keeps each test's listing (and its blob) its own.
    let body = json!({"versions": ["1.0.0"], "id": id, "feed": feed.base});
    (StatusCode::OK, [("etag", "\"1\"")], Json(body)).into_response()
}

#[tokio::test]
async fn invalidation_forgets_the_upstreams_not_found_answers() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let (proxy, hosted) = (format!("ncprox{s}"), format!("nchost{s}"));
    let feed = start_feed().await;
    for body in [
        json!({
            "name": proxy,
            "kind": "proxy",
            "remote_url": format!("{}/index.json", feed.base),
            "package_delay_seconds": 0,
            "metadata_ttl_seconds": 3600,
            "not_found_ttl_seconds": 3600,
        }),
        json!({"name": hosted, "kind": "hosted"}),
    ] {
        let resp = client
            .post(format!("{}/admin/repositories", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    }

    let versions = |id: &str| {
        let request = client
            .get(format!(
                "{}/repository/{proxy}/flat/{id}/index.json",
                srv.base_url
            ))
            .basic_auth(&u, Some(&p));
        async move {
            let resp = request.send().await.unwrap();
            match resp.status().as_u16() {
                404 => None,
                200 => Some(resp.json::<Value>().await.unwrap()["versions"].clone()),
                status => panic!("flat index: {status}"),
            }
        }
    };
    let invalidate = |body: Option<Value>| {
        let mut request = client
            .post(format!(
                "{}/admin/repositories/{proxy}/proxy-cache/invalidate",
                srv.base_url
            ))
            .basic_auth(&u, Some(&p));
        if let Some(body) = body {
            request = request.json(&body);
        }
        async move {
            let resp = request.send().await.unwrap();
            assert_eq!(resp.status(), 200);
            resp.json::<Value>().await.unwrap()
        }
    };

    // Both ids are unknown upstream; once published there, the proxy still
    // answers "not found" from its negative cache.
    assert_eq!(versions("late.pkg").await, None);
    assert_eq!(versions("other.pkg").await, None);
    feed.published
        .lock()
        .unwrap()
        .extend(["late.pkg".to_string(), "other.pkg".to_string()]);
    assert_eq!(versions("late.pkg").await, None);
    let index_gets = feed.index_gets.load(Ordering::SeqCst);

    // One package (any casing): only its answer is forgotten, and the
    // upstream index is kept.
    let body = invalidate(Some(json!({"package": "Late.Pkg"}))).await;
    assert_eq!(
        body,
        json!({"not_found_cleared": 1, "tags_expired": 0, "documents_dropped": 1}),
        "the service index's document"
    );
    assert_eq!(versions("late.pkg").await, Some(json!(["1.0.0"])));
    assert_eq!(versions("other.pkg").await, None);
    assert_eq!(feed.index_gets.load(Ordering::SeqCst), index_gets);

    // The whole repository (no body): every answer, and the upstream index
    // is fetched again.
    let body = invalidate(None).await;
    assert_eq!(body["not_found_cleared"], 1, "{body}");
    assert_eq!(versions("other.pkg").await, Some(json!(["1.0.0"])));
    assert_eq!(feed.index_gets.load(Ordering::SeqCst), index_gets + 1);

    // Only a proxy has a cache to invalidate, and the package is an id.
    let post = |repo: String, body: Value| {
        let request = client
            .post(format!(
                "{}/admin/repositories/{repo}/proxy-cache/invalidate",
                srv.base_url
            ))
            .basic_auth(&u, Some(&p))
            .json(&body);
        async move { request.send().await.unwrap().status().as_u16() }
    };
    assert_eq!(post(hosted.clone(), json!({})).await, 400);
    assert_eq!(post(format!("missing{s}"), json!({})).await, 404);
    assert_eq!(post(proxy.clone(), json!({"package": "a/../b"})).await, 400);
    assert_eq!(post(proxy.clone(), json!({"packages": ["x"]})).await, 422);
}

/// The proxy stores the upstream documents it fetched for every instance
/// (`proxy_document`, the bytes in the CAS). Invalidating its cache deletes
/// them and releases their blobs, so the upstream is asked again without the
/// stored validators; repointing and deleting the proxy delete them too.
#[tokio::test]
async fn invalidation_drops_the_stored_upstream_documents() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let proxy = format!("ncdocs{}", common::unique());
    let feed = start_feed().await;
    feed.published.lock().unwrap().insert("doc.pkg".to_string());
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": proxy,
            "kind": "proxy",
            "remote_url": format!("{}/index.json", feed.base),
            "package_delay_seconds": 0,
            "metadata_ttl_seconds": 3600,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let repo = forge_db::repository_dao::find_repository_by_name(&srv.pool, &proxy)
        .await
        .unwrap()
        .unwrap();
    let listing = || {
        let request = client
            .get(format!(
                "{}/repository/{proxy}/flat/doc.pkg/index.json",
                srv.base_url
            ))
            .basic_auth(&u, Some(&p));
        async move {
            let resp = request.send().await.unwrap();
            assert_eq!(resp.status(), 200);
            resp.json::<Value>().await.unwrap()["versions"].clone()
        }
    };
    let (pool, repo_id) = (srv.pool.clone(), repo.id);
    let stored = || {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (String, String)>(
                "SELECT url, blob_sha256 FROM proxy_document WHERE repository_id = $1 \
                 ORDER BY url",
            )
            .bind(repo_id)
            .fetch_all(&pool)
            .await
            .unwrap()
        }
    };
    // A released blob may be gone already, once the outbox deleted it.
    let ref_count = |sha256: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT ref_count FROM blob WHERE sha256 = $1")
                .bind(sha256)
                .fetch_optional(&pool)
                .await
                .unwrap()
                .unwrap_or(0)
        }
    };

    assert_eq!(listing().await, json!(["1.0.0"]));
    let docs = stored().await;
    assert_eq!(docs.len(), 2, "the service index and the listing: {docs:?}");
    let (_, listing_blob) = docs
        .iter()
        .find(|(url, _)| url.ends_with("/flat/doc.pkg/index.json"))
        .cloned()
        .unwrap();
    assert_eq!(ref_count(listing_blob.clone()).await, 1);

    let resp = client
        .post(format!(
            "{}/admin/repositories/{proxy}/proxy-cache/invalidate",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["documents_dropped"], 2, "{body}");
    assert!(stored().await.is_empty());
    assert_eq!(ref_count(listing_blob).await, 0, "the blob is released");

    // Asked again, and in full: nothing stored to revalidate.
    assert_eq!(listing().await, json!(["1.0.0"]));
    assert_eq!(
        feed.listing_gets.lock().unwrap().clone(),
        [None, None],
        "both listing requests unconditional"
    );
    assert_eq!(stored().await.len(), 2);

    // Repointed: the previous upstream's documents go.
    let resp = client
        .put(format!("{}/admin/repositories/{proxy}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"remote_url": format!("{}/index.json?moved", feed.base)}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    assert!(stored().await.is_empty());

    // Deleted: the documents it stored release their blobs first.
    assert_eq!(listing().await, json!(["1.0.0"]));
    let docs = stored().await;
    assert!(!docs.is_empty());
    let resp = client
        .delete(format!("{}/admin/repositories/{proxy}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    for (_, sha256) in docs {
        assert_eq!(ref_count(sha256).await, 0);
    }
}
