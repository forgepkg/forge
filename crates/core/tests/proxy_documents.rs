//! Integration tests for the upstream documents a proxy stores
//! (`proxy_document`, their bytes in the CAS) and revalidates.
//!
//! Drives [`forge_core::repo::proxy::ProxyRepo`] against real Postgres +
//! versitygw containers and an in-process NuGet feed whose version listings
//! carry an `ETag` and answer `If-None-Match` with `304 Not Modified`:
//!
//! * **shared** — instances with caches of their own (or a restarted one)
//!   read the document one of them fetched, without asking the upstream;
//! * **revalidated** — past the metadata TTL the upstream is asked with the
//!   stored `ETag`, and a 304 serves the stored copy without a download; a
//!   changed document replaces it and releases the old blob;
//! * **scoped** — a document is served without asking only while the
//!   repository has the `remote_url` and `updated_at` it was fetched under,
//!   and its validators go to that `remote_url` only;
//! * **dropped** — one the upstream no longer has is deleted, a search's
//!   pages are never stored, and the reconciler's pass removes the documents
//!   nobody read.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use forge_cache::Cache;
use forge_core::repo::proxy::ProxyRepo;
use forge_core::repo::RepoReadOps;
use forge_db::repository_dao::{self, NewRepository};
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::net::TcpListener;

fn nuget() -> forge_core::format::SpecFormat {
    forge_core::format::SpecFormat::new(std::sync::Arc::new(forge_format_nuget::Nuget::default()))
}

// ── An upstream feed with conditional listings ──────────────────────────────

struct FeedState {
    base: String,
    /// `lower_id -> versions`; the listing's `ETag` is its generation.
    packages: Mutex<HashMap<String, (Vec<String>, u64)>>,
    /// Listings sent in full (200).
    listings_sent: AtomicUsize,
    /// Listings answered `304 Not Modified`.
    listings_not_modified: AtomicUsize,
    /// The `If-None-Match` of every listing request, in order.
    if_none_match: Mutex<Vec<Option<String>>>,
    searches: AtomicUsize,
}

struct Feed {
    state: Arc<FeedState>,
    _task: tokio::task::JoinHandle<()>,
}

impl Feed {
    async fn start() -> Feed {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind feed");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(FeedState {
            base,
            packages: Mutex::default(),
            listings_sent: AtomicUsize::new(0),
            listings_not_modified: AtomicUsize::new(0),
            if_none_match: Mutex::default(),
            searches: AtomicUsize::new(0),
        });
        let app = Router::new()
            .route("/index.json", get(serve_index))
            .route("/flat/{id}/index.json", get(serve_listing))
            .route("/query", get(serve_search))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve feed");
        });
        Feed { state, _task: task }
    }

    fn index_url(&self) -> String {
        format!("{}/index.json", self.state.base)
    }

    /// Publish `version` of `id`: its listing changes (a new `ETag`).
    fn publish(&self, id: &str, version: &str) {
        let mut packages = self.state.packages.lock().unwrap();
        let (versions, generation) = packages.entry(id.to_string()).or_default();
        versions.push(version.to_string());
        *generation += 1;
    }

    fn unpublish_all(&self, id: &str) {
        self.state.packages.lock().unwrap().remove(id);
    }

    fn sent(&self) -> usize {
        self.state.listings_sent.load(Ordering::SeqCst)
    }

    fn not_modified(&self) -> usize {
        self.state.listings_not_modified.load(Ordering::SeqCst)
    }

    fn last_if_none_match(&self) -> Option<String> {
        self.state
            .if_none_match
            .lock()
            .unwrap()
            .last()
            .cloned()
            .flatten()
    }
}

async fn serve_index(State(feed): State<Arc<FeedState>>) -> Json<Value> {
    Json(json!({
        "version": "3.0.0",
        "resources": [
            {"@id": format!("{}/flat/", feed.base), "@type": "PackageBaseAddress/3.0.0"},
            {"@id": format!("{}/query", feed.base), "@type": "SearchQueryService/3.5.0"},
        ],
    }))
}

async fn serve_listing(
    State(feed): State<Arc<FeedState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let asked = headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    feed.if_none_match.lock().unwrap().push(asked.clone());
    let Some((versions, generation)) = feed.packages.lock().unwrap().get(&id).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = format!("\"{id}-{generation}\"");
    if asked.as_deref() == Some(etag.as_str()) {
        feed.listings_not_modified.fetch_add(1, Ordering::SeqCst);
        return (StatusCode::NOT_MODIFIED, [("etag", etag)]).into_response();
    }
    feed.listings_sent.fetch_add(1, Ordering::SeqCst);
    // The id and the feed's URL keep each listing (and its blob) its own.
    let body = json!({"versions": versions, "id": id, "feed": feed.base});
    (StatusCode::OK, [("etag", etag)], Json(body)).into_response()
}

async fn serve_search(State(feed): State<Arc<FeedState>>) -> Json<Value> {
    feed.searches.fetch_add(1, Ordering::SeqCst);
    Json(json!({"totalHits": 0, "data": [], "feed": feed.base}))
}

// ── Fixtures ────────────────────────────────────────────────────────────────

async fn make_proxy(pool: &PgPool, remote_url: &str) -> forge_db::model::Repository {
    let mut new = NewRepository::proxy(format!("docproxy{}", common::unique()));
    new.remote_url = Some(remote_url.to_string());
    new.package_delay_seconds = 0;
    new.metadata_ttl_seconds = Some(600);
    new.not_found_ttl_seconds = Some(600);
    repository_dao::insert_repository(pool, new)
        .await
        .expect("insert proxy repository")
}

/// An instance of the proxy: the shared database and object store, with a
/// local cache of its own.
fn instance(pool: &PgPool, cas: &forge_storage::Cas) -> ProxyRepo {
    ProxyRepo::new(
        pool.clone(),
        Arc::new(nuget()),
        cas.clone(),
        Cache::l1_only(128),
        common::envelope(pool),
    )
    .with_delete_grace(chrono::Duration::zero())
}

async fn versions(px: &ProxyRepo, repo: &str, id: &str) -> Vec<String> {
    px.list_versions(repo, id)
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.version)
        .collect()
}

/// The stored documents of `repository_id`: URL, the blob, its reference
/// count, and seconds since the upstream last sent or confirmed it.
async fn stored(pool: &PgPool, repository_id: i64) -> Vec<(String, String, i64, f64)> {
    sqlx::query_as(
        "SELECT d.url, d.blob_sha256, b.ref_count, \
                extract(epoch FROM now() - d.fetched_at)::float8 \
         FROM proxy_document d JOIN blob b ON b.sha256 = d.blob_sha256 \
         WHERE d.repository_id = $1 ORDER BY d.url",
    )
    .bind(repository_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The stored listing of `id`, if any.
async fn stored_listing(
    pool: &PgPool,
    repository_id: i64,
    id: &str,
) -> Option<(String, String, i64, f64)> {
    stored(pool, repository_id)
        .await
        .into_iter()
        .find(|(url, ..)| url.ends_with(&format!("/flat/{id}/index.json")))
}

/// The metadata TTL of every stored document of `repository_id` passes.
async fn age(pool: &PgPool, repository_id: i64) {
    sqlx::query(
        "UPDATE proxy_document SET fetched_at = now() - interval '1 hour' \
         WHERE repository_id = $1",
    )
    .bind(repository_id)
    .execute(pool)
    .await
    .unwrap();
}

async fn ref_count(pool: &PgPool, sha256: &str) -> i64 {
    sqlx::query_scalar("SELECT ref_count FROM blob WHERE sha256 = $1")
        .bind(sha256)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn delete_enqueued(pool: &PgPool, sha256: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM blob_outbox WHERE sha256 = $1 AND processed_at IS NULL)",
    )
    .bind(sha256)
    .fetch_one(pool)
    .await
    .unwrap()
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Two instances, each with a cache of its own, and a restarted one: the
/// document the first fetched is stored once and read by the others,
/// without asking the upstream.
#[tokio::test]
async fn instances_share_one_stored_document() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let feed = Feed::start().await;
    feed.publish("sample.lib", "1.0.0");
    feed.publish("sample.lib", "1.1.0");
    let repo = make_proxy(&pool, &feed.index_url()).await;

    let (first, second) = (instance(&pool, &cas), instance(&pool, &cas));
    assert_eq!(
        versions(&first, &repo.name, "sample.lib").await,
        ["1.0.0", "1.1.0"]
    );
    assert_eq!(feed.sent(), 1);
    assert_eq!(
        versions(&second, &repo.name, "sample.lib").await,
        ["1.0.0", "1.1.0"]
    );
    let restarted = instance(&pool, &cas);
    assert_eq!(
        versions(&restarted, &repo.name, "sample.lib").await,
        ["1.0.0", "1.1.0"]
    );
    assert_eq!(
        feed.sent(),
        1,
        "the other instances read the stored listing"
    );
    assert_eq!(feed.not_modified(), 0, "nor did they revalidate it");

    // The service index and the listing, each stored once, each holding a
    // reference to its blob.
    let docs = stored(&pool, repo.id).await;
    let urls: Vec<&str> = docs.iter().map(|(url, ..)| url.as_str()).collect();
    assert_eq!(
        urls,
        [
            format!("{}/flat/sample.lib/index.json", feed.state.base),
            feed.index_url(),
        ]
    );
    assert!(docs.iter().all(|(_, _, refs, _)| *refs == 1), "{docs:?}");
}

/// Past the metadata TTL the upstream is asked with the stored `ETag`: a
/// 304 serves the stored copy and restarts its TTL without a download; a
/// changed listing is downloaded and replaces it, releasing the old blob.
#[tokio::test]
async fn an_expired_document_is_revalidated_without_a_download() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let feed = Feed::start().await;
    feed.publish("sample.lib", "1.0.0");
    let repo = make_proxy(&pool, &feed.index_url()).await;

    assert_eq!(
        versions(&instance(&pool, &cas), &repo.name, "sample.lib").await,
        ["1.0.0"]
    );
    assert_eq!(feed.sent(), 1);
    let (_, blob, _, _) = stored_listing(&pool, repo.id, "sample.lib").await.unwrap();

    age(&pool, repo.id).await;
    assert_eq!(
        versions(&instance(&pool, &cas), &repo.name, "sample.lib").await,
        ["1.0.0"]
    );
    assert_eq!(feed.not_modified(), 1, "asked whether it changed");
    assert_eq!(feed.sent(), 1, "and downloaded nothing");
    assert_eq!(
        feed.last_if_none_match().as_deref(),
        Some("\"sample.lib-1\"")
    );
    let (_, same, _, age_seconds) = stored_listing(&pool, repo.id, "sample.lib").await.unwrap();
    assert_eq!(same, blob);
    assert!(
        age_seconds < 60.0,
        "the 304 restarted its TTL: {age_seconds}"
    );
    // Fresh again: the next instance does not ask.
    versions(&instance(&pool, &cas), &repo.name, "sample.lib").await;
    assert_eq!(feed.not_modified(), 1);

    // The upstream publishes: the listing changed.
    feed.publish("sample.lib", "2.0.0");
    age(&pool, repo.id).await;
    assert_eq!(
        versions(&instance(&pool, &cas), &repo.name, "sample.lib").await,
        ["1.0.0", "2.0.0"]
    );
    assert_eq!(feed.sent(), 2);
    let (_, replaced, refs, _) = stored_listing(&pool, repo.id, "sample.lib").await.unwrap();
    assert_ne!(replaced, blob);
    assert_eq!(refs, 1);
    assert_eq!(ref_count(&pool, &blob).await, 0, "the old listing's blob");
    assert!(delete_enqueued(&pool, &blob).await);
}

/// A document is served without asking only while the repository has the
/// `updated_at` it was fetched under (an edit has it revalidated), and its
/// validators go only to the `remote_url` it came from: a listing stored
/// for the previous `remote_url` (fetched while the proxy was repointed) is
/// not used, even at the same URL.
#[tokio::test]
async fn a_stored_document_stands_for_the_upstream_it_came_from() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let feed = Feed::start().await;
    feed.publish("sample.lib", "1.0.0");
    let repo = make_proxy(&pool, &feed.index_url()).await;
    versions(&instance(&pool, &cas), &repo.name, "sample.lib").await;
    assert_eq!(feed.sent(), 1);

    // An edit of the repository (its name, a TTL) bumps `updated_at`.
    sqlx::query("UPDATE repository SET updated_at = now() WHERE id = $1")
        .bind(repo.id)
        .execute(&pool)
        .await
        .unwrap();
    versions(&instance(&pool, &cas), &repo.name, "sample.lib").await;
    assert_eq!(feed.not_modified(), 1, "revalidated after the edit");
    assert_eq!(feed.sent(), 1);

    // Repointed to another `remote_url` whose index names the same listing
    // URL; the stored documents are left behind, as a fetch from the
    // previous upstream still under way would leave its own.
    sqlx::query("UPDATE repository SET remote_url = $2, updated_at = now() WHERE id = $1")
        .bind(repo.id)
        .bind(format!("{}?repointed", feed.index_url()))
        .execute(&pool)
        .await
        .unwrap();
    versions(&instance(&pool, &cas), &repo.name, "sample.lib").await;
    assert_eq!(feed.sent(), 2, "the listing is downloaded again");
    assert_eq!(feed.not_modified(), 1);
    assert_eq!(
        feed.last_if_none_match(),
        None,
        "without the validators stored for the previous remote_url"
    );
    let remote: String = sqlx::query_scalar(
        "SELECT remote_url FROM proxy_document WHERE repository_id = $1 AND url LIKE '%/flat/%'",
    )
    .bind(repo.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(remote.ends_with("?repointed"), "{remote}");
}

/// A listing the upstream no longer has is deleted with its blob reference;
/// a search's pages are never stored.
#[tokio::test]
async fn documents_the_upstream_no_longer_has_or_searches_are_not_kept() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let feed = Feed::start().await;
    feed.publish("gone.lib", "1.0.0");
    let repo = make_proxy(&pool, &feed.index_url()).await;
    let px = instance(&pool, &cas);
    versions(&px, &repo.name, "gone.lib").await;
    let (_, blob, _, _) = stored_listing(&pool, repo.id, "gone.lib").await.unwrap();

    feed.unpublish_all("gone.lib");
    age(&pool, repo.id).await;
    versions(&instance(&pool, &cas), &repo.name, "gone.lib").await;
    assert_eq!(stored_listing(&pool, repo.id, "gone.lib").await, None);
    assert_eq!(ref_count(&pool, &blob).await, 0);

    px.search(
        &repo.name,
        &forge_core::repo::SearchParams {
            q: "anything".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(feed.state.searches.load(Ordering::SeqCst), 1);
    let urls: Vec<String> = stored(&pool, repo.id)
        .await
        .into_iter()
        .map(|(url, ..)| url)
        .collect();
    assert!(urls.iter().all(|url| !url.contains("/query")), "{urls:?}");
}

/// The reconciler's pass removes the documents nobody read for a week,
/// releasing their blobs; reading one marks it used.
#[tokio::test]
async fn unused_documents_are_pruned() {
    let pool = common::pool().await;
    let cas = common::cas(&pool).await;
    let feed = Feed::start().await;
    feed.publish("idle.lib", "1.0.0");
    feed.publish("busy.lib", "1.0.0");
    let repo = make_proxy(&pool, &feed.index_url()).await;
    let px = instance(&pool, &cas);
    versions(&px, &repo.name, "idle.lib").await;
    versions(&px, &repo.name, "busy.lib").await;
    sqlx::query(
        "UPDATE proxy_document SET used_at = now() - interval '8 days' WHERE repository_id = $1",
    )
    .bind(repo.id)
    .execute(&pool)
    .await
    .unwrap();
    // Read again (by another instance): marked used.
    versions(&instance(&pool, &cas), &repo.name, "busy.lib").await;
    let (_, idle, _, _) = stored_listing(&pool, repo.id, "idle.lib").await.unwrap();

    let pruned = forge_db::proxy_document_dao::prune_unused(
        &pool,
        chrono::Duration::seconds(forge_core::repo::proxy::UNUSED_DOCUMENT_SECONDS),
        1000,
        chrono::Duration::zero(),
    )
    .await
    .unwrap();
    assert!(
        pruned >= 2,
        "the idle listing and the service index: {pruned}"
    );
    assert_eq!(stored_listing(&pool, repo.id, "idle.lib").await, None);
    assert!(stored_listing(&pool, repo.id, "busy.lib").await.is_some());
    assert_eq!(ref_count(&pool, &idle).await, 0);
    assert!(delete_enqueued(&pool, &idle).await);
}
