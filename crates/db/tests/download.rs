//! Integration tests for the best-effort download-tracking DAO
//! (`forge_db::download_dao`).
//!
//! Postgres only. Verifies the hosted bump increments the asset count + stamps
//! both asset and component timestamps, and that the proxy bump stamps the
//! cached-version row and mirrors onto a parallel cached component/asset.

mod common;

use forge_db::asset_dao::{self, NewAsset};
use forge_db::blob_dao;
use forge_db::component_dao::{self, NewComponent};
use forge_db::download_dao;
use forge_db::proxy_dao::{self, NewProxyCachedVersion};
use forge_db::repository_dao::{self, NewRepository};
use sqlx::PgPool;

use common::{pool, unique};

/// Seed a hosted component + its `.nupkg` asset (blob row not required: the
/// bump touches only `asset`/`component`). Returns `(component_id, asset_id)`.
async fn seed_component_asset(
    pool: &PgPool,
    repo_id: i64,
    name: &str,
    version: &str,
) -> (i64, i64) {
    let comp = component_dao::insert_component(
        pool,
        NewComponent {
            repository_id: repo_id,
            name: name.into(),
            original_id: name.into(),
            version: version.into(),
            version_original: version.into(),
            listed: true,
        },
    )
    .await
    .expect("insert component");
    let sha = format!("{:064x}", comp.id);
    blob_dao::upsert_pending(pool, &sha, 100, &format!("k/{sha}"))
        .await
        .expect("upsert blob");
    let mut tx = pool.begin().await.unwrap();
    blob_dao::commit_and_incref(&mut tx, &sha).await.unwrap();
    tx.commit().await.unwrap();
    let asset = asset_dao::insert_asset(
        pool,
        NewAsset {
            component_id: comp.id,
            path: format!("{name}.{version}.nupkg"),
            content_type: "application/octet-stream".into(),
            blob_sha256: sha,
            size: 100,
            sha512_base64: None,
        },
    )
    .await
    .expect("insert asset");
    (comp.id, asset.id)
}

async fn asset_count_and_ts(pool: &PgPool, asset_id: i64) -> (i64, bool) {
    sqlx::query_as::<_, (i64, bool)>(
        "SELECT download_count, last_downloaded_at IS NOT NULL FROM asset WHERE id = $1",
    )
    .bind(asset_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn component_ts_set(pool: &PgPool, component_id: i64) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT last_downloaded_at IS NOT NULL FROM component WHERE id = $1",
    )
    .bind(component_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn proxy_ts_set(pool: &PgPool, cached_id: i64) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT last_downloaded_at IS NOT NULL FROM proxy_cached_version WHERE id = $1",
    )
    .bind(cached_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn hosted_bump_increments_count_and_stamps_timestamps() {
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::hosted(format!("dh-{n}")))
        .await
        .unwrap();
    let (comp_id, asset_id) = seed_component_asset(&pool, repo.id, "lib", "1.0.0").await;

    // Before: count 0, both timestamps null.
    assert_eq!(asset_count_and_ts(&pool, asset_id).await, (0, false));
    assert!(!component_ts_set(&pool, comp_id).await);

    download_dao::bump_hosted_downloads(&pool, &[asset_id], &[comp_id], &[1])
        .await
        .expect("bump");

    assert_eq!(asset_count_and_ts(&pool, asset_id).await, (1, true));
    assert!(component_ts_set(&pool, comp_id).await);

    // A batch adds its counts: three more downloads make 4.
    download_dao::bump_hosted_downloads(&pool, &[asset_id], &[comp_id], &[3])
        .await
        .unwrap();
    assert_eq!(asset_count_and_ts(&pool, asset_id).await.0, 4);
}

#[tokio::test]
async fn proxy_bump_stamps_cached_row_and_mirrors_onto_component() {
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::proxy(format!("dp-{n}")))
        .await
        .unwrap();
    // Parallel cached component + asset (a downloaded proxy version).
    let (comp_id, asset_id) = seed_component_asset(&pool, repo.id, "lib", "2.0.0").await;
    proxy_dao::upsert_cached_version(
        &pool,
        NewProxyCachedVersion {
            repository_id: repo.id,
            name: "lib".into(),
            version: "2.0.0".into(),
            listed: true,
            downloaded: true,
            not_found: false,
        },
    )
    .await
    .unwrap();
    let cached = proxy_dao::get_cached_version(&pool, repo.id, "lib", "2.0.0")
        .await
        .unwrap()
        .unwrap();

    download_dao::bump_proxy_download(&pool, cached.id)
        .await
        .expect("bump proxy");

    assert!(proxy_ts_set(&pool, cached.id).await);
    // Mirrored onto the parallel component/asset.
    assert_eq!(asset_count_and_ts(&pool, asset_id).await, (1, true));
    assert!(component_ts_set(&pool, comp_id).await);
}

#[tokio::test]
async fn proxy_bump_by_name_stamps_cached_row_and_mirrors_onto_component() {
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::proxy(format!("dpn-{n}")))
        .await
        .unwrap();
    let (comp_id, asset_id) = seed_component_asset(&pool, repo.id, "lib", "3.0.0").await;
    proxy_dao::upsert_cached_version(
        &pool,
        NewProxyCachedVersion {
            repository_id: repo.id,
            name: "lib".into(),
            version: "3.0.0".into(),
            listed: true,
            downloaded: true,
            not_found: false,
        },
    )
    .await
    .unwrap();
    let cached = proxy_dao::get_cached_version(&pool, repo.id, "lib", "3.0.0")
        .await
        .unwrap()
        .unwrap();

    download_dao::bump_proxy_downloads_by_name(
        &pool,
        &[repo.id],
        &["lib".to_string()],
        &["3.0.0".to_string()],
        &[2],
    )
    .await
    .expect("bump by name");

    assert!(proxy_ts_set(&pool, cached.id).await);
    assert_eq!(asset_count_and_ts(&pool, asset_id).await, (2, true));
    assert!(component_ts_set(&pool, comp_id).await);
}

#[tokio::test]
async fn proxy_bump_without_cached_component_only_stamps_cached_row() {
    // A metadata-only cached version (never downloaded bytes) has no parallel
    // component; the bump must still stamp the cached row and not error.
    let pool = pool().await;
    let n = unique();
    let repo = repository_dao::insert_repository(&pool, NewRepository::proxy(format!("dpm-{n}")))
        .await
        .unwrap();
    proxy_dao::upsert_cached_version(
        &pool,
        NewProxyCachedVersion {
            repository_id: repo.id,
            name: "meta".into(),
            version: "1.0.0".into(),
            listed: true,
            downloaded: false,
            not_found: false,
        },
    )
    .await
    .unwrap();
    let cached = proxy_dao::get_cached_version(&pool, repo.id, "meta", "1.0.0")
        .await
        .unwrap()
        .unwrap();

    download_dao::bump_proxy_download(&pool, cached.id)
        .await
        .expect("bump proxy (no component)");

    assert!(proxy_ts_set(&pool, cached.id).await);
}
