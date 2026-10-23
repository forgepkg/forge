//! `raw_dao` against a real Postgres: storing, redeploying and deleting
//! files with their blob references, and walking directory listings.

mod common;

use chrono::{Duration, Utc};
use forge_db::blob_dao::{self, BeginIngestOutcome};
use forge_db::raw_dao::{self, NewRawFile, Redeploy, StoreOutcome};
use forge_db::repository_dao::{self, NewRepository};
use sqlx::PgPool;
use uuid::Uuid;

use common::{pool, unique};

async fn repo(pool: &PgPool) -> i64 {
    let name = format!("raw-{}", unique());
    repository_dao::insert_repository(pool, NewRepository::hosted(&name))
        .await
        .expect("insert repository")
        .id
}

/// A pending blob of unique content and its ingest lease.
async fn ingest(pool: &PgPool) -> (String, Uuid) {
    let sha = format!(
        "{:032x}{:032x}",
        Uuid::new_v4().as_u128(),
        Uuid::new_v4().as_u128()
    );
    let outcome = blob_dao::begin_ingest(
        pool,
        &sha,
        3,
        &format!("blobs/{sha}"),
        Utc::now() + Duration::hours(1),
        Utc::now() - Duration::minutes(1),
    )
    .await
    .expect("begin ingest");
    match outcome {
        BeginIngestOutcome::Ready { token, .. } => (sha, token),
        _ => panic!("unexpected ingest outcome"),
    }
}

fn file<'a>(path: &'a str, sha: &'a str) -> NewRawFile<'a> {
    NewRawFile {
        path,
        sha256: sha,
        size: 3,
        content_type: "application/octet-stream",
        sha512_base64: "sha512",
        sha1: "sha1",
        md5: "md5",
        upstream_etag: None,
        upstream_last_modified: None,
        checked: false,
    }
}

async fn store(
    pool: &PgPool,
    repo: i64,
    path: &str,
    sha: &str,
    token: Uuid,
    redeploy: Redeploy,
) -> StoreOutcome {
    let mut tx = pool.begin().await.unwrap();
    let outcome = raw_dao::store(
        &mut tx,
        repo,
        &file(path, sha),
        token,
        redeploy,
        Duration::zero(),
    )
    .await
    .expect("store");
    tx.commit().await.unwrap();
    outcome
}

async fn ref_count(pool: &PgPool, sha: &str) -> i64 {
    sqlx::query_scalar("SELECT ref_count FROM blob WHERE sha256 = $1")
        .bind(sha)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn store_takes_one_reference_per_path_and_redeploy_moves_it() {
    let pool = pool().await;
    let repo = repo(&pool).await;
    let (a, token) = ingest(&pool).await;
    assert!(matches!(
        store(&pool, repo, "dir/x.bin", &a, token, Redeploy::Deny).await,
        StoreOutcome::Created(_)
    ));
    assert_eq!(ref_count(&pool, &a).await, 1);

    // The same content again: nothing changes, whatever the policy.
    let token = ingest_existing(&pool, &a).await;
    assert!(matches!(
        store(&pool, repo, "dir/x.bin", &a, token, Redeploy::Deny).await,
        StoreOutcome::Unchanged(_)
    ));
    assert_eq!(ref_count(&pool, &a).await, 1);

    // Other content: refused without redeploy, replaced with it.
    let (b, token) = ingest(&pool).await;
    assert_eq!(
        store(&pool, repo, "dir/x.bin", &b, token, Redeploy::Deny).await,
        StoreOutcome::Exists
    );
    assert_eq!(ref_count(&pool, &b).await, 0);
    let before = raw_dao::find(&pool, repo, "dir/x.bin")
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        store(&pool, repo, "dir/x.bin", &b, token, Redeploy::Allow).await,
        StoreOutcome::Replaced(_)
    ));
    assert_eq!(ref_count(&pool, &a).await, 0);
    assert_eq!(ref_count(&pool, &b).await, 1);
    let after = raw_dao::find(&pool, repo, "dir/x.bin")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.blob_sha256, b);
    assert!(after.updated_at > before.updated_at);
    assert_eq!(after.created_at, before.created_at);

    // The same blob under a second path holds a second reference.
    let token = ingest_existing(&pool, &b).await;
    store(&pool, repo, "other/x.bin", &b, token, Redeploy::Deny).await;
    assert_eq!(ref_count(&pool, &b).await, 2);

    let mut tx = pool.begin().await.unwrap();
    assert!(
        raw_dao::delete(&mut tx, repo, "dir/x.bin", Duration::zero())
            .await
            .unwrap()
    );
    assert!(
        !raw_dao::delete(&mut tx, repo, "dir/x.bin", Duration::zero())
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    assert_eq!(ref_count(&pool, &b).await, 1);
}

/// A new lease on a blob that exists already (a deduplicated upload).
async fn ingest_existing(pool: &PgPool, sha: &str) -> Uuid {
    match blob_dao::begin_ingest(
        pool,
        sha,
        3,
        &format!("blobs/{sha}"),
        Utc::now() + Duration::hours(1),
        Utc::now() - Duration::minutes(1),
    )
    .await
    .unwrap()
    {
        BeginIngestOutcome::Ready { token, .. } => token,
        _ => panic!("unexpected ingest outcome"),
    }
}

#[tokio::test]
async fn listings_walk_entries_in_byte_order_and_page() {
    let pool = pool().await;
    let repo = repo(&pool).await;
    // `N` (a file), `N!x` (a file sorting before the directory `N/`), the
    // directory `N/` with many files, and a sibling directory's files.
    let paths = [
        "top/N",
        "top/N!x",
        "top/N/a",
        "top/N/b/c",
        "top/N/z",
        "top/b.txt",
        "top0/outside",
        "to/outside",
    ];
    for path in paths {
        let (sha, token) = ingest(&pool).await;
        store(&pool, repo, path, &sha, token, Redeploy::Deny).await;
    }

    let names = |entries: &[raw_dao::WalkedEntry], prefix: &str| -> Vec<String> {
        entries
            .iter()
            .map(|e| {
                let rest = &e.path[prefix.len()..];
                match (rest.find('/'), &e.file) {
                    (Some(i), None) => format!("{}/", &rest[..i]),
                    (None, Some(_)) => rest.to_string(),
                    other => panic!("inconsistent entry {e:?}: {other:?}"),
                }
            })
            .collect()
    };

    let all = raw_dao::walk_directory(&pool, repo, "top/", "top/", 100)
        .await
        .unwrap();
    assert_eq!(names(&all, "top/"), ["N", "N!x", "N/", "b.txt"]);
    let file = all[0].file.as_ref().unwrap();
    assert_eq!(file.path, "top/N");
    assert!(file.s3_key.starts_with("blobs/"));

    // Pages: two entries, then resume after the directory `N/`.
    let first = raw_dao::walk_directory(&pool, repo, "top/", "top/", 2)
        .await
        .unwrap();
    assert_eq!(names(&first, "top/"), ["N", "N!x"]);
    let rest = raw_dao::walk_directory(&pool, repo, "top/", "top/N!x\u{1}", 100)
        .await
        .unwrap();
    assert_eq!(names(&rest, "top/"), ["N/", "b.txt"]);
    let after_dir = raw_dao::walk_directory(&pool, repo, "top/", "top/N0", 100)
        .await
        .unwrap();
    assert_eq!(names(&after_dir, "top/"), ["b.txt"]);

    let root = raw_dao::walk_directory(&pool, repo, "", "", 100)
        .await
        .unwrap();
    assert_eq!(names(&root, ""), ["to/", "top/", "top0/"]);
    let sub = raw_dao::walk_directory(&pool, repo, "top/N/", "top/N/", 100)
        .await
        .unwrap();
    assert_eq!(names(&sub, "top/N/"), ["a", "b/", "z"]);

    assert!(raw_dao::directory_exists(&pool, repo, "top/N/")
        .await
        .unwrap());
    assert!(!raw_dao::directory_exists(&pool, repo, "top/M/")
        .await
        .unwrap());
    assert_eq!(
        raw_dao::paths_under(&pool, repo, "top/N/", "top/N/a", 10)
            .await
            .unwrap(),
        ["top/N/b/c", "top/N/z"]
    );

    let mut tx = pool.begin().await.unwrap();
    let locked = raw_dao::lock_directory_for_retention(&mut tx, repo, "top/N/")
        .await
        .unwrap();
    let locked: Vec<&str> = locked.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(locked, ["top/N/a", "top/N/z"]);
    // A directory delete takes its files only, in batches.
    assert_eq!(
        raw_dao::delete_under(&mut tx, repo, "top/N/", 2, Duration::zero())
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        raw_dao::delete_under(&mut tx, repo, "top/N/", 2, Duration::zero())
            .await
            .unwrap(),
        1
    );
    tx.commit().await.unwrap();
    let left: Vec<String> = raw_dao::retention_files(&pool, repo)
        .await
        .unwrap()
        .into_iter()
        .map(|f| f.path)
        .collect();
    assert_eq!(
        left,
        [
            "to/outside",
            "top/N",
            "top/N!x",
            "top/b.txt",
            "top0/outside"
        ]
    );

    let mut tx = pool.begin().await.unwrap();
    assert_eq!(
        raw_dao::purge_repository(&mut tx, repo, Duration::zero())
            .await
            .unwrap(),
        5
    );
    assert!(!raw_dao::repository_has_files(&mut *tx, repo).await.unwrap());
    tx.commit().await.unwrap();
}
