//! `oci_dao`'s image listings against a real Postgres: reading every image
//! of a repository a batch at a time by name (#596); and the lock every
//! write of an image's manifests and tags takes first (#575).

mod common;

use forge_db::oci_dao;
use forge_db::repository_dao::{self, NewRepository};

use common::{pool, unique};

/// Index entries and table rows of `oci_manifest` this transaction read.
async fn rows_read(conn: &mut sqlx::PgConnection) -> i64 {
    sqlx::query_scalar(
        r#"
        SELECT coalesce(sum(pg_stat_get_xact_tuples_returned(i.indexrelid)), 0)::bigint
             + coalesce(pg_stat_get_xact_tuples_returned('oci_manifest'::regclass), 0)
        FROM pg_index i
        WHERE i.indrelid = 'oci_manifest'::regclass
        "#,
    )
    .fetch_one(conn)
    .await
    .unwrap()
}

/// Reading a repository's images batch by batch with `list_images_after`
/// reads each manifest a bounded number of times, however many batches came
/// before: an `OFFSET` page reads every image before it again, so reading
/// them all costs the square of their number.
#[tokio::test]
async fn reading_every_image_by_name_reads_each_manifest_a_few_times() {
    let pool = pool().await;
    let repo = repository_dao::insert_repository(
        &pool,
        NewRepository::hosted(format!("images-{}", unique())),
    )
    .await
    .unwrap()
    .id;
    let sha = format!("{:064x}", (u128::from(unique()) << 64) | 0x596);
    sqlx::query(
        "INSERT INTO blob (sha256, size, s3_key, state) VALUES ($1, 1, $1, 'committed') \
         ON CONFLICT DO NOTHING",
    )
    .bind(&sha)
    .execute(&pool)
    .await
    .unwrap();
    const IMAGES: i64 = 10_000;
    sqlx::query(
        r#"
        INSERT INTO oci_manifest (repository_id, image, digest, blob_sha256, media_type, size)
        SELECT $1, 'team/app-' || lpad(n::text, 5, '0'), 'sha256:' || $2, $2,
               'application/vnd.oci.image.manifest.v1+json', 1
        FROM generate_series(0, $3 - 1) AS n
        "#,
    )
    .bind(repo)
    .bind(&sha)
    .bind(IMAGES)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("ANALYZE oci_manifest")
        .execute(&pool)
        .await
        .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let before = rows_read(&mut tx).await;
    let mut listed = Vec::new();
    let mut after = String::new();
    loop {
        let batch = oci_dao::list_images_after(&mut *tx, repo, "app", &after, 1000)
            .await
            .unwrap();
        let full = batch.len() == 1000;
        let Some(last) = batch.last() else {
            break;
        };
        after = last.image.clone();
        listed.extend(batch.into_iter().map(|image| image.image));
        if !full {
            break;
        }
    }
    let read = rows_read(&mut tx).await - before;
    assert_eq!(listed.len() as i64, IMAGES);
    assert!(
        listed.windows(2).all(|w| w[0] < w[1]),
        "in order, once each"
    );
    assert_eq!(listed[0], "team/app-00000");
    assert!(
        read < 3 * IMAGES,
        "listing {IMAGES} images read {read} manifest rows"
    );
}

/// Wait until the session `pid` is blocked on a lock. Panics after 10 s.
async fn wait_for_lock_wait(pool: &sqlx::PgPool, pid: i32) {
    for _ in 0..500 {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
             WHERE pid = $1 AND wait_event_type = 'Lock')",
        )
        .bind(pid)
        .fetch_one(pool)
        .await
        .unwrap();
        if waiting {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("session {pid} never waited for a lock");
}

async fn backend_pid(conn: &mut sqlx::PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .unwrap()
}

/// Image retention (and an administrator's manifest delete) locks an image's
/// manifests and then its tags; a tag delete and a push that moves a tag
/// lock the tag and then its manifest. In these opposite orders the two
/// transactions deadlocked and Postgres aborted the tag's writer (`40P01`,
/// #575). Both take the image's lock first: the writer waits for it.
#[tokio::test]
async fn a_tag_write_waits_for_an_image_locked_for_retention() {
    let pool = pool().await;
    let repo = repository_dao::insert_repository(
        &pool,
        NewRepository::hosted(format!("images-{}", unique())),
    )
    .await
    .unwrap()
    .id;
    let sha = format!("{:064x}", (u128::from(unique()) << 64) | 0x575);
    sqlx::query(
        "INSERT INTO blob (sha256, size, s3_key, state) VALUES ($1, 1, $1, 'committed') \
         ON CONFLICT DO NOTHING",
    )
    .bind(&sha)
    .execute(&pool)
    .await
    .unwrap();
    for (image, moves) in [("deleted", false), ("moved", true)] {
        // `latest` on one manifest and `aaa`, the first tag in tag order,
        // on another.
        let mut manifests = Vec::new();
        for (n, tag) in ["latest", "aaa"].into_iter().enumerate() {
            let id: i64 = sqlx::query_scalar(
                r#"
                INSERT INTO oci_manifest (repository_id, image, digest, blob_sha256, media_type, size)
                VALUES ($1, $2, 'sha256:' || $3 || $4::text, $3,
                        'application/vnd.oci.image.manifest.v1+json', 1)
                RETURNING id
                "#,
            )
            .bind(repo)
            .bind(image)
            .bind(&sha)
            .bind(n as i64)
            .fetch_one(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO oci_tag (repository_id, image, tag, manifest_id) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(repo)
            .bind(image)
            .bind(tag)
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
            manifests.push(id);
        }
        let (tagged, other) = (manifests[0], manifests[1]);

        // Retention holds the image's manifests and stops at its first tag,
        // which another transaction holds.
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM oci_tag WHERE repository_id = $1 AND image = $2 AND tag = 'aaa' \
             FOR UPDATE",
        )
        .bind(repo)
        .bind(image)
        .execute(&mut *blocker)
        .await
        .unwrap();
        let mut retention = pool.begin().await.unwrap();
        let retention_pid = backend_pid(&mut retention).await;
        let retention = tokio::spawn(async move {
            let locked = oci_dao::lock_image_for_retention(&mut retention, repo, image).await;
            (retention, locked)
        });
        wait_for_lock_wait(&pool, retention_pid).await;

        // The writer of `latest` starts meanwhile: it locked the tag, and
        // then waited for the manifest retention holds.
        let mut writer = pool.begin().await.unwrap();
        let writer_pid = backend_pid(&mut writer).await;
        let writer = tokio::spawn(async move {
            let written = if moves {
                // As a push does (`commit_manifest`).
                match oci_dao::lock_image(&mut writer, repo, image).await {
                    Ok(()) => oci_dao::set_tag(&mut writer, repo, image, "latest", other, true)
                        .await
                        .map(|write| write == oci_dao::TagWrite::Moved { previous: tagged }),
                    Err(e) => Err(e),
                }
            } else {
                oci_dao::delete_tag(&mut writer, repo, image, "latest").await
            };
            (writer, written)
        });
        wait_for_lock_wait(&pool, writer_pid).await;

        // Retention goes on to the tags, `latest` among them.
        blocker.rollback().await.unwrap();
        let (retention, locked) = retention.await.unwrap();
        let (tags, locked) = locked.expect("retention locks the image");
        assert_eq!((tags.len(), locked.len()), (2, 2), "{image}");
        retention.commit().await.unwrap();
        let (writer, written) = writer.await.unwrap();
        assert!(written.expect("the tag's writer is not aborted"), "{image}");
        writer.commit().await.unwrap();

        let latest: Option<i64> = sqlx::query_scalar(
            "SELECT manifest_id FROM oci_tag \
             WHERE repository_id = $1 AND image = $2 AND tag = 'latest'",
        )
        .bind(repo)
        .bind(image)
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(latest, moves.then_some(other), "{image}");
        let untagged: bool =
            sqlx::query_scalar("SELECT untagged_since IS NOT NULL FROM oci_manifest WHERE id = $1")
                .bind(tagged)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(untagged, "{image}: the manifest `latest` left");
    }
}
