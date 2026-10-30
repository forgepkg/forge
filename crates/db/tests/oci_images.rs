//! `oci_dao`'s image listings against a real Postgres: reading every image
//! of a repository a batch at a time by name (#596).

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
