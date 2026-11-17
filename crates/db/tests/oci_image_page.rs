//! `oci_dao`'s reads for an image's page against a real Postgres: the newest
//! of an image without reading the whole image, and what a group's lower
//! priority member adds to the members before it (#561).
//!
//! In a test binary of its own, and so in a database of its own: a plan
//! follows the table's statistics, and the `oci_images` test counts the rows
//! of plans that an image of 30,000 manifests in the same table changes.

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

/// A blob for seeded manifests to name.
async fn seeded_blob(pool: &sqlx::PgPool) -> String {
    let sha = format!("{:064x}", (u128::from(unique()) << 64) | 0x561);
    sqlx::query(
        "INSERT INTO blob (sha256, size, s3_key, state) VALUES ($1, 1, $1, 'committed') \
         ON CONFLICT DO NOTHING",
    )
    .bind(&sha)
    .execute(pool)
    .await
    .unwrap();
    sha
}

/// Manifests `from .. to` of the image `app` in `repo`, each tagged
/// `<prefix><n>`: manifest `n` has the digest `sha256:<n in hex>` and was
/// pushed `n` minutes after `pushed_from`.
async fn seed_tagged(
    pool: &sqlx::PgPool,
    repo: i64,
    blob: &str,
    (from, to): (i64, i64),
    pushed_from: &str,
    prefix: &str,
) {
    sqlx::query(
        r#"
        WITH pushed AS (
            INSERT INTO oci_manifest
                (repository_id, image, digest, blob_sha256, media_type, size, summary, created_at)
            SELECT $1, 'app', 'sha256:' || lpad(to_hex(n), 64, '0'), $2,
                   'application/vnd.oci.image.manifest.v1+json', 1,
                   jsonb_build_object('layers_size', n),
                   $5::timestamptz + n * interval '1 minute'
            FROM generate_series($3::bigint, $4::bigint - 1) AS n
            RETURNING id, digest
        )
        INSERT INTO oci_tag (repository_id, image, tag, manifest_id)
        SELECT $1, 'app', $6 || ('x' || right(digest, 8))::bit(32)::int, id FROM pushed
        "#,
    )
    .bind(repo)
    .bind(blob)
    .bind(from)
    .bind(to)
    .bind(pushed_from)
    .bind(prefix)
    .execute(pool)
    .await
    .unwrap();
}

fn digest(n: i64) -> String {
    format!("sha256:{n:064x}")
}

/// The page of an image with 30,000 tagged manifests reads the 1,000 it
/// lists through `oci_manifest_newest_idx`, not the image: the query before
/// read (and returned) every manifest of it on each request (#561). The
/// totals count the image from its index entries.
#[tokio::test]
async fn an_image_page_reads_the_manifests_it_lists_not_the_image() {
    let pool = pool().await;
    let repo = repository_dao::insert_repository(
        &pool,
        NewRepository::hosted(format!("page-{}", unique())),
    )
    .await
    .unwrap()
    .id;
    let blob = seeded_blob(&pool).await;
    const MANIFESTS: i64 = 30_000;
    seed_tagged(&pool, repo, &blob, (0, MANIFESTS), "2025-01-01", "t").await;
    sqlx::query("ANALYZE oci_manifest")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ANALYZE oci_tag").execute(&pool).await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    let before = rows_read(&mut tx).await;
    let listed = oci_dao::image_listing(&mut *tx, &[repo], 0, "app", 1000, 1000)
        .await
        .unwrap();
    let read = rows_read(&mut tx).await - before;
    drop(tx);
    // The newest 1,000, each with its tag.
    let mut digests: Vec<&str> = listed.iter().map(|m| m.digest.as_str()).collect();
    digests.sort_unstable();
    let newest: Vec<String> = (MANIFESTS - 1000..MANIFESTS).map(digest).collect();
    assert_eq!(digests, newest);
    assert!(listed
        .iter()
        .all(|m| m.repository_id == repo && m.tags.len() == 1));
    let last = listed.iter().find(|m| m.digest == newest[999]).unwrap();
    assert_eq!(last.tags, [format!("t{}", MANIFESTS - 1)]);
    assert!(
        read < 10_000,
        "listing 1,000 of {MANIFESTS} manifests read {read} manifest rows"
    );

    assert_eq!(
        oci_dao::image_totals(&pool, &[repo], 0, "app")
            .await
            .unwrap(),
        (MANIFESTS, MANIFESTS)
    );

    // With `FORGE_TEST_DATABASE_URL` the suites share a database: leave no
    // large image in it, nor the size it gave the indexes, for the plans
    // of their tests.
    sqlx::query("DELETE FROM repository WHERE id = $1")
        .bind(repo)
        .execute(&pool)
        .await
        .unwrap();
    for tidy in [
        "REINDEX TABLE oci_manifest",
        "REINDEX TABLE oci_tag",
        "VACUUM ANALYZE oci_manifest",
        "VACUUM ANALYZE oci_tag",
    ] {
        sqlx::query(tidy).execute(&pool).await.unwrap();
    }
}

/// A repository after another one (a group's lower priority member) lists
/// and counts what it adds to it: not a tag the first one has, and a digest
/// the first one holds only as the first one's manifest, when one of its
/// own tags points at it.
#[tokio::test]
async fn a_lower_priority_repository_lists_what_it_adds_to_the_first() {
    let pool = pool().await;
    let mut repos = Vec::new();
    for _ in 0..2 {
        let repo = repository_dao::insert_repository(
            &pool,
            NewRepository::hosted(format!("member-{}", unique())),
        )
        .await
        .unwrap();
        repos.push(repo.id);
    }
    let (first, second) = (repos[0], repos[1]);
    let blob = seeded_blob(&pool).await;
    // The first holds 0 … 9 (tagged a<n>); the second 5 … 14, tagged b<n>
    // and, for 5 … 9, also a<n - 5>: tags of the first.
    seed_tagged(&pool, first, &blob, (0, 10), "2025-03-01", "a").await;
    seed_tagged(&pool, second, &blob, (5, 15), "2025-02-01", "b").await;
    sqlx::query(
        r#"
        INSERT INTO oci_tag (repository_id, image, tag, manifest_id)
        SELECT repository_id, image, 'a' || n - 5, id
        FROM oci_manifest
        JOIN generate_series(5, 9) AS n ON digest = 'sha256:' || lpad(to_hex(n), 64, '0')
        WHERE repository_id = $1 AND image = 'app'
        "#,
    )
    .bind(second)
    .execute(&pool)
    .await
    .unwrap();
    // An index of the second: a child only the first holds, one both hold
    // (the first's counts) and one neither holds.
    sqlx::query(
        r#"
        INSERT INTO oci_manifest_ref (manifest_id, kind, digest)
        SELECT id, 'manifest', unnest($2::text[])
        FROM oci_manifest
        WHERE repository_id = $1 AND image = 'app' AND digest = $3
        "#,
    )
    .bind(second)
    .bind([digest(1), digest(7), digest(99)])
    .bind(digest(14))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE oci_manifest SET summary = '{\"layers_size\": 700}' \
         WHERE repository_id = $1 AND image = 'app' AND digest = $2",
    )
    .bind(second)
    .bind(digest(7))
    .execute(&pool)
    .await
    .unwrap();

    let listed = oci_dao::image_listing(&pool, &repos, 1, "app", 1000, 1000)
        .await
        .unwrap();
    let mut rows: Vec<(String, i64, Vec<String>)> = listed
        .iter()
        .map(|m| {
            let mut tags = m.tags.clone();
            tags.sort();
            (m.digest.clone(), m.repository_id, tags)
        })
        .collect();
    rows.sort();
    let mut expected: Vec<(String, i64, Vec<String>)> = (5..10)
        .map(|n| (digest(n), first, vec![format!("b{n}")]))
        .chain((10..15).map(|n| (digest(n), second, vec![format!("b{n}")])))
        .collect();
    expected.sort();
    assert_eq!(rows, expected);
    let index = listed.iter().find(|m| m.digest == digest(14)).unwrap();
    assert_eq!(index.children, [digest(1), digest(7), digest(99)]);
    let sizes: Vec<Option<i64>> = index
        .child_summaries
        .iter()
        .map(|child| child.as_ref().map(|c| c["layers_size"].as_i64().unwrap()))
        .collect();
    assert_eq!(sizes, [Some(1), Some(7), None]);
    // Five manifests and ten tags more than the first's.
    assert_eq!(
        oci_dao::image_totals(&pool, &repos, 1, "app")
            .await
            .unwrap(),
        (5, 10)
    );

    // The bounds: the newest tagged manifests, and the newest of all.
    let listed = oci_dao::image_listing(&pool, &repos, 0, "app", 2, 3)
        .await
        .unwrap();
    let mut digests: Vec<&str> = listed.iter().map(|m| m.digest.as_str()).collect();
    digests.sort_unstable();
    assert_eq!(digests, [digest(7), digest(8), digest(9)]);
}
