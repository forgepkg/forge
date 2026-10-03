//! Integration tests for the DAO layer against a real Postgres testcontainer.
//!
//! Requires Docker on the host. All tests share one container/pool (see
//! `common`) and isolate themselves with unique names.

mod common;

use chrono::{Duration, Utc};
use forge_db::asset_dao::{self, NewAsset};
use forge_db::blob_dao;
use forge_db::component_dao::{self, NewComponent};
use forge_db::model::{BlobState, RepoKind};
use forge_db::outbox_dao;
use forge_db::proxy_dao::{self, NewProxyCachedVersion};
use forge_db::repository_dao::{self, NewRepository};
use forge_db::token_dao::{self, NewToken};
use forge_db::user_dao::{self, NewUser};

use common::{pool, unique};

// ── repository / group_member ───────────────────────────────────────────────

#[tokio::test]
async fn repository_insert_and_fetch_round_trip() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let name = format!("repo-rt-{n}");

    let inserted = repository_dao::insert_repository(pool, NewRepository::hosted(&name))
        .await
        .expect("insert");
    assert_eq!(inserted.name, name);
    assert_eq!(inserted.kind(), RepoKind::Hosted);

    let by_name = repository_dao::find_repository_by_name(pool, &name)
        .await
        .expect("find by name")
        .expect("present");
    assert_eq!(by_name.id, inserted.id);

    let by_id = repository_dao::find_repository_by_id(pool, inserted.id)
        .await
        .expect("find by id")
        .expect("present");
    assert_eq!(by_id.name, name);

    let all = repository_dao::list_repositories(pool).await.expect("list");
    assert!(all.iter().any(|r| r.id == inserted.id));
}

#[tokio::test]
async fn group_members_ordered_by_priority_desc() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();

    let group = repository_dao::insert_repository(pool, NewRepository::group(format!("grp-{n}")))
        .await
        .expect("group");
    let low = repository_dao::insert_repository(pool, NewRepository::hosted(format!("m-low-{n}")))
        .await
        .expect("low");
    let high =
        repository_dao::insert_repository(pool, NewRepository::hosted(format!("m-high-{n}")))
            .await
            .expect("high");
    let mid = repository_dao::insert_repository(pool, NewRepository::hosted(format!("m-mid-{n}")))
        .await
        .expect("mid");

    repository_dao::add_group_member(pool, group.id, low.id, 1)
        .await
        .expect("add low");
    repository_dao::add_group_member(pool, group.id, high.id, 100)
        .await
        .expect("add high");
    repository_dao::add_group_member(pool, group.id, mid.id, 50)
        .await
        .expect("add mid");

    let members = repository_dao::group_members(pool, group.id)
        .await
        .expect("members");

    // Highest priority first (wins ties per spec §7).
    let priorities: Vec<i32> = members.iter().map(|(_, p)| *p).collect();
    assert_eq!(priorities, vec![100, 50, 1], "must be priority DESC");
    assert_eq!(members[0].0.id, high.id);
    assert_eq!(members[2].0.id, low.id);

    assert!(repository_dao::remove_group_member(pool, group.id, mid.id)
        .await
        .expect("remove"));
    let after = repository_dao::group_members(pool, group.id)
        .await
        .expect("members after");
    assert_eq!(after.len(), 2);
}

// ── nested groups: cycle + depth guard (§12.4 Phase 4) ──────────────────────

#[tokio::test]
async fn add_group_member_checked_allows_valid_nesting() {
    use forge_db::repository_dao::AddMemberOutcome;
    let pool = pool().await;
    let pool = &pool;
    let n = unique();

    // g1 -> g2 -> leaf. Both edges are acyclic and within depth.
    let g1 = repository_dao::insert_repository(pool, NewRepository::group(format!("g1-{n}")))
        .await
        .expect("g1");
    let g2 = repository_dao::insert_repository(pool, NewRepository::group(format!("g2-{n}")))
        .await
        .expect("g2");
    let leaf = repository_dao::insert_repository(pool, NewRepository::hosted(format!("leaf-{n}")))
        .await
        .expect("leaf");

    // g2 -> leaf (depth 1 below g2).
    assert_eq!(
        repository_dao::add_group_member_checked(pool, g2.id, leaf.id, 10, 20)
            .await
            .expect("g2->leaf"),
        AddMemberOutcome::Added
    );
    // g1 -> g2 (nested group member): valid, no cycle.
    assert_eq!(
        repository_dao::add_group_member_checked(pool, g1.id, g2.id, 10, 20)
            .await
            .expect("g1->g2"),
        AddMemberOutcome::Added
    );
}

#[tokio::test]
async fn concurrent_opposite_edges_never_form_a_cycle() {
    // P1.4: `A -> B` and `B -> A` added concurrently each look acyclic on their
    // own; the graph lock must make exactly one of them win in the FINAL state.
    use forge_db::repository_dao::AddMemberOutcome;
    let pool = pool().await;
    for round in 0..10 {
        let n = unique();
        let a =
            repository_dao::insert_repository(&pool, NewRepository::group(format!("race-a-{n}")))
                .await
                .expect("a");
        let b =
            repository_dao::insert_repository(&pool, NewRepository::group(format!("race-b-{n}")))
                .await
                .expect("b");
        let (p1, p2) = (pool.clone(), pool.clone());
        let (r1, r2) = tokio::join!(
            tokio::spawn(async move {
                repository_dao::add_group_member_checked(&p1, a.id, b.id, 10, 20).await
            }),
            tokio::spawn(async move {
                repository_dao::add_group_member_checked(&p2, b.id, a.id, 10, 20).await
            }),
        );
        let outcomes = [r1.unwrap().expect("a->b"), r2.unwrap().expect("b->a")];
        let added = outcomes
            .iter()
            .filter(|o| **o == AddMemberOutcome::Added)
            .count();
        assert_eq!(
            added, 1,
            "round {round}: exactly one edge wins: {outcomes:?}"
        );
        let edges = repository_dao::group_members(&pool, a.id)
            .await
            .unwrap()
            .len()
            + repository_dao::group_members(&pool, b.id)
                .await
                .unwrap()
                .len();
        assert_eq!(edges, 1, "round {round}: no cycle persisted");
    }
}

#[tokio::test]
async fn add_group_member_checked_rejects_cycle() {
    use forge_db::repository_dao::AddMemberOutcome;
    let pool = pool().await;
    let pool = &pool;
    let n = unique();

    let g1 = repository_dao::insert_repository(pool, NewRepository::group(format!("cyc-g1-{n}")))
        .await
        .expect("g1");
    let g2 = repository_dao::insert_repository(pool, NewRepository::group(format!("cyc-g2-{n}")))
        .await
        .expect("g2");

    // g1 -> g2 is fine.
    assert_eq!(
        repository_dao::add_group_member_checked(pool, g1.id, g2.id, 10, 20)
            .await
            .expect("g1->g2"),
        AddMemberOutcome::Added
    );
    // g2 -> g1 would close a cycle (g1 reachable from g2) ⇒ rejected, not inserted.
    assert_eq!(
        repository_dao::add_group_member_checked(pool, g2.id, g1.id, 10, 20)
            .await
            .expect("g2->g1 checked"),
        AddMemberOutcome::WouldCycle
    );
    // And nothing was persisted on g2.
    let g2_members = repository_dao::group_members(pool, g2.id)
        .await
        .expect("g2 members");
    assert!(g2_members.is_empty(), "cycle edge must not be persisted");

    // Direct self-cycle (g1 -> g1) is also a cycle.
    assert_eq!(
        repository_dao::add_group_member_checked(pool, g1.id, g1.id, 5, 20)
            .await
            .expect("self checked"),
        AddMemberOutcome::WouldCycle
    );
}

#[tokio::test]
async fn add_group_member_checked_enforces_depth() {
    use forge_db::repository_dao::AddMemberOutcome;
    let pool = pool().await;
    let pool = &pool;
    let n = unique();

    // Build a chain g_top -> g_mid -> leaf, then with max_depth = 2 attempting
    // to nest g_mid under a new g_top must be rejected (its subtree is depth 2,
    // the new edge makes depth 3 > 2).
    let top = repository_dao::insert_repository(pool, NewRepository::group(format!("d-top-{n}")))
        .await
        .expect("top");
    let mid = repository_dao::insert_repository(pool, NewRepository::group(format!("d-mid-{n}")))
        .await
        .expect("mid");
    let leaf =
        repository_dao::insert_repository(pool, NewRepository::hosted(format!("d-leaf-{n}")))
            .await
            .expect("leaf");

    // mid -> leaf (depth 1).
    assert_eq!(
        repository_dao::add_group_member_checked(pool, mid.id, leaf.id, 1, 5)
            .await
            .expect("mid->leaf"),
        AddMemberOutcome::Added
    );
    // top -> mid with max_depth = 1 ⇒ new path top->mid->leaf is length 2 > 1.
    assert_eq!(
        repository_dao::add_group_member_checked(pool, top.id, mid.id, 1, 1)
            .await
            .expect("too deep checked"),
        AddMemberOutcome::TooDeep
    );
    // With a generous depth it is fine.
    assert_eq!(
        repository_dao::add_group_member_checked(pool, top.id, mid.id, 1, 5)
            .await
            .expect("ok at depth 5"),
        AddMemberOutcome::Added
    );
}

#[tokio::test]
async fn add_group_member_checked_reports_duplicate() {
    use forge_db::repository_dao::AddMemberOutcome;
    let pool = pool().await;
    let pool = &pool;
    let n = unique();

    let g = repository_dao::insert_repository(pool, NewRepository::group(format!("dup-g-{n}")))
        .await
        .expect("g");
    let m = repository_dao::insert_repository(pool, NewRepository::hosted(format!("dup-m-{n}")))
        .await
        .expect("m");

    assert_eq!(
        repository_dao::add_group_member_checked(pool, g.id, m.id, 10, 20)
            .await
            .expect("first"),
        AddMemberOutcome::Added
    );
    // Same member again ⇒ unique violation surfaced as Duplicate.
    assert_eq!(
        repository_dao::add_group_member_checked(pool, g.id, m.id, 11, 20)
            .await
            .expect("dup"),
        AddMemberOutcome::Duplicate
    );
}

// ── blob ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn blob_upsert_pending_returns_true_then_false() {
    let pool = pool().await;
    let pool = &pool;
    let sha = format!("sha-upsert-{}", unique());

    let first = blob_dao::upsert_pending(pool, &sha, 123, "k/1")
        .await
        .expect("first");
    assert!(first, "first insert returns true");

    let second = blob_dao::upsert_pending(pool, &sha, 123, "k/1")
        .await
        .expect("second");
    assert!(!second, "already-existing returns false");

    let blob = blob_dao::get_blob(pool, &sha)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(blob.state(), BlobState::Pending);
    assert_eq!(blob.ref_count, 0);
    assert_eq!(blob.size, 123);
}

#[tokio::test]
async fn refreshed_ingest_lease_still_fences_delete_after_original_expiry() {
    let pool = pool().await;
    let pool = &pool;
    let sha = format!("sha-lease-refresh-{}", unique());
    let now = Utc::now();
    let outcome = blob_dao::begin_ingest(
        pool,
        &sha,
        10,
        "k/lease-refresh",
        now + Duration::milliseconds(10),
        now - Duration::minutes(2),
    )
    .await
    .expect("begin ingest");
    let token = match outcome {
        blob_dao::BeginIngestOutcome::Ready { token, .. } => token,
        other => panic!("unexpected begin outcome: {other:?}"),
    };

    assert!(
        blob_dao::refresh_ingest(pool, token, Utc::now() + Duration::hours(1))
            .await
            .expect("refresh")
    );
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    let outcome = blob_dao::reserve_outbox_delete(pool, &sha, Utc::now() - Duration::minutes(2))
        .await
        .expect("reserve");
    assert_eq!(outcome, blob_dao::ReserveDeleteOutcome::Busy);
    blob_dao::abort_ingest(pool, token).await.expect("abort");
}

#[tokio::test]
async fn blob_commit_and_incref_increments_and_commits() {
    let pool = pool().await;
    let pool = &pool;
    let sha = format!("sha-incref-{}", unique());
    blob_dao::upsert_pending(pool, &sha, 10, "k/2")
        .await
        .expect("upsert");

    let mut tx = pool.begin().await.expect("begin");
    blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .expect("incref 1");
    blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .expect("incref 2");
    tx.commit().await.expect("commit");

    let blob = blob_dao::get_blob(pool, &sha)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(blob.ref_count, 2);
    assert_eq!(blob.state(), BlobState::Committed);
}

#[tokio::test]
async fn blob_decref_to_zero_enqueues_exactly_one_outbox_row_in_same_tx() {
    let pool = pool().await;
    let pool = &pool;
    let sha = format!("sha-zero-{}", unique());
    let s3_key = format!("blobs/{sha}");
    blob_dao::upsert_pending(pool, &sha, 10, &s3_key)
        .await
        .expect("upsert");

    // refcount -> 1
    let mut tx = pool.begin().await.expect("begin");
    blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .expect("incref");
    tx.commit().await.expect("commit");

    // decref -> 0, must enqueue and return true; assert the outbox row exists
    // INSIDE the same transaction (before commit).
    let mut tx = pool.begin().await.expect("begin");
    let hit_zero =
        blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &sha, Duration::seconds(3600))
            .await
            .expect("decref");
    assert!(hit_zero, "decref to zero returns true");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM blob_outbox WHERE sha256 = $1 AND op = 'delete_object'",
    )
    .bind(&sha)
    .fetch_one(&mut *tx)
    .await
    .expect("count in tx");
    assert_eq!(
        count, 1,
        "exactly one delete_object row enqueued in same tx"
    );

    // The enqueued row carries the blob's s3_key and a future available_at.
    let row = sqlx::query!(
        "SELECT s3_key, available_at FROM blob_outbox WHERE sha256 = $1",
        sha
    )
    .fetch_one(&mut *tx)
    .await
    .expect("row in tx");
    assert_eq!(row.s3_key, s3_key);
    assert!(row.available_at > Utc::now());

    tx.commit().await.expect("commit");
}

#[tokio::test]
async fn blob_decref_above_zero_returns_false_and_enqueues_nothing() {
    let pool = pool().await;
    let pool = &pool;
    let sha = format!("sha-nonzero-{}", unique());
    blob_dao::upsert_pending(pool, &sha, 10, "k/nz")
        .await
        .expect("upsert");

    // refcount -> 2
    let mut tx = pool.begin().await.expect("begin");
    blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .expect("incref 1");
    blob_dao::commit_and_incref(&mut tx, &sha)
        .await
        .expect("incref 2");
    tx.commit().await.expect("commit");

    // decref -> 1
    let mut tx = pool.begin().await.expect("begin");
    let hit_zero = blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &sha, Duration::seconds(60))
        .await
        .expect("decref");
    assert!(!hit_zero, "decref above zero returns false");
    tx.commit().await.expect("commit");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blob_outbox WHERE sha256 = $1")
        .bind(&sha)
        .fetch_one(pool)
        .await
        .expect("count");
    assert_eq!(count, 0, "nothing enqueued when refcount stays above zero");

    let blob = blob_dao::get_blob(pool, &sha)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(blob.ref_count, 1);
}

/// Wait until at least `n` backends are blocked — directly or through another
/// blocked backend — behind the locks held by `holder_pid`.
async fn wait_blocked_behind(pool: &sqlx::PgPool, holder_pid: i32, n: i64) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let blocked: i64 = sqlx::query_scalar(
            r#"
            WITH RECURSIVE waiter(pid) AS (
                SELECT pid FROM pg_stat_activity
                WHERE $1 = ANY(pg_blocking_pids(pid))
                UNION
                SELECT a.pid FROM pg_stat_activity a
                JOIN waiter w ON w.pid = ANY(pg_blocking_pids(a.pid))
            )
            SELECT count(*) FROM waiter
            "#,
        )
        .bind(holder_pid)
        .fetch_one(pool)
        .await
        .expect("blocked count");
        if blocked >= n {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "only {blocked} of {n} backends ever blocked behind pid {holder_pid}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// L4: a deletion that finalizes (deletes the blob row) after `begin_ingest`'s
/// `INSERT … ON CONFLICT DO NOTHING` saw the old row but before its row lock is
/// granted must not surface as `RowNotFound` (a 500 on publish). The ingest
/// retries and creates a fresh pending incarnation.
///
/// Deterministic interleaving: a reader holds `FOR SHARE` on the row, so the
/// finalize `DELETE` queues behind it; the ingest's insert still sees a live
/// (merely share-locked) row and inserts nothing, and its `FOR UPDATE` queues
/// behind the finalize. Releasing the reader lets the finalize delete the row
/// before the ingest's lock is granted.
#[tokio::test]
async fn begin_ingest_retries_when_deletion_finalizes_mid_ingest() {
    let pool = pool().await;
    let sha = format!("sha-vanish-{}", unique());
    let stale_before = Utc::now() - Duration::minutes(2);
    blob_dao::upsert_pending(&pool, &sha, 10, "k/vanish/old")
        .await
        .expect("upsert");
    let reservation = match blob_dao::reserve_outbox_delete(&pool, &sha, stale_before)
        .await
        .expect("reserve")
    {
        blob_dao::ReserveDeleteOutcome::Reserved(r) => r,
        other => panic!("unexpected reserve outcome: {other:?}"),
    };

    let mut reader = pool.begin().await.expect("begin reader");
    let reader_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *reader)
        .await
        .expect("pid");
    sqlx::query("SELECT 1 FROM blob WHERE sha256 = $1 FOR SHARE")
        .bind(&sha)
        .execute(&mut *reader)
        .await
        .expect("share lock");

    let finalize = {
        let (pool, reservation) = (pool.clone(), reservation.clone());
        tokio::spawn(
            async move { blob_dao::finalize_delete_reservation(&pool, &reservation).await },
        )
    };
    wait_blocked_behind(&pool, reader_pid, 1).await;

    let ingest = {
        let (pool, sha) = (pool.clone(), sha.clone());
        tokio::spawn(async move {
            blob_dao::begin_ingest(
                &pool,
                &sha,
                10,
                "k/vanish/new",
                Utc::now() + Duration::hours(1),
                stale_before,
            )
            .await
        })
    };
    wait_blocked_behind(&pool, reader_pid, 2).await;
    reader.commit().await.expect("release reader");

    assert!(
        finalize.await.unwrap().expect("finalize"),
        "the deletion owner finalizes its reservation"
    );
    let outcome = ingest
        .await
        .unwrap()
        .expect("begin_ingest must retry instead of failing with RowNotFound");
    match outcome {
        blob_dao::BeginIngestOutcome::Ready {
            token,
            inserted,
            s3_key,
        } => {
            assert!(inserted, "the retry creates a fresh incarnation");
            assert_eq!(s3_key, "k/vanish/new");
            blob_dao::abort_ingest(&pool, token).await.expect("abort");
        }
        other => panic!("unexpected begin outcome: {other:?}"),
    }
    let blob = blob_dao::get_blob(&pool, &sha)
        .await
        .expect("get")
        .expect("fresh row present");
    assert_eq!(blob.state(), BlobState::Pending);
}

/// B1 defence in depth: a decrement below zero (reference-count drift) aborts
/// instead of enqueueing a delete (`blob_ref_count_nonnegative`, 0017).
#[tokio::test]
async fn blob_decref_below_zero_is_rejected() {
    let pool = pool().await;
    let sha = format!("sha-negative-{}", unique());
    blob_dao::upsert_pending(&pool, &sha, 10, "k/negative")
        .await
        .expect("upsert");

    let mut tx = pool.begin().await.expect("begin");
    let err = blob_dao::decref_and_maybe_enqueue_delete(&mut tx, &sha, Duration::seconds(0))
        .await
        .expect_err("decrement of a zero-ref blob must fail");
    match &err {
        sqlx::Error::Database(db) => {
            assert_eq!(db.code().as_deref(), Some("23514"), "check_violation");
            assert_eq!(db.constraint(), Some("blob_ref_count_nonnegative"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    tx.rollback().await.expect("rollback");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM blob_outbox WHERE sha256 = $1")
        .bind(&sha)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(count, 0, "nothing enqueued");
    let blob = blob_dao::get_blob(&pool, &sha)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(blob.ref_count, 0);
}

// ── outbox ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn outbox_claim_due_concurrent_txns_get_disjoint_rows() {
    let pool = pool().await;
    let pool = &pool;
    let tag = format!("claim-{}", unique());

    // Seed several due rows (sha tagged so we can isolate them).
    for i in 0..6 {
        sqlx::query(
            "INSERT INTO blob_outbox (op, sha256, s3_key, available_at) \
             VALUES ('delete_object', $1, $2, now() - interval '1 minute')",
        )
        .bind(format!("{tag}-{i}"))
        .bind(format!("k/{tag}/{i}"))
        .execute(pool)
        .await
        .expect("seed");
    }

    let now = Utc::now();

    // Two concurrent transactions, each claiming a batch with SKIP LOCKED.
    let mut tx_a = pool.begin().await.expect("begin a");
    let mut tx_b = pool.begin().await.expect("begin b");

    let claimed_a = outbox_dao::claim_due(&mut tx_a, 3, now, Duration::seconds(30))
        .await
        .expect("claim a");
    let claimed_b = outbox_dao::claim_due(&mut tx_b, 3, now, Duration::seconds(30))
        .await
        .expect("claim b");

    let ids_a: std::collections::HashSet<i64> = claimed_a.iter().map(|r| r.id).collect();
    let ids_b: std::collections::HashSet<i64> = claimed_b.iter().map(|r| r.id).collect();

    assert!(!ids_a.is_empty(), "tx A claimed some rows");
    assert!(!ids_b.is_empty(), "tx B claimed some rows");
    assert!(
        ids_a.is_disjoint(&ids_b),
        "concurrent claims must be disjoint (SKIP LOCKED): a={ids_a:?} b={ids_b:?}"
    );

    tx_a.commit().await.expect("commit a");
    tx_b.commit().await.expect("commit b");
}

#[tokio::test]
async fn outbox_mark_processed_and_bump_attempt() {
    let pool = pool().await;
    let pool = &pool;
    let tag = format!("mp-{}", unique());

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO blob_outbox (op, sha256, s3_key, available_at) \
         VALUES ('delete_object', $1, $2, now() - interval '1 minute') RETURNING id",
    )
    .bind(&tag)
    .bind(format!("k/{tag}"))
    .fetch_one(pool)
    .await
    .expect("seed");

    let next = Utc::now() + Duration::minutes(5);
    outbox_dao::bump_attempt(pool, id, next)
        .await
        .expect("bump");
    let row = sqlx::query!(
        "SELECT attempts, locked_until, processed_at FROM blob_outbox WHERE id = $1",
        id
    )
    .fetch_one(pool)
    .await
    .expect("row");
    assert_eq!(row.attempts, 1);
    assert!(row.locked_until.is_none());
    assert!(row.processed_at.is_none());

    outbox_dao::mark_processed(pool, id)
        .await
        .expect("processed");
    let processed_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT processed_at FROM blob_outbox WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("processed_at");
    assert!(processed_at.is_some());
}

/// M19: pruning removes processed rows older than the cutoff (in batches)
/// and never touches recent processed rows or unprocessed rows of any age.
/// (The unprocessed row is scheduled in the future so sibling claim tests
/// never pick it up.)
#[tokio::test]
async fn outbox_prune_processed_drops_only_old_processed_rows() {
    let pool = pool().await;
    let pool = &pool;
    let tag = format!("prune-{}", unique());

    sqlx::query(
        "INSERT INTO blob_outbox (op, sha256, s3_key, available_at, processed_at, created_at) \
         SELECT 'delete_object', $1 || '-old-' || g, 'k', now() - interval '30 days', \
                now() - interval '20 days', now() - interval '30 days' \
         FROM generate_series(1, 5) g",
    )
    .bind(&tag)
    .execute(pool)
    .await
    .expect("seed old processed");
    sqlx::query(
        "INSERT INTO blob_outbox (op, sha256, s3_key, available_at, processed_at) \
         VALUES ('delete_object', $1 || '-recent', 'k', now(), now() - interval '1 day')",
    )
    .bind(&tag)
    .execute(pool)
    .await
    .expect("seed recent processed");
    sqlx::query(
        "INSERT INTO blob_outbox (op, sha256, s3_key, available_at, created_at) \
         VALUES ('delete_object', $1 || '-pending', 'k', now() + interval '30 days', \
                 now() - interval '30 days')",
    )
    .bind(&tag)
    .execute(pool)
    .await
    .expect("seed old unprocessed");

    let cutoff = Utc::now() - Duration::days(7);
    let mut pruned = 0;
    loop {
        let n = outbox_dao::prune_processed(pool, cutoff, 2)
            .await
            .expect("prune");
        assert!(n <= 2, "a batch never exceeds its limit");
        pruned += n;
        if n < 2 {
            break;
        }
    }
    assert!(
        pruned >= 5,
        "all five old processed rows pruned (got {pruned})"
    );

    let left: Vec<String> = sqlx::query_scalar(
        "SELECT sha256 FROM blob_outbox WHERE sha256 LIKE $1 || '-%' ORDER BY sha256",
    )
    .bind(&tag)
    .fetch_all(pool)
    .await
    .expect("remaining");
    assert_eq!(
        left,
        vec![format!("{tag}-pending"), format!("{tag}-recent")],
        "recent processed and unprocessed rows survive"
    );
}

// ── component / asset ─────────────────────────────────────────────────────────

#[tokio::test]
async fn component_find_and_list_versions() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo = repository_dao::insert_repository(pool, NewRepository::hosted(format!("crepo-{n}")))
        .await
        .expect("repo");

    for v in ["1.0.0", "1.1.0", "2.0.0"] {
        component_dao::insert_component(
            pool,
            NewComponent {
                repository_id: repo.id,
                name: "newtonsoft.json".to_string(),
                original_id: "Newtonsoft.Json".to_string(),
                version: v.to_string(),
                version_original: v.to_string(),
                listed: true,
            },
        )
        .await
        .expect("insert component");
    }

    let found = component_dao::find_component(pool, repo.id, "newtonsoft.json", "1.1.0")
        .await
        .expect("find")
        .expect("present");
    assert_eq!(found.version, "1.1.0");
    assert_eq!(found.original_id, "Newtonsoft.Json");

    let versions = component_dao::list_versions(pool, repo.id, "newtonsoft.json")
        .await
        .expect("list");
    assert_eq!(versions.len(), 3);

    // set_listed flips the flag.
    assert!(
        component_dao::set_listed(pool, repo.id, "newtonsoft.json", "1.0.0", false)
            .await
            .expect("set_listed")
    );
    let unlisted = component_dao::find_component(pool, repo.id, "newtonsoft.json", "1.0.0")
        .await
        .expect("find")
        .expect("present");
    assert!(!unlisted.listed);

    // delete_component removes the version.
    assert!(
        component_dao::delete_component(pool, repo.id, "newtonsoft.json", "2.0.0")
            .await
            .expect("delete")
    );
    let remaining = component_dao::list_versions(pool, repo.id, "newtonsoft.json")
        .await
        .expect("list");
    assert_eq!(remaining.len(), 2);
}

#[tokio::test]
async fn asset_insert_find_and_list() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo = repository_dao::insert_repository(pool, NewRepository::hosted(format!("arepo-{n}")))
        .await
        .expect("repo");
    let component = component_dao::insert_component(
        pool,
        NewComponent {
            repository_id: repo.id,
            name: "pkg".to_string(),
            original_id: "Pkg".to_string(),
            version: "1.0.0".to_string(),
            version_original: "1.0.0".to_string(),
            listed: true,
        },
    )
    .await
    .expect("component");

    let sha = format!("asha-{n}");
    blob_dao::upsert_pending(pool, &sha, 99, &format!("k/{sha}"))
        .await
        .expect("blob");

    asset_dao::insert_asset(
        pool,
        NewAsset {
            component_id: component.id,
            path: "pkg.1.0.0.nupkg".to_string(),
            content_type: "application/octet-stream".to_string(),
            blob_sha256: sha.clone(),
            size: 99,
            sha512_base64: Some("deadbeef".to_string()),
        },
    )
    .await
    .expect("asset nupkg");
    asset_dao::insert_asset(
        pool,
        NewAsset {
            component_id: component.id,
            path: "pkg.nuspec".to_string(),
            content_type: "application/xml".to_string(),
            blob_sha256: sha.clone(),
            size: 99,
            sha512_base64: None,
        },
    )
    .await
    .expect("asset nuspec");

    let found = asset_dao::find_asset(pool, component.id, "pkg.1.0.0.nupkg")
        .await
        .expect("find")
        .expect("present");
    assert_eq!(found.blob_sha256, sha);

    let all = asset_dao::assets_for_component(pool, component.id)
        .await
        .expect("list");
    assert_eq!(all.len(), 2);
    // Ordered by path.
    assert_eq!(all[0].path, "pkg.1.0.0.nupkg");
    assert_eq!(all[1].path, "pkg.nuspec");
}

/// B1: `hard_delete_component` decrements one reference per asset row it
/// actually deleted — both assets of a component may share one blob — and a
/// repeated delete of the same version is a no-op that decrements nothing.
/// `hard_delete_all_components` does the same for a whole repository.
#[tokio::test]
async fn hard_delete_component_decrements_only_deleted_refs() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo =
        repository_dao::insert_repository(pool, NewRepository::hosted(format!("hdrepo-{n}")))
            .await
            .expect("repo");
    let sha = format!("hdsha-{n}");
    blob_dao::upsert_pending(pool, &sha, 10, &format!("k/{sha}"))
        .await
        .expect("blob");

    // Three versions; each has two assets referencing the same blob (6 refs).
    let mut tx = pool.begin().await.expect("begin");
    for version in ["1.0.0", "2.0.0", "3.0.0"] {
        let comp = component_dao::insert_component(
            &mut *tx,
            NewComponent {
                repository_id: repo.id,
                name: "pkg".to_string(),
                original_id: "Pkg".to_string(),
                version: version.to_string(),
                version_original: version.to_string(),
                listed: true,
            },
        )
        .await
        .expect("component");
        for path in ["pkg.nupkg", "pkg.nuspec"] {
            asset_dao::insert_asset(
                &mut *tx,
                NewAsset {
                    component_id: comp.id,
                    path: path.to_string(),
                    content_type: "application/octet-stream".to_string(),
                    blob_sha256: sha.clone(),
                    size: 10,
                    sha512_base64: None,
                },
            )
            .await
            .expect("asset");
            blob_dao::commit_and_incref(&mut tx, &sha)
                .await
                .expect("incref");
        }
    }
    tx.commit().await.expect("commit");

    let grace = Duration::seconds(0);
    let mut tx = pool.begin().await.expect("begin");
    assert!(
        component_dao::hard_delete_component(&mut tx, repo.id, "pkg", "1.0.0", grace)
            .await
            .expect("hard delete")
    );
    tx.commit().await.expect("commit");
    let blob = blob_dao::get_blob(pool, &sha)
        .await
        .expect("get")
        .expect("blob");
    assert_eq!(blob.ref_count, 4, "both asset references released");

    let mut tx = pool.begin().await.expect("begin");
    assert!(
        !component_dao::hard_delete_component(&mut tx, repo.id, "pkg", "1.0.0", grace)
            .await
            .expect("repeat hard delete"),
        "a repeated delete finds nothing"
    );
    tx.commit().await.expect("commit");
    let blob = blob_dao::get_blob(pool, &sha)
        .await
        .expect("get")
        .expect("blob");
    assert_eq!(blob.ref_count, 4, "a repeated delete decrements nothing");

    let mut tx = pool.begin().await.expect("begin");
    assert!(component_dao::repository_has_components(&mut *tx, repo.id)
        .await
        .expect("has components"));
    assert_eq!(
        component_dao::hard_delete_all_components(&mut tx, repo.id, grace)
            .await
            .expect("purge"),
        2
    );
    assert!(!component_dao::repository_has_components(&mut *tx, repo.id)
        .await
        .expect("has components"));
    tx.commit().await.expect("commit");

    let blob = blob_dao::get_blob(pool, &sha)
        .await
        .expect("get")
        .expect("blob");
    assert_eq!(blob.ref_count, 0);
    let enqueued: i64 = sqlx::query_scalar("SELECT count(*) FROM blob_outbox WHERE sha256 = $1")
        .bind(&sha)
        .fetch_one(pool)
        .await
        .expect("count");
    assert_eq!(enqueued, 1, "exactly one deferred delete, at zero refs");
}

// ── user / token ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_and_token_round_trip() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let username = format!("user-{n}");

    let user = user_dao::insert_user(
        pool,
        NewUser::local(username.clone(), "argon2-hash".to_string(), true, true),
    )
    .await
    .expect("user");

    assert_eq!(
        user_dao::find_user_by_username(pool, &username)
            .await
            .expect("by name")
            .expect("present")
            .id,
        user.id
    );
    assert_eq!(
        user_dao::find_user_by_id(pool, user.id)
            .await
            .expect("by id")
            .expect("present")
            .username,
        username
    );

    // A local user carries its provenance: source 'local', a password hash, and
    // no external subject.
    assert_eq!(user.auth_source, "local");
    assert_eq!(user.password_hash.as_deref(), Some("argon2-hash"));
    assert_eq!(user.external_subject, None);

    let hash = format!("token-hash-{n}");
    let token = token_dao::insert_token(
        pool,
        NewToken {
            user_id: user.id,
            name: "ci".to_string(),
            token_hash: hash.clone(),
            expires_at: None,
            minted_with_forwarded_credential: false,
        },
    )
    .await
    .expect("token");
    assert!(token.last_used_at.is_none());

    let by_hash = token_dao::find_token_by_hash(pool, &hash)
        .await
        .expect("by hash")
        .expect("present");
    assert_eq!(by_hash.id, token.id);
    assert_eq!(by_hash.user_id, user.id);

    token_dao::touch_last_used(pool, token.id)
        .await
        .expect("touch");
    let touched = token_dao::find_token_by_hash(pool, &hash)
        .await
        .expect("by hash")
        .expect("present");
    assert!(touched.last_used_at.is_some());
}

#[tokio::test]
async fn upstream_basic_user_has_no_local_password() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let username = format!("nexus-{n}");

    // An upstream-basic user is provisioned with NO local password hash and
    // carries provenance (source + external subject).
    let user = user_dao::insert_user(
        pool,
        NewUser {
            username: username.clone(),
            password_hash: None,
            is_admin: false,
            active: true,
            auth_source: "upstream-basic".to_string(),
            external_subject: Some(username.clone()),
        },
    )
    .await
    .expect("upstream user inserts with NULL password_hash");

    assert_eq!(user.password_hash, None);
    assert_eq!(user.auth_source, "upstream-basic");
    assert_eq!(user.external_subject.as_deref(), Some(username.as_str()));

    // Provenance round-trips through a fresh read.
    let reread = user_dao::find_user_by_username(pool, &username)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(reread.password_hash, None);
    assert_eq!(reread.auth_source, "upstream-basic");
    assert_eq!(reread.external_subject.as_deref(), Some(username.as_str()));
}

#[tokio::test]
async fn provision_upstream_user_inserts_then_tracks_authoritative_admin() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let username = format!("up-prov-{n}");

    // First call inserts a passwordless upstream-basic user (non-admin).
    let u1 = user_dao::provision_upstream_user(pool, &username, false, true, None)
        .await
        .expect("provision")
        .expect("row");
    assert_eq!(u1.auth_source, "upstream-basic");
    assert!(u1.password_hash.is_none());
    assert!(u1.active);
    assert!(!u1.is_admin);
    assert_eq!(u1.external_subject.as_deref(), Some(username.as_str()));

    // Authoritative admin suggestion reuses the row AND grants admin.
    let u2 = user_dao::provision_upstream_user(pool, &username, true, true, None)
        .await
        .expect("re-provision grants admin")
        .expect("row");
    assert_eq!(u2.id, u1.id, "same row");
    assert!(u2.is_admin, "admin granted on refresh");

    // A non-authoritative reading never changes the stored admin flag.
    let u3 = user_dao::provision_upstream_user(pool, &username, false, false, None)
        .await
        .expect("re-provision")
        .expect("row");
    assert_eq!(u3.id, u1.id);
    assert!(u3.is_admin, "non-authoritative: admin untouched");

    // An authoritative non-admin reading revokes it.
    let u4 = user_dao::provision_upstream_user(pool, &username, false, true, None)
        .await
        .expect("re-provision")
        .expect("row");
    assert!(!u4.is_admin, "authoritative: admin revoked");
}

#[tokio::test]
async fn provision_upstream_user_does_not_clobber_local_user() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let username = format!("up-prov-local-{n}");

    // Pre-existing LOCAL user with a password.
    user_dao::insert_user(
        pool,
        NewUser::local(username.clone(), "$argon2id$dummy".to_string(), false, true),
    )
    .await
    .expect("insert local");

    // An upstream provision for the same username returns no row (deny) and
    // must NOT null the password, flip auth_source or grant admin.
    let u = user_dao::provision_upstream_user(pool, &username, true, true, None)
        .await
        .expect("provision over local");
    assert!(u.is_none(), "local user is never taken over");
    assert!(user_dao::find_upstream_user(pool, &username, None)
        .await
        .unwrap()
        .is_none());
    let local = user_dao::find_user_by_username(pool, &username)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(local.auth_source, "local", "local provenance preserved");
    assert!(local.password_hash.is_some(), "local password preserved");
    assert!(!local.is_admin, "no admin grant through upstream");
}

// ── proxy_dao ─────────────────────────────────────────────────────────────────

/// Helper: insert a proxy repository and return its id.
async fn proxy_repo(pool: &sqlx::PgPool, suffix: u64) -> i64 {
    repository_dao::insert_repository(pool, NewRepository::proxy(format!("proxy-repo-{suffix}")))
        .await
        .expect("proxy repo")
        .id
}

/// Rows only a download attempt created (never listed or served upstream)
/// are pruned once the repository's negative-cache window lapsed; confirmed
/// and recent rows are kept.
#[tokio::test]
async fn proxy_prune_unconfirmed_drops_only_expired_unconfirmed_rows() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;
    let name = format!("pkg-{n}");

    for v in ["9.0.0", "9.0.1"] {
        proxy_dao::insert_unconfirmed_cached_version(pool, repo_id, &name, v)
            .await
            .unwrap();
    }
    proxy_dao::upsert_cached_versions(pool, repo_id, &name, &["1.0.0".to_string()])
        .await
        .unwrap();
    // 9.0.0 and the confirmed 1.0.0 were first seen long ago; 9.0.1 just now.
    sqlx::query(
        "UPDATE proxy_cached_version SET first_seen_at = now() - interval '1 day' \
         WHERE repository_id = $1 AND version IN ('9.0.0', '1.0.0')",
    )
    .bind(repo_id)
    .execute(pool)
    .await
    .unwrap();

    // A large batch so rows of other tests in the shared database cannot
    // crowd this repository's row out of the batch.
    proxy_dao::prune_unconfirmed(pool, 600, 1_000_000)
        .await
        .unwrap();

    let mut left: Vec<String> =
        sqlx::query_scalar("SELECT version FROM proxy_cached_version WHERE repository_id = $1")
            .bind(repo_id)
            .fetch_all(pool)
            .await
            .unwrap();
    left.sort();
    assert_eq!(left, ["1.0.0", "9.0.1"]);
}

#[tokio::test]
async fn proxy_upsert_cached_version_insert_then_conflict_is_noop() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;

    let new = NewProxyCachedVersion {
        repository_id: repo_id,
        name: format!("pkg-{n}"),
        version: "1.0.0".to_string(),
        listed: true,
        downloaded: false,
        not_found: false,
    };

    // First insert: returns true (row created).
    let inserted = proxy_dao::upsert_cached_version(pool, new.clone())
        .await
        .expect("first upsert");
    assert!(inserted, "first upsert must return true");

    // Second insert with same (repo, name, version): ON CONFLICT DO NOTHING.
    let conflict = proxy_dao::upsert_cached_version(pool, new)
        .await
        .expect("second upsert");
    assert!(!conflict, "ON CONFLICT DO NOTHING must return false");
}

#[tokio::test]
async fn proxy_get_cached_version_returns_inserted_row() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;
    let name = format!("pkg-get-{n}");

    proxy_dao::upsert_cached_version(
        pool,
        NewProxyCachedVersion {
            repository_id: repo_id,
            name: name.clone(),
            version: "2.0.0".to_string(),
            listed: false,
            downloaded: true,
            not_found: false,
        },
    )
    .await
    .expect("upsert");

    let row = proxy_dao::get_cached_version(pool, repo_id, &name, "2.0.0")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(row.repository_id, repo_id);
    assert_eq!(row.name, name);
    assert_eq!(row.version, "2.0.0");
    assert!(!row.listed);
    assert!(row.downloaded);
    assert!(!row.not_found);

    // Missing version returns None.
    let missing = proxy_dao::get_cached_version(pool, repo_id, &name, "9.9.9")
        .await
        .expect("get missing");
    assert!(missing.is_none());
}

#[tokio::test]
async fn proxy_set_upstream_index_insert_then_upsert_updates_resources() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;

    let v1 = serde_json::json!([{"@id": "https://example.com/v1/", "@type": "SearchQueryService"}]);
    let first = proxy_dao::set_upstream_index(pool, repo_id, v1.clone(), Some("etag-1"))
        .await
        .expect("insert");
    assert_eq!(first.repository_id, repo_id);
    assert_eq!(first.resources, v1);
    assert_eq!(first.etag.as_deref(), Some("etag-1"));

    // Upsert with updated resources and etag.
    let v2 = serde_json::json!([{"@id": "https://example.com/v2/", "@type": "SearchQueryService"}]);
    let second = proxy_dao::set_upstream_index(pool, repo_id, v2.clone(), Some("etag-2"))
        .await
        .expect("upsert");
    assert_eq!(second.resources, v2);
    assert_eq!(second.etag.as_deref(), Some("etag-2"));
}

#[tokio::test]
async fn proxy_get_upstream_index_returns_latest() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;

    // Not yet set.
    let missing = proxy_dao::get_upstream_index(pool, repo_id)
        .await
        .expect("get missing");
    assert!(missing.is_none());

    let resources =
        serde_json::json!([{"@id": "https://example.com/", "@type": "RegistrationsBaseUrl"}]);
    proxy_dao::set_upstream_index(pool, repo_id, resources.clone(), None)
        .await
        .expect("set");

    let fetched = proxy_dao::get_upstream_index(pool, repo_id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(fetched.repository_id, repo_id);
    assert_eq!(fetched.resources, resources);
    assert!(fetched.etag.is_none());
}

#[tokio::test]
async fn proxy_lock_cached_version_for_update_blocks_concurrent_tx() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo_id = proxy_repo(pool, n).await;
    let name = format!("pkg-lock-{n}");
    let version = "1.0.0".to_string();

    // Seed the row.
    proxy_dao::upsert_cached_version(
        pool,
        NewProxyCachedVersion {
            repository_id: repo_id,
            name: name.clone(),
            version: version.clone(),
            listed: true,
            downloaded: false,
            not_found: false,
        },
    )
    .await
    .expect("seed");

    // Transaction A locks the row.
    let mut tx_a = pool.begin().await.expect("begin a");
    let locked = proxy_dao::lock_cached_version_for_update(&mut tx_a, repo_id, &name, &version)
        .await
        .expect("lock a")
        .expect("row present");
    assert_eq!(locked.version, version);

    // Transaction B tries to lock the same row with a statement timeout; it
    // must block (and time out) because A still holds the FOR UPDATE lock.
    let mut tx_b = pool.begin().await.expect("begin b");
    sqlx::query("SET LOCAL statement_timeout = '500ms'")
        .execute(&mut *tx_b)
        .await
        .expect("set timeout b");
    let blocked =
        proxy_dao::lock_cached_version_for_update(&mut tx_b, repo_id, &name, &version).await;
    assert!(
        blocked.is_err(),
        "second locker must block (and time out) while A holds FOR UPDATE"
    );
    let _ = tx_b.rollback().await;

    // A releases by committing; row is now free.
    tx_a.commit().await.expect("commit a");

    // Transaction C can now lock the row without timing out.
    let mut tx_c = pool.begin().await.expect("begin c");
    sqlx::query("SET LOCAL statement_timeout = '2s'")
        .execute(&mut *tx_c)
        .await
        .expect("set timeout c");
    let re_locked = proxy_dao::lock_cached_version_for_update(&mut tx_c, repo_id, &name, &version)
        .await
        .expect("lock c")
        .expect("row present c");
    assert_eq!(re_locked.version, version);
    tx_c.commit().await.expect("commit c");
}

/// L6: the nesting-depth guard counts the longest path *above* the group too,
/// not only the depth below the new member.
#[tokio::test]
async fn add_group_member_checked_counts_depth_above_the_group() {
    use forge_db::repository_dao::{self, AddMemberOutcome, NewRepository};

    let pool = common::pool().await;
    let n = common::unique();
    let make = |kind: &'static str| {
        let pool = pool.clone();
        async move {
            let name = format!("depthup-{kind}-{n}-{}", common::unique());
            let new = if kind == "leaf" {
                NewRepository::hosted(name)
            } else {
                NewRepository::group(name)
            };
            repository_dao::insert_repository(&pool, new)
                .await
                .expect("insert repo")
        }
    };
    let a = make("a").await;
    let b = make("b").await;
    let c = make("c").await;
    let mid = make("mid").await;
    let leaf = make("leaf").await;

    // Two ancestor chains above `mid`: a -> b -> mid (2 edges) and c -> mid.
    for (group, member) in [(&a, &b), (&b, &mid), (&c, &mid)] {
        assert_eq!(
            repository_dao::add_group_member_checked(&pool, group.id, member.id, 10, 20)
                .await
                .expect("add"),
            AddMemberOutcome::Added
        );
    }

    // mid -> leaf creates a -> b -> mid -> leaf (3 edges): too deep for 2,
    // although only one edge lies below `mid`.
    assert_eq!(
        repository_dao::add_group_member_checked(&pool, mid.id, leaf.id, 10, 2)
            .await
            .expect("add"),
        AddMemberOutcome::TooDeep,
        "the path above the group counts"
    );
    assert_eq!(
        repository_dao::add_group_member_checked(&pool, mid.id, leaf.id, 10, 3)
            .await
            .expect("add"),
        AddMemberOutcome::Added,
        "3 edges fit a limit of 3"
    );
}

/// Usernames are canonical: the DAO stores and looks names up in canonical
/// form, and the database refuses a second row that differs only in case or
/// Unicode composition even when written around the DAO.
#[tokio::test]
async fn usernames_are_unique_in_canonical_form() {
    use forge_db::user_dao::{self, NewUser};
    let pool = common::pool().await;
    let n = common::unique();
    let user = user_dao::insert_user(
        &pool,
        NewUser::local(format!("  Dora{n} "), "x".into(), false, true),
    )
    .await
    .unwrap();
    assert_eq!(user.username, format!("dora{n}"));
    let found = user_dao::find_user_by_username(&pool, &format!("DORA{n}"))
        .await
        .unwrap()
        .expect("any spelling finds the account");
    assert_eq!(found.id, user.id);

    let raw = sqlx::query(
        "INSERT INTO app_user (username, password_hash, is_admin, active, auth_source) \
         VALUES ($1, 'x', false, true, 'local')",
    )
    .bind(format!("DORA{n}"))
    .execute(&pool)
    .await;
    let err = raw.expect_err("a case variant must violate the canonical unique index");
    assert!(
        err.to_string().contains("app_user_username_canonical_key"),
        "{err}"
    );

    let invalid = user_dao::insert_user(
        &pool,
        NewUser::local("bad\nname".into(), "x".into(), false, true),
    )
    .await;
    assert!(matches!(invalid, Err(sqlx::Error::InvalidArgument(_))));
}

/// Names migration 0021 left non-canonical (its SQL `lower()` follows the
/// database collation and `btrim` trims ASCII spaces only) are brought into
/// the form every lookup uses, so their accounts can sign in again.
#[tokio::test]
async fn stored_usernames_are_brought_into_canonical_form() {
    use forge_db::user_dao::{self, NewUser};
    let pool = common::pool().await;
    let n = common::unique();
    let raw = |name: String| {
        sqlx::query_scalar::<_, i64>(
            "INSERT INTO app_user (username, password_hash, is_admin, active, auth_source) \
             VALUES ($1, 'x', false, true, 'local') RETURNING id",
        )
        .bind(name)
        .fetch_one(&pool)
    };
    // A non-ASCII space btrim kept; a capital a "C" ctype does not lower.
    let spaced = raw(format!("erin{n}\u{a0}")).await.unwrap();
    let upper = raw(format!("Ünal{n}")).await.unwrap();
    // A twin of an account that already holds the canonical name.
    let holder = user_dao::insert_user(
        &pool,
        NewUser::local(format!("fritz{n}"), "x".into(), false, true),
    )
    .await
    .unwrap();
    let twin = raw(format!("fritz{n}\u{2003}")).await.unwrap();

    let repairs = user_dao::canonicalize_stored_usernames(&pool)
        .await
        .unwrap();
    let renamed = |id: i64| repairs.iter().find(|r| r.id == id).map(|r| r.to.clone());
    assert_eq!(renamed(spaced), Some(format!("erin{n}")));
    assert_eq!(renamed(upper), Some(format!("ünal{n}")));
    assert_eq!(renamed(twin), Some(format!("fritz{n}#{twin}")));
    assert_eq!(
        renamed(holder.id),
        None,
        "the canonical holder keeps its name"
    );

    for (spelling, id) in [
        (format!(" ERIN{n} "), spaced),
        (format!("ÜNAL{n}"), upper),
        (format!("Fritz{n}"), holder.id),
    ] {
        let found = user_dao::find_user_by_username(&pool, &spelling)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{spelling} finds its account"));
        assert_eq!(found.id, id, "{spelling}");
    }

    // Idempotent: a second run has nothing left to do for these accounts.
    let again = user_dao::canonicalize_stored_usernames(&pool)
        .await
        .unwrap();
    assert!(again.iter().all(|r| ![spaced, upper, twin].contains(&r.id)));
}
