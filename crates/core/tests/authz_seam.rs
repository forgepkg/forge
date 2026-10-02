//! Integration tests for the cached authorization seam (§12.4 Phase 3).
//!
//! These drive the real [`Authz`] service (cache → DB) against a Postgres
//! testcontainer with the seeded built-in roles from migration 0005 plus
//! per-test roles/grants/users. They prove:
//!
//! * the principal × repo × action **matrix** through the cached seam matches
//!   the pure evaluator's contract (admin allow-all, ANY-repo, per-repo, deny by
//!   default / fail-closed);
//! * **caching** — a grant changed directly in the DB is *not* observed until
//!   the relevant cache entry is invalidated (proving the seam read from cache,
//!   not the DB), and invalidation (targeted user / anonymous / blanket) makes
//!   the change visible;
//! * **per-token scoping** — a token's stored `scope` intersects (never widens)
//!   its owner's set, applied *after* the cached owner-set lookup;
//! * the **`is_admin` dual-read** fallback grants admin to a slice-1 admin even
//!   with no `admin`-role assignment.
//!
//! Every name is `unique()`-suffixed so tests run in parallel against the shared
//! schema. Each test uses a **fresh `Cache::l1_only`** so cache state never
//! bleeds across tests.

mod common;

use forge_cache::Cache;
use forge_core::auth::authz::Authz;
use forge_core::auth::principal::Principal;
use forge_core::authz as core_authz;
use forge_db::authz_dao::{add_grant, assign_role, insert_content_selector, ANONYMOUS_ROLE};
use forge_db::model::Repository;
use forge_db::repository_dao::{self, NewRepository};
use forge_db::token_dao::{self, NewToken};
use forge_db::user_dao::{self, NewUser};

use common::{pool, unique};

const IP: &str = "127.0.0.1";

fn anon() -> Principal {
    Principal::Anonymous {
        ip: IP.parse().unwrap(),
    }
}

fn user(user_id: i64, is_admin: bool) -> Principal {
    Principal::User {
        user_id,
        token_id: None,
        is_admin,
    }
}

async fn make_role(pool: &sqlx::PgPool, n: u64) -> i64 {
    sqlx::query_scalar!(
        r#"INSERT INTO role (name, description) VALUES ($1, '') RETURNING id"#,
        format!("seamrole-{n}"),
    )
    .fetch_one(pool)
    .await
    .expect("insert role")
}

async fn make_user(pool: &sqlx::PgPool, n: u64, is_admin: bool) -> i64 {
    user_dao::insert_user(
        pool,
        NewUser::local(format!("seamuser-{n}"), "x".into(), is_admin, true),
    )
    .await
    .expect("insert user")
    .id
}

async fn make_repo(pool: &sqlx::PgPool, n: u64) -> Repository {
    repository_dao::insert_repository(pool, NewRepository::hosted(format!("seamrepo-{n}")))
        .await
        .expect("insert repo")
}

#[tokio::test]
async fn matrix_user_with_per_repo_read_grant() {
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache);

    let repo_a = make_repo(&pool, unique()).await;
    let repo_b = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique(), false).await;
    add_grant(&pool, role, Some(repo_a.id), "read", None)
        .await
        .expect("grant");
    assign_role(&pool, uid, role).await.expect("assign");
    let p = user(uid, false);

    assert!(az.can_read(&p, &repo_a).await, "read granted on A");
    assert!(!az.can_write(&p, &repo_a).await, "no write grant on A");
    assert!(!az.can_delete(&p, &repo_a).await, "no delete grant on A");
    assert!(!az.can_admin(&p, &repo_a).await, "not admin");
    assert!(
        !az.can_read(&p, &repo_b).await,
        "no grant on B (fail-closed)"
    );
}

#[tokio::test]
async fn matrix_user_with_no_roles_is_denied() {
    let pool = pool().await;
    let az = Authz::new(pool.clone(), Cache::l1_only(64));
    let repo = make_repo(&pool, unique()).await;
    let uid = make_user(&pool, unique(), false).await;
    let p = user(uid, false);
    assert!(!az.can_read(&p, &repo).await);
    assert!(!az.can_write(&p, &repo).await);
    assert!(!az.can_delete(&p, &repo).await);
    assert!(!az.can_admin(&p, &repo).await);
}

#[tokio::test]
async fn dual_read_is_admin_grants_admin_without_role() {
    // A slice-1 admin (app_user.is_admin = true) with NO admin-role assignment
    // is still admin via the dual-read fallback.
    let pool = pool().await;
    let az = Authz::new(pool.clone(), Cache::l1_only(64));
    let repo = make_repo(&pool, unique()).await;
    let uid = make_user(&pool, unique(), true).await;
    let p = user(uid, true);
    assert!(az.can_admin(&p, &repo).await, "dual-read admin");
    assert!(az.can_read(&p, &repo).await, "admin reads everything");
    assert!(az.can_write(&p, &repo).await, "admin writes everything");
    assert!(az.can_delete(&p, &repo).await, "admin deletes everything");
}

#[tokio::test]
async fn unauthenticated_is_always_denied() {
    let pool = pool().await;
    let az = Authz::new(pool.clone(), Cache::l1_only(64));
    let repo = make_repo(&pool, unique()).await;
    let p = Principal::Unauthenticated;
    assert!(!az.can_read(&p, &repo).await);
    assert!(!az.can_write(&p, &repo).await);
    assert!(!az.can_delete(&p, &repo).await);
    assert!(!az.can_admin(&p, &repo).await);
}

#[tokio::test]
async fn cache_serves_stale_until_user_invalidated() {
    // Prove the seam reads from cache: after warming, a grant added directly in
    // the DB is NOT visible until we invalidate that user's entry.
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone());

    let repo = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique(), false).await;
    assign_role(&pool, uid, role).await.expect("assign");
    let p = user(uid, false);

    // Warm the cache: currently no grants ⇒ deny.
    assert!(!az.can_read(&p, &repo).await, "initially denied");

    // Add a read grant directly in the DB (bypassing any invalidation).
    add_grant(&pool, role, Some(repo.id), "read", None)
        .await
        .expect("grant");

    // Still denied: the seam answers from the warm cache entry.
    assert!(
        !az.can_read(&p, &repo).await,
        "stale cache hides the new grant"
    );

    // Targeted invalidation ⇒ next read reloads and sees the grant.
    core_authz::invalidate_user(&cache, uid).await;
    assert!(
        az.can_read(&p, &repo).await,
        "after invalidation the grant is visible"
    );
}

#[tokio::test]
async fn blanket_invalidation_drops_all_entries() {
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone());

    let repo = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique(), false).await;
    assign_role(&pool, uid, role).await.expect("assign");
    let p = user(uid, false);

    assert!(!az.can_read(&p, &repo).await, "warm: denied");
    add_grant(&pool, role, Some(repo.id), "read", None)
        .await
        .expect("grant");
    assert!(!az.can_read(&p, &repo).await, "stale: still denied");

    // The "epoch roll": blanket-invalidate every cached set.
    core_authz::invalidate_all(&cache).await;
    assert!(az.can_read(&p, &repo).await, "blanket invalidation reloads");
}

#[tokio::test]
async fn anonymous_uses_anonymous_role_grants() {
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone());

    let repo = make_repo(&pool, unique()).await;
    let p = anon();

    // No anonymous grant on this repo ⇒ deny (fresh-install closed default).
    assert!(!az.can_read(&p, &repo).await, "anon denied by default");

    // Grant the built-in anonymous role read on this repo (mirrors the data
    // migration converting anonymous_read into a grant).
    let anon_role = forge_db::authz_dao::role_id_by_name(&pool, ANONYMOUS_ROLE)
        .await
        .expect("query")
        .expect("anonymous role seeded");
    add_grant(&pool, anon_role, Some(repo.id), "read", None)
        .await
        .expect("grant");
    // Invalidate the shared anonymous entry (mirrors the admin mutation path).
    core_authz::invalidate_anonymous(&cache).await;

    assert!(az.can_read(&p, &repo).await, "anon now reads the repo");
    assert!(!az.can_write(&p, &repo).await, "anon never writes");
}

#[tokio::test]
async fn anonymous_never_admin_even_with_admin_grant() {
    // Defense in depth: even a (mis)granted admin on the anonymous role must not
    // make an anonymous caller admin via the short-circuit (the loader forces
    // is_admin=false for anonymous), but a literal admin *grant* on the repo
    // would still satisfy can_admin. Assert the short-circuit is not triggered:
    // an anonymous caller is not allow-all across unrelated repos.
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone());

    let repo = make_repo(&pool, unique()).await;
    let other = make_repo(&pool, unique()).await;
    let anon_role = forge_db::authz_dao::role_id_by_name(&pool, ANONYMOUS_ROLE)
        .await
        .expect("query")
        .expect("seeded");
    add_grant(&pool, anon_role, Some(repo.id), "admin", None)
        .await
        .expect("grant");
    core_authz::invalidate_anonymous(&cache).await;

    let p = anon();
    // The grant is repo-scoped admin on `repo` only — NOT an allow-all
    // short-circuit, so an unrelated repo stays denied.
    assert!(
        !az.can_read(&p, &other).await,
        "anon admin grant on one repo is not allow-all"
    );
}

#[tokio::test]
async fn token_scope_narrows_actions() {
    // Owner has read+write on repo A; a token scoped to read-only may read but
    // not write. The scope is applied after the cached owner-set lookup.
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone());

    let repo = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique(), false).await;
    add_grant(&pool, role, Some(repo.id), "read", None)
        .await
        .expect("grant");
    add_grant(&pool, role, Some(repo.id), "write", None)
        .await
        .expect("grant");
    assign_role(&pool, uid, role).await.expect("assign");

    let token = token_dao::insert_token(
        &pool,
        NewToken {
            user_id: uid,
            name: format!("tok-{}", unique()),
            token_hash: format!("hash-{}", unique()),
            expires_at: None,
        },
    )
    .await
    .expect("token");

    // Set the token scope to read-only via raw SQL (admin API lands in Phase 6).
    sqlx::query!(
        r#"UPDATE token SET scope = $2 WHERE id = $1"#,
        token.id,
        serde_json::json!({ "actions": ["read"] }),
    )
    .execute(&pool)
    .await
    .expect("set scope");

    let scoped = Principal::User {
        user_id: uid,
        token_id: Some(token.id),
        is_admin: false,
    };
    let unscoped = Principal::User {
        user_id: uid,
        token_id: None,
        is_admin: false,
    };

    assert!(az.can_read(&scoped, &repo).await, "scoped token reads");
    assert!(
        !az.can_write(&scoped, &repo).await,
        "read-only scope blocks write"
    );
    // The owner (no token scope) keeps both — proving the scope is per-token and
    // does not poison the shared owner cache entry.
    assert!(az.can_write(&unscoped, &repo).await, "owner still writes");
}

#[tokio::test]
async fn token_scope_cannot_widen_owner() {
    // A token scoped to repo B grants nothing when the owner only has repo A.
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone());

    let repo_a = make_repo(&pool, unique()).await;
    let repo_b = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique(), false).await;
    add_grant(&pool, role, Some(repo_a.id), "read", None)
        .await
        .expect("grant");
    assign_role(&pool, uid, role).await.expect("assign");

    let token = token_dao::insert_token(
        &pool,
        NewToken {
            user_id: uid,
            name: format!("tok-{}", unique()),
            token_hash: format!("hash-{}", unique()),
            expires_at: None,
        },
    )
    .await
    .expect("token");
    sqlx::query!(
        r#"UPDATE token SET scope = $2 WHERE id = $1"#,
        token.id,
        serde_json::json!({ "repositories": [repo_b.id] }),
    )
    .execute(&pool)
    .await
    .expect("set scope");

    let p = Principal::User {
        user_id: uid,
        token_id: Some(token.id),
        is_admin: false,
    };
    assert!(
        !az.can_read(&p, &repo_b).await,
        "scope can't grant a repo the owner lacks"
    );
    assert!(
        !az.can_read(&p, &repo_a).await,
        "repo A is outside the token's repo scope"
    );
}

#[tokio::test]
async fn malformed_token_scope_denies_everything() {
    // A token with a stored scope that is not a valid TokenScope must be
    // fail-closed: it grants nothing (not the owner's full set).
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone());

    let repo = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique(), false).await;
    add_grant(&pool, role, Some(repo.id), "read", None)
        .await
        .expect("grant");
    assign_role(&pool, uid, role).await.expect("assign");

    let token = token_dao::insert_token(
        &pool,
        NewToken {
            user_id: uid,
            name: format!("tok-{}", unique()),
            token_hash: format!("hash-{}", unique()),
            expires_at: None,
        },
    )
    .await
    .expect("token");
    // Not a TokenScope object (a bare string) ⇒ parse error ⇒ deny.
    sqlx::query!(
        r#"UPDATE token SET scope = $2 WHERE id = $1"#,
        token.id,
        serde_json::json!("garbage"),
    )
    .execute(&pool)
    .await
    .expect("set scope");

    let p = Principal::User {
        user_id: uid,
        token_id: Some(token.id),
        is_admin: false,
    };
    assert!(
        !az.can_read(&p, &repo).await,
        "malformed scope is fail-closed (no fallback to owner set)"
    );
}

#[tokio::test]
async fn package_filter_respects_content_selector() {
    // A selector-scoped read grant passes the repo-level gate but the package
    // filter only exposes matching package names.
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone());

    let repo = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique(), false).await;
    let sel = insert_content_selector(
        &pool,
        &format!("sel-{}", unique()),
        &["company.*".to_string()],
        &["company.secret*".to_string()],
    )
    .await
    .expect("selector");
    add_grant(&pool, role, Some(repo.id), "read", Some(sel))
        .await
        .expect("grant");
    assign_role(&pool, uid, role).await.expect("assign");
    let p = user(uid, false);

    assert!(
        az.can_read(&p, &repo).await,
        "selector-scoped read still reaches the repo"
    );
    let f = az.package_filter(&p, &repo).await;
    assert!(f.allows("Company.Tools"), "include matches");
    assert!(!f.allows("Other.Lib"), "outside include hidden");
    assert!(!f.allows("Company.Secret.Keys"), "exclude wins");
}

#[tokio::test]
async fn package_filter_denies_when_no_read_grant() {
    let pool = pool().await;
    let az = Authz::new(pool.clone(), Cache::l1_only(64));
    let repo = make_repo(&pool, unique()).await;
    let uid = make_user(&pool, unique(), false).await;
    let p = user(uid, false);
    let f = az.package_filter(&p, &repo).await;
    assert!(!f.allows("Anything"), "no read grant ⇒ DenyAll");
}

/// Insert a token for `uid` with the given raw `scope` jsonb (`None` = NULL).
async fn make_token(pool: &sqlx::PgPool, uid: i64, scope: Option<serde_json::Value>) -> i64 {
    let token = token_dao::insert_token(
        pool,
        NewToken {
            user_id: uid,
            name: format!("tok-{}", unique()),
            token_hash: format!("hash-{}", unique()),
            expires_at: None,
        },
    )
    .await
    .expect("token");
    sqlx::query!(
        r#"UPDATE token SET scope = $2 WHERE id = $1"#,
        token.id,
        scope,
    )
    .execute(pool)
    .await
    .expect("set scope");
    token.id
}

fn token_of(uid: i64, token_id: i64, is_admin: bool) -> Principal {
    Principal::User {
        user_id: uid,
        token_id: Some(token_id),
        is_admin,
    }
}

/// B4: an admin's API token is not an admin credential unless its scope names
/// `admin`. The unscoped token keeps the admin's read/write/delete reach on the
/// feed; the password/session principal stays a global admin.
#[tokio::test]
async fn unscoped_admin_token_is_not_global_admin() {
    let pool = pool().await;
    let az = Authz::new(pool.clone(), Cache::l1_only(64));
    let repo = make_repo(&pool, unique()).await;
    // Admin through the built-in role (no legacy flag) and through the flag.
    let role_admin = make_user(&pool, unique(), false).await;
    let admin_role = forge_db::authz_dao::role_id_by_name(&pool, "admin")
        .await
        .expect("query")
        .expect("admin role seeded");
    assign_role(&pool, role_admin, admin_role)
        .await
        .expect("assign");
    let flag_admin = make_user(&pool, unique(), true).await;

    for (uid, is_admin) in [(role_admin, false), (flag_admin, true)] {
        assert!(
            az.is_global_admin(&user(uid, is_admin)).await,
            "password/session admin stays admin"
        );

        let unscoped = token_of(uid, make_token(&pool, uid, None).await, is_admin);
        assert!(
            !az.is_global_admin(&unscoped).await,
            "an unscoped token must not be a global admin"
        );
        assert!(!az.can_admin(&unscoped, &repo).await);
        assert!(az.can_read(&unscoped, &repo).await, "feed reach kept");
        assert!(az.can_write(&unscoped, &repo).await, "feed reach kept");
        assert!(az.can_delete(&unscoped, &repo).await, "feed reach kept");

        // `{}` is the same as no scope.
        let empty = token_of(
            uid,
            make_token(&pool, uid, Some(serde_json::json!({}))).await,
            is_admin,
        );
        assert!(!az.is_global_admin(&empty).await);

        let admin_scoped = token_of(
            uid,
            make_token(&pool, uid, Some(serde_json::json!({"actions": ["admin"]}))).await,
            is_admin,
        );
        assert!(
            az.is_global_admin(&admin_scoped).await,
            "an explicitly admin-scoped token is a global admin"
        );

        let repo_scoped_admin = token_of(
            uid,
            make_token(
                &pool,
                uid,
                Some(serde_json::json!({"actions": ["admin"], "repositories": [repo.id]})),
            )
            .await,
            is_admin,
        );
        assert!(
            !az.is_global_admin(&repo_scoped_admin).await,
            "a repo-restricted scope never keeps global admin"
        );
    }
}

/// L6: a stored scope with an unknown key (a typo for `repositories`) is
/// fail-closed instead of an unscoped token.
#[tokio::test]
async fn mistyped_token_scope_denies_everything() {
    let pool = pool().await;
    let az = Authz::new(pool.clone(), Cache::l1_only(64));
    let repo = make_repo(&pool, unique()).await;
    let other = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique(), false).await;
    add_grant(&pool, role, None, "read", None)
        .await
        .expect("grant");
    assign_role(&pool, uid, role).await.expect("assign");

    let tid = make_token(&pool, uid, Some(serde_json::json!({"repos": [repo.id]}))).await;
    let p = token_of(uid, tid, false);
    assert!(!az.can_read(&p, &repo).await, "typo scope grants nothing");
    assert!(!az.can_read(&p, &other).await, "and is not unscoped");
}

/// L6: a signed-in principal without grants may read what an anonymous caller
/// may (the `anonymous_read` flag and the anonymous role's read grants), still
/// cut down to any token scope and never extended to writes.
#[tokio::test]
async fn signed_in_user_reads_what_anonymous_reads() {
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone());

    let flagged = repository_dao::insert_repository(
        &pool,
        NewRepository {
            anonymous_read: true,
            ..NewRepository::hosted(format!("seamrepo-{}", unique()))
        },
    )
    .await
    .expect("insert repo");
    let granted = make_repo(&pool, unique()).await;
    let private = make_repo(&pool, unique()).await;
    let anon_role = forge_db::authz_dao::role_id_by_name(&pool, ANONYMOUS_ROLE)
        .await
        .expect("query")
        .expect("anonymous role seeded");
    let sel = insert_content_selector(
        &pool,
        &format!("sel-{}", unique()),
        &["pub.*".to_string()],
        &[],
    )
    .await
    .expect("selector");
    add_grant(&pool, anon_role, Some(granted.id), "read", Some(sel))
        .await
        .expect("grant");
    core_authz::invalidate_anonymous(&cache).await;

    let uid = make_user(&pool, unique(), false).await;
    let p = user(uid, false);
    assert!(az.can_read(&p, &flagged).await, "anonymous_read flag");
    assert!(
        az.package_filter(&p, &flagged).await.allows("Any.Package"),
        "the flag exposes every package"
    );
    assert!(az.can_read(&p, &granted).await, "anonymous role grant");
    let f = az.package_filter(&p, &granted).await;
    assert!(f.allows("Pub.Lib"), "the grant's selector applies");
    assert!(!f.allows("Priv.Lib"));
    assert!(!az.can_read(&p, &private).await, "no public reach");
    assert!(
        !az.can_write(&p, &flagged).await,
        "public reach is read-only"
    );

    // An unscoped token of that user reads the same public repos.
    let unscoped = token_of(uid, make_token(&pool, uid, None).await, false);
    assert!(az.can_read(&unscoped, &flagged).await);
    assert!(az.can_read(&unscoped, &granted).await);

    // A token scoped to another repository gains nothing from it.
    let scoped = token_of(
        uid,
        make_token(
            &pool,
            uid,
            Some(serde_json::json!({"repositories": [private.id]})),
        )
        .await,
        false,
    );
    assert!(!az.can_read(&scoped, &flagged).await, "outside the scope");
    assert!(!az.can_read(&scoped, &granted).await, "outside the scope");
    assert!(
        !az.package_filter(&scoped, &flagged)
            .await
            .allows("Any.Package"),
        "the package filter is scoped as well"
    );

    // A write-only token gains no read at all.
    let write_only = token_of(
        uid,
        make_token(&pool, uid, Some(serde_json::json!({"actions": ["write"]}))).await,
        false,
    );
    assert!(!az.can_read(&write_only, &flagged).await);

    // Anonymous callers keep the same reach (the flag fast path).
    assert!(az.can_read(&anon(), &flagged).await);
    assert!(az.can_read(&anon(), &granted).await);
    assert!(!az.can_read(&anon(), &private).await);
}
