//! Integration tests for the cached authorization seam.
//!
//! These drive the real [`Authz`] service (cache → DB) against a Postgres
//! testcontainer with the seeded built-in roles from migration 0005 plus
//! per-test roles/grants/users. They prove:
//!
//! * the principal × repo × level **matrix** through the cached seam matches
//!   the pure evaluator's contract (admin allow-all, ANY-repo, per-repo, each
//!   level including the ones below it, deny by default / fail-closed);
//! * **caching** — a grant changed directly in the DB is *not* observed until
//!   the relevant cache entry is invalidated (proving the seam read from cache,
//!   not the DB), and invalidation (targeted user / anonymous / blanket) makes
//!   the change visible;
//! * **per-token scoping** — a token's stored `scope` intersects (never widens)
//!   its owner's set, applied *after* the cached owner-set lookup.
//!
//! Every name is `unique()`-suffixed so tests run in parallel against the shared
//! schema. Each test uses a **fresh `Cache::l1_only`** so cache state never
//! bleeds across tests.

mod common;

use forge_cache::Cache;
use forge_core::auth::authz::Authz;
use forge_core::auth::principal::Principal;
use forge_core::authz::{self as core_authz, Level};
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

fn user(user_id: i64) -> Principal {
    Principal::User {
        user_id,
        token_id: None,
        method: forge_core::auth::AuthMethod::Password,
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

async fn make_user(pool: &sqlx::PgPool, n: u64) -> i64 {
    user_dao::insert_user(
        pool,
        NewUser::local(format!("seamuser-{n}@example.com"), "x".into(), true),
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
    let uid = make_user(&pool, unique()).await;
    add_grant(&pool, role, Some(repo_a.id), "read", None)
        .await
        .expect("grant");
    assign_role(&pool, uid, role).await.expect("assign");
    let p = user(uid);

    assert!(az.can_read(&p, &repo_a).await, "read granted on A");
    assert!(!az.can_write(&p, &repo_a).await, "no write grant on A");
    assert!(!az.can_delete(&p, &repo_a).await, "no delete grant on A");
    assert!(!az.is_global_admin(&p).await, "not admin");
    assert!(
        !az.can_read(&p, &repo_b).await,
        "no grant on B (fail-closed)"
    );
}

/// Each level includes the ones below it, through the cached seam: a `write`
/// grant reads and writes but does not delete, and its selector filters
/// what it reads as well as what it writes.
#[tokio::test]
async fn matrix_levels_include_the_ones_below() {
    let pool = pool().await;
    let az = Authz::new(pool.clone(), Cache::l1_only(64));

    let writable = make_repo(&pool, unique()).await;
    let removable = make_repo(&pool, unique()).await;
    let scoped = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique()).await;
    let sel = insert_content_selector(
        &pool,
        &format!("sel-{}", unique()),
        &["acme.*".to_string()],
        &[],
    )
    .await
    .expect("selector");
    add_grant(&pool, role, Some(writable.id), "write", None)
        .await
        .expect("grant");
    add_grant(&pool, role, Some(removable.id), "delete", None)
        .await
        .expect("grant");
    add_grant(&pool, role, Some(scoped.id), "write", Some(sel))
        .await
        .expect("grant");
    assign_role(&pool, uid, role).await.expect("assign");
    let p = user(uid);

    assert!(az.can_read(&p, &writable).await, "write includes read");
    assert!(az.can_write(&p, &writable).await);
    assert!(!az.can_delete(&p, &writable).await, "write excludes delete");
    assert!(az.can_read(&p, &removable).await, "delete includes read");
    assert!(az.can_write(&p, &removable).await, "delete includes write");
    assert!(az.can_delete(&p, &removable).await);

    assert!(az.can_read(&p, &scoped).await);
    let read = az.package_filter(&p, &scoped).await;
    assert!(read.allows("Acme.Lib"));
    assert!(
        !read.allows("Other.Lib"),
        "the write grant's selector filters reads"
    );
    let write = az.package_filter_for(&p, &scoped, Level::Write).await;
    assert!(write.allows("Acme.Lib"));
    assert!(!write.allows("Other.Lib"));
    assert!(!az
        .package_filter_for(&p, &scoped, Level::Delete)
        .await
        .allows("Acme.Lib"));
}

#[tokio::test]
async fn matrix_user_with_no_roles_is_denied() {
    let pool = pool().await;
    let az = Authz::new(pool.clone(), Cache::l1_only(64));
    let repo = make_repo(&pool, unique()).await;
    let uid = make_user(&pool, unique()).await;
    let p = user(uid);
    assert!(!az.can_read(&p, &repo).await);
    assert!(!az.can_write(&p, &repo).await);
    assert!(!az.can_delete(&p, &repo).await);
    assert!(!az.is_global_admin(&p).await);
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
    assert!(!az.is_global_admin(&p).await);
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
    let uid = make_user(&pool, unique()).await;
    assign_role(&pool, uid, role).await.expect("assign");
    let p = user(uid);

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
    let uid = make_user(&pool, unique()).await;
    assign_role(&pool, uid, role).await.expect("assign");
    let p = user(uid);

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
    // Defense in depth: an `admin` grant can never make an anonymous caller
    // admin. Administration is no level (#411), so the table refuses one, and
    // the short-circuit is not triggered: an anonymous caller is not
    // allow-all.
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
        .expect_err("an admin grant is refused");
    add_grant(&pool, anon_role, None, "admin", None)
        .await
        .expect_err("on every repository too");
    core_authz::invalidate_anonymous(&cache).await;

    let p = anon();
    assert!(!az.is_global_admin(&p).await, "anon is not admin");
    assert!(!az.can_read(&p, &repo).await, "anon is not allow-all");
    assert!(!az.can_read(&p, &other).await, "anon is not allow-all");
}

#[tokio::test]
async fn token_scope_caps_the_level() {
    // Owner has write on repo A; a token scoped to `read` may read but not
    // write. The scope is applied after the cached owner-set lookup.
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone());

    let repo = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique()).await;
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
            minted_with_forwarded_credential: false,
        },
    )
    .await
    .expect("token");

    // Set the token scope to read-only via raw SQL.
    sqlx::query!(
        r#"UPDATE token SET scope = $2 WHERE id = $1"#,
        token.id,
        serde_json::json!({ "level": "read" }),
    )
    .execute(&pool)
    .await
    .expect("set scope");

    let scoped = Principal::User {
        user_id: uid,
        token_id: Some(token.id),
        method: forge_core::auth::AuthMethod::Token,
    };
    let unscoped = Principal::User {
        user_id: uid,
        token_id: None,
        method: forge_core::auth::AuthMethod::Password,
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
    let uid = make_user(&pool, unique()).await;
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
            minted_with_forwarded_credential: false,
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
        method: forge_core::auth::AuthMethod::Token,
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
    let uid = make_user(&pool, unique()).await;
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
            minted_with_forwarded_credential: false,
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
        method: forge_core::auth::AuthMethod::Token,
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
    let uid = make_user(&pool, unique()).await;
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
    let p = user(uid);

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
    let uid = make_user(&pool, unique()).await;
    let p = user(uid);
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
            minted_with_forwarded_credential: false,
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

fn token_of(uid: i64, token_id: i64) -> Principal {
    Principal::User {
        user_id: uid,
        token_id: Some(token_id),
        method: forge_core::auth::AuthMethod::Token,
    }
}

/// B4: an admin's API token is not an admin credential unless its scope opts
/// in with `admin: true`. The unscoped token keeps the admin's levels on the
/// feed; the password/session principal stays a global admin.
#[tokio::test]
async fn unscoped_admin_token_is_not_global_admin() {
    let pool = pool().await;
    let az = Authz::new(pool.clone(), Cache::l1_only(64));
    let repo = make_repo(&pool, unique()).await;
    let uid = make_user(&pool, unique()).await;
    let admin_role = forge_db::authz_dao::role_id_by_name(&pool, "admin")
        .await
        .expect("query")
        .expect("admin role seeded");
    assign_role(&pool, uid, admin_role).await.expect("assign");

    assert!(
        az.is_global_admin(&user(uid)).await,
        "password/session admin stays admin"
    );

    let unscoped = token_of(uid, make_token(&pool, uid, None).await);
    assert!(
        !az.is_global_admin(&unscoped).await,
        "an unscoped token must not be a global admin"
    );
    assert!(az.can_read(&unscoped, &repo).await, "feed reach kept");
    assert!(az.can_write(&unscoped, &repo).await, "feed reach kept");
    assert!(az.can_delete(&unscoped, &repo).await, "feed reach kept");

    // `{}` is the same as no scope.
    let empty = token_of(
        uid,
        make_token(&pool, uid, Some(serde_json::json!({}))).await,
    );
    assert!(!az.is_global_admin(&empty).await);

    let admin_scoped = token_of(
        uid,
        make_token(&pool, uid, Some(serde_json::json!({"admin": true}))).await,
    );
    assert!(
        az.is_global_admin(&admin_scoped).await,
        "an explicitly admin-scoped token is a global admin"
    );

    // The opt-in keeps the allow-all short-circuit, whatever the level.
    let admin_read = token_of(
        uid,
        make_token(
            &pool,
            uid,
            Some(serde_json::json!({"admin": true, "level": "read"})),
        )
        .await,
    );
    assert!(az.is_global_admin(&admin_read).await);
    assert!(az.can_delete(&admin_read, &repo).await);

    // Without it, a level-scoped token of the admin is capped at its level.
    let read_only = token_of(
        uid,
        make_token(&pool, uid, Some(serde_json::json!({"level": "read"}))).await,
    );
    assert!(!az.is_global_admin(&read_only).await);
    assert!(az.can_read(&read_only, &repo).await);
    assert!(!az.can_write(&read_only, &repo).await, "capped at read");

    let repo_scoped_admin = token_of(
        uid,
        make_token(
            &pool,
            uid,
            Some(serde_json::json!({"admin": true, "repositories": [repo.id]})),
        )
        .await,
    );
    assert!(
        !az.is_global_admin(&repo_scoped_admin).await,
        "a repo-restricted scope never keeps global admin"
    );
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
    let uid = make_user(&pool, unique()).await;
    add_grant(&pool, role, None, "read", None)
        .await
        .expect("grant");
    assign_role(&pool, uid, role).await.expect("assign");

    let tid = make_token(&pool, uid, Some(serde_json::json!({"repos": [repo.id]}))).await;
    let p = token_of(uid, tid);
    assert!(!az.can_read(&p, &repo).await, "typo scope grants nothing");
    assert!(!az.can_read(&p, &other).await, "and is not unscoped");
}

/// A stored scope that still lists `actions` (which `level` and `admin`
/// replaced, #411) is fail-closed instead of an unscoped token.
#[tokio::test]
async fn token_scope_with_actions_denies_everything() {
    let pool = pool().await;
    let az = Authz::new(pool.clone(), Cache::l1_only(64));
    let repo = make_repo(&pool, unique()).await;
    let role = make_role(&pool, unique()).await;
    let uid = make_user(&pool, unique()).await;
    add_grant(&pool, role, None, "delete", None)
        .await
        .expect("grant");
    assign_role(&pool, uid, role).await.expect("assign");

    for scope in [
        serde_json::json!({"actions": ["read"]}),
        serde_json::json!({"actions": null}),
    ] {
        let p = token_of(uid, make_token(&pool, uid, Some(scope)).await);
        assert!(!az.can_read(&p, &repo).await, "grants nothing");
    }
}

/// L6: under `anonymous_mode = "all"` a signed-in principal without grants
/// may read what an anonymous caller may (the `anonymous_read` flag and the
/// anonymous role's grants capped at `read`), still cut down to any token
/// scope and never extended to writes. Without that switch it holds only its
/// own grants.
#[tokio::test]
async fn signed_in_user_reads_what_anonymous_reads() {
    let pool = pool().await;
    let cache = Cache::l1_only(64);
    let az = Authz::new(pool.clone(), cache.clone()).with_public_read_for_signed_in(true);
    let az_default = Authz::new(pool.clone(), cache.clone());

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
    // A higher level than `read` on the anonymous role reaches signed-in
    // callers as `read` only.
    add_grant(&pool, anon_role, Some(granted.id), "write", Some(sel))
        .await
        .expect("grant");
    core_authz::invalidate_anonymous(&cache).await;

    let uid = make_user(&pool, unique()).await;
    let p = user(uid);
    assert!(
        !az_default.can_read(&p, &flagged).await,
        "no public reach for signed-in callers unless anonymous_mode = all"
    );
    assert!(!az_default.can_read(&p, &granted).await);
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
    assert!(
        !az.can_write(&p, &granted).await,
        "the anonymous role's write is capped at read"
    );

    // An unscoped token of that user reads the same public repos.
    let unscoped = token_of(uid, make_token(&pool, uid, None).await);
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
    );
    assert!(!az.can_read(&scoped, &flagged).await, "outside the scope");
    assert!(!az.can_read(&scoped, &granted).await, "outside the scope");
    assert!(
        !az.package_filter(&scoped, &flagged)
            .await
            .allows("Any.Package"),
        "the package filter is scoped as well"
    );

    // Nor does a level raise it.
    let delete = token_of(
        uid,
        make_token(&pool, uid, Some(serde_json::json!({"level": "delete"}))).await,
    );
    assert!(az.can_read(&delete, &flagged).await);
    assert!(!az.can_write(&delete, &flagged).await);

    // Anonymous callers keep the same reach (the flag fast path).
    assert!(az.can_read(&anon(), &flagged).await);
    assert!(az.can_read(&anon(), &granted).await);
    assert!(!az.can_read(&anon(), &private).await);
}
