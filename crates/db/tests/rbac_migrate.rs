//! Integration tests for the §12.4 Phase 5 behavior-preserving data migration
//! (`0007_rbac_migrate.sql`) against a real Postgres testcontainer.
//!
//! Two properties matter and are both proven here:
//!
//!   * **Upgrade preserves slice-1 behavior.** A DB that already had users +
//!     `anonymous_read` repos *before* RBAC existed must keep working after the
//!     migration: existing users still read/write everywhere (the
//!     `authenticated` role), `is_admin` users are still admin (the `admin`
//!     role), and each `anonymous_read` repo becomes an anonymous read grant.
//!     Migration 0038 then removes the mapping routine and its settings and
//!     leaves those assignments alone.
//!
//!   * **Fresh install fails closed.** An empty DB migrating 0001..0007 in
//!     sequence (the bootstrap admin is inserted by the server *after*
//!     migrations) assigns no roles, and a roleless user has an empty effective
//!     set (deny-all).
//!
//! The upgrade case is exercised faithfully: migrations 0001..0006 are applied
//! first, pre-RBAC rows are seeded, then 0007 runs — reproducing exactly what an
//! upgrading deployment experiences (a non-empty `app_user` at 0007 time).

use forge_db::authz_dao::{self, ADMIN_ROLE, AUTHENTICATED_ROLE};
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt},
};

/// Start a dedicated, throwaway Postgres and return a connected (un-migrated)
/// pool. Each test in this file needs full control over *when* migrations run
/// relative to seeding, so it cannot share the common migrated container.
///
/// With `FORGE_TEST_DATABASE_URL` set (no Docker), a fresh empty database is
/// created on that server instead.
async fn fresh_pool() -> (PgPool, Option<ContainerAsync<Postgres>>) {
    if let Ok(admin_url) = std::env::var("FORGE_TEST_DATABASE_URL") {
        return (fresh_external_database(&admin_url).await, None);
    }
    let container = Postgres::default()
        .with_db_name("forge")
        .with_user("forge")
        .with_password("forge")
        .with_name("mirror.gcr.io/library/postgres")
        .with_tag("17")
        .start()
        .await
        .expect("failed to start postgres testcontainer (is Docker running?)");

    let host = container.get_host().await.expect("host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("mapped port");
    let url = format!("postgres://forge:forge@{host}:{port}/forge");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");
    (pool, Some(container))
}

/// Create an empty, uniquely named database next to `admin_url` and connect.
async fn fresh_external_database(admin_url: &str) -> PgPool {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let name = format!(
        "rbac_migrate_{}_{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(admin_url)
        .await
        .expect("connect admin");
    // The name is generated here, never user input.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(r#"CREATE DATABASE "{name}""#)))
        .execute(&admin)
        .await
        .expect("create database");
    admin.close().await;
    let (base, _) = admin_url.rsplit_once('/').expect("database url has a path");
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&format!("{base}/{name}"))
        .await
        .expect("connect fresh database")
}

/// Build a [`Migrator`] over the workspace `migrations/` dir.
async fn migrator() -> Migrator {
    Migrator::new(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../migrations"
    )))
    .await
    .expect("load migrations")
}

/// A [`Migrator`] containing only the migrations with `version <= target` (used
/// to bring a DB up to a pre-RBAC-data state before seeding the upgrade).
async fn migrator_up_to(target: i64) -> Migrator {
    let mut m = migrator().await;
    let subset: Vec<_> = m
        .iter()
        .filter(|mig| mig.version <= target)
        .cloned()
        .collect();
    m.migrations = std::borrow::Cow::Owned(subset);
    m
}

/// `0007_rbac_migrate.sql` carries version 7.
const RBAC_MIGRATE_VERSION: i64 = 7;

#[tokio::test]
async fn upgrade_preserves_slice1_behavior() {
    let (pool, _container) = fresh_pool().await;

    // 1. Bring the DB up to *before* the data migration (schema through 0006:
    //    RBAC tables exist + built-in roles seeded, but inert).
    migrator_up_to(RBAC_MIGRATE_VERSION - 1)
        .await
        .run(&pool)
        .await
        .expect("migrate 0001..0006");

    // 2. Seed pre-RBAC rows exactly as a slice-1 deployment would have: a normal
    //    user, an admin user, a public (anonymous_read) repo, and a private one.
    let normal_user: i64 = sqlx::query_scalar(
        "INSERT INTO app_user (username, password_hash, is_admin) VALUES ('normal', 'x', false) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed normal user");
    let admin_user: i64 = sqlx::query_scalar(
        "INSERT INTO app_user (username, password_hash, is_admin) VALUES ('legacy-admin', 'x', true) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed admin user");
    let public_repo: i64 = sqlx::query_scalar(
        "INSERT INTO repository (name, kind, anonymous_read) VALUES ('public', 'hosted', true) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed public repo");
    let private_repo: i64 = sqlx::query_scalar(
        "INSERT INTO repository (name, kind, anonymous_read) VALUES ('private', 'hosted', false) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed private repo");

    // 3. Now run the data migration (0007). Because app_user is non-empty, it
    //    must detect an UPGRADE and open access.
    migrator().await.run(&pool).await.expect("migrate 0007");

    // 0038 dropped the mapping routine and its install-wide settings.
    for key in ["legacy_open_access", "legacy_rbac_synced"] {
        assert_eq!(
            authz_dao::get_setting(&pool, key).await.expect("setting"),
            None,
            "{key} is gone"
        );
    }
    let routine: Option<String> =
        sqlx::query_scalar("SELECT to_regprocedure('forge_rbac_apply_legacy_migration()')::text")
            .fetch_one(&pool)
            .await
            .expect("look up routine");
    assert_eq!(routine, None, "the mapping routine is dropped");

    // Every existing user holds `authenticated` ⇒ read/write everywhere (slice-1
    // open access preserved).
    for uid in [normal_user, admin_user] {
        assert!(
            authz_dao::user_has_role(&pool, uid, AUTHENTICATED_ROLE)
                .await
                .expect("query"),
            "existing user {uid} must hold the authenticated role after upgrade"
        );
        let eff = authz_dao::load_user_effective(&pool, uid)
            .await
            .expect("effective");
        // authenticated seeds (read, ANY) + (write, ANY): a grant with ANY repo
        // covers both repos for both actions.
        let has = |action: &str| {
            eff.grants
                .iter()
                .any(|g| g.action == action && g.repository_id.is_none())
        };
        assert!(has("read"), "user {uid} keeps read everywhere");
        assert!(has("write"), "user {uid} keeps write everywhere");
    }

    // The is_admin user additionally holds the admin role (still admin).
    assert!(
        authz_dao::user_has_role(&pool, admin_user, ADMIN_ROLE)
            .await
            .expect("query"),
        "is_admin user must hold the admin role after upgrade"
    );
    assert!(
        authz_dao::load_user_effective(&pool, admin_user)
            .await
            .expect("effective")
            .is_admin,
        "admin user's effective set is flagged admin"
    );
    // The normal user is NOT admin.
    assert!(
        !authz_dao::user_has_role(&pool, normal_user, ADMIN_ROLE)
            .await
            .expect("query"),
        "normal user must not become admin"
    );

    // anonymous_read=true repo became an (anonymous role, repo, read) grant; the
    // private repo did not.
    let anon = authz_dao::load_anonymous_effective(&pool)
        .await
        .expect("anon effective");
    assert!(
        anon.grants
            .iter()
            .any(|g| g.action == "read" && g.repository_id == Some(public_repo)),
        "anonymous_read repo must get an anonymous read grant"
    );
    assert!(
        !anon
            .grants
            .iter()
            .any(|g| g.repository_id == Some(private_repo)),
        "the private repo must NOT get an anonymous grant"
    );
    assert!(!anon.is_admin, "anonymous is never admin");
}

#[tokio::test]
async fn fresh_install_fails_closed() {
    let (pool, _container) = fresh_pool().await;

    // Full migration on an EMPTY DB (no users yet — the bootstrap admin is
    // created by the server after migrations). 0007 must detect a fresh install.
    migrator().await.run(&pool).await.expect("migrate all");

    // No anonymous grants on a fresh install ⇒ anonymous is denied everything.
    let anon = authz_dao::load_anonymous_effective(&pool)
        .await
        .expect("anon effective");
    assert!(
        anon.grants.is_empty(),
        "fresh install: anonymous role has no grants (deny-all)"
    );

    // A user created post-migration on a fresh (closed) install holds no roles
    // and has an empty effective set — fail-closed deny.
    let user: i64 = sqlx::query_scalar(
        "INSERT INTO app_user (username, password_hash) VALUES ('first', 'x') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("insert user");

    assert!(
        !authz_dao::user_has_role(&pool, user, AUTHENTICATED_ROLE)
            .await
            .expect("query"),
        "fresh install must NOT auto-assign authenticated to new users"
    );
    let eff = authz_dao::load_user_effective(&pool, user)
        .await
        .expect("effective");
    assert!(
        !eff.is_admin && eff.grants.is_empty(),
        "a roleless user on a fresh install has no privileges (fail-closed)"
    );
}
