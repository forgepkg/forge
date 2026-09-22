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
//!     `legacy_open_access` is recorded `true`.
//!
//!   * **Fresh install fails closed.** An empty DB migrating 0001..0007 in
//!     sequence (the bootstrap admin is inserted by the server *after*
//!     migrations) records `legacy_open_access = false`, assigns no roles, and a
//!     roleless user has an empty effective set (deny-all).
//!
//! The upgrade case is exercised faithfully: migrations 0001..0006 are applied
//! first, pre-RBAC rows are seeded, then 0007 runs — reproducing exactly what an
//! upgrading deployment experiences (a non-empty `app_user` at 0007 time).

use forge_db::authz_dao::{self, ADMIN_ROLE, ANONYMOUS_ROLE, AUTHENTICATED_ROLE};
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
async fn fresh_pool() -> (PgPool, ContainerAsync<Postgres>) {
    let container = Postgres::default()
        .with_db_name("forge")
        .with_user("forge")
        .with_password("forge")
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
    (pool, container)
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

    // legacy_open_access recorded true (upgrade detected).
    assert!(
        authz_dao::legacy_open_access(&pool)
            .await
            .expect("read flag"),
        "upgrade must record legacy_open_access = true"
    );

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

    assert!(
        !authz_dao::legacy_open_access(&pool)
            .await
            .expect("read flag"),
        "fresh install must record legacy_open_access = false"
    );

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

    // Re-running the idempotent routine (as the boot path does) must NOT open
    // access on a fresh install: the user stays roleless.
    authz_dao::apply_legacy_migration(&pool)
        .await
        .expect("re-apply legacy migration");

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

#[tokio::test]
async fn apply_legacy_migration_is_idempotent() {
    let (pool, _container) = fresh_pool().await;
    migrator_up_to(RBAC_MIGRATE_VERSION - 1)
        .await
        .run(&pool)
        .await
        .expect("migrate 0001..0006");

    let admin_user: i64 = sqlx::query_scalar(
        "INSERT INTO app_user (username, password_hash, is_admin) VALUES ('a', 'x', true) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed admin");
    sqlx::query(
        "INSERT INTO repository (name, kind, anonymous_read) VALUES ('pub', 'hosted', true)",
    )
    .execute(&pool)
    .await
    .expect("seed repo");

    migrator().await.run(&pool).await.expect("migrate 0007");

    // Capture row counts after the one-shot migration.
    let user_role_count = |pool: PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_role")
            .fetch_one(&pool)
            .await
            .expect("count user_role")
    };
    let grant_count = |pool: PgPool| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM repository_privilege rp JOIN role r ON r.id = rp.role_id WHERE r.name = 'anonymous'",
        )
        .fetch_one(&pool)
        .await
        .expect("count anon grants")
    };

    let ur_before = user_role_count(pool.clone()).await;
    let ag_before = grant_count(pool.clone()).await;
    assert!(
        ur_before > 0 && ag_before > 0,
        "migration applied something"
    );

    // Re-run the boot path twice: counts must not change (pure upserts).
    authz_dao::apply_legacy_migration(&pool)
        .await
        .expect("rerun");
    authz_dao::apply_legacy_migration(&pool)
        .await
        .expect("rerun");

    assert_eq!(
        ur_before,
        user_role_count(pool.clone()).await,
        "re-running must not duplicate user_role rows"
    );
    assert_eq!(
        ag_before,
        grant_count(pool.clone()).await,
        "re-running must not duplicate anonymous grants"
    );

    // The admin user is admin and the anonymous role exists (sanity).
    assert!(authz_dao::user_has_role(&pool, admin_user, ADMIN_ROLE)
        .await
        .expect("query"));
    assert!(authz_dao::role_id_by_name(&pool, ANONYMOUS_ROLE)
        .await
        .expect("query")
        .is_some());
}

/// P1.2: the boot hook applies the legacy mapping only ONCE per install, so an
/// admin role an operator revokes through RBAC is not silently re-synthesized
/// from the legacy `is_admin` column on the next restart.
#[tokio::test]
async fn boot_sync_runs_once_so_revocations_stick() {
    let (pool, _container) = fresh_pool().await;
    migrator_up_to(RBAC_MIGRATE_VERSION - 1)
        .await
        .run(&pool)
        .await
        .expect("migrate 0001..0006");
    let admin_user: i64 = sqlx::query_scalar(
        "INSERT INTO app_user (username, password_hash, is_admin) VALUES ('a', 'x', true) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed admin");
    migrator().await.run(&pool).await.expect("migrate all");

    // First boot: runs (the marker is absent) and records the marker.
    assert!(authz_dao::apply_legacy_migration_once(&pool)
        .await
        .expect("first boot"));
    assert_eq!(
        authz_dao::get_setting(&pool, authz_dao::LEGACY_RBAC_SYNCED_KEY)
            .await
            .expect("setting")
            .as_deref(),
        Some("true")
    );

    // The operator revokes the synthesized admin role.
    let admin_role = authz_dao::role_id_by_name(&pool, ADMIN_ROLE)
        .await
        .expect("query")
        .expect("admin role");
    authz_dao::unassign_role(&pool, admin_user, admin_role)
        .await
        .expect("revoke");

    // Later boots are no-ops: the revocation sticks.
    assert!(!authz_dao::apply_legacy_migration_once(&pool)
        .await
        .expect("second boot"));
    assert!(!authz_dao::user_has_role(&pool, admin_user, ADMIN_ROLE)
        .await
        .expect("query"));
}

/// §12.4 Phase 5 per-creation semantics: on an UPGRADED (legacy_open_access)
/// install a user created *after* boot — by the admin API, OIDC/upstream
/// auto-provision — must inherit the `authenticated` role *immediately* via
/// [`authz_dao::assign_authenticated_if_legacy_open`], not only at the next
/// restart. Without this, a freshly-created user on a slice-1-compatible install
/// would silently lose its read/write reach until the server restarts.
#[tokio::test]
async fn legacy_open_assigns_authenticated_to_new_user() {
    let (pool, _container) = fresh_pool().await;
    migrator_up_to(RBAC_MIGRATE_VERSION - 1)
        .await
        .run(&pool)
        .await
        .expect("migrate 0001..0006");

    // Seed a pre-existing user so 0007 detects an UPGRADE (opens access).
    sqlx::query("INSERT INTO app_user (username, password_hash) VALUES ('old', 'x')")
        .execute(&pool)
        .await
        .expect("seed pre-existing user");
    migrator().await.run(&pool).await.expect("migrate 0007");
    assert!(
        authz_dao::legacy_open_access(&pool)
            .await
            .expect("read flag"),
        "precondition: this is an upgraded (open) install"
    );

    // A user created AFTER the migration ran (the bug scenario: post-boot create).
    let new_user: i64 = sqlx::query_scalar(
        "INSERT INTO app_user (username, password_hash) VALUES ('post-boot', 'x') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("insert post-boot user");

    // Before the per-creation hook runs it holds no role (proves the hook, not the
    // one-shot migration, is what grants it).
    assert!(
        !authz_dao::user_has_role(&pool, new_user, AUTHENTICATED_ROLE)
            .await
            .expect("query"),
        "freshly inserted user has no role until the creation hook runs"
    );

    // The creation hook every user-create path invokes.
    let assigned = authz_dao::assign_authenticated_if_legacy_open(&pool, new_user)
        .await
        .expect("assign on legacy-open install");
    assert!(assigned, "must report it assigned the authenticated role");

    assert!(
        authz_dao::user_has_role(&pool, new_user, AUTHENTICATED_ROLE)
            .await
            .expect("query"),
        "new user must hold authenticated immediately, not after a restart"
    );
    let eff = authz_dao::load_user_effective(&pool, new_user)
        .await
        .expect("effective");
    let has = |action: &str| {
        eff.grants
            .iter()
            .any(|g| g.action == action && g.repository_id.is_none())
    };
    assert!(
        has("read") && has("write"),
        "new user reads/writes everywhere"
    );

    // Idempotent: a second call is a harmless no-op (still true, no dup row).
    assert!(
        authz_dao::assign_authenticated_if_legacy_open(&pool, new_user)
            .await
            .expect("idempotent re-call")
    );
    let role_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM user_role ur JOIN role r ON r.id = ur.role_id WHERE ur.user_id = $1 AND r.name = 'authenticated'",
    )
    .bind(new_user)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(role_rows, 1, "no duplicate authenticated assignment");
}

/// On a FRESH (fail-closed) install the per-creation hook must be a no-op: a new
/// user gets no automatic role, preserving deny-by-default.
#[tokio::test]
async fn fresh_install_create_hook_is_noop() {
    let (pool, _container) = fresh_pool().await;
    migrator().await.run(&pool).await.expect("migrate all");
    assert!(
        !authz_dao::legacy_open_access(&pool)
            .await
            .expect("read flag"),
        "precondition: fresh install is closed"
    );

    let user: i64 = sqlx::query_scalar(
        "INSERT INTO app_user (username, password_hash) VALUES ('fresh', 'x') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("insert user");

    let assigned = authz_dao::assign_authenticated_if_legacy_open(&pool, user)
        .await
        .expect("hook on closed install");
    assert!(!assigned, "closed install must not auto-assign anything");
    assert!(
        !authz_dao::user_has_role(&pool, user, AUTHENTICATED_ROLE)
            .await
            .expect("query"),
        "fresh-install new user stays roleless (deny-by-default)"
    );
    assert!(
        authz_dao::load_user_effective(&pool, user)
            .await
            .expect("effective")
            .grants
            .is_empty(),
        "fresh-install new user has an empty effective set"
    );
}
