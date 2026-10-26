//! Integration test: spin up a real Postgres in a container, run the migrations,
//! and assert every expected table exists.
//!
//! Requires Docker to be available on the host running the test.

use sqlx::Row;
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{runners::AsyncRunner, ImageExt},
};

/// Every table the migrations are expected to create. The unlabelled head of
/// the list comes from `0001_init.sql`; every later group is labelled with the
/// migration that creates it.
const EXPECTED_TABLES: &[&str] = &[
    "repository",
    "group_member",
    "blob",
    "blob_ingest",
    "blob_outbox",
    "component",
    "asset",
    "proxy_cached_version",
    "proxy_upstream_index",
    "app_user",
    "token",
    // 0002_retention.sql
    "retention_run",
    "retention_audit",
    // 0003_oidc.sql
    "external_identity",
    "session",
    "oidc_flow",
    // 0004_credforward.sql
    "validated_credential",
    // 0014_validated_credential_tags.sql
    "validated_credential_tag",
    // 0015_auth_success.sql
    "auth_success",
    // 0005_rbac.sql (its `privilege` table is dropped by 0046)
    "role",
    "content_selector",
    "repository_privilege",
    "user_role",
    // 0012_trusted_publish_audit.sql
    "trusted_publish_audit",
    // 0049_trusted_publishers.sql
    "trusted_publisher",
    "workload_api_key_trusted_publisher",
];

/// Columns `0004_credforward.sql` adds to `app_user` (provenance): (table, column).
const EXPECTED_CREDFORWARD_COLUMNS: &[(&str, &str)] = &[
    ("app_user", "auth_source"),
    ("app_user", "external_subject"),
    ("app_user", "last_auth_source_at"),
];

/// Unique constraints `0003_oidc.sql` is expected to enforce: (table, columns).
/// We assert these by attempting a duplicate insert below.
const _OIDC_UNIQUE_DOC: &[(&str, &str)] = &[
    ("external_identity", "(issuer, subject)"),
    ("session", "(token_hash)"),
];

/// Columns `0002_retention.sql` adds to the `0001_init.sql` tables:
/// (table, column).
const EXPECTED_RETENTION_COLUMNS: &[(&str, &str)] = &[
    ("repository", "retention_policy"),
    ("repository", "retention_last_run_at"),
    ("asset", "last_downloaded_at"),
    ("asset", "download_count"),
    ("component", "last_downloaded_at"),
    ("proxy_cached_version", "last_downloaded_at"),
];

#[tokio::test]
async fn migrations_create_all_expected_tables() {
    // Start a throwaway Postgres 17 container matching docker-compose (db/user/pw = forge)
    // — or, with FORGE_TEST_DATABASE_URL (no Docker), a fresh empty database
    // on that server.
    let (url, _container) = match std::env::var("FORGE_TEST_DATABASE_URL") {
        Ok(admin_url) => (fresh_external_database(&admin_url).await, None),
        Err(_) => {
            let container = Postgres::default()
                .with_db_name("forge")
                .with_user("forge")
                .with_password("forge")
                .with_name("mirror.gcr.io/library/postgres")
                .with_tag("17")
                .start()
                .await
                .expect("failed to start postgres testcontainer (is Docker running?)");
            let host = container
                .get_host()
                .await
                .expect("failed to get container host");
            let port = container
                .get_host_port_ipv4(5432)
                .await
                .expect("failed to get mapped port");
            (
                format!("postgres://forge:forge@{host}:{port}/forge"),
                Some(container),
            )
        }
    };

    let pool = forge_db::connect(&url).await.expect("failed to connect");
    forge_db::migrate(&pool).await.expect("migrations failed");

    // Assert every expected table is present in the public schema.
    let rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
    )
    .fetch_all(&pool)
    .await
    .expect("failed to query information_schema.tables");

    let actual: Vec<String> = rows
        .iter()
        .map(|r| r.get::<String, _>("table_name"))
        .collect();

    for expected in EXPECTED_TABLES {
        assert!(
            actual.iter().any(|t| t == expected),
            "expected table `{expected}` to exist after migration; found tables: {actual:?}"
        );
    }

    // Assert the retention columns added to `0001_init.sql` tables exist.
    for (table, column) in EXPECTED_RETENTION_COLUMNS {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2\
             )",
        )
        .bind(table)
        .bind(column)
        .fetch_one(&pool)
        .await
        .expect("failed to query information_schema.columns");

        assert!(
            exists,
            "expected column `{table}.{column}` to exist after the retention migration"
        );
    }

    // Assert the credential-forwarding provenance columns exist (0004).
    for (table, column) in EXPECTED_CREDFORWARD_COLUMNS {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                 SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2\
             )",
        )
        .bind(table)
        .bind(column)
        .fetch_one(&pool)
        .await
        .expect("failed to query information_schema.columns");

        assert!(
            exists,
            "expected column `{table}.{column}` to exist after the credforward migration"
        );
    }

    // `app_user.password_hash` must now be NULLABLE (0004 dropped NOT NULL).
    let password_hash_nullable: String = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'app_user' \
           AND column_name = 'password_hash'",
    )
    .fetch_one(&pool)
    .await
    .expect("failed to query password_hash nullability");
    assert_eq!(
        password_hash_nullable, "YES",
        "app_user.password_hash should be nullable after 0004"
    );

    // `repository.retention_policy` is jsonb and accepts a well-formed policy
    // document (sanity check that the column type is usable from SQL).
    sqlx::query(
        "INSERT INTO repository (name, kind, retention_policy) \
         VALUES ($1, 'hosted', $2::jsonb)",
    )
    .bind("retention-jsonb-test")
    .bind(
        r#"{"version":1,"enabled":true,"dry_run_only":false,
            "min_run_interval_seconds":3600,
            "rules":[{"id":"r1","action":"hard_delete","release_type":"any",
                      "criteria":{"keep_last_n":10,"older_than_days":90}}]}"#,
    )
    .execute(&pool)
    .await
    .expect("retention_policy column should accept a jsonb policy document");

    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT retention_policy FROM repository WHERE name = $1")
            .bind("retention-jsonb-test")
            .fetch_one(&pool)
            .await
            .expect("failed to read back stored retention_policy");

    assert_eq!(
        stored["version"], 1,
        "round-tripped retention_policy jsonb should preserve its shape"
    );

    // retention_run upsert + lazy creation works (PK = repository_id).
    let repo_id: i64 = sqlx::query_scalar("SELECT id FROM repository WHERE name = $1")
        .bind("retention-jsonb-test")
        .fetch_one(&pool)
        .await
        .expect("failed to read repo id");

    sqlx::query("INSERT INTO retention_run (repository_id) VALUES ($1)")
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("retention_run row should be insertable for a repository");

    // retention_audit row referencing the same repo is insertable.
    sqlx::query(
        "INSERT INTO retention_audit \
             (repository_id, run_id, rule_id, action, target_kind, package_name, version, reason) \
         VALUES ($1, gen_random_uuid(), 'r1', 'hard_delete', 'component', 'Sample.Lib', '1.0.0', '{}'::jsonb)",
    )
    .bind(repo_id)
    .execute(&pool)
    .await
    .expect("retention_audit row should be insertable");

    // -----------------------------------------------------------------------
    // 0003_oidc.sql: external_identity / session / oidc_flow round-trips
    // -----------------------------------------------------------------------

    // A user to attach an external identity + session to.
    let user_id: i64 = sqlx::query_scalar(
        "INSERT INTO app_user (username, password_hash) VALUES ('oidc-user', 'x') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("app_user insertable");

    // external_identity links (issuer, subject) -> app_user.
    let ext_id: i64 = sqlx::query_scalar(
        "INSERT INTO external_identity (user_id, issuer, subject, email, display_name) \
         VALUES ($1, 'https://issuer.example/v2.0', 'sub-abc', 'u@example.com', 'OIDC User') \
         RETURNING id",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("external_identity row should be insertable");

    // UNIQUE (issuer, subject) is enforced: a duplicate (iss, sub) must fail.
    let dup = sqlx::query(
        "INSERT INTO external_identity (user_id, issuer, subject) \
         VALUES ($1, 'https://issuer.example/v2.0', 'sub-abc')",
    )
    .bind(user_id)
    .execute(&pool)
    .await;
    assert!(
        dup.is_err(),
        "external_identity must enforce UNIQUE (issuer, subject)"
    );

    // session row referencing the user + external identity, with the hashed
    // cookie secret (token_hash) and CSRF secret.
    sqlx::query(
        "INSERT INTO session \
             (user_id, external_identity_id, token_hash, csrf_secret, idle_expiry, absolute_expiry) \
         VALUES ($1, $2, 'sha256-of-cookie', 'csrf-secret', now() + interval '8 hours', now() + interval '7 days')",
    )
    .bind(user_id)
    .bind(ext_id)
    .execute(&pool)
    .await
    .expect("session row should be insertable");

    // UNIQUE (token_hash) is enforced.
    let dup_session = sqlx::query(
        "INSERT INTO session (user_id, token_hash, csrf_secret, idle_expiry, absolute_expiry) \
         VALUES ($1, 'sha256-of-cookie', 'csrf2', now() + interval '8 hours', now() + interval '7 days')",
    )
    .bind(user_id)
    .execute(&pool)
    .await;
    assert!(
        dup_session.is_err(),
        "session must enforce UNIQUE (token_hash)"
    );

    // oidc_flow: text `state` PK is the single-use auth-code-flow row. A DELETE
    // ... RETURNING consumes it exactly once, even across instances.
    sqlx::query(
        "INSERT INTO oidc_flow (state, nonce, pkce_verifier, redirect_to, expires_at) \
         VALUES ('state-xyz', 'nonce-1', 'verifier-1', '/', now() + interval '10 minutes')",
    )
    .execute(&pool)
    .await
    .expect("oidc_flow row should be insertable");

    let first: Option<(String, String)> = sqlx::query_as(
        "DELETE FROM oidc_flow WHERE state = $1 AND expires_at > now() \
         RETURNING nonce, pkce_verifier",
    )
    .bind("state-xyz")
    .fetch_optional(&pool)
    .await
    .expect("oidc_flow consume query runs");
    assert_eq!(
        first,
        Some(("nonce-1".to_string(), "verifier-1".to_string())),
        "first consume returns the row"
    );

    let second: Option<(String, String)> = sqlx::query_as(
        "DELETE FROM oidc_flow WHERE state = $1 AND expires_at > now() \
         RETURNING nonce, pkce_verifier",
    )
    .bind("state-xyz")
    .fetch_optional(&pool)
    .await
    .expect("oidc_flow consume query runs");
    assert!(
        second.is_none(),
        "second consume returns nothing (single-use / replay protection)"
    );

    // -----------------------------------------------------------------------
    // 0004_credforward.sql: app_user provenance + validated_credential
    // -----------------------------------------------------------------------

    // Existing rows backfilled to auth_source = 'local' via the DEFAULT.
    let backfilled: String =
        sqlx::query_scalar("SELECT auth_source FROM app_user WHERE username = 'oidc-user'")
            .fetch_one(&pool)
            .await
            .expect("read backfilled auth_source");
    assert_eq!(
        backfilled, "local",
        "existing app_user rows backfill to auth_source = 'local'"
    );

    // CHECK app_user_local_password_hash_check: a 'local' user with a NULL
    // password_hash is rejected.
    let local_null = sqlx::query(
        "INSERT INTO app_user (username, password_hash, auth_source) \
         VALUES ('local-no-hash', NULL, 'local')",
    )
    .execute(&pool)
    .await;
    assert!(
        local_null.is_err(),
        "a local user with NULL password_hash must violate the CHECK"
    );

    // ... but an upstream-basic user with a NULL password_hash is allowed
    // (no local password), and external_subject is settable.
    sqlx::query(
        "INSERT INTO app_user (username, password_hash, auth_source, external_subject) \
         VALUES ('nexus-user', NULL, 'upstream-basic', 'nexus-user')",
    )
    .execute(&pool)
    .await
    .expect("upstream-basic user with NULL password_hash should be insertable");

    // CHECK app_user_auth_source_check: an unknown auth_source is rejected.
    let bad_source = sqlx::query(
        "INSERT INTO app_user (username, password_hash, auth_source) \
         VALUES ('bad-source', NULL, 'ldap')",
    )
    .execute(&pool)
    .await;
    assert!(
        bad_source.is_err(),
        "an unknown auth_source value must violate the CHECK"
    );

    // validated_credential round-trips a verdict; the plaintext password is
    // never a column — only the HMAC.
    sqlx::query(
        "INSERT INTO validated_credential \
             (provider_id, username, cred_hmac, verdict, expires_at) \
         VALUES ('upstream-basic', 'nexus-user', 'deadbeefhmac', true, now() + interval '5 minutes')",
    )
    .execute(&pool)
    .await
    .expect("validated_credential row should be insertable");

    // UNIQUE (provider_id, username, cred_hmac) is enforced.
    let dup_vc = sqlx::query(
        "INSERT INTO validated_credential \
             (provider_id, username, cred_hmac, verdict, expires_at) \
         VALUES ('upstream-basic', 'nexus-user', 'deadbeefhmac', false, now() + interval '5 minutes')",
    )
    .execute(&pool)
    .await;
    assert!(
        dup_vc.is_err(),
        "validated_credential must enforce UNIQUE (provider_id, username, cred_hmac)"
    );

    // The expiry sweep deletes only expired rows. Insert an already-expired row,
    // then DELETE ... WHERE expires_at < now() and assert it removes exactly the
    // expired one (the unexpired row above survives).
    sqlx::query(
        "INSERT INTO validated_credential \
             (provider_id, username, cred_hmac, verdict, expires_at) \
         VALUES ('upstream-basic', 'nexus-user', 'expiredhmac', true, now() - interval '1 minute')",
    )
    .execute(&pool)
    .await
    .expect("expired validated_credential row should be insertable");

    let reaped = sqlx::query("DELETE FROM validated_credential WHERE expires_at < now()")
        .execute(&pool)
        .await
        .expect("sweep query runs");
    assert_eq!(
        reaped.rows_affected(),
        1,
        "sweep deletes exactly the one expired validated_credential row"
    );

    let survivors: i64 =
        sqlx::query_scalar("SELECT count(*) FROM validated_credential WHERE expires_at >= now()")
            .fetch_one(&pool)
            .await
            .expect("count surviving rows");
    assert_eq!(
        survivors, 1,
        "the unexpired validated_credential row survives the sweep"
    );

    // -----------------------------------------------------------------------
    // 0005_rbac.sql: seeded built-in roles + grants, as levels since 0046
    // -----------------------------------------------------------------------

    // 0046 dropped the action vocabulary: a grant gives a level.
    let privilege: Option<String> = sqlx::query_scalar("SELECT to_regclass('privilege')::text")
        .fetch_one(&pool)
        .await
        .expect("look up privilege");
    assert_eq!(privilege, None, "the privilege table is dropped");

    // The level column holds the three levels only.
    let admin_role_id: i64 = sqlx::query_scalar("SELECT id FROM role WHERE name = 'admin'")
        .fetch_one(&pool)
        .await
        .expect("admin role exists");
    for level in ["frobnicate", "admin"] {
        let bad_level = sqlx::query(
            "INSERT INTO repository_privilege (role_id, repository_id, level) VALUES ($1, NULL, $2)",
        )
        .bind(admin_role_id)
        .bind(level)
        .execute(&pool)
        .await;
        assert!(
            bad_level.is_err(),
            "repository_privilege.level must refuse {level:?}"
        );
    }

    // The three built-in roles exist and are flagged builtin = true.
    for name in ["admin", "authenticated", "anonymous"] {
        let builtin: bool = sqlx::query_scalar("SELECT builtin FROM role WHERE name = $1")
            .bind(name)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|_| panic!("built-in role `{name}` must exist"));
        assert!(builtin, "role `{name}` must be flagged builtin");
    }

    // role.name is UNIQUE.
    let dup_role = sqlx::query("INSERT INTO role (name) VALUES ('admin')")
        .execute(&pool)
        .await;
    assert!(dup_role.is_err(), "role.name must be UNIQUE");

    // Seeded grants: admin has none (administration is the role itself);
    // authenticated has (ANY, write); anonymous has none (the data migration
    // adds its grants).
    let admin_grants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM repository_privilege rp JOIN role r ON r.id = rp.role_id \
         WHERE r.name = 'admin'",
    )
    .fetch_one(&pool)
    .await
    .expect("count admin grants");
    assert_eq!(admin_grants, 0, "the admin role holds no grant");

    let authenticated_grants: Vec<String> = sqlx::query_scalar(
        "SELECT rp.level FROM repository_privilege rp JOIN role r ON r.id = rp.role_id \
         WHERE r.name = 'authenticated' AND rp.repository_id IS NULL ORDER BY rp.level",
    )
    .fetch_all(&pool)
    .await
    .expect("read authenticated grants");
    assert_eq!(
        authenticated_grants,
        vec!["write".to_string()],
        "authenticated role holds (ANY, write)"
    );

    let anon_grant_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM repository_privilege rp JOIN role r ON r.id = rp.role_id \
         WHERE r.name = 'anonymous'",
    )
    .fetch_one(&pool)
    .await
    .expect("count anonymous grants");
    assert_eq!(
        anon_grant_count, 0,
        "anonymous role seeds no grants in 0005_rbac.sql"
    );

    // The COALESCE-based unique index allows one grant per (role, ANY,
    // no-selector), whatever its level: a second one must fail.
    let authenticated_role_id: i64 =
        sqlx::query_scalar("SELECT id FROM role WHERE name = 'authenticated'")
            .fetch_one(&pool)
            .await
            .expect("authenticated role exists");
    let dup_grant = sqlx::query(
        "INSERT INTO repository_privilege (role_id, repository_id, level) VALUES ($1, NULL, 'read')",
    )
    .bind(authenticated_role_id)
    .execute(&pool)
    .await;
    assert!(
        dup_grant.is_err(),
        "repository_privilege_uq must allow one grant per (role, ANY, no-selector)"
    );

    // 0013: issuer routing is unambiguous among enabled WIF realms, including
    // raw rows that differ only by a trailing slash.
    sqlx::query(
        r#"INSERT INTO auth_realm (kind, name, enabled, priority, config)
           VALUES ('workload_identity', 'wif-one', true, 100,
                   '{"issuer":"https://issuer.example"}'::jsonb)"#,
    )
    .execute(&pool)
    .await
    .expect("first enabled WIF issuer is accepted");
    let duplicate_wif_issuer = sqlx::query(
        r#"INSERT INTO auth_realm (kind, name, enabled, priority, config)
           VALUES ('workload_identity', 'wif-two', true, 110,
                   '{"issuer":"  https://issuer.example/  "}'::jsonb)"#,
    )
    .execute(&pool)
    .await;
    let duplicate_wif_issuer =
        duplicate_wif_issuer.expect_err("enabled WIF issuer must be unique after normalization");
    match duplicate_wif_issuer {
        sqlx::Error::Database(error) => {
            assert_eq!(error.code().as_deref(), Some("23505"));
            assert_eq!(
                error.constraint(),
                Some("auth_realm_enabled_wif_issuer_uq"),
                "0013's DB index, not only the API pre-check, must reject the duplicate"
            );
        }
        other => panic!("expected unique-constraint error, got {other:?}"),
    }
}

/// Create an empty, uniquely named database next to `admin_url`; return its URL.
async fn fresh_external_database(admin_url: &str) -> String {
    let name = format!("migrations_{}", std::process::id());
    let admin = forge_db::connect(admin_url).await.expect("connect admin");
    // The name is generated here, never user input.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(r#"CREATE DATABASE "{name}""#)))
        .execute(&admin)
        .await
        .expect("create database");
    admin.close().await;
    let (base, _) = admin_url.rsplit_once('/').expect("database url has a path");
    format!("{base}/{name}")
}
