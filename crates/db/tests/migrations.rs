//! Integration test: spin up a real Postgres in a container, run the migrations,
//! and assert every expected table exists; and refuse a database an earlier
//! build created.
//!
//! Requires Docker to be available on the host running the test.

use sqlx::Row;
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt},
};

/// Every table the migrations are expected to create, grouped by domain.
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
    // retention
    "retention_run",
    "retention_audit",
    // OIDC login
    "external_identity",
    "session",
    "oidc_flow",
    // credential forwarding
    "validated_credential",
    "validated_credential_tag",
    "auth_success",
    // RBAC
    "role",
    "content_selector",
    "repository_privilege",
    "user_role",
    // trusted publishing
    "trusted_publish_audit",
    "trusted_publisher",
    "workload_api_key_trusted_publisher",
];

/// The credential-forwarding provenance columns of `app_user`: (table, column).
const EXPECTED_CREDFORWARD_COLUMNS: &[(&str, &str)] = &[
    ("app_user", "auth_source"),
    ("app_user", "external_subject"),
    ("app_user", "last_auth_source_at"),
];

/// Unique constraints the OIDC login tables are expected to enforce: (table, columns).
/// We assert these by attempting a duplicate insert below.
const _OIDC_UNIQUE_DOC: &[(&str, &str)] = &[
    ("external_identity", "(issuer, subject)"),
    ("session", "(token_hash)"),
];

/// The retention columns of the repository and content tables: (table, column).
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
    let (server, _container) = server().await;
    let url = fresh_database(&server, "migrations").await;

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

    // Assert the retention columns exist.
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
            "expected column `{table}.{column}` to exist for retention"
        );
    }

    // Assert the credential-forwarding provenance columns exist.
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
            "expected column `{table}.{column}` to exist for credential forwarding"
        );
    }

    // `app_user.password_hash` is NULLABLE: an account of another realm has no
    // local password.
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
        "app_user.password_hash should be nullable"
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
    // OIDC login: external_identity / session / oidc_flow round-trips
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
    // Credential forwarding: app_user provenance + validated_credential
    // -----------------------------------------------------------------------

    // A row inserted without auth_source is 'local' (the DEFAULT).
    let auth_source: String =
        sqlx::query_scalar("SELECT auth_source FROM app_user WHERE username = 'oidc-user'")
            .fetch_one(&pool)
            .await
            .expect("read default auth_source");
    assert_eq!(
        auth_source, "local",
        "app_user.auth_source defaults to 'local'"
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

    // A trusted-header realm and its accounts (#506): an account has no
    // local password.
    let realm_id: i64 = sqlx::query_scalar(
        "INSERT INTO auth_realm (kind, name, priority) \
         VALUES ('trusted_header', 'sso-proxy', 90) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("a trusted_header realm is insertable");
    sqlx::query(
        "INSERT INTO app_user (username, password_hash, auth_source, realm_id) \
         VALUES ('proxied@example.com', NULL, 'trusted-header', $1)",
    )
    .bind(realm_id)
    .execute(&pool)
    .await
    .expect("a trusted-header account without a password is insertable");
    let with_password = sqlx::query(
        "INSERT INTO app_user (username, password_hash, auth_source, realm_id) \
         VALUES ('proxied2@example.com', 'x', 'trusted-header', $1)",
    )
    .bind(realm_id)
    .execute(&pool)
    .await;
    assert!(
        with_password.is_err(),
        "a trusted-header account with a password must violate the CHECK"
    );

    // Service accounts (#508): the accounts that exist are users; a service
    // account has the source 'service', no password, invitation or email,
    // belongs to a trusted-header realm or to none, keeps its kind, never
    // holds `admin` and is never linked to an identity.
    let kind: String =
        sqlx::query_scalar("SELECT kind FROM app_user WHERE username = 'proxied@example.com'")
            .fetch_one(&pool)
            .await
            .expect("read the default kind");
    assert_eq!(kind, "user", "app_user.kind defaults to 'user'");
    let service_id: i64 = sqlx::query_scalar(
        "INSERT INTO app_user (username, kind, auth_source, realm_id, description) \
         VALUES ('ci@example.com', 'service', 'service', $1, 'CI') RETURNING id",
    )
    .bind(realm_id)
    .fetch_one(&pool)
    .await
    .expect("a service account of a trusted-header realm is insertable");
    sqlx::query(
        "INSERT INTO app_user (username, kind, auth_source) \
         VALUES ('build@example.com', 'service', 'service')",
    )
    .execute(&pool)
    .await
    .expect("a service account of no realm is insertable");
    let oidc_realm: i64 = sqlx::query_scalar(
        "INSERT INTO auth_realm (kind, name, priority) \
         VALUES ('oidc', 'idp-for-service-accounts', 91) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("an oidc realm is insertable");
    for (what, sql) in [
        (
            "a password",
            "INSERT INTO app_user (username, kind, auth_source, password_hash) \
             VALUES ('svc1@example.com', 'service', 'service', 'x')",
        ),
        (
            "an email",
            "INSERT INTO app_user (username, kind, auth_source, email) \
             VALUES ('svc2@example.com', 'service', 'service', 'svc2@example.com')",
        ),
        (
            "an invitation",
            "INSERT INTO app_user (username, kind, auth_source, invited) \
             VALUES ('svc3@example.com', 'service', 'service', true)",
        ),
        (
            "another source",
            "INSERT INTO app_user (username, kind, auth_source) \
             VALUES ('svc4@example.com', 'service', 'trusted-header')",
        ),
        (
            "a user of the source 'service'",
            "INSERT INTO app_user (username, auth_source) \
             VALUES ('svc5@example.com', 'service')",
        ),
    ] {
        let refused = sqlx::query(sql).execute(&pool).await;
        assert!(refused.is_err(), "a service account with {what} is refused");
    }
    let other_realm = sqlx::query(
        "INSERT INTO app_user (username, kind, auth_source, realm_id) \
         VALUES ('svc6@example.com', 'service', 'service', $1)",
    )
    .bind(oidc_realm)
    .execute(&pool)
    .await;
    assert!(
        other_realm.is_err(),
        "a service account belongs to no realm of another kind"
    );
    let kind_change = sqlx::query(
        "UPDATE app_user SET kind = 'user', auth_source = 'trusted-header' WHERE id = $1",
    )
    .bind(service_id)
    .execute(&pool)
    .await;
    assert!(kind_change.is_err(), "a service account stays one");
    let admin = sqlx::query(
        "INSERT INTO user_role (user_id, role_id) \
         SELECT $1, id FROM role WHERE name = 'admin'",
    )
    .bind(service_id)
    .execute(&pool)
    .await;
    assert!(
        admin.is_err(),
        "a service account cannot hold the admin role"
    );
    sqlx::query(
        "INSERT INTO user_role (user_id, role_id) \
         SELECT $1, id FROM role WHERE name = 'writer'",
    )
    .bind(service_id)
    .execute(&pool)
    .await
    .expect("a service account holds other roles");
    let linked = sqlx::query(
        "INSERT INTO external_identity (user_id, issuer, subject) \
         VALUES ($1, 'https://idp.example.com', 'ci')",
    )
    .bind(service_id)
    .execute(&pool)
    .await;
    assert!(
        linked.is_err(),
        "a service account is never linked to an identity"
    );

    // Nor does an account of a trusted-header realm hold `admin` (#547); it
    // holds other roles.
    let proxied_id: i64 =
        sqlx::query_scalar("SELECT id FROM app_user WHERE username = 'proxied@example.com'")
            .fetch_one(&pool)
            .await
            .expect("read the trusted-header account");
    let admin = sqlx::query(
        "INSERT INTO user_role (user_id, role_id) \
         SELECT $1, id FROM role WHERE name = 'admin'",
    )
    .bind(proxied_id)
    .execute(&pool)
    .await;
    assert!(
        admin.is_err(),
        "an account of a trusted-header realm cannot hold the admin role"
    );
    sqlx::query(
        "INSERT INTO user_role (user_id, role_id) \
         SELECT $1, id FROM role WHERE name = 'writer'",
    )
    .bind(proxied_id)
    .execute(&pool)
    .await
    .expect("an account of a trusted-header realm holds other roles");

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
    // RBAC: the seeded built-in roles and their grants
    // -----------------------------------------------------------------------

    // A grant gives a level: there is no vocabulary of verbs.
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

    // The three built-in roles exist and are flagged builtin = true, and
    // the pre-RBAC `authenticated` role is gone (#499).
    for name in ["admin", "anonymous", "writer"] {
        let builtin: bool = sqlx::query_scalar("SELECT builtin FROM role WHERE name = $1")
            .bind(name)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|_| panic!("built-in role `{name}` must exist"));
        assert!(builtin, "role `{name}` must be flagged builtin");
    }
    let roles: i64 = sqlx::query_scalar("SELECT count(*) FROM role")
        .fetch_one(&pool)
        .await
        .expect("count roles");
    assert_eq!(roles, 3, "no other role is seeded");

    // role.name is UNIQUE.
    let dup_role = sqlx::query("INSERT INTO role (name) VALUES ('admin')")
        .execute(&pool)
        .await;
    assert!(dup_role.is_err(), "role.name must be UNIQUE");

    // Seeded grants: admin has none (administration is the role itself);
    // writer has (ANY, write); anonymous has none.
    let admin_grants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM repository_privilege rp JOIN role r ON r.id = rp.role_id \
         WHERE r.name = 'admin'",
    )
    .fetch_one(&pool)
    .await
    .expect("count admin grants");
    assert_eq!(admin_grants, 0, "the admin role holds no grant");

    // writer (#318): `write` (which includes `read`) on every repository and
    // nothing else: no delete, no admin.
    let writer_grants: Vec<(Option<i64>, Option<i64>, String)> = sqlx::query_as(
        "SELECT rp.repository_id, rp.selector_id, rp.level \
         FROM repository_privilege rp JOIN role r ON r.id = rp.role_id \
         WHERE r.name = 'writer'",
    )
    .fetch_all(&pool)
    .await
    .expect("read writer grants");
    assert_eq!(
        writer_grants,
        vec![(None, None, "write".to_string())],
        "writer role holds (ANY, write) only"
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
        "the anonymous role is seeded without grants"
    );

    // The COALESCE-based unique index allows one grant per (role, ANY,
    // no-selector), whatever its level: a second one must fail.
    let writer_role_id: i64 = sqlx::query_scalar("SELECT id FROM role WHERE name = 'writer'")
        .fetch_one(&pool)
        .await
        .expect("writer role exists");
    let dup_grant = sqlx::query(
        "INSERT INTO repository_privilege (role_id, repository_id, level) VALUES ($1, NULL, 'read')",
    )
    .bind(writer_role_id)
    .execute(&pool)
    .await;
    assert!(
        dup_grant.is_err(),
        "repository_privilege_uq must allow one grant per (role, ANY, no-selector)"
    );

    // Issuer routing is unambiguous among enabled WIF realms, including
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
                "the DB index, not only the API pre-check, must reject the duplicate"
            );
        }
        other => panic!("expected unique-constraint error, got {other:?}"),
    }
}

/// 2.0.0's baseline replaced the migrations of 1.x and of the builds before
/// it: a database they created is refused with a message that names the
/// cause (sqlx alone would say "migration 1 was previously applied but has
/// been modified"), and nothing is migrated. An empty database migrates, and
/// one this build migrated migrates again.
#[tokio::test]
async fn a_database_of_an_earlier_build_is_refused() {
    let (server, _container) = server().await;

    let url = fresh_database(&server, "empty").await;
    let pool = forge_db::connect(&url).await.expect("connect");
    forge_db::migrate(&pool)
        .await
        .expect("an empty database migrates");
    forge_db::migrate(&pool)
        .await
        .expect("a database this build migrated migrates again");

    // What an earlier build recorded: version 49 (the last of 1.x and the
    // builds before 2.0.0), or a version 1 of another content.
    for (label, version) in [("v49", 49_i64), ("v1", 1)] {
        let url = fresh_database(&server, label).await;
        let pool = forge_db::connect(&url).await.expect("connect");
        // sqlx's table, as sqlx creates it.
        sqlx::raw_sql(
            "CREATE TABLE _sqlx_migrations (
                 version BIGINT PRIMARY KEY,
                 description TEXT NOT NULL,
                 installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
                 success BOOLEAN NOT NULL,
                 checksum BYTEA NOT NULL,
                 execution_time BIGINT NOT NULL
             )",
        )
        .execute(&pool)
        .await
        .expect("create _sqlx_migrations");
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
             VALUES ($1, 'from an earlier build', true, sha384('an earlier schema'), 1)",
        )
        .bind(version)
        .execute(&pool)
        .await
        .expect("record a migration of an earlier build");

        let err = forge_db::migrate(&pool)
            .await
            .expect_err("a database of an earlier build is refused");
        let message = err.to_string();
        assert!(
            message.contains("created by Forge 1.x or by a build before 2.0.0")
                && message.contains("needs an empty database"),
            "{label}: {message}"
        );
        let migrated: Option<String> = sqlx::query_scalar("SELECT to_regclass('repository')::text")
            .fetch_one(&pool)
            .await
            .expect("look up repository");
        assert_eq!(migrated, None, "{label}: nothing is migrated");
    }
}

/// A Postgres server for one test: a throwaway Postgres 18 container matching
/// docker-compose (db/user/pw = forge), or, with FORGE_TEST_DATABASE_URL (no
/// Docker), that server. Returns the URL of a database on it, and the
/// container to keep alive.
async fn server() -> (String, Option<ContainerAsync<Postgres>>) {
    if let Ok(url) = std::env::var("FORGE_TEST_DATABASE_URL") {
        return (url, None);
    }
    let container = Postgres::default()
        .with_db_name("forge")
        .with_user("forge")
        .with_password("forge")
        .with_name("mirror.gcr.io/library/postgres")
        .with_tag("18")
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

/// Create an empty, uniquely named database next to `admin_url`; return its URL.
async fn fresh_database(admin_url: &str, label: &str) -> String {
    let name = format!("{label}_{}", std::process::id());
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
