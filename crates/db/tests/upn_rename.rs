//! #317: the startup rename of every pre-1.2 account name to a UPN
//! ([`forge_db::user_dao::rename_legacy_usernames`], run by
//! [`forge_db::migrate`]). Each test has a database of its own: the rename
//! touches every account of a database.
//!
//! Requires Docker (or `FORGE_TEST_DATABASE_URL`).

mod common;

use forge_db::user_dao;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// A migrated, empty database next to the shared one.
async fn fresh_pool() -> PgPool {
    let shared = common::pool().await;
    let name = format!("upn_rename_{}_{}", std::process::id(), common::unique());
    // The name is generated here, never user input.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(r#"CREATE DATABASE "{name}""#)))
        .execute(&shared)
        .await
        .expect("create database");
    let options = (*shared.connect_options()).clone().database(&name);
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .expect("connect fresh database");
    forge_db::migrate(&pool).await.expect("migrate");
    pool
}

/// An account as a release before 1.2 stored it (around the DAO, which no
/// longer creates one).
async fn pre_upn_account(
    pool: &PgPool,
    username: &str,
    auth_source: &str,
    external_subject: Option<&str>,
) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO app_user (username, password_hash, active, auth_source, external_subject) \
         VALUES ($1, CASE WHEN $2 = 'local' THEN '$argon2id$unused' END, true, $2, $3) \
         RETURNING id",
    )
    .bind(username)
    .bind(auth_source)
    .bind(external_subject)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn username(pool: &PgPool, id: i64) -> String {
    sqlx::query_scalar("SELECT username FROM app_user WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

const MARKER: &str = "bootstrap_admin_created:";

#[tokio::test]
async fn pre_upn_accounts_become_example_com_upns() {
    let pool = fresh_pool().await;
    let admin = pre_upn_account(&pool, "admin", "local", None).await;
    let holder = pre_upn_account(&pool, "bob@example.com", "local", None).await;
    let bob = pre_upn_account(&pool, "bob", "local", None).await;
    let carol = pre_upn_account(&pool, "carol", "upstream-basic", Some("carol")).await;
    let dave = pre_upn_account(&pool, "dave@entra", "oidc", Some("sub-dave")).await;
    let erin = pre_upn_account(&pool, "erin@corp.example", "local", None).await;

    let token = forge_db::token_dao::insert_token(
        &pool,
        forge_db::token_dao::NewToken {
            user_id: admin,
            name: "ci".into(),
            token_hash: "hash-of-admins-token".into(),
            expires_at: None,
            minted_with_forwarded_credential: false,
        },
    )
    .await
    .unwrap();
    // The bootstrap admin's marker, and that of one created and deleted since.
    for (name, value) in [("admin", admin.to_string()), ("root", "999999".to_string())] {
        forge_db::authz_dao::set_setting(&pool, &format!("{MARKER}{name}"), &value)
            .await
            .unwrap();
    }
    // Carol's cached upstream verdict and her recorded upstream logins.
    sqlx::query(
        "INSERT INTO validated_credential (provider_id, username, cred_hmac, verdict, expires_at) \
         VALUES ('realm:nexus', 'carol', 'hmac', true, now() + interval '1 hour')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO validated_credential_tag (username, generation) VALUES ('carol', 3)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO auth_success (username, auth_method) VALUES ('carol', 'basic')")
        .execute(&pool)
        .await
        .unwrap();

    let repairs = user_dao::rename_legacy_usernames(&pool).await.unwrap();
    let renamed: Vec<_> = repairs
        .iter()
        .map(|r| (r.id, r.from.as_str(), r.to.as_str()))
        .collect();
    let bob_upn = format!("bob#{bob}@example.com");
    assert_eq!(
        renamed,
        [
            (admin, "admin", "admin@example.com"),
            (bob, "bob", bob_upn.as_str()),
            (carol, "carol", "carol@example.com"),
            (dave, "dave@entra", "dave+entra@example.com"),
        ]
    );
    assert_eq!(username(&pool, holder).await, "bob@example.com");
    assert_eq!(
        username(&pool, erin).await,
        "erin@corp.example",
        "a UPN stays"
    );

    // The account keeps its id and what hangs off it.
    let found = user_dao::find_user_by_username(&pool, "Admin@Example.com")
        .await
        .unwrap()
        .expect("the new name finds the account");
    assert_eq!(found.id, admin);
    assert!(user_dao::find_user_by_username(&pool, "admin")
        .await
        .unwrap()
        .is_none());
    let tokens = forge_db::token_dao::list_tokens_for_user(&pool, admin)
        .await
        .unwrap();
    assert_eq!(tokens.iter().map(|t| t.id).collect::<Vec<_>>(), [token.id]);
    // The upstream still knows carol as `carol`: the local part.
    let carol_row = user_dao::find_user_by_id(&pool, carol)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(carol_row.external_subject.as_deref(), Some("carol"));
    assert_eq!(
        forge_db::username::upn_local_part(&carol_row.username),
        Some("carol")
    );

    // Markers follow their account, or the name a deleted one would have.
    let get = |name: &str| {
        let pool = pool.clone();
        let key = format!("{MARKER}{name}");
        async move { forge_db::authz_dao::get_setting(&pool, &key).await.unwrap() }
    };
    assert_eq!(get("admin@example.com").await, Some(admin.to_string()));
    assert_eq!(get("root@example.com").await, Some("999999".to_string()));
    assert_eq!(get("admin").await, None);
    assert_eq!(get("root").await, None);

    // The old name's verdicts are gone; its logins count for the new name.
    let verdicts: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM validated_credential WHERE username = 'carol') \
              + (SELECT count(*) FROM validated_credential_tag WHERE username = 'carol')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(verdicts, 0);
    let logins: Vec<String> =
        sqlx::query_scalar("SELECT username FROM auth_success ORDER BY username")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(logins, ["carol@example.com"]);

    // A second start finds nothing to do.
    assert!(user_dao::rename_legacy_usernames(&pool)
        .await
        .unwrap()
        .is_empty());
    forge_db::migrate(&pool).await.expect("migrate again");
    assert_eq!(username(&pool, bob).await, bob_upn);
}

/// A name without a canonical form signs in neither before nor after, and is
/// left alone rather than turned into a UPN that could.
#[tokio::test]
async fn a_name_without_a_canonical_form_is_left_alone() {
    let pool = fresh_pool().await;
    let broken = pre_upn_account(&pool, "bad\nname", "local", None).await;
    assert!(user_dao::rename_legacy_usernames(&pool)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(username(&pool, broken).await, "bad\nname");
}
