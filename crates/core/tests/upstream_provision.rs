//! Integration tests for mapping credential-forwarding logins onto accounts:
//! [`forge_core::auth::provision_and_map`] over a real Postgres testcontainer.
//!
//! Covers:
//!   * a login maps onto the account an administrator created for the realm
//!     (`auth_source = 'upstream-basic'`, NULL `password_hash`), every time;
//!   * a login without such an account creates none and is denied;
//!   * an authoritative admin-group reading grants and removes the `admin`
//!     role (a demotion also ends the admin's sessions); a non-authoritative
//!     one changes nothing;
//!   * an existing LOCAL user is never clobbered NOR mapped (the upstream login
//!     is denied) when an upstream login shares the username;
//!   * another realm's account, and an orphan of a deleted realm, are never
//!     mapped;
//!   * a deactivated user resolves to `None` (login denied).
//!
//! Requires Docker.

mod common;

use forge_core::auth::provider::{AuthSource, ProvenIdentity};
use forge_core::auth::provision_and_map;
use forge_db::user_dao::{self, NewUser};
use sqlx::PgPool;

use common::{pool, unique};

/// A fresh UPN: every account name is one.
fn unique_user(prefix: &str) -> String {
    format!("{prefix}-{}@example.com", unique())
}

/// Whether the user holds the built-in `admin` role.
async fn is_admin(pool: &PgPool, user_id: i64) -> bool {
    forge_db::authz_dao::user_has_role(pool, user_id, "admin")
        .await
        .unwrap()
}

/// A disabled credential-forwarding realm row (only its id matters here).
async fn realm(pool: &PgPool, prefix: &str) -> i64 {
    forge_db::auth_realm_dao::insert_realm(
        pool,
        forge_db::auth_realm_dao::NewAuthRealm {
            kind: "credential_forwarding".into(),
            name: format!("{prefix}-{}", unique()),
            enabled: false,
            priority: 100_000 + (unique() % 100_000_000) as i32,
            config: serde_json::json!({}),
        },
    )
    .await
    .unwrap()
    .id
}

/// The identity realm `realm_id` vouches for after the upstream accepted
/// `username`'s local part.
fn upstream_identity(username: &str, realm_id: Option<i64>, admin: bool) -> ProvenIdentity {
    ProvenIdentity {
        username: username.to_string(),
        source: AuthSource::UpstreamBasic,
        external_subject: forge_db::username::upn_local_part(username).map(str::to_string),
        groups: Vec::new(),
        suggested_is_admin: admin,
        admin_authoritative: false,
        realm_id,
        captured_password_hash: None,
    }
}

/// A realm with one active account created by an administrator.
async fn realm_with_account(pool: &PgPool, prefix: &str) -> (i64, String, i64) {
    let realm_id = realm(pool, prefix).await;
    let username = unique_user(prefix);
    let user = user_dao::insert_forwarded_user(pool, &username, realm_id, true)
        .await
        .unwrap();
    (realm_id, username, user.id)
}

#[tokio::test]
async fn a_login_maps_onto_the_realms_account() {
    let pool = pool().await;
    let (realm_id, username, user_id) = realm_with_account(&pool, "fwd").await;

    for _ in 0..2 {
        let principal =
            provision_and_map(&pool, &upstream_identity(&username, Some(realm_id), false))
                .await
                .unwrap()
                .expect("the account signs in");
        assert_eq!(principal.user_id, user_id, "the same account, every time");
        assert!(principal.token_id.is_none());
        assert!(!is_admin(&pool, user_id).await);
    }

    let user = user_dao::find_user_by_username(&pool, &username)
        .await
        .unwrap()
        .expect("the account");
    assert_eq!(user.auth_source, "upstream-basic");
    assert!(user.password_hash.is_none(), "no local password");
    assert_eq!(
        user.external_subject.as_deref(),
        forge_db::username::upn_local_part(&username),
        "the upstream knows the account by its local part"
    );
    let all = user_dao::list_users(&pool).await.unwrap();
    assert_eq!(all.iter().filter(|u| u.username == username).count(), 1);
}

/// Credential forwarding creates no accounts: a login the upstream accepts
/// but no administrator created an account for is denied.
#[tokio::test]
async fn a_login_without_an_account_creates_none() {
    let pool = pool().await;
    let realm_id = realm(&pool, "fwd-none").await;
    let username = unique_user("fwd-none");

    let mut identity = upstream_identity(&username, Some(realm_id), true);
    identity.admin_authoritative = true;
    assert!(provision_and_map(&pool, &identity).await.unwrap().is_none());
    assert!(
        user_dao::find_user_by_username(&pool, &username)
            .await
            .unwrap()
            .is_none(),
        "no row created"
    );
}

#[tokio::test]
async fn the_admin_group_grants_and_removes_admin() {
    let pool = pool().await;
    let (realm_id, username, user_id) = realm_with_account(&pool, "fwd-admin").await;

    // Without an authoritative reading the suggestion grants nothing.
    provision_and_map(&pool, &upstream_identity(&username, Some(realm_id), true))
        .await
        .unwrap()
        .unwrap();
    assert!(!is_admin(&pool, user_id).await);

    let mut grant = upstream_identity(&username, Some(realm_id), true);
    grant.admin_authoritative = true;
    provision_and_map(&pool, &grant).await.unwrap().unwrap();
    assert!(
        is_admin(&pool, user_id).await,
        "the admin group grants admin"
    );

    let now = chrono::Utc::now();
    let session = forge_db::session_dao::create(
        &pool,
        forge_db::session_dao::NewSession {
            user_id,
            external_identity_id: None,
            token_hash: format!("hash-{username}"),
            csrf_secret: "csrf".to_string(),
            user_agent_hash: None,
            idle_expiry: now + chrono::Duration::hours(1),
            absolute_expiry: now + chrono::Duration::hours(8),
        },
    )
    .await
    .unwrap();

    // A non-authoritative login (cache hit / no mapping) leaves admin alone.
    provision_and_map(&pool, &upstream_identity(&username, Some(realm_id), false))
        .await
        .unwrap()
        .unwrap();
    assert!(is_admin(&pool, user_id).await);

    // An authoritative login without the admin group demotes and ends the
    // sessions opened as an admin.
    let mut demote = upstream_identity(&username, Some(realm_id), false);
    demote.admin_authoritative = true;
    provision_and_map(&pool, &demote).await.unwrap().unwrap();
    assert!(!is_admin(&pool, user_id).await, "admin role removed");
    assert!(
        forge_db::session_dao::find_valid_by_hash(&pool, &session.token_hash)
            .await
            .unwrap()
            .is_none(),
        "the admin session was ended"
    );
}

#[tokio::test]
async fn existing_local_user_is_not_clobbered_or_mapped() {
    let pool = pool().await;
    let username = unique_user("fwd-local");
    let realm_id = realm(&pool, "fwd-local").await;

    // A pre-existing LOCAL admin (with a password hash).
    let local = user_dao::insert_user(
        &pool,
        NewUser::local(username.clone(), "$argon2id$dummy".to_string(), true),
    )
    .await
    .unwrap();
    forge_db::authz_dao::sync_admin_role(&pool, local.id, true)
        .await
        .unwrap();

    // An upstream login with the same username must be DENIED (never mapped
    // onto the local account), and must not drop its local password or flip
    // auth_source to upstream-basic.
    for realm_id in [Some(realm_id), None] {
        let mut identity = upstream_identity(&username, realm_id, false);
        identity.admin_authoritative = true;
        assert!(
            provision_and_map(&pool, &identity).await.unwrap().is_none(),
            "upstream identity never maps to a local user"
        );
    }

    let user = user_dao::find_user_by_username(&pool, &username)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.auth_source, "local", "local provenance preserved");
    assert!(is_admin(&pool, user.id).await, "local admin untouched");
    assert!(
        user.password_hash.is_some(),
        "local password preserved, not nulled by upstream login"
    );
}

#[tokio::test]
async fn upstream_user_of_another_realm_is_not_mapped() {
    let pool = pool().await;
    let (_, username, user_id) = realm_with_account(&pool, "fwd-ra").await;
    let realm_b = realm(&pool, "fwd-rb").await;

    let mut from_b = upstream_identity(&username, Some(realm_b), true);
    from_b.admin_authoritative = true;
    assert!(
        provision_and_map(&pool, &from_b).await.unwrap().is_none(),
        "realm B cannot claim realm A's user"
    );
    assert!(
        provision_and_map(&pool, &upstream_identity(&username, None, false))
            .await
            .unwrap()
            .is_none(),
        "nor can the realm-less wiring"
    );
    assert!(!is_admin(&pool, user_id).await);
}

/// Deleting a realm orphans its users: a NULL realm is not a wildcard, so
/// another realm whose directory knows the same username can never adopt the
/// account (with its roles and tokens), and the orphan is flagged.
#[tokio::test]
async fn users_of_a_deleted_realm_are_never_adopted_by_another_realm() {
    let pool = pool().await;
    let (realm_a, username, user_id) = realm_with_account(&pool, "orphan-a").await;
    let realm_b = realm(&pool, "orphan-b").await;

    assert!(forge_db::auth_realm_dao::delete_realm(&pool, realm_a)
        .await
        .unwrap());
    let orphaned: bool = sqlx::query_scalar("SELECT realm_orphaned FROM app_user WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(orphaned, "deleting the realm flags its users");

    let mut from_b = upstream_identity(&username, Some(realm_b), true);
    from_b.admin_authoritative = true;
    assert!(
        provision_and_map(&pool, &from_b).await.unwrap().is_none(),
        "realm B must not adopt realm A's orphaned account"
    );
    // Not even the realm-less static wiring may claim it.
    assert!(
        provision_and_map(&pool, &upstream_identity(&username, None, false))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !is_admin(&pool, user_id).await,
        "the orphan was not touched"
    );
}

#[tokio::test]
async fn deactivated_user_resolves_to_none() {
    let pool = pool().await;
    let realm_id = realm(&pool, "fwd-inactive").await;
    let username = unique_user("fwd-inactive");
    user_dao::insert_forwarded_user(&pool, &username, realm_id, false)
        .await
        .unwrap();

    let mut identity = upstream_identity(&username, Some(realm_id), true);
    identity.admin_authoritative = true;
    assert!(
        provision_and_map(&pool, &identity).await.unwrap().is_none(),
        "inactive user denied"
    );
}
