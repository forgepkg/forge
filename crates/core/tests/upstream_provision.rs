//! Integration tests for slice-12.3 phase-5 auto-provisioning of upstream-basic
//! users: [`forge_core::auth::provision_and_map`] over a real Postgres
//! testcontainer.
//!
//! Covers (plan §2.4 / §5 Phase 5):
//!   * first upstream success provisions an `app_user` with
//!     `auth_source = 'upstream-basic'`, NULL `password_hash`, active;
//!   * a second login reuses the row (no duplicate, idempotent);
//!   * an admin-group suggestion grants admin on provision;
//!   * a provisioned admin is never *downgraded* by a later non-admin login
//!     (grant-only);
//!   * an existing LOCAL user is never clobbered (auth_source / password_hash
//!     preserved) when an upstream login shares the username;
//!   * `auto_provision = false` does not create a user (unknown → `None`);
//!   * a deactivated user resolves to `None` (login denied).
//!
//! Requires Docker.

mod common;

use forge_core::auth::provider::{AuthSource, ProvenIdentity};
use forge_core::auth::provision_and_map;
use forge_db::user_dao::{self, NewUser};

use common::{pool, unique};

fn unique_user(prefix: &str) -> String {
    format!("{prefix}-{}", unique())
}

fn upstream_identity(username: &str, admin: bool) -> ProvenIdentity {
    ProvenIdentity {
        username: username.to_string(),
        source: AuthSource::UpstreamBasic,
        external_subject: Some(username.to_string()),
        groups: Vec::new(),
        suggested_is_admin: admin,
    }
}

#[tokio::test]
async fn first_success_provisions_passwordless_upstream_user() {
    let pool = pool().await;
    let username = unique_user("prov");

    // No such user yet.
    assert!(user_dao::find_user_by_username(&pool, &username)
        .await
        .unwrap()
        .is_none());

    let principal = provision_and_map(&pool, &upstream_identity(&username, false), true)
        .await
        .unwrap()
        .expect("provisioned principal");
    assert!(!principal.is_admin);
    assert!(principal.token_id.is_none());

    let user = user_dao::find_user_by_username(&pool, &username)
        .await
        .unwrap()
        .expect("user now exists");
    assert_eq!(user.auth_source, "upstream-basic");
    assert!(user.password_hash.is_none(), "no local password");
    assert!(user.active);
    assert_eq!(user.external_subject.as_deref(), Some(username.as_str()));
}

#[tokio::test]
async fn second_login_reuses_user_no_duplicate() {
    let pool = pool().await;
    let username = unique_user("prov-reuse");

    let p1 = provision_and_map(&pool, &upstream_identity(&username, false), true)
        .await
        .unwrap()
        .unwrap();
    let p2 = provision_and_map(&pool, &upstream_identity(&username, false), true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p1.user_id, p2.user_id, "same row reused");

    let all = user_dao::list_users(&pool).await.unwrap();
    assert_eq!(
        all.iter().filter(|u| u.username == username).count(),
        1,
        "no duplicate row"
    );
}

#[tokio::test]
async fn admin_group_grants_admin_on_provision() {
    let pool = pool().await;
    let username = unique_user("prov-admin");

    let principal = provision_and_map(&pool, &upstream_identity(&username, true), true)
        .await
        .unwrap()
        .unwrap();
    assert!(principal.is_admin, "suggested_is_admin grants admin");

    // A subsequent NON-admin login must NOT downgrade the granted admin.
    let principal2 = provision_and_map(&pool, &upstream_identity(&username, false), true)
        .await
        .unwrap()
        .unwrap();
    assert!(principal2.is_admin, "grant-only: never revoked here");
}

#[tokio::test]
async fn existing_local_user_is_not_clobbered() {
    let pool = pool().await;
    let username = unique_user("prov-local");

    // A pre-existing LOCAL user (with a password hash).
    user_dao::insert_user(
        &pool,
        NewUser::local(username.clone(), "$argon2id$dummy".to_string(), false, true),
    )
    .await
    .unwrap();

    // An upstream login with the same username must reuse the row WITHOUT
    // dropping its local password or flipping auth_source to upstream-basic.
    let principal = provision_and_map(&pool, &upstream_identity(&username, false), true)
        .await
        .unwrap()
        .expect("resolves to the existing local user");
    assert!(!principal.is_admin);

    let user = user_dao::find_user_by_username(&pool, &username)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.auth_source, "local", "local provenance preserved");
    assert!(
        user.password_hash.is_some(),
        "local password preserved, not nulled by upstream login"
    );
}

#[tokio::test]
async fn no_auto_provision_does_not_create_user() {
    let pool = pool().await;
    let username = unique_user("prov-off");

    let resolved = provision_and_map(&pool, &upstream_identity(&username, false), false)
        .await
        .unwrap();
    assert!(resolved.is_none(), "unknown user not provisioned");
    assert!(
        user_dao::find_user_by_username(&pool, &username)
            .await
            .unwrap()
            .is_none(),
        "no row created"
    );
}

#[tokio::test]
async fn deactivated_user_resolves_to_none() {
    let pool = pool().await;
    let username = unique_user("prov-inactive");

    // Provision then deactivate via a fresh insert path: simulate by inserting a
    // deactivated upstream user, then attempting a (no-auto-provision) resolve.
    user_dao::insert_user(
        &pool,
        NewUser {
            username: username.clone(),
            password_hash: None,
            is_admin: false,
            active: false,
            auth_source: "upstream-basic".to_string(),
            external_subject: Some(username.clone()),
        },
    )
    .await
    .unwrap();

    // With auto_provision = false, an inactive existing user is denied.
    let resolved = provision_and_map(&pool, &upstream_identity(&username, false), false)
        .await
        .unwrap();
    assert!(resolved.is_none(), "inactive user denied");
}
