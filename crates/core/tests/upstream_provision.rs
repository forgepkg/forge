//! Integration tests for slice-12.3 phase-5 auto-provisioning of upstream-basic
//! users: [`forge_core::auth::provision_and_map`] over a real Postgres
//! testcontainer.
//!
//! Covers (plan §2.4 / §5 Phase 5):
//!   * first upstream success provisions an `app_user` with
//!     `auth_source = 'upstream-basic'`, NULL `password_hash`, active;
//!   * a second login reuses the row (no duplicate, idempotent);
//!   * an admin-group suggestion grants admin on provision;
//!   * a provisioned admin is not downgraded by a non-authoritative login, but
//!     is when the realm's admin mapping authoritatively says so;
//!   * an existing LOCAL user is never clobbered NOR mapped (the upstream login
//!     is denied) when an upstream login shares the username;
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

/// An upstream-vouched identity whose provider allows auto-provisioning
/// (`auto_provision` rides on the identity since 12.7 — per-realm).
fn upstream_identity(username: &str, admin: bool, auto_provision: bool) -> ProvenIdentity {
    ProvenIdentity {
        username: username.to_string(),
        source: AuthSource::UpstreamBasic,
        external_subject: Some(username.to_string()),
        groups: Vec::new(),
        suggested_is_admin: admin,
        admin_authoritative: false,
        auto_provision,
        realm_id: None,
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

    let principal = provision_and_map(&pool, &upstream_identity(&username, false, true))
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

    let p1 = provision_and_map(&pool, &upstream_identity(&username, false, true))
        .await
        .unwrap()
        .unwrap();
    let p2 = provision_and_map(&pool, &upstream_identity(&username, false, true))
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

    let principal = provision_and_map(&pool, &upstream_identity(&username, true, true))
        .await
        .unwrap()
        .unwrap();
    assert!(principal.is_admin, "suggested_is_admin grants admin");

    // A subsequent NON-authoritative login (cache hit / no mapping) must NOT
    // touch the granted admin.
    let principal2 = provision_and_map(&pool, &upstream_identity(&username, false, true))
        .await
        .unwrap()
        .unwrap();
    assert!(
        principal2.is_admin,
        "non-authoritative login leaves admin alone"
    );

    // An authoritative login without the admin group demotes (column + role).
    let mut demote = upstream_identity(&username, false, true);
    demote.admin_authoritative = true;
    let principal3 = provision_and_map(&pool, &demote).await.unwrap().unwrap();
    assert!(!principal3.is_admin, "upstream revocation tracked");
    assert!(
        !forge_db::authz_dao::user_has_role(&pool, principal3.user_id, "admin")
            .await
            .unwrap(),
        "admin role removed on authoritative demotion"
    );
}

#[tokio::test]
async fn existing_local_user_is_not_clobbered_or_mapped() {
    let pool = pool().await;
    let username = unique_user("prov-local");

    // A pre-existing LOCAL admin (with a password hash).
    user_dao::insert_user(
        &pool,
        NewUser::local(username.clone(), "$argon2id$dummy".to_string(), true, true),
    )
    .await
    .unwrap();

    // An upstream login with the same username must be DENIED (never mapped
    // onto the local account), with or without auto-provisioning, and must not
    // drop its local password or flip auth_source to upstream-basic.
    for auto_provision in [true, false] {
        let resolved =
            provision_and_map(&pool, &upstream_identity(&username, false, auto_provision))
                .await
                .unwrap();
        assert!(
            resolved.is_none(),
            "upstream identity never maps to a local user"
        );
    }

    let user = user_dao::find_user_by_username(&pool, &username)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.auth_source, "local", "local provenance preserved");
    assert!(user.is_admin, "local admin flag untouched");
    assert!(
        user.password_hash.is_some(),
        "local password preserved, not nulled by upstream login"
    );
}

#[tokio::test]
async fn upstream_user_of_another_realm_is_not_mapped() {
    let pool = pool().await;
    let username = unique_user("prov-realm");
    let realm_a = forge_db::auth_realm_dao::insert_realm(
        &pool,
        forge_db::auth_realm_dao::NewAuthRealm {
            kind: "credential_forwarding".into(),
            name: format!("ra-{}", unique()),
            enabled: false,
            priority: 100_000 + (unique() % 1_000_000) as i32,
            config: serde_json::json!({}),
        },
    )
    .await
    .unwrap();
    let realm_b = forge_db::auth_realm_dao::insert_realm(
        &pool,
        forge_db::auth_realm_dao::NewAuthRealm {
            kind: "credential_forwarding".into(),
            name: format!("rb-{}", unique()),
            enabled: false,
            priority: 2_000_000 + (unique() % 1_000_000) as i32,
            config: serde_json::json!({}),
        },
    )
    .await
    .unwrap();

    let mut from_a = upstream_identity(&username, false, true);
    from_a.realm_id = Some(realm_a.id);
    assert!(provision_and_map(&pool, &from_a).await.unwrap().is_some());

    let mut from_b = upstream_identity(&username, false, true);
    from_b.realm_id = Some(realm_b.id);
    assert!(
        provision_and_map(&pool, &from_b).await.unwrap().is_none(),
        "realm B cannot claim realm A's user"
    );
    from_b.auto_provision = false;
    assert!(provision_and_map(&pool, &from_b).await.unwrap().is_none());
}

#[tokio::test]
async fn no_auto_provision_does_not_create_user() {
    let pool = pool().await;
    let username = unique_user("prov-off");

    let resolved = provision_and_map(&pool, &upstream_identity(&username, false, false))
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
    let resolved = provision_and_map(&pool, &upstream_identity(&username, false, false))
        .await
        .unwrap();
    assert!(resolved.is_none(), "inactive user denied");
}
