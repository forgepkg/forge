//! Legacy open access (installs upgraded from pre-release builds): an
//! upstream-provisioned user inherits the `authenticated` role when its
//! account is created, and an administrator's removal of that role survives
//! the user's next login. A test binary of its own (and so a database of its
//! own): the legacy flag is install-wide.
//!
//! Requires Docker.

mod common;

use forge_core::auth::provider::{AuthSource, ProvenIdentity};
use forge_core::auth::provision_and_map;
use forge_db::authz_dao;

use common::{pool, unique};

#[tokio::test]
async fn removing_authenticated_survives_the_next_upstream_login() {
    let pool = pool().await;
    authz_dao::set_legacy_open_access(&pool, true)
        .await
        .unwrap();
    let username = format!("legacy-{}", unique());
    let identity = ProvenIdentity {
        username: username.clone(),
        source: AuthSource::UpstreamBasic,
        external_subject: Some(username),
        groups: Vec::new(),
        suggested_is_admin: false,
        admin_authoritative: false,
        auto_provision: true,
        realm_id: None,
        captured_password_hash: None,
    };
    let roles = |user_id: i64| {
        let pool = pool.clone();
        async move {
            authz_dao::list_roles_for_user(&pool, user_id)
                .await
                .unwrap()
        }
    };

    let principal = provision_and_map(&pool, &identity).await.unwrap().unwrap();
    let authenticated = roles(principal.user_id)
        .await
        .into_iter()
        .find(|r| r.name == "authenticated")
        .expect("a new account on a legacy-open install gets `authenticated`");

    authz_dao::unassign_role(&pool, principal.user_id, authenticated.id)
        .await
        .unwrap();
    provision_and_map(&pool, &identity).await.unwrap().unwrap();
    assert!(
        roles(principal.user_id)
            .await
            .iter()
            .all(|r| r.name != "authenticated"),
        "the next login must not re-add a role an administrator removed"
    );
}
