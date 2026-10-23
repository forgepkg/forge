//! Invitations (#322, migration 0045): an invited local account has no
//! password only while it is invited, its invitation is replaced by a new
//! one, and a token is accepted once, live, for an active account.

mod common;

use chrono::{Duration, Utc};
use forge_db::invitation_dao;
use forge_db::user_dao::{self, NewUser};

use common::{pool, unique};

async fn invited(pool: &sqlx::PgPool, n: u64) -> forge_db::model::AppUser {
    invitation_dao::insert_invited_user(
        pool,
        &format!("Invited-{n}@Example.com"),
        &format!("mail-{n}@example.org"),
    )
    .await
    .expect("insert invited")
}

#[tokio::test]
async fn only_an_invited_local_account_may_lack_a_password() {
    let pool = pool().await;
    let n = unique();
    let user = invited(&pool, n).await;
    assert_eq!(user.username, format!("invited-{n}@example.com"));
    assert_eq!(user.auth_source, "local");
    assert!(user.password_hash.is_none());
    assert!(user.active);
    let onboarding = invitation_dao::onboarding(&pool, user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(onboarding.invited);
    assert_eq!(
        onboarding.email.as_deref(),
        Some(format!("mail-{n}@example.org").as_str())
    );

    // A local account without a password that is not invited: refused.
    let err = user_dao::insert_user(
        &pool,
        NewUser {
            username: format!("plain-{n}@example.com"),
            password_hash: None,
            active: true,
            auth_source: "local".into(),
            external_subject: None,
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("app_user_local_password_hash_check"),
        "{err}"
    );

    // Invited with a password, or not local: refused.
    for update in [
        "UPDATE app_user SET password_hash = 'x' WHERE id = $1",
        "UPDATE app_user SET auth_source = 'oidc' WHERE id = $1",
    ] {
        let err = sqlx::query(update)
            .bind(user.id)
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("app_user_invited_check"),
            "{update}: {err}"
        );
    }

    // Not a UPN, or a name no password login takes: refused.
    for bad in ["alice", "a:b@example.com"] {
        assert!(
            invitation_dao::insert_invited_user(&pool, bad, "a@example.org")
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn a_token_is_accepted_once_while_live() {
    let pool = pool().await;
    let n = unique();
    let user = invited(&pool, n).await;
    let expires = Utc::now() + Duration::hours(1);
    let made = invitation_dao::put(
        &pool,
        user.id,
        &format!("hash-a-{n}"),
        "a@example.org",
        expires,
        None,
    )
    .await
    .unwrap()
    .expect("made");
    assert_eq!(made.email, "a@example.org");
    assert!(made.is_live(Utc::now()));
    assert!(made.sent_at.is_none());
    invitation_dao::mark_sent(&pool, user.id, &format!("hash-a-{n}"))
        .await
        .unwrap();
    assert!(invitation_dao::get(&pool, user.id)
        .await
        .unwrap()
        .unwrap()
        .sent_at
        .is_some());

    let (username, _) = invitation_dao::find_live(&pool, &format!("hash-a-{n}"))
        .await
        .unwrap()
        .expect("live");
    assert_eq!(username, user.username);
    assert!(invitation_dao::find_live(&pool, "unknown")
        .await
        .unwrap()
        .is_none());

    let accepted = invitation_dao::accept(&pool, &format!("hash-a-{n}"), "$argon2id$stub")
        .await
        .unwrap()
        .expect("accepted");
    assert_eq!(accepted.password_hash.as_deref(), Some("$argon2id$stub"));
    let onboarding = invitation_dao::onboarding(&pool, user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!onboarding.invited);
    assert!(invitation_dao::get(&pool, user.id)
        .await
        .unwrap()
        .unwrap()
        .accepted_at
        .is_some());

    // Once.
    assert!(
        invitation_dao::accept(&pool, &format!("hash-a-{n}"), "$argon2id$other")
            .await
            .unwrap()
            .is_none()
    );
    assert!(invitation_dao::find_live(&pool, &format!("hash-a-{n}"))
        .await
        .unwrap()
        .is_none());
    // No invitation for an account that is no longer invited.
    assert!(invitation_dao::put(
        &pool,
        user.id,
        &format!("hash-b-{n}"),
        "a@example.org",
        expires,
        None
    )
    .await
    .unwrap()
    .is_none());
}

#[tokio::test]
async fn a_replaced_expired_revoked_or_deactivated_invitation_is_dead() {
    let pool = pool().await;
    let n = unique();
    let expires = Utc::now() + Duration::hours(1);

    // Replaced: the old token no longer works, the new one does.
    let user = invited(&pool, n).await;
    invitation_dao::put(
        &pool,
        user.id,
        &format!("old-{n}"),
        "a@example.org",
        expires,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    invitation_dao::put(
        &pool,
        user.id,
        &format!("new-{n}"),
        "b@example.org",
        expires,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(invitation_dao::accept(&pool, &format!("old-{n}"), "h")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        invitation_dao::get(&pool, user.id)
            .await
            .unwrap()
            .unwrap()
            .email,
        "b@example.org"
    );

    // Expired.
    let user = invited(&pool, n + 1_000_000).await;
    invitation_dao::put(
        &pool,
        user.id,
        &format!("expired-{n}"),
        "a@example.org",
        Utc::now() - Duration::seconds(1),
        None,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(invitation_dao::find_live(&pool, &format!("expired-{n}"))
        .await
        .unwrap()
        .is_none());
    assert!(invitation_dao::accept(&pool, &format!("expired-{n}"), "h")
        .await
        .unwrap()
        .is_none());

    // Revoked.
    let user = invited(&pool, n + 2_000_000).await;
    invitation_dao::put(
        &pool,
        user.id,
        &format!("revoked-{n}"),
        "a@example.org",
        expires,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(invitation_dao::revoke(&pool, user.id).await.unwrap());
    assert!(!invitation_dao::revoke(&pool, user.id).await.unwrap());
    assert!(invitation_dao::accept(&pool, &format!("revoked-{n}"), "h")
        .await
        .unwrap()
        .is_none());

    // The account deactivated.
    let user = invited(&pool, n + 3_000_000).await;
    invitation_dao::put(
        &pool,
        user.id,
        &format!("inactive-{n}"),
        "a@example.org",
        expires,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    user_dao::set_active(&pool, user.id, false).await.unwrap();
    assert!(invitation_dao::accept(&pool, &format!("inactive-{n}"), "h")
        .await
        .unwrap()
        .is_none());
    assert!(invitation_dao::put(
        &pool,
        user.id,
        &format!("again-{n}"),
        "a@example.org",
        expires,
        None
    )
    .await
    .unwrap()
    .is_none());

    // Deleted: the invitation goes with the account.
    let user = invited(&pool, n + 4_000_000).await;
    invitation_dao::put(
        &pool,
        user.id,
        &format!("deleted-{n}"),
        "a@example.org",
        expires,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    user_dao::delete_user(&pool, user.id).await.unwrap();
    assert!(invitation_dao::get(&pool, user.id).await.unwrap().is_none());
}
