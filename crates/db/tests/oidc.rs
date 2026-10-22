//! Integration tests for the OIDC / session DAO layer against a real Postgres
//! testcontainer.
//!
//! Covers the three properties the design hinges on:
//!   * `oidc_flow` is single-use — a second `consume` of the same `state` returns
//!     `None` (replay defence + cross-instance race-safety);
//!   * `session` validity / revocation / reaping is enforced in SQL;
//!   * `external_identity` links an IdP `(issuer, subject)` to an `app_user` and
//!     looks it up.
//!
//! Requires Docker on the host. All tests share one container/pool (see
//! `common`) and isolate themselves with unique names.

mod common;

use chrono::{Duration, Utc};
use forge_db::external_identity_dao::{self, IdentityClaims};
use forge_db::model::{AppUser, OidcFlow};
use forge_db::oidc_flow_dao::{self, NewOidcFlow};
use forge_db::session_dao::{self, NewSession};
use forge_db::user_dao::{self, NewUser};

use common::{pool, unique};

/// Insert a throwaway user to satisfy the `session`/`external_identity` FKs.
async fn make_user(pool: &sqlx::PgPool, n: u64) -> AppUser {
    user_dao::insert_user(
        pool,
        NewUser::local(format!("oidc-user-{n}"), "x".to_string(), false, true),
    )
    .await
    .expect("insert user")
}

// ── oidc_flow ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn oidc_flow_consume_is_single_use() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let state = format!("state-{n}");

    let inserted = oidc_flow_dao::begin(
        pool,
        NewOidcFlow {
            state: state.clone(),
            nonce: format!("nonce-{n}"),
            pkce_verifier: format!("verifier-{n}"),
            redirect_to: "/packages".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
        },
    )
    .await
    .expect("begin");
    assert_eq!(inserted.state, state);
    assert_eq!(inserted.redirect_to, "/packages");

    // First consume returns the row, with the verifier + nonce a *different*
    // instance would need to complete the callback.
    let first: Option<OidcFlow> = oidc_flow_dao::consume(pool, &state)
        .await
        .expect("consume 1");
    let first = first.expect("first consume yields the row");
    assert_eq!(first.nonce, format!("nonce-{n}"));
    assert_eq!(first.pkce_verifier, format!("verifier-{n}"));
    assert_eq!(first.redirect_to, "/packages");

    // Second consume of the same state finds nothing — single-use / replay block.
    let second = oidc_flow_dao::consume(pool, &state)
        .await
        .expect("consume 2");
    assert!(second.is_none(), "replayed state must not return a row");
}

#[tokio::test]
async fn oidc_flow_consume_rejects_expired() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let state = format!("state-exp-{n}");

    oidc_flow_dao::begin(
        pool,
        NewOidcFlow {
            state: state.clone(),
            nonce: "n".to_string(),
            pkce_verifier: "v".to_string(),
            redirect_to: "/".to_string(),
            expires_at: Utc::now() - Duration::seconds(1), // already expired
        },
    )
    .await
    .expect("begin");

    let consumed = oidc_flow_dao::consume(pool, &state).await.expect("consume");
    assert!(consumed.is_none(), "expired flow must not be consumable");
}

#[tokio::test]
async fn oidc_flow_reap_expired_removes_only_expired() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let live = format!("live-{n}");
    let dead = format!("dead-{n}");

    oidc_flow_dao::begin(
        pool,
        NewOidcFlow {
            state: live.clone(),
            nonce: "n".into(),
            pkce_verifier: "v".into(),
            redirect_to: "/".into(),
            expires_at: Utc::now() + Duration::minutes(10),
        },
    )
    .await
    .expect("begin live");
    oidc_flow_dao::begin(
        pool,
        NewOidcFlow {
            state: dead.clone(),
            nonce: "n".into(),
            pkce_verifier: "v".into(),
            redirect_to: "/".into(),
            expires_at: Utc::now() - Duration::minutes(1),
        },
    )
    .await
    .expect("begin dead");

    oidc_flow_dao::reap_expired(pool).await.expect("reap");

    // The live row survives; the expired one is gone.
    assert!(oidc_flow_dao::consume(pool, &live)
        .await
        .expect("consume live")
        .is_some());
    assert!(oidc_flow_dao::consume(pool, &dead)
        .await
        .expect("consume dead")
        .is_none());
}

// ── session ──────────────────────────────────────────────────────────────────

fn new_session(user_id: i64, hash: &str) -> NewSession {
    NewSession {
        user_id,
        external_identity_id: None,
        token_hash: hash.to_string(),
        csrf_secret: "csrf".to_string(),
        user_agent_hash: None,
        idle_expiry: Utc::now() + Duration::hours(8),
        absolute_expiry: Utc::now() + Duration::days(7),
    }
}

#[tokio::test]
async fn session_create_then_validate_round_trip() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;
    let hash = format!("hash-{n}");

    let created = session_dao::create(pool, new_session(user.id, &hash))
        .await
        .expect("create");
    assert_eq!(created.user_id, user.id);
    assert!(created.revoked_at.is_none());

    let found = session_dao::find_valid_by_hash(pool, &hash)
        .await
        .expect("find")
        .expect("valid session present");
    assert_eq!(found.id, created.id);
    assert_eq!(found.csrf_secret, "csrf");
}

#[tokio::test]
async fn session_validate_rejects_revoked() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;
    let hash = format!("hash-rev-{n}");

    let created = session_dao::create(pool, new_session(user.id, &hash))
        .await
        .expect("create");

    let revoked = session_dao::revoke(pool, created.id).await.expect("revoke");
    assert!(revoked, "first revoke updates the row");
    // Idempotent: a second revoke changes nothing.
    assert!(!session_dao::revoke(pool, created.id)
        .await
        .expect("revoke again"));

    let found = session_dao::find_valid_by_hash(pool, &hash)
        .await
        .expect("find");
    assert!(found.is_none(), "revoked session must not validate");
}

#[tokio::test]
async fn session_validate_rejects_idle_and_absolute_expiry() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;

    // Idle-expired (idle_expiry in the past, absolute still future).
    let idle_hash = format!("idle-{n}");
    session_dao::create(
        pool,
        NewSession {
            idle_expiry: Utc::now() - Duration::seconds(1),
            absolute_expiry: Utc::now() + Duration::days(7),
            ..new_session(user.id, &idle_hash)
        },
    )
    .await
    .expect("create idle");
    assert!(session_dao::find_valid_by_hash(pool, &idle_hash)
        .await
        .expect("find idle")
        .is_none());

    // Absolute-expired (idle still future, absolute in the past).
    let abs_hash = format!("abs-{n}");
    session_dao::create(
        pool,
        NewSession {
            idle_expiry: Utc::now() + Duration::hours(8),
            absolute_expiry: Utc::now() - Duration::seconds(1),
            ..new_session(user.id, &abs_hash)
        },
    )
    .await
    .expect("create abs");
    assert!(session_dao::find_valid_by_hash(pool, &abs_hash)
        .await
        .expect("find abs")
        .is_none());
}

#[tokio::test]
async fn session_touch_last_seen_is_throttled() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;
    let hash = format!("touch-{n}");

    let created = session_dao::create(pool, new_session(user.id, &hash))
        .await
        .expect("create");

    // Just created -> last_seen_at is fresh, so a 60s-throttled touch is a no-op.
    let touched = session_dao::touch_last_seen(pool, created.id, 60, 8 * 3600)
        .await
        .expect("touch throttled");
    assert!(!touched, "fresh session must not be touched under throttle");

    // min_age = 0 forces a touch and extends idle_expiry.
    let touched = session_dao::touch_last_seen(pool, created.id, 0, 8 * 3600)
        .await
        .expect("touch forced");
    assert!(touched, "min_age=0 must touch");
}

#[tokio::test]
async fn session_revoke_all_for_user_and_reap() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;

    let h1 = format!("ra-1-{n}");
    let h2 = format!("ra-2-{n}");
    session_dao::create(pool, new_session(user.id, &h1))
        .await
        .expect("s1");
    session_dao::create(pool, new_session(user.id, &h2))
        .await
        .expect("s2");

    let revoked = session_dao::revoke_all_for_user(pool, user.id)
        .await
        .expect("revoke all");
    assert_eq!(revoked, 2);
    assert!(session_dao::find_valid_by_hash(pool, &h1)
        .await
        .expect("find h1")
        .is_none());

    // reap removes the revoked rows (count includes both just-revoked sessions).
    let reaped = session_dao::reap_expired(pool).await.expect("reap");
    assert!(reaped >= 2, "reap should remove the revoked sessions");
}

// ── external_identity ──────────────────────────────────────────────────────

#[tokio::test]
async fn external_identity_link_and_lookup() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;
    let issuer = format!("https://issuer-{n}.example/v2.0");
    let subject = format!("sub-{n}");

    // No link yet.
    assert!(
        external_identity_dao::find_user_by_subject(pool, &issuer, &subject)
            .await
            .expect("lookup empty")
            .is_none()
    );

    let linked = external_identity_dao::link(
        pool,
        user.id,
        &issuer,
        &subject,
        IdentityClaims {
            preferred_username: Some("alice".into()),
            email: Some("alice@example.com".into()),
            display_name: Some("Alice".into()),
        },
    )
    .await
    .expect("link");
    assert_eq!(linked.user_id, user.id);
    assert_eq!(linked.preferred_username.as_deref(), Some("alice"));
    assert!(linked.last_login_at.is_some());

    // find_by_issuer_subject returns the row.
    let row = external_identity_dao::find_by_issuer_subject(pool, &issuer, &subject)
        .await
        .expect("find row")
        .expect("present");
    assert_eq!(row.id, linked.id);

    // find_user_by_subject resolves the joined app_user.
    let resolved = external_identity_dao::find_user_by_subject(pool, &issuer, &subject)
        .await
        .expect("lookup user")
        .expect("user present");
    assert_eq!(resolved.id, user.id);
}

#[tokio::test]
async fn external_identity_link_is_upsert_on_issuer_subject() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;
    let issuer = format!("https://issuer-up-{n}.example/v2.0");
    let subject = format!("sub-up-{n}");

    let first = external_identity_dao::link(
        pool,
        user.id,
        &issuer,
        &subject,
        IdentityClaims {
            email: Some("old@example.com".into()),
            ..IdentityClaims::default()
        },
    )
    .await
    .expect("link 1");

    // Second login with refreshed claims upserts the same row (same id), updates
    // the denormalized email, and never duplicates the (issuer, subject) link.
    let second = external_identity_dao::link(
        pool,
        user.id,
        &issuer,
        &subject,
        IdentityClaims {
            email: Some("new@example.com".into()),
            display_name: Some("Alice".into()),
            ..IdentityClaims::default()
        },
    )
    .await
    .expect("link 2");

    assert_eq!(first.id, second.id, "upsert must reuse the same row");
    assert_eq!(second.email.as_deref(), Some("new@example.com"));
    assert_eq!(second.display_name.as_deref(), Some("Alice"));
}
