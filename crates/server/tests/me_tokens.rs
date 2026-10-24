//! E2E: self-service token management (`/admin/me/tokens`).
//!
//! Any signed-in user manages their **own** tokens without admin rights; the
//! routes require a browser session (neither a token nor a password sent over
//! Basic can mint or revoke tokens), and one user can never touch another user's tokens.

mod common;

use serde_json::{json, Value};

/// Create a non-admin user via the admin API; returns its (username, password).
async fn make_user(srv: &common::TestServer) -> (String, String) {
    let username = format!("self{}@example.com", common::unique());
    srv.create_user(&username, "pw123456-self", "reader").await;
    (username, "pw123456-self".into())
}

/// A non-admin user mints, lists, uses, and revokes their own token.
#[tokio::test]
async fn self_token_lifecycle() {
    let srv = common::start().await;
    let client = srv.client();
    let (u, p) = make_user(&srv).await;
    let sess_u = srv.login(&u, &p).await;

    // Mint: 201 with the one-time plaintext.
    let resp = sess_u
        .apply(client.post(format!("{}/admin/me/tokens", srv.base_url)))
        .json(&json!({"name": "my-laptop"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: Value = resp.json().await.unwrap();
    let token_id = created["id"].as_i64().unwrap();
    let secret = created["token"].as_str().unwrap().to_string();
    assert_eq!(created["name"], json!("my-laptop"));
    assert!(!secret.is_empty());

    // The minted token authenticates the feed-style API as that user.
    let resp = client
        .get(format!("{}/admin/me", srv.base_url))
        .header("X-NuGet-ApiKey", &secret)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let me: Value = resp.json().await.unwrap();
    assert_eq!(me["user"]["username"], json!(u));

    // List: metadata only, never the secret or hash.
    let resp = sess_u
        .apply(client.get(format!("{}/admin/me/tokens", srv.base_url)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let listed: Value = resp.json().await.unwrap();
    let entry = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"].as_i64() == Some(token_id))
        .expect("minted token listed");
    assert!(entry.get("token").is_none(), "plaintext never re-listed");
    assert!(entry.get("token_hash").is_none(), "hash never listed");
    assert_eq!(
        entry["scope"],
        Value::Null,
        "unscoped token lists scope null"
    );

    // Revoke own token: 204, then a second revoke is 404.
    let resp = sess_u
        .apply(client.delete(format!("{}/admin/me/tokens/{token_id}", srv.base_url)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = sess_u
        .apply(client.delete(format!("{}/admin/me/tokens/{token_id}", srv.base_url)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // The revoked token no longer authenticates.
    let resp = client
        .get(format!("{}/admin/me", srv.base_url))
        .header("X-NuGet-ApiKey", &secret)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "revoked token must not authenticate");
}

#[tokio::test]
async fn token_creation_rejects_expiry_in_the_past() {
    let srv = common::start().await;
    let client = srv.client();
    let (username, password) = make_user(&srv).await;
    let session = srv.login(&username, &password).await;

    let resp = session
        .apply(client.post(format!("{}/admin/me/tokens", srv.base_url)))
        .json(&json!({"name": "expired", "expires_at": "2000-01-01T00:00:00Z"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let (admin, password) = srv.admin_basic();
    let users: Value = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_id = users
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["username"] == json!(admin))
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    let resp = client
        .post(format!("{}/admin/users/{admin_id}/tokens", srv.base_url))
        .basic_auth(&admin, Some(&password))
        .json(&json!({"name": "expired", "expires_at": "2000-01-01T00:00:00Z"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// A token-authenticated caller cannot manage tokens (403) — tokens are feed /
/// API credentials, not a login, and must not be able to mint further tokens.
#[tokio::test]
async fn token_cannot_manage_tokens() {
    let srv = common::start().await;
    let client = srv.client();
    let api_key = srv.admin_token().await;

    let resp = client
        .post(format!("{}/admin/me/tokens", srv.base_url))
        .header("X-NuGet-ApiKey", &api_key)
        .json(&json!({"name": "sneaky"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "a token must not mint tokens");

    let resp = client
        .get(format!("{}/admin/me/tokens", srv.base_url))
        .header("X-NuGet-ApiKey", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "a token must not list tokens");
}

/// Unauthenticated callers get 401 from every self-token route.
#[tokio::test]
async fn self_tokens_unauthenticated_401() {
    let srv = common::start().await;
    let client = srv.client();

    let resp = client
        .get(format!("{}/admin/me/tokens", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let resp = client
        .post(format!("{}/admin/me/tokens", srv.base_url))
        .json(&json!({"name": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

/// One user cannot revoke another user's token; the foreign id answers 404
/// (not 403) so it does not confirm the token exists.
#[tokio::test]
async fn cannot_revoke_foreign_token() {
    let srv = common::start().await;
    let client = srv.client();
    let (owner_u, owner_p) = make_user(&srv).await;
    let (other_u, other_p) = make_user(&srv).await;
    let sess_owner_u = srv.login(&owner_u, &owner_p).await;
    let sess_other_u = srv.login(&other_u, &other_p).await;

    let resp = sess_owner_u
        .apply(client.post(format!("{}/admin/me/tokens", srv.base_url)))
        .json(&json!({"name": "owned"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: Value = resp.json().await.unwrap();
    let token_id = created["id"].as_i64().unwrap();

    let resp = sess_other_u
        .apply(client.delete(format!("{}/admin/me/tokens/{token_id}", srv.base_url)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "foreign token id must answer 404");

    // The owner's token is still active and revocable by the owner.
    let resp = sess_owner_u
        .apply(client.delete(format!("{}/admin/me/tokens/{token_id}", srv.base_url)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

/// L6: a self-service token's scope is echoed and listed, and a mistyped scope
/// key is a 400 rather than an unscoped token.
#[tokio::test]
async fn self_token_scope_is_listed_and_unknown_keys_rejected() {
    let srv = common::start().await;
    let client = srv.client();
    let (u, p) = make_user(&srv).await;
    let sess_u = srv.login(&u, &p).await;

    for body in [
        json!({"name": "typo", "scope": {"repos": [1]}}),
        json!({"name": "typo", "scope": {"level": "read", "repository": [1]}}),
        json!({"name": "typo", "scop": {"level": "read"}}),
        json!({"name": "legacy", "scope": {"actions": ["read"]}}),
    ] {
        let resp = sess_u
            .apply(client.post(format!("{}/admin/me/tokens", srv.base_url)))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{body}");
    }
    let listed: Value = sess_u
        .apply(client.get(format!("{}/admin/me/tokens", srv.base_url)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        listed.as_array().unwrap().is_empty(),
        "no token was issued for a rejected scope"
    );

    let resp = sess_u
        .apply(client.post(format!("{}/admin/me/tokens", srv.base_url)))
        .json(&json!({"name": "ro", "scope": {"level": "read"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: Value = resp.json().await.unwrap();
    assert_eq!(created["scope"], json!({"level": "read"}));
    let listed: Value = sess_u
        .apply(client.get(format!("{}/admin/me/tokens", srv.base_url)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed[0]["scope"], json!({"level": "read"}));
}

/// B4 leaves `/admin/me/tokens` as it was: an admin-scoped token still cannot
/// manage tokens there (session/password principals only).
#[tokio::test]
async fn admin_scoped_token_cannot_manage_own_tokens() {
    let srv = common::start().await;
    let client = srv.client();
    let (u, p) = srv.admin_password_basic();
    let sess_u = srv.login(&u, &p).await;
    let created: Value = sess_u
        .apply(client.post(format!("{}/admin/me/tokens", srv.base_url)))
        .json(&json!({"name": "automation", "scope": {"admin": true}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = created["token"].as_str().unwrap();
    let resp = client
        .post(format!("{}/admin/me/tokens", srv.base_url))
        .header("X-NuGet-ApiKey", token)
        .json(&json!({"name": "sneaky"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = client
        .get(format!("{}/admin/me/tokens", srv.base_url))
        .header("X-NuGet-ApiKey", token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
