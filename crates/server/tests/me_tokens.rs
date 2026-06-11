//! E2E: self-service token management (`/admin/me/tokens`).
//!
//! Any signed-in user manages their **own** tokens without admin rights; the
//! routes require a password/realm-authenticated principal (a token cannot
//! mint or revoke tokens), and one user can never touch another user's tokens.

mod common;

use serde_json::{json, Value};

/// Create a non-admin user via the admin API; returns its (username, password).
async fn make_user(srv: &common::TestServer) -> (String, String) {
    let (au, ap) = srv.admin_basic();
    let username = format!("self{}", common::unique());
    let resp = srv
        .client()
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"username": username, "password": "pw123456", "is_admin": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    (username, "pw123456".into())
}

/// A non-admin user mints, lists, uses, and revokes their own token.
#[tokio::test]
async fn self_token_lifecycle() {
    let srv = common::start().await;
    let client = srv.client();
    let (u, p) = make_user(&srv).await;

    // Mint: 201 with the one-time plaintext.
    let resp = client
        .post(format!("{}/admin/me/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
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
    let resp = client
        .get(format!("{}/admin/me/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
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

    // Revoke own token: 204, then a second revoke is 404.
    let resp = client
        .delete(format!("{}/admin/me/tokens/{token_id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = client
        .delete(format!("{}/admin/me/tokens/{token_id}", srv.base_url))
        .basic_auth(&u, Some(&p))
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

    let resp = client
        .post(format!("{}/admin/me/tokens", srv.base_url))
        .basic_auth(&owner_u, Some(&owner_p))
        .json(&json!({"name": "owned"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: Value = resp.json().await.unwrap();
    let token_id = created["id"].as_i64().unwrap();

    let resp = client
        .delete(format!("{}/admin/me/tokens/{token_id}", srv.base_url))
        .basic_auth(&other_u, Some(&other_p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "foreign token id must answer 404");

    // The owner's token is still active and revocable by the owner.
    let resp = client
        .delete(format!("{}/admin/me/tokens/{token_id}", srv.base_url))
        .basic_auth(&owner_u, Some(&owner_p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}
