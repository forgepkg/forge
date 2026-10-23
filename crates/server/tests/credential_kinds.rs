//! Which kind of credential may do what (security review): a password sent
//! over HTTP Basic is a feed credential only. It cannot administer Forge or
//! mint tokens, even for an administrator; that takes a browser session (or,
//! for the admin API, an admin-scoped token). Tokens minted from a session
//! that credential forwarding established die with an admin-forced reauth.

mod common;

use serde_json::{json, Value};

#[tokio::test]
async fn admin_api_refuses_a_password_sent_over_basic() {
    let srv = common::start().await;
    let client = srv.client();
    let (user, password) = srv.admin_password_basic();

    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&user, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "an admin's password over Basic is not an admin login"
    );

    // The same password through the login form yields a session that may.
    let session = srv.login(&user, &password).await;
    let resp = session
        .apply(client.get(format!("{}/admin/users", srv.base_url)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // An admin-scoped token may; an unscoped one may not.
    let (u, scoped) = srv.admin_basic();
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&u, Some(&scoped))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let unscoped = srv.admin_token().await;
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .header("X-NuGet-ApiKey", &unscoped)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // The password still works on the feed.
    let resp = client
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&user, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn tokens_are_minted_only_from_a_session() {
    let srv = common::start().await;
    let client = srv.client();
    let (au, ap) = srv.admin_basic();
    let username = format!("minter{}@example.com", common::unique());
    let resp = client
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"username": username, "password": "pw123456"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let resp = client
        .post(format!("{}/admin/me/tokens", srv.base_url))
        .basic_auth(&username, Some("pw123456"))
        .json(&json!({"name": "via-basic"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "a Basic password cannot mint tokens");

    let session = srv.login(&username, "pw123456").await;
    let resp = session
        .apply(client.post(format!("{}/admin/me/tokens", srv.base_url)))
        .json(&json!({"name": "via-session"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn reauth_revokes_tokens_minted_via_credential_forwarding() {
    let srv = common::start().await;
    let client = srv.client();
    let (au, ap) = srv.admin_basic();
    let username = format!("fwd{}", common::unique());
    let user = forge_db::user_dao::provision_upstream_user(&srv.pool, &username, None)
        .await
        .unwrap()
        .expect("provisioned upstream user");

    // The user mints a token from a (forwarded-credential) session...
    let session = srv.session_for(user.id).await;
    let resp = session
        .apply(client.post(format!("{}/admin/me/tokens", srv.base_url)))
        .json(&json!({"name": "laptop"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let forwarded: Value = resp.json().await.unwrap();
    let forwarded = forwarded["token"].as_str().unwrap().to_string();
    // ...and an administrator mints one for them.
    let resp = client
        .post(format!("{}/admin/users/{}/tokens", srv.base_url, user.id))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": "ci"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let admin_minted: Value = resp.json().await.unwrap();
    let admin_minted = admin_minted["token"].as_str().unwrap().to_string();

    let resp = client
        .post(format!("{}/admin/users/{}/reauth", srv.base_url, user.id))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let status_with = |token: String| {
        let client = client.clone();
        let url = format!("{}/admin/me", srv.base_url);
        async move {
            client
                .get(url)
                .header("X-NuGet-ApiKey", token)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(
        status_with(forwarded).await,
        401,
        "a token minted on a forwarded credential dies with the reauth"
    );
    assert_eq!(
        status_with(admin_minted).await,
        200,
        "an administrator's token for the user is kept"
    );
}
