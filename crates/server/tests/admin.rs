//! E2E: admin API gating, bootstrap admin, repository/user/token/member CRUD,
//! password redaction, the scheme-only `remote_url` guard, and group-member
//! validation (nested groups accepted, cycles and duplicate priorities
//! rejected). Requires Docker (Postgres + versitygw).

mod common;

use forge_db::asset_dao::{self, NewAsset};
use forge_db::blob_dao;
use forge_db::component_dao::{self, NewComponent};
use forge_db::repository_dao::{self, NewRepository};
use serde_json::{json, Value};

/// The bootstrap admin can authenticate (basic) and list repositories; the
/// admin API requires admin (anonymous → 401).
#[tokio::test]
async fn bootstrap_admin_and_gating() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    // No credentials → 401.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anonymous admin call must be 401");

    // Bootstrap admin via basic auth → 200.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admin basic auth must succeed");
    let repos: Value = resp.json().await.unwrap();
    // Shared test DB: just assert a well-formed array (other parallel tests may
    // have created repos).
    assert!(repos.is_array(), "repositories list must be a JSON array");
}

/// A non-admin user is forbidden (403) from the admin API.
#[tokio::test]
async fn non_admin_forbidden() {
    let srv = common::start().await;
    let client = srv.client();
    let suffix = common::unique();
    let username = format!("plain{suffix}@example.com");

    // Admin creates a non-admin user, who chooses a password.
    srv.create_user(&username, "pw123456-plain", "reader").await;

    // That user authenticates (password basic) but is forbidden from admin.
    let resp = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&username, Some("pw123456-plain"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-admin must be 403");
}

/// Proxy timings are bounded: a negative TTL made every unconfirmed row
/// prunable at once, and an unbounded not-found TTL let one request hide a
/// package for years.
/// A group's reserved prefixes are validated, normalized (lowercase, a
/// trailing `*` dropped, deduplicated) and only accepted on groups.
#[tokio::test]
async fn group_reserved_prefixes_are_validated() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let create = |body: Value| {
        let req = client
            .post(format!("{}/admin/repositories", srv.base_url))
            .basic_auth(&au, Some(&ap))
            .json(&body);
        async move { req.send().await.unwrap() }
    };
    let group = format!("grp{}", common::unique());
    let resp = create(json!({"name": group, "kind": "group",
                             "reserved_prefixes": ["Acme.*", " Contoso.", "acme."]}))
    .await;
    assert_eq!(resp.status(), 201);
    let view: Value = resp.json().await.unwrap();
    assert_eq!(view["reserved_prefixes"], json!(["acme.", "contoso."]));

    for bad in [json!([""]), json!(["acme/"]), json!(["a b"]), json!(["*"])] {
        let resp = create(json!({"name": format!("grp{}", common::unique()),
                                 "kind": "group", "reserved_prefixes": bad}))
        .await;
        assert_eq!(resp.status(), 400, "{bad}");
    }
    let resp = create(
        json!({"name": format!("h{}", common::unique()), "kind": "hosted",
                             "reserved_prefixes": ["acme."]}),
    )
    .await;
    assert_eq!(resp.status(), 400, "only groups reserve prefixes");

    // Update replaces the list; `[]` clears it.
    let update = |body: Value| {
        let req = client
            .put(format!("{}/admin/repositories/{group}", srv.base_url))
            .basic_auth(&au, Some(&ap))
            .json(&body);
        async move { req.send().await.unwrap() }
    };
    let view: Value = update(json!({"reserved_prefixes": ["Fabrikam."]}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(view["reserved_prefixes"], json!(["fabrikam."]));
    assert_eq!(view["prefer_hosted"], json!(true));
    let view: Value = update(json!({"reserved_prefixes": []}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(view["reserved_prefixes"], json!([]));
}

#[tokio::test]
async fn proxy_timings_are_validated() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    for (field, value) in [
        ("not_found_ttl_seconds", -1),
        ("not_found_ttl_seconds", 31_536_000),
        ("metadata_ttl_seconds", -5),
        ("package_delay_seconds", -1),
    ] {
        let mut body = json!({
            "name": format!("px{}", common::unique()),
            "kind": "proxy",
            "remote_url": "https://api.nuget.org/v3/index.json",
        });
        body[field] = json!(value);
        let resp = client
            .post(format!("{}/admin/repositories", srv.base_url))
            .basic_auth(&au, Some(&ap))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{field} = {value}");
    }
    let name = format!("px{}", common::unique());
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": name, "kind": "proxy",
                      "remote_url": "https://api.nuget.org/v3/index.json",
                      "not_found_ttl_seconds": 600}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let resp = client
        .put(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"not_found_ttl_seconds": -1}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "updates are validated too");
}

/// Usernames are stored canonical (trimmed, NFC, lowercased): a case or
/// spacing variant of an existing name is the same account (409 on create),
/// and every spelling signs in to it. Names without a canonical form are 400.
#[tokio::test]
async fn usernames_are_canonical() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let lower = format!("carol{}@example.com", common::unique());
    let typed = format!("  {} ", lower.to_uppercase());

    let resp = client
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"username": typed}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: Value = resp.json().await.unwrap();
    assert_eq!(created["username"], json!(lower), "stored canonical");
    let link = created["invitation"]["link"].as_str().unwrap();
    let resp = srv
        .accept_invitation(link.split_once('#').unwrap().1, "pw123456-carol")
        .await;
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"username": lower}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "a case variant is the same account");

    for bad in ["", "   ", r"bad\nname", r"nul\u0000name"] {
        let resp = client
            .post(format!("{}/admin/users", srv.base_url))
            .basic_auth(&au, Some(&ap))
            .header("content-type", "application/json")
            .body(format!(r#"{{"username": "{bad}"}}"#))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{bad:?}");
    }

    for spelling in [lower.to_uppercase(), format!(" {lower}")] {
        let resp = client
            .post(format!("{}/auth/login", srv.base_url))
            .json(&json!({"username": spelling, "password": "pw123456-carol"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{spelling:?} signs in");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(
            body["user_id"], created["id"],
            "{spelling:?} is the same account"
        );
        assert_eq!(body["username"], json!(lower));
    }
}

/// Review 2026-10-20 M2: a local account signs in with a password, and no
/// password login accepts a name containing `:` (HTTP Basic splits at the
/// first colon), so such an account is refused at creation.
#[tokio::test]
async fn usernames_with_a_colon_are_refused() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();

    for bad in [
        format!("mallory{s}:abc"),
        format!(":dave{s}"),
        format!("erin{s}:"),
    ] {
        let resp = client
            .post(format!("{}/admin/users", srv.base_url))
            .basic_auth(&au, Some(&ap))
            .json(&json!({"username": bad}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{bad:?}");
        assert_eq!(
            resp.text().await.unwrap(),
            "invalid username: username must not contain ':'"
        );
        let stored = forge_db::user_dao::find_user_by_username(&srv.pool, &bad)
            .await
            .unwrap();
        assert!(stored.is_none(), "{bad:?} was not created");
    }
}

/// #317: every account is named by a UPN (`POST /admin/users` answers 400
/// otherwise).
#[tokio::test]
async fn new_accounts_need_a_upn() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();

    for bad in [
        format!("dave{s}"),
        format!("dave{s}@corp"),
        format!("dave{s}@corp.example."),
        format!("dave{s}@corp@example.com"),
        format!("@corp{s}.example"),
    ] {
        let resp = client
            .post(format!("{}/admin/users", srv.base_url))
            .basic_auth(&au, Some(&ap))
            .json(&json!({"username": bad}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{bad:?}");
        assert_eq!(
            resp.text().await.unwrap(),
            "invalid username: username must be a UPN such as alice@example.com"
        );
        assert!(forge_db::user_dao::find_user_by_username(&srv.pool, &bad)
            .await
            .unwrap()
            .is_none());
    }
}

/// `POST /admin/users/{id}/reauth`: admin-only, 204 on a known user
/// (idempotent even with no cached verdicts), 404 for an unknown id, 403 for a
/// non-admin caller.
#[tokio::test]
async fn reauth_endpoint_admin_only_and_idempotent() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let suffix = common::unique();
    let username = format!("reauth{suffix}@example.com");

    // Admin creates a non-admin user and discovers its id.
    let user_id = srv
        .create_user(&username, "pw123456-reauth", "reader")
        .await;

    // Admin reauth → 204 (no cached verdicts, but still succeeds idempotently).
    let resp = client
        .post(format!("{}/admin/users/{user_id}/reauth", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "admin reauth succeeds");

    // Unknown id → 404.
    let resp = client
        .post(format!("{}/admin/users/9999999/reauth", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "unknown user → 404");

    // Non-admin caller → 403 (gated by require_admin).
    let resp = client
        .post(format!("{}/admin/users/{user_id}/reauth", srv.base_url))
        .basic_auth(&username, Some("pw123456-reauth"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-admin reauth → 403");
}

/// Create a proxy repository; `upstream_password` is accepted but REDACTED in
/// all responses (write-only).
#[tokio::test]
async fn proxy_password_is_write_only_and_redacted() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let name = format!("proxy{}", common::unique());

    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": name,
            "kind": "proxy",
            "remote_url": "https://api.nuget.org/v3/index.json",
            "upstream_username": "svc",
            "upstream_password": "s3cret",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "proxy create should succeed");
    let body: Value = resp.json().await.unwrap();
    // No password field anywhere; only a boolean flag.
    assert_eq!(body["has_upstream_password"], json!(true));
    assert!(body.get("upstream_password").is_none());
    assert_eq!(body["upstream_username"], json!("svc"));

    // GET also redacts.
    let resp = client
        .get(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("upstream_password").is_none());
    assert_eq!(body["has_upstream_password"], json!(true));
}

/// A proxy `remote_url` is only scheme-checked — a non-http(s) scheme is
/// rejected (400), while a private/loopback address is accepted (upstream
/// config is admin-only).
#[tokio::test]
async fn remote_url_scheme_guarded_private_accepted() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let name = format!("ssrf{}", common::unique());

    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": name,
            "kind": "proxy",
            "remote_url": "ftp://example.com/index.json",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "non-http scheme must be rejected");

    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": name,
            "kind": "proxy",
            "remote_url": "http://127.0.0.1:6379/index.json",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "loopback remote_url is accepted");
}

/// Token issue returns the plaintext **once**; an admin-scoped token then
/// authenticates against the admin API (an unscoped one is refused, see
/// [`unscoped_admin_token_cannot_use_admin_api`]); revoke disables it.
#[tokio::test]
async fn token_issue_use_and_revoke() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    // Find the admin user's id.
    let users: Value = client
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&u, Some(&p))
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
        .find(|x| x["username"] == json!(u))
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    // Issue an admin-scoped (automation) token.
    let resp = client
        .post(format!("{}/admin/users/{admin_id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": "ci", "scope": {"actions": ["admin"]}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    let token_id = body["id"].as_i64().unwrap();
    assert!(!token.is_empty());
    assert_eq!(body["scope"], json!({"actions": ["admin"]}), "scope echoed");

    // The token authenticates via the X-NuGet-ApiKey header on the admin API.
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "issued token should authenticate");

    // Revoke it.
    let resp = client
        .delete(format!("{}/admin/tokens/{token_id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Now the token is rejected (present-but-invalid → 401).
    let resp = client
        .get(format!("{}/admin/repositories", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "revoked token must be rejected");
}

/// Look up the bootstrap admin's user id.
async fn admin_id(srv: &common::TestServer) -> i64 {
    let (u, p) = srv.admin_basic();
    let users: Value = srv
        .client()
        .get(format!("{}/admin/users", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    users
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["username"] == json!(u))
        .unwrap()["id"]
        .as_i64()
        .unwrap()
}

/// Issue a token for the bootstrap admin with an optional scope (as the
/// admin, password-authenticated); returns the plaintext secret.
async fn admin_token_with_scope(srv: &common::TestServer, scope: Option<Value>) -> String {
    let (u, p) = srv.admin_basic();
    let id = admin_id(srv).await;
    let mut body = json!({"name": "b4"});
    if let Some(scope) = scope {
        body["scope"] = scope;
    }
    let resp = srv
        .client()
        .post(format!("{}/admin/users/{id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

/// B4: an admin's **unscoped** API token is not an admin credential: it cannot
/// mint tokens or create users (403), so a leaked feed token cannot outlive
/// its own revocation. It keeps its owner's feed reach.
#[tokio::test]
async fn unscoped_admin_token_cannot_use_admin_api() {
    let srv = common::start().await;
    let client = srv.client();
    let id = admin_id(&srv).await;

    // Both the legacy "no scope" and an empty scope object.
    for scope in [
        None,
        Some(json!({})),
        Some(json!({"actions": ["read", "write", "delete"]})),
    ] {
        let token = admin_token_with_scope(&srv, scope.clone()).await;

        let resp = client
            .post(format!("{}/admin/users/{id}/tokens", srv.base_url))
            .header("X-NuGet-ApiKey", &token)
            .json(&json!({"name": "minted-by-token"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{scope:?}: token must not mint tokens");

        let resp = client
            .post(format!("{}/admin/users", srv.base_url))
            .header("X-NuGet-ApiKey", &token)
            .json(&json!({
                "username": format!("evil{}@example.com", common::unique()),
                "role": "admin"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{scope:?}: token must not create users");

        let resp = client
            .get(format!("{}/admin/repositories", srv.base_url))
            .header("X-NuGet-ApiKey", &token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{scope:?}: no admin reads either");
    }

    // The unscoped token still publishes (the owner's write reach is kept).
    let repo = format!("b4feed{}", common::unique());
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(srv.admin_basic().0, Some(srv.admin_basic().1))
        .json(&json!({"name": repo, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let token = admin_token_with_scope(&srv, None).await;
    let form = reqwest::multipart::Form::new().part(
        "package",
        reqwest::multipart::Part::bytes(common::make_nupkg("B4.Pkg", "1.0.0"))
            .file_name("package.nupkg")
            .mime_str("application/octet-stream")
            .unwrap(),
    );
    let resp = client
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "unscoped admin token still publishes");

    // The password principal is unaffected.
    let (u, p) = srv.admin_basic();
    let resp = client
        .post(format!("{}/admin/users/{id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": "by-password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "password admin mints tokens");
}

/// B4: a token whose scope explicitly lists `admin` (and does not restrict
/// repositories) may call the admin API, including minting tokens; a
/// repo-restricted admin scope may not.
#[tokio::test]
async fn admin_scoped_token_can_use_admin_api() {
    let srv = common::start().await;
    let client = srv.client();
    let id = admin_id(&srv).await;

    let token = admin_token_with_scope(&srv, Some(json!({"actions": ["admin"]}))).await;
    let resp = client
        .post(format!("{}/admin/users/{id}/tokens", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .json(&json!({"name": "minted-by-admin-token"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "admin-scoped token mints tokens");
    let resp = client
        .post(format!("{}/admin/users", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .json(&json!({
            "username": format!("automated{}@example.com", common::unique())
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "admin-scoped token creates users");

    let repo_id = repository_dao::insert_repository(
        &srv.pool,
        NewRepository::hosted(format!("b4scoped{}", common::unique())),
    )
    .await
    .unwrap()
    .id;
    let token = admin_token_with_scope(
        &srv,
        Some(json!({"actions": ["admin"], "repositories": [repo_id]})),
    )
    .await;
    let resp = client
        .post(format!("{}/admin/users/{id}/tokens", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .json(&json!({"name": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "repo-restricted scope is never global admin"
    );
}

/// L6: token views carry the stored scope, and a scope with an unknown key is
/// rejected instead of issuing (or leaving) an unscoped token.
#[tokio::test]
async fn token_scope_is_listed_and_unknown_keys_rejected() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let id = admin_id(&srv).await;

    let resp = client
        .post(format!("{}/admin/users/{id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": "typo", "scope": {"repos": [3]}}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "mistyped scope key must be rejected, got {}",
        resp.status()
    );
    let resp = client
        .post(format!("{}/admin/users/{id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": "typo", "scop": {"actions": ["read"]}}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_client_error(),
        "mistyped top-level key must be rejected, got {}",
        resp.status()
    );

    let name = format!("scoped{}", common::unique());
    let created: Value = client
        .post(format!("{}/admin/users/{id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": name, "scope": {"actions": ["read"]}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token_id = created["id"].as_i64().unwrap();
    assert_eq!(created["scope"], json!({"actions": ["read"]}));

    let list: Value = client
        .get(format!("{}/admin/users/{id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let listed = list
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == json!(token_id))
        .expect("token listed");
    assert_eq!(listed["scope"], json!({"actions": ["read"]}));
    assert!(list
        .as_array()
        .unwrap()
        .iter()
        .all(|t| t.get("scope").is_some()));

    // PATCH with a mistyped key is rejected and leaves the scope in place.
    for body in [
        json!({"scope": {"repos": [1]}}),
        json!({"scop": {"actions": ["write"]}}),
    ] {
        let resp = client
            .patch(format!("{}/admin/tokens/{token_id}/scope", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_client_error(), "{body}: {}", resp.status());
    }
    let stored = forge_db::token_dao::find_token_by_id(&srv.pool, token_id)
        .await
        .unwrap()
        .unwrap()
        .scope;
    assert_eq!(
        stored,
        Some(json!({"actions": ["read"]})),
        "scope unchanged"
    );
}

/// L5: `PATCH /admin/tokens/{id}/scope` needs the `scope` key. `{}` (what
/// `JSON.stringify({scope: undefined})` sends) is refused with 400 instead of
/// clearing the scope, which would widen the token to its owner's full reach;
/// only an explicit `"scope": null` clears it.
#[tokio::test]
async fn token_scope_patch_clears_only_on_explicit_null() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let id = admin_id(&srv).await;

    let created: Value = client
        .post(format!("{}/admin/users/{id}/tokens", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(
            &json!({"name": format!("narrow{}", common::unique()), "scope": {"actions": ["read"]}}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token_id = created["id"].as_i64().unwrap();
    let patch = |body: Value| {
        client
            .patch(format!("{}/admin/tokens/{token_id}/scope", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
    };
    let stored = || async {
        forge_db::token_dao::find_token_by_id(&srv.pool, token_id)
            .await
            .unwrap()
            .unwrap()
            .scope
    };

    let resp = patch(json!({})).await.unwrap();
    assert_eq!(resp.status(), 400, "an empty body must not clear the scope");
    assert_eq!(stored().await, Some(json!({"actions": ["read"]})));

    let resp = patch(json!({"scope": {"actions": ["read", "write"]}}))
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(stored().await, Some(json!({"actions": ["read", "write"]})));

    let resp = patch(json!({"scope": null})).await.unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(stored().await, None, "an explicit null clears the scope");
}

/// Deleting a **proxy** repository that has cached packages must decrement the
/// referenced blobs' ref-counts (enqueuing outbox deletes at zero) so S3 objects
/// can be reclaimed — a raw FK cascade would orphan the blob references. The
/// repository is then removed (204).
#[tokio::test]
async fn delete_proxy_repo_decrefs_cached_blobs() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("proxydel{s}");
    let sha = format!("{:0>64}", format!("deadbeef{s}"));
    let s3_key = format!("blobs/{sha}");

    // Seed a proxy repo with a cached package: blob (committed, ref_count 1) +
    // component + asset — mirroring what the proxy download path persists.
    let repo = repository_dao::insert_repository(
        &srv.pool,
        NewRepository {
            remote_url: Some("https://api.nuget.org/v3/index.json".into()),
            ..NewRepository::proxy(name.clone())
        },
    )
    .await
    .unwrap();

    assert!(
        blob_dao::upsert_pending(&srv.pool, &sha, 123, &s3_key)
            .await
            .unwrap(),
        "blob should be newly inserted"
    );
    {
        let mut tx = srv.pool.begin().await.unwrap();
        blob_dao::commit_and_incref(&mut tx, &sha).await.unwrap();
        let comp = component_dao::insert_component(
            &mut *tx,
            NewComponent {
                repository_id: repo.id,
                name: "somepkg".into(),
                original_id: "SomePkg".into(),
                version: "1.0.0".into(),
                version_original: "1.0.0".into(),
                listed: true,
            },
        )
        .await
        .unwrap();
        asset_dao::insert_asset(
            &mut *tx,
            NewAsset {
                component_id: comp.id,
                path: "somepkg.1.0.0.nupkg".into(),
                content_type: "application/octet-stream".into(),
                blob_sha256: sha.clone(),
                size: 123,
                sha512_base64: Some("c2hh".into()),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let before = blob_dao::get_blob(&srv.pool, &sha).await.unwrap().unwrap();
    assert_eq!(before.ref_count, 1, "blob seeded with one reference");

    // Delete the proxy repository.
    let resp = client
        .delete(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "proxy repo with cache must delete");

    // The repository is gone.
    assert!(repository_dao::find_repository_by_name(&srv.pool, &name)
        .await
        .unwrap()
        .is_none());

    // The blob ref-count was decremented to zero (not leaked).
    let after = blob_dao::get_blob(&srv.pool, &sha).await.unwrap().unwrap();
    assert_eq!(
        after.ref_count, 0,
        "blob ref-count must be decremented on repo delete"
    );

    // A deferred delete was enqueued so the S3 object is reclaimable (grace=0).
    let enqueued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM blob_outbox WHERE sha256 = $1 AND op = 'delete_object'",
    )
    .bind(&sha)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(
        enqueued, 1,
        "an outbox delete must be enqueued at zero refs"
    );
}

/// Deleting a **hosted** repository that still owns packages is refused (409);
/// the admin must hard-delete the packages first.
#[tokio::test]
async fn delete_hosted_repo_with_packages_refused() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let name = format!("hosteddel{s}");

    let repo = repository_dao::insert_repository(&srv.pool, NewRepository::hosted(name.clone()))
        .await
        .unwrap();
    component_dao::insert_component(
        &srv.pool,
        NewComponent {
            repository_id: repo.id,
            name: "pkg".into(),
            original_id: "Pkg".into(),
            version: "1.0.0".into(),
            version_original: "1.0.0".into(),
            listed: true,
        },
    )
    .await
    .unwrap();

    let resp = client
        .delete(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        409,
        "hosted repo with packages must be refused"
    );

    // Still present.
    assert!(repository_dao::find_repository_by_name(&srv.pool, &name)
        .await
        .unwrap()
        .is_some());
}

/// Group membership: a hosted member and a **nested group** member are
/// accepted; an edge that would create a cycle is rejected with 409; duplicate
/// priorities are rejected with 409.
#[tokio::test]
async fn group_member_validation() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let group = format!("grp{s}");
    let group2 = format!("grp2_{s}");
    let hosted = format!("host{s}");

    let create = |name: &str, kind: &str| {
        let url = format!("{}/admin/repositories", srv.base_url);
        let (u, p) = (u.clone(), p.clone());
        let body = json!({"name": name, "kind": kind});
        let client = client.clone();
        async move {
            client
                .post(url)
                .basic_auth(&u, Some(&p))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    assert_eq!(create(&group, "group").await, 201);
    assert_eq!(create(&group2, "group").await, 201);
    assert_eq!(create(&hosted, "hosted").await, 201);

    let add = |into_group: String, member: String, priority: i32| {
        let url = format!("{}/admin/repositories/{into_group}/members", srv.base_url);
        let (u, p) = (u.clone(), p.clone());
        let body = json!({"member": member, "priority": priority});
        let client = client.clone();
        async move {
            client
                .post(url)
                .basic_auth(&u, Some(&p))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    // Hosted member at priority 10 → created.
    assert_eq!(add(group.clone(), hosted.clone(), 10).await, 201);
    // A nested group member is ALLOWED: group2 nested under group.
    assert_eq!(
        add(group.clone(), group2.clone(), 20).await,
        201,
        "nested group member must be accepted"
    );
    // Closing a cycle (group nested back under group2) → 409.
    assert_eq!(
        add(group2.clone(), group.clone(), 30).await,
        409,
        "edge creating a cycle must be rejected"
    );
    // Duplicate priority/member → 409.
    assert_eq!(
        add(group.clone(), hosted.clone(), 10).await,
        409,
        "duplicate priority/member must be rejected"
    );
}

/// Group members can be flagged as owners of the group's package ids (review
/// M-c): when added or later, shown in the member list, never a proxy.
#[tokio::test]
async fn group_member_owner_flag() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let base = srv.base_url.clone();
    for (name, kind, extra) in [
        (format!("ogrp{s}"), "group", json!({})),
        (format!("orel{s}"), "hosted", json!({})),
        (format!("odev{s}"), "hosted", json!({})),
        (
            format!("oprx{s}"),
            "proxy",
            json!({"remote_url": "https://api.nuget.org/v3/index.json"}),
        ),
    ] {
        let mut body = json!({"name": name, "kind": kind});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let resp = client
            .post(format!("{base}/admin/repositories"))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    }
    let members = format!("{base}/admin/repositories/ogrp{s}/members");
    let add = |body: serde_json::Value| {
        let (client, url, u, p) = (client.clone(), members.clone(), u.clone(), p.clone());
        async move {
            client
                .post(url)
                .basic_auth(&u, Some(&p))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(
        add(json!({"member": format!("orel{s}"), "priority": 50, "owner": true})).await,
        201
    );
    assert_eq!(
        add(json!({"member": format!("odev{s}"), "priority": 10})).await,
        201
    );
    assert_eq!(
        add(json!({"member": format!("oprx{s}"), "priority": 100, "owner": true})).await,
        400,
        "a proxy cannot own ids"
    );
    assert_eq!(
        add(json!({"member": format!("oprx{s}"), "priority": 100})).await,
        201
    );

    let owners = || {
        let (client, url, u, p) = (client.clone(), members.clone(), u.clone(), p.clone());
        async move {
            let list: Vec<serde_json::Value> = client
                .get(url)
                .basic_auth(&u, Some(&p))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let mut owners: Vec<String> = list
                .iter()
                .filter(|m| m["owner"] == json!(true))
                .map(|m| m["name"].as_str().unwrap().to_string())
                .collect();
            owners.sort();
            owners
        }
    };
    assert_eq!(owners().await, [format!("orel{s}")]);

    let patch = |member: String, body: serde_json::Value| {
        let (client, u, p) = (client.clone(), u.clone(), p.clone());
        let url = format!("{members}/{member}");
        async move {
            client
                .patch(url)
                .basic_auth(&u, Some(&p))
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(patch(format!("odev{s}"), json!({"owner": true})).await, 204);
    assert_eq!(
        patch(format!("orel{s}"), json!({"owner": false})).await,
        204
    );
    assert_eq!(owners().await, [format!("odev{s}")]);
    assert_eq!(patch(format!("oprx{s}"), json!({"owner": true})).await, 400);
    assert_eq!(patch(format!("ogrp{s}"), json!({"owner": true})).await, 404);
    assert_eq!(
        patch(format!("odev{s}"), json!({"owners": true})).await,
        422
    );

    // An owner is neither removed from the group nor deleted while flagged:
    // the group would silently fall back to trusting every hosted member.
    let remove = client
        .delete(format!("{members}/odev{s}"))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(remove.status(), 409);
    let delete = client
        .delete(format!("{base}/admin/repositories/odev{s}"))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 409);
    assert!(delete.text().await.unwrap().contains(&format!("ogrp{s}")));
    assert_eq!(
        patch(format!("odev{s}"), json!({"owner": false})).await,
        204
    );
    let remove = client
        .delete(format!("{members}/odev{s}"))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(remove.status(), 204);
}

// ── secret encryption at rest ───────────────────────────────────────────────

/// Serializes the crypto-enabled tests of this binary: they share the
/// cluster-wide rotation advisory lock (and the `default` key scope). Each
/// runs on a database of its own (`common::fresh_pool`): a server with
/// `[crypto]` seals install-wide secrets, such as the registry token key,
/// that a server without it refuses to open or replace.
static CRYPTO_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Root-key env var for the crypto-enabled server below. One fixed key for the
/// whole test binary: the Postgres container (and so the `encryption_key`
/// rows) is shared, so every crypto-enabled server must reach the same root.
fn ensure_crypto_root_env() -> &'static str {
    const VAR: &str = "FORGE_TEST_SERVER_ROOT_KEY";
    // 32 fixed bytes, base64 — a *test* root key, never used outside tests.
    std::env::set_var(VAR, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
    VAR
}

/// With `[crypto]` enabled: a created proxy password is stored as an envelope
/// blob (plaintext column NULL, ciphertext free of the plaintext), responses
/// stay redacted, `/admin/crypto/keys` returns metadata only (and is
/// admin-gated), and a DEK rotation re-seals the stored secret while it keeps
/// decrypting to the original value.
#[tokio::test]
async fn crypto_encrypts_proxy_password_at_rest_and_rotates() {
    let _serial = CRYPTO_SERIAL.lock().await;
    let var = ensure_crypto_root_env();
    let crypto_block = format!(
        "[crypto]\n[crypto.root]\nprovider = \"env\"\nroot_key_env = \"{var}\"\n\
         [crypto.rotation]\nenabled = false\n"
    );
    let admin = format!("admin{}@example.com", common::unique());
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((admin, "adminpw".into())),
            crypto_block: Some(crypto_block),
            ..Default::default()
        },
    )
    .await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let name = format!("cryptoproxy{}", common::unique());

    // Create a proxy with a password → redacted response, encrypted at rest.
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": name,
            "kind": "proxy",
            "remote_url": "https://api.nuget.org/v3/index.json",
            "upstream_username": "svc",
            "upstream_password": "s3cret-at-rest",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["has_upstream_password"], json!(true));
    assert!(body.get("upstream_password").is_none());
    let repo_id = body["id"].as_i64().expect("repo id");

    // At rest: plaintext column NULL, envelope blob present + plaintext-free.
    let row = sqlx::query!(
        r#"SELECT upstream_password, upstream_password_enc FROM repository WHERE id = $1"#,
        repo_id
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert!(row.upstream_password.is_none(), "no plaintext column value");
    let blob = row.upstream_password_enc.expect("envelope blob stored");
    assert!(
        !blob.windows(14).any(|w| w == b"s3cret-at-rest"),
        "ciphertext must not contain the plaintext"
    );

    // The sanctioned decrypt path returns the original plaintext.
    let envelope = srv.state.envelope.as_ref().expect("envelope enabled");
    let secret = forge_db::secret_dao::get_upstream_password(&srv.pool, envelope, repo_id)
        .await
        .unwrap()
        .expect("password stored");
    assert_eq!(
        forge_crypto::ExposeSecret::expose_secret(&secret),
        "s3cret-at-rest"
    );

    // /admin/crypto/keys: admin-gated, metadata only, never key bytes/secrets.
    let resp = client
        .get(format!("{}/admin/crypto/keys", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "anonymous crypto-keys call must be 401");
    let resp = client
        .get(format!("{}/admin/crypto/keys", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let raw = resp.text().await.unwrap();
    assert!(!raw.contains("wrapped_key"), "no key bytes in {raw}");
    assert!(!raw.contains("s3cret-at-rest"), "no plaintext in {raw}");
    let keys: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(keys["enabled"], json!(true));
    assert!(keys["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .any(|k| k["layer"] == "dek"));
    assert!(keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["layer"] == "kek"));

    // DEK rotation re-seals the stored blob; the secret still decrypts.
    let resp = client
        .post(format!("{}/admin/crypto/rotate/dek", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let rot: Value = resp.json().await.unwrap();
    assert_eq!(rot["rotated"], json!("dek"));
    assert!(rot["resealed_secrets"].as_u64().unwrap() >= 1);

    let row = sqlx::query!(
        r#"SELECT upstream_password_enc AS "b!" FROM repository WHERE id = $1"#,
        repo_id
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_ne!(row.b, blob, "rotation must re-seal the blob");
    let secret = forge_db::secret_dao::get_upstream_password(&srv.pool, envelope, repo_id)
        .await
        .unwrap()
        .expect("still stored");
    assert_eq!(
        forge_crypto::ExposeSecret::expose_secret(&secret),
        "s3cret-at-rest"
    );

    // KEK rotation leaves the secret ciphertext untouched and decryptable.
    let resp = client
        .post(format!("{}/admin/crypto/rotate/kek", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let after_kek = sqlx::query!(
        r#"SELECT upstream_password_enc AS "b!" FROM repository WHERE id = $1"#,
        repo_id
    )
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(after_kek.b, row.b, "KEK rotation must not touch ciphertext");
    let secret = forge_db::secret_dao::get_upstream_password(&srv.pool, envelope, repo_id)
        .await
        .unwrap()
        .expect("still stored");
    assert_eq!(
        forge_crypto::ExposeSecret::expose_secret(&secret),
        "s3cret-at-rest"
    );
}

/// Review M13: admin rotations take the rotation worker's cluster-wide
/// advisory lock, so a rotation requested while another one (the worker, or
/// an admin request on another instance) is running gets 409 instead of
/// racing it; once the lock is free the same request succeeds.
#[tokio::test]
async fn crypto_rotation_is_serialized_with_the_rotation_worker() {
    let _serial = CRYPTO_SERIAL.lock().await;
    let var = ensure_crypto_root_env();
    let crypto_block = format!(
        "[crypto]\n[crypto.root]\nprovider = \"env\"\nroot_key_env = \"{var}\"\n\
         [crypto.rotation]\nenabled = false\n"
    );
    let admin = format!("admin{}@example.com", common::unique());
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((admin, "adminpw".into())),
            crypto_block: Some(crypto_block),
            ..Default::default()
        },
    )
    .await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    // Another holder of the rotation lock (as the worker's pass would be).
    let mut holder = srv.pool.acquire().await.unwrap();
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(forge_server::crypto::ROTATION_LOCK_KEY)
        .fetch_one(&mut *holder)
        .await
        .unwrap();
    assert!(got, "test must hold the rotation lock");

    for layer in ["dek", "kek", "root"] {
        let resp = client
            .post(format!("{}/admin/crypto/rotate/{layer}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            409,
            "rotate/{layer} must not run while a rotation holds the lock"
        );
    }
    // An unknown layer is still a plain 400, lock or not.
    let resp = client
        .post(format!("{}/admin/crypto/rotate/bogus", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(forge_server::crypto::ROTATION_LOCK_KEY)
        .execute(&mut *holder)
        .await
        .unwrap();
    drop(holder);

    let resp = client
        .post(format!("{}/admin/crypto/rotate/kek", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "free lock: the rotation runs");
    // …and released it again: a second rotation is not locked out.
    let resp = client
        .post(format!("{}/admin/crypto/rotate/root", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "the admin rotation released the lock");
}

/// The generated registry token key survives DEK rotation (#196): rotation
/// re-seals it, and its DEK stays until then. An instance that starts after
/// the old DEK is revoked loads the same key, so it accepts the tokens the
/// running instances sign, instead of generating a key of its own.
#[tokio::test]
async fn registry_token_key_survives_dek_rotation() {
    let _serial = CRYPTO_SERIAL.lock().await;
    let var = ensure_crypto_root_env();
    let crypto_block = format!(
        "[crypto]\n[crypto.root]\nprovider = \"env\"\nroot_key_env = \"{var}\"\n\
         [crypto.rotation]\nenabled = false\n"
    );
    let admin = format!("admin{}@example.com", common::unique());
    // A database of its own: the key and the DEKs are install-wide.
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((admin, "adminpw".into())),
            crypto_block: Some(crypto_block),
            ..Default::default()
        },
    )
    .await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let stored = || async {
        forge_db::authz_dao::get_setting(&srv.pool, forge_server::registry::TOKEN_KEY_SETTING)
            .await
            .unwrap()
            .expect("the generated key is stored")
    };
    let before = stored().await;
    assert!(before.starts_with("sealed:"), "{before}");

    let resp = client
        .post(format!("{}/admin/crypto/rotate/dek", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let rot: Value = resp.json().await.unwrap();
    assert!(rot["revoked_deks"].as_u64().unwrap() >= 1, "{rot}");
    let after = stored().await;
    assert_ne!(after, before, "re-sealed under the new DEK");

    let restarted = forge_server::registry::load_token_keys(
        &srv.state.config,
        &srv.pool,
        srv.state.envelope.as_deref(),
    )
    .await
    .unwrap();
    assert_eq!(stored().await, after, "not replaced");
    let now = chrono::Utc::now().timestamp();
    let claims = forge_oci::token::Claims {
        iss: forge_oci::token::issuer("https://forge.example.com"),
        aud: "forge.example.com".into(),
        sub: "anonymous".into(),
        iat: now,
        nbf: now,
        exp: now + 300,
        jti: "j".into(),
        access: Vec::new(),
        fp: forge_oci::token::TokenPrincipal::Anonymous,
    };
    let token = forge_oci::token::issue(&srv.state.registry_keys, &claims).unwrap();
    assert!(
        forge_oci::token::verify(&restarted, &token, &claims.iss, &claims.aud).is_some(),
        "a restarted instance accepts the running instance's tokens"
    );
}

/// The OIDC issuer keys are sealed like every other secret and survive DEK
/// rotation: rotation re-seals them, and an instance that starts afterwards
/// publishes and signs with the same keys instead of generating its own.
#[tokio::test]
async fn oidc_issuer_keys_are_sealed_and_survive_dek_rotation() {
    let _serial = CRYPTO_SERIAL.lock().await;
    let var = ensure_crypto_root_env();
    let crypto_block = format!(
        "[crypto]\n[crypto.root]\nprovider = \"env\"\nroot_key_env = \"{var}\"\n\
         [crypto.rotation]\nenabled = false\n"
    );
    let admin = format!("admin{}@example.com", common::unique());
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((admin, "adminpw".into())),
            crypto_block: Some(crypto_block),
            ..Default::default()
        },
    )
    .await;
    let (u, p) = srv.admin_basic();
    let kids = |keys: &forge_core::oidc::IssuerKeySet| {
        keys.keys()
            .iter()
            .map(|k| k.kid().to_string())
            .collect::<Vec<_>>()
    };
    let created = srv.state.assertion_issuer.ensure().await.unwrap();
    let stored = || async {
        forge_db::authz_dao::get_setting(&srv.pool, forge_server::auth::ISSUER_KEYS_SETTING)
            .await
            .unwrap()
            .expect("the issuer keys are stored")
    };
    let before = stored().await;
    assert!(before.starts_with("sealed:"), "{before}");

    let resp = srv
        .client()
        .post(format!("{}/admin/crypto/rotate/dek", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let after = stored().await;
    assert_ne!(after, before, "re-sealed under the new DEK");

    let restarted = forge_server::auth::AssertionIssuer::new(
        srv.pool.clone(),
        srv.state.envelope.clone(),
        srv.state.config.public_base_url(),
    );
    assert_eq!(kids(&restarted.ensure().await.unwrap()), kids(&created));
    assert_eq!(stored().await, after, "not replaced");
}

/// Without `[crypto]`, rotation is a 409 and `/admin/crypto/keys` reports
/// disabled.
#[tokio::test]
async fn crypto_disabled_reports_and_rejects() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();

    let resp = client
        .get(format!("{}/admin/crypto/keys", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], json!(false));

    let resp = client
        .post(format!("{}/admin/crypto/rotate/dek", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "rotation without [crypto] must 409");
}

/// Create a local user through the admin API and sign it in through
/// `/auth/login`; returns `(user_id, session_cookie_pair, csrf_token)`.
async fn create_and_login(
    srv: &common::TestServer,
    username: &str,
    password: &str,
) -> (i64, String, String) {
    let client = srv.client();
    let user_id = srv.create_user(username, password, "reader").await;
    let resp = client
        .post(format!("{}/auth/login", srv.base_url))
        .json(&json!({"username": username, "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "login succeeds");
    let cookie = resp
        .headers()
        .get("set-cookie")
        .expect("session cookie")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body: Value = resp.json().await.unwrap();
    let csrf = body["csrf_token"].as_str().expect("csrf").to_string();
    (user_id, cookie, csrf)
}

/// Review M5: `PATCH /admin/users/{id}` with `{"active": false}` cuts a user
/// off everywhere — its live browser session is revoked, its API token and
/// password stop working — and `{"active": true}` restores password/token
/// access (the revoked session stays dead). Bad bodies, unknown ids and
/// non-admin callers are refused.
#[tokio::test]
async fn deactivate_cuts_off_sessions_tokens_and_passwords() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let username = format!("deact{}@example.com", common::unique());
    let password = "pw123456-login";
    let (user_id, cookie, csrf) = create_and_login(&srv, &username, password).await;

    // The user mints a token from its session.
    let resp = client
        .post(format!("{}/auth/tokens", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .json(&json!({"name": "cli"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let token = resp.json::<Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let me_with_token = || {
        client
            .get(format!("{}/admin/me", srv.base_url))
            .header("X-NuGet-ApiKey", &token)
            .send()
    };
    assert_eq!(me_with_token().await.unwrap().status(), 200);

    // Validation: empty body, unknown fields, unknown id, non-admin caller.
    let patch = |id: i64, body: Value| {
        client
            .patch(format!("{}/admin/users/{id}", srv.base_url))
            .basic_auth(&au, Some(&ap))
            .json(&body)
            .send()
    };
    assert_eq!(patch(user_id, json!({})).await.unwrap().status(), 400);
    assert_eq!(
        patch(user_id, json!({"active": false, "is_admin": true}))
            .await
            .unwrap()
            .status(),
        422,
        "unknown fields are rejected, not ignored"
    );
    assert_eq!(
        patch(9_999_999, json!({"active": false}))
            .await
            .unwrap()
            .status(),
        404
    );
    let resp = client
        .patch(format!("{}/admin/users/{user_id}", srv.base_url))
        .basic_auth(&username, Some(password))
        .json(&json!({"active": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "non-admin cannot deactivate");

    // Deactivate.
    let resp = patch(user_id, json!({"active": false})).await.unwrap();
    assert_eq!(resp.status(), 200);
    let view: Value = resp.json().await.unwrap();
    assert_eq!(view["active"], json!(false));
    assert_eq!(view["id"], json!(user_id));

    let live_sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM session WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&srv.pool)
    .await
    .unwrap();
    assert_eq!(live_sessions, 0, "deactivation revokes every session");

    let resp = client
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "the browser session is dead");
    assert_eq!(
        me_with_token().await.unwrap().status(),
        401,
        "API tokens of an inactive user are refused"
    );
    let resp = client
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&username, Some(password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "password auth is refused");
    let resp = client
        .post(format!("{}/auth/login", srv.base_url))
        .json(&json!({"username": username, "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "no new session for an inactive user");

    // Reactivate: password and token work again; the old session does not.
    let resp = patch(user_id, json!({"active": true})).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["active"], json!(true));
    assert_eq!(me_with_token().await.unwrap().status(), 200);
    let resp = client
        .get(format!("{}/admin/me", srv.base_url))
        .basic_auth(&username, Some(password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "a revoked session stays revoked");
}

/// `(active, holds the built-in admin role)` of a user.
async fn admin_state(pool: &sqlx::PgPool, id: i64) -> (bool, bool) {
    sqlx::query_as(
        "SELECT u.active, EXISTS (
             SELECT 1 FROM user_role ur JOIN role r ON r.id = ur.role_id
             WHERE ur.user_id = u.id AND r.name = 'admin')
         FROM app_user u WHERE u.id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Create an active admin through the API, returning its id.
async fn create_admin(srv: &common::TestServer, username: &str, password: &str) -> i64 {
    srv.create_user(username, password, "admin").await
}

/// L4: nothing takes admin away from the last active administrator, not
/// deactivating or deleting the account and not unassigning its `admin`
/// role, since getting an administrator back would take SQL (a deleted
/// bootstrap admin is never re-created). Each path answers 409 and changes
/// nothing. An inactive admin does not count.
#[tokio::test]
async fn the_last_active_admin_cannot_lose_admin() {
    // Its own database: the shared one holds every other test's admins.
    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let boot = admin_id(&srv).await;
    let admin_role = forge_db::authz_dao::role_id_by_name(&srv.pool, "admin")
        .await
        .unwrap()
        .unwrap();
    let req = |method: reqwest::Method, path: &str, body: &Option<Value>| {
        let rb = client.request(method, format!("{}{path}", srv.base_url));
        match body {
            Some(body) => rb.json(body),
            None => rb,
        }
    };
    let removals = |id: i64| {
        [
            (
                reqwest::Method::PATCH,
                format!("/admin/users/{id}"),
                Some(json!({"active": false})),
            ),
            (
                reqwest::Method::DELETE,
                format!("/admin/users/{id}/roles/{admin_role}"),
                None,
            ),
            (reqwest::Method::DELETE, format!("/admin/users/{id}"), None),
        ]
    };

    // The bootstrap admin removes itself.
    let dormant = create_admin(&srv, "dormant@example.com", "pw-dormant-admin").await;
    forge_db::user_dao::set_active(&srv.pool, dormant, false)
        .await
        .unwrap();
    for (method, path, body) in removals(boot) {
        let resp = req(method, &path, &body)
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 409, "{path}");
    }
    assert_eq!(admin_state(&srv.pool, boot).await, (true, true));

    // With a second admin, the bootstrap admin may step down, and the second
    // one is then the last.
    let second = create_admin(&srv, "second@example.com", "pw-second-admin").await;
    let resp = req(
        reqwest::Method::DELETE,
        &format!("/admin/users/{boot}/roles/{admin_role}"),
        &None,
    )
    .basic_auth(&u, Some(&p))
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 204, "another active admin remains");

    let session = srv.login("second@example.com", "pw-second-admin").await;
    for (method, path, body) in removals(second) {
        let resp = session
            .apply(req(method, &path, &body))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 409, "{path}");
    }
    assert_eq!(admin_state(&srv.pool, second).await, (true, true));
    let resp = session
        .apply(req(
            reqwest::Method::DELETE,
            &format!("/admin/users/{boot}"),
            &None,
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "a former admin can be deleted");
}

/// L4: the last-admin guard is race-safe. Two admins deactivated at once
/// would each still see the other as an admin; the guard runs them one at a
/// time on the built-in `admin` role row, so the second is refused (409) and
/// one active admin remains.
#[tokio::test]
async fn concurrent_admin_deactivations_leave_one_admin() {
    let srv = common::start_with(common::fresh_pool().await, common::ServerOpts::default()).await;
    let (u, p) = srv.admin_basic();
    let boot = admin_id(&srv).await;
    let second = create_admin(&srv, "second@example.com", "pw-second-admin").await;

    // Hold the role row so both requests park inside the guard.
    let mut holder = srv.pool.begin().await.unwrap();
    let pid = backend_pid(&mut holder).await;
    sqlx::query("SELECT 1 FROM role WHERE name = 'admin' FOR NO KEY UPDATE")
        .execute(&mut *holder)
        .await
        .unwrap();
    let deactivate = |id: i64| {
        let (client, url, u, p) = (
            srv.client(),
            format!("{}/admin/users/{id}", srv.base_url),
            u.clone(),
            p.clone(),
        );
        tokio::spawn(async move {
            client
                .patch(url)
                .basic_auth(u, Some(p))
                .json(&json!({"active": false}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    };
    let (a, b) = (deactivate(boot), deactivate(second));
    wait_blocked_behind(&srv.pool, pid, 2).await;
    holder.commit().await.unwrap();

    let mut statuses = vec![a.await.unwrap(), b.await.unwrap()];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 409]);
    let (boot_active, ..) = admin_state(&srv.pool, boot).await;
    let (second_active, ..) = admin_state(&srv.pool, second).await;
    assert!(
        boot_active != second_active,
        "exactly one admin stays active"
    );
}

/// `POST /auth/tokens` mints unscoped tokens only: a `scope` in the body is
/// refused, never dropped (which would hand back an unscoped token).
#[tokio::test]
async fn auth_tokens_refuses_a_scope_it_would_drop() {
    let srv = common::start().await;
    let username = format!("scoped{}@example.com", common::unique());
    let (_id, cookie, csrf) = create_and_login(&srv, &username, "pw123456-login").await;
    let resp = srv
        .client()
        .post(format!("{}/auth/tokens", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .json(&json!({"name": "ci", "scope": {"actions": ["read"]}}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error(), "{}", resp.status());
}

/// Review M5 / L6: the cookie-authenticated `/auth/me` and `/auth/tokens`
/// endpoints check the session user's live `active` flag, not just the
/// session row — even a session that was never revoked (e.g. the account was
/// disabled directly in the database) grants nothing once the user is
/// inactive: no listing, no minting, no revoking.
#[tokio::test]
async fn auth_tokens_refuse_inactive_user_with_live_session() {
    let srv = common::start().await;
    let client = srv.client();
    let username = format!("inact{}@example.com", common::unique());
    let (user_id, cookie, csrf) = create_and_login(&srv, &username, "pw123456-login").await;

    let resp = client
        .post(format!("{}/auth/tokens", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .json(&json!({"name": "before"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let token_id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();

    // Disable the account without touching its session.
    sqlx::query("UPDATE app_user SET active = false WHERE id = $1")
        .bind(user_id)
        .execute(&srv.pool)
        .await
        .unwrap();

    let resp = client
        .get(format!("{}/auth/tokens", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "list refused for an inactive user");
    let resp = client
        .post(format!("{}/auth/tokens", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .json(&json!({"name": "after"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "mint refused for an inactive user");
    let resp = client
        .delete(format!("{}/auth/tokens/{token_id}", srv.base_url))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "revoke refused for an inactive user");
    let resp = client
        .get(format!("{}/auth/me", srv.base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let minted: i64 = sqlx::query_scalar("SELECT count(*) FROM token WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    assert_eq!(minted, 1, "no token was minted for the inactive user");
}

/// Review M5: `POST /admin/users/{id}/reauth` also revokes the user's browser
/// sessions, so a signed-in browser has to log in (and re-validate) again.
#[tokio::test]
async fn reauth_revokes_sessions() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let username = format!("reauthsess{}@example.com", common::unique());
    let (user_id, cookie, _csrf) = create_and_login(&srv, &username, "pw123456-login").await;

    let me = || {
        client
            .get(format!("{}/auth/me", srv.base_url))
            .header("cookie", &cookie)
            .send()
    };
    assert_eq!(me().await.unwrap().status(), 200);

    let resp = client
        .post(format!("{}/admin/users/{user_id}/reauth", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(
        me().await.unwrap().status(),
        401,
        "reauth kills the live session"
    );
}

// ── repository update semantics (M2), names (M18), anonymous_read (M20) ─────

/// Whether any password (plaintext column or sealed blob) is stored. Tests on
/// a crypto-less server use this rather than the plaintext column: a
/// crypto-enabled server started by a parallel test backfills plaintext
/// passwords of the shared database into sealed blobs.
async fn has_password(pool: &sqlx::PgPool, id: i64) -> bool {
    let (_, pw, enc, ..) = stored_creds(pool, id).await;
    pw.is_some() || enc
}

/// The stored credential columns of a repository:
/// `(username, plaintext password, has encrypted blob, metadata ttl, not-found ttl)`.
async fn stored_creds(
    pool: &sqlx::PgPool,
    id: i64,
) -> (
    Option<String>,
    Option<String>,
    bool,
    Option<i32>,
    Option<i32>,
) {
    let row = sqlx::query!(
        r#"
        SELECT upstream_username, upstream_password, upstream_password_enc,
               metadata_ttl_seconds, not_found_ttl_seconds
        FROM repository WHERE id = $1
        "#,
        id
    )
    .fetch_one(pool)
    .await
    .unwrap();
    (
        row.upstream_username,
        row.upstream_password,
        row.upstream_password_enc.is_some(),
        row.metadata_ttl_seconds,
        row.not_found_ttl_seconds,
    )
}

/// Create a proxy with credentials and TTLs via the admin API; returns its id.
async fn create_cred_proxy(srv: &common::TestServer, name: &str, url: &str) -> i64 {
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "name": name,
            "kind": "proxy",
            "remote_url": url,
            "upstream_username": "svc",
            "upstream_password": "private-pat",
            "metadata_ttl_seconds": 60,
            "not_found_ttl_seconds": 30,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap()
}

async fn put_repo(srv: &common::TestServer, name: &str, body: Value) -> reqwest::Response {
    let (u, p) = srv.admin_basic();
    srv.client()
        .put(format!("{}/admin/repositories/{name}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// #65: changing a proxy's `remote_url` forgets what it learned from the
/// previous upstream: versions never downloaded (and the not-found markers)
/// are dropped, downloaded ones lose their not-found and missing flags. An
/// update that keeps the URL leaves the rows alone.
#[tokio::test]
async fn repointing_a_proxy_resets_its_cached_version_rows() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let name = format!("repoint{}", common::unique());
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": name, "kind": "proxy",
                      "remote_url": "https://feed-a.example/v3/index.json"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    let seed = || async {
        sqlx::query("DELETE FROM proxy_cached_version WHERE repository_id = $1")
            .bind(id)
            .execute(&srv.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO proxy_cached_version \
                 (repository_id, name, version, listed, downloaded, not_found, not_found_at, \
                  upstream_missing, metadata_refreshed_at) VALUES \
             ($1, 'contoso.lib', '*', false, false, true, now(), false, NULL), \
             ($1, 'contoso.lib', '1.0.0', true, false, false, NULL, false, now()), \
             ($1, 'sample', '2.0.0', true, true, true, now(), true, now())",
        )
        .bind(id)
        .execute(&srv.pool)
        .await
        .unwrap();
    };
    let rows = || async {
        sqlx::query_as::<_, (String, String, bool, bool, bool)>(
            "SELECT name, version, downloaded, not_found, upstream_missing \
             FROM proxy_cached_version WHERE repository_id = $1 ORDER BY name, version",
        )
        .bind(id)
        .fetch_all(&srv.pool)
        .await
        .unwrap()
    };

    seed().await;
    let resp = put_repo(
        &srv,
        &name,
        json!({"remote_url": "https://feed-a.example/v3/index.json"}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(rows().await.len(), 3, "the same URL keeps every row");

    let resp = put_repo(
        &srv,
        &name,
        json!({"remote_url": "https://feed-b.example/v3/index.json"}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        rows().await,
        [(
            "sample".to_string(),
            "2.0.0".to_string(),
            true,
            false,
            false
        )],
        "only the downloaded version stays, with its flags cleared"
    );
}

/// M2: update body semantics — absent keeps, `null` clears (TTLs fall back to
/// the default), a value sets.
#[tokio::test]
async fn repo_update_absent_keeps_null_clears() {
    let srv = common::start().await;
    let name = format!("credsem{}", common::unique());
    let id = create_cred_proxy(&srv, &name, "https://feed.example.com/v3/index.json").await;

    // Absent fields keep everything (incl. the password).
    let resp = put_repo(&srv, &name, json!({"online": true})).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["upstream_credentials_dropped"], json!(false));
    assert_eq!(body["has_upstream_password"], json!(true));
    let (user, _, _, meta, nf) = stored_creds(&srv.pool, id).await;
    assert_eq!(
        (user.as_deref(), meta, nf),
        (Some("svc"), Some(60), Some(30))
    );
    assert!(has_password(&srv.pool, id).await, "password kept");

    // A value sets.
    let resp = put_repo(
        &srv,
        &name,
        json!({"upstream_username": "svc2", "metadata_ttl_seconds": 120}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let (user, _, _, meta, nf) = stored_creds(&srv.pool, id).await;
    assert_eq!(
        (user.as_deref(), meta, nf),
        (Some("svc2"), Some(120), Some(30))
    );
    assert!(has_password(&srv.pool, id).await, "password kept");

    // `null` clears each of the four fields.
    let resp = put_repo(
        &srv,
        &name,
        json!({
            "upstream_username": null,
            "upstream_password": null,
            "metadata_ttl_seconds": null,
            "not_found_ttl_seconds": null,
        }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["upstream_username"], Value::Null);
    assert_eq!(body["has_upstream_password"], json!(false));
    assert_eq!(body["metadata_ttl_seconds"], Value::Null);
    assert_eq!(body["not_found_ttl_seconds"], Value::Null);
    assert_eq!(
        stored_creds(&srv.pool, id).await,
        (None, None, false, None, None)
    );
}

/// M2: credentials stay with their origin. A same-origin path change keeps
/// them; a different host, scheme or port drops username and password unless
/// the request sets a new password, and the response says so.
#[tokio::test]
async fn repo_update_origin_change_drops_credentials() {
    let srv = common::start().await;
    let name = format!("credorigin{}", common::unique());
    let id = create_cred_proxy(&srv, &name, "https://feed.example.com/v3/index.json").await;

    // Same origin (default port spelled out), different path: kept.
    let resp = put_repo(
        &srv,
        &name,
        json!({"remote_url": "https://FEED.example.com:443/other/v3/index.json"}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["upstream_credentials_dropped"], json!(false));
    assert_eq!(stored_creds(&srv.pool, id).await.0.as_deref(), Some("svc"));
    assert!(has_password(&srv.pool, id).await, "password kept");

    // A new origin with a new password: the new credentials are kept.
    let resp = put_repo(
        &srv,
        &name,
        json!({
            "remote_url": "https://mirror.example.net/v3/index.json",
            "upstream_username": "mirror",
            "upstream_password": "mirror-pat",
        }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["upstream_credentials_dropped"], json!(false));
    assert_eq!(
        stored_creds(&srv.pool, id).await.0.as_deref(),
        Some("mirror")
    );
    assert!(has_password(&srv.pool, id).await, "new password stored");

    // Repointing to a different origin without a new password drops both.
    for url in [
        "https://api.nuget.org/v3/index.json",     // host
        "http://api.nuget.org/v3/index.json",      // scheme
        "http://api.nuget.org:8080/v3/index.json", // port
    ] {
        sqlx::query!(
            "UPDATE repository SET upstream_username = 'svc', upstream_password = 'pat' WHERE id = $1",
            id
        )
        .execute(&srv.pool)
        .await
        .unwrap();
        let resp = put_repo(&srv, &name, json!({"remote_url": url})).await;
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["upstream_credentials_dropped"], json!(true), "{url}");
        assert_eq!(body["has_upstream_password"], json!(false), "{url}");
        assert_eq!(body["upstream_username"], Value::Null, "{url}");
        let (user, pw, enc, ..) = stored_creds(&srv.pool, id).await;
        assert_eq!((user, pw, enc), (None, None, false), "{url}");
    }

    // Nothing stored: nothing reported as dropped.
    let resp = put_repo(
        &srv,
        &name,
        json!({"remote_url": "https://feed.example.com/v3/index.json"}),
    )
    .await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["upstream_credentials_dropped"], json!(false));

    // A username sent along an origin change is applied; the old password is not.
    sqlx::query!(
        "UPDATE repository SET upstream_username = 'svc', upstream_password = 'pat' WHERE id = $1",
        id
    )
    .execute(&srv.pool)
    .await
    .unwrap();
    let resp = put_repo(
        &srv,
        &name,
        json!({"remote_url": "https://other.example.com/v3/index.json", "upstream_username": "new"}),
    )
    .await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["upstream_credentials_dropped"], json!(true));
    assert_eq!(stored_creds(&srv.pool, id).await.0.as_deref(), Some("new"));
    assert!(!has_password(&srv.pool, id).await, "old password dropped");
}

/// M2 with secret encryption: an origin change drops the encrypted blob too,
/// a kept legacy plaintext password is sealed (never carried forward), and
/// `null` clears the blob.
#[tokio::test]
async fn repo_update_with_encryption_never_keeps_plaintext() {
    let var = ensure_crypto_root_env();
    let crypto_block = format!(
        "[crypto]\n[crypto.root]\nprovider = \"env\"\nroot_key_env = \"{var}\"\n\
         [crypto.rotation]\nenabled = false\n"
    );
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            crypto_block: Some(crypto_block),
            ..Default::default()
        },
    )
    .await;
    let envelope = srv.state.envelope.as_ref().expect("envelope enabled");
    let name = format!("credenc{}", common::unique());
    let id = create_cred_proxy(&srv, &name, "https://feed.example.com/v3/index.json").await;
    let (_, pw, enc, ..) = stored_creds(&srv.pool, id).await;
    assert_eq!((pw, enc), (None, true), "sealed at create");

    // A legacy (pre-backfill) plaintext value on a kept password is sealed.
    sqlx::query!(
        "UPDATE repository SET upstream_password = 'legacy-pat', upstream_password_enc = NULL WHERE id = $1",
        id
    )
    .execute(&srv.pool)
    .await
    .unwrap();
    let resp = put_repo(&srv, &name, json!({"online": true})).await;
    assert_eq!(resp.status(), 200);
    let (_, pw, enc, ..) = stored_creds(&srv.pool, id).await;
    assert_eq!((pw, enc), (None, true), "plaintext not carried forward");
    let secret = forge_db::secret_dao::get_upstream_password(&srv.pool, envelope, id)
        .await
        .unwrap()
        .expect("still stored");
    assert_eq!(
        forge_crypto::ExposeSecret::expose_secret(&secret),
        "legacy-pat"
    );

    // Both a plaintext leftover and a blob: the update nulls the plaintext.
    sqlx::query!(
        "UPDATE repository SET upstream_password = 'leftover' WHERE id = $1",
        id
    )
    .execute(&srv.pool)
    .await
    .unwrap();
    put_repo(&srv, &name, json!({"online": true})).await;
    let (_, pw, enc, ..) = stored_creds(&srv.pool, id).await;
    assert_eq!((pw, enc), (None, true));

    // An origin change without a new password drops the sealed blob.
    let resp = put_repo(
        &srv,
        &name,
        json!({"remote_url": "https://api.nuget.org/v3/index.json"}),
    )
    .await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["upstream_credentials_dropped"], json!(true));
    let (user, pw, enc, ..) = stored_creds(&srv.pool, id).await;
    assert_eq!((user, pw, enc), (None, None, false));

    // Set, then clear with `null`.
    put_repo(&srv, &name, json!({"upstream_password": "fresh"})).await;
    let (_, pw, enc, ..) = stored_creds(&srv.pool, id).await;
    assert_eq!((pw, enc), (None, true));
    put_repo(&srv, &name, json!({"upstream_password": null})).await;
    let (_, pw, enc, ..) = stored_creds(&srv.pool, id).await;
    assert_eq!((pw, enc), (None, false));
}

/// An OIDC realm whose sealed client secret no longer decrypts (its issuer
/// was changed in SQL) is repaired through `PATCH`: the stored secret counts
/// as absent, so an update without one is a 400 naming it (never a 500, and
/// the sealed copy is left alone), and one that carries it re-seals it.
#[tokio::test]
async fn realm_with_undecryptable_secrets_is_repaired_through_patch() {
    let var = ensure_crypto_root_env();
    let crypto_block = format!(
        "[crypto]\n[crypto.root]\nprovider = \"env\"\nroot_key_env = \"{var}\"\n\
         [crypto.rotation]\nenabled = false\n"
    );
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            crypto_block: Some(crypto_block),
            ..Default::default()
        },
    )
    .await;
    let envelope = srv.state.envelope.as_ref().expect("envelope enabled");
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let resp = client
        .post(format!("{}/admin/realms", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({
            "kind": "oidc",
            "name": format!("repairidp{}", common::unique()),
            "enabled": false,
            "config": {
                "issuer": "https://login.example.com/tenant/v2.0",
                "client_id": "forge",
                "client_secret": "first-secret",
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    let issuer = "https://login.example.org/tenant/v2.0";
    sqlx::query("UPDATE auth_realm SET config = jsonb_set(config, '{issuer}', to_jsonb($2::text)) WHERE id = $1")
        .bind(id)
        .bind(issuer)
        .execute(&srv.pool)
        .await
        .unwrap();
    let sealed = || forge_db::auth_realm_dao::find_realm_by_id(&srv.pool, id);
    let broken = sealed().await.unwrap().unwrap();
    assert!(
        forge_db::secret_dao::realm_config(Some(envelope), &broken)
            .await
            .is_err(),
        "the secret is bound to the old issuer"
    );

    let patch = |body: Value| {
        client
            .patch(format!("{}/admin/realms/{id}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
    };
    for body in [
        json!({"enabled": false}),
        json!({"config": {"issuer": issuer, "client_id": "forge"}}),
    ] {
        let resp = patch(body.clone()).await.unwrap();
        assert_eq!(resp.status(), 400, "{body}");
        let msg = resp.text().await.unwrap();
        assert!(msg.contains("client_secret"), "{body}: {msg}");
    }
    let unchanged = sealed().await.unwrap().unwrap();
    assert_eq!(unchanged.secrets_enc, broken.secrets_enc, "left alone");

    let resp = patch(json!({"config": {
        "issuer": issuer,
        "client_id": "forge",
        "client_secret": "second-secret",
    }}))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["config"]["client_secret_set"], json!(true));
    let repaired = sealed().await.unwrap().unwrap();
    let config = forge_db::secret_dao::realm_config(Some(envelope), &repaired)
        .await
        .expect("re-sealed for the new issuer");
    assert_eq!(config["client_secret"], json!("second-secret"));
    assert_eq!(config["issuer"], json!(issuer));

    let resp = client
        .delete(format!("{}/admin/realms/{id}", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

/// M18: repository names are URL path segments: anything outside
/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, and the reserved `new`, is a 400 on
/// create and on rename.
#[tokio::test]
async fn repository_names_are_validated() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let create = |name: String| {
        let client = client.clone();
        let (u, p) = (u.clone(), p.clone());
        let url = format!("{}/admin/repositories", srv.base_url);
        async move {
            client
                .post(url)
                .basic_auth(&u, Some(&p))
                .json(&json!({"name": name, "kind": "hosted"}))
                .send()
                .await
                .unwrap()
        }
    };

    for bad in [
        "Team Packages".to_string(),
        "a%20b".to_string(),
        "a/b".to_string(),
        "".to_string(),
        "-leading".to_string(),
        ".hidden".to_string(),
        "x".repeat(65),
        "new".to_string(),
        "NEW".to_string(),
        "nëw".to_string(),
    ] {
        let resp = create(bad.clone()).await;
        assert_eq!(resp.status(), 400, "{bad:?} must be rejected");
        let msg = resp.text().await.unwrap();
        assert!(msg.contains("repository name"), "{bad:?}: {msg}");
    }

    let s = common::unique();
    for good in [
        format!("Team.Packages_{s}"),
        format!("a-{s}"),
        format!("9{s}"),
        format!("{s}{}", "x".repeat(64 - s.to_string().len())),
        format!("new{s}"),
    ] {
        assert_eq!(
            create(good.clone()).await.status(),
            201,
            "{good:?} is valid"
        );
    }

    // Rename is validated too; an unchanged name is not re-checked.
    let name = format!("a-{s}");
    let resp = put_repo(&srv, &name, json!({"name": "has space"})).await;
    assert_eq!(resp.status(), 400);
    let resp = put_repo(&srv, &name, json!({"name": "New"})).await;
    assert_eq!(resp.status(), 400);
    let resp = put_repo(&srv, &name, json!({"name": name})).await;
    assert_eq!(resp.status(), 200);
}

/// Repository and realm bodies refuse a misspelled field instead of dropping
/// it: a dropped `reserved_prefixes` turned a group's dependency-confusion
/// guard off, and a dropped `anonymous_read` left a repository public.
#[tokio::test]
async fn repository_and_realm_bodies_reject_unknown_fields() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let post = |path: &str, body: Value| {
        client
            .post(format!("{}{path}", srv.base_url))
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
    };

    let resp = post(
        "/admin/repositories",
        json!({"name": format!("strictgrp{s}"), "kind": "group", "reserved_prefix": ["acme."]}),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), 422);
    let msg = resp.text().await.unwrap();
    assert!(msg.contains("unknown field `reserved_prefix`"), "{msg}");
    let name = format!("strict{s}");
    let resp = post(
        "/admin/repositories",
        json!({"name": name, "kind": "hosted", "anonymous_read": true}),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), 201);
    let resp = put_repo(&srv, &name, json!({"anonymous": false})).await;
    assert_eq!(resp.status(), 422);
    let resp = put_repo(&srv, &name, json!({"anonymous_read": false})).await;
    assert_eq!(resp.status(), 200);

    let config = json!({"url": "https://nexus.internal/status", "key_pepper": "pepper"});
    let realm = json!({
        "kind": "credential_forwarding",
        "name": format!("strict{s}"),
        "enabled": false,
        "config": config,
    });
    let mut with_priority = realm.clone();
    with_priority["priority"] = json!(1);
    let resp = post("/admin/realms", with_priority).await.unwrap();
    assert_eq!(resp.status(), 422);
    for (kind, config, typo) in [
        (
            "credential_forwarding",
            json!({"url": "https://nexus.internal/status", "key_pepper": "p", "identity_pth": "login"}),
            "identity_pth",
        ),
        (
            "oidc",
            json!({
                "issuer": "https://login.example.com", "client_id": "forge",
                "client_secret": "s", "required_claim": {"hd": ["corp.example"]}
            }),
            "required_claim",
        ),
    ] {
        let resp = post(
            "/admin/realms",
            json!({"kind": kind, "name": format!("typo{typo}{s}"), "enabled": false, "config": config}),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 400, "{kind}");
        let msg = resp.text().await.unwrap();
        assert!(msg.contains(&format!("unknown field `{typo}`")), "{msg}");
    }
    let resp = post("/admin/realms", realm).await.unwrap();
    assert_eq!(resp.status(), 201);
    let realm_url = format!(
        "{}/admin/realms/{}",
        srv.base_url,
        resp.json::<Value>().await.unwrap()["id"]
    );
    let patch = |body: Value| {
        client
            .patch(&realm_url)
            .basic_auth(&u, Some(&p))
            .json(&body)
            .send()
    };
    assert_eq!(patch(json!({"enable": true})).await.unwrap().status(), 422);
    assert_eq!(
        patch(json!({"enabled": false})).await.unwrap().status(),
        200
    );
    // A misspelled key inside `config` is refused too: a dropped
    // `identity_path` let any token holder sign in as any account.
    let resp = patch(json!({"config": {
        "url": "https://nexus.internal/status", "identity_pth": "login"
    }}))
    .await
    .unwrap();
    assert_eq!(resp.status(), 400);
    let msg = resp.text().await.unwrap();
    assert!(msg.contains("unknown field `identity_pth`"), "{msg}");
    // The redaction marker a client echoes back is not an unknown field.
    let resp = patch(json!({"config": {
        "url": "https://nexus.internal/status", "key_pepper_set": true, "identity_path": "login"
    }}))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .delete(&realm_url)
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

/// M20: turning `anonymous_read` off also deletes the anonymous role's
/// unscoped read grant on the repository (what migration 0007 synthesized),
/// while an update that leaves the flag off does not touch explicit grants.
#[tokio::test]
async fn anonymous_read_off_deletes_the_synthesized_grant() {
    let srv = common::start_with(
        common::fresh_pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            ..Default::default()
        },
    )
    .await;
    srv.set_auth_settings(serde_json::json!({"anonymous_mode": "all"}))
        .await;
    let (u, p) = srv.admin_basic();
    let client = srv.client();
    let anon_role = forge_db::authz_dao::role_id_by_name(&srv.pool, "anonymous")
        .await
        .unwrap()
        .unwrap();
    let anon_grant = |repo_id: i64| {
        let pool = srv.pool.clone();
        async move {
            forge_db::authz_dao::list_grants_for_role(&pool, anon_role)
                .await
                .unwrap()
                .iter()
                .any(|g| g.repository_id == Some(repo_id) && g.action == "read")
        }
    };

    // An upgraded repository: the flag plus the grant 0007 synthesized from it.
    let public = format!("anonoff{}", common::unique());
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": public, "kind": "hosted", "anonymous_read": true}))
        .send()
        .await
        .unwrap();
    let public_id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    forge_db::authz_dao::add_grant(&srv.pool, anon_role, Some(public_id), "read", None)
        .await
        .unwrap();
    let index = format!("{}/v3/{public}/index.json", srv.base_url);
    assert_eq!(client.get(&index).send().await.unwrap().status(), 200);

    let resp = put_repo(&srv, &public, json!({"anonymous_read": false})).await;
    assert_eq!(resp.status(), 200);
    assert!(!anon_grant(public_id).await, "synthesized grant removed");
    assert_eq!(
        client.get(&index).send().await.unwrap().status(),
        401,
        "anonymous read really ends"
    );

    // A repository that was never anonymous_read keeps an explicit grant even
    // when an update (the SPA sends the whole form) repeats `false`.
    let explicit = format!("anonexplicit{}", common::unique());
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&u, Some(&p))
        .json(&json!({"name": explicit, "kind": "hosted", "anonymous_read": false}))
        .send()
        .await
        .unwrap();
    let explicit_id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    forge_db::authz_dao::add_grant(&srv.pool, anon_role, Some(explicit_id), "read", None)
        .await
        .unwrap();
    let resp = put_repo(
        &srv,
        &explicit,
        json!({"anonymous_read": false, "online": true}),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert!(anon_grant(explicit_id).await, "explicit RBAC grant kept");
}

// ── delete concurrency (review 2026-10-02 B1 / L3) ──────────────────────────

/// A 64-hex-char test sha unique to this run (`tag` keeps tests apart).
fn test_sha(tag: &str) -> String {
    format!("{:0>64}", format!("{tag}{}", common::unique()))
}

/// Seed a package `name`/`version` in `repo_id` whose single asset references
/// the (already inserted) blob `sha`, incrementing its ref-count — what a
/// publish or a proxy cache fill commits.
async fn seed_package(pool: &sqlx::PgPool, repo_id: i64, name: &str, version: &str, sha: &str) {
    let mut tx = pool.begin().await.unwrap();
    insert_package_in(&mut tx, repo_id, name, version, sha).await;
    tx.commit().await.unwrap();
}

/// The writes of [`seed_package`], inside the caller's (open) transaction.
async fn insert_package_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repo_id: i64,
    name: &str,
    version: &str,
    sha: &str,
) {
    let comp = component_dao::insert_component(
        &mut **tx,
        NewComponent {
            repository_id: repo_id,
            name: name.into(),
            original_id: name.into(),
            version: version.into(),
            version_original: version.into(),
            listed: true,
        },
    )
    .await
    .unwrap();
    asset_dao::insert_asset(
        &mut **tx,
        NewAsset {
            component_id: comp.id,
            path: format!("{name}.{version}.nupkg"),
            content_type: "application/octet-stream".into(),
            blob_sha256: sha.into(),
            size: 123,
            sha512_base64: Some("c2hh".into()),
        },
    )
    .await
    .unwrap();
    blob_dao::commit_and_incref(tx, sha).await.unwrap();
}

async fn ref_count(pool: &sqlx::PgPool, sha: &str) -> i64 {
    blob_dao::get_blob(pool, sha)
        .await
        .unwrap()
        .expect("blob row present")
        .ref_count
}

async fn outbox_deletes(pool: &sqlx::PgPool, sha: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM blob_outbox WHERE sha256 = $1 AND op = 'delete_object'",
    )
    .bind(sha)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The backend pid of an open transaction.
async fn backend_pid(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await
        .unwrap()
}

/// Wait until at least `n` backends are blocked — directly or through another
/// blocked backend — behind the locks held by `holder_pid`. Makes the
/// interleavings below deterministic instead of sleep-based.
async fn wait_blocked_behind(pool: &sqlx::PgPool, holder_pid: i32, n: i64) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let blocked: i64 = sqlx::query_scalar(
            r#"
            WITH RECURSIVE waiter(pid) AS (
                SELECT pid FROM pg_stat_activity
                WHERE $1 = ANY(pg_blocking_pids(pid))
                UNION
                SELECT a.pid FROM pg_stat_activity a
                JOIN waiter w ON w.pid = ANY(pg_blocking_pids(a.pid))
            )
            SELECT count(*) FROM waiter
            "#,
        )
        .bind(holder_pid)
        .fetch_one(pool)
        .await
        .unwrap();
        if blocked >= n {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "only {blocked} of {n} backends ever blocked behind pid {holder_pid}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Fire two identical admin `DELETE`s at `url` while the test holds the blob
/// row of `sha` `FOR UPDATE`, release it only once both requests are parked
/// behind that lock (directly or behind each other), and return both statuses
/// sorted. Before the B1 fix both requests read the same asset set without a
/// lock and each decremented the shared blob.
async fn race_two_deletes(srv: &common::TestServer, url: &str, sha: &str) -> Vec<u16> {
    let (u, p) = srv.admin_basic();
    let mut holder = srv.pool.begin().await.unwrap();
    let pid = backend_pid(&mut holder).await;
    sqlx::query("SELECT 1 FROM blob WHERE sha256 = $1 FOR UPDATE")
        .bind(sha)
        .execute(&mut *holder)
        .await
        .unwrap();

    let send = || {
        let (client, url, u, p) = (srv.client(), url.to_string(), u.clone(), p.clone());
        tokio::spawn(async move {
            client
                .delete(url)
                .basic_auth(u, Some(p))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    };
    let (a, b) = (send(), send());
    wait_blocked_behind(&srv.pool, pid, 2).await;
    holder.commit().await.unwrap();

    let mut statuses = vec![a.await.unwrap(), b.await.unwrap()];
    statuses.sort_unstable();
    statuses
}

/// B1: two overlapping admin hard deletes of the same version, whose blob is
/// shared with another repository, must decrement the blob exactly once — the
/// loser finds the version gone (404) — so the other repository keeps its
/// reference and no S3 delete is queued.
#[tokio::test]
async fn concurrent_hard_deletes_decrement_shared_blob_once() {
    let srv = common::start().await;
    let s = common::unique();
    let dev =
        repository_dao::insert_repository(&srv.pool, NewRepository::hosted(format!("dev{s}")))
            .await
            .unwrap();
    let release =
        repository_dao::insert_repository(&srv.pool, NewRepository::hosted(format!("rel{s}")))
            .await
            .unwrap();
    let sha = test_sha("b1hd");
    blob_dao::upsert_pending(&srv.pool, &sha, 123, &format!("blobs/{sha}"))
        .await
        .unwrap();
    seed_package(&srv.pool, dev.id, "shared", "1.0.0", &sha).await;
    seed_package(&srv.pool, release.id, "shared", "1.0.0", &sha).await;
    assert_eq!(ref_count(&srv.pool, &sha).await, 2);

    let url = format!(
        "{}/admin/repositories/{}/packages/shared/1.0.0",
        srv.base_url, dev.name
    );
    let statuses = race_two_deletes(&srv, &url, &sha).await;
    assert_eq!(statuses, vec![204, 404], "exactly one delete wins");

    assert_eq!(
        ref_count(&srv.pool, &sha).await,
        1,
        "the shared blob must be decremented once, not twice"
    );
    assert_eq!(
        outbox_deletes(&srv.pool, &sha).await,
        0,
        "a still-referenced blob must not be queued for deletion"
    );
    assert!(
        component_dao::find_component(&srv.pool, release.id, "shared", "1.0.0")
            .await
            .unwrap()
            .is_some(),
        "the other repository's package is untouched"
    );
}

/// B1 (repository purge): two overlapping deletes of a proxy repository whose
/// cached blob is shared with another repository must decrement it once.
#[tokio::test]
async fn concurrent_proxy_repo_deletes_decrement_shared_blob_once() {
    let srv = common::start().await;
    let s = common::unique();
    let proxy = repository_dao::insert_repository(
        &srv.pool,
        NewRepository {
            remote_url: Some("https://api.nuget.org/v3/index.json".into()),
            ..NewRepository::proxy(format!("pxrace{s}"))
        },
    )
    .await
    .unwrap();
    let hosted =
        repository_dao::insert_repository(&srv.pool, NewRepository::hosted(format!("hxrace{s}")))
            .await
            .unwrap();
    let sha = test_sha("b1px");
    blob_dao::upsert_pending(&srv.pool, &sha, 123, &format!("blobs/{sha}"))
        .await
        .unwrap();
    seed_package(&srv.pool, proxy.id, "cached", "2.0.0", &sha).await;
    seed_package(&srv.pool, hosted.id, "cached", "2.0.0", &sha).await;

    let url = format!("{}/admin/repositories/{}", srv.base_url, proxy.name);
    let statuses = race_two_deletes(&srv, &url, &sha).await;
    assert_eq!(statuses, vec![204, 404], "exactly one delete wins");

    assert_eq!(ref_count(&srv.pool, &sha).await, 1);
    assert_eq!(outbox_deletes(&srv.pool, &sha).await, 0);
}

/// L3: a proxy cache fill that commits while the repository delete is in
/// flight must be purged *with* its blob decrement. The delete locks the
/// repository row first, so it waits for the fill and then sees its component;
/// before the fix the emptiness snapshot was taken outside the delete
/// transaction and the FK cascade dropped the new asset, leaking its blob
/// reference.
#[tokio::test]
async fn proxy_repo_delete_accounts_for_inflight_cache_fill() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let s = common::unique();
    let proxy = repository_dao::insert_repository(
        &srv.pool,
        NewRepository {
            remote_url: Some("https://api.nuget.org/v3/index.json".into()),
            ..NewRepository::proxy(format!("pxfill{s}"))
        },
    )
    .await
    .unwrap();
    let sha = test_sha("l3px");
    blob_dao::upsert_pending(&srv.pool, &sha, 123, &format!("blobs/{sha}"))
        .await
        .unwrap();

    // The in-flight fill: its component insert holds FOR KEY SHARE on the
    // repository row until it commits.
    let mut fill = srv.pool.begin().await.unwrap();
    let pid = backend_pid(&mut fill).await;
    insert_package_in(&mut fill, proxy.id, "late", "1.0.0", &sha).await;

    let delete = {
        let (client, url) = (
            srv.client(),
            format!("{}/admin/repositories/{}", srv.base_url, proxy.name),
        );
        tokio::spawn(async move {
            client
                .delete(url)
                .basic_auth(u, Some(p))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    };
    wait_blocked_behind(&srv.pool, pid, 1).await;
    fill.commit().await.unwrap();

    assert_eq!(delete.await.unwrap(), 204);
    assert!(repository_dao::find_repository_by_id(&srv.pool, proxy.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        ref_count(&srv.pool, &sha).await,
        0,
        "the late component's blob reference must be released"
    );
    assert_eq!(
        outbox_deletes(&srv.pool, &sha).await,
        1,
        "the now-unreferenced blob is queued for deletion"
    );
}

/// L3: a publish that commits while a hosted repository delete is in flight
/// must make the delete refuse (409) instead of cascade-deleting the freshly
/// published package.
#[tokio::test]
async fn hosted_repo_delete_refuses_inflight_publish() {
    let srv = common::start().await;
    let (u, p) = srv.admin_basic();
    let s = common::unique();
    let hosted =
        repository_dao::insert_repository(&srv.pool, NewRepository::hosted(format!("hpub{s}")))
            .await
            .unwrap();
    let sha = test_sha("l3h");
    blob_dao::upsert_pending(&srv.pool, &sha, 123, &format!("blobs/{sha}"))
        .await
        .unwrap();

    let mut publish = srv.pool.begin().await.unwrap();
    let pid = backend_pid(&mut publish).await;
    insert_package_in(&mut publish, hosted.id, "fresh", "1.0.0", &sha).await;

    let delete = {
        let (client, url) = (
            srv.client(),
            format!("{}/admin/repositories/{}", srv.base_url, hosted.name),
        );
        tokio::spawn(async move {
            client
                .delete(url)
                .basic_auth(u, Some(p))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    };
    wait_blocked_behind(&srv.pool, pid, 1).await;
    publish.commit().await.unwrap();

    assert_eq!(
        delete.await.unwrap(),
        409,
        "a package published mid-delete must block the delete"
    );
    assert!(
        component_dao::find_component(&srv.pool, hosted.id, "fresh", "1.0.0")
            .await
            .unwrap()
            .is_some(),
        "the published package survives"
    );
    assert_eq!(ref_count(&srv.pool, &sha).await, 1);
}

/// Deleting a proxy repository while a first download is being finalized:
/// the download holds its cached-version row and then takes the foreign-key
/// lock on the repository row (inserting the component). The delete used to
/// lock the repository row first and then wait for the cached version, a
/// lock cycle Postgres broke by aborting one side (a 500 for the download).
/// It now waits for the cached versions first, so the download's
/// foreign-key lock is granted at once.
#[tokio::test]
async fn deleting_a_proxy_waits_for_an_in_flight_download_instead_of_deadlocking() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let name = format!("px{}", common::unique());
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": name, "kind": "proxy",
                      "remote_url": "https://api.nuget.org/v3/index.json"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let repo_id: i64 = sqlx::query_scalar("SELECT id FROM repository WHERE name = $1")
        .bind(&name)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO proxy_cached_version (repository_id, name, version) \
         VALUES ($1, 'contoso.lib', '1.0.0')",
    )
    .bind(repo_id)
    .execute(&srv.pool)
    .await
    .unwrap();

    // The download: holds its cached version...
    let mut download = srv.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM proxy_cached_version WHERE repository_id = $1 FOR UPDATE")
        .bind(repo_id)
        .execute(&mut *download)
        .await
        .unwrap();
    // ...while the delete starts.
    let delete = tokio::spawn({
        let client = client.clone();
        let url = format!("{}/admin/repositories/{name}", srv.base_url);
        async move {
            client
                .delete(url)
                .basic_auth(&au, Some(&ap))
                .send()
                .await
                .unwrap()
                .status()
        }
    });
    // The delete waits: for the cached version (or, in the old lock order,
    // holding the repository row, in the cascade to it).
    common::wait_for_lock_wait(
        &srv.pool,
        &[
            "%FROM proxy_cached_version%FOR UPDATE%",
            "%DELETE FROM repository%",
        ],
    )
    .await;
    // The component insert's foreign-key lock, well before Postgres' 1 s
    // deadlock check would break a cycle.
    sqlx::query("SET LOCAL lock_timeout = '300ms'")
        .execute(&mut *download)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM repository WHERE id = $1 FOR KEY SHARE")
        .bind(repo_id)
        .execute(&mut *download)
        .await
        .expect("the download's foreign-key lock waited on the delete");
    download.commit().await.unwrap();

    assert_eq!(delete.await.unwrap(), 204);
}

/// Each instance has a blob cache of its own: `GET /admin/blob-cache` names
/// the instance its numbers come from, with or without a cache.
#[tokio::test]
async fn blob_cache_statistics_name_their_instance() {
    let dir = tempfile::tempdir().unwrap();
    let with_cache = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((
                format!("admin{}@example.com", common::unique()),
                "adminpw".into(),
            )),
            plugins_block: Some(format!(
                "[blob_cache]\npath = {:?}\n",
                dir.path().join("cache").display().to_string()
            )),
            ..Default::default()
        },
    )
    .await;
    let without_cache = common::start().await;
    for (srv, enabled) in [(&with_cache, true), (&without_cache, false)] {
        let (u, p) = srv.admin_basic();
        let stats: Value = srv
            .client()
            .get(format!("{}/admin/blob-cache", srv.base_url))
            .basic_auth(&u, Some(&p))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(stats["enabled"], enabled, "{stats}");
        let instance = &stats["instance"];
        assert_eq!(instance["host"], json!(srv.state.instance.host), "{stats}");
        let started: chrono::DateTime<chrono::Utc> =
            serde_json::from_value(instance["started_at"].clone()).expect("a start time");
        assert_eq!(started, srv.state.instance.started_at, "{stats}");
    }
    assert!(
        with_cache.state.instance.host.is_some(),
        "this host has a name (HOSTNAME or the kernel's)"
    );
}
