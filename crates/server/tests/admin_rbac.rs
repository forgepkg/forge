//! E2E: §12.4 Phase 6 — admin REST API for fine-grained RBAC.
//!
//! Covers (plan §4 Phase 6 test list):
//! * role CRUD round-trip + built-in protections (can't delete `admin`);
//! * non-admin caller is 403 on every RBAC endpoint;
//! * editing a role's grants invalidates the cache and changes a subsequent
//!   authorization decision (granted read on a closed install lets a previously
//!   denied user read; removing it denies again);
//! * `GET /admin/users/{id}/effective` reflects the grant state;
//! * content-selector CRUD + invalid-glob 400;
//! * user-role assign/unassign with targeted invalidation;
//! * per-token scoping narrows (read-only scoped token cannot write).
//!
//! A brand-new non-admin user holds no roles and is denied by default — exactly
//! the deny-by-default baseline against which a grant's effect is observable.

mod common;

use serde_json::{json, Value};

/// Create a non-admin user, returning `(id, username, password)`.
async fn make_user(srv: &common::TestServer) -> (i64, String, String) {
    let (au, ap) = srv.admin_basic();
    let username = format!("rbac{}", common::unique());
    let password = "pw12345678".to_string();
    let created: Value = srv
        .client()
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"username": username, "password": password, "is_admin": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_i64().expect("user id");
    (id, username, password)
}

/// Publish a `.nupkg` via the NuGet `PUT /v3/{repo}/package` multipart endpoint,
/// authenticating with the given token (`X-NuGet-ApiKey`). Returns the HTTP
/// status so a caller can assert allow (201) / deny (403).
async fn publish_with_token(
    srv: &common::TestServer,
    repo: &str,
    token: &str,
    id: &str,
    version: &str,
) -> reqwest::StatusCode {
    let bytes = common::make_nupkg(id, version);
    let part = reqwest::multipart::Part::bytes(bytes)
        .file_name("package.nupkg")
        .mime_str("application/octet-stream")
        .unwrap();
    let form = reqwest::multipart::Form::new().part("package", part);
    srv.client()
        .put(format!("{}/v3/{repo}/package", srv.base_url))
        .header("X-NuGet-ApiKey", token)
        .multipart(form)
        .send()
        .await
        .unwrap()
        .status()
}

/// Create a hosted repo, returning its name.
async fn make_repo(srv: &common::TestServer) -> String {
    let (au, ap) = srv.admin_basic();
    let name = format!("repo{}", common::unique());
    let resp = srv
        .client()
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": name, "kind": "hosted"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    name
}

/// Role CRUD round-trip + built-in-role protections.
#[tokio::test]
async fn role_crud_and_builtin_protection() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let role_name = format!("ci-readers-{}", common::unique());

    // Create.
    let resp = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": role_name, "description": "CI read access"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let role: Value = resp.json().await.unwrap();
    let role_id = role["id"].as_i64().unwrap();
    assert_eq!(role["builtin"], json!(false));

    // Duplicate name → 409.
    let resp = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": role_name, "description": "dup"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Get.
    let resp = client
        .get(format!("{}/admin/roles/{role_id}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Patch description.
    let resp = client
        .patch(format!("{}/admin/roles/{role_id}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"description": "updated"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let updated: Value = resp.json().await.unwrap();
    assert_eq!(updated["description"], json!("updated"));

    // Delete custom role → 204.
    let resp = client
        .delete(format!("{}/admin/roles/{role_id}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Find the built-in `admin` role and try to delete it → 403.
    let roles: Value = client
        .get(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_role = roles
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == json!("admin"))
        .expect("admin role seeded");
    let admin_role_id = admin_role["id"].as_i64().unwrap();
    assert_eq!(admin_role["builtin"], json!(true));
    let resp = client
        .delete(format!("{}/admin/roles/{admin_role_id}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "built-in role delete must be forbidden");
}

/// A non-admin caller is 403 on the RBAC endpoints.
#[tokio::test]
async fn non_admin_forbidden_on_rbac_endpoints() {
    let srv = common::start().await;
    let (_id, username, password) = make_user(&srv).await;
    let client = srv.client();

    for (method, path) in [
        ("GET", "/admin/roles"),
        ("GET", "/admin/content-selectors"),
        ("GET", "/admin/anonymous/effective"),
    ] {
        let req = match method {
            "GET" => client.get(format!("{}{}", srv.base_url, path)),
            _ => unreachable!(),
        };
        let resp = req
            .basic_auth(&username, Some(&password))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "non-admin must be 403 on {path}");
    }
}

/// Granting a role `read` on a repo, then assigning it to a user, lets a
/// previously-denied user read; the `effective` endpoint reflects it; removing
/// the grant denies again (cache invalidation on mutation).
#[tokio::test]
async fn grant_changes_decision_and_invalidates_cache() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();

    let (user_id, username, password) = make_user(&srv).await;
    let repo = make_repo(&srv).await;

    // Baseline: fresh-closed install ⇒ the user has no roles ⇒ read denied (403).
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .basic_auth(&username, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "no grant ⇒ deny (fail-closed)");

    // Create a role with a (read, repo) grant.
    let role_name = format!("readers-{}", common::unique());
    let role: Value = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": role_name}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_i64().unwrap();

    let resp = client
        .put(format!("{}/admin/roles/{role_id}/grants", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"repository": repo, "action": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // #84: both `role` and `role_id` is refused, never silently resolved to
    // one of them (here a name that differs from the id's role).
    let resp = client
        .put(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"role": "admin", "role_id": role_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Assign the role to the user (targeted invalidation).
    let resp = client
        .put(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"role_id": role_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // The effective endpoint now shows the read grant.
    let eff: Value = client
        .get(format!("{}/admin/users/{user_id}/effective", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let has_read = eff["grants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["action"] == json!("read"));
    assert!(has_read, "effective set must include the read grant: {eff}");

    // The user can now read (the role-grant mutation invalidated the cache).
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .basic_auth(&username, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "granted read ⇒ allow");

    // Remove the grant; the user is denied again.
    let grants: Value = client
        .get(format!("{}/admin/roles/{role_id}/grants", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id = grants.as_array().unwrap()[0]["id"].as_i64().unwrap();
    let resp = client
        .delete(format!(
            "{}/admin/roles/{role_id}/grants/{grant_id}",
            srv.base_url
        ))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .basic_auth(&username, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "grant removed ⇒ deny again");
}

/// Unassigning a role denies a previously-allowed user.
/// A grant body that names its repository the way the grant listing does
/// (`repository_id`) is scoped to that repository, and a body with a field the
/// API does not know is refused instead of silently becoming a grant on every
/// repository. Content selectors likewise refuse a mistyped `include`.
#[tokio::test]
async fn rbac_bodies_reject_unknown_fields() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let repo = make_repo(&srv).await;
    let repo_id: i64 = sqlx::query_scalar("SELECT id FROM repository WHERE name = $1")
        .bind(&repo)
        .fetch_one(&srv.pool)
        .await
        .unwrap();
    let role: Value = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": format!("strict-{}", common::unique())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grants_url = format!("{}/admin/roles/{}/grants", srv.base_url, role["id"]);
    let put = |body: Value| {
        client
            .put(&grants_url)
            .basic_auth(&au, Some(&ap))
            .json(&body)
            .send()
    };

    // The listing's own shape, sent back.
    let resp = put(json!({"repository_id": repo_id, "action": "read"}))
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    // A mistyped field, and both names at once, are refused.
    let resp = put(json!({"repo": repo, "action": "write"})).await.unwrap();
    assert!(resp.status().is_client_error(), "{}", resp.status());
    let resp = put(json!({"repository": repo, "repository_id": repo_id, "action": "write"}))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    // `admin` on one repository delegates nothing (administration is
    // global), so it is refused rather than stored, by name or by id.
    for body in [
        json!({"repository": repo, "action": "admin"}),
        json!({"repository_id": repo_id, "action": "admin"}),
    ] {
        let resp = put(body).await.unwrap();
        assert_eq!(resp.status(), 400);
        let text = resp.text().await.unwrap();
        assert!(text.contains("repository admin is not supported"), "{text}");
    }
    // The table refuses one written past the API as well.
    let role_id = role["id"].as_i64().unwrap();
    let direct =
        forge_db::authz_dao::add_grant(&srv.pool, role_id, Some(repo_id), "admin", None).await;
    assert!(direct.is_err(), "the CHECK constraint refuses it");

    let grants: Value = client
        .get(&grants_url)
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grants = grants.as_array().unwrap();
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(grants[0]["repository_id"], repo_id);
    assert_eq!(grants[0]["action"], "read");

    let resp = client
        .post(format!("{}/admin/content-selectors", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": format!("sel{}", common::unique()), "include": ["acme.*"]}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_client_error(), "{}", resp.status());
}

#[tokio::test]
async fn unassign_role_denies() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();

    let (user_id, username, password) = make_user(&srv).await;
    let repo = make_repo(&srv).await;

    let role_name = format!("temp-{}", common::unique());
    let role: Value = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": role_name}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_i64().unwrap();
    client
        .put(format!("{}/admin/roles/{role_id}/grants", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"repository": repo, "action": "read"}))
        .send()
        .await
        .unwrap();
    client
        .put(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"role_id": role_id}))
        .send()
        .await
        .unwrap();

    // Allowed.
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .basic_auth(&username, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List roles for the user shows the assignment.
    let user_roles: Value = client
        .get(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(user_roles
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == json!(role_id)));

    // Unassign → denied again.
    let resp = client
        .delete(format!(
            "{}/admin/users/{user_id}/roles/{role_id}",
            srv.base_url
        ))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .basic_auth(&username, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "role unassigned ⇒ deny");
}

/// Content-selector CRUD + invalid-glob rejection.
#[tokio::test]
async fn content_selector_crud_and_invalid_glob() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let sel_name = format!("public-{}", common::unique());

    // Create.
    let resp = client
        .post(format!("{}/admin/content-selectors", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({
            "name": sel_name,
            "description": "public packages",
            "includes": ["company.*"],
            "excludes": ["company.secret*"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let sel: Value = resp.json().await.unwrap();
    let sel_id = sel["id"].as_i64().unwrap();
    assert_eq!(sel["includes"], json!(["company.*"]));

    // List shows it.
    let list: Value = client
        .get(format!("{}/admin/content-selectors", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(list
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["id"] == json!(sel_id)));

    // Patch.
    let resp = client
        .patch(format!("{}/admin/content-selectors/{sel_id}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"description": "x", "includes": ["internal.*"], "excludes": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let patched: Value = resp.json().await.unwrap();
    assert_eq!(patched["includes"], json!(["internal.*"]));

    // Invalid glob → 400, never persisted.
    let resp = client
        .post(format!("{}/admin/content-selectors", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": format!("bad-{}", common::unique()), "includes": ["[unterminated"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "uncompilable glob must be rejected");

    // Delete.
    let resp = client
        .delete(format!("{}/admin/content-selectors/{sel_id}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

/// A redeploy replaces a version's bytes, so with `allow_redeploy` on it takes
/// the delete permission as well as write: a push-only token can publish a new
/// version but not overwrite a released one.
#[tokio::test]
async fn redeploy_needs_delete_as_well_as_write() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let (user_id, _username, _password) = make_user(&srv).await;
    let repo = make_repo(&srv).await;
    let resp = client
        .put(format!("{}/admin/repositories/{repo}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"allow_redeploy": true}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());

    let role: Value = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": format!("push-{}", common::unique())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_i64().unwrap();
    let grant = |action: &'static str| {
        client
            .put(format!("{}/admin/roles/{role_id}/grants", srv.base_url))
            .basic_auth(&au, Some(&ap))
            .json(&json!({"repository": repo, "action": action}))
            .send()
    };
    for action in ["read", "write"] {
        assert_eq!(grant(action).await.unwrap().status(), 201);
    }
    let resp = client
        .put(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"role_id": role_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let created: Value = client
        .post(format!("{}/admin/users/{user_id}/tokens", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": "ci"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = created["token"].as_str().unwrap().to_string();

    let push = || publish_with_token(&srv, &repo, &token, "Acme.Core", "1.2.0");
    assert_eq!(push().await, 201, "a new version needs write only");
    assert_eq!(push().await, 403, "replacing it needs delete too");
    assert_eq!(grant("delete").await.unwrap().status(), 201);
    assert!(push().await.is_success(), "write + delete may redeploy");
}

/// A read-only scoped token cannot write even though its owner can.
#[tokio::test]
async fn token_scope_narrows_to_read_only() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();

    let (user_id, _username, _password) = make_user(&srv).await;
    let repo = make_repo(&srv).await;

    // Give the user read+write on the repo via a role.
    let role_name = format!("rw-{}", common::unique());
    let role: Value = client
        .post(format!("{}/admin/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": role_name}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_i64().unwrap();
    for action in ["read", "write"] {
        client
            .put(format!("{}/admin/roles/{role_id}/grants", srv.base_url))
            .basic_auth(&au, Some(&ap))
            .json(&json!({"repository": repo, "action": action}))
            .send()
            .await
            .unwrap();
    }
    client
        .put(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"role_id": role_id}))
        .send()
        .await
        .unwrap();

    // Issue a token scoped to read-only.
    let created: Value = client
        .post(format!("{}/admin/users/{user_id}/tokens", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": "ci", "scope": {"actions": ["read"]}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = created["token"]
        .as_str()
        .expect("plaintext token")
        .to_string();
    let token_id = created["id"].as_i64().unwrap();

    // The scoped token can read.
    let resp = client
        .get(format!("{}/v3/{repo}/index.json", srv.base_url))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "read-scoped token may read");

    // But a publish (write) is forbidden — the read-only scope drops the write
    // grant. Authz denies (403) before the package body is even parsed.
    let status = publish_with_token(&srv, &repo, &token, "ScopeTest", "1.0.0").await;
    assert_eq!(
        status, 403,
        "read-scoped token must not write; got {status}"
    );

    // Clearing the scope (PATCH null) restores the owner's full set (write).
    let resp = client
        .patch(format!("{}/admin/tokens/{token_id}/scope", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"scope": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let status = publish_with_token(&srv, &repo, &token, "ScopeTest", "1.0.0").await;
    assert_eq!(status, 201, "unscoped token may write; got {status}");
}

/// #32: reading a group grants no read on its members, and a token scope is
/// no exception. Scoped to the group alone a token sees an empty feed; with
/// the member listed too, the group serves it. (Documented behavior.)
#[tokio::test]
async fn a_token_scoped_to_a_group_reads_only_the_members_it_lists() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let hosted = make_repo(&srv).await;
    let id = format!("Scoped.Group{}", common::unique());
    let admin_token = srv.admin_token().await;
    assert_eq!(
        publish_with_token(&srv, &hosted, &admin_token, &id, "1.0.0").await,
        201
    );
    let group = format!("grp{}", common::unique());
    for (url, body) in [
        (
            format!("{}/admin/repositories", srv.base_url),
            json!({"name": group, "kind": "group"}),
        ),
        (
            format!("{}/admin/repositories/{group}/members", srv.base_url),
            json!({"member": hosted, "priority": 100}),
        ),
    ] {
        let resp = client
            .post(url)
            .basic_auth(&au, Some(&ap))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{}", resp.status());
    }
    let repo_id = |name: String| {
        let pool = srv.pool.clone();
        async move {
            forge_db::repository_dao::find_repository_by_name(&pool, &name)
                .await
                .unwrap()
                .unwrap()
                .id
        }
    };
    let (group_id, hosted_id) = (repo_id(group.clone()).await, repo_id(hosted.clone()).await);
    let admin_id = forge_db::user_dao::find_user_by_username(&srv.pool, &au)
        .await
        .unwrap()
        .unwrap()
        .id;
    let listing = |repositories: Vec<i64>| {
        let (client, srv_url) = (client.clone(), srv.base_url.clone());
        let (au, ap, group, lower) = (au.clone(), ap.clone(), group.clone(), id.to_lowercase());
        async move {
            let created: Value = client
                .post(format!("{srv_url}/admin/users/{admin_id}/tokens"))
                .basic_auth(&au, Some(&ap))
                .json(&json!({"name": "ci", "scope": {"actions": ["read"],
                                                       "repositories": repositories}}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            client
                .get(format!("{srv_url}/v3/{group}/flat/{lower}/index.json"))
                .header("X-NuGet-ApiKey", created["token"].as_str().unwrap())
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(listing(vec![group_id]).await, 404, "the group alone: empty");
    assert_eq!(listing(vec![group_id, hosted_id]).await, 200);
}

/// M1: `PATCH /admin/content-selectors/{id}` is a true PATCH — an omitted
/// `includes` / `excludes` / `description` keeps the stored value (an omitted
/// `includes` reset to `[]` would mean match-all and widen every grant).
#[tokio::test]
async fn content_selector_patch_keeps_omitted_fields() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();

    let created: Value = client
        .post(format!("{}/admin/content-selectors", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({
            "name": format!("patch-{}", common::unique()),
            "description": "public packages",
            "includes": ["company.*"],
            "excludes": ["company.secret*"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sel_id = created["id"].as_i64().unwrap();
    let url = format!("{}/admin/content-selectors/{sel_id}", srv.base_url);
    let patch = |body: Value| {
        let client = client.clone();
        let (url, au, ap) = (url.clone(), au.clone(), ap.clone());
        async move {
            let resp = client
                .patch(url)
                .basic_auth(&au, Some(&ap))
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 200, "{body}");
            resp.json::<Value>().await.unwrap()
        }
    };

    let s = patch(json!({"description": "renamed"})).await;
    assert_eq!(s["description"], json!("renamed"));
    assert_eq!(s["includes"], json!(["company.*"]), "includes kept");
    assert_eq!(s["excludes"], json!(["company.secret*"]), "excludes kept");

    let s = patch(json!({"excludes": ["company.internal*"]})).await;
    assert_eq!(s["description"], json!("renamed"), "description kept");
    assert_eq!(s["includes"], json!(["company.*"]), "includes kept");
    assert_eq!(s["excludes"], json!(["company.internal*"]));

    let s = patch(json!({"includes": null})).await;
    assert_eq!(s["includes"], json!(["company.*"]), "null keeps too");

    // An explicit `[]` is honored (the only way to make it match-all).
    let s = patch(json!({"includes": []})).await;
    assert_eq!(s["includes"], json!([]));

    // An invalid glob in a supplied list is still a 400.
    let resp = client
        .patch(&url)
        .basic_auth(&au, Some(&ap))
        .json(&json!({"excludes": ["[unterminated"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let stored: Value = client
        .get(&url)
        .basic_auth(&au, Some(&ap))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        stored["excludes"],
        json!(["company.internal*"]),
        "not persisted"
    );
}

/// L6: with `anonymous_mode = "all"` a signed-in user without grants can read
/// a repository anonymous callers can read (`anonymous_read`), but cannot
/// write it; a token scoped to another repository gains nothing from it.
#[tokio::test]
async fn signed_in_user_reads_anonymous_read_repo() {
    let srv = common::start_with(
        common::pool().await,
        common::ServerOpts {
            bootstrap_admin: Some((format!("admin{}", common::unique()), "adminpw".into())),
            anonymous_mode: "all".into(),
            ..Default::default()
        },
    )
    .await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let (user_id, username, password) = make_user(&srv).await;

    let public = format!("pub{}", common::unique());
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": public, "kind": "hosted", "anonymous_read": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let private = make_repo(&srv).await;
    let private_id = forge_db::repository_dao::find_repository_by_name(&srv.pool, &private)
        .await
        .unwrap()
        .unwrap()
        .id;

    let resp = client
        .get(format!("{}/v3/{public}/index.json", srv.base_url))
        .basic_auth(&username, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "roleless user reads the public repo");
    let resp = client
        .get(format!("{}/v3/{private}/index.json", srv.base_url))
        .basic_auth(&username, Some(&password))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "but not a private one");

    // Writing still needs a grant.
    let created: Value = client
        .post(format!("{}/admin/users/{user_id}/tokens", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": "ci"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = created["token"].as_str().unwrap().to_string();
    let status = publish_with_token(&srv, &public, &token, "PubTest", "1.0.0").await;
    assert_eq!(status, 403, "public read is read-only");

    // A token scoped to the private repository cannot read the public one.
    let scoped: Value = client
        .post(format!("{}/admin/users/{user_id}/tokens", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": "scoped", "scope": {"repositories": [private_id]}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = client
        .get(format!("{}/v3/{public}/index.json", srv.base_url))
        .header("X-NuGet-ApiKey", scoped["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "scope still bounds the public reach");
}

/// #84: turning `anonymous_read` off drops the read grant for everyone who
/// holds the `anonymous` role, also a user assigned it (cached under the
/// user's own key), not only the anonymous principal.
#[tokio::test]
async fn anonymous_read_off_applies_at_once_to_users_holding_the_anonymous_role() {
    let srv = common::start().await;
    let (au, ap) = srv.admin_basic();
    let client = srv.client();
    let s = common::unique();
    let repo = format!("anonrole{s}");
    let resp = client
        .post(format!("{}/admin/repositories", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"name": repo, "kind": "hosted", "anonymous_read": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    // The anonymous role's read grant on the repository (what migration 0007
    // synthesized for repositories that were anonymous-readable).
    let anon_role = forge_db::authz_dao::role_id_by_name(&srv.pool, "anonymous")
        .await
        .unwrap()
        .unwrap();
    let resp = client
        .put(format!("{}/admin/roles/{anon_role}/grants", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"repository": repo, "action": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let username = format!("anonuser{s}");
    let resp = client
        .post(format!("{}/admin/users", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"username": username, "password": "pw-anon-role"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let user_id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    let resp = client
        .put(format!("{}/admin/users/{user_id}/roles", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"role": "anonymous"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let session = srv.login(&username, "pw-anon-role").await;
    let index = format!("{}/v3/{repo}/index.json", srv.base_url);
    let resp = session.apply(client.get(&index)).send().await.unwrap();
    assert_eq!(resp.status(), 200, "read through the anonymous role");

    let resp = client
        .put(format!("{}/admin/repositories/{repo}", srv.base_url))
        .basic_auth(&au, Some(&ap))
        .json(&json!({"anonymous_read": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = session.apply(client.get(&index)).send().await.unwrap();
    assert_eq!(resp.status(), 403, "the cached grant is gone at once");
}
