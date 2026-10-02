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
//! The test harness defaults to a **fresh (closed)** install (`legacy_open_access`
//! unset ⇒ false), so a brand-new non-admin user holds no roles and is denied by
//! default — exactly the deny-by-default baseline against which a grant's effect
//! is observable.

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

/// L6: a signed-in user without grants can read a repository anonymous callers
/// can read (`anonymous_read`), but cannot write it; a token scoped to another
/// repository gains nothing from it.
#[tokio::test]
async fn signed_in_user_reads_anonymous_read_repo() {
    let srv = common::start().await;
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
