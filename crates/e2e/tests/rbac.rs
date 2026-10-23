//! E2E: fine-grained RBAC + nested groups (§12.4 Phase 7 — the full matrix).
//!
//! These scenarios drive a **real server** (Postgres + versitygw, the slice-1
//! testcontainers harness) over HTTP and assert the RBAC seam end-to-end:
//!
//!   * **principal × repo × action matrix** — a roleless user is denied (403);
//!     a `read`-on-repoA role lets read A but denies write A and denies repoB;
//!     an `ANY` grant covers every repo; admin is allow-all.
//!   * **per-token scoping** — a token scoped below its owner's roles is limited
//!     to that subset (read-only token can read but not push; a repo-scoped token
//!     cannot touch a different repo) and can never out-grant its owner.
//!   * **anonymous role grant** — an `anonymous`-role `read` grant on a repo
//!     enables anonymous read; without it anonymous is denied.
//!   * **nested-group visibility honoring privileges** — a user who can read only
//!     one leaf of a nested group sees only that leaf's packages through the
//!     group; a forbidden leaf's version 404s.
//!   * **cycle rejected at config-time AND safe at resolve-time** — the admin API
//!     rejects an edge that would close a cycle (409); an injected raw-SQL cycle
//!     does not hang the resolver (fail-closed, bounded).
//!   * **cross-instance cache invalidation** — a grant change on instance A is
//!     observed on instance B within the TTL/backplane bound (two instances +
//!     Redis L2).
//!   * **UPGRADE-PRESERVES-BEHAVIOR** — a slice-1-seeded DB upgraded through the
//!     data migration keeps existing users reading/writing everywhere and admins
//!     admin; **FRESH-DEFAULTS-CLOSED** — a fresh install denies a roleless user.
//!
//! Gated behind `forge-e2e`.

#![cfg(feature = "forge-e2e")]

use std::time::Duration;

use forge_e2e::{make_nupkg, start_stack, AnonMode, StackBuilder};
use reqwest::StatusCode;
use serde_json::Value;
use sha2::{Digest, Sha256};

// ── principal × repo × action matrix ────────────────────────────────────────

/// A roleless authenticated user is denied (fail-closed); granting `(read, repoA)`
/// lets it read A but not write A and not read B; an `(read, ANY)` grant covers
/// every repo; the admin is allow-all.
#[tokio::test]
async fn matrix_read_write_any_and_fail_closed() {
    // Fresh install ⇒ deny-by-default for a roleless user.
    let srv = start_stack().await;

    for repo in ["repo-a", "repo-b"] {
        assert_eq!(
            srv.create_repo(serde_json::json!({"name": repo, "kind": "hosted"}))
                .await
                .status(),
            201
        );
    }

    // A non-admin user with NO roles — fail-closed deny everywhere.
    let uid = srv.create_user("matrix-user@example.com", "pw").await;
    let token = srv.issue_token(uid, None).await;

    assert_eq!(
        srv.read_index_with_token("repo-a", &token).await,
        StatusCode::FORBIDDEN,
        "roleless authenticated user is denied read (fail-closed, 403)"
    );

    // Grant the user `(read, repo-a)` via a fresh role.
    let role = srv.create_role("a-readers").await;
    assert_eq!(
        srv.add_grant(role, Some("repo-a"), "read", None)
            .await
            .status(),
        201
    );
    assert_eq!(srv.assign_role(uid, role).await.status(), 204);

    assert_eq!(
        srv.read_index_with_token("repo-a", &token).await,
        StatusCode::OK,
        "read grant on repo-a lets the user read repo-a"
    );
    assert_eq!(
        srv.read_index_with_token("repo-b", &token).await,
        StatusCode::FORBIDDEN,
        "the read grant is scoped to repo-a; repo-b stays denied"
    );
    // Read does not imply write: a push to repo-a is forbidden (403).
    assert_eq!(
        srv.push_nupkg_with_token("repo-a", &token, make_nupkg("Matrix.Pkg", "1.0.0"))
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "a read-only grant must NOT permit a write"
    );

    // An ANY-repo write grant now covers every repo for writes.
    let writers = srv.create_role("any-writers").await;
    assert_eq!(
        srv.add_grant(writers, None, "write", None).await.status(),
        201
    );
    assert_eq!(srv.assign_role(uid, writers).await.status(), 204);
    assert_eq!(
        srv.push_nupkg_with_token("repo-a", &token, make_nupkg("Matrix.Pkg", "1.0.0"))
            .await
            .status(),
        201,
        "an (write, ANY) grant covers repo-a"
    );
    let delete_without_grant = srv
        .client()
        .delete(format!(
            "{}/v3/repo-a/package/Matrix.Pkg/1.0.0",
            srv.base_url
        ))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        delete_without_grant.status(),
        StatusCode::FORBIDDEN,
        "write does not imply the distinct delete privilege"
    );

    // The bootstrap admin (admin role) is allow-all: it can read repo-b which the
    // user cannot.
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!("{}/v3/repo-b/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admin reads every repo");
}

// ── per-token scoping ───────────────────────────────────────────────────────

/// A token scoped below its owner's roles is limited to that subset: a `read`-only
/// scoped token can read but cannot push, even though its owner holds write; and a
/// token scoped to repoA cannot touch repoB even though its owner can.
#[tokio::test]
async fn token_scope_narrows_below_owner() {
    let srv = start_stack().await;
    for repo in ["scoped-a", "scoped-b"] {
        assert_eq!(
            srv.create_repo(serde_json::json!({"name": repo, "kind": "hosted"}))
                .await
                .status(),
            201
        );
    }

    // Owner holds read+write on ANY repo.
    let uid = srv.create_user("scoped-user@example.com", "pw").await;
    let role = srv.create_role("rw-any").await;
    assert_eq!(srv.add_grant(role, None, "read", None).await.status(), 201);
    assert_eq!(srv.add_grant(role, None, "write", None).await.status(), 201);
    assert_eq!(srv.assign_role(uid, role).await.status(), 204);

    // Resolve repo ids for the scope (the scope names repository ids).
    let a_id = forge_db::repository_dao::find_repository_by_name(&srv.pool, "scoped-a")
        .await
        .unwrap()
        .unwrap()
        .id;

    // An unscoped token inherits the full owner set: read+write everywhere.
    let full = srv.issue_token(uid, None).await;
    assert_eq!(
        srv.read_index_with_token("scoped-b", &full).await,
        StatusCode::OK,
        "unscoped token inherits the owner's full read reach"
    );
    assert_eq!(
        srv.push_nupkg_with_token("scoped-b", &full, make_nupkg("Scope.Pkg", "1.0.0"))
            .await
            .status(),
        201,
        "unscoped token inherits the owner's write reach"
    );

    // A token scoped to {actions:[read], repositories:[scoped-a]}.
    let scope = serde_json::json!({"actions": ["read"], "repositories": [a_id]});
    let limited = srv.issue_token(uid, Some(scope)).await;

    assert_eq!(
        srv.read_index_with_token("scoped-a", &limited).await,
        StatusCode::OK,
        "scoped token may read its in-scope repo"
    );
    assert_eq!(
        srv.push_nupkg_with_token("scoped-a", &limited, make_nupkg("Scope.Pkg", "2.0.0"))
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "a read-only scope forbids a write even though the owner can write"
    );
    assert_eq!(
        srv.read_index_with_token("scoped-b", &limited).await,
        StatusCode::FORBIDDEN,
        "a repo-scoped token cannot touch a repo outside its scope"
    );
}

/// A token's scope can never out-grant its owner: scoping a token to an action /
/// repo the owner lacks contributes nothing (intersection, never union).
#[tokio::test]
async fn token_scope_cannot_widen_owner() {
    let srv = start_stack().await;
    assert_eq!(
        srv.create_repo(serde_json::json!({"name": "narrow", "kind": "hosted"}))
            .await
            .status(),
        201
    );

    // Owner holds ONLY read on `narrow` (no write anywhere).
    let uid = srv.create_user("narrow-user@example.com", "pw").await;
    let role = srv.create_role("read-only-narrow").await;
    assert_eq!(
        srv.add_grant(role, Some("narrow"), "read", None)
            .await
            .status(),
        201
    );
    assert_eq!(srv.assign_role(uid, role).await.status(), 204);

    // A scope that *claims* write does not grant it — the owner has no write.
    let scope = serde_json::json!({"actions": ["read", "write", "delete", "admin"]});
    let token = srv.issue_token(uid, Some(scope)).await;

    assert_eq!(
        srv.read_index_with_token("narrow", &token).await,
        StatusCode::OK,
        "the token still reads (owner has read)"
    );
    assert_eq!(
        srv.push_nupkg_with_token("narrow", &token, make_nupkg("Narrow.Pkg", "1.0.0"))
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "a scope naming write the owner lacks cannot widen the token"
    );
}

// ── anonymous role grant ─────────────────────────────────────────────────────

/// An `anonymous`-role `read` grant on a repo enables anonymous read; a repo
/// without such a grant denies anonymous (401).
#[tokio::test]
async fn anonymous_role_grant_enables_anon_read() {
    let srv = StackBuilder::default().anon(AnonMode::All).start().await;

    // Created with anonymous_read = FALSE so the ONLY path to anonymous access
    // is the RBAC anonymous-role grant — this isolates the grant path from the
    // `anonymous_read` fast-path (asserted separately at the end).
    for repo in ["anon-pub", "anon-priv"] {
        assert_eq!(
            srv.create_repo(
                serde_json::json!({"name": repo, "kind": "hosted", "anonymous_read": false})
            )
            .await
            .status(),
            201
        );
    }

    // Grant the built-in anonymous role read on anon-pub only.
    let anon_role = srv.role_id("anonymous").await;
    assert_eq!(
        srv.add_grant(anon_role, Some("anon-pub"), "read", None)
            .await
            .status(),
        201
    );

    let resp = srv
        .client()
        .get(format!("{}/v3/anon-pub/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "anonymous read flows through the anonymous-role grant"
    );

    let resp = srv
        .client()
        .get(format!("{}/v3/anon-priv/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "a repo with no anonymous grant denies anonymous (401)"
    );

    // The `anonymous_read` toggle grants anonymous read directly (a first-class
    // fast-path independent of RBAC grants): a repo with anonymous_read=true and
    // NO anonymous-role grant is still anon-readable.
    assert_eq!(
        srv.create_repo(
            serde_json::json!({"name": "anon-flag", "kind": "hosted", "anonymous_read": true})
        )
        .await
        .status(),
        201
    );
    let resp = srv
        .client()
        .get(format!("{}/v3/anon-flag/index.json", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "anonymous_read=true grants anonymous read without an RBAC grant (fast-path)"
    );
}

// ── content-selector enforcement ───────────────────────────────────────────

/// Content selectors are enforced at every package-aware HTTP boundary. The
/// repo-level service index remains reachable, matching packages work, and an
/// excluded id is absent from listings/details/downloads and cannot be mutated.
#[tokio::test]
async fn content_selector_filters_reads_and_package_mutations() {
    let srv = start_stack().await;
    assert_eq!(
        srv.create_repo(serde_json::json!({"name": "selected", "kind": "hosted"}))
            .await
            .status(),
        201
    );
    for id in ["Company.Allowed", "Other.Hidden"] {
        assert_eq!(
            srv.push_nupkg("selected", make_nupkg(id, "1.0.0"))
                .await
                .status(),
            201
        );
    }

    let selector = srv
        .create_content_selector("company-only", &["company.*"], &[])
        .await;
    let user = srv.create_user("selector-user@example.com", "pw").await;
    let role = srv.create_role("selector-role").await;
    for action in ["read", "write", "delete"] {
        assert_eq!(
            srv.add_grant(role, Some("selected"), action, Some(selector))
                .await
                .status(),
            201
        );
    }
    assert_eq!(srv.assign_role(user, role).await.status(), 204);
    let token = srv.issue_token(user, None).await;

    // A selector-scoped grant still reaches the repository-level index.
    assert_eq!(
        srv.read_index_with_token("selected", &token).await,
        StatusCode::OK
    );

    let get = |path: &str| {
        srv.client()
            .get(format!("{}{path}", srv.base_url))
            .header("X-NuGet-ApiKey", &token)
            .send()
    };
    assert_eq!(
        get("/v3/selected/flat/company.allowed/index.json")
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
        "matching flat-container id remains visible"
    );
    for path in [
        "/v3/selected/flat/other.hidden/index.json",
        "/v3/selected/registration/other.hidden/index.json",
        "/v3/selected/flat/other.hidden/1.0.0/other.hidden.1.0.0.nupkg",
        "/browse/packages/selected/other.hidden",
    ] {
        assert_eq!(
            get(path).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "excluded identifier path must look absent: {path}"
        );
    }

    let search: Value = get("/v3/selected/query?q=&prerelease=true")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(search["totalHits"], 1);
    assert_eq!(search["data"][0]["id"], "Company.Allowed");

    let browse: Value = get("/browse/packages?repo=selected&take=20")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(browse["total"], 1);
    assert_eq!(browse["items"][0]["original_id"], "Company.Allowed");

    // Upload authorization uses the canonical id parsed from the nupkg. The
    // excluded upload is rejected before it can create a component.
    assert_eq!(
        srv.push_nupkg_with_token("selected", &token, make_nupkg("Company.New", "1.0.0"))
            .await
            .status(),
        StatusCode::CREATED
    );
    let denied_package = make_nupkg("Other.New", "1.0.0");
    let denied_sha = hex::encode(Sha256::digest(&denied_package));
    assert_eq!(
        srv.push_nupkg_with_token("selected", &token, denied_package)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let repo = forge_db::repository_dao::find_repository_by_name(&srv.pool, "selected")
        .await
        .unwrap()
        .unwrap();
    assert!(
        forge_db::component_dao::find_component(&srv.pool, repo.id, "other.new", "1.0.0")
            .await
            .unwrap()
            .is_none(),
        "denied upload must not create a component"
    );
    let denied_blob_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM blob WHERE sha256 = $1)")
            .bind(denied_sha)
            .fetch_one(&srv.pool)
            .await
            .unwrap();
    assert!(
        !denied_blob_exists,
        "denied upload must not promote its staged bytes into CAS"
    );

    let mutation = |method: reqwest::Method, id: &str| {
        srv.client()
            .request(
                method,
                format!("{}/v3/selected/package/{id}/1.0.0", srv.base_url),
            )
            .header("X-NuGet-ApiKey", &token)
            .send()
    };
    assert_eq!(
        mutation(reqwest::Method::DELETE, "Company.Allowed")
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        mutation(reqwest::Method::POST, "Company.Allowed")
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    for method in [reqwest::Method::DELETE, reqwest::Method::POST] {
        assert_eq!(
            mutation(method, "Other.Hidden").await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "excluded identifier mutation must not reveal package existence"
        );
    }
}

// ── nested-group visibility honoring privileges ─────────────────────────────

/// A nested group `g-outer → g-inner → {leaf-ok, leaf-no}`: a user who can read
/// only `leaf-ok` sees only its packages when enumerating the outer group; the
/// forbidden leaf's version is not downloadable (404, not 403 — no existence
/// leak).
#[tokio::test]
async fn nested_group_visibility_honors_privileges() {
    let srv = start_stack().await;
    let id = "Nest.Lib";
    let lower = id.to_lowercase();

    // Two hosted leaves, an inner group, and an outer group nesting it.
    for repo in ["leaf-ok", "leaf-no"] {
        assert_eq!(
            srv.create_repo(serde_json::json!({"name": repo, "kind": "hosted"}))
                .await
                .status(),
            201
        );
    }
    for grp in ["g-inner", "g-outer"] {
        assert_eq!(
            srv.create_repo(serde_json::json!({"name": grp, "kind": "group"}))
                .await
                .status(),
            201
        );
    }
    // g-outer → g-inner (nested!) → {leaf-ok, leaf-no}.
    assert_eq!(srv.add_member("g-inner", "leaf-ok", 10).await.status(), 201);
    assert_eq!(srv.add_member("g-inner", "leaf-no", 20).await.status(), 201);
    assert_eq!(
        srv.add_member("g-outer", "g-inner", 10).await.status(),
        201,
        "a group may nest another group (§12.4)"
    );

    // Distinct versions per leaf (admin pushes).
    assert_eq!(
        srv.push_nupkg("leaf-ok", make_nupkg(id, "1.0.0"))
            .await
            .status(),
        201
    );
    assert_eq!(
        srv.push_nupkg("leaf-no", make_nupkg(id, "2.0.0"))
            .await
            .status(),
        201
    );
    assert_eq!(
        srv.push_nupkg("leaf-ok", make_nupkg("Other.Hidden", "1.0.0"))
            .await
            .status(),
        201
    );

    // A user who can read g-outer, g-inner and leaf-ok — but NOT leaf-no.
    let uid = srv.create_user("nest-user@example.com", "pw").await;
    let role = srv.create_role("nest-reader").await;
    for repo in ["g-outer", "g-inner"] {
        assert_eq!(
            srv.add_grant(role, Some(repo), "read", None).await.status(),
            201
        );
    }
    let leaf_selector = srv
        .create_content_selector("nested-leaf-nest-only", &["nest.*"], &[])
        .await;
    assert_eq!(
        srv.add_grant(role, Some("leaf-ok"), "read", Some(leaf_selector))
            .await
            .status(),
        201
    );
    assert_eq!(srv.assign_role(uid, role).await.status(), 204);
    let token = srv.issue_token(uid, None).await;

    // Enumerating the outer group shows only leaf-ok's version (1.0.0); leaf-no's
    // 2.0.0 is filtered out because the user cannot read leaf-no — even though it
    // is reachable through the nesting.
    let resp = srv
        .client()
        .get(format!(
            "{}/v3/g-outer/flat/{lower}/index.json",
            srv.base_url
        ))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "user reads the outer group");
    let body: Value = resp.json().await.unwrap();
    let versions: Vec<String> = body["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        versions,
        vec!["1.0.0".to_string()],
        "nested-group enumeration shows only the leaf the user may read"
    );

    // The forbidden leaf's version is not downloadable via the group: 404 (avoids
    // leaking that the package exists), not 403.
    let resp = srv
        .client()
        .get(format!(
            "{}/v3/g-outer/flat/{lower}/2.0.0/{lower}.2.0.0.nupkg",
            srv.base_url
        ))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "a package in a forbidden nested leaf is 404 (no existence leak)"
    );

    let resp = srv
        .client()
        .get(format!(
            "{}/v3/g-outer/flat/other.hidden/index.json",
            srv.base_url
        ))
        .header("X-NuGet-ApiKey", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "a leaf content selector is preserved through nested-group resolution"
    );

    // The admin, who can read every leaf, sees the union of both versions.
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!(
            "{}/v3/g-outer/flat/{lower}/index.json",
            srv.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let mut versions: Vec<String> = body["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    versions.sort();
    assert_eq!(
        versions,
        vec!["1.0.0".to_string(), "2.0.0".to_string()],
        "admin sees the union across both nested leaves"
    );
}

// ── cycle: config-time rejection + resolve-time safety ──────────────────────

/// Config-time: adding an edge that would close a cycle in the group graph is
/// rejected with 409. Resolve-time: a cycle injected by a raw DB write does NOT
/// hang the resolver — the request completes (bounded, fail-closed).
#[tokio::test]
async fn group_cycle_rejected_config_and_safe_at_resolve() {
    let srv = start_stack().await;

    for grp in ["c1", "c2"] {
        assert_eq!(
            srv.create_repo(serde_json::json!({"name": grp, "kind": "group"}))
                .await
                .status(),
            201
        );
    }
    // c1 → c2 is fine.
    assert_eq!(srv.add_member("c1", "c2", 10).await.status(), 201);
    // c2 → c1 would close a cycle ⇒ rejected at config time with 409.
    assert_eq!(
        srv.add_member("c2", "c1", 10).await.status(),
        409,
        "an edge closing a cycle is rejected at config time (409)"
    );

    // Inject the cyclic edge directly via raw SQL, bypassing the admin guard, to
    // prove the resolve-time guard terminates instead of looping forever.
    let c1 = forge_db::repository_dao::find_repository_by_name(&srv.pool, "c1")
        .await
        .unwrap()
        .unwrap()
        .id;
    let c2 = forge_db::repository_dao::find_repository_by_name(&srv.pool, "c2")
        .await
        .unwrap()
        .unwrap()
        .id;
    sqlx::query("INSERT INTO group_member (group_id, member_id, priority) VALUES ($1, $2, 99)")
        .bind(c2)
        .bind(c1)
        .execute(&srv.pool)
        .await
        .expect("inject raw cyclic edge");

    // Hitting the group endpoint must return (bounded) rather than hang. We bound
    // the whole request with a timeout: reaching it would mean the resolver looped.
    let (u, p) = srv.admin_basic();
    let fut = srv
        .client()
        .get(format!("{}/v3/c1/flat/anything/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send();
    let resp = tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .expect("resolver must terminate on an injected cycle — it must NOT hang")
        .unwrap();
    // The exact status is unimportant (empty/404 for a nonexistent package); what
    // matters is that the request *completed* within the bound.
    assert!(
        resp.status().as_u16() < 500 || resp.status() == 404 || resp.status().is_success(),
        "request completed (fail-closed) on a cyclic graph; status {}",
        resp.status()
    );
}

// ── cross-instance cache invalidation ───────────────────────────────────────

/// Two instances (A + B) share Postgres + S3 + Redis. A user can read repo R on
/// both (warm caches). An admin removes the read grant via instance A; B must
/// stop allowing the read within the TTL / backplane bound. The symmetric grant
/// direction propagates too.
#[tokio::test]
async fn cross_instance_cache_invalidation_on_grant_change() {
    let a = StackBuilder::default()
        .with_redis()
        .cache_ttl_seconds(60) // long TTL so convergence is driven by invalidation, not expiry
        .start()
        .await;
    let b = a.spawn_peer().await;

    assert_eq!(
        a.create_repo(serde_json::json!({"name": "xinst", "kind": "hosted"}))
            .await
            .status(),
        201
    );

    // A user granted read on xinst via a role.
    let uid = a.create_user("xinst-user@example.com", "pw").await;
    let role = a.create_role("xinst-readers").await;
    assert_eq!(
        a.add_grant(role, Some("xinst"), "read", None)
            .await
            .status(),
        201
    );
    assert_eq!(a.assign_role(uid, role).await.status(), 204);
    let token = a.issue_token(uid, None).await;

    // Warm both instances' caches: the user can read on A and on B.
    assert_eq!(
        a.read_index_with_token("xinst", &token).await,
        StatusCode::OK
    );
    assert_eq!(
        b.read_index_with_token("xinst", &token).await,
        StatusCode::OK
    );

    // Remove the grant via A's admin API. Listing the role's grants gets the id.
    let (u, p) = a.admin_basic();
    let grants: Value = a
        .client()
        .get(format!("{}/admin/roles/{role}/grants", a.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id = grants.as_array().unwrap()[0]["id"].as_i64().unwrap();
    let resp = a
        .client()
        .delete(format!(
            "{}/admin/roles/{role}/grants/{grant_id}",
            a.base_url
        ))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "grant removed on A");

    // B must observe the removal (denied) within the invalidation bound. Poll.
    let mut denied_on_b = false;
    for _ in 0..50 {
        if b.read_index_with_token("xinst", &token).await == StatusCode::FORBIDDEN {
            denied_on_b = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        denied_on_b,
        "removing the grant on A must deny the read on B (cross-instance invalidation)"
    );

    // Symmetric: re-grant on A; B must allow again within the bound.
    assert_eq!(
        a.add_grant(role, Some("xinst"), "read", None)
            .await
            .status(),
        201
    );
    let mut allowed_on_b = false;
    for _ in 0..50 {
        if b.read_index_with_token("xinst", &token).await == StatusCode::OK {
            allowed_on_b = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        allowed_on_b,
        "re-granting on A must allow the read on B (cross-instance invalidation)"
    );
}

// ── fresh defaults closed ───────────────────────────────────────────────────

/// FRESH-DEFAULTS-CLOSED: a fresh install denies a newly-created roleless user
/// (deny-by-default). The bootstrap admin still works (admin role). This is the
/// security-by-default counterpart to the upgrade scenario.
#[tokio::test]
async fn fresh_install_defaults_closed_over_http() {
    let srv = start_stack().await;

    assert_eq!(
        srv.create_repo(serde_json::json!({"name": "fresh-repo", "kind": "hosted"}))
            .await
            .status(),
        201
    );

    // A user created on a fresh install holds no roles ⇒ denied (fail-closed).
    let uid = srv.create_user("fresh-user@example.com", "pw").await;
    let token = srv.issue_token(uid, None).await;
    assert_eq!(
        srv.read_index_with_token("fresh-repo", &token).await,
        StatusCode::FORBIDDEN,
        "a roleless user on a fresh install is denied (deny-by-default)"
    );

    // But the bootstrap admin works (admin role).
    let (u, p) = srv.admin_basic();
    let resp = srv
        .client()
        .get(format!("{}/v3/fresh-repo/index.json", srv.base_url))
        .basic_auth(&u, Some(&p))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "bootstrap admin reads on a fresh install"
    );
}

// ── API tokens and the admin API (B4) ──────────────────────────────────────

/// An admin's unscoped API token (the stack's push token) cannot use the admin
/// API — not to create users, not to mint tokens — while an explicitly
/// admin-scoped token can. The same unscoped token still publishes.
#[tokio::test]
async fn admin_api_requires_admin_scoped_token() {
    let srv = start_stack().await;
    let admin_id = forge_db::user_dao::find_user_by_username(
        &srv.pool,
        srv.admin_user.as_deref().expect("admin user"),
    )
    .await
    .expect("lookup")
    .expect("bootstrap admin present")
    .id;
    let create_user = |token: String, name: &'static str| {
        let client = srv.client();
        let url = format!("{}/admin/users", srv.base_url);
        async move {
            client
                .post(url)
                .header("X-NuGet-ApiKey", token)
                .json(&serde_json::json!({"username": name, "password": "pw", "is_admin": true}))
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    let mint = |token: String| {
        let client = srv.client();
        let url = format!("{}/admin/users/{admin_id}/tokens", srv.base_url);
        async move {
            client
                .post(url)
                .header("X-NuGet-ApiKey", token)
                .json(&serde_json::json!({"name": "minted"}))
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    let unscoped = srv.admin_token.clone();
    assert_eq!(
        create_user(unscoped.clone(), "token-made-admin@example.com").await,
        StatusCode::FORBIDDEN,
        "an unscoped admin token must not create (admin) users"
    );
    assert_eq!(
        mint(unscoped.clone()).await,
        StatusCode::FORBIDDEN,
        "an unscoped admin token must not mint tokens"
    );

    // It is still the admin's push credential.
    assert_eq!(
        srv.create_repo(serde_json::json!({"name": "b4-feed", "kind": "hosted"}))
            .await
            .status(),
        201
    );
    assert_eq!(
        srv.push_nupkg("b4-feed", make_nupkg("B4.Pkg", "1.0.0"))
            .await
            .status(),
        201,
        "the unscoped token keeps the admin's write reach"
    );

    let automation = srv
        .issue_token(admin_id, Some(serde_json::json!({"actions": ["admin"]})))
        .await;
    assert_eq!(
        mint(automation.clone()).await,
        StatusCode::CREATED,
        "an admin-scoped token may mint tokens"
    );
    assert_eq!(
        create_user(automation, "automation-made@example.com").await,
        StatusCode::CREATED,
        "an admin-scoped token may create users"
    );
}

// ── public read for signed-in principals (L6) ───────────────────────────────

/// A signed-in user without grants reads what anonymous callers can (the
/// `anonymous_read` flag, the anonymous role's grants) but cannot write it, and
/// a token scoped elsewhere gains nothing from it.
#[tokio::test]
async fn signed_in_user_reads_anonymous_readable_repos() {
    let srv = StackBuilder::default().anon(AnonMode::All).start().await;
    for (repo, anonymous_read) in [("l6-flag", true), ("l6-grant", false), ("l6-priv", false)] {
        assert_eq!(
            srv.create_repo(
                serde_json::json!({"name": repo, "kind": "hosted", "anonymous_read": anonymous_read})
            )
            .await
            .status(),
            201
        );
    }
    let anon_role = srv.role_id("anonymous").await;
    assert_eq!(
        srv.add_grant(anon_role, Some("l6-grant"), "read", None)
            .await
            .status(),
        201
    );

    let uid = srv.create_user("l6-user@example.com", "pw").await;
    let token = srv.issue_token(uid, None).await;
    for repo in ["l6-flag", "l6-grant"] {
        assert_eq!(
            srv.read_index_with_token(repo, &token).await,
            StatusCode::OK,
            "{repo}: a roleless user reads what anonymous can"
        );
    }
    assert_eq!(
        srv.read_index_with_token("l6-priv", &token).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        srv.push_nupkg_with_token("l6-flag", &token, make_nupkg("L6.Pkg", "1.0.0"))
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "public reach is read-only"
    );

    let priv_id = forge_db::repository_dao::find_repository_by_name(&srv.pool, "l6-priv")
        .await
        .unwrap()
        .unwrap()
        .id;
    let scoped = srv
        .issue_token(uid, Some(serde_json::json!({"repositories": [priv_id]})))
        .await;
    assert_eq!(
        srv.read_index_with_token("l6-flag", &scoped).await,
        StatusCode::FORBIDDEN,
        "a token scoped elsewhere cannot read the public repo"
    );
}

/// The public reach follows `anonymous_mode`: with anonymous access off (or
/// limited to an allowlist the server cannot judge per principal) a signed-in
/// user without grants does not inherit the `anonymous_read` flag.
#[tokio::test]
async fn signed_in_user_gets_no_public_reach_when_anonymous_access_is_off() {
    let srv = start_stack().await;
    assert_eq!(
        srv.create_repo(
            serde_json::json!({"name": "l6-off", "kind": "hosted", "anonymous_read": true})
        )
        .await
        .status(),
        201
    );
    let uid = srv.create_user("l6-off-user@example.com", "pw").await;
    let token = srv.issue_token(uid, None).await;
    assert_eq!(
        srv.read_index_with_token("l6-off", &token).await,
        StatusCode::FORBIDDEN
    );
}
