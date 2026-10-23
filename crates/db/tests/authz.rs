//! Integration tests for the RBAC data-access layer (`authz_dao`) against a real
//! Postgres testcontainer.
//!
//! These exercise the effective-set loader end-to-end against the seeded
//! built-in roles from migration 0005 plus per-test users/roles/grants/selectors.
//! Tests isolate themselves with `unique()` suffixes on every name so they run
//! in parallel against the shared schema.

mod common;

use forge_db::authz_dao::{
    self, add_grant, assign_role, insert_content_selector, load_anonymous_effective,
    load_user_effective, role_id_by_name, unassign_role, user_has_role, ADMIN_ROLE, ANONYMOUS_ROLE,
    AUTHENTICATED_ROLE,
};
use forge_db::repository_dao::{self, NewRepository};
use forge_db::user_dao::{self, NewUser};

use common::{pool, unique};

/// Create a non-builtin role with a unique name; return its id.
async fn make_role(pool: &sqlx::PgPool, n: u64) -> i64 {
    sqlx::query_scalar!(
        r#"INSERT INTO role (name, description) VALUES ($1, '') RETURNING id"#,
        format!("role-{n}"),
    )
    .fetch_one(pool)
    .await
    .expect("insert role")
}

async fn make_user(pool: &sqlx::PgPool, n: u64) -> i64 {
    user_dao::insert_user(
        pool,
        NewUser::local(format!("user-{n}@example.com"), "x".into(), true),
    )
    .await
    .expect("insert user")
    .id
}

async fn make_repo(pool: &sqlx::PgPool, n: u64) -> i64 {
    repository_dao::insert_repository(pool, NewRepository::hosted(format!("repo-{n}")))
        .await
        .expect("insert repo")
        .id
}

#[tokio::test]
async fn seeded_builtin_roles_exist() {
    let pool = pool().await;
    for name in [ADMIN_ROLE, ANONYMOUS_ROLE, AUTHENTICATED_ROLE] {
        let id = role_id_by_name(&pool, name)
            .await
            .expect("query")
            .unwrap_or_else(|| panic!("builtin role {name} must be seeded"));
        assert!(id > 0);
    }
    assert!(role_id_by_name(&pool, "does-not-exist")
        .await
        .expect("query")
        .is_none());
}

#[tokio::test]
async fn user_with_no_roles_has_empty_set() {
    let pool = pool().await;
    let pool = &pool;
    let user = make_user(pool, unique()).await;

    let eff = load_user_effective(pool, user).await.expect("load");
    assert!(!eff.is_admin, "no role ⇒ not admin");
    assert!(eff.grants.is_empty(), "no role ⇒ no grants (fail-closed)");
}

#[tokio::test]
async fn user_in_admin_role_is_admin() {
    let pool = pool().await;
    let pool = &pool;
    let user = make_user(pool, unique()).await;
    let admin_role = role_id_by_name(pool, ADMIN_ROLE)
        .await
        .expect("query")
        .expect("seeded");

    assign_role(pool, user, admin_role).await.expect("assign");

    let eff = load_user_effective(pool, user).await.expect("load");
    assert!(eff.is_admin, "admin-role member ⇒ is_admin");
    // The seeded admin role carries a sentinel (ANY, admin) grant.
    assert!(eff
        .grants
        .iter()
        .any(|g| g.action == "admin" && g.repository_id.is_none()));
}

#[tokio::test]
async fn user_grants_are_loaded_with_repo_scope() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;
    let repo = make_repo(pool, n).await;
    let role = make_role(pool, n).await;

    add_grant(pool, role, Some(repo), "read", None)
        .await
        .expect("grant read");
    add_grant(pool, role, None, "write", None)
        .await
        .expect("grant write ANY");
    assign_role(pool, user, role).await.expect("assign");

    let eff = load_user_effective(pool, user).await.expect("load");
    assert!(!eff.is_admin);
    assert_eq!(eff.grants.len(), 2);

    let read = eff
        .grants
        .iter()
        .find(|g| g.action == "read")
        .expect("read grant");
    assert_eq!(read.repository_id, Some(repo));
    assert!(read.selector.is_none());

    let write = eff
        .grants
        .iter()
        .find(|g| g.action == "write")
        .expect("write grant");
    assert_eq!(write.repository_id, None, "ANY-repo grant");
}

#[tokio::test]
async fn grant_with_selector_loads_raw_patterns() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;
    let repo = make_repo(pool, n).await;
    let role = make_role(pool, n).await;

    let sel = insert_content_selector(
        pool,
        &format!("sel-{n}"),
        &["company.*".to_string()],
        &["company.secret*".to_string()],
    )
    .await
    .expect("selector");

    add_grant(pool, role, Some(repo), "read", Some(sel))
        .await
        .expect("grant");
    assign_role(pool, user, role).await.expect("assign");

    let eff = load_user_effective(pool, user).await.expect("load");
    let g = eff
        .grants
        .iter()
        .find(|g| g.action == "read")
        .expect("grant");
    let selector = g.selector.as_ref().expect("selector loaded");
    assert_eq!(selector.id, sel);
    let (inc, exc) = selector.patterns().expect("parse");
    assert_eq!(inc, vec!["company.*"]);
    assert_eq!(exc, vec!["company.secret*"]);
}

#[tokio::test]
async fn multiple_roles_union_grants() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;
    let repo_a = make_repo(pool, n).await;
    let repo_b = make_repo(pool, unique()).await;
    let role1 = make_role(pool, n).await;
    let role2 = make_role(pool, unique()).await;

    add_grant(pool, role1, Some(repo_a), "read", None)
        .await
        .expect("g1");
    add_grant(pool, role2, Some(repo_b), "read", None)
        .await
        .expect("g2");
    assign_role(pool, user, role1).await.expect("a1");
    assign_role(pool, user, role2).await.expect("a2");

    let eff = load_user_effective(pool, user).await.expect("load");
    assert_eq!(eff.grants.len(), 2, "union of both roles' grants");
    let repos: Vec<_> = eff.grants.iter().filter_map(|g| g.repository_id).collect();
    assert!(repos.contains(&repo_a));
    assert!(repos.contains(&repo_b));
}

#[tokio::test]
async fn anonymous_effective_reflects_anonymous_role_grants() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let repo = make_repo(pool, n).await;
    let anon_role = role_id_by_name(pool, ANONYMOUS_ROLE)
        .await
        .expect("query")
        .expect("seeded");

    // Grant the anonymous role read on this repo (mirrors anonymous_read).
    add_grant(pool, anon_role, Some(repo), "read", None)
        .await
        .expect("grant");

    let eff = load_anonymous_effective(pool).await.expect("load");
    assert!(!eff.is_admin, "anonymous is never admin");
    assert!(
        eff.grants
            .iter()
            .any(|g| g.action == "read" && g.repository_id == Some(repo)),
        "anonymous role read grant must appear"
    );
}

#[tokio::test]
async fn assign_and_unassign_role_round_trip() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;
    let role = make_role(pool, n).await;
    let role_name = format!("role-{n}");

    assert!(!user_has_role(pool, user, &role_name).await.expect("check"));
    assign_role(pool, user, role).await.expect("assign");
    assert!(user_has_role(pool, user, &role_name).await.expect("check"));

    // Idempotent re-assign.
    assign_role(pool, user, role).await.expect("re-assign");
    let eff = load_user_effective(pool, user).await.expect("load");
    assert!(!eff.is_admin);

    unassign_role(pool, user, role).await.expect("unassign");
    assert!(!user_has_role(pool, user, &role_name).await.expect("check"));
}

#[tokio::test]
async fn add_grant_is_idempotent() {
    let pool = pool().await;
    let pool = &pool;
    let n = unique();
    let user = make_user(pool, n).await;
    let repo = make_repo(pool, n).await;
    let role = make_role(pool, n).await;

    add_grant(pool, role, Some(repo), "read", None)
        .await
        .expect("grant");
    add_grant(pool, role, Some(repo), "read", None)
        .await
        .expect("duplicate grant tolerated");
    assign_role(pool, user, role).await.expect("assign");

    let eff = load_user_effective(pool, user).await.expect("load");
    assert_eq!(
        eff.grants.len(),
        1,
        "duplicate grant collapses via unique index"
    );
}

#[tokio::test]
async fn admin_role_dao_constant_matches_db() {
    // Defensive: the constant the loader keys on must equal the seeded name.
    let pool = pool().await;
    assert!(authz_dao::role_id_by_name(&pool, ADMIN_ROLE)
        .await
        .expect("query")
        .is_some());
}

/// M1: `update_content_selector` has PATCH semantics — an omitted field keeps
/// its stored value. (An omitted `includes` reset to `[]` would mean
/// match-all and silently widen every grant using the selector.)
#[tokio::test]
async fn update_content_selector_keeps_omitted_fields() {
    let pool = common::pool().await;
    let name = format!("patchsel-{}", common::unique());
    let sel = forge_db::authz_dao::create_content_selector(
        &pool,
        &name,
        "desc",
        &["company.*".to_string()],
        &["company.secret*".to_string()],
    )
    .await
    .expect("create");

    let upd = forge_db::authz_dao::update_content_selector(&pool, sel.id, Some("new"), None, None)
        .await
        .expect("update")
        .expect("selector exists");
    assert_eq!(upd.description, "new");
    assert_eq!(upd.includes, serde_json::json!(["company.*"]), "kept");
    assert_eq!(upd.excludes, serde_json::json!(["company.secret*"]), "kept");

    let includes = ["internal.*".to_string()];
    let upd =
        forge_db::authz_dao::update_content_selector(&pool, sel.id, None, Some(&includes), None)
            .await
            .expect("update")
            .expect("selector exists");
    assert_eq!(upd.description, "new", "kept");
    assert_eq!(upd.includes, serde_json::json!(["internal.*"]), "replaced");
    assert_eq!(upd.excludes, serde_json::json!(["company.secret*"]), "kept");

    // An explicit empty list is still a real value.
    let upd = forge_db::authz_dao::update_content_selector(&pool, sel.id, None, None, Some(&[]))
        .await
        .expect("update")
        .expect("selector exists");
    assert_eq!(upd.includes, serde_json::json!(["internal.*"]), "kept");
    assert_eq!(upd.excludes, serde_json::json!([]), "cleared explicitly");

    assert!(
        forge_db::authz_dao::update_content_selector(&pool, -1, Some("x"), None, None)
            .await
            .expect("update")
            .is_none(),
        "unknown id"
    );
}

/// M20: turning `anonymous_read` off deletes exactly the synthesized grant —
/// the anonymous role's unscoped `read` on that repository — and nothing else.
#[tokio::test]
async fn delete_anonymous_read_grant_removes_only_the_synthesized_grant() {
    let pool = common::pool().await;
    let n = common::unique();
    let repo = make_repo(&pool, n).await;
    let other_repo = make_repo(&pool, common::unique()).await;
    let anon = forge_db::authz_dao::role_id_by_name(&pool, forge_db::authz_dao::ANONYMOUS_ROLE)
        .await
        .expect("query")
        .expect("anonymous role seeded");
    let custom = make_role(&pool, common::unique()).await;
    let sel = forge_db::authz_dao::insert_content_selector(
        &pool,
        &format!("anonsel-{n}"),
        &["pub.*".to_string()],
        &[],
    )
    .await
    .expect("selector");
    for (role, repo_id, action, selector) in [
        (anon, repo, "read", None),
        (anon, repo, "read", Some(sel)),
        (anon, other_repo, "read", None),
        (custom, repo, "read", None),
    ] {
        forge_db::authz_dao::add_grant(&pool, role, Some(repo_id), action, selector)
            .await
            .expect("grant");
    }

    assert!(
        forge_db::authz_dao::delete_anonymous_read_grant(&pool, repo)
            .await
            .expect("delete")
    );
    assert!(
        !forge_db::authz_dao::delete_anonymous_read_grant(&pool, repo)
            .await
            .expect("delete again"),
        "idempotent"
    );

    let anon_grants = forge_db::authz_dao::list_grants_for_role(&pool, anon)
        .await
        .expect("list");
    let on = |repo_id: i64, selector: Option<i64>| {
        anon_grants.iter().any(|g| {
            g.repository_id == Some(repo_id) && g.action == "read" && g.selector_id == selector
        })
    };
    assert!(!on(repo, None), "the synthesized grant is gone");
    assert!(on(repo, Some(sel)), "a selector-scoped grant stays");
    assert!(on(other_repo, None), "other repositories are untouched");
    let custom_grants = forge_db::authz_dao::list_grants_for_role(&pool, custom)
        .await
        .expect("list");
    assert_eq!(custom_grants.len(), 1, "other roles are untouched");
}
