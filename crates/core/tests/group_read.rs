//! Integration tests for identity-aware group resolution.
//!
//! Seeds two hosted **member** repositories plus a **group** that federates
//! them, then drives [`forge_core::repo::group::GroupRepo`] through the
//! [`RepoReadOps`] trait. Members are built with real [`HostedRepo`] instances
//! (over the shared Postgres) via an in-memory [`MemberOpsFactory`], with a stub
//! [`BlobFetch`] so no S3 is needed.
//!
//! Coverage:
//! * two members share an overlapping version → the **highest-priority** member
//!   serves the `.nupkg`;
//! * `list_versions` returns the **union** of both members' versions;
//! * a **mixed-anonymity** group filters by principal: anonymous sees only
//!   `anonymous_read` members, authenticated sees all.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use forge_cache::Cache;
use forge_core::auth::authz::Authz;
use forge_core::auth::principal::Principal;
use forge_core::repo::group::{GroupRepo, MemberOpsFactory};
use forge_core::repo::hosted::{BlobFetch, HostedRepo};
use forge_core::repo::{
    NupkgLocation, RepoError, RepoReadOps, SearchParams, NUPKG_ASSET_PATH, NUSPEC_ASSET_PATH,
};
use forge_db::asset_dao::{self, NewAsset};
use forge_db::authz_dao::{self, AUTHENTICATED_ROLE};
use forge_db::blob_dao;
use forge_db::component_dao::{self, NewComponent};
use forge_db::model::Repository;
use forge_db::repository_dao::{self, NewRepository};
use forge_db::user_dao::{self, NewUser};
use sqlx::PgPool;

/// NuGet, the built-in format plugin, as the `Format` the repository code
/// works with.
fn nuget() -> forge_plugin::PluginFormat {
    let plugin = forge_plugin::Plugin::builtin(
        forge_format_nuget::PLUGIN_TOML,
        forge_format_nuget::Nuget::default(),
    )
    .expect("plugins/nuget/plugin.toml is valid");
    forge_plugin::PluginFormat::new(&plugin)
}

/// In-memory blob byte store: maps `s3_key -> bytes`.
#[derive(Default, Clone)]
struct StubBlobs {
    map: HashMap<String, Vec<u8>>,
}

#[async_trait]
impl BlobFetch for StubBlobs {
    async fn fetch_all(&self, blob: &forge_db::model::Blob) -> Result<Vec<u8>, RepoError> {
        let s3_key = &blob.s3_key;
        self.map
            .get(s3_key)
            .cloned()
            .ok_or_else(|| RepoError::RepoNotFound(format!("missing blob {s3_key}")))
    }
}

/// A [`MemberOpsFactory`] that builds a [`HostedRepo`] for every member, sharing
/// the pool and the stub blob bytes. The leaf members the factory is asked for
/// are hosted or proxy repositories (nested groups are flattened by the
/// resolver); the tests only exercise hosted members, which is sufficient for
/// the resolution semantics (the factory seam is what the server swaps for
/// proxy support).
struct HostedFactory {
    pool: PgPool,
    blobs: StubBlobs,
}

impl MemberOpsFactory for HostedFactory {
    fn ops_for(&self, _member: &Repository) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        Ok(Arc::new(HostedRepo::new(
            self.pool.clone(),
            Arc::new(nuget()),
            Arc::new(self.blobs.clone()),
        )))
    }
}

/// Hosted factory that counts constructions. Since each returned hosted ops is
/// called once by a group method, this also detects path-count backend fan-out.
struct CountingHostedFactory {
    inner: HostedFactory,
    builds: Arc<AtomicUsize>,
}

impl MemberOpsFactory for CountingHostedFactory {
    fn ops_for(&self, member: &Repository) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        self.inner.ops_for(member)
    }
}

/// Default nesting depth bound used by the test resolver (generous; the
/// dedicated depth/cycle tests below pass a tighter bound or inject a cycle).
const TEST_MAX_DEPTH: u32 = 20;

/// Build a `GroupRepo` for `principal` over the pool + stub blobs.
fn group_repo(pool: &PgPool, blobs: StubBlobs, principal: Principal) -> GroupRepo {
    group_repo_depth(pool, blobs, principal, TEST_MAX_DEPTH)
}

/// Like [`group_repo`] but with an explicit nesting-depth bound.
fn group_repo_depth(
    pool: &PgPool,
    blobs: StubBlobs,
    principal: Principal,
    max_depth: u32,
) -> GroupRepo {
    let factory = Arc::new(HostedFactory {
        pool: pool.clone(),
        blobs,
    });
    let authz = Authz::new(pool.clone(), Cache::l1_only(16));
    GroupRepo::new(pool.clone(), principal, factory, authz, max_depth)
}

/// A real (non-admin) authenticated user holding the seeded `authenticated`
/// role, which carries read/write on every repository. This is what makes the
/// authenticated-sees-all assertions hold under fine-grained RBAC: visibility
/// flows through `can_read`, so the user must actually be granted read.
async fn user(pool: &PgPool) -> Principal {
    let u = user_dao::insert_user(
        pool,
        NewUser::local(format!("groupuser-{}", common::unique()), "x".into(), true),
    )
    .await
    .expect("insert user");
    let role = authz_dao::role_id_by_name(pool, AUTHENTICATED_ROLE)
        .await
        .expect("query")
        .expect("authenticated role seeded");
    authz_dao::assign_role(pool, u.id, role)
        .await
        .expect("assign authenticated");
    Principal::User {
        user_id: u.id,
        token_id: None,
        method: forge_core::auth::AuthMethod::Password,
    }
}

fn anon() -> Principal {
    Principal::Anonymous {
        ip: "127.0.0.1".parse().unwrap(),
    }
}

/// Insert a committed blob (pending → commit_and_incref) and return nothing.
async fn seed_blob(pool: &PgPool, sha: &str, s3_key: &str, size: i64) {
    blob_dao::upsert_pending(pool, sha, size, s3_key)
        .await
        .expect("upsert_pending");
    let mut tx = pool.begin().await.expect("begin");
    blob_dao::commit_and_incref(&mut tx, sha)
        .await
        .expect("commit_and_incref");
    tx.commit().await.expect("commit");
}

/// Seed a hosted member repository. When `anonymous_read` is set, also grant the
/// built-in `anonymous` role `read` on it — under RBAC anonymous visibility
/// flows through that grant (what the RBAC data migration converted the
/// `anonymous_read` flag into), not the column. The column is still set for
/// parity but is not consulted by the seam.
async fn seed_member(pool: &PgPool, anonymous_read: bool) -> Repository {
    let name = format!("member-{}", common::unique());
    let new = NewRepository {
        anonymous_read,
        ..NewRepository::hosted(name)
    };
    let repo = repository_dao::insert_repository(pool, new)
        .await
        .expect("insert member");
    if anonymous_read {
        let anon_role = authz_dao::role_id_by_name(pool, authz_dao::ANONYMOUS_ROLE)
            .await
            .expect("query")
            .expect("anonymous role seeded");
        authz_dao::add_grant(pool, anon_role, Some(repo.id), "read", None)
            .await
            .expect("anon read grant");
    }
    repo
}

/// Seed a group repository.
async fn seed_group(pool: &PgPool) -> Repository {
    let name = format!("group-{}", common::unique());
    repository_dao::insert_repository(pool, NewRepository::group(name))
        .await
        .expect("insert group")
}

/// Seed a complete (component + nupkg asset + nuspec asset + blobs) package
/// version into a member repo. The `tag` lets the test tell which member served
/// a given `.nupkg` (it is embedded in the blob s3 key).
async fn seed_version(
    pool: &PgPool,
    blobs: &mut StubBlobs,
    repo_id: i64,
    id: &str,
    version: &str,
    tag: &str,
) {
    let lower = id.to_lowercase();
    let suffix = common::unique();
    // 64-hex-char shas that actually embed the unique suffix (a leading marker
    // plus the zero-padded counter); distinct per call so blobs never dedup
    // across tests sharing the pool.
    let nupkg_sha = format!("a{suffix:063}");
    let nuspec_sha = format!("b{suffix:063}");
    let nupkg_key = format!("blobs/{tag}/{nupkg_sha}");
    let nuspec_key = format!("blobs/{tag}/{nuspec_sha}");

    seed_blob(pool, &nupkg_sha, &nupkg_key, 1234).await;
    seed_blob(pool, &nuspec_sha, &nuspec_key, 256).await;

    blobs
        .map
        .insert(nuspec_key.clone(), format!("nuspec-{tag}").into_bytes());
    blobs
        .map
        .insert(nupkg_key.clone(), format!("nupkg-{tag}").into_bytes());

    let comp = component_dao::insert_component(
        pool,
        NewComponent {
            repository_id: repo_id,
            name: lower,
            original_id: id.to_string(),
            version: version.to_string(),
            version_original: version.to_string(),
            listed: true,
        },
    )
    .await
    .expect("insert_component");

    asset_dao::insert_asset(
        pool,
        NewAsset {
            component_id: comp.id,
            path: NUPKG_ASSET_PATH.to_string(),
            content_type: "application/octet-stream".to_string(),
            blob_sha256: nupkg_sha,
            size: 1234,
            sha512_base64: Some(format!("hash-{tag}")),
        },
    )
    .await
    .expect("insert nupkg asset");

    asset_dao::insert_asset(
        pool,
        NewAsset {
            component_id: comp.id,
            path: NUSPEC_ASSET_PATH.to_string(),
            content_type: "application/xml".to_string(),
            blob_sha256: nuspec_sha,
            size: 256,
            sha512_base64: None,
        },
    )
    .await
    .expect("insert nuspec asset");
}

/// Resolve the stub-blob bytes a `NupkgLocation` points at — the embedded `tag`
/// identifies which member produced it.
fn served_tag(blobs: &StubBlobs, loc: &NupkgLocation) -> String {
    let bytes = blobs
        .map
        .get(&loc.blob_s3_key)
        .cloned()
        .expect("resolved blob key present in stub");
    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn highest_priority_member_serves_overlapping_version() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();

    let high = seed_member(&pool, false).await;
    let low = seed_member(&pool, false).await;
    let group = seed_group(&pool).await;

    // Both members have Sample 1.0.0; give `high` the higher priority.
    seed_version(&pool, &mut blobs, high.id, "Sample", "1.0.0", "nupkg-high").await;
    seed_version(&pool, &mut blobs, low.id, "Sample", "1.0.0", "nupkg-low").await;

    repository_dao::add_group_member(&pool, group.id, high.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, low.id, 10)
        .await
        .unwrap();

    let g = group_repo(&pool, blobs.clone(), user(&pool).await);
    let loc = g
        .resolve_nupkg(&group.name, "sample", "1.0.0")
        .await
        .unwrap()
        .expect("version resolved");
    // The highest-priority member (`high`) serves it.
    assert_eq!(served_tag(&blobs, &loc), "nupkg-nupkg-high");

    // Registration also dedups to the high-priority winner (one entry only).
    let reg = g.registration(&group.name, "sample").await.unwrap();
    assert_eq!(reg.len(), 1);
    assert_eq!(
        reg[0].package_hash_sha512_base64.as_deref(),
        Some("hash-nupkg-high")
    );
}

#[tokio::test]
async fn list_versions_is_union_across_members() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();

    let high = seed_member(&pool, false).await;
    let low = seed_member(&pool, false).await;
    let group = seed_group(&pool).await;

    // high: 1.0.0, 2.0.0 ; low: 1.0.0 (overlap), 1.5.0
    seed_version(&pool, &mut blobs, high.id, "Sample", "1.0.0", "h").await;
    seed_version(&pool, &mut blobs, high.id, "Sample", "2.0.0", "h").await;
    seed_version(&pool, &mut blobs, low.id, "Sample", "1.0.0", "l").await;
    seed_version(&pool, &mut blobs, low.id, "Sample", "1.5.0", "l").await;

    repository_dao::add_group_member(&pool, group.id, high.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, low.id, 10)
        .await
        .unwrap();

    let g = group_repo(&pool, blobs, user(&pool).await);
    let versions = g.list_versions(&group.name, "sample").await.unwrap();
    let mut vs: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
    vs.sort_unstable();
    // Union, deduped: 1.0.0 appears once.
    assert_eq!(vs, vec!["1.0.0", "1.5.0", "2.0.0"]);
}

#[tokio::test]
async fn mixed_anon_group_filters_by_principal() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();

    // public member is anonymous-readable; private is not.
    let public = seed_member(&pool, true).await;
    let private = seed_member(&pool, false).await;
    let group = seed_group(&pool).await;

    seed_version(&pool, &mut blobs, public.id, "Pub", "1.0.0", "pub").await;
    seed_version(&pool, &mut blobs, private.id, "Priv", "1.0.0", "priv").await;

    repository_dao::add_group_member(&pool, group.id, public.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, private.id, 10)
        .await
        .unwrap();

    // Anonymous: only the public member is visible.
    let g_anon = group_repo(&pool, blobs.clone(), anon());
    assert!(
        g_anon
            .list_versions(&group.name, "pub")
            .await
            .unwrap()
            .len()
            == 1,
        "anon sees public member"
    );
    assert!(
        g_anon
            .list_versions(&group.name, "priv")
            .await
            .unwrap()
            .is_empty(),
        "anon cannot see private member"
    );
    assert!(g_anon
        .resolve_nupkg(&group.name, "priv", "1.0.0")
        .await
        .unwrap()
        .is_none());

    // Authenticated user: both members visible.
    let g_user = group_repo(&pool, blobs, user(&pool).await);
    assert_eq!(
        g_user
            .list_versions(&group.name, "priv")
            .await
            .unwrap()
            .len(),
        1,
        "user sees private member"
    );
    assert!(g_user
        .resolve_nupkg(&group.name, "priv", "1.0.0")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn search_merges_and_dedups_highest_priority_wins() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();

    let high = seed_member(&pool, false).await;
    let low = seed_member(&pool, false).await;
    let group = seed_group(&pool).await;

    // Both members publish "Shared"; only `low` publishes "OnlyLow".
    seed_version(&pool, &mut blobs, high.id, "Shared", "2.0.0", "h").await;
    seed_version(&pool, &mut blobs, low.id, "Shared", "1.0.0", "l").await;
    seed_version(&pool, &mut blobs, low.id, "OnlyLow", "1.0.0", "l").await;

    repository_dao::add_group_member(&pool, group.id, high.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, low.id, 10)
        .await
        .unwrap();

    let g = group_repo(&pool, blobs, user(&pool).await);
    let res = g
        .search(&group.name, &SearchParams::default())
        .await
        .unwrap();
    // Two distinct ids: Shared (from high) + OnlyLow (from low).
    assert_eq!(res.total_hits, 2);
    let shared = res
        .hits
        .iter()
        .find(|h| h.original_id.eq_ignore_ascii_case("shared"))
        .expect("Shared present");
    // Highest-priority member wins the dedup → its latest version (2.0.0).
    assert_eq!(shared.latest_version, "2.0.0");
    assert!(res
        .hits
        .iter()
        .any(|h| h.original_id.eq_ignore_ascii_case("onlylow")));
}

// ── nested groups ───────────────────────────────────────────────────────────

#[tokio::test]
async fn nested_group_flattens_leaves_through_inner_group() {
    // g_outer -> g_inner -> { high, low }, plus g_outer -> direct.
    // A nested-group member is descended into; all leaves flatten out.
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();

    let high = seed_member(&pool, false).await;
    let low = seed_member(&pool, false).await;
    let direct = seed_member(&pool, false).await;
    let inner = seed_group(&pool).await;
    let outer = seed_group(&pool).await;

    seed_version(&pool, &mut blobs, high.id, "Sample", "2.0.0", "high").await;
    seed_version(&pool, &mut blobs, low.id, "Sample", "1.0.0", "low").await;
    seed_version(&pool, &mut blobs, direct.id, "Other", "1.0.0", "direct").await;

    // inner: high (prio 100) > low (prio 10).
    repository_dao::add_group_member(&pool, inner.id, high.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, inner.id, low.id, 10)
        .await
        .unwrap();
    // outer: inner (prio 100) then direct (prio 10).
    repository_dao::add_group_member(&pool, outer.id, inner.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, outer.id, direct.id, 10)
        .await
        .unwrap();

    let g = group_repo(&pool, blobs.clone(), user(&pool).await);

    // Sample 1.0.0 + 2.0.0 reachable via the inner group; Other via direct.
    let sample = g.list_versions(&outer.name, "sample").await.unwrap();
    let mut vs: Vec<&str> = sample.iter().map(|v| v.version.as_str()).collect();
    vs.sort_unstable();
    assert_eq!(vs, vec!["1.0.0", "2.0.0"], "both inner leaves flatten out");

    assert_eq!(
        g.list_versions(&outer.name, "other").await.unwrap().len(),
        1,
        "direct leaf also resolves"
    );

    // Priority across nesting: high (2.0.0) wins the overlap within inner.
    let loc = g
        .resolve_nupkg(&outer.name, "sample", "2.0.0")
        .await
        .unwrap()
        .expect("2.0.0 resolved");
    assert_eq!(served_tag(&blobs, &loc), "nupkg-high");
}

#[tokio::test]
async fn nested_group_filtering_honors_privileges_per_level() {
    // outer -> inner -> { pub (anon_read), priv }. Anonymous descends into the
    // inner group but only sees the anonymous-granted leaf; the private leaf is
    // hidden even though it is reachable through nesting.
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();

    let public = seed_member(&pool, true).await;
    let private = seed_member(&pool, false).await;
    let inner = seed_group(&pool).await;
    let outer = seed_group(&pool).await;

    seed_version(&pool, &mut blobs, public.id, "Pub", "1.0.0", "pub").await;
    seed_version(&pool, &mut blobs, private.id, "Priv", "1.0.0", "priv").await;

    repository_dao::add_group_member(&pool, inner.id, public.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, inner.id, private.id, 10)
        .await
        .unwrap();
    // The inner group itself must be anon-readable for an anonymous caller to
    // descend into it (read on the outer/inner group != read on the leaves).
    let anon_role = authz_dao::role_id_by_name(&pool, authz_dao::ANONYMOUS_ROLE)
        .await
        .unwrap()
        .unwrap();
    authz_dao::add_grant(&pool, anon_role, Some(inner.id), "read", None)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, outer.id, inner.id, 100)
        .await
        .unwrap();
    authz_dao::add_grant(&pool, anon_role, Some(outer.id), "read", None)
        .await
        .unwrap();

    // Anonymous: only the public leaf (reachable through two group levels).
    let g_anon = group_repo(&pool, blobs.clone(), anon());
    assert_eq!(
        g_anon
            .list_versions(&outer.name, "pub")
            .await
            .unwrap()
            .len(),
        1,
        "anon sees public leaf through nesting"
    );
    assert!(
        g_anon
            .list_versions(&outer.name, "priv")
            .await
            .unwrap()
            .is_empty(),
        "anon cannot see the private leaf inside the nested group"
    );

    // Authenticated user: both leaves visible.
    let g_user = group_repo(&pool, blobs, user(&pool).await);
    assert_eq!(
        g_user
            .list_versions(&outer.name, "priv")
            .await
            .unwrap()
            .len(),
        1,
        "authenticated user sees the private leaf through nesting"
    );
}

#[tokio::test]
async fn diamond_paths_preserve_each_paths_package_filter() {
    // outer -> company_path -> leaf
    //       -> middle
    //       -> other_path   -> leaf
    //
    // The higher-priority path only allows Company.*, while the second path
    // only allows Other.*. `middle` must still beat the shared leaf for an
    // Other.* package because that leaf is only visible through its lower-
    // priority path. Deduplicating or unioning at the first structural sighting
    // would respectively hide or incorrectly promote Other.Public.
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();

    let leaf = seed_member(&pool, false).await;
    let middle = seed_member(&pool, false).await;
    let company_path = seed_group(&pool).await;
    let other_path = seed_group(&pool).await;
    let outer = seed_group(&pool).await;

    seed_version(
        &pool,
        &mut blobs,
        leaf.id,
        "Company.Tools",
        "1.0.0",
        "company",
    )
    .await;
    seed_version(
        &pool,
        &mut blobs,
        leaf.id,
        "Other.Public",
        "1.0.0",
        "other-low",
    )
    .await;
    seed_version(
        &pool,
        &mut blobs,
        leaf.id,
        "Other.Public",
        "2.0.0",
        "other-low",
    )
    .await;
    seed_version(
        &pool,
        &mut blobs,
        middle.id,
        "Other.Public",
        "1.0.0",
        "middle",
    )
    .await;

    repository_dao::add_group_member(&pool, company_path.id, leaf.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, other_path.id, leaf.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, outer.id, company_path.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, outer.id, middle.id, 50)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, outer.id, other_path.id, 10)
        .await
        .unwrap();

    let suffix = common::unique();
    let account = user_dao::insert_user(
        &pool,
        NewUser::local(format!("diamond-user-{suffix}"), "x".into(), true),
    )
    .await
    .expect("insert user");
    let role = authz_dao::insert_role(
        &pool,
        &format!("diamond-reader-{suffix}"),
        "diamond path selector regression",
    )
    .await
    .expect("insert role");
    let company_selector = authz_dao::insert_content_selector(
        &pool,
        &format!("diamond-company-{suffix}"),
        &["company.*".to_string()],
        &[],
    )
    .await
    .expect("insert company selector");
    let other_selector = authz_dao::insert_content_selector(
        &pool,
        &format!("diamond-other-{suffix}"),
        &["other.*".to_string()],
        &[],
    )
    .await
    .expect("insert other selector");

    authz_dao::add_grant(&pool, role.id, Some(outer.id), "read", None)
        .await
        .expect("grant outer read");
    authz_dao::add_grant(
        &pool,
        role.id,
        Some(company_path.id),
        "read",
        Some(company_selector),
    )
    .await
    .expect("grant company path read");
    authz_dao::add_grant(
        &pool,
        role.id,
        Some(other_path.id),
        "read",
        Some(other_selector),
    )
    .await
    .expect("grant other path read");
    authz_dao::add_grant(&pool, role.id, Some(leaf.id), "read", None)
        .await
        .expect("grant leaf read");
    authz_dao::add_grant(&pool, role.id, Some(middle.id), "read", None)
        .await
        .expect("grant middle read");
    authz_dao::assign_role(&pool, account.id, role.id)
        .await
        .expect("assign role");

    let principal = Principal::User {
        user_id: account.id,
        token_id: None,
        method: forge_core::auth::AuthMethod::Password,
    };
    let g = group_repo(&pool, blobs.clone(), principal);

    assert_eq!(
        g.list_versions(&outer.name, "company.tools")
            .await
            .unwrap()
            .len(),
        1,
        "higher-priority path keeps its matching package"
    );
    let other_versions = g.list_versions(&outer.name, "other.public").await.unwrap();
    assert_eq!(
        other_versions
            .iter()
            .map(|entry| entry.version.as_str())
            .collect::<Vec<_>>(),
        vec!["1.0.0", "2.0.0"],
        "lower path contributes its additional version without duplicate reads"
    );

    let loc = g
        .resolve_nupkg(&outer.name, "other.public", "1.0.0")
        .await
        .unwrap()
        .expect("Other.Public 1.0.0 resolves");
    assert_eq!(
        served_tag(&blobs, &loc),
        "nupkg-middle",
        "the middle leaf beats the shared leaf's lower-priority visible path"
    );

    let registration = g.registration(&outer.name, "other.public").await.unwrap();
    assert_eq!(registration.len(), 2);
    assert_eq!(
        registration[0].package_hash_sha512_base64.as_deref(),
        Some("hash-middle"),
        "registration overlap uses the package-specific highest-priority leaf"
    );

    let search = g
        .search(
            &outer.name,
            &SearchParams {
                q: "other.public".to_string(),
                ..SearchParams::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(search.total_hits, 1);
    assert_eq!(
        search.hits[0].latest_version, "1.0.0",
        "search winner follows the package-specific path order"
    );
}

#[tokio::test]
async fn layered_diamond_queries_each_leaf_once_per_operation() {
    // Eight two-wide layers produce 256 root-to-leaf paths but only 17 group
    // nodes (including the root) and one leaf. Every read operation must
    // construct/query that leaf once, not once per path.
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let leaf = seed_member(&pool, false).await;
    let outer = seed_group(&pool).await;
    seed_version(&pool, &mut blobs, leaf.id, "Dense.Graph", "1.0.0", "dense").await;

    let mut previous = vec![outer.clone()];
    for _ in 0..8 {
        let left = seed_group(&pool).await;
        let right = seed_group(&pool).await;
        for parent in &previous {
            repository_dao::add_group_member(&pool, parent.id, left.id, 100)
                .await
                .unwrap();
            repository_dao::add_group_member(&pool, parent.id, right.id, 90)
                .await
                .unwrap();
        }
        previous = vec![left, right];
    }
    for parent in &previous {
        repository_dao::add_group_member(&pool, parent.id, leaf.id, 100)
            .await
            .unwrap();
    }

    let builds = Arc::new(AtomicUsize::new(0));
    let factory = Arc::new(CountingHostedFactory {
        inner: HostedFactory {
            pool: pool.clone(),
            blobs,
        },
        builds: builds.clone(),
    });
    let authz = Authz::new(pool.clone(), Cache::l1_only(32));
    let g = GroupRepo::new(
        pool.clone(),
        user(&pool).await,
        factory,
        authz,
        TEST_MAX_DEPTH,
    );

    assert_eq!(
        g.list_versions(&outer.name, "dense.graph")
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(g
        .resolve_nupkg(&outer.name, "dense.graph", "1.0.0")
        .await
        .unwrap()
        .is_some());
    assert!(g
        .resolve_nuspec(&outer.name, "dense.graph", "1.0.0")
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        g.registration(&outer.name, "dense.graph")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        g.search(
            &outer.name,
            &SearchParams {
                q: "dense.graph".to_string(),
                ..SearchParams::default()
            }
        )
        .await
        .unwrap()
        .total_hits,
        1
    );
    assert_eq!(
        builds.load(Ordering::SeqCst),
        5,
        "five operations construct the unique leaf once each, not 256 times each"
    );
}

#[tokio::test]
async fn nested_group_inner_unreadable_blocks_descent() {
    // outer -> inner (NOT anon-readable) -> pub (anon-readable leaf). An
    // anonymous caller cannot read the inner group, so it must not descend and
    // therefore never reaches the public leaf: reading an outer group grants no
    // transitive read past an unreadable intermediate group.
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();

    let public = seed_member(&pool, true).await;
    let inner = seed_group(&pool).await; // no anon grant
    let outer = seed_group(&pool).await;

    seed_version(&pool, &mut blobs, public.id, "Pub", "1.0.0", "pub").await;

    repository_dao::add_group_member(&pool, inner.id, public.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, outer.id, inner.id, 100)
        .await
        .unwrap();
    let anon_role = authz_dao::role_id_by_name(&pool, authz_dao::ANONYMOUS_ROLE)
        .await
        .unwrap()
        .unwrap();
    authz_dao::add_grant(&pool, anon_role, Some(outer.id), "read", None)
        .await
        .unwrap();

    let g_anon = group_repo(&pool, blobs, anon());
    assert!(
        g_anon
            .list_versions(&outer.name, "pub")
            .await
            .unwrap()
            .is_empty(),
        "unreadable intermediate group blocks descent to its leaves"
    );
}

#[tokio::test]
async fn resolve_time_cycle_is_fail_closed_and_terminates() {
    // Inject a cycle directly via raw SQL (bypassing the config-time guard):
    // g_a -> g_b -> g_a, with a leaf hung off g_b. Resolution must terminate
    // (no hang) and serve the reachable leaf without looping.
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();

    let leaf = seed_member(&pool, false).await;
    let g_a = seed_group(&pool).await;
    let g_b = seed_group(&pool).await;

    seed_version(&pool, &mut blobs, leaf.id, "Sample", "1.0.0", "leaf").await;

    // g_a -> g_b (raw, no guard), g_b -> leaf, g_b -> g_a (the back-edge).
    sqlx::query!(
        "INSERT INTO group_member (group_id, member_id, priority) VALUES ($1,$2,$3)",
        g_a.id,
        g_b.id,
        100
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO group_member (group_id, member_id, priority) VALUES ($1,$2,$3)",
        g_b.id,
        leaf.id,
        50
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO group_member (group_id, member_id, priority) VALUES ($1,$2,$3)",
        g_b.id,
        g_a.id,
        10
    )
    .execute(&pool)
    .await
    .unwrap();

    let g = group_repo(&pool, blobs, user(&pool).await);

    // The visited-set breaks the back-edge; the leaf still resolves. A 5s
    // timeout guards against a regression that would loop forever.
    let versions = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        g.list_versions(&g_a.name, "sample"),
    )
    .await
    .expect("resolution must terminate (no infinite loop)")
    .expect("ok");
    assert_eq!(versions.len(), 1, "reachable leaf still served once");
}

#[tokio::test]
async fn resolve_time_depth_bound_is_fail_closed() {
    // outer -> inner -> leaf, but with max_depth = 1 the resolver stops before
    // descending into `inner` (depth bound hit), serving nothing — fail-closed.
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();

    let leaf = seed_member(&pool, false).await;
    let inner = seed_group(&pool).await;
    let outer = seed_group(&pool).await;

    seed_version(&pool, &mut blobs, leaf.id, "Sample", "1.0.0", "leaf").await;
    repository_dao::add_group_member(&pool, inner.id, leaf.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, outer.id, inner.id, 100)
        .await
        .unwrap();

    // depth bound 1: outer's direct members are walked at depth 0; descending
    // into `inner` would be depth 1 >= max ⇒ stop, fail-closed.
    let g = group_repo_depth(&pool, blobs, user(&pool).await, 1);
    assert!(
        g.list_versions(&outer.name, "sample")
            .await
            .unwrap()
            .is_empty(),
        "depth bound stops descent (fail-closed)"
    );
}

#[tokio::test]
async fn unknown_group_errors() {
    let pool = common::pool().await;
    let g = group_repo(&pool, StubBlobs::default(), user(&pool).await);
    let err = g.list_versions("no-such-group", "x").await.unwrap_err();
    assert!(matches!(err, RepoError::RepoNotFound(_)));
}

#[tokio::test]
async fn wrong_kind_errors() {
    let pool = common::pool().await;
    // A hosted repo is not a group → WrongKind.
    let hosted = seed_member(&pool, false).await;
    let g = group_repo(&pool, StubBlobs::default(), user(&pool).await);
    let err = g.list_versions(&hosted.name, "x").await.unwrap_err();
    assert!(matches!(err, RepoError::WrongKind { .. }));
}

// ── Proxy-kind members: failure tolerance, precedence, prefer-hosted ────────

/// A scripted stand-in for a proxy member: fixed versions, or a hard failure
/// (an unreachable upstream).
struct FakeProxy {
    versions: Vec<&'static str>,
    fail: bool,
}

impl FakeProxy {
    fn err() -> RepoError {
        RepoError::Storage("upstream unreachable".into())
    }

    fn entries(&self) -> Vec<forge_core::repo::VersionEntry> {
        self.versions
            .iter()
            .map(|v| forge_core::repo::VersionEntry {
                original_id: "Sample".into(),
                version: (*v).into(),
                version_original: (*v).into(),
                listed: true,
            })
            .collect()
    }
}

#[async_trait]
impl RepoReadOps for FakeProxy {
    async fn list_versions(
        &self,
        _repo: &str,
        _id: &str,
    ) -> Result<Vec<forge_core::repo::VersionEntry>, RepoError> {
        if self.fail {
            return Err(Self::err());
        }
        Ok(self.entries())
    }

    async fn resolve_nupkg(
        &self,
        _repo: &str,
        _id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        if self.fail {
            return Err(Self::err());
        }
        Ok(self.versions.contains(&version).then(|| NupkgLocation {
            blob_sha256: format!("proxy-{version}"),
            blob_s3_key: format!("proxy/{version}"),
            size: 1,
            content_type: "application/octet-stream".into(),
        }))
    }

    async fn resolve_nuspec(
        &self,
        _repo: &str,
        _id: &str,
        _version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        if self.fail {
            return Err(Self::err());
        }
        Ok(None)
    }

    async fn registration(
        &self,
        _repo: &str,
        _id: &str,
    ) -> Result<Vec<forge_core::repo::RegistrationEntry>, RepoError> {
        if self.fail {
            return Err(Self::err());
        }
        Ok(self
            .versions
            .iter()
            .map(|v| forge_core::repo::RegistrationEntry {
                original_id: "Sample".into(),
                version: (*v).into(),
                version_original: (*v).into(),
                listed: true,
                package_hash_sha512_base64: None,
                package_sha256: None,
                package_size: None,
                nuspec_bytes: None,
                manifest_summary: None,
                published: None,
            })
            .collect())
    }

    async fn search(
        &self,
        _repo: &str,
        _params: &SearchParams,
    ) -> Result<forge_core::repo::SearchResult, RepoError> {
        if self.fail {
            return Err(Self::err());
        }
        let versions = self.entries();
        Ok(forge_core::repo::SearchResult {
            total_hits: 1,
            hits: vec![forge_core::repo::SearchHit {
                original_id: "Sample".into(),
                latest_version: versions
                    .last()
                    .map(|v| v.version.clone())
                    .unwrap_or_default(),
                versions,
                ..Default::default()
            }],
        })
    }
}

/// Hosted members are real; proxy-kind members are [`FakeProxy`] by id.
struct MixedFactory {
    hosted: HostedFactory,
    proxies: HashMap<i64, Arc<FakeProxy>>,
}

impl MemberOpsFactory for MixedFactory {
    fn ops_for(&self, member: &Repository) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        match self.proxies.get(&member.id) {
            Some(fake) => Ok(fake.clone()),
            None => self.hosted.ops_for(member),
        }
    }
}

async fn seed_proxy_member(pool: &PgPool) -> Repository {
    let mut new = NewRepository::proxy(format!("proxy-{}", common::unique()));
    new.remote_url = Some("https://upstream.invalid/v3/index.json".into());
    repository_dao::insert_repository(pool, new)
        .await
        .expect("insert proxy member")
}

async fn set_prefer_hosted(pool: &PgPool, group: &Repository, on: bool) {
    sqlx::query("UPDATE repository SET config = jsonb_build_object('prefer_hosted', $2::boolean) WHERE id = $1")
        .bind(group.id)
        .bind(on)
        .execute(pool)
        .await
        .expect("set prefer_hosted");
}

fn mixed_group_repo(
    pool: &PgPool,
    blobs: StubBlobs,
    principal: Principal,
    proxies: HashMap<i64, Arc<FakeProxy>>,
) -> GroupRepo {
    let factory = Arc::new(MixedFactory {
        hosted: HostedFactory {
            pool: pool.clone(),
            blobs,
        },
        proxies,
    });
    let authz = Authz::new(pool.clone(), Cache::l1_only(16));
    GroupRepo::new(pool.clone(), principal, factory, authz, TEST_MAX_DEPTH)
        .with_format(Arc::new(nuget()))
}

/// An unreachable proxy member must not break restores of packages another
/// member can serve; only an all-members failure is an error.
#[tokio::test]
async fn failing_member_is_skipped_while_others_answer() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let hosted = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let group = seed_group(&pool).await;
    seed_version(&pool, &mut blobs, hosted.id, "Sample", "1.0.0", "h").await;
    // The broken proxy has the higher priority.
    repository_dao::add_group_member(&pool, group.id, proxy.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, hosted.id, 10)
        .await
        .unwrap();

    // Plain union semantics, so the proxy is consulted for this id at all.
    set_prefer_hosted(&pool, &group, false).await;
    let mut proxies = HashMap::new();
    proxies.insert(
        proxy.id,
        Arc::new(FakeProxy {
            versions: vec![],
            fail: true,
        }),
    );
    let g = mixed_group_repo(&pool, blobs, user(&pool).await, proxies);

    let versions = g.list_versions(&group.name, "sample").await.unwrap();
    assert_eq!(versions.len(), 1);
    assert!(g
        .resolve_nupkg(&group.name, "sample", "1.0.0")
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        g.registration(&group.name, "sample").await.unwrap().len(),
        1
    );
    assert!(g
        .registration_entry(&group.name, "sample", "1.0.0")
        .await
        .unwrap()
        .is_some());
    let params = SearchParams {
        q: "sample".into(),
        ..SearchParams::default()
    };
    assert_eq!(g.search(&group.name, &params).await.unwrap().total_hits, 1);

    // A version only the broken member could have is "unknown", not "absent".
    assert!(g
        .resolve_nupkg(&group.name, "sample", "9.9.9")
        .await
        .is_err());
    assert!(g
        .registration_entry(&group.name, "sample", "9.9.9")
        .await
        .is_err());
}

/// An id only the failing member could serve is "unknown", not "absent": the
/// group returns the member's error rather than an empty answer, which the
/// routes would turn into a 404 that clients and downstream proxies cache.
#[tokio::test]
async fn id_only_a_failing_member_could_serve_is_an_error() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let hosted = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let group = seed_group(&pool).await;
    // The hosted member answers, but only has an internal package.
    seed_version(&pool, &mut blobs, hosted.id, "Internal", "1.0.0", "h").await;
    repository_dao::add_group_member(&pool, group.id, hosted.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, proxy.id, 10)
        .await
        .unwrap();
    let mut proxies = HashMap::new();
    proxies.insert(
        proxy.id,
        Arc::new(FakeProxy {
            versions: vec![],
            fail: true,
        }),
    );
    let g = mixed_group_repo(&pool, blobs, user(&pool).await, proxies);

    let member_error = |result: Result<_, RepoError>| matches!(result, Err(RepoError::Storage(_)));
    assert!(member_error(
        g.list_versions(&group.name, "sample").await.map(|_| ())
    ));
    assert!(member_error(
        g.registration(&group.name, "sample").await.map(|_| ())
    ));
    assert!(member_error(
        g.registration_entry(&group.name, "sample", "1.0.0")
            .await
            .map(|_| ())
    ));
    assert!(member_error(
        g.resolve_nupkg(&group.name, "sample", "1.0.0")
            .await
            .map(|_| ())
    ));
    assert!(member_error(
        g.resolve_nuspec(&group.name, "sample", "1.0.0")
            .await
            .map(|_| ())
    ));

    // Search stays lenient: the hosted member answered (with no hits).
    let params = SearchParams {
        q: "sample".into(),
        ..SearchParams::default()
    };
    assert_eq!(g.search(&group.name, &params).await.unwrap().total_hits, 0);

    // The hosted member owns its id, so the failing proxy is not consulted.
    assert_eq!(
        g.list_versions(&group.name, "internal")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        g.registration(&group.name, "internal").await.unwrap().len(),
        1
    );
}

/// Merged versions follow NuGet precedence, not string order.
#[tokio::test]
async fn merged_versions_are_in_precedence_order() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let a = seed_member(&pool, false).await;
    let b = seed_member(&pool, false).await;
    let group = seed_group(&pool).await;
    seed_version(&pool, &mut blobs, a.id, "Sample", "1.10.0", "a").await;
    seed_version(&pool, &mut blobs, b.id, "Sample", "1.9.0", "b").await;
    seed_version(&pool, &mut blobs, b.id, "Sample", "1.9.0-beta", "b").await;
    repository_dao::add_group_member(&pool, group.id, a.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, b.id, 10)
        .await
        .unwrap();

    let g = mixed_group_repo(&pool, blobs, user(&pool).await, HashMap::new());
    let listed: Vec<String> = g
        .list_versions(&group.name, "sample")
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.version)
        .collect();
    assert_eq!(listed, ["1.9.0-beta", "1.9.0", "1.10.0"]);
    let reg: Vec<String> = g
        .registration(&group.name, "sample")
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.version)
        .collect();
    assert_eq!(reg, ["1.9.0-beta", "1.9.0", "1.10.0"]);
}

/// Dependency confusion: once a hosted member owns an id, a public proxy's
/// higher version of the same id is not served (prefer_hosted, default on).
#[tokio::test]
async fn prefer_hosted_hides_proxy_versions_of_internal_ids() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let hosted = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let group = seed_group(&pool).await;
    seed_version(&pool, &mut blobs, hosted.id, "Sample", "1.0.0", "h").await;
    repository_dao::add_group_member(&pool, group.id, proxy.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, hosted.id, 10)
        .await
        .unwrap();
    let mut proxies = HashMap::new();
    proxies.insert(
        proxy.id,
        Arc::new(FakeProxy {
            versions: vec!["99.0.0"],
            fail: false,
        }),
    );

    // Default (no config key): on.
    let g = mixed_group_repo(&pool, blobs.clone(), user(&pool).await, proxies.clone());
    let versions: Vec<String> = g
        .list_versions(&group.name, "sample")
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.version)
        .collect();
    assert_eq!(versions, ["1.0.0"]);
    assert!(g
        .resolve_nupkg(&group.name, "sample", "99.0.0")
        .await
        .unwrap()
        .is_none());
    let params = SearchParams {
        q: "sample".into(),
        ..SearchParams::default()
    };
    let hits = g.search(&group.name, &params).await.unwrap().hits;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].latest_version, "1.0.0");

    // Ids the hosted members do not have still come from the proxy.
    assert_eq!(
        g.list_versions(&group.name, "other").await.unwrap().len(),
        1
    );

    // Opting out restores plain union semantics.
    set_prefer_hosted(&pool, &group, false).await;
    let g = mixed_group_repo(&pool, blobs, user(&pool).await, proxies);
    assert_eq!(
        g.list_versions(&group.name, "sample").await.unwrap().len(),
        2
    );
}

// ── prefer_hosted is decided over every hosted leaf (review B2) ─────────────

/// Grant the built-in `anonymous` role `read` on `repo`.
async fn grant_anon_read(pool: &PgPool, repo: &Repository) {
    let anon_role = authz_dao::role_id_by_name(pool, authz_dao::ANONYMOUS_ROLE)
        .await
        .expect("query")
        .expect("anonymous role seeded");
    authz_dao::add_grant(pool, anon_role, Some(repo.id), "read", None)
        .await
        .expect("anon read grant");
}

/// A [`FakeProxy`] serving the attacker's `99.0.0`, keyed by its member id.
fn shadowing_proxy(proxy: &Repository) -> HashMap<i64, Arc<FakeProxy>> {
    let mut proxies = HashMap::new();
    proxies.insert(
        proxy.id,
        Arc::new(FakeProxy {
            versions: vec!["99.0.0"],
            fail: false,
        }),
    );
    proxies
}

/// The caller can see the group and the public proxy but not the hosted copy
/// of `sample`: every read must look like an unknown package, never fall
/// through to the proxy's higher version.
async fn assert_internal_id_not_served(g: &GroupRepo, group: &str, who: &str) {
    assert!(
        g.list_versions(group, "sample").await.unwrap().is_empty(),
        "{who}: flat index must not list the proxy's versions of an internal id"
    );
    assert!(
        g.resolve_nupkg(group, "sample", "99.0.0")
            .await
            .unwrap()
            .is_none(),
        "{who}: the proxy's nupkg of an internal id must not be downloadable"
    );
    assert!(
        g.resolve_nuspec(group, "sample", "99.0.0")
            .await
            .unwrap()
            .is_none(),
        "{who}: the proxy's nuspec of an internal id must not be served"
    );
    assert!(
        g.registration(group, "sample").await.unwrap().is_empty(),
        "{who}: registration must not carry the proxy's versions"
    );
    let search = g
        .search(
            group,
            &SearchParams {
                q: "sample".into(),
                ..SearchParams::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        (search.total_hits, search.hits.len()),
        (0, 0),
        "{who}: search must drop the proxy hit for an internal id"
    );
}

/// Mixed-anonymity group: anonymous group + anonymous proxy + private hosted
/// member owning the id. The anonymous caller cannot see the hosted copy, yet
/// must not be handed the proxy's (attacker's) version; ids the hosted members
/// do not own still come from the proxy, and an authenticated caller still
/// gets the hosted copy.
#[tokio::test]
async fn prefer_hosted_shields_internal_ids_from_anonymous_callers() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let hosted = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let group = seed_group(&pool).await;
    seed_version(&pool, &mut blobs, hosted.id, "Sample", "1.0.0", "h").await;
    // The proxy even outranks the hosted member.
    repository_dao::add_group_member(&pool, group.id, proxy.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, hosted.id, 10)
        .await
        .unwrap();
    grant_anon_read(&pool, &group).await;
    grant_anon_read(&pool, &proxy).await;

    let g = mixed_group_repo(&pool, blobs.clone(), anon(), shadowing_proxy(&proxy));
    assert_internal_id_not_served(&g, &group.name, "anonymous").await;
    assert_eq!(
        g.list_versions(&group.name, "other").await.unwrap().len(),
        1,
        "ids no hosted leaf owns are still proxied for the anonymous caller"
    );

    let g = mixed_group_repo(&pool, blobs, user(&pool).await, shadowing_proxy(&proxy));
    let versions: Vec<String> = g
        .list_versions(&group.name, "sample")
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.version)
        .collect();
    assert_eq!(
        versions,
        ["1.0.0"],
        "authenticated caller gets the hosted copy"
    );
}

/// A caller whose read grant on the hosted member is selector-scoped away from
/// the id is treated like one who cannot read the member at all.
#[tokio::test]
async fn prefer_hosted_shields_internal_ids_from_selector_scoped_callers() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let hosted = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let group = seed_group(&pool).await;
    seed_version(&pool, &mut blobs, hosted.id, "Sample", "1.0.0", "h").await;
    repository_dao::add_group_member(&pool, group.id, proxy.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, hosted.id, 10)
        .await
        .unwrap();

    let suffix = common::unique();
    let account = user_dao::insert_user(
        &pool,
        NewUser::local(format!("scoped-user-{suffix}"), "x".into(), true),
    )
    .await
    .expect("insert user");
    let role = authz_dao::insert_role(&pool, &format!("scoped-{suffix}"), "B2 regression")
        .await
        .expect("insert role");
    let selector = authz_dao::insert_content_selector(
        &pool,
        &format!("scoped-other-{suffix}"),
        &["other.*".to_string()],
        &[],
    )
    .await
    .expect("insert selector");
    for (repo, selector) in [
        (group.id, None),
        (proxy.id, None),
        (hosted.id, Some(selector)),
    ] {
        authz_dao::add_grant(&pool, role.id, Some(repo), "read", selector)
            .await
            .expect("grant read");
    }
    authz_dao::assign_role(&pool, account.id, role.id)
        .await
        .expect("assign role");
    let principal = Principal::User {
        user_id: account.id,
        token_id: None,
        method: forge_core::auth::AuthMethod::Password,
    };

    let g = mixed_group_repo(&pool, blobs, principal, shadowing_proxy(&proxy));
    assert_internal_id_not_served(&g, &group.name, "selector-scoped").await;
}

/// The owning hosted leaf sits in a nested group the caller cannot read at
/// all; ownership is still decided over it.
#[tokio::test]
async fn prefer_hosted_counts_hosted_leaves_behind_unreadable_nested_groups() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let hosted = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let inner = seed_group(&pool).await; // no anonymous grant
    let outer = seed_group(&pool).await;
    seed_version(&pool, &mut blobs, hosted.id, "Sample", "1.0.0", "h").await;
    repository_dao::add_group_member(&pool, inner.id, hosted.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, outer.id, proxy.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, outer.id, inner.id, 10)
        .await
        .unwrap();
    grant_anon_read(&pool, &outer).await;
    grant_anon_read(&pool, &proxy).await;
    // Even read on the hosted leaf itself does not help while the inner group
    // blocks descent — the leaf still owns the id.
    grant_anon_read(&pool, &hosted).await;

    let g = mixed_group_repo(&pool, blobs, anon(), shadowing_proxy(&proxy));
    assert_internal_id_not_served(&g, &outer.name, "anonymous (nested)").await;
}

/// Ownership counts unlisted versions too, and opting out of prefer_hosted
/// restores the proxy for callers who cannot see the hosted copy.
#[tokio::test]
async fn prefer_hosted_ownership_includes_unlisted_and_respects_opt_out() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let hosted = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let group = seed_group(&pool).await;
    seed_version(&pool, &mut blobs, hosted.id, "Sample", "1.0.0", "h").await;
    assert!(
        component_dao::set_listed(&pool, hosted.id, "sample", "1.0.0", false)
            .await
            .unwrap()
    );
    repository_dao::add_group_member(&pool, group.id, proxy.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, hosted.id, 10)
        .await
        .unwrap();
    grant_anon_read(&pool, &group).await;
    grant_anon_read(&pool, &proxy).await;

    let g = mixed_group_repo(&pool, blobs.clone(), anon(), shadowing_proxy(&proxy));
    assert_internal_id_not_served(&g, &group.name, "anonymous (unlisted owner)").await;

    // An authenticated caller sees the hosted member, whose only version is
    // unlisted: search drops the proxy hit and has no hosted hit to show.
    let g = mixed_group_repo(
        &pool,
        blobs.clone(),
        user(&pool).await,
        shadowing_proxy(&proxy),
    );
    let params = SearchParams {
        q: "sample".into(),
        ..SearchParams::default()
    };
    assert_eq!(g.search(&group.name, &params).await.unwrap().total_hits, 0);

    set_prefer_hosted(&pool, &group, false).await;
    let g = mixed_group_repo(&pool, blobs, anon(), shadowing_proxy(&proxy));
    assert_eq!(
        g.list_versions(&group.name, "sample").await.unwrap().len(),
        1,
        "without prefer_hosted the proxy serves the id"
    );
}

/// Reserved prefixes: an internal name no hosted member has yet (before its
/// first publish, or after its last version was deleted) is still never served
/// from a proxy member, which prefer_hosted alone cannot ensure.
#[tokio::test]
async fn reserved_prefixes_keep_unpublished_internal_ids_off_proxies() {
    let pool = common::pool().await;
    let blobs = StubBlobs::default();
    let hosted = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let group = seed_group(&pool).await;
    repository_dao::add_group_member(&pool, group.id, proxy.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, hosted.id, 10)
        .await
        .unwrap();
    let set_prefixes = |prefixes: serde_json::Value| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "UPDATE repository SET config = jsonb_build_object(\
                 'prefer_hosted', true, 'reserved_prefixes', $2::jsonb) WHERE id = $1",
            )
            .bind(group.id)
            .bind(prefixes)
            .execute(&pool)
            .await
            .unwrap();
        }
    };

    // No hosted copy and no reservation: the public package is served.
    let g = mixed_group_repo(
        &pool,
        blobs.clone(),
        user(&pool).await,
        shadowing_proxy(&proxy),
    );
    assert_eq!(
        g.list_versions(&group.name, "sample").await.unwrap().len(),
        1
    );

    // `Samp` is reserved: nothing under it comes from the proxy.
    set_prefixes(serde_json::json!(["samp"])).await;
    let g = mixed_group_repo(
        &pool,
        blobs.clone(),
        user(&pool).await,
        shadowing_proxy(&proxy),
    );
    assert_internal_id_not_served(&g, &group.name, "reserved prefix").await;

    // Another organization's prefix leaves the id alone.
    set_prefixes(serde_json::json!(["acme."])).await;
    let g = mixed_group_repo(&pool, blobs, user(&pool).await, shadowing_proxy(&proxy));
    assert_eq!(
        g.list_versions(&group.name, "sample").await.unwrap().len(),
        1
    );
}

// ── group search enriches only the final page (review M8) ───────────────────

/// [`StubBlobs`] that counts every blob read (the S3 manifest fetches search
/// enrichment performs).
#[derive(Clone)]
struct CountingBlobs {
    inner: StubBlobs,
    fetches: Arc<AtomicUsize>,
}

#[async_trait]
impl BlobFetch for CountingBlobs {
    async fn fetch_all(&self, blob: &forge_db::model::Blob) -> Result<Vec<u8>, RepoError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        self.inner.fetch_all(blob).await
    }
}

struct CountingBlobsFactory {
    pool: PgPool,
    blobs: CountingBlobs,
}

impl MemberOpsFactory for CountingBlobsFactory {
    fn ops_for(&self, _member: &Repository) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        Ok(Arc::new(HostedRepo::new(
            self.pool.clone(),
            Arc::new(nuget()),
            Arc::new(self.blobs.clone()),
        )))
    }
}

/// Two hosted members with 30 ids each (10 shared). A paged group search reads
/// manifests for the returned page only — not for every member's full result —
/// while totals, order, paging and the highest-priority winner are unchanged
/// and each hit's manifest comes from the member that won it.
#[tokio::test]
async fn group_search_enriches_only_the_final_page() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let high = seed_member(&pool, false).await;
    let low = seed_member(&pool, false).await;
    let group = seed_group(&pool).await;
    let prefix = format!("Paged{}", common::unique());
    // high: ids 00..29, low: ids 20..49 → 50 distinct ids, 20..29 shared.
    for n in 0..30 {
        let id = format!("{prefix}.P{n:02}");
        seed_version(&pool, &mut blobs, high.id, &id, "2.0.0", "high").await;
    }
    for n in 20..50 {
        let id = format!("{prefix}.P{n:02}");
        seed_version(&pool, &mut blobs, low.id, &id, "1.0.0", "low").await;
    }
    repository_dao::add_group_member(&pool, group.id, high.id, 100)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, low.id, 10)
        .await
        .unwrap();

    let fetches = Arc::new(AtomicUsize::new(0));
    let factory = Arc::new(CountingBlobsFactory {
        pool: pool.clone(),
        blobs: CountingBlobs {
            inner: blobs,
            fetches: fetches.clone(),
        },
    });
    let authz = Authz::new(pool.clone(), Cache::l1_only(16));
    let g = GroupRepo::new(
        pool.clone(),
        user(&pool).await,
        factory,
        authz,
        TEST_MAX_DEPTH,
    )
    .with_format(Arc::new(nuget()));

    let result = g
        .search(
            &group.name,
            &SearchParams {
                q: prefix.clone(),
                skip: 27,
                take: 5,
                prerelease: false,
                include_semver2: true,
                include_upstream: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(result.total_hits, 50, "totals count every merged id");
    let page: Vec<(String, String)> = result
        .hits
        .iter()
        .map(|h| (h.original_id.clone(), h.latest_version.clone()))
        .collect();
    let expected: Vec<(String, String)> = (27..32)
        .map(|n| {
            let version = if n < 30 { "2.0.0" } else { "1.0.0" };
            (format!("{prefix}.P{n:02}"), version.to_string())
        })
        .collect();
    assert_eq!(page, expected, "merged order, paging and winners unchanged");
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        5,
        "only the 5 returned hits read a manifest (not 30 + 30)"
    );
    for hit in &result.hits {
        let winner = if hit.latest_version == "2.0.0" {
            "high"
        } else {
            "low"
        };
        assert_eq!(
            hit.nuspec_bytes.as_deref(),
            Some(format!("nuspec-{winner}").as_bytes()),
            "{}: manifest comes from the winning member",
            hit.original_id
        );
        assert_eq!(hit.total_downloads, Some(0), "download totals attached");
    }
}

// ── owner members (review M-c) ───────────────────────────────────────────────

async fn sorted_versions(g: &GroupRepo, group: &str, id: &str) -> Vec<String> {
    let mut versions: Vec<String> = g
        .list_versions(group, id)
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.version)
        .collect();
    versions.sort();
    versions
}

/// Once a group flags owner members, a writer of another hosted member (a
/// developer feed in the same group) can neither publish under a reserved
/// prefix nor take a public id away from the proxy; the owners, including
/// the hosted leaves of a flagged nested group, still can.
#[tokio::test]
async fn only_owner_members_claim_ids_and_serve_reserved_prefixes() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let releases = seed_member(&pool, false).await;
    let dev = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let group = seed_group(&pool).await;
    for (member, priority) in [(&proxy, 100), (&releases, 50), (&dev, 10)] {
        repository_dao::add_group_member(&pool, group.id, member.id, priority)
            .await
            .unwrap();
    }
    sqlx::query(
        "UPDATE repository SET config = jsonb_build_object(\
         'prefer_hosted', true, 'reserved_prefixes', '[\"acme.\"]'::jsonb) WHERE id = $1",
    )
    .bind(group.id)
    .execute(&pool)
    .await
    .unwrap();
    seed_version(
        &pool,
        &mut blobs,
        releases.id,
        "Acme.Internal",
        "1.0.0",
        "rel",
    )
    .await;
    seed_version(&pool, &mut blobs, dev.id, "Acme.Internal", "99.0.0", "dev").await;
    seed_version(&pool, &mut blobs, dev.id, "Sample", "1.0.0", "dev-sample").await;
    seed_version(
        &pool,
        &mut blobs,
        releases.id,
        "Contoso.Lib",
        "1.0.0",
        "lib",
    )
    .await;
    seed_version(&pool, &mut blobs, dev.id, "Contoso.Lib", "9.0.0", "dev-lib").await;

    // No owner flagged: every hosted member is trusted (the old behaviour).
    let g = mixed_group_repo(
        &pool,
        blobs.clone(),
        user(&pool).await,
        shadowing_proxy(&proxy),
    );
    assert_eq!(
        sorted_versions(&g, &group.name, "acme.internal").await,
        ["1.0.0", "99.0.0"]
    );
    assert_eq!(
        sorted_versions(&g, &group.name, "sample").await,
        ["1.0.0"],
        "dev claims the public id"
    );
    assert_eq!(
        sorted_versions(&g, &group.name, "contoso.lib").await,
        ["1.0.0", "9.0.0"]
    );

    // `releases` owns the group's ids.
    assert!(
        repository_dao::set_group_member_owner(&pool, group.id, releases.id, true)
            .await
            .unwrap()
    );
    let g = mixed_group_repo(
        &pool,
        blobs.clone(),
        user(&pool).await,
        shadowing_proxy(&proxy),
    );
    assert_eq!(
        sorted_versions(&g, &group.name, "acme.internal").await,
        ["1.0.0"]
    );
    assert!(g
        .resolve_nupkg(&group.name, "acme.internal", "99.0.0")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        sorted_versions(&g, &group.name, "sample").await,
        ["1.0.0", "99.0.0"],
        "dev's copy no longer hides the proxy's versions"
    );
    let hits = g
        .search(
            &group.name,
            &SearchParams {
                q: "acme".into(),
                ..SearchParams::default()
            },
        )
        .await
        .unwrap()
        .hits;
    let internal = hits
        .iter()
        .find(|hit| hit.original_id.eq_ignore_ascii_case("acme.internal"))
        .expect("the owner's package is found");
    assert_eq!(internal.latest_version, "1.0.0");
    // An id the owner has, outside the reserved prefixes: dev cannot add a
    // version to it either, in any read.
    assert_eq!(
        sorted_versions(&g, &group.name, "contoso.lib").await,
        ["1.0.0"]
    );
    assert!(g
        .resolve_nupkg(&group.name, "contoso.lib", "9.0.0")
        .await
        .unwrap()
        .is_none());
    let hits = g
        .search(
            &group.name,
            &SearchParams {
                q: "contoso".into(),
                ..SearchParams::default()
            },
        )
        .await
        .unwrap()
        .hits;
    let lib = hits
        .iter()
        .find(|hit| hit.original_id.eq_ignore_ascii_case("contoso.lib"))
        .expect("the owner's package is found");
    assert_eq!(lib.latest_version, "1.0.0");
    assert_eq!(lib.versions.len(), 1, "{lib:?}");

    // A flagged nested group: its hosted leaves own ids too.
    let inner = seed_group(&pool).await;
    let platform = seed_member(&pool, false).await;
    repository_dao::add_group_member(&pool, inner.id, platform.id, 10)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, inner.id, 40)
        .await
        .unwrap();
    seed_version(
        &pool,
        &mut blobs,
        platform.id,
        "Acme.Platform",
        "2.0.0",
        "plat",
    )
    .await;
    let g = mixed_group_repo(
        &pool,
        blobs.clone(),
        user(&pool).await,
        shadowing_proxy(&proxy),
    );
    assert!(
        sorted_versions(&g, &group.name, "acme.platform")
            .await
            .is_empty(),
        "not an owner yet"
    );
    repository_dao::set_group_member_owner(&pool, group.id, inner.id, true)
        .await
        .unwrap();
    let g = mixed_group_repo(&pool, blobs, user(&pool).await, shadowing_proxy(&proxy));
    assert_eq!(
        sorted_versions(&g, &group.name, "acme.platform").await,
        ["2.0.0"]
    );
}

/// A nested group keeps its own guards when it is read through an outer
/// group, whatever the outer group's settings: its reserved prefixes, its
/// owners and its prefer-hosted setting decide what its members serve, so
/// nesting is never less protective than reading the inner group directly.
#[tokio::test]
async fn a_nested_group_keeps_its_guards_when_read_through_an_outer_group() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let releases = seed_member(&pool, false).await;
    let dev = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let inner = seed_group(&pool).await;
    for (member, priority) in [(&proxy, 100), (&releases, 50), (&dev, 10)] {
        repository_dao::add_group_member(&pool, inner.id, member.id, priority)
            .await
            .unwrap();
    }
    repository_dao::set_group_member_owner(&pool, inner.id, releases.id, true)
        .await
        .unwrap();
    let outer = seed_group(&pool).await;
    repository_dao::add_group_member(&pool, outer.id, inner.id, 10)
        .await
        .unwrap();
    for (group, config) in [
        (
            &inner,
            r#"{"prefer_hosted": true, "reserved_prefixes": ["acme."]}"#,
        ),
        // The most permissive outer group: no guard of its own at all.
        (&outer, r#"{"prefer_hosted": false}"#),
    ] {
        sqlx::query("UPDATE repository SET config = $2::jsonb WHERE id = $1")
            .bind(group.id)
            .bind(config)
            .execute(&pool)
            .await
            .unwrap();
    }
    seed_version(
        &pool,
        &mut blobs,
        releases.id,
        "Contoso.Lib",
        "1.0.0",
        "lib",
    )
    .await;
    seed_version(&pool, &mut blobs, dev.id, "Contoso.Lib", "9.0.0", "dev-lib").await;
    seed_version(&pool, &mut blobs, dev.id, "Sample", "1.0.0", "dev-sample").await;

    for flag_inner_as_owner in [false, true] {
        repository_dao::set_group_member_owner(&pool, outer.id, inner.id, flag_inner_as_owner)
            .await
            .unwrap();
        let g = mixed_group_repo(
            &pool,
            blobs.clone(),
            user(&pool).await,
            shadowing_proxy(&proxy),
        );
        for group in [&inner.name, &outer.name] {
            let why = format!("through {group}, inner flagged in outer: {flag_inner_as_owner}");
            // `dev` cannot add a version to the owner's package.
            assert_eq!(
                sorted_versions(&g, group, "contoso.lib").await,
                ["1.0.0"],
                "{why}"
            );
            assert!(
                g.resolve_nupkg(group, "contoso.lib", "9.0.0")
                    .await
                    .unwrap()
                    .is_none(),
                "{why}"
            );
            // The proxy cannot serve an id under the inner reserved prefix.
            assert!(
                sorted_versions(&g, group, "acme.new").await.is_empty(),
                "{why}"
            );
            assert!(
                g.resolve_nupkg(group, "acme.new", "99.0.0")
                    .await
                    .unwrap()
                    .is_none(),
                "{why}"
            );
            // `dev` cannot take a public id away from the proxy.
            assert_eq!(
                sorted_versions(&g, group, "sample").await,
                ["1.0.0", "99.0.0"],
                "{why}"
            );
            let hits = g
                .search(
                    group,
                    &SearchParams {
                        q: "contoso".into(),
                        ..SearchParams::default()
                    },
                )
                .await
                .unwrap()
                .hits;
            let lib = hits
                .iter()
                .find(|hit| hit.original_id.eq_ignore_ascii_case("contoso.lib"))
                .expect("the owner's package is found");
            assert_eq!(lib.latest_version, "1.0.0", "{why}");
            assert_eq!(lib.versions.len(), 1, "{why}: {lib:?}");
            let hits = g
                .search(
                    group,
                    &SearchParams {
                        q: "acme".into(),
                        ..SearchParams::default()
                    },
                )
                .await
                .unwrap()
                .hits;
            assert!(
                !hits
                    .iter()
                    .any(|hit| hit.original_id.to_ascii_lowercase().starts_with("acme.")),
                "{why}: {hits:?}"
            );
        }
    }
}

/// #73: an offline hosted member is a failing member: what only it could
/// serve is an error (clients retry), never a not-found; the other members
/// still answer.
#[tokio::test]
async fn an_offline_hosted_member_fails_instead_of_serving() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let a = seed_member(&pool, false).await;
    let b = seed_member(&pool, false).await;
    let group = seed_group(&pool).await;
    repository_dao::add_group_member(&pool, group.id, a.id, 20)
        .await
        .unwrap();
    repository_dao::add_group_member(&pool, group.id, b.id, 10)
        .await
        .unwrap();
    seed_version(&pool, &mut blobs, a.id, "Only.In.A", "1.0.0", "a").await;
    seed_version(&pool, &mut blobs, b.id, "Only.In.B", "2.0.0", "b").await;
    sqlx::query("UPDATE repository SET online = false WHERE id = $1")
        .bind(a.id)
        .execute(&pool)
        .await
        .unwrap();
    let g = mixed_group_repo(&pool, blobs, user(&pool).await, HashMap::new());
    assert!(matches!(
        g.list_versions(&group.name, "only.in.a").await,
        Err(forge_core::repo::RepoError::Busy(_))
    ));
    assert!(g
        .resolve_nupkg(&group.name, "only.in.a", "1.0.0")
        .await
        .is_err());
    assert_eq!(
        sorted_versions(&g, &group.name, "only.in.b").await,
        ["2.0.0"]
    );
}

/// #106: an offline nested group is a failing member of its outer group, like
/// an offline hosted member: nothing below it is served through the outer
/// group (it is not descended into), what only it could serve is an error,
/// never a not-found, and the other members still answer. An id one of its
/// hosted leaves owns does not fall back to a public proxy meanwhile.
#[tokio::test]
async fn an_offline_nested_group_fails_instead_of_serving() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let inner_leaf = seed_member(&pool, false).await;
    let other = seed_member(&pool, false).await;
    let proxy = seed_proxy_member(&pool).await;
    let inner = seed_group(&pool).await;
    repository_dao::add_group_member(&pool, inner.id, inner_leaf.id, 10)
        .await
        .unwrap();
    let outer = seed_group(&pool).await;
    for (member, priority) in [(&inner, 30), (&other, 20), (&proxy, 10)] {
        repository_dao::add_group_member(&pool, outer.id, member.id, priority)
            .await
            .unwrap();
    }
    set_prefer_hosted(&pool, &outer, true).await;
    seed_version(&pool, &mut blobs, inner_leaf.id, "Only.Inner", "1.0.0", "i").await;
    seed_version(&pool, &mut blobs, inner_leaf.id, "Sample", "1.0.0", "s").await;
    seed_version(&pool, &mut blobs, other.id, "Only.Other", "2.0.0", "o").await;

    let principal = user(&pool).await;
    let read =
        |blobs: StubBlobs| mixed_group_repo(&pool, blobs, principal, shadowing_proxy(&proxy));
    let g = read(blobs.clone());
    assert_eq!(
        sorted_versions(&g, &outer.name, "only.inner").await,
        ["1.0.0"],
        "online: served through the inner group"
    );

    sqlx::query("UPDATE repository SET online = false WHERE id = $1")
        .bind(inner.id)
        .execute(&pool)
        .await
        .unwrap();
    let g = read(blobs);
    assert!(matches!(
        g.list_versions(&outer.name, "only.inner").await,
        Err(forge_core::repo::RepoError::Busy(_))
    ));
    assert!(g
        .resolve_nupkg(&outer.name, "only.inner", "1.0.0")
        .await
        .is_err());
    assert!(g.registration(&outer.name, "only.inner").await.is_err());
    // The inner leaf's internal id is not handed to the public proxy.
    assert!(g.list_versions(&outer.name, "sample").await.is_err());
    assert!(g
        .resolve_nupkg(&outer.name, "sample", "99.0.0")
        .await
        .is_err());
    // The other members still answer.
    assert_eq!(
        sorted_versions(&g, &outer.name, "only.other").await,
        ["2.0.0"]
    );
    let hits = g
        .search(
            &outer.name,
            &SearchParams {
                q: "only".into(),
                ..SearchParams::default()
            },
        )
        .await
        .unwrap()
        .hits;
    let ids: Vec<String> = hits.iter().map(|h| h.original_id.to_lowercase()).collect();
    assert_eq!(ids, ["only.other"], "{hits:?}");
}

/// #107: a leaf is served when one visible path admits it, also when the
/// same inner group is reached along two paths of the same length and only
/// the first path's group guards the id. Root → {A, B} → N → hosted leaf;
/// A reserves `acme.` for its owners (which exclude N's leaf), B has no
/// guard: `Acme.Lib` is served through the root and through B, not through
/// A.
#[tokio::test]
async fn a_diamond_serves_what_its_unguarded_path_admits() {
    let pool = common::pool().await;
    let mut blobs = StubBlobs::default();
    let leaf = seed_member(&pool, false).await;
    let a_owner = seed_member(&pool, false).await;
    let n = seed_group(&pool).await;
    repository_dao::add_group_member(&pool, n.id, leaf.id, 10)
        .await
        .unwrap();
    let a = seed_group(&pool).await;
    let b = seed_group(&pool).await;
    for (group, members) in [(&a, vec![(&n, 20), (&a_owner, 10)]), (&b, vec![(&n, 10)])] {
        for (member, priority) in members {
            repository_dao::add_group_member(&pool, group.id, member.id, priority)
                .await
                .unwrap();
        }
    }
    repository_dao::set_group_member_owner(&pool, a.id, a_owner.id, true)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE repository SET config = jsonb_build_object(\
         'prefer_hosted', true, 'reserved_prefixes', '[\"acme.\"]'::jsonb) WHERE id = $1",
    )
    .bind(a.id)
    .execute(&pool)
    .await
    .unwrap();
    let root = seed_group(&pool).await;
    // A first, so the walk reaches N through the guarded path first.
    for (member, priority) in [(&a, 20), (&b, 10)] {
        repository_dao::add_group_member(&pool, root.id, member.id, priority)
            .await
            .unwrap();
    }
    seed_version(&pool, &mut blobs, leaf.id, "Acme.Lib", "1.0.0", "leaf").await;

    let g = group_repo(&pool, blobs, user(&pool).await);
    for group in [&root, &b] {
        assert_eq!(
            sorted_versions(&g, &group.name, "acme.lib").await,
            ["1.0.0"],
            "through {}",
            group.name
        );
        assert!(
            g.resolve_nupkg(&group.name, "acme.lib", "1.0.0")
                .await
                .unwrap()
                .is_some(),
            "through {}",
            group.name
        );
        let hits = g
            .search(
                &group.name,
                &SearchParams {
                    q: "acme".into(),
                    ..SearchParams::default()
                },
            )
            .await
            .unwrap()
            .hits;
        assert_eq!(hits.len(), 1, "through {}: {hits:?}", group.name);
    }
    assert!(
        sorted_versions(&g, &a.name, "acme.lib").await.is_empty(),
        "A's guard keeps it from its non-owner"
    );
}
