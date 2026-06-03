//! Integration tests for identity-aware group resolution (Phase 9, Task 9.1).
//!
//! Seeds two hosted **member** repositories plus a **group** that federates
//! them, then drives [`forge_core::repo::group::GroupRepo`] through the
//! [`RepoReadOps`] trait. Members are built with real [`HostedRepo`] instances
//! (over the shared Postgres) via an in-memory [`MemberOpsFactory`], with a stub
//! [`BlobFetch`] so no S3 is needed.
//!
//! Coverage (per plan Phase 9):
//! * two members share an overlapping version → the **highest-priority** member
//!   serves the `.nupkg`;
//! * `list_versions` returns the **union** of both members' versions;
//! * a **mixed-anonymity** group filters by principal: anonymous sees only
//!   `anonymous_read` members, authenticated sees all.

mod common;

use std::collections::HashMap;
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
use forge_nuget::NugetFormat;
use sqlx::PgPool;

/// In-memory blob byte store: maps `s3_key -> bytes`.
#[derive(Default, Clone)]
struct StubBlobs {
    map: HashMap<String, Vec<u8>>,
}

#[async_trait]
impl BlobFetch for StubBlobs {
    async fn fetch_all(&self, s3_key: &str) -> Result<Vec<u8>, RepoError> {
        self.map
            .get(s3_key)
            .cloned()
            .ok_or_else(|| RepoError::RepoNotFound(format!("missing blob {s3_key}")))
    }
}

/// A [`MemberOpsFactory`] that builds a [`HostedRepo`] for every member, sharing
/// the pool and the stub blob bytes. Slice-1 group members are hosted/proxy; the
/// tests only exercise hosted members, which is sufficient for the resolution
/// semantics (the factory seam is what the server swaps for proxy support).
struct HostedFactory {
    pool: PgPool,
    blobs: StubBlobs,
}

impl MemberOpsFactory for HostedFactory {
    fn ops_for(&self, _member: &Repository) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        Ok(Arc::new(HostedRepo::new(
            self.pool.clone(),
            Arc::new(NugetFormat::new()),
            Arc::new(self.blobs.clone()),
        )))
    }
}

/// Build a `GroupRepo` for `principal` over the pool + stub blobs.
fn group_repo(pool: &PgPool, blobs: StubBlobs, principal: Principal) -> GroupRepo {
    let factory = Arc::new(HostedFactory {
        pool: pool.clone(),
        blobs,
    });
    let authz = Authz::new(pool.clone(), Cache::l1_only(16));
    GroupRepo::new(pool.clone(), principal, factory, authz)
}

/// A real (non-admin) authenticated user holding the seeded `authenticated`
/// role — the role the §12.4 data migration assigns to preserve slice-1
/// "any authenticated user reads/writes everywhere". This is what makes the
/// authenticated-sees-all assertions hold under fine-grained RBAC: visibility
/// now flows through `can_read`, so the user must actually be granted read.
async fn user(pool: &PgPool) -> Principal {
    let u = user_dao::insert_user(
        pool,
        NewUser::local(
            format!("groupuser-{}", common::unique()),
            "x".into(),
            false,
            true,
        ),
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
        is_admin: false,
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
/// built-in `anonymous` role `read` on it — under §12.4 RBAC anonymous
/// visibility flows through that grant (what the data migration converts the
/// slice-1 `anonymous_read` flag into), not the column. The column is still set
/// for parity but is no longer consulted by the seam.
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
