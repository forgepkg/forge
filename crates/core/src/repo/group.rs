//! Group-repository read resolution (spec §7 "Group", plan Phase 9).
//!
//! A **group** repository has no storage of its own: it federates reads across
//! an ordered list of **member** repositories (hosted or proxy). Members carry a
//! per-group `priority` (unique within the group); the highest priority wins
//! ties. Resolution is **identity-aware**: for a calling [`Principal`] `P`, only
//! members `P` may read (per [`authz::can_read`]) are visible. In particular a
//! mixed-anonymity group serves an anonymous caller only its `anonymous_read`
//! members, while an authenticated caller sees them all.
//!
//! Semantics (spec §7):
//! * **Enumeration** ([`list_versions`](RepoReadOps::list_versions)) = the
//!   **union** of the visible members' versions, deduped by normalized version.
//! * **Specific download** ([`resolve_nupkg`](RepoReadOps::resolve_nupkg) /
//!   [`resolve_nuspec`](RepoReadOps::resolve_nuspec)) = the **highest-priority**
//!   visible member that has the exact `(id, version)`.
//! * **Registration / search** merge across visible members, dedup by
//!   `id + version` (registration) / `id` (search), **highest-priority wins**.
//!
//! Groups are **read-only**. Since §12.4 Phase 4 a group member **may itself be
//! a group** (nested groups). Resolution flattens the nested graph into the
//! ordered list of **leaf** (hosted/proxy) members before reading: the
//! [`MemberOpsFactory`] is only ever asked for a leaf. Two guards keep this
//! safe even against a cycle injected by a raw DB write:
//!
//! * a **visited-set** (group ids already on the current descent) — a re-visit
//!   is treated as an empty subtree (fail-closed) and logged, never followed;
//! * a **depth bound** (`max_depth`, from `groups.max_nesting_depth`) — descent
//!   past it stops (fail-closed).
//!
//! Identity-aware filtering is applied at **every** level: a member (group or
//! leaf) is descended-into / included only if the principal [`can_read`] it
//! ([`Authz::can_read`]). Being able to read an outer group grants **no**
//! transitive read on an inner member — only a `read` grant on the actual leaf
//! repo does. Priority ordering (slice §7: higher wins ties) is preserved as a
//! stable pre-order walk; a leaf reachable by several paths is kept once, at its
//! highest-priority (first) sighting.
//!
//! ## Decoupling from concrete member kinds
//! `forge-core` must not hard-wire how a hosted vs. proxy member is constructed
//! (that needs the S3 client, the cache, the SSRF resolver — all server wiring).
//! [`GroupRepo`] therefore takes a [`MemberOpsFactory`]: given a member
//! [`Repository`] row it returns that member's [`RepoReadOps`]. The server
//! implements it by branching on [`Repository::kind`]; tests implement it with
//! an in-memory map.

use std::sync::Arc;

use async_trait::async_trait;
use forge_db::model::Repository;
use forge_db::repository_dao;
use sqlx::PgPool;

use crate::auth::authz::Authz;
use crate::auth::principal::Principal;
use crate::repo::{
    NupkgLocation, RegistrationEntry, RepoError, RepoReadOps, SearchHit, SearchParams,
    SearchResult, VersionEntry,
};

/// Builds the [`RepoReadOps`] for one member repository of a group.
///
/// The group resolver itself is format/kind-agnostic; the server wires this to
/// branch on [`Repository::kind`] (hosted → `HostedRepo`, proxy → `ProxyRepo`)
/// while tests supply an in-memory stub. The factory is fallible so a member
/// whose backing wiring is unavailable surfaces as a [`RepoError`] rather than a
/// panic.
pub trait MemberOpsFactory: Send + Sync {
    /// Construct the read ops for `member`. Implementations should reject a
    /// nested group member (kind == "group") — though Phase 10 config validation
    /// already prevents one from being persisted.
    fn ops_for(&self, member: &Repository) -> Result<Arc<dyn RepoReadOps>, RepoError>;
}

/// Identity-aware group read resolver.
///
/// Constructed per request with the [`Principal`] in hand so visibility
/// filtering is baked into every method. Implements [`RepoReadOps`] keyed by the
/// **group** repository name; the per-member ops are keyed by each member's own
/// name (resolved from the `group_member` join).
pub struct GroupRepo {
    pool: PgPool,
    principal: Principal,
    factory: Arc<dyn MemberOpsFactory>,
    authz: Authz,
    /// Maximum nesting depth followed when flattening nested groups
    /// (`groups.max_nesting_depth`). Descent past this bound stops, fail-closed.
    max_depth: u32,
}

/// A visible member: its repository row (carrying its own `name`) and the ops to
/// read it, in descending priority order.
struct VisibleMember {
    repo: Repository,
    ops: Arc<dyn RepoReadOps>,
}

impl GroupRepo {
    /// Build a group resolver for `principal` over `pool`, using `factory` to
    /// construct each member's read ops and `authz` to filter members the
    /// principal may read. `max_depth` bounds nested-group descent
    /// (`groups.max_nesting_depth`).
    pub fn new(
        pool: PgPool,
        principal: Principal,
        factory: Arc<dyn MemberOpsFactory>,
        authz: Authz,
        max_depth: u32,
    ) -> Self {
        GroupRepo {
            pool,
            principal,
            factory,
            authz,
            max_depth,
        }
    }

    /// Resolve the group repository row by name, erroring if missing or not a
    /// group.
    async fn group_row(&self, repo: &str) -> Result<Repository, RepoError> {
        let row = repository_dao::find_repository_by_name(&self.pool, repo)
            .await?
            .ok_or_else(|| RepoError::RepoNotFound(repo.to_string()))?;
        if row.kind() != forge_db::model::RepoKind::Group {
            return Err(RepoError::WrongKind {
                name: repo.to_string(),
                kind: row.kind.clone(),
            });
        }
        Ok(row)
    }

    /// The **leaf** (hosted/proxy) members `self.principal` may read, flattened
    /// across nested groups in **descending priority** pre-order (the DAO orders
    /// each level `priority DESC`), each paired with its read ops.
    ///
    /// Nested groups are descended into (subject to `can_read` at every level);
    /// a leaf reachable by several paths is kept once, at its first (highest
    /// effective priority) sighting. The walk is bounded by a visited-set (group
    /// ids on the current path) and [`Self::max_depth`]; hitting either treats
    /// that subtree as empty (fail-closed) and logs, so a cycle injected by a
    /// raw DB write terminates rather than looping.
    async fn visible_members(&self, group: &str) -> Result<Vec<VisibleMember>, RepoError> {
        let group_row = self.group_row(group).await?;

        let mut out: Vec<VisibleMember> = Vec::new();
        let mut seen_leaves: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut visited: std::collections::HashSet<i64> = std::collections::HashSet::new();
        visited.insert(group_row.id);

        self.flatten_into(group_row.id, 0, &mut visited, &mut seen_leaves, &mut out)
            .await?;
        Ok(out)
    }

    /// Recursive worker for [`Self::visible_members`]. Walks `group_id`'s direct
    /// members (priority DESC); for each member the principal `can_read`:
    /// * a **group** member is descended into (cycle/depth-guarded);
    /// * a **leaf** member is appended (deduped by repo id).
    ///
    /// `visited` holds the group ids on the current descent path; `seen_leaves`
    /// dedups leaves across the whole flatten. Boxed future because the async fn
    /// is recursive.
    fn flatten_into<'a>(
        &'a self,
        group_id: i64,
        depth: u32,
        visited: &'a mut std::collections::HashSet<i64>,
        seen_leaves: &'a mut std::collections::HashSet<i64>,
        out: &'a mut Vec<VisibleMember>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RepoError>> + Send + 'a>>
    {
        Box::pin(async move {
            if depth >= self.max_depth {
                tracing::error!(
                    group_id,
                    depth,
                    max_depth = self.max_depth,
                    "group nesting depth bound hit; treating subtree as empty (fail-closed)"
                );
                return Ok(());
            }

            let members = repository_dao::group_members(&self.pool, group_id).await?;
            for (member, _priority) in members {
                // Identity filter at every level: skip members this principal
                // cannot read. Reading an outer group grants no transitive read.
                if !self.authz.can_read(&self.principal, &member).await {
                    continue;
                }

                if member.kind() == forge_db::model::RepoKind::Group {
                    // Cycle guard: a group already on the descent path is a
                    // back-edge — log and skip (fail-closed), never follow it.
                    if !visited.insert(member.id) {
                        tracing::error!(
                            cyclic_group_id = member.id,
                            "group membership cycle detected at resolve time; treating subtree as empty (fail-closed)"
                        );
                        continue;
                    }
                    self.flatten_into(member.id, depth + 1, visited, seen_leaves, out)
                        .await?;
                    // Pop off the path so a diamond (two paths to the same group
                    // via distinct parents) is still resolvable, while a true
                    // back-edge on the *current* path stays blocked.
                    visited.remove(&member.id);
                } else if seen_leaves.insert(member.id) {
                    let ops = self.factory.ops_for(&member)?;
                    out.push(VisibleMember { repo: member, ops });
                }
            }
            Ok(())
        })
    }
}

#[async_trait]
impl RepoReadOps for GroupRepo {
    async fn list_versions(&self, repo: &str, id: &str) -> Result<Vec<VersionEntry>, RepoError> {
        let members = self.visible_members(repo).await?;

        // Union across visible members, deduped by normalized version. Members
        // are highest-priority first, so the first sighting of a version wins
        // (its `original_id`/casing comes from the highest-priority member).
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut merged: Vec<VersionEntry> = Vec::new();
        for m in &members {
            for entry in m.ops.list_versions(&m.repo.name, id).await? {
                if seen.insert(entry.version.clone()) {
                    merged.push(entry);
                }
            }
        }
        // No `Format` here; sort by the version string. Callers that need
        // precedence ordering re-sort with the format (route layer); a stable
        // lexicographic order is enough for a deduped union and keeps this layer
        // format-agnostic.
        merged.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(merged)
    }

    async fn resolve_nupkg(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        let members = self.visible_members(repo).await?;
        // Highest-priority visible member that has the exact (id, version).
        for m in &members {
            if let Some(loc) = m.ops.resolve_nupkg(&m.repo.name, id, version).await? {
                return Ok(Some(loc));
            }
        }
        Ok(None)
    }

    async fn resolve_nuspec(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        let members = self.visible_members(repo).await?;
        for m in &members {
            if let Some(bytes) = m.ops.resolve_nuspec(&m.repo.name, id, version).await? {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    async fn registration(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        let members = self.visible_members(repo).await?;

        // Merge, dedup by version (id is fixed here), highest-priority wins.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut merged: Vec<RegistrationEntry> = Vec::new();
        for m in &members {
            for entry in m.ops.registration(&m.repo.name, id).await? {
                if seen.insert(entry.version.clone()) {
                    merged.push(entry);
                }
            }
        }
        merged.sort_by(|a, b| a.version.cmp(&b.version));
        Ok(merged)
    }

    async fn search(&self, repo: &str, params: &SearchParams) -> Result<SearchResult, RepoError> {
        let members = self.visible_members(repo).await?;

        // Merge hits across members, dedup by lowercased id, highest-priority
        // wins (first member that yields a hit for that id keeps its versions).
        // We request the full corpus from each member (skip=0, take=MAX) and
        // page the merged result ourselves, since paging cannot be pushed down
        // across independently-paged members.
        let mut member_params = params.clone();
        member_params.skip = 0;
        member_params.take = SearchParams::MAX_TAKE;

        use std::collections::BTreeMap;
        // BTreeMap keyed by lowercased id for a deterministic merged order.
        let mut by_id: BTreeMap<String, SearchHit> = BTreeMap::new();
        for m in &members {
            let result = m.ops.search(&m.repo.name, &member_params).await?;
            for hit in result.hits {
                by_id.entry(hit.original_id.to_lowercase()).or_insert(hit);
            }
        }

        let mut hits: Vec<SearchHit> = by_id.into_values().collect();
        hits.sort_by(|a, b| {
            a.original_id
                .to_lowercase()
                .cmp(&b.original_id.to_lowercase())
        });

        let total_hits = hits.len();
        let skip = params.skip.min(total_hits);
        let take = params.effective_take();
        let page = hits.into_iter().skip(skip).take(take).collect();
        Ok(SearchResult {
            total_hits,
            hits: page,
        })
    }
}
