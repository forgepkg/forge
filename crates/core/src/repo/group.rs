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
//!   Merged versions are ordered by the format's version precedence (so
//!   `1.10.0` sorts after `1.9.0`).
//! * **Prefer hosted** (group `config.prefer_hosted`, default on): once a
//!   package id exists (listed or not) in **any** hosted leaf reachable from
//!   the group, proxy members are not consulted for that id at all — for
//!   every caller. Ownership is decided over the whole membership DAG,
//!   independent of the caller's repo grants and package selectors: a caller
//!   who cannot see the hosted copy (an anonymous caller on a mixed-anonymity
//!   group, a selector-scoped token) gets the ordinary not-found answer, never
//!   the public substitute. Search drops proxy hits for owned ids the same
//!   way. An attacker publishing a same-named, higher-versioned package on a
//!   public feed therefore cannot shadow an internal package (dependency
//!   confusion). The check is one batched existence query over the hosted
//!   leaves; a failure of it fails the request (fail closed), and it reveals
//!   no more than the resulting 404 does.
//! * **Reserved prefixes** (group `config.reserved_prefixes`, e.g. `acme.`):
//!   ids under a reserved prefix never come from a proxy member, whether or
//!   not a hosted member has them yet — prefer-hosted alone cannot protect an
//!   internal name before its first publish (or after its last version is
//!   deleted).
//! * **Owner members** (`group_member.owner`): by default every hosted leaf
//!   owns ids for both guards above. Once a group flags at least one member,
//!   only the flagged members, and the hosted leaves inside a flagged nested
//!   group, do: only they hide proxy versions under prefer-hosted, and only
//!   they serve ids under a reserved prefix. Someone who can push to another
//!   hosted member (a scratch or developer feed in the same group) can then
//!   neither publish an internal name the group serves nor take a public id
//!   away from its proxy.
//! * **Degraded members** — a member that errors (e.g. an unreachable proxy
//!   upstream) is logged and skipped; the group still answers from the
//!   remaining members. Only when *every* consulted member fails does the
//!   group return an error, so a public-feed outage never breaks restores of
//!   internal packages.
//!
//! Groups are **read-only**. Since §12.4 Phase 4 a group member **may itself be
//! a group** (nested groups). Resolution first loads each readable group node
//! and edge once, then evaluates package-specific reachability over that compact
//! graph: the [`MemberOpsFactory`] is only ever asked for each selected leaf.
//! Two guards keep this safe even against a cycle injected by a raw DB write:
//!
//! * a **visited-set** (group ids already on the current descent) — a re-visit
//!   is treated as an empty subtree (fail-closed) and logged, never followed;
//! * a **depth bound** (`max_depth`, from `groups.max_nesting_depth`) — descent
//!   past it stops (fail-closed).
//!
//! Identity-aware filtering is applied at **every** level: a member (group or
//! leaf) is descended-into / included only if the principal [`can_read`] it
//! ([`Authz::can_read`]). The prefer-hosted ownership check above is the one
//! deliberate exception: it only ever *removes* proxy candidates, so it
//! consults every hosted leaf. Being able to read an outer group grants **no**
//! transitive read on an inner member — only a `read` grant on the actual leaf
//! repo does. Priority ordering (slice §7: higher wins ties) is preserved as a
//! stable pre-order walk. For a concrete package id, selectors are evaluated
//! while walking and a repeated group is expanded only when reached at a
//! strictly shallower depth. A repeated leaf is queried once at its first
//! package-visible sighting. Search also queries each unique leaf once and uses
//! the same package-specific walk to select the highest-priority winner.
//! Members answer search **unenriched** ([`RepoReadOps::search_unenriched`]);
//! the group merges, counts and pages their hits, then enriches only the final
//! page through the member that won each hit, so per-hit manifest reads are
//! bounded by the client's `take`, not by every member's result.
//!
//! ## Decoupling from concrete member kinds
//! `forge-core` must not hard-wire how a hosted vs. proxy member is constructed
//! (that needs the S3 client, the cache, the SSRF resolver — all server wiring).
//! [`GroupRepo`] therefore takes a [`MemberOpsFactory`]: given a member
//! [`Repository`] row it returns that member's [`RepoReadOps`]. The server
//! implements it by branching on [`Repository::kind`]; tests implement it with
//! an in-memory map.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use forge_db::model::{RepoKind, Repository};
use forge_db::{component_dao, repository_dao};
use sqlx::PgPool;

use crate::auth::authz::Authz;
use crate::auth::principal::Principal;
use crate::authz::PackageFilter;
use crate::format::Format;
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
    /// Version precedence for merged results. `None` ⇒ string order (tests).
    format: Option<Arc<dyn Format>>,
}

/// A visible member: its repository row (carrying its own `name`) and the ops to
/// read it, in descending priority order.
struct VisibleMember {
    repo: Repository,
    ops: Arc<dyn RepoReadOps>,
}

/// One readable edge in the compact group graph. The filter belongs to the
/// member repository itself; a package is reachable along a path only when
/// every edge filter on that path allows it.
#[derive(Debug, Clone)]
struct GraphMember {
    repo: Repository,
    filter: PackageFilter,
}

/// Readable group DAG for one request principal.
///
/// `groups` stores every reachable group adjacency list once, preserving each
/// list's priority order. `leaves` stores every readable leaf once. Package-id
/// walks are memoized because hosted/proxy search may evaluate the same id once
/// per version row.
#[derive(Debug)]
struct GroupGraph {
    root_id: i64,
    /// The requested group's `prefer_hosted` option.
    prefer_hosted: bool,
    /// The requested group's reserved id prefixes (lowercase).
    reserved_prefixes: Vec<String>,
    max_depth: u32,
    groups: HashMap<i64, Vec<GraphMember>>,
    leaves: Vec<Repository>,
    /// Every hosted leaf reachable from the root within the depth bound,
    /// **regardless of the principal**, that owns ids here (all of them unless
    /// the group flags owner members) — the owners the prefer-hosted guard
    /// consults ([`GroupRepo::hosted_owned_ids`]).
    hosted_leaf_ids: Vec<i64>,
    /// The leaves allowed to serve reserved ids: `None` when the group flags
    /// no owner member (every non-proxy leaf may).
    owner_leaf_ids: Option<HashSet<i64>>,
    visible_leaf_cache: Mutex<HashMap<String, Arc<VisibleLeaves>>>,
    cycle_logged: AtomicBool,
}

#[derive(Debug)]
struct VisibleLeaves {
    ordered: Vec<i64>,
    ranks: HashMap<i64, usize>,
}

impl GroupGraph {
    /// Whether the lowercase `id` falls under one of the group's reserved
    /// prefixes (never served from a proxy member).
    fn is_reserved(&self, lower_id: &str) -> bool {
        self.reserved_prefixes
            .iter()
            .any(|prefix| lower_id.starts_with(prefix.as_str()))
    }

    /// Whether `leaf` may serve an id under a reserved prefix: never a proxy,
    /// and only an owner when the group names owners.
    fn may_serve_reserved(&self, leaf: &Repository) -> bool {
        !is_proxy(leaf)
            && self
                .owner_leaf_ids
                .as_ref()
                .is_none_or(|owners| owners.contains(&leaf.id))
    }

    /// Visible leaf ids for `package_id`, in the same package-specific stable
    /// pre-order as the former path-expanding traversal.
    fn visible_leaves(&self, package_id: &str) -> Arc<VisibleLeaves> {
        let key = crate::format::lower_invariant(package_id);
        if let Some(cached) = self
            .visible_leaf_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .cloned()
        {
            return cached;
        }

        let mut path = HashSet::new();
        path.insert(self.root_id);
        let mut best_group_depth = HashMap::new();
        best_group_depth.insert(self.root_id, 0);
        let mut seen_leaves = HashSet::new();
        let mut out = Vec::new();
        self.walk_visible(
            self.root_id,
            0,
            &key,
            &mut path,
            &mut best_group_depth,
            &mut seen_leaves,
            &mut out,
        );

        let ranks = out
            .iter()
            .enumerate()
            .map(|(rank, leaf_id)| (*leaf_id, rank))
            .collect();
        let out = Arc::new(VisibleLeaves {
            ordered: out,
            ranks,
        });
        self.visible_leaf_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, out.clone());
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_visible(
        &self,
        group_id: i64,
        depth: u32,
        package_id: &str,
        path: &mut HashSet<i64>,
        best_group_depth: &mut HashMap<i64, u32>,
        seen_leaves: &mut HashSet<i64>,
        out: &mut Vec<i64>,
    ) {
        if depth >= self.max_depth {
            return;
        }

        let Some(members) = self.groups.get(&group_id) else {
            return;
        };
        for member in members {
            if !member.filter.allows(package_id) {
                continue;
            }

            if member.repo.kind() == RepoKind::Group {
                if path.contains(&member.repo.id) {
                    if !self.cycle_logged.swap(true, Ordering::Relaxed) {
                        tracing::error!(
                            cyclic_group_id = member.repo.id,
                            "group membership cycle detected at resolve time; treating subtree as empty (fail-closed)"
                        );
                    }
                    continue;
                }

                let next_depth = depth + 1;
                if best_group_depth
                    .get(&member.repo.id)
                    .is_some_and(|seen_depth| *seen_depth <= next_depth)
                {
                    continue;
                }
                best_group_depth.insert(member.repo.id, next_depth);
                path.insert(member.repo.id);
                self.walk_visible(
                    member.repo.id,
                    next_depth,
                    package_id,
                    path,
                    best_group_depth,
                    seen_leaves,
                    out,
                );
                path.remove(&member.repo.id);
            } else if seen_leaves.insert(member.repo.id) {
                out.push(member.repo.id);
            }
        }
    }

    fn leaf_rank(&self, package_id: &str, leaf_id: i64) -> Option<usize> {
        self.visible_leaves(package_id).ranks.get(&leaf_id).copied()
    }

    fn filter_for_leaf(self: &Arc<Self>, leaf_id: i64) -> PackageFilter {
        let graph = self.clone();
        PackageFilter::Predicate(Arc::new(move |package_id| {
            graph
                .visible_leaves(package_id)
                .ranks
                .contains_key(&leaf_id)
        }))
    }
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
            format: None,
        }
    }

    /// Order merged versions by `format`'s precedence instead of by string.
    pub fn with_format(mut self, format: Arc<dyn Format>) -> Self {
        self.format = Some(format);
        self
    }

    fn compare_versions(&self, a: &str, b: &str) -> std::cmp::Ordering {
        match &self.format {
            Some(format) => format.compare_versions(a, b),
            None => a.cmp(b),
        }
    }

    /// Resolve the group repository row by name, erroring if missing or not a
    /// group.
    async fn group_row(&self, repo: &str) -> Result<Repository, RepoError> {
        let row = repository_dao::find_repository_by_name(&self.pool, repo)
            .await?
            .ok_or_else(|| RepoError::RepoNotFound(repo.to_string()))?;
        if row.kind() != RepoKind::Group {
            return Err(RepoError::WrongKind {
                name: repo.to_string(),
                kind: row.kind.clone(),
            });
        }
        Ok(row)
    }

    /// Build the compact readable group graph for this principal.
    ///
    /// Two breadth-first passes over the membership DAG below `group`. Both
    /// reach every group at its minimum depth and respect the configured depth
    /// bound; a global discovery set bounds raw-DB cycles without discarding
    /// diamond edges (package-specific evaluation applies the current-path
    /// cycle guard later). Edges remain in DAO priority order.
    ///
    /// 1. **Structure**, independent of the principal: every group's adjacency
    ///    list is fetched once, following *every* edge, which also yields the
    ///    hosted leaves the prefer-hosted guard consults. A caller's grants
    ///    must not decide whether an internal id is shielded from the proxies.
    /// 2. **Visibility**: the same walk over the loaded adjacency lists, keeping
    ///    only edges whose member the principal may read.
    async fn group_graph(&self, group: &str) -> Result<Arc<GroupGraph>, RepoError> {
        let group_row = self.group_row(group).await?;

        // Pass 1. A group past the depth bound is not expanded: no caller can
        // be served from below it, so its leaves own nothing here either.
        let mut adjacency: HashMap<i64, Vec<Repository>> = HashMap::new();
        let mut hosted_leaf_ids = Vec::new();
        let mut seen_hosted = HashSet::new();
        let mut discovered_groups = HashSet::from([group_row.id]);
        let mut queue = VecDeque::from([(group_row.id, 0_u32)]);
        while let Some((group_id, depth)) = queue.pop_front() {
            if depth >= self.max_depth {
                continue;
            }
            let rows = repository_dao::group_members(&self.pool, group_id).await?;
            let mut members = Vec::with_capacity(rows.len());
            for (member, _priority) in rows {
                match member.kind() {
                    RepoKind::Group => {
                        if discovered_groups.insert(member.id) {
                            queue.push_back((member.id, depth + 1));
                        }
                    }
                    RepoKind::Hosted => {
                        if seen_hosted.insert(member.id) {
                            hosted_leaf_ids.push(member.id);
                        }
                    }
                    RepoKind::Proxy => {}
                }
                members.push(member);
            }
            adjacency.insert(group_id, members);
        }

        // Owner members: the hosted leaves reachable through a flagged member
        // of the requested group (within the same depth bound) own ids here.
        let flagged = repository_dao::group_owner_ids(&self.pool, group_row.id).await?;
        let owner_leaf_ids = if flagged.is_empty() {
            None
        } else {
            let mut owners = HashSet::new();
            let mut seen_groups = HashSet::new();
            let mut queue: VecDeque<(i64, u32)> = VecDeque::new();
            for member in adjacency
                .get(&group_row.id)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                if !flagged.contains(&member.id) {
                    continue;
                }
                match member.kind() {
                    RepoKind::Hosted => {
                        owners.insert(member.id);
                    }
                    RepoKind::Group => queue.push_back((member.id, 1)),
                    RepoKind::Proxy => {}
                }
            }
            while let Some((group_id, depth)) = queue.pop_front() {
                if depth >= self.max_depth || !seen_groups.insert(group_id) {
                    continue;
                }
                for member in adjacency
                    .get(&group_id)
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                {
                    match member.kind() {
                        RepoKind::Hosted => {
                            owners.insert(member.id);
                        }
                        RepoKind::Group => queue.push_back((member.id, depth + 1)),
                        RepoKind::Proxy => {}
                    }
                }
            }
            hosted_leaf_ids.retain(|id| owners.contains(id));
            Some(owners)
        };

        // Pass 2.
        let mut groups = HashMap::new();
        let mut leaves = Vec::new();
        let mut seen_leaves = HashSet::new();
        let mut discovered_groups = HashSet::from([group_row.id]);
        let mut queue = VecDeque::from([(group_row.id, 0_u32)]);
        while let Some((group_id, depth)) = queue.pop_front() {
            if depth >= self.max_depth {
                tracing::error!(
                    group_id,
                    depth,
                    max_depth = self.max_depth,
                    "group nesting depth bound hit; treating subtree as empty (fail-closed)"
                );
                groups.entry(group_id).or_insert_with(Vec::new);
                continue;
            }

            // Pass 1 reached this group no deeper than this pass does, so its
            // adjacency is loaded; a missing entry is treated as empty.
            let rows = adjacency
                .get(&group_id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let mut members = Vec::with_capacity(rows.len());
            for member in rows {
                // Reading an outer group grants no transitive read. An edge is
                // absent from this principal's graph unless the member itself
                // passes the repo-level gate.
                if !self.authz.can_read(&self.principal, member).await {
                    continue;
                }
                let filter = self.authz.package_filter(&self.principal, member).await;

                if member.kind() == RepoKind::Group {
                    if discovered_groups.insert(member.id) {
                        queue.push_back((member.id, depth + 1));
                    }
                } else if seen_leaves.insert(member.id) {
                    leaves.push(member.clone());
                }
                members.push(GraphMember {
                    repo: member.clone(),
                    filter,
                });
            }
            groups.insert(group_id, members);
        }

        Ok(Arc::new(GroupGraph {
            root_id: group_row.id,
            prefer_hosted: group_row.prefer_hosted(),
            reserved_prefixes: group_row.reserved_prefixes(),
            max_depth: self.max_depth,
            groups,
            leaves,
            hosted_leaf_ids,
            owner_leaf_ids,
            visible_leaf_cache: Mutex::new(HashMap::new()),
            cycle_logged: AtomicBool::new(false),
        }))
    }

    /// The format's canonical (stored) form of a package id — what
    /// `component.name` holds.
    fn lower_id(&self, id: &str) -> String {
        match &self.format {
            Some(format) => format.lower_id(id),
            None => crate::format::lower_invariant(id),
        }
    }

    /// The subset of `lower_ids` (canonical ids) owned by a hosted leaf of the
    /// group: present there in any version, listed or not.
    ///
    /// Decided over **every** hosted leaf reachable from the group
    /// ([`GroupGraph::hosted_leaf_ids`]), independent of the principal's repo
    /// grants and package selectors, in one batched existence query. An error
    /// propagates: deciding without it could expose an internal id to a
    /// public-feed shadow (fail closed).
    async fn hosted_owned_ids(
        &self,
        graph: &GroupGraph,
        lower_ids: &[String],
    ) -> Result<HashSet<String>, RepoError> {
        if graph.hosted_leaf_ids.is_empty() || lower_ids.is_empty() {
            return Ok(HashSet::new());
        }
        Ok(component_dao::names_present_in_repositories(
            &self.pool,
            &graph.hosted_leaf_ids,
            lower_ids,
        )
        .await?
        .into_iter()
        .collect())
    }

    /// Construct each package-visible leaf once, in package-specific priority
    /// order. The requested root repository's filter remains the caller's outer
    /// [`crate::repo::PackageFilteredReadOps`] responsibility.
    fn visible_members_for_id(
        &self,
        graph: &GroupGraph,
        package_id: &str,
    ) -> Result<Vec<VisibleMember>, RepoError> {
        let mut out = Vec::new();
        for leaf_id in &graph.visible_leaves(package_id).ordered {
            let Some(repo) = graph.leaves.iter().find(|repo| repo.id == *leaf_id) else {
                continue;
            };
            out.push(VisibleMember {
                repo: repo.clone(),
                ops: self.factory.ops_for(repo)?,
            });
        }
        Ok(out)
    }

    /// The members allowed to serve `package_id`: for an id under a reserved
    /// prefix only the members that may serve it
    /// ([`GroupGraph::may_serve_reserved`]); otherwise the visible members,
    /// minus every proxy member when the group prefers hosted packages and
    /// **any** owning hosted leaf of the group has the id
    /// ([`Self::hosted_owned_ids`]) — whether or not this principal can see
    /// that leaf. A caller who cannot is then left with no serving member and
    /// gets the ordinary not-found answer. A lookup failure propagates (fail
    /// closed).
    async fn serving_members_for_id(
        &self,
        graph: &GroupGraph,
        package_id: &str,
    ) -> Result<Vec<VisibleMember>, RepoError> {
        let members = self.visible_members_for_id(graph, package_id)?;
        let lower = self.lower_id(package_id);
        if graph.is_reserved(&lower) {
            return Ok(members
                .into_iter()
                .filter(|m| graph.may_serve_reserved(&m.repo))
                .collect());
        }
        if !members.iter().any(|m| is_proxy(&m.repo)) {
            return Ok(members);
        }
        let hosted_only =
            graph.prefer_hosted && !self.hosted_owned_ids(graph, &[lower]).await?.is_empty();
        if !hosted_only {
            return Ok(members);
        }
        Ok(members.into_iter().filter(|m| !is_proxy(&m.repo)).collect())
    }

    /// Merge member search results with the caller's package predicate pushed
    /// through every member wrapper. This keeps selector filtering inside each
    /// production backend's single corpus scan rather than repeatedly
    /// re-running the whole group search for successive filtered pages.
    ///
    /// Members answer unenriched; only the merged, paged result is enriched
    /// ([`Self::enrich_page`]).
    async fn search_filtered(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        let graph = self.group_graph(repo).await?;
        let mut member_params = params.clone();
        member_params.skip = 0;
        member_params.take = SearchParams::MAX_TAKE;

        // `member_ops[i]` reads `graph.leaves[i]`.
        let mut member_ops: Vec<Arc<dyn RepoReadOps>> = Vec::with_capacity(graph.leaves.len());
        let mut by_id: BTreeMap<String, RankedHit> = BTreeMap::new();
        let mut proxy_hits: Vec<RankedHit> = Vec::new();
        let mut failures = MemberFailures::default();
        for (member, leaf) in graph.leaves.iter().enumerate() {
            let ops = self.factory.ops_for(leaf)?;
            member_ops.push(ops.clone());
            let leaf_filter = graph.filter_for_leaf(leaf.id).intersect(filter.clone());
            let result = match ops
                .search_unenriched(&leaf.name, &member_params, &leaf_filter)
                .await
            {
                Ok(result) => {
                    failures.ok();
                    result
                }
                Err(e) => {
                    failures.failed(&leaf.name, e);
                    continue;
                }
            };
            for hit in result.hits {
                let Some(rank) = graph.leaf_rank(&hit.original_id, leaf.id) else {
                    continue;
                };
                let ranked = RankedHit { rank, member, hit };
                if graph.is_reserved(&self.lower_id(&ranked.hit.original_id))
                    && !graph.may_serve_reserved(leaf)
                {
                    continue;
                }
                if is_proxy(leaf) && graph.prefer_hosted {
                    // Decided below against every owning hosted leaf of the group.
                    proxy_hits.push(ranked);
                    continue;
                }
                insert_ranked(&mut by_id, ranked);
            }
        }
        failures.into_result()?;
        if !proxy_hits.is_empty() {
            let candidates: Vec<String> = proxy_hits
                .iter()
                .map(|ranked| self.lower_id(&ranked.hit.original_id))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let owned = self.hosted_owned_ids(&graph, &candidates).await?;
            for ranked in proxy_hits {
                if !owned.contains(&self.lower_id(&ranked.hit.original_id)) {
                    insert_ranked(&mut by_id, ranked);
                }
            }
        }

        let mut ranked: Vec<RankedHit> = by_id.into_values().collect();
        ranked.sort_by(|a, b| {
            crate::format::lower_invariant(&a.hit.original_id)
                .cmp(&crate::format::lower_invariant(&b.hit.original_id))
        });
        let total_hits = ranked.len();
        let page: Vec<RankedHit> = ranked
            .into_iter()
            .skip(params.skip.min(total_hits))
            .take(params.effective_take())
            .collect();
        let hits = self.enrich_page(&graph, &member_ops, page).await;
        Ok(SearchResult { total_hits, hits })
    }

    /// Enrich the final search page: each hit through the member that won it,
    /// one batch per member. Members run one after another, each bounding its
    /// own concurrency. A member whose enrichment fails leaves its hits without
    /// metadata rather than failing the search — the same degraded answer as a
    /// failed manifest read; which packages are listed never depends on it.
    async fn enrich_page(
        &self,
        graph: &GroupGraph,
        member_ops: &[Arc<dyn RepoReadOps>],
        page: Vec<RankedHit>,
    ) -> Vec<SearchHit> {
        let mut positions_by_member: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (position, ranked) in page.iter().enumerate() {
            positions_by_member
                .entry(ranked.member)
                .or_default()
                .push(position);
        }
        let mut hits: Vec<SearchHit> = page.into_iter().map(|ranked| ranked.hit).collect();
        for (member, positions) in positions_by_member {
            let leaf = &graph.leaves[member];
            let mut batch: Vec<SearchHit> = positions
                .iter()
                .map(|&position| std::mem::take(&mut hits[position]))
                .collect();
            if let Err(e) = member_ops[member]
                .enrich_search_hits(&leaf.name, &mut batch)
                .await
            {
                tracing::warn!(member = %leaf.name, error = %e, "group search: enriching member hits failed; serving them without metadata");
            }
            for (position, hit) in positions.into_iter().zip(batch) {
                hits[position] = hit;
            }
        }
        hits
    }
}

#[async_trait]
impl RepoReadOps for GroupRepo {
    async fn list_versions(&self, repo: &str, id: &str) -> Result<Vec<VersionEntry>, RepoError> {
        let graph = self.group_graph(repo).await?;
        let members = self.serving_members_for_id(&graph, id).await?;

        // Union across serving members, deduped by normalized version. Members
        // are highest-priority first, so the first sighting of a version wins
        // (its `original_id`/casing comes from the highest-priority member).
        let mut seen: HashSet<String> = HashSet::new();
        let mut merged: Vec<VersionEntry> = Vec::new();
        let mut failures = MemberFailures::default();
        for m in &members {
            match m.ops.list_versions(&m.repo.name, id).await {
                Ok(entries) => {
                    failures.ok();
                    for entry in entries {
                        if seen.insert(entry.version.clone()) {
                            merged.push(entry);
                        }
                    }
                }
                Err(e) => failures.failed(&m.repo.name, e),
            }
        }
        failures.into_result()?;
        merged.sort_by(|a, b| self.compare_versions(&a.version, &b.version));
        Ok(merged)
    }

    async fn resolve_nupkg(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        let graph = self.group_graph(repo).await?;
        let members = self.serving_members_for_id(&graph, id).await?;
        // Highest-priority serving member that has the exact (id, version).
        let mut failures = MemberFailures::default();
        for m in &members {
            match m.ops.resolve_nupkg(&m.repo.name, id, version).await {
                Ok(Some(loc)) => return Ok(Some(loc)),
                Ok(None) => failures.ok(),
                Err(e) => failures.failed(&m.repo.name, e),
            }
        }
        // Not found anywhere reachable: a member failure means "unknown", not
        // "absent" — report it so clients retry instead of caching a miss.
        failures.into_strict_result()?;
        Ok(None)
    }

    async fn resolve_nuspec(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        let graph = self.group_graph(repo).await?;
        let members = self.serving_members_for_id(&graph, id).await?;
        let mut failures = MemberFailures::default();
        for m in &members {
            match m.ops.resolve_nuspec(&m.repo.name, id, version).await {
                Ok(Some(bytes)) => return Ok(Some(bytes)),
                Ok(None) => failures.ok(),
                Err(e) => failures.failed(&m.repo.name, e),
            }
        }
        failures.into_strict_result()?;
        Ok(None)
    }

    async fn registration(
        &self,
        repo: &str,
        id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        let graph = self.group_graph(repo).await?;
        let members = self.serving_members_for_id(&graph, id).await?;

        // Merge, dedup by version (id is fixed here), highest-priority wins.
        let mut seen: HashSet<String> = HashSet::new();
        let mut merged: Vec<RegistrationEntry> = Vec::new();
        let mut failures = MemberFailures::default();
        for m in &members {
            match m.ops.registration(&m.repo.name, id).await {
                Ok(entries) => {
                    failures.ok();
                    for entry in entries {
                        if seen.insert(entry.version.clone()) {
                            merged.push(entry);
                        }
                    }
                }
                Err(e) => failures.failed(&m.repo.name, e),
            }
        }
        failures.into_result()?;
        merged.sort_by(|a, b| self.compare_versions(&a.version, &b.version));
        Ok(merged)
    }

    async fn search(&self, repo: &str, params: &SearchParams) -> Result<SearchResult, RepoError> {
        self.search_filtered(repo, params, &PackageFilter::AllowAll)
            .await
    }

    async fn search_with_package_filter(
        &self,
        repo: &str,
        params: &SearchParams,
        filter: &PackageFilter,
    ) -> Result<SearchResult, RepoError> {
        self.search_filtered(repo, params, filter).await
    }
}

fn is_proxy(repo: &Repository) -> bool {
    repo.kind() == RepoKind::Proxy
}

/// A merged search hit: its package-specific priority `rank` (lower wins) and
/// the index into [`GroupGraph::leaves`] of the `member` that produced it,
/// which later enriches it.
struct RankedHit {
    rank: usize,
    member: usize,
    hit: SearchHit,
}

/// Keep the highest-priority (lowest rank) hit per package id.
fn insert_ranked(by_id: &mut BTreeMap<String, RankedHit>, ranked: RankedHit) {
    match by_id.entry(crate::format::lower_invariant(&ranked.hit.original_id)) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(ranked);
        }
        std::collections::btree_map::Entry::Occupied(mut entry)
            if ranked.rank < entry.get().rank =>
        {
            entry.insert(ranked);
        }
        std::collections::btree_map::Entry::Occupied(_) => {}
    }
}

/// Tracks member outcomes for one group operation: failing members are
/// logged and skipped while at least one member answered.
#[derive(Default)]
struct MemberFailures {
    succeeded: usize,
    last_error: Option<RepoError>,
}

impl MemberFailures {
    fn ok(&mut self) {
        self.succeeded += 1;
    }

    fn failed(&mut self, member: &str, error: RepoError) {
        tracing::warn!(member, error = %error, "group member failed; continuing with the remaining members");
        self.last_error = Some(error);
    }

    /// Error only when members were consulted and **none** answered.
    fn into_result(self) -> Result<(), RepoError> {
        match (self.succeeded, self.last_error) {
            (0, Some(error)) => Err(error),
            _ => Ok(()),
        }
    }

    /// Error when **any** member failed — for lookups whose miss is only
    /// authoritative if every member answered.
    fn into_strict_result(self) -> Result<(), RepoError> {
        match self.last_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
