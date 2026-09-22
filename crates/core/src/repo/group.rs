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
//!   package id exists in a visible hosted member, proxy members are not
//!   consulted for that id at all. An attacker publishing a same-named,
//!   higher-versioned package on a public feed therefore cannot shadow an
//!   internal package (dependency confusion).
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
//! ([`Authz::can_read`]). Being able to read an outer group grants **no**
//! transitive read on an inner member — only a `read` grant on the actual leaf
//! repo does. Priority ordering (slice §7: higher wins ties) is preserved as a
//! stable pre-order walk. For a concrete package id, selectors are evaluated
//! while walking and a repeated group is expanded only when reached at a
//! strictly shallower depth. A repeated leaf is queried once at its first
//! package-visible sighting. Search also queries each unique leaf once and uses
//! the same package-specific walk to select the highest-priority winner.
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
use forge_db::model::Repository;
use forge_db::repository_dao;
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
    max_depth: u32,
    groups: HashMap<i64, Vec<GraphMember>>,
    leaves: Vec<Repository>,
    visible_leaf_cache: Mutex<HashMap<String, Arc<VisibleLeaves>>>,
    cycle_logged: AtomicBool,
}

#[derive(Debug)]
struct VisibleLeaves {
    ordered: Vec<i64>,
    ranks: HashMap<i64, usize>,
}

impl GroupGraph {
    /// Visible leaf ids for `package_id`, in the same package-specific stable
    /// pre-order as the former path-expanding traversal.
    fn visible_leaves(&self, package_id: &str) -> Arc<VisibleLeaves> {
        let key = package_id.to_lowercase();
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

            if member.repo.kind() == forge_db::model::RepoKind::Group {
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
        if row.kind() != forge_db::model::RepoKind::Group {
            return Err(RepoError::WrongKind {
                name: repo.to_string(),
                kind: row.kind.clone(),
            });
        }
        Ok(row)
    }

    /// Build the compact readable group graph for this principal.
    ///
    /// Breadth-first discovery reaches every group at its minimum depth, so its
    /// adjacency list is fetched once while still respecting the configured
    /// depth bound. Edges remain in DAO priority order. A global discovery set
    /// bounds raw-DB cycles without discarding diamond edges; package-specific
    /// evaluation applies the current-path cycle guard later.
    async fn group_graph(&self, group: &str) -> Result<Arc<GroupGraph>, RepoError> {
        let group_row = self.group_row(group).await?;
        let mut groups = HashMap::new();
        let mut leaves = Vec::new();
        let mut seen_leaves = HashSet::new();
        let mut discovered_groups = HashSet::new();
        let mut queue = VecDeque::new();
        discovered_groups.insert(group_row.id);
        queue.push_back((group_row.id, 0_u32));

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

            let rows = repository_dao::group_members(&self.pool, group_id).await?;
            let mut members = Vec::with_capacity(rows.len());
            for (member, _priority) in rows {
                // Reading an outer group grants no transitive read. An edge is
                // absent from this principal's graph unless the member itself
                // passes the repo-level gate.
                if !self.authz.can_read(&self.principal, &member).await {
                    continue;
                }
                let filter = self.authz.package_filter(&self.principal, &member).await;

                if member.kind() == forge_db::model::RepoKind::Group {
                    if discovered_groups.insert(member.id) {
                        queue.push_back((member.id, depth + 1));
                    }
                } else if seen_leaves.insert(member.id) {
                    leaves.push(member.clone());
                }
                members.push(GraphMember {
                    repo: member,
                    filter,
                });
            }
            groups.insert(group_id, members);
        }

        Ok(Arc::new(GroupGraph {
            root_id: group_row.id,
            prefer_hosted: group_row.prefer_hosted(),
            max_depth: self.max_depth,
            groups,
            leaves,
            visible_leaf_cache: Mutex::new(HashMap::new()),
            cycle_logged: AtomicBool::new(false),
        }))
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

    /// The members allowed to serve `package_id`: the visible members, minus
    /// every proxy member when the group prefers hosted packages and a visible
    /// hosted member already has the id (listed or not). A hosted lookup
    /// failure propagates — deciding without it could expose the id to a
    /// public-feed shadow (fail closed).
    async fn serving_members_for_id(
        &self,
        graph: &GroupGraph,
        package_id: &str,
    ) -> Result<Vec<VisibleMember>, RepoError> {
        let members = self.visible_members_for_id(graph, package_id)?;
        if !graph.prefer_hosted || !members.iter().any(|m| is_proxy(&m.repo)) {
            return Ok(members);
        }
        for m in members.iter().filter(|m| is_hosted(&m.repo)) {
            if !m
                .ops
                .list_versions(&m.repo.name, package_id)
                .await?
                .is_empty()
            {
                return Ok(members.into_iter().filter(|m| !is_proxy(&m.repo)).collect());
            }
        }
        Ok(members)
    }

    /// Merge member search results with the caller's package predicate pushed
    /// through every member wrapper. This keeps selector filtering inside each
    /// production backend's single corpus scan rather than repeatedly
    /// re-running the whole group search for successive filtered pages.
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

        let mut by_id: BTreeMap<String, (usize, SearchHit)> = BTreeMap::new();
        let mut hosted_ids: HashSet<String> = HashSet::new();
        let mut proxy_hits: Vec<(usize, SearchHit)> = Vec::new();
        let mut failures = MemberFailures::default();
        for leaf in &graph.leaves {
            let ops = self.factory.ops_for(leaf)?;
            let leaf_filter = graph.filter_for_leaf(leaf.id).intersect(filter.clone());
            let result = match ops
                .search_with_package_filter(&leaf.name, &member_params, &leaf_filter)
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
                if graph.prefer_hosted {
                    if is_hosted(leaf) {
                        hosted_ids.insert(hit.original_id.to_lowercase());
                    } else if is_proxy(leaf) {
                        // Decided once every hosted leaf has answered.
                        proxy_hits.push((rank, hit));
                        continue;
                    }
                }
                insert_ranked(&mut by_id, rank, hit);
            }
        }
        failures.into_result()?;
        for (rank, hit) in proxy_hits {
            if !hosted_ids.contains(&hit.original_id.to_lowercase()) {
                insert_ranked(&mut by_id, rank, hit);
            }
        }

        let mut hits: Vec<SearchHit> = by_id.into_values().map(|(_, hit)| hit).collect();
        hits.sort_by(|a, b| {
            a.original_id
                .to_lowercase()
                .cmp(&b.original_id.to_lowercase())
        });
        let total_hits = hits.len();
        let hits = hits
            .into_iter()
            .skip(params.skip.min(total_hits))
            .take(params.effective_take())
            .collect();
        Ok(SearchResult { total_hits, hits })
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

fn is_hosted(repo: &Repository) -> bool {
    repo.kind() == forge_db::model::RepoKind::Hosted
}

fn is_proxy(repo: &Repository) -> bool {
    repo.kind() == forge_db::model::RepoKind::Proxy
}

/// Keep the highest-priority (lowest rank) hit per package id.
fn insert_ranked(by_id: &mut BTreeMap<String, (usize, SearchHit)>, rank: usize, hit: SearchHit) {
    match by_id.entry(hit.original_id.to_lowercase()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert((rank, hit));
        }
        std::collections::btree_map::Entry::Occupied(mut entry) if rank < entry.get().0 => {
            entry.insert((rank, hit));
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
