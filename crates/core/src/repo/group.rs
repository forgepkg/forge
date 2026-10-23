//! Group-repository read resolution.
//!
//! A **group** repository has no storage of its own: it federates reads across
//! an ordered list of **member** repositories (hosted or proxy). Members carry a
//! per-group `priority` (unique within the group); the highest priority wins
//! ties. Resolution is **identity-aware**: for a calling [`Principal`] `P`, only
//! members `P` may read (per [`authz::can_read`]) are visible. In particular a
//! mixed-anonymity group serves an anonymous caller only its `anonymous_read`
//! members, while an authenticated caller sees them all.
//!
//! Semantics:
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
//!   package id exists (listed or not) in **any** owning hosted leaf reachable
//!   from the group, proxy members are not consulted for that id at all — for
//!   every caller. Ownership is decided over the whole membership DAG,
//!   independent of the caller's repo grants and package selectors: a caller
//!   who cannot see the hosted copy (an anonymous caller on a mixed-anonymity
//!   group, a selector-scoped token) gets the ordinary not-found answer, never
//!   the public substitute. Search drops proxy hits for owned ids the same
//!   way. An attacker publishing a same-named, higher-versioned package on a
//!   public feed therefore cannot shadow an internal package (dependency
//!   confusion). The check is one batched existence query over the hosted
//!   leaves; a failure of it fails the request (fail closed). The 404 does
//!   tell such a caller that an id the upstream has also exists in a hosted
//!   leaf it cannot read (a documented limitation: the guard cannot both
//!   withhold the public package and look absent).
//! * **Reserved prefixes** (group `config.reserved_prefixes`, e.g. `acme.`):
//!   ids under a reserved prefix never come from a proxy member, whether or
//!   not a hosted member has them yet — prefer-hosted alone cannot protect an
//!   internal name before its first publish (or after its last version is
//!   deleted).
//! * **Owner members** (`group_member.owner`): by default every hosted leaf
//!   owns ids for both guards above. Once a group flags at least one member,
//!   only the flagged members, and the owners of a flagged nested group, do.
//!   A nested group's owners are its own: its flagged members, or every
//!   hosted leaf below it when it flags none. Under prefer-hosted, an id an owner has is then served by
//!   the owners alone: neither a proxy nor another hosted member adds
//!   versions to it. Only owners serve ids under a reserved prefix. Someone
//!   who can push to another hosted member (a scratch or developer feed in
//!   the same group) can then neither publish an internal name the group
//!   serves, nor add a version to an owner's package, nor take a public id
//!   away from its proxy.
//! * **Nested groups keep their guards**: every group on the way from the
//!   requested group to a leaf applies its own prefer-hosted setting,
//!   reserved prefixes and owners to what its members serve. Reading an inner
//!   group through an outer one is therefore never less protective than
//!   reading it directly, whatever the outer group's settings. A leaf reached
//!   along several paths serves an id if one visible path admits it, also
//!   when another path to the same inner group is guarded.
//! * **Degraded members** — a member that errors (e.g. an unreachable proxy
//!   upstream) is logged and skipped; the group still answers from the
//!   remaining members, so a public-feed outage never breaks restores of
//!   internal packages. A miss is only authoritative if every consulted
//!   member answered: when a member failed and the answer would be empty (no
//!   versions, no registration, no such exact version), the group returns the
//!   error, so clients and downstream proxies retry rather than cache a
//!   not-found. Search errors only when *every* member fails. An offline
//!   hosted member and an offline nested group are such failing members: the
//!   group serves nothing through them (an offline nested group is not
//!   descended into), while an offline proxy still serves what it cached.
//!
//! Groups are **read-only**. A group member **may itself be a group** (nested
//! groups). Resolution first loads each readable group node
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
//! repo does. Priority ordering (higher wins ties) is preserved as a
//! stable pre-order walk. For a concrete package id, selectors are evaluated
//! while walking and a repeated group is expanded only when reached at a
//! strictly shallower depth or under other active guards. A repeated leaf is queried once at its first
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
    /// Construct the read ops for a leaf `member` (hosted or proxy). Nested
    /// groups are walked by the resolver itself and never reach the factory, so
    /// implementations should reject a group member (kind == "group").
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
    max_depth: u32,
    groups: HashMap<i64, Vec<GraphMember>>,
    leaves: Vec<Repository>,
    /// The dependency-confusion guard of every group reachable from the root
    /// within the depth bound, decided **regardless of the principal**.
    guards: HashMap<i64, GroupGuard>,
    visible_leaf_cache: Mutex<HashMap<String, Arc<VisibleLeaves>>>,
    cycle_logged: AtomicBool,
}

/// One group's dependency-confusion guard: its own options and owners.
#[derive(Debug)]
struct GroupGuard {
    /// The group's `prefer_hosted` option.
    prefer_hosted: bool,
    /// The group's reserved id prefixes (lowercase).
    reserved_prefixes: Vec<String>,
    /// The hosted leaves that own ids in this group: the flagged hosted
    /// members and the owners of flagged nested groups, or every hosted leaf
    /// below the group (nested groups contributing their own owners) when it
    /// flags no member. Proxies never own ids.
    owners: HashSet<i64>,
}

impl GroupGuard {
    /// Whether the lowercase `id` falls under one of the group's reserved
    /// prefixes (only owners serve it).
    fn is_reserved(&self, lower_id: &str) -> bool {
        self.reserved_prefixes
            .iter()
            .any(|prefix| lower_id.starts_with(prefix.as_str()))
    }
}

/// The guard state of one package id for [`GroupGraph::serving_leaves`].
struct IdGuards<'a> {
    /// The id, lowercase.
    lower_id: &'a str,
    /// The prefer-hosted groups one of whose owners has the id.
    owned_in: &'a HashSet<i64>,
}

#[derive(Debug)]
struct VisibleLeaves {
    ordered: Vec<i64>,
    ranks: HashMap<i64, usize>,
}

impl GroupGraph {
    /// Whether `group_id`'s guard restricts `id` to the group's owners: the id
    /// is under one of its reserved prefixes, or the group prefers hosted
    /// packages and one of its owners has the id.
    fn guard_active(&self, group_id: i64, id: &IdGuards<'_>) -> Option<&HashSet<i64>> {
        let guard = self.guards.get(&group_id)?;
        (guard.is_reserved(id.lower_id) || (guard.prefer_hosted && id.owned_in.contains(&group_id)))
            .then_some(&guard.owners)
    }

    /// Whether a prefer-hosted group could take `leaf` out for an id its
    /// owners have, i.e. whether serving it needs the ownership lookup.
    fn may_yield(&self, leaf_id: i64) -> bool {
        self.guards
            .values()
            .any(|guard| guard.prefer_hosted && !guard.owners.contains(&leaf_id))
    }

    /// The prefer-hosted groups whose owners have the id, given the hosted
    /// leaves that have it.
    fn owned_in(&self, having: &HashSet<i64>) -> HashSet<i64> {
        self.guards
            .iter()
            .filter(|(_, guard)| {
                guard.prefer_hosted && guard.owners.iter().any(|leaf| having.contains(leaf))
            })
            .map(|(group_id, _)| *group_id)
            .collect()
    }

    /// Every owning hosted leaf of a prefer-hosted group: what the ownership
    /// lookup has to consult.
    fn prefer_hosted_owners(&self) -> Vec<i64> {
        let mut owners: Vec<i64> = self
            .guards
            .values()
            .filter(|guard| guard.prefer_hosted)
            .flat_map(|guard| guard.owners.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        owners.sort_unstable();
        owners
    }

    /// The leaves that serve `package_id`, in priority order: the visible
    /// leaves ([`Self::visible_leaves`]) that every group on their way from the
    /// root lets through. A group whose guard is active for the id
    /// ([`Self::guard_active`]) lets through only its owners.
    fn serving_leaves(&self, package_id: &str, id: &IdGuards<'_>) -> Vec<i64> {
        let key = crate::format::lower_invariant(package_id);
        let mut path = HashSet::from([self.root_id]);
        let mut best_group_depth = HashMap::from([((self.root_id, Vec::new()), 0)]);
        let mut seen_leaves = HashSet::new();
        let mut out = Vec::new();
        self.walk_visible(
            self.root_id,
            0,
            &key,
            Some(id),
            &mut Vec::new(),
            &mut path,
            &mut best_group_depth,
            &mut seen_leaves,
            &mut out,
        );
        out
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
        best_group_depth.insert((self.root_id, Vec::new()), 0);
        let mut seen_leaves = HashSet::new();
        let mut out = Vec::new();
        self.walk_visible(
            self.root_id,
            0,
            &key,
            None,
            &mut Vec::new(),
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

    /// Pre-order walk of the visible leaves below `group_id`. With `guards`,
    /// a leaf is only emitted if the owner set of every group on the path
    /// whose guard is active for the id (`required`, by group id) contains
    /// it; a leaf left out is not marked seen, so another path may still
    /// admit it. For the same reason a group already walked is walked again
    /// when reached under other active guards: a diamond's unguarded path
    /// must not be skipped because a guarded one reached the group first. An
    /// offline nested group is emitted as a leaf whatever the guards: it
    /// serves nothing, it only makes a miss non-authoritative.
    #[allow(clippy::too_many_arguments)]
    fn walk_visible<'g>(
        &'g self,
        group_id: i64,
        depth: u32,
        package_id: &str,
        guards: Option<&IdGuards<'_>>,
        required: &mut Vec<(i64, &'g HashSet<i64>)>,
        path: &mut HashSet<i64>,
        best_group_depth: &mut HashMap<(i64, Vec<i64>), u32>,
        seen_leaves: &mut HashSet<i64>,
        out: &mut Vec<i64>,
    ) {
        if depth >= self.max_depth {
            return;
        }

        let Some(members) = self.groups.get(&group_id) else {
            return;
        };
        let active = guards.and_then(|id| self.guard_active(group_id, id));
        if let Some(owners) = active {
            required.push((group_id, owners));
        }
        for member in members {
            if !member.filter.allows(package_id) {
                continue;
            }

            if is_descended_group(&member.repo) {
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
                let mut guarded_by: Vec<i64> = required.iter().map(|(id, _)| *id).collect();
                guarded_by.sort_unstable();
                let visit = (member.repo.id, guarded_by);
                if best_group_depth
                    .get(&visit)
                    .is_some_and(|seen_depth| *seen_depth <= next_depth)
                {
                    continue;
                }
                best_group_depth.insert(visit, next_depth);
                path.insert(member.repo.id);
                self.walk_visible(
                    member.repo.id,
                    next_depth,
                    package_id,
                    guards,
                    required,
                    path,
                    best_group_depth,
                    seen_leaves,
                    out,
                );
                path.remove(&member.repo.id);
            } else if (member.repo.kind() == RepoKind::Group
                || required
                    .iter()
                    .all(|(_, owners)| owners.contains(&member.repo.id)))
                && seen_leaves.insert(member.repo.id)
            {
                out.push(member.repo.id);
            }
        }
        if active.is_some() {
            required.pop();
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
        let mut flagged: HashMap<i64, HashSet<i64>> = HashMap::new();
        let mut group_rows: HashMap<i64, Repository> =
            HashMap::from([(group_row.id, group_row.clone())]);
        let mut queue = VecDeque::from([(group_row.id, 0_u32)]);
        while let Some((group_id, depth)) = queue.pop_front() {
            if depth >= self.max_depth {
                continue;
            }
            let rows = repository_dao::group_members(&self.pool, group_id).await?;
            let mut members = Vec::with_capacity(rows.len());
            for (member, _priority) in rows {
                if member.kind() == RepoKind::Group && !group_rows.contains_key(&member.id) {
                    group_rows.insert(member.id, member.clone());
                    queue.push_back((member.id, depth + 1));
                }
                members.push(member);
            }
            adjacency.insert(group_id, members);
            let owners = repository_dao::group_owner_ids(&self.pool, group_id).await?;
            flagged.insert(group_id, owners.into_iter().collect());
        }

        // Every group's own guard. Its owners are decided over the whole
        // structure, never the caller's grants: a caller's grants must not
        // decide whether an internal id is shielded from the proxies.
        let mut owner_sets: HashMap<i64, HashSet<i64>> = HashMap::new();
        let guards = group_rows
            .iter()
            .filter(|(group_id, _)| adjacency.contains_key(group_id))
            .map(|(group_id, row)| {
                let owners = group_owners(
                    *group_id,
                    &adjacency,
                    &flagged,
                    &mut owner_sets,
                    &mut HashSet::new(),
                );
                (
                    *group_id,
                    GroupGuard {
                        prefer_hosted: row.prefer_hosted(),
                        reserved_prefixes: row.reserved_prefixes(),
                        owners,
                    },
                )
            })
            .collect();

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

                // An offline nested group is not descended into: it stands
                // in the graph as one failing member, like an offline hosted
                // one, so nothing below it is served through this group.
                if is_descended_group(member) {
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
            max_depth: self.max_depth,
            groups,
            leaves,
            guards,
            visible_leaf_cache: Mutex::new(HashMap::new()),
            cycle_logged: AtomicBool::new(false),
        }))
    }

    /// The read ops of `member`: an offline hosted member, or an offline
    /// nested group (which the graph does not descend into), fails every read
    /// ([`OfflineMember`]); an offline proxy still serves what it cached.
    fn member_ops(&self, member: &Repository) -> Result<Arc<dyn RepoReadOps>, RepoError> {
        if is_offline_member(member) {
            return Ok(Arc::new(OfflineMember(member.name.clone())));
        }
        self.factory.ops_for(member)
    }

    /// The format's canonical (stored) form of a package id — what
    /// `component.name` holds.
    fn lower_id(&self, id: &str) -> String {
        match &self.format {
            Some(format) => format.lower_id(id),
            None => crate::format::lower_invariant(id),
        }
    }

    /// For each of `lower_ids` (canonical ids), the prefer-hosted groups of
    /// the graph one of whose owners has it (present there in any version,
    /// listed or not); ids no such owner has are absent.
    ///
    /// Decided over the owners of every group in the graph
    /// ([`GroupGuard::owners`]), independent of the principal's repo grants
    /// and package selectors, in one batched existence query. An error
    /// propagates: deciding without it could expose an internal id to a
    /// public-feed shadow (fail closed).
    async fn owned_in(
        &self,
        graph: &GroupGraph,
        lower_ids: &[String],
    ) -> Result<HashMap<String, HashSet<i64>>, RepoError> {
        let owners = graph.prefer_hosted_owners();
        if owners.is_empty() || lower_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let mut having: HashMap<String, HashSet<i64>> = HashMap::new();
        for (repository_id, name) in
            component_dao::repositories_having_names(&self.pool, &owners, lower_ids).await?
        {
            having.entry(name).or_default().insert(repository_id);
        }
        Ok(having
            .into_iter()
            .map(|(name, having)| (name, graph.owned_in(&having)))
            .collect())
    }

    /// The members allowed to serve `package_id`, in priority order: the
    /// visible members that every group on their way lets through
    /// ([`GroupGraph::serving_leaves`]). A group lets only its owners serve an
    /// id under one of its reserved prefixes, and, when it prefers hosted
    /// packages and **any** of its owners has the id
    /// ([`Self::owned_in`]) — whether or not this principal can see that
    /// owner. A caller who cannot is then left with no serving member and gets
    /// the ordinary not-found answer. A lookup failure propagates (fail
    /// closed).
    async fn serving_members_for_id(
        &self,
        graph: &GroupGraph,
        package_id: &str,
    ) -> Result<Vec<VisibleMember>, RepoError> {
        let lower = self.lower_id(package_id);
        let owned_in = if graph
            .visible_leaves(package_id)
            .ordered
            .iter()
            .any(|leaf| graph.may_yield(*leaf))
        {
            self.owned_in(graph, std::slice::from_ref(&lower))
                .await?
                .remove(&lower)
                .unwrap_or_default()
        } else {
            HashSet::new()
        };
        let guards = IdGuards {
            lower_id: &lower,
            owned_in: &owned_in,
        };
        let mut out = Vec::new();
        for leaf_id in graph.serving_leaves(package_id, &guards) {
            let Some(repo) = graph.leaves.iter().find(|repo| repo.id == leaf_id) else {
                continue;
            };
            out.push(VisibleMember {
                repo: repo.clone(),
                ops: self.member_ops(repo)?,
            });
        }
        Ok(out)
    }

    /// The highest-priority serving member's `.nupkg` for the exact
    /// `(id, version)`; for a `HEAD` request (`head`) without counting a
    /// download.
    async fn resolve_nupkg_from_members(
        &self,
        repo: &str,
        id: &str,
        version: &str,
        head: bool,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        let graph = self.group_graph(repo).await?;
        let members = self.serving_members_for_id(&graph, id).await?;
        let mut failures = MemberFailures::default();
        for m in &members {
            let resolved = if head {
                m.ops.resolve_nupkg_head(&m.repo.name, id, version).await
            } else {
                m.ops.resolve_nupkg(&m.repo.name, id, version).await
            };
            match resolved {
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
        let mut candidates: Vec<RankedHit> = Vec::new();
        let mut failures = MemberFailures::default();
        for (member, leaf) in graph.leaves.iter().enumerate() {
            let ops = self.member_ops(leaf)?;
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
                candidates.push(RankedHit { rank, member, hit });
            }
        }
        failures.into_result()?;

        // The guards of every group on the way, decided against every owner
        // ([`Self::serving_members_for_id`]). Only hits a prefer-hosted group
        // could take out need the ownership lookup.
        let lookup: Vec<String> = candidates
            .iter()
            .filter(|ranked| graph.may_yield(graph.leaves[ranked.member].id))
            .map(|ranked| self.lower_id(&ranked.hit.original_id))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let owned_in = self.owned_in(&graph, &lookup).await?;
        let no_owner = HashSet::new();
        let mut serving: HashMap<String, HashSet<i64>> = HashMap::new();
        let mut by_id: BTreeMap<String, RankedHit> = BTreeMap::new();
        for ranked in candidates {
            let lower = self.lower_id(&ranked.hit.original_id);
            let leaves = serving.entry(lower.clone()).or_insert_with(|| {
                let guards = IdGuards {
                    lower_id: &lower,
                    owned_in: owned_in.get(&lower).unwrap_or(&no_owner),
                };
                graph
                    .serving_leaves(&ranked.hit.original_id, &guards)
                    .into_iter()
                    .collect()
            });
            if leaves.contains(&graph.leaves[ranked.member].id) {
                insert_ranked(&mut by_id, ranked);
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
        failures.into_merged_result(merged.is_empty())?;
        merged.sort_by(|a, b| self.compare_versions(&a.version, &b.version));
        Ok(merged)
    }

    async fn resolve_nupkg(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        self.resolve_nupkg_from_members(repo, id, version, false)
            .await
    }

    async fn resolve_nupkg_head(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        self.resolve_nupkg_from_members(repo, id, version, true)
            .await
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
        failures.into_merged_result(merged.is_empty())?;
        merged.sort_by(|a, b| self.compare_versions(&a.version, &b.version));
        Ok(merged)
    }

    async fn registration_versions(&self, repo: &str, id: &str) -> Result<Vec<String>, RepoError> {
        let graph = self.group_graph(repo).await?;
        let members = self.serving_members_for_id(&graph, id).await?;
        // The versions `registration` merges: the union over serving members.
        let mut seen: HashSet<String> = HashSet::new();
        let mut merged: Vec<String> = Vec::new();
        let mut failures = MemberFailures::default();
        for m in &members {
            match m.ops.registration_versions(&m.repo.name, id).await {
                Ok(versions) => {
                    failures.ok();
                    merged.extend(versions.into_iter().filter(|v| seen.insert(v.clone())));
                }
                Err(e) => failures.failed(&m.repo.name, e),
            }
        }
        failures.into_merged_result(merged.is_empty())?;
        merged.sort_by(|a, b| self.compare_versions(a, b));
        Ok(merged)
    }

    async fn registration_entries(
        &self,
        repo: &str,
        id: &str,
        versions: &[String],
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        let graph = self.group_graph(repo).await?;
        let members = self.serving_members_for_id(&graph, id).await?;
        // Highest-priority member first, as in `registration`.
        let mut seen: HashSet<String> = HashSet::new();
        let mut merged: Vec<RegistrationEntry> = Vec::new();
        let mut failures = MemberFailures::default();
        for m in &members {
            match m.ops.registration_entries(&m.repo.name, id, versions).await {
                Ok(entries) => {
                    failures.ok();
                    merged.extend(
                        entries
                            .into_iter()
                            .filter(|e| seen.insert(e.version.clone())),
                    );
                }
                Err(e) => failures.failed(&m.repo.name, e),
            }
        }
        failures.into_merged_result(merged.is_empty())?;
        Ok(merged)
    }

    async fn registration_entry(
        &self,
        repo: &str,
        id: &str,
        version: &str,
    ) -> Result<Option<RegistrationEntry>, RepoError> {
        let graph = self.group_graph(repo).await?;
        let members = self.serving_members_for_id(&graph, id).await?;
        // Highest-priority serving member that has the exact (id, version),
        // the entry `registration` would keep; a miss is strict like downloads.
        let mut failures = MemberFailures::default();
        for m in &members {
            match m.ops.registration_entry(&m.repo.name, id, version).await {
                Ok(Some(entry)) => return Ok(Some(entry)),
                Ok(None) => failures.ok(),
                Err(e) => failures.failed(&m.repo.name, e),
            }
        }
        failures.into_strict_result()?;
        Ok(None)
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

/// Whether `member` is switched off for maintenance and serves nothing in a
/// group: an offline hosted member or an offline nested group. An offline
/// proxy still serves what it cached.
fn is_offline_member(member: &Repository) -> bool {
    !member.online && member.kind() != RepoKind::Proxy
}

/// Whether a group walk descends into `member`: an online nested group. An
/// offline one is a leaf of the readable graph that fails every read.
fn is_descended_group(member: &Repository) -> bool {
    member.kind() == RepoKind::Group && member.online
}

/// The read ops of an offline hosted or nested group member: every read
/// fails as temporarily unavailable, so the group treats it as a failing
/// member (clients retry rather than cache a miss) instead of serving it.
struct OfflineMember(String);

impl OfflineMember {
    fn error(&self) -> RepoError {
        RepoError::Busy(format!("repository {} is offline", self.0))
    }
}

#[async_trait]
impl RepoReadOps for OfflineMember {
    async fn list_versions(&self, _repo: &str, _id: &str) -> Result<Vec<VersionEntry>, RepoError> {
        Err(self.error())
    }

    async fn resolve_nupkg(
        &self,
        _repo: &str,
        _id: &str,
        _version: &str,
    ) -> Result<Option<NupkgLocation>, RepoError> {
        Err(self.error())
    }

    async fn resolve_nuspec(
        &self,
        _repo: &str,
        _id: &str,
        _version: &str,
    ) -> Result<Option<Vec<u8>>, RepoError> {
        Err(self.error())
    }

    async fn registration(
        &self,
        _repo: &str,
        _id: &str,
    ) -> Result<Vec<RegistrationEntry>, RepoError> {
        Err(self.error())
    }

    async fn search(&self, _repo: &str, _params: &SearchParams) -> Result<SearchResult, RepoError> {
        Err(self.error())
    }
}

/// The hosted leaves that own ids in `group_id` ([`GroupGuard::owners`]):
/// those of its flagged members, or of all its members when it flags none. A
/// nested group contributes its own owners, so its flags still count when it
/// is read through an outer group. A group already on the current descent
/// (a cycle a raw database write could create) contributes nothing.
fn group_owners(
    group_id: i64,
    adjacency: &HashMap<i64, Vec<Repository>>,
    flagged: &HashMap<i64, HashSet<i64>>,
    memo: &mut HashMap<i64, HashSet<i64>>,
    descent: &mut HashSet<i64>,
) -> HashSet<i64> {
    if let Some(owners) = memo.get(&group_id) {
        return owners.clone();
    }
    if !descent.insert(group_id) {
        return HashSet::new();
    }
    let flags = flagged.get(&group_id);
    let mut owners = HashSet::new();
    for member in adjacency
        .get(&group_id)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        if flags.is_some_and(|flags| !flags.is_empty() && !flags.contains(&member.id)) {
            continue;
        }
        match member.kind() {
            RepoKind::Hosted => {
                owners.insert(member.id);
            }
            RepoKind::Group => {
                owners.extend(group_owners(member.id, adjacency, flagged, memo, descent));
            }
            RepoKind::Proxy => {}
        }
    }
    descent.remove(&group_id);
    memo.insert(group_id, owners.clone());
    owners
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

    /// For a merge across members: an empty merge is a miss, so it is strict
    /// ([`Self::into_strict_result`]); a non-empty one is served from the
    /// members that answered.
    fn into_merged_result(self, merged_is_empty: bool) -> Result<(), RepoError> {
        if merged_is_empty {
            self.into_strict_result()
        } else {
            self.into_result()
        }
    }
}
