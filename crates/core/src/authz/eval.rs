//! The **pure** fine-grained-RBAC evaluator (§12.4 Phase 2).
//!
//! This module is deliberately free of any database, cache, or async concern.
//! It defines the in-memory shape of a principal's resolved authorization —
//! the [`EffectiveSet`] — and the pure decision functions over it:
//!
//! * [`EffectiveSet::allows_repo`] — the **repo-level gate** used by
//!   `can_read` / `can_write` / `can_admin`. "Does any held grant for this
//!   action cover this repo?" Content selectors are *ignored* for the gate (a
//!   selector-scoped read grant still lets you reach the repo — it only filters
//!   *which packages* are visible inside it, see below).
//! * [`EffectiveSet::package_filter`] — the **package-level filter** used when
//!   listing/serving packages. Returns a [`PackageFilter`] predicate: a package
//!   is visible iff at least one held `read` grant covering the repo either has
//!   no selector or matches the package name.
//!
//! ## Model (plan §3 "The permission model")
//!
//! A principal holds a flat, **additive** set of [`Grant`]s (the union of all
//! its roles' grants). Each grant is `(action, repo|ANY, selector?)`. There are
//! **no explicit-deny rows**: "no access" is the absence of a matching grant —
//! the evaluator is **fail-closed** (default DENY). Membership in the built-in
//! `admin` role is represented by [`EffectiveSet::is_admin`] and short-circuits
//! to allow-all.
//!
//! Per-token scoping is applied here by [`EffectiveSet::intersect_scope`]: a
//! token may only ever *narrow* its owner's set, never widen it. The DB loads
//! the owner's set (cached); the token scope is intersected **after** the cache
//! lookup so the owner set stays shared across that user's tokens.
//!
//! ## Selector semantics (plan §3 "Content scoping")
//!
//! Selectors are glob include/exclude lists matched against the **lowercased**
//! package name (NuGet ids are case-insensitive). An empty include list means
//! match-all; excludes always win over includes. Globs compile once into a
//! [`globset::GlobSet`] held behind `Arc` inside a [`CompiledSelector`] so the
//! cached set is cheap to clone and the hot path does no recompilation.

use std::sync::Arc;

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

/// The four authorization verbs. Mirrors the seeded `privilege` reference table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Download / list / search.
    Read,
    /// Push / relist.
    Write,
    /// Hard delete / unlist beyond owner.
    Delete,
    /// Repository config + privilege management.
    Admin,
}

impl Action {
    /// The wire/DB string for this action (matches `privilege.action`).
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Delete => "delete",
            Action::Admin => "admin",
        }
    }

    /// Parse an action from its DB string. Unknown verbs are rejected (an
    /// unrecognized action must never silently widen access).
    pub fn parse(s: &str) -> Option<Action> {
        match s {
            "read" => Some(Action::Read),
            "write" => Some(Action::Write),
            "delete" => Some(Action::Delete),
            "admin" => Some(Action::Admin),
            _ => None,
        }
    }
}

/// An error compiling a content selector's glob patterns.
///
/// Fail-closed contract: when an [`EffectiveSet`] is built and a selector fails
/// to compile, the *whole build* errors (the caller denies) rather than treating
/// the grant as unscoped (which would over-grant).
#[derive(Debug, thiserror::Error)]
#[error("invalid content-selector glob {pattern:?}: {source}")]
pub struct SelectorCompileError {
    /// The pattern that failed to parse.
    pub pattern: String,
    /// The underlying globset error.
    #[source]
    pub source: globset::Error,
}

/// The raw, serializable include/exclude glob lists of a content selector, as
/// stored in `content_selector.includes` / `.excludes`.
///
/// This is the form that lives in the DB and in the cache; the compiled form
/// ([`CompiledSelector`]) is derived from it when an [`EffectiveSet`] is built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorPatterns {
    /// Glob include patterns. Empty ⇒ match-all (then excludes subtract).
    pub includes: Vec<String>,
    /// Glob exclude patterns. Always win over includes.
    pub excludes: Vec<String>,
}

impl SelectorPatterns {
    /// Compile the include/exclude lists into matchable [`GlobSet`]s.
    ///
    /// Patterns are matched against the **lowercased** package name, so they are
    /// lowercased here at compile time (NuGet ids are case-insensitive). An
    /// empty include list compiles to a sentinel "match-all" so the predicate is
    /// uniform.
    fn compile(&self) -> Result<CompiledSelector, SelectorCompileError> {
        let includes = build_globset(&self.includes)?;
        let excludes = build_globset(&self.excludes)?;
        Ok(CompiledSelector {
            include_all: self.includes.is_empty(),
            includes,
            excludes,
        })
    }
}

/// Build a [`GlobSet`] from a list of patterns, lowercasing each (package names
/// are matched case-insensitively).
fn build_globset(patterns: &[String]) -> Result<GlobSet, SelectorCompileError> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let glob = Glob::new(&p.to_lowercase()).map_err(|source| SelectorCompileError {
            pattern: p.clone(),
            source,
        })?;
        builder.add(glob);
    }
    builder.build().map_err(|source| SelectorCompileError {
        pattern: patterns.join(","),
        source,
    })
}

/// A compiled content selector: include/exclude [`GlobSet`]s ready to match a
/// lowercased package name. Shared behind `Arc` so cloning an [`EffectiveSet`]
/// is cheap.
#[derive(Debug, Clone)]
pub struct CompiledSelector {
    /// True when the include list was empty ⇒ everything is included (subject to
    /// excludes).
    include_all: bool,
    includes: GlobSet,
    excludes: GlobSet,
}

impl CompiledSelector {
    /// Does this selector match `package_name`? The name is lowercased before
    /// matching. Excludes win over includes; an empty include list matches all.
    pub fn matches(&self, package_name: &str) -> bool {
        let name = package_name.to_lowercase();
        if self.excludes.is_match(&name) {
            return false;
        }
        self.include_all || self.includes.is_match(&name)
    }
}

/// A single resolved grant held by a principal: "may perform `action` on
/// `repo` (or any repo when `repo == None`), optionally scoped to packages
/// matching `selector`".
#[derive(Debug, Clone)]
pub struct Grant {
    /// The action this grant authorizes.
    pub action: Action,
    /// The repository the grant applies to; `None` means **ANY** repository
    /// (the `*`/`ANY` wildcard).
    pub repo: Option<i64>,
    /// Optional package-name scope. `None` ⇒ the grant covers all packages in
    /// the repo.
    pub selector: Option<Arc<CompiledSelector>>,
}

impl Grant {
    /// Does this grant cover `action` on repository `repo_id`, ignoring any
    /// selector (the repo-level gate)?
    fn covers_repo(&self, action: Action, repo_id: i64) -> bool {
        self.action == action && self.repo.map(|r| r == repo_id).unwrap_or(true)
    }
}

/// A raw, serializable grant as loaded from the DB / stored in the cache. The
/// selector is its raw [`SelectorPatterns`]; it is compiled when the
/// [`EffectiveSet`] is built via [`EffectiveSet::build`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawGrant {
    /// The action string (`read`/`write`/`delete`/`admin`). Unknown actions are
    /// dropped at build time (fail-closed; an unrecognized verb grants nothing).
    pub action: String,
    /// `repository.id`, or `None` for an ANY-repo grant.
    pub repo: Option<i64>,
    /// Raw selector patterns, or `None` for an unscoped grant.
    pub selector: Option<SelectorPatterns>,
}

/// The raw, serializable effective set as produced by the DB loader and stored
/// in the cache. Cheap to (de)serialize; compiled into an [`EffectiveSet`] for
/// evaluation via [`EffectiveSet::build`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEffectiveSet {
    /// Membership in the built-in `admin` role ⇒ allow-all short-circuit.
    pub is_admin: bool,
    /// The flat union of grants from all the principal's roles.
    pub grants: Vec<RawGrant>,
}

impl RawEffectiveSet {
    /// An empty (deny-everything) raw set — the fail-closed default.
    pub fn empty() -> Self {
        RawEffectiveSet {
            is_admin: false,
            grants: Vec::new(),
        }
    }
}

/// A principal's resolved, **compiled** effective authorization set.
///
/// Built from a [`RawEffectiveSet`] (which compiles selector globs). Holds only
/// owned data behind `Arc`, so it is cheap to clone. All decision methods are
/// pure and synchronous.
#[derive(Debug, Clone)]
pub struct EffectiveSet {
    is_admin: bool,
    grants: Vec<Grant>,
}

impl EffectiveSet {
    /// Build (and compile) an effective set from its raw DB/cache form.
    ///
    /// Grants whose `action` is not a known verb are **dropped** (fail-closed).
    /// A selector that fails to compile fails the whole build (the caller then
    /// denies) — we never silently treat an unparseable selector as "no scope".
    pub fn build(raw: &RawEffectiveSet) -> Result<EffectiveSet, SelectorCompileError> {
        let mut grants = Vec::with_capacity(raw.grants.len());
        for g in &raw.grants {
            let Some(action) = Action::parse(&g.action) else {
                // Unknown action verb: drop it (cannot widen access).
                continue;
            };
            let selector = match &g.selector {
                Some(patterns) => Some(Arc::new(patterns.compile()?)),
                None => None,
            };
            grants.push(Grant {
                action,
                repo: g.repo,
                selector,
            });
        }
        Ok(EffectiveSet {
            is_admin: raw.is_admin,
            grants,
        })
    }

    /// The empty (deny-everything) set — the fail-closed default for a principal
    /// with no roles / no grants.
    pub fn empty() -> EffectiveSet {
        EffectiveSet {
            is_admin: false,
            grants: Vec::new(),
        }
    }

    /// Whether this principal holds the built-in `admin` role (allow-all).
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }

    /// **Repo-level gate.** May this principal perform `action` on repository
    /// `repo_id`?
    ///
    /// `admin`-role membership allows everything. Otherwise: true iff at least
    /// one held grant covers `(action, repo_id)`. **Selectors are ignored here**
    /// — a selector-scoped read grant still passes the repo gate; package
    /// filtering happens separately in [`Self::package_filter`].
    pub fn allows_repo(&self, action: Action, repo_id: i64) -> bool {
        if self.is_admin {
            return true;
        }
        self.grants.iter().any(|g| g.covers_repo(action, repo_id))
    }

    /// **Package-level filter** for `read` on `repo_id`.
    ///
    /// Returns the predicate to apply when listing/serving packages from the
    /// repo. Admin and any unscoped `read` grant covering the repo ⇒
    /// [`PackageFilter::AllowAll`]. Otherwise the visible packages are the union
    /// of every selector-scoped read grant covering the repo
    /// ([`PackageFilter::Selectors`]). If no read grant covers the repo at all,
    /// returns [`PackageFilter::DenyAll`] (the repo gate should have already
    /// denied, but this stays fail-closed independently).
    pub fn package_filter(&self, repo_id: i64) -> PackageFilter {
        if self.is_admin {
            return PackageFilter::AllowAll;
        }
        let mut selectors: Vec<Arc<CompiledSelector>> = Vec::new();
        let mut covers = false;
        for g in &self.grants {
            if !g.covers_repo(Action::Read, repo_id) {
                continue;
            }
            covers = true;
            match &g.selector {
                // An unscoped read grant covering the repo ⇒ everything visible.
                None => return PackageFilter::AllowAll,
                Some(sel) => selectors.push(sel.clone()),
            }
        }
        if !covers {
            PackageFilter::DenyAll
        } else {
            PackageFilter::Selectors(selectors)
        }
    }

    /// Apply a token scope, returning a **narrowed** set (never widened).
    ///
    /// Each grant is kept only if the scope permits its action AND its repo.
    /// `admin` is preserved only if the scope permits the `admin` action (a
    /// scoped token cannot exercise admin unless explicitly scoped to it). A
    /// `None` scope (no scoping) returns the set unchanged.
    ///
    /// Note: a grant for `repo == ANY` (None) is narrowed to the scope's repo
    /// allowlist when the scope restricts repos — the ANY grant is expanded into
    /// one grant per allowed repo id so the token can never reach a repo outside
    /// its scope. When the scope does not restrict repos, ANY is preserved.
    pub fn intersect_scope(&self, scope: &TokenScope) -> EffectiveSet {
        if scope.actions.is_none() && scope.repositories.is_none() {
            return self.clone();
        }
        let action_ok = |a: Action| match &scope.actions {
            None => true,
            Some(allowed) => allowed.contains(&a),
        };

        let mut grants = Vec::new();
        for g in &self.grants {
            if !action_ok(g.action) {
                continue;
            }
            match (&scope.repositories, g.repo) {
                // Scope does not restrict repos: keep the grant as-is.
                (None, _) => grants.push(g.clone()),
                // Grant is repo-specific: keep iff that repo is in the scope.
                (Some(allowed), Some(repo_id)) => {
                    if allowed.contains(&repo_id) {
                        grants.push(g.clone());
                    }
                }
                // Grant is ANY-repo but scope restricts repos: expand ANY into
                // one grant per allowed repo so the token cannot reach others.
                (Some(allowed), None) => {
                    for &repo_id in allowed {
                        grants.push(Grant {
                            action: g.action,
                            repo: Some(repo_id),
                            selector: g.selector.clone(),
                        });
                    }
                }
            }
        }

        EffectiveSet {
            // admin short-circuit survives only if the scope allows the admin
            // action (a read-scoped token must not retain allow-all).
            is_admin: self.is_admin && action_ok(Action::Admin),
            grants,
        }
    }
}

/// The package-visibility predicate returned by [`EffectiveSet::package_filter`].
#[derive(Debug, Clone)]
pub enum PackageFilter {
    /// Every package in the repo is visible (admin, or an unscoped read grant).
    AllowAll,
    /// No package is visible (no read grant covers the repo). Fail-closed.
    DenyAll,
    /// A package is visible iff **any** of these selectors matches it (union).
    Selectors(Vec<Arc<CompiledSelector>>),
}

impl PackageFilter {
    /// Is `package_name` visible under this filter?
    pub fn allows(&self, package_name: &str) -> bool {
        match self {
            PackageFilter::AllowAll => true,
            PackageFilter::DenyAll => false,
            PackageFilter::Selectors(sels) => sels.iter().any(|s| s.matches(package_name)),
        }
    }
}

/// An optional per-token privilege scope (from `token.scope` jsonb).
///
/// A token's effective set is `owner_set ∩ scope`. `None` on a field means that
/// dimension is not restricted (the token inherits all of the owner's actions /
/// repos). A scope can only ever **narrow**; see [`EffectiveSet::intersect_scope`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenScope {
    /// Allowed actions; `None` ⇒ all of the owner's actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<Action>>,
    /// Allowed repository ids; `None` ⇒ all repos the owner can touch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<i64>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an [`EffectiveSet`] from `(action, repo, selector)` tuples.
    fn set(
        is_admin: bool,
        grants: &[(Action, Option<i64>, Option<SelectorPatterns>)],
    ) -> EffectiveSet {
        let raw = RawEffectiveSet {
            is_admin,
            grants: grants
                .iter()
                .map(|(a, r, s)| RawGrant {
                    action: a.as_str().to_string(),
                    repo: *r,
                    selector: s.clone(),
                })
                .collect(),
        };
        EffectiveSet::build(&raw).expect("compile")
    }

    fn sel(includes: &[&str], excludes: &[&str]) -> SelectorPatterns {
        SelectorPatterns {
            includes: includes.iter().map(|s| s.to_string()).collect(),
            excludes: excludes.iter().map(|s| s.to_string()).collect(),
        }
    }

    // --- repo-level gate matrix --------------------------------------------

    #[test]
    fn empty_set_denies_everything() {
        let s = EffectiveSet::empty();
        for a in [Action::Read, Action::Write, Action::Delete, Action::Admin] {
            assert!(!s.allows_repo(a, 1), "empty must deny {a:?}");
            assert!(!s.allows_repo(a, 2));
        }
        assert!(!s.is_admin());
    }

    #[test]
    fn admin_allows_all_actions_and_repos() {
        let s = set(true, &[]);
        for a in [Action::Read, Action::Write, Action::Delete, Action::Admin] {
            assert!(s.allows_repo(a, 1));
            assert!(s.allows_repo(a, 999));
        }
        assert!(s.is_admin());
    }

    #[test]
    fn read_grant_on_repo_a_only() {
        let s = set(false, &[(Action::Read, Some(1), None)]);
        assert!(s.allows_repo(Action::Read, 1), "read on A");
        assert!(!s.allows_repo(Action::Read, 2), "deny read on B");
        assert!(!s.allows_repo(Action::Write, 1), "deny write on A");
        assert!(!s.allows_repo(Action::Admin, 1));
    }

    #[test]
    fn any_repo_grant_covers_every_repo() {
        let s = set(false, &[(Action::Write, None, None)]);
        assert!(s.allows_repo(Action::Write, 1));
        assert!(s.allows_repo(Action::Write, 42));
        assert!(
            !s.allows_repo(Action::Read, 1),
            "write ANY does not grant read"
        );
    }

    #[test]
    fn multiple_grants_union() {
        let s = set(
            false,
            &[
                (Action::Read, Some(1), None),
                (Action::Write, Some(1), None),
                (Action::Read, Some(2), None),
            ],
        );
        assert!(s.allows_repo(Action::Read, 1));
        assert!(s.allows_repo(Action::Write, 1));
        assert!(s.allows_repo(Action::Read, 2));
        assert!(!s.allows_repo(Action::Write, 2), "no write grant on B");
    }

    // --- selector semantics -------------------------------------------------

    #[test]
    fn selector_scoped_read_passes_repo_gate() {
        // A selector-scoped read grant must still pass the repo-level gate.
        let s = set(
            false,
            &[(Action::Read, Some(1), Some(sel(&["company.*"], &[])))],
        );
        assert!(
            s.allows_repo(Action::Read, 1),
            "selector-scoped read still reaches the repo"
        );
    }

    #[test]
    fn selector_include_matches_and_excludes_win() {
        let s = set(
            false,
            &[(
                Action::Read,
                Some(1),
                Some(sel(&["company.*"], &["company.secret*"])),
            )],
        );
        let f = s.package_filter(1);
        assert!(
            f.allows("Company.Tools"),
            "include matches (case-insensitive)"
        );
        assert!(f.allows("company.tools"));
        assert!(!f.allows("Other.Lib"), "outside include");
        assert!(
            !f.allows("Company.Secret.Keys"),
            "exclude wins over include"
        );
    }

    #[test]
    fn empty_include_means_match_all_minus_excludes() {
        let s = set(
            false,
            &[(Action::Read, Some(1), Some(sel(&[], &["internal.*"])))],
        );
        let f = s.package_filter(1);
        assert!(f.allows("Anything.Goes"));
        assert!(!f.allows("Internal.Secret"));
    }

    #[test]
    fn unscoped_read_grant_yields_allow_all_filter() {
        let s = set(false, &[(Action::Read, Some(1), None)]);
        assert!(matches!(s.package_filter(1), PackageFilter::AllowAll));
    }

    #[test]
    fn no_read_grant_yields_deny_all_filter() {
        let s = set(false, &[(Action::Write, Some(1), None)]);
        assert!(matches!(s.package_filter(1), PackageFilter::DenyAll));
    }

    #[test]
    fn admin_filter_is_allow_all() {
        let s = set(true, &[]);
        assert!(matches!(s.package_filter(7), PackageFilter::AllowAll));
    }

    #[test]
    fn union_of_selectors_widens_visibility() {
        // Two selector-scoped read grants: a package visible under either is OK.
        let s = set(
            false,
            &[
                (Action::Read, Some(1), Some(sel(&["a.*"], &[]))),
                (Action::Read, Some(1), Some(sel(&["b.*"], &[]))),
            ],
        );
        let f = s.package_filter(1);
        assert!(f.allows("A.One"));
        assert!(f.allows("B.Two"));
        assert!(!f.allows("C.Three"));
    }

    #[test]
    fn unscoped_grant_overrides_selector_to_allow_all() {
        // One unscoped + one selector-scoped read grant on the same repo ⇒
        // unscoped wins (everything visible).
        let s = set(
            false,
            &[
                (Action::Read, Some(1), Some(sel(&["a.*"], &[]))),
                (Action::Read, Some(1), None),
            ],
        );
        assert!(matches!(s.package_filter(1), PackageFilter::AllowAll));
    }

    #[test]
    fn any_repo_selector_grant_filters_each_repo() {
        let s = set(false, &[(Action::Read, None, Some(sel(&["pub.*"], &[])))]);
        assert!(s.allows_repo(Action::Read, 1));
        assert!(s.allows_repo(Action::Read, 2));
        let f1 = s.package_filter(1);
        assert!(f1.allows("Pub.A"));
        assert!(!f1.allows("Priv.A"));
    }

    // --- token scoping ------------------------------------------------------

    #[test]
    fn scope_none_is_identity() {
        let s = set(
            false,
            &[
                (Action::Read, Some(1), None),
                (Action::Write, Some(1), None),
            ],
        );
        let scoped = s.intersect_scope(&TokenScope::default());
        assert!(scoped.allows_repo(Action::Read, 1));
        assert!(scoped.allows_repo(Action::Write, 1));
    }

    #[test]
    fn scope_narrows_actions() {
        let s = set(
            false,
            &[
                (Action::Read, Some(1), None),
                (Action::Write, Some(1), None),
            ],
        );
        let scoped = s.intersect_scope(&TokenScope {
            actions: Some(vec![Action::Read]),
            repositories: None,
        });
        assert!(scoped.allows_repo(Action::Read, 1), "read kept");
        assert!(!scoped.allows_repo(Action::Write, 1), "write dropped");
    }

    #[test]
    fn scope_narrows_repositories() {
        let s = set(
            false,
            &[(Action::Read, Some(1), None), (Action::Read, Some(2), None)],
        );
        let scoped = s.intersect_scope(&TokenScope {
            actions: None,
            repositories: Some(vec![1]),
        });
        assert!(scoped.allows_repo(Action::Read, 1));
        assert!(!scoped.allows_repo(Action::Read, 2), "repo 2 outside scope");
    }

    #[test]
    fn scope_cannot_widen_beyond_owner() {
        // Owner only has repo 1; scoping to repo 2 grants nothing on repo 2.
        let s = set(false, &[(Action::Read, Some(1), None)]);
        let scoped = s.intersect_scope(&TokenScope {
            actions: None,
            repositories: Some(vec![2]),
        });
        assert!(
            !scoped.allows_repo(Action::Read, 2),
            "scope can't grant repo owner lacks"
        );
        assert!(!scoped.allows_repo(Action::Read, 1), "repo 1 not in scope");
    }

    #[test]
    fn scope_expands_any_grant_to_allowed_repos_only() {
        // Owner has read on ANY repo; scope restricts to repo 1 only.
        let s = set(false, &[(Action::Read, None, None)]);
        let scoped = s.intersect_scope(&TokenScope {
            actions: None,
            repositories: Some(vec![1]),
        });
        assert!(scoped.allows_repo(Action::Read, 1));
        assert!(
            !scoped.allows_repo(Action::Read, 2),
            "ANY narrowed to scope"
        );
    }

    #[test]
    fn scope_drops_admin_unless_scoped_to_admin() {
        let s = set(true, &[]);
        let read_only = s.intersect_scope(&TokenScope {
            actions: Some(vec![Action::Read]),
            repositories: None,
        });
        assert!(!read_only.is_admin(), "read-scoped token loses admin");
        assert!(!read_only.allows_repo(Action::Admin, 1));

        let admin_scoped = s.intersect_scope(&TokenScope {
            actions: Some(vec![Action::Admin]),
            repositories: None,
        });
        assert!(admin_scoped.is_admin(), "admin-scoped token keeps admin");
    }

    #[test]
    fn scope_preserves_selectors() {
        let s = set(false, &[(Action::Read, Some(1), Some(sel(&["a.*"], &[])))]);
        let scoped = s.intersect_scope(&TokenScope {
            actions: Some(vec![Action::Read]),
            repositories: Some(vec![1]),
        });
        let f = scoped.package_filter(1);
        assert!(f.allows("A.One"));
        assert!(!f.allows("B.One"));
    }

    // --- build / parsing edge cases ----------------------------------------

    #[test]
    fn unknown_action_is_dropped_fail_closed() {
        let raw = RawEffectiveSet {
            is_admin: false,
            grants: vec![RawGrant {
                action: "superuser".to_string(),
                repo: Some(1),
                selector: None,
            }],
        };
        let s = EffectiveSet::build(&raw).expect("build");
        for a in [Action::Read, Action::Write, Action::Delete, Action::Admin] {
            assert!(!s.allows_repo(a, 1), "unknown action grants nothing");
        }
    }

    #[test]
    fn invalid_glob_fails_build() {
        let raw = RawEffectiveSet {
            is_admin: false,
            grants: vec![RawGrant {
                action: "read".to_string(),
                repo: Some(1),
                selector: Some(SelectorPatterns {
                    includes: vec!["a[".to_string()], // unterminated class
                    excludes: vec![],
                }),
            }],
        };
        let err = EffectiveSet::build(&raw);
        assert!(
            err.is_err(),
            "invalid glob must fail the build (fail-closed)"
        );
    }

    #[test]
    fn action_roundtrips_through_str() {
        for a in [Action::Read, Action::Write, Action::Delete, Action::Admin] {
            assert_eq!(Action::parse(a.as_str()), Some(a));
        }
        assert_eq!(Action::parse("nope"), None);
    }

    #[test]
    fn raw_set_serde_roundtrip() {
        let raw = RawEffectiveSet {
            is_admin: false,
            grants: vec![RawGrant {
                action: "read".to_string(),
                repo: None,
                selector: Some(sel(&["x.*"], &["x.secret"])),
            }],
        };
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEffectiveSet = serde_json::from_str(&json).unwrap();
        assert_eq!(raw, back);
    }

    #[test]
    fn token_scope_serde_omits_none_fields() {
        let scope = TokenScope {
            actions: Some(vec![Action::Read]),
            repositories: None,
        };
        let json = serde_json::to_string(&scope).unwrap();
        assert_eq!(json, r#"{"actions":["read"]}"#);
        let back: TokenScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }
}
