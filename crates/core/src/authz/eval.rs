//! The **pure** fine-grained-RBAC evaluator.
//!
//! This module is deliberately free of any database, cache, or async concern.
//! It defines the in-memory shape of a principal's resolved authorization —
//! the [`EffectiveSet`] — and the pure decision functions over it:
//!
//! * [`EffectiveSet::allows_repo`] — the **repo-level gate** used by
//!   `can_read` / `can_write` / `can_delete`. "Does any held grant of the
//!   required level or a higher one cover this repo?" Content selectors are
//!   *ignored* for the gate (a selector-scoped grant still lets you reach the
//!   repo — it only filters *which packages* are visible inside it, see below).
//! * [`EffectiveSet::package_filter`] — the **package-level filter** used when
//!   listing/serving packages. Returns a [`PackageFilter`] predicate: a package
//!   is visible iff at least one held grant covering the repo either has no
//!   selector or matches the package name.
//!
//! ## Model
//!
//! A principal holds a flat, **additive** set of [`Grant`]s (the union of all
//! its roles' grants). Each grant is `(level, repo|ANY, selector?)`, where the
//! [`Level`]s are ordered, `read` < `write` < `delete`, and each includes the
//! ones below it. There are **no explicit-deny rows**: "no access" is the
//! absence of a matching grant — the evaluator is **fail-closed** (default
//! DENY). Administration is no grant: membership in the built-in `admin` role
//! is represented by [`EffectiveSet::is_admin`] and short-circuits to
//! allow-all.
//!
//! Per-token scoping is applied here by [`EffectiveSet::intersect_scope`]: a
//! token may only ever *narrow* its owner's set, never widen it, and it keeps
//! the owner's `admin` role only when its scope opts in with `admin: true`.
//! The DB loads the owner's set (cached); the token scope is intersected
//! **after** the cache lookup so the owner set stays shared across that
//! user's tokens.
//!
//! ## Selector semantics (content scoping)
//!
//! Selectors are glob include/exclude lists matched against the **lowercased**
//! package name (NuGet ids are case-insensitive). An empty include list means
//! match-all; excludes always win over includes. Globs compile once into a
//! [`globset::GlobSet`] held behind `Arc` inside a [`CompiledSelector`] so the
//! cached set is cheap to clone and the hot path does no recompilation.

use std::fmt;
use std::sync::Arc;

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Deserializer, Serialize};

/// The three ordered access levels a grant or a token scope gives. Each
/// includes the ones below it (`read` < `write` < `delete`), so a check for a
/// level passes on a grant of that level or a higher one. The values of
/// `repository_privilege.level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Browse and read: download, list, search.
    Read,
    /// `read`, plus add and edit: push, relist.
    Write,
    /// `write`, plus delete: unlist, delete.
    Delete,
}

impl Level {
    /// Every level, lowest first.
    pub const ALL: [Level; 3] = [Level::Read, Level::Write, Level::Delete];

    /// The wire/DB string for this level (matches `repository_privilege.level`).
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Read => "read",
            Level::Write => "write",
            Level::Delete => "delete",
        }
    }

    /// Parse a level from its DB string. Unknown values are rejected (an
    /// unrecognized level must never silently widen access).
    pub fn parse(s: &str) -> Option<Level> {
        match s {
            "read" => Some(Level::Read),
            "write" => Some(Level::Write),
            "delete" => Some(Level::Delete),
            _ => None,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
    pub fn compile(&self) -> Result<CompiledSelector, SelectorCompileError> {
        let includes = build_globset(&self.includes)?;
        let excludes = build_globset(&self.excludes)?;
        Ok(CompiledSelector {
            include_all: self.includes.is_empty(),
            includes,
            excludes,
        })
    }

    /// Validate that every include/exclude pattern compiles, without returning
    /// the compiled form. Used by the admin API to reject an uncompilable
    /// selector at write time (a selector that won't compile would fail-closed
    /// at evaluation, so persisting one is never useful).
    pub fn compile_check(&self) -> Result<(), SelectorCompileError> {
        self.compile().map(|_| ())
    }

    /// Compile the patterns and match `package_name` against them, exactly as
    /// a grant scoped by this selector would. Used by the admin API's selector
    /// test, so an admin checks a pattern against the evaluator's own globs.
    pub fn matches(&self, package_name: &str) -> Result<bool, SelectorCompileError> {
        self.compile().map(|c| c.matches(package_name))
    }
}

/// Build a [`GlobSet`] from a list of patterns, lowercasing each (package names
/// are matched case-insensitively).
fn build_globset(patterns: &[String]) -> Result<GlobSet, SelectorCompileError> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let glob = Glob::new(&crate::format::lower_invariant(p)).map_err(|source| {
            SelectorCompileError {
                pattern: p.clone(),
                source,
            }
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
        let name = crate::format::lower_invariant(package_name);
        if self.excludes.is_match(&name) {
            return false;
        }
        self.include_all || self.includes.is_match(&name)
    }
}

/// A single resolved grant held by a principal: "may act up to `level` on
/// `repo` (or any repo when `repo == None`), optionally scoped to packages
/// matching `selector`".
#[derive(Debug, Clone)]
pub struct Grant {
    /// The level this grant gives (and every level below it).
    pub level: Level,
    /// The repository the grant applies to; `None` means **ANY** repository
    /// (the `*`/`ANY` wildcard).
    pub repo: Option<i64>,
    /// Optional package-name scope. `None` ⇒ the grant covers all packages in
    /// the repo.
    pub selector: Option<Arc<CompiledSelector>>,
}

impl Grant {
    /// Does this grant give `required` (or a higher level) on repository
    /// `repo_id`, ignoring any selector (the repo-level gate)?
    fn covers_repo(&self, required: Level, repo_id: i64) -> bool {
        self.level >= required && self.repo.map(|r| r == repo_id).unwrap_or(true)
    }

    /// This grant with its level lowered to at most `cap`.
    fn capped(&self, cap: Level) -> Grant {
        Grant {
            level: self.level.min(cap),
            ..self.clone()
        }
    }
}

/// A raw, serializable grant as loaded from the DB / stored in the cache. The
/// selector is its raw [`SelectorPatterns`]; it is compiled when the
/// [`EffectiveSet`] is built via [`EffectiveSet::build`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawGrant {
    /// The level string (`read`/`write`/`delete`). Unknown levels are dropped
    /// at build time (fail-closed; an unrecognized level grants nothing).
    pub level: String,
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
    /// Grants whose `level` is not a known level are **dropped** (fail-closed).
    /// A selector that fails to compile fails the whole build (the caller then
    /// denies) — we never silently treat an unparseable selector as "no scope".
    pub fn build(raw: &RawEffectiveSet) -> Result<EffectiveSet, SelectorCompileError> {
        let mut grants = Vec::with_capacity(raw.grants.len());
        for g in &raw.grants {
            let Some(level) = Level::parse(&g.level) else {
                // Unknown level: drop it (cannot widen access).
                continue;
            };
            let selector = match &g.selector {
                Some(patterns) => Some(Arc::new(patterns.compile()?)),
                None => None,
            };
            grants.push(Grant {
                level,
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

    /// **Repo-level gate.** Does this principal hold `required` (or a higher
    /// level) on repository `repo_id`?
    ///
    /// `admin`-role membership allows everything. Otherwise: true iff at least
    /// one held grant covering `repo_id` has the required level or a higher
    /// one. **Selectors are ignored here** — a selector-scoped grant still
    /// passes the repo gate; package filtering happens separately in
    /// [`Self::package_filter_for`].
    pub fn allows_repo(&self, required: Level, repo_id: i64) -> bool {
        if self.is_admin {
            return true;
        }
        self.grants.iter().any(|g| g.covers_repo(required, repo_id))
    }

    /// Whether this principal holds `required` (or a higher level) on
    /// **every** repository, including ones created later and every package
    /// in them: the `admin` role, or an unscoped grant of that level or a
    /// higher one on ANY repository (what the built-in `writer` role holds for
    /// `write`).
    pub fn allows_every_repo(&self, required: Level) -> bool {
        self.is_admin
            || self
                .grants
                .iter()
                .any(|g| g.level >= required && g.repo.is_none() && g.selector.is_none())
    }

    /// **Package-level filter** for `required` on `repo_id`.
    ///
    /// Returns the predicate to apply when listing/serving/changing packages
    /// of the repo. Only grants of the required level or a higher one count:
    /// a selector-scoped `write` grant also filters what its holder reads,
    /// while a `read` grant never lets anything be written. Admin and any
    /// unscoped counting grant covering the repo ⇒ [`PackageFilter::AllowAll`].
    /// Otherwise the allowed packages are the union of every selector-scoped
    /// counting grant covering the repo ([`PackageFilter::Selectors`]). If no
    /// counting grant covers the repo at all, returns
    /// [`PackageFilter::DenyAll`] (the repo gate should have already denied,
    /// but this stays fail-closed independently).
    pub fn package_filter_for(&self, required: Level, repo_id: i64) -> PackageFilter {
        if self.is_admin {
            return PackageFilter::AllowAll;
        }
        let mut selectors: Vec<Arc<CompiledSelector>> = Vec::new();
        let mut covers = false;
        for g in &self.grants {
            if !g.covers_repo(required, repo_id) {
                continue;
            }
            covers = true;
            match &g.selector {
                // An unscoped grant covering the repo ⇒ every package.
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

    /// **Package-level filter** for `read` on `repo_id`.
    ///
    /// Kept as the read-oriented convenience API used by existing callers;
    /// package-aware mutations use [`Self::package_filter_for`] with their own
    /// level so a `read` grant can never authorize a write or delete.
    pub fn package_filter(&self, repo_id: i64) -> PackageFilter {
        self.package_filter_for(Level::Read, repo_id)
    }

    /// Apply a token scope, returning a **narrowed** set (never widened).
    ///
    /// Every API token goes through here — an unscoped token (NULL `scope`)
    /// is evaluated as [`TokenScope::default()`] — so the rules below are the
    /// whole token policy:
    ///
    /// * Each grant is kept only if the scope permits its repo, and its level
    ///   is lowered to the scope's `level` (a `delete` grant under a `read`
    ///   scope reads). No `level` keeps the owner's levels.
    /// * **`admin` is opt-in.** Without `admin: true` (or with no scope at
    ///   all) the token never keeps the owner's `admin` role: a leaked feed
    ///   token therefore never reaches `/admin/*` (privilege management, user
    ///   creation, minting further tokens).
    /// * **Admin** (the allow-all short-circuit) survives only when the scope
    ///   sets `admin: true` and does not restrict repositories: a token scoped
    ///   to some repositories must never keep server-wide admin (it would
    ///   reach every repo and the privilege-management API). When admin is
    ///   dropped, the owner's allow-all is replaced by an unscoped grant of
    ///   the scope's level (`delete` without one) on the scoped repos (or on
    ///   ANY repo when repos are unrestricted), so an admin's ordinary CI
    ///   token can still push everywhere (or to exactly its scoped repos)
    ///   without being an admin credential. A kept admin short-circuit allows
    ///   every level, whatever the scope's `level`.
    ///
    /// The automation scope for a token that must call the admin API is
    /// `{"admin": true}`, with **no** `repositories`. Issued to an admin
    /// account, such a token is a full admin credential (it can create users
    /// and mint tokens), so give it an `expires_at` and keep it out of
    /// `NuGet.config`.
    ///
    /// Note: a grant for `repo == ANY` (None) is narrowed to the scope's repo
    /// allowlist when the scope restricts repos — the ANY grant is expanded into
    /// one grant per allowed repo id so the token can never reach a repo outside
    /// its scope. When the scope does not restrict repos, ANY is preserved.
    pub fn intersect_scope(&self, scope: &TokenScope) -> EffectiveSet {
        let cap = scope.level.unwrap_or(Level::Delete);
        // Allow-all survives only an unrestricted-repo scope that opts in.
        let keep_admin = self.is_admin && scope.admin && scope.repositories.is_none();

        let mut grants = Vec::new();
        for g in &self.grants {
            match (&scope.repositories, g.repo) {
                // Scope does not restrict repos: keep the grant, capped.
                (None, _) => grants.push(g.capped(cap)),
                // Grant is repo-specific: keep iff that repo is in the scope.
                (Some(allowed), Some(repo_id)) => {
                    if allowed.contains(&repo_id) {
                        grants.push(g.capped(cap));
                    }
                }
                // Grant is ANY-repo but scope restricts repos: expand ANY into
                // one grant per allowed repo so the token cannot reach others.
                (Some(allowed), None) => {
                    for &repo_id in allowed {
                        grants.push(Grant {
                            repo: Some(repo_id),
                            ..g.capped(cap)
                        });
                    }
                }
            }
        }

        if self.is_admin && !keep_admin {
            // The owner could do anything; the token keeps every package level
            // up to the scope's (never `admin`) within its repositories.
            match &scope.repositories {
                None => grants.push(Grant {
                    level: cap,
                    repo: None,
                    selector: None,
                }),
                Some(allowed) => grants.extend(allowed.iter().map(|&repo_id| Grant {
                    level: cap,
                    repo: Some(repo_id),
                    selector: None,
                })),
            }
        }

        EffectiveSet {
            is_admin: keep_admin,
            grants,
        }
    }

    /// Add the **public read** reach to this set: every grant of `public` (the
    /// built-in `anonymous` role's effective set) capped at `read`, plus, when
    /// `anonymous_read_repo` is `Some(id)`, an unscoped `read` grant on that
    /// repository (its `anonymous_read` flag).
    ///
    /// This is how a signed-in principal reads at least what an anonymous
    /// caller can. Every added grant is capped at `read` and `public`'s admin
    /// flag is ignored, so it can never add `write` / `delete` / `admin`. For
    /// a token the seam applies it **before** [`Self::intersect_scope`], so
    /// the public reach is still cut down to the token's scope (a token scoped
    /// to other repositories gains nothing from it).
    pub fn with_public_read(
        mut self,
        public: &EffectiveSet,
        anonymous_read_repo: Option<i64>,
    ) -> EffectiveSet {
        self.grants
            .extend(public.grants.iter().map(|g| g.capped(Level::Read)));
        if let Some(repo_id) = anonymous_read_repo {
            self.grants.push(Grant {
                level: Level::Read,
                repo: Some(repo_id),
                selector: None,
            });
        }
        self
    }
}

/// The package-visibility predicate returned by [`EffectiveSet::package_filter`].
#[derive(Clone)]
pub enum PackageFilter {
    /// Every package in the repo is visible (admin, or an unscoped read grant).
    AllowAll,
    /// No package is visible (no read grant covers the repo). Fail-closed.
    DenyAll,
    /// A package is visible iff **any** of these selectors matches it (union).
    Selectors(Vec<Arc<CompiledSelector>>),
    /// A package is visible iff every nested filter allows it. Used for group
    /// traversal, where the filters on the outer group, nested groups, and leaf
    /// repository must all hold.
    All(Vec<PackageFilter>),
    /// A runtime-composed package predicate. Group DAG resolution uses this to
    /// push a compact reachability check into each unique leaf search without
    /// expanding every root-to-leaf path into a separate backend query.
    Predicate(Arc<dyn Fn(&str) -> bool + Send + Sync>),
    /// A package is visible when any nested filter allows it.
    Any(Vec<PackageFilter>),
}

impl fmt::Debug for PackageFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackageFilter::AllowAll => f.write_str("AllowAll"),
            PackageFilter::DenyAll => f.write_str("DenyAll"),
            PackageFilter::Selectors(selectors) => {
                f.debug_tuple("Selectors").field(selectors).finish()
            }
            PackageFilter::All(filters) => f.debug_tuple("All").field(filters).finish(),
            PackageFilter::Predicate(_) => f.write_str("Predicate(..)"),
            PackageFilter::Any(filters) => f.debug_tuple("Any").field(filters).finish(),
        }
    }
}

impl PackageFilter {
    /// Is `package_name` visible under this filter?
    pub fn allows(&self, package_name: &str) -> bool {
        match self {
            PackageFilter::AllowAll => true,
            PackageFilter::DenyAll => false,
            PackageFilter::Selectors(sels) => sels.iter().any(|s| s.matches(package_name)),
            PackageFilter::All(filters) => filters.iter().all(|f| f.allows(package_name)),
            PackageFilter::Predicate(predicate) => predicate(package_name),
            PackageFilter::Any(filters) => filters.iter().any(|f| f.allows(package_name)),
        }
    }

    /// Intersect two package filters without losing either selector boundary.
    /// This is primarily used while descending nested repository groups.
    pub fn intersect(self, other: PackageFilter) -> PackageFilter {
        match (self, other) {
            (PackageFilter::DenyAll, _) | (_, PackageFilter::DenyAll) => PackageFilter::DenyAll,
            (PackageFilter::AllowAll, rhs) => rhs,
            (lhs, PackageFilter::AllowAll) => lhs,
            (PackageFilter::All(mut lhs), PackageFilter::All(rhs)) => {
                lhs.extend(rhs);
                PackageFilter::All(lhs)
            }
            (PackageFilter::Any(mut lhs), PackageFilter::Any(rhs)) => {
                lhs.extend(rhs);
                PackageFilter::Any(lhs)
            }
            (PackageFilter::Any(filters), rhs) | (rhs, PackageFilter::Any(filters)) => {
                PackageFilter::All(vec![PackageFilter::Any(filters), rhs])
            }
            (PackageFilter::All(mut lhs), rhs) => {
                lhs.push(rhs);
                PackageFilter::All(lhs)
            }
            (lhs, PackageFilter::All(mut rhs)) => {
                rhs.insert(0, lhs);
                PackageFilter::All(rhs)
            }
            (lhs, rhs) => PackageFilter::All(vec![lhs, rhs]),
        }
    }
}

/// An optional per-token privilege scope (from `token.scope` jsonb).
///
/// A token's effective set is `owner_set ∩ scope`. `None` on a field means that
/// dimension is not restricted (the token inherits the owner's repos and
/// levels), and `admin` is `false` unless the scope opts in to the owner's
/// `admin` role. A scope can only ever **narrow**; see
/// [`EffectiveSet::intersect_scope`].
///
/// Unknown fields are **rejected**: a mistyped key such as `{"repos": [3]}`
/// must fail to parse (a 400 at the admin API, fail-closed deny-all at
/// evaluation) rather than silently produce an unscoped token. `actions`, the
/// list of verbs that `level` and `admin` replaced, fails with a message naming
/// them. Stored scopes are always the canonical serialization of this struct
/// (the admin API re-serializes what it validated), so they keep parsing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TokenScopeWire")]
pub struct TokenScope {
    /// The highest level the token keeps; `None` ⇒ the owner's levels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<Level>,
    /// The opt-in to the admin API: the token keeps its owner's `admin` role
    /// (only while `repositories` is unrestricted).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub admin: bool,
    /// Allowed repository ids; `None` ⇒ all repos the owner can touch. A group
    /// listed here grants no read on its members (as for any principal): to
    /// read through a group, list the members it should serve from as well.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<i64>>,
}

/// What a [`TokenScope`] deserializes from: its fields, plus `actions` to
/// refuse by name.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenScopeWire {
    #[serde(default)]
    level: Option<Level>,
    #[serde(default, deserialize_with = "null_is_false")]
    admin: bool,
    #[serde(default)]
    repositories: Option<Vec<i64>>,
    #[serde(default, deserialize_with = "present")]
    actions: Option<()>,
}

impl TryFrom<TokenScopeWire> for TokenScope {
    type Error = &'static str;

    fn try_from(wire: TokenScopeWire) -> Result<Self, Self::Error> {
        if wire.actions.is_some() {
            return Err("`actions` is replaced by `level` (read, write or delete) \
                        and `admin` (true to reach the admin API)");
        }
        Ok(TokenScope {
            level: wire.level,
            admin: wire.admin,
            repositories: wire.repositories,
        })
    }
}

/// `admin: null` is `admin: false`, as an explicit `null` is an absent field
/// for the other keys.
fn null_is_false<'de, D: Deserializer<'de>>(de: D) -> Result<bool, D::Error> {
    Option::<bool>::deserialize(de).map(Option::unwrap_or_default)
}

/// `Some(())` for a key that is present, whatever its value.
fn present<'de, D: Deserializer<'de>>(de: D) -> Result<Option<()>, D::Error> {
    serde::de::IgnoredAny::deserialize(de).map(|_| Some(()))
}

/// Parse a token's raw `scope` jsonb (`Option<serde_json::Value>` as loaded from
/// the DB) into a [`TokenScope`].
///
/// * `None` (NULL column) ⇒ `None`: the token is **unscoped**. The seam
///   evaluates it as [`TokenScope::default()`]: the owner's set minus `admin`.
/// * `Some(value)` that fails to deserialize into a [`TokenScope`] ⇒ a
///   [`TokenScopeParseError`]. The caller treats this **fail-closed**: a token
///   carrying a malformed scope must not fall back to the owner's full set (that
///   would silently widen it), so it is denied / treated as an empty scope by the
///   seam.
/// * `Some(value)` that parses ⇒ `Some(scope)`.
pub fn parse_token_scope(
    raw: Option<serde_json::Value>,
) -> Result<Option<TokenScope>, TokenScopeParseError> {
    match raw {
        None => Ok(None),
        Some(value) => serde_json::from_value(value)
            .map(Some)
            .map_err(|e| TokenScopeParseError(e.to_string())),
    }
}

/// A token's stored `scope` jsonb was not a valid [`TokenScope`]. Fail-closed:
/// the seam denies rather than ignoring the (broken) scope.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid token scope: {0}")]
pub struct TokenScopeParseError(String);

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an [`EffectiveSet`] from `(level, repo, selector)` tuples.
    fn set(
        is_admin: bool,
        grants: &[(Level, Option<i64>, Option<SelectorPatterns>)],
    ) -> EffectiveSet {
        let raw = RawEffectiveSet {
            is_admin,
            grants: grants
                .iter()
                .map(|(l, r, s)| RawGrant {
                    level: l.as_str().to_string(),
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

    fn scope(level: Option<Level>, admin: bool, repositories: Option<Vec<i64>>) -> TokenScope {
        TokenScope {
            level,
            admin,
            repositories,
        }
    }

    // --- levels -------------------------------------------------------------

    #[test]
    fn levels_are_ordered() {
        assert!(Level::Read < Level::Write);
        assert!(Level::Write < Level::Delete);
        assert_eq!(Level::ALL, [Level::Read, Level::Write, Level::Delete]);
    }

    #[test]
    fn level_roundtrips_through_str() {
        for l in Level::ALL {
            assert_eq!(Level::parse(l.as_str()), Some(l));
            assert_eq!(l.to_string(), l.as_str());
        }
        assert_eq!(Level::parse("admin"), None, "admin is no level");
        assert_eq!(Level::parse("nope"), None);
    }

    // --- repo-level gate matrix --------------------------------------------

    #[test]
    fn empty_set_denies_everything() {
        let s = EffectiveSet::empty();
        for l in Level::ALL {
            assert!(!s.allows_repo(l, 1), "empty must deny {l:?}");
            assert!(!s.allows_repo(l, 2));
        }
        assert!(!s.is_admin());
    }

    #[test]
    fn admin_allows_all_levels_and_repos() {
        let s = set(true, &[]);
        for l in Level::ALL {
            assert!(s.allows_repo(l, 1));
            assert!(s.allows_repo(l, 999));
        }
        assert!(s.is_admin());
    }

    #[test]
    fn read_grant_on_repo_a_only() {
        let s = set(false, &[(Level::Read, Some(1), None)]);
        assert!(s.allows_repo(Level::Read, 1), "read on A");
        assert!(!s.allows_repo(Level::Read, 2), "deny read on B");
        assert!(!s.allows_repo(Level::Write, 1), "deny write on A");
        assert!(!s.allows_repo(Level::Delete, 1), "deny delete on A");
    }

    /// Each level includes the ones below it, and none above.
    #[test]
    fn a_grant_passes_its_level_and_every_lower_one() {
        for granted in Level::ALL {
            let s = set(false, &[(granted, Some(1), None)]);
            for required in Level::ALL {
                assert_eq!(
                    s.allows_repo(required, 1),
                    required <= granted,
                    "{granted:?} grant, {required:?} check"
                );
            }
        }
    }

    #[test]
    fn any_repo_grant_covers_every_repo() {
        let s = set(false, &[(Level::Write, None, None)]);
        assert!(s.allows_repo(Level::Write, 1));
        assert!(s.allows_repo(Level::Write, 42));
        assert!(s.allows_repo(Level::Read, 1), "write includes read");
        assert!(!s.allows_repo(Level::Delete, 1), "write excludes delete");
    }

    #[test]
    fn only_an_unscoped_any_repo_grant_covers_every_repo_ever() {
        let writer = set(false, &[(Level::Write, None, None)]);
        assert!(writer.allows_every_repo(Level::Write));
        assert!(writer.allows_every_repo(Level::Read));
        assert!(!writer.allows_every_repo(Level::Delete));
        assert!(set(true, &[]).allows_every_repo(Level::Delete), "admin");
        // One repository, or a package scope, is not every repository.
        assert!(!set(false, &[(Level::Write, Some(1), None)]).allows_every_repo(Level::Write));
        assert!(
            !set(false, &[(Level::Delete, None, Some(sel(&["acme.*"], &[])))])
                .allows_every_repo(Level::Write)
        );
        assert!(!EffectiveSet::empty().allows_every_repo(Level::Read));
    }

    #[test]
    fn multiple_grants_union() {
        let s = set(
            false,
            &[(Level::Write, Some(1), None), (Level::Read, Some(2), None)],
        );
        assert!(s.allows_repo(Level::Read, 1));
        assert!(s.allows_repo(Level::Write, 1));
        assert!(s.allows_repo(Level::Read, 2));
        assert!(!s.allows_repo(Level::Write, 2), "only read on B");
    }

    // --- selector semantics -------------------------------------------------

    #[test]
    fn selector_scoped_read_passes_repo_gate() {
        // A selector-scoped read grant must still pass the repo-level gate.
        let s = set(
            false,
            &[(Level::Read, Some(1), Some(sel(&["company.*"], &[])))],
        );
        assert!(
            s.allows_repo(Level::Read, 1),
            "selector-scoped read still reaches the repo"
        );
    }

    #[test]
    fn selector_include_matches_and_excludes_win() {
        let s = set(
            false,
            &[(
                Level::Read,
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
            &[(Level::Read, Some(1), Some(sel(&[], &["internal.*"])))],
        );
        let f = s.package_filter(1);
        assert!(f.allows("Anything.Goes"));
        assert!(!f.allows("Internal.Secret"));
    }

    #[test]
    fn unscoped_grant_yields_allow_all_filter() {
        let s = set(false, &[(Level::Read, Some(1), None)]);
        assert!(matches!(s.package_filter(1), PackageFilter::AllowAll));
        let s = set(false, &[(Level::Delete, Some(1), None)]);
        assert!(
            matches!(s.package_filter(1), PackageFilter::AllowAll),
            "a delete grant reads every package too"
        );
    }

    #[test]
    fn no_grant_yields_deny_all_filter() {
        let s = set(false, &[(Level::Read, Some(2), None)]);
        assert!(matches!(s.package_filter(1), PackageFilter::DenyAll));
        let s = set(false, &[(Level::Read, Some(1), None)]);
        assert!(
            matches!(
                s.package_filter_for(Level::Write, 1),
                PackageFilter::DenyAll
            ),
            "a read grant writes nothing"
        );
    }

    #[test]
    fn admin_filter_is_allow_all() {
        let s = set(true, &[]);
        assert!(matches!(s.package_filter(7), PackageFilter::AllowAll));
        assert!(matches!(
            s.package_filter_for(Level::Delete, 7),
            PackageFilter::AllowAll
        ));
    }

    #[test]
    fn union_of_selectors_widens_visibility() {
        // Two selector-scoped read grants: a package visible under either is OK.
        let s = set(
            false,
            &[
                (Level::Read, Some(1), Some(sel(&["a.*"], &[]))),
                (Level::Read, Some(1), Some(sel(&["b.*"], &[]))),
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
                (Level::Read, Some(1), Some(sel(&["a.*"], &[]))),
                (Level::Read, None, None),
            ],
        );
        assert!(matches!(s.package_filter(1), PackageFilter::AllowAll));
    }

    #[test]
    fn any_repo_selector_grant_filters_each_repo() {
        let s = set(false, &[(Level::Read, None, Some(sel(&["pub.*"], &[])))]);
        assert!(s.allows_repo(Level::Read, 1));
        assert!(s.allows_repo(Level::Read, 2));
        let f1 = s.package_filter(1);
        assert!(f1.allows("Pub.A"));
        assert!(!f1.allows("Priv.A"));
    }

    /// A selector-scoped grant filters every level it includes: what its
    /// holder may write it may read too, and only a grant of the level counts.
    #[test]
    fn package_filters_follow_the_level_order() {
        let s = set(
            false,
            &[
                (Level::Read, Some(1), Some(sel(&["public.*"], &[]))),
                (Level::Write, Some(1), Some(sel(&["publish.*"], &[]))),
                (Level::Delete, Some(1), Some(sel(&["retire.*"], &[]))),
            ],
        );

        let read = s.package_filter_for(Level::Read, 1);
        assert!(read.allows("Public.Tools"));
        assert!(read.allows("Publish.Tools"), "a write grant reads too");
        assert!(read.allows("Retire.Tools"), "a delete grant reads too");
        assert!(!read.allows("Other.Tools"));

        let write = s.package_filter_for(Level::Write, 1);
        assert!(write.allows("Publish.Tools"));
        assert!(write.allows("Retire.Tools"), "a delete grant writes too");
        assert!(!write.allows("Public.Tools"), "a read grant writes nothing");

        let delete = s.package_filter_for(Level::Delete, 1);
        assert!(delete.allows("Retire.Tools"));
        assert!(!delete.allows("Publish.Tools"));
        assert!(!delete.allows("Public.Tools"));
    }

    /// The gap the levels close: a selector-scoped `write` grant used to say
    /// nothing about reads, so its holder could push a package it could not
    /// read. Now the same selector filters both.
    #[test]
    fn a_selector_scoped_write_grant_also_filters_reads() {
        let s = set(
            false,
            &[(Level::Write, Some(1), Some(sel(&["acme.*"], &[])))],
        );
        assert!(s.allows_repo(Level::Read, 1));
        let read = s.package_filter(1);
        assert!(read.allows("Acme.Lib"));
        assert!(!read.allows("Other.Lib"), "the selector filters reads");
        let write = s.package_filter_for(Level::Write, 1);
        assert!(write.allows("Acme.Lib"));
        assert!(!write.allows("Other.Lib"));
    }

    #[test]
    fn intersect_requires_every_group_path_filter() {
        let outer = set(
            false,
            &[(Level::Read, Some(1), Some(sel(&["company.*"], &[])))],
        )
        .package_filter(1);
        let leaf = set(
            false,
            &[(Level::Read, Some(2), Some(sel(&["*.public"], &[])))],
        )
        .package_filter(2);
        let combined = outer.intersect(leaf);

        assert!(combined.allows("Company.Public"));
        assert!(!combined.allows("Company.Secret"));
        assert!(!combined.allows("Other.Public"));
    }

    // --- token scoping ------------------------------------------------------

    #[test]
    fn default_scope_keeps_owner_levels() {
        let s = set(
            false,
            &[(Level::Write, Some(1), None), (Level::Delete, None, None)],
        );
        let scoped = s.intersect_scope(&TokenScope::default());
        assert!(scoped.allows_repo(Level::Write, 1));
        assert!(scoped.allows_repo(Level::Delete, 7), "ANY preserved");
    }

    /// B4: an unscoped token (evaluated as the default scope) never carries
    /// the owner's `admin` role.
    #[test]
    fn default_scope_drops_admin() {
        let admin = set(true, &[]);
        let scoped = admin.intersect_scope(&TokenScope::default());
        assert!(!scoped.is_admin(), "unscoped admin token is not an admin");
        // …but keeps the admin's package-level reach everywhere.
        for l in Level::ALL {
            assert!(scoped.allows_repo(l, 1), "{l:?} kept");
            assert!(scoped.allows_repo(l, 99), "{l:?} kept on ANY repo");
        }

        // A level-restricted scope without the opt-in drops it too.
        let scoped = admin.intersect_scope(&scope(Some(Level::Read), false, None));
        assert!(!scoped.is_admin());
    }

    /// The scope's level caps every grant: lowered, never dropped, never raised.
    #[test]
    fn scope_level_caps_grants() {
        let s = set(
            false,
            &[
                (Level::Read, Some(1), None),
                (Level::Write, Some(2), None),
                (Level::Delete, Some(3), None),
            ],
        );
        let scoped = s.intersect_scope(&scope(Some(Level::Write), false, None));
        assert!(scoped.allows_repo(Level::Read, 1));
        assert!(!scoped.allows_repo(Level::Write, 1), "read is not raised");
        assert!(scoped.allows_repo(Level::Write, 2));
        assert!(
            scoped.allows_repo(Level::Write, 3),
            "delete lowered to write"
        );
        assert!(!scoped.allows_repo(Level::Delete, 3), "delete capped");

        let read_only = s.intersect_scope(&scope(Some(Level::Read), false, None));
        for repo in [1, 2, 3] {
            assert!(read_only.allows_repo(Level::Read, repo));
            assert!(!read_only.allows_repo(Level::Write, repo));
        }
    }

    #[test]
    fn scope_narrows_repositories() {
        let s = set(
            false,
            &[(Level::Read, Some(1), None), (Level::Read, Some(2), None)],
        );
        let scoped = s.intersect_scope(&scope(None, false, Some(vec![1])));
        assert!(scoped.allows_repo(Level::Read, 1));
        assert!(!scoped.allows_repo(Level::Read, 2), "repo 2 outside scope");
    }

    #[test]
    fn scope_cannot_widen_beyond_owner() {
        // Owner only reads repo 1; scoping to repo 2 or a higher level grants
        // nothing more.
        let s = set(false, &[(Level::Read, Some(1), None)]);
        let scoped = s.intersect_scope(&scope(Some(Level::Delete), true, Some(vec![2])));
        assert!(
            !scoped.allows_repo(Level::Read, 2),
            "scope can't grant repo owner lacks"
        );
        assert!(!scoped.allows_repo(Level::Read, 1), "repo 1 not in scope");
        let scoped = s.intersect_scope(&scope(Some(Level::Delete), true, None));
        assert!(!scoped.allows_repo(Level::Write, 1), "level not raised");
        assert!(!scoped.is_admin(), "admin opt-in needs an admin owner");
    }

    #[test]
    fn scope_expands_any_grant_to_allowed_repos_only() {
        // Owner writes on ANY repo; scope restricts to repo 1 at read.
        let s = set(false, &[(Level::Write, None, None)]);
        let scoped = s.intersect_scope(&scope(Some(Level::Read), false, Some(vec![1])));
        assert!(scoped.allows_repo(Level::Read, 1));
        assert!(!scoped.allows_repo(Level::Write, 1), "capped at read");
        assert!(!scoped.allows_repo(Level::Read, 2), "ANY narrowed to scope");
    }

    #[test]
    fn scope_drops_admin_unless_it_opts_in() {
        let s = set(true, &[]);
        let read_only = s.intersect_scope(&scope(Some(Level::Read), false, None));
        assert!(!read_only.is_admin(), "read-scoped token loses admin");
        // …but keeps the owner's (admin-implied) read everywhere.
        assert!(read_only.allows_repo(Level::Read, 1));
        assert!(!read_only.allows_repo(Level::Write, 1));

        let admin_scoped = s.intersect_scope(&scope(None, true, None));
        assert!(admin_scoped.is_admin(), "admin-scoped token keeps admin");
        // The kept short-circuit allows every level, whatever the scope's.
        let admin_read = s.intersect_scope(&scope(Some(Level::Read), true, None));
        assert!(admin_read.is_admin());
        assert!(admin_read.allows_repo(Level::Delete, 1));
    }

    #[test]
    fn repo_scoped_token_never_keeps_admin() {
        let s = set(true, &[]);
        // Repo restriction only (level unrestricted): admin must NOT survive.
        let scoped = s.intersect_scope(&scope(None, false, Some(vec![1])));
        assert!(!scoped.is_admin(), "repo-scoped token loses global admin");
        // The admin's package-level reach is kept on the scoped repo only.
        for l in Level::ALL {
            assert!(scoped.allows_repo(l, 1), "{l:?} on scoped repo");
            assert!(!scoped.allows_repo(l, 2), "{l:?} outside scope denied");
        }
        assert!(matches!(
            scoped.package_filter_for(Level::Write, 1),
            PackageFilter::AllowAll
        ));

        // Even opting in to `admin` does not restore it for a repo scope.
        let with_admin = s.intersect_scope(&scope(Some(Level::Write), true, Some(vec![1, 3])));
        assert!(!with_admin.is_admin());
        assert!(with_admin.allows_repo(Level::Write, 3));
        assert!(!with_admin.allows_repo(Level::Delete, 1), "capped at write");
        assert!(!with_admin.allows_repo(Level::Read, 2));
    }

    #[test]
    fn scope_preserves_selectors() {
        let s = set(false, &[(Level::Delete, Some(1), Some(sel(&["a.*"], &[])))]);
        let scoped = s.intersect_scope(&scope(Some(Level::Read), false, Some(vec![1])));
        let f = scoped.package_filter(1);
        assert!(f.allows("A.One"));
        assert!(!f.allows("B.One"));
        assert!(matches!(
            scoped.package_filter_for(Level::Write, 1),
            PackageFilter::DenyAll
        ));
    }

    // --- build / parsing edge cases ----------------------------------------

    #[test]
    fn unknown_level_is_dropped_fail_closed() {
        for level in ["admin", "superuser"] {
            let raw = RawEffectiveSet {
                is_admin: false,
                grants: vec![RawGrant {
                    level: level.to_string(),
                    repo: Some(1),
                    selector: None,
                }],
            };
            let s = EffectiveSet::build(&raw).expect("build");
            for l in Level::ALL {
                assert!(!s.allows_repo(l, 1), "{level} grants nothing");
            }
        }
    }

    #[test]
    fn invalid_glob_fails_build() {
        let raw = RawEffectiveSet {
            is_admin: false,
            grants: vec![RawGrant {
                level: "read".to_string(),
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
    fn raw_set_serde_roundtrip() {
        let raw = RawEffectiveSet {
            is_admin: false,
            grants: vec![RawGrant {
                level: "write".to_string(),
                repo: None,
                selector: Some(sel(&["x.*"], &["x.secret"])),
            }],
        };
        let json = serde_json::to_string(&raw).unwrap();
        let back: RawEffectiveSet = serde_json::from_str(&json).unwrap();
        assert_eq!(raw, back);
    }

    /// L6: a mistyped key must not parse into an unscoped token.
    #[test]
    fn token_scope_rejects_unknown_fields() {
        assert!(parse_token_scope(Some(serde_json::json!({"repos": [3]}))).is_err());
        assert!(parse_token_scope(Some(serde_json::json!({
            "level": "read",
            "repository": [3]
        })))
        .is_err());
        assert!(parse_token_scope(Some(serde_json::json!({"level": "admin"}))).is_err());
        // Every canonical (serialized) form still parses.
        for scope in [
            TokenScope::default(),
            scope(Some(Level::Read), true, None),
            scope(None, false, Some(vec![1, 2])),
            scope(Some(Level::Delete), false, Some(vec![])),
        ] {
            let stored = serde_json::to_value(&scope).unwrap();
            assert_eq!(parse_token_scope(Some(stored)).unwrap(), Some(scope));
        }
        // Explicit nulls are the same as absent fields.
        assert_eq!(
            parse_token_scope(Some(serde_json::json!({
                "level": null,
                "admin": null,
                "repositories": null
            })))
            .unwrap(),
            Some(TokenScope::default())
        );
    }

    /// `actions`, which `level` and `admin` replaced, is refused by name —
    /// stored or sent, with any value — instead of being read as unscoped.
    #[test]
    fn token_scope_refuses_actions_naming_level() {
        for actions in [
            serde_json::json!(["read"]),
            serde_json::json!(["admin"]),
            serde_json::json!([]),
            serde_json::Value::Null,
        ] {
            let err = parse_token_scope(Some(serde_json::json!({ "actions": actions })))
                .expect_err("actions refused");
            let message = err.to_string();
            assert!(message.contains("`level`"), "{message}");
            assert!(message.contains("`admin`"), "{message}");
        }
    }

    // --- public read (anonymous reach for signed-in principals) ------------

    #[test]
    fn public_read_adds_the_anonymous_grants_capped_at_read() {
        let owner = set(false, &[(Level::Write, Some(1), None)]);
        let public = set(
            false,
            &[
                (Level::Read, Some(2), Some(sel(&["pub.*"], &[]))),
                (Level::Delete, Some(4), None),
            ],
        );
        let s = owner.with_public_read(&public, Some(3));
        assert!(s.allows_repo(Level::Write, 1), "own grants kept");
        assert!(s.allows_repo(Level::Read, 2), "anonymous-role read added");
        assert!(s.allows_repo(Level::Read, 4), "anonymous delete reads");
        assert!(!s.allows_repo(Level::Write, 4), "…capped at read");
        assert!(!s.allows_repo(Level::Delete, 4));
        assert!(s.allows_repo(Level::Read, 3), "anonymous_read flag added");
        assert!(!s.allows_repo(Level::Write, 3));
        assert!(matches!(s.package_filter(3), PackageFilter::AllowAll));
        let f = s.package_filter(2);
        assert!(f.allows("Pub.Lib"), "selector preserved");
        assert!(!f.allows("Priv.Lib"));
        assert!(!s.is_admin());

        // The public set's admin flag is never carried over.
        let s = EffectiveSet::empty().with_public_read(&set(true, &[]), None);
        assert!(!s.is_admin());
        assert!(!s.allows_repo(Level::Read, 1));
    }

    #[test]
    fn public_read_never_widens_a_token_scope() {
        let owner = set(false, &[]);
        let public = set(false, &[(Level::Read, None, None)]);
        let with_public = owner.with_public_read(&public, Some(5));
        assert!(with_public.allows_repo(Level::Read, 5));
        assert!(with_public.allows_repo(Level::Read, 6));

        // A token scoped to repo 7 reaches only repo 7 (via the ANY grant).
        let scoped = with_public.intersect_scope(&scope(None, false, Some(vec![7])));
        assert!(
            !scoped.allows_repo(Level::Read, 5),
            "flag repo out of scope"
        );
        assert!(!scoped.allows_repo(Level::Read, 6), "ANY narrowed");
        assert!(scoped.allows_repo(Level::Read, 7));
        assert!(!scoped.allows_repo(Level::Write, 7), "nor raised");
    }

    #[test]
    fn token_scope_serde_omits_unset_fields() {
        let s = scope(Some(Level::Read), false, None);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"level":"read"}"#);
        let back: TokenScope = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);

        let s = scope(None, true, Some(vec![4]));
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"admin":true,"repositories":[4]}"#);
        assert_eq!(serde_json::to_string(&TokenScope::default()).unwrap(), "{}");
    }
}
