//! Fine-grained RBAC: the **pure** policy evaluator.
//!
//! This module hosts the database-free, cache-free, synchronous core of the
//! authorization model — the resolved [`EffectiveSet`] and the decision
//! functions over it ([`EffectiveSet::allows_repo`],
//! [`EffectiveSet::package_filter`], [`EffectiveSet::intersect_scope`]).
//!
//! The *seam* that the rest of the codebase calls (`can_read` / `can_write` /
//! `can_delete`) lives in [`crate::auth::authz`] (the [`Authz`] service). That
//! service loads a [`RawEffectiveSet`] through the cached DB loader ([`cache`]),
//! [`build`](EffectiveSet::build)s it, applies any token scope, and answers the
//! seam predicates from the result. Keeping the evaluator pure here makes the
//! whole decision matrix testable in isolation, with no DB.
//!
//! [`Authz`]: crate::auth::authz::Authz

pub mod cache;
pub mod eval;

pub use cache::{
    invalidate_all, invalidate_anonymous, invalidate_user, load_anonymous_effective,
    load_role_effective, load_user_effective, LoadError, DEFAULT_TTL, NS_AUTHZ,
};
pub use eval::{
    parse_token_scope, CompiledSelector, EffectiveSet, Grant, Level, PackageFilter,
    RawEffectiveSet, RawGrant, SelectorCompileError, SelectorPatterns, TokenScope,
};
