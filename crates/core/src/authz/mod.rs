//! Fine-grained RBAC (§12.4): the **pure** policy evaluator.
//!
//! This module hosts the database-free, cache-free, synchronous core of the
//! authorization model — the resolved [`EffectiveSet`] and the decision
//! functions over it ([`EffectiveSet::allows_repo`],
//! [`EffectiveSet::package_filter`], [`EffectiveSet::intersect_scope`]).
//!
//! The *seam* that the rest of the codebase calls (`can_read` / `can_write` /
//! `can_admin`) lives in [`crate::auth::authz`] (the [`Authz`] service). A later
//! phase wires that service's cached DB loader to produce a [`RawEffectiveSet`],
//! [`build`](EffectiveSet::build)s it, applies any token scope, and answers the
//! seam predicates from the result. Keeping the evaluator pure here makes the
//! whole decision matrix testable in isolation, with no DB.
//!
//! [`Authz`]: crate::auth::authz::Authz

pub mod eval;

pub use eval::{
    Action, CompiledSelector, EffectiveSet, Grant, PackageFilter, RawEffectiveSet, RawGrant,
    SelectorCompileError, SelectorPatterns, TokenScope,
};
