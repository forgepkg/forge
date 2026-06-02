//! Retention / cleanup policy model and the pure decision evaluator (slice 12.1).
//!
//! This module is the **format-agnostic** core of retention: it defines the
//! serde [`RetentionPolicy`] stored in `repository.retention_policy` (with
//! [`validate_policy`]) and a **pure** evaluator ([`evaluate`] / [`evaluate_proxy`])
//! that, given a policy and a component/proxy snapshot, computes the set of
//! versions to delete or unlist. Versions are ordered through the
//! [`crate::format::Format`] seam, never by importing a concrete format.
//!
//! The DB-touching pieces (claim/apply/worker) live in later phases and reuse
//! the slice-1 transactional blob outbox for all blob GC — this module performs
//! **no I/O** and is fully unit-testable.

pub mod apply;
pub mod evaluate;
pub mod model;

pub use apply::{apply, ApplyContext};
pub use evaluate::{
    evaluate, evaluate_proxy, CandidateComponent, Decision, DecisionReason, ProxyCandidate,
    ProxyDecision,
};
pub use model::{
    validate_policy, Action, Criteria, PolicyError, ReleaseType, RetentionPolicy, RetentionRule,
    Scope, POLICY_VERSION,
};
