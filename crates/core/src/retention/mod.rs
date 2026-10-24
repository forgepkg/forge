//! Retention / cleanup policy model and the pure decision evaluator.
//!
//! This module is the **format-agnostic** core of retention: it defines the
//! serde [`RetentionPolicy`] stored in `repository.retention_policy` (with
//! [`validate_policy`]) and a **pure** evaluator ([`evaluate`] / [`evaluate_proxy`])
//! that, given a policy and a component/proxy snapshot, computes the set of
//! versions to delete or unlist. Versions are ordered through the
//! [`crate::format::Format`] seam, never by importing a concrete format.
//!
//! The DB-touching pieces live in [`apply`](mod@apply) and [`worker`] (the
//! claim ledger in `forge_db::retention_dao`) and route all blob GC through
//! the transactional blob outbox; the model and the evaluator perform **no
//! I/O** and are fully unit-testable.

pub mod apply;
pub mod evaluate;
pub mod files;
pub mod images;
pub mod model;
pub mod worker;

pub use apply::{apply, ApplyContext, RunFence};
pub use evaluate::{
    evaluate, evaluate_proxy, CandidateComponent, Decision, DecisionReason, ProxyCandidate,
    ProxyDecision,
};
pub use model::{
    validate_policy, Action, Criteria, PolicyError, ReleaseType, RetentionPolicy, RetentionRule,
    Scope, SizeBudget, POLICY_VERSION,
};
pub use worker::{FormatResolver, RetentionConfig, RetentionWorker, WorkerError};

/// Leave out of `decisions` the versions retention never touches: every
/// version a package tag names (npm's dist-tags, `latest` included).
/// Returns how many decisions were dropped. The apply path checks again,
/// with the version locked.
pub async fn spare_protected(
    pool: &sqlx::PgPool,
    repository_id: i64,
    decisions: &mut Vec<Decision>,
) -> sqlx::Result<usize> {
    if decisions.is_empty() {
        return Ok(0);
    }
    let tagged: std::collections::HashSet<(String, String)> =
        forge_db::tag_dao::tagged_versions(pool, repository_id)
            .await?
            .into_iter()
            .collect();
    let before = decisions.len();
    decisions.retain(|d| !tagged.contains(&(d.package_name.clone(), d.version.clone())));
    Ok(before - decisions.len())
}
