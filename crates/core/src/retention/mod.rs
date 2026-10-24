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
    let tagged = tagged_versions(pool, repository_id).await?;
    let before = decisions.len();
    decisions.retain(|d| !tagged.contains(&(d.package_name.clone(), d.version.clone())));
    Ok(before - decisions.len())
}

/// Package-tagged versions must be excluded from hosted budget victims.
pub async fn tagged_candidate_ids(
    pool: &sqlx::PgPool,
    repository_id: i64,
    candidates: &[evaluate::CandidateComponent],
) -> sqlx::Result<std::collections::HashSet<i64>> {
    if candidates.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let tagged = tagged_versions(pool, repository_id).await?;
    Ok(candidates
        .iter()
        .filter(|candidate| {
            tagged.contains(&(candidate.package_name.clone(), candidate.version.clone()))
        })
        .map(|candidate| candidate.component_id)
        .collect())
}

async fn tagged_versions(
    pool: &sqlx::PgPool,
    repository_id: i64,
) -> sqlx::Result<std::collections::HashSet<(String, String)>> {
    Ok(forge_db::tag_dao::tagged_versions(pool, repository_id)
        .await?
        .into_iter()
        .collect())
}
