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
pub mod schedule;
pub mod worker;

pub use apply::{apply, ApplyContext, RunFence};
pub use evaluate::{
    evaluate, evaluate_proxy, CandidateComponent, Decision, DecisionReason, ProxyCandidate,
    ProxyDecision, Selectors,
};
pub use model::{
    validate_policy, Action, Criteria, PolicyError, ReleaseType, RetentionPolicy, RetentionRule,
    Scope, SizeBudget, SizeBudgetSummary, POLICY_VERSION,
};
pub use worker::{FormatResolver, RetentionConfig, RetentionWorker, WorkerError};

/// The hosted `candidates` a package tag names (npm's dist-tags, `latest`
/// included): retention never touches them, whatever a rule or the size
/// budget decides. The apply path checks again, with the version locked.
pub async fn tagged_candidate_ids(
    pool: &sqlx::PgPool,
    repository_id: i64,
    candidates: &[evaluate::CandidateComponent],
) -> sqlx::Result<std::collections::HashSet<i64>> {
    if candidates.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let tagged: std::collections::HashSet<(String, String)> =
        forge_db::tag_dao::tagged_versions(pool, repository_id)
            .await?
            .into_iter()
            .collect();
    Ok(candidates
        .iter()
        .filter(|candidate| {
            tagged.contains(&(candidate.package_name.clone(), candidate.version.clone()))
        })
        .map(|candidate| candidate.component_id)
        .collect())
}

/// Why the content selectors a policy names could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum SelectorError {
    /// A rule names a selector that does not exist (any more).
    #[error("content selector {0:?} does not exist")]
    Missing(String),
    /// A selector's stored patterns do not read or compile.
    #[error("content selector {name:?} cannot be used: {reason}")]
    Invalid {
        /// The selector's name.
        name: String,
        /// What is wrong with it.
        reason: String,
    },
    /// Reading the selectors failed.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// The content selectors `policy`'s rules name (`selector`), read from
/// `content_selector` and compiled, for the evaluator. A name that matches
/// no selector is an error: a run or a preview then refuses the policy
/// instead of evaluating a rule that would admit nothing.
pub async fn resolve_selectors(
    pool: &sqlx::PgPool,
    policy: &model::RetentionPolicy,
) -> Result<Selectors, SelectorError> {
    let names = model::selector_names(policy);
    let mut selectors = Selectors::none();
    if names.is_empty() {
        return Ok(selectors);
    }
    let stored = forge_db::authz_dao::list_content_selectors(pool).await?;
    for name in names {
        let Some(row) = stored.iter().find(|s| s.name == name) else {
            return Err(SelectorError::Missing(name));
        };
        let invalid = |reason: String| SelectorError::Invalid {
            name: name.clone(),
            reason,
        };
        let (includes, excludes) = forge_db::authz_dao::SelectorRow {
            id: row.id,
            includes: row.includes.clone(),
            excludes: row.excludes.clone(),
        }
        .patterns()
        .map_err(|e| invalid(e.to_string()))?;
        let compiled = crate::authz::SelectorPatterns { includes, excludes }
            .compile()
            .map_err(|e| invalid(e.to_string()))?;
        selectors.insert(name.clone(), compiled);
    }
    Ok(selectors)
}
