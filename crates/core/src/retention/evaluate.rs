//! The **pure** retention evaluator.
//!
//! Given a policy and a snapshot of a repository's components (or a proxy repo's
//! cached versions), [`evaluate`] / [`evaluate_proxy`] compute the set of
//! `Decision`s the worker should apply. There is **no I/O** here: every input is
//! plain data plus a `&dyn Format` used only to order versions, so the whole
//! algorithm is unit-testable without a database or clock.
//!
//! ## Algorithm (hosted, [`evaluate`])
//!
//! 1. Filter out components whose version fails to apply to any rule's
//!    `release_type` / `package_name_prefix` — handled per rule.
//! 2. **Group by package id.** Within a group, order versions newest-first using
//!    [`Format::compare_versions`] (format-agnostic — we never import a concrete
//!    format here).
//! 3. **Compute protections per group, per rule.** Each rule's protections
//!    are taken over that rule's own *pool* — the group's versions its
//!    `release_type` / `package_name_prefix` filters admit: `keep_last_n` is
//!    the newest N **listed** versions of the pool (unlisted versions neither
//!    count nor are protected), `keep_n_most_downloaded` the N most-recently
//!    downloaded versions of the pool, listed or not (nulls last). The
//!    protected set is the **union** over all rules; a protected version is
//!    **never** deleted or unlisted, by any rule.
//! 4. For each version, a rule *selects* it iff the rule's filters match **and**
//!    all of the rule's present triggers are satisfied (ANDed):
//!    `older_than_days` (age since `created_at`) and `not_downloaded_for_days`
//!    (days since the last download or, for a version never downloaded, since
//!    it was published — so a fresh push is not cold on its first run).
//! 5. Protection overrides selection. Otherwise the highest-severity action
//!    wins (`hard_delete` > `unlist`).
//!
//! ## Proxy ([`evaluate_proxy`])
//!
//! `scope: proxy_cached` rules evict a cached version when `not_pulled_for_days`
//! is satisfied, comparing against `last_downloaded_at` or, when never pulled,
//! `first_seen_at`. Only versions whose bytes are cached locally are
//! candidates. Their protections work as on hosted rules, over each package's
//! cached versions: `keep_last_n` keeps the newest N the upstream lists,
//! `keep_n_most_downloaded` the N pulled last, and a version any proxy rule
//! keeps is never evicted. Proxy entries are never unlisted — eviction always
//! deletes the cached bytes (the version stays listed and re-caches on the
//! next pull).

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use crate::format::Format;
use crate::retention::model::{
    Action, Criteria, ReleaseType, RetentionPolicy, RetentionRule, Scope,
};

/// One hosted component in the evaluation snapshot. All fields come straight
/// from the `component` / primary `asset` rows; `version` is **normalized**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateComponent {
    /// `component.id` — identifies the row the apply path will lock & delete.
    pub component_id: i64,
    /// Lowercased package id (`component.name`), for prefix filtering + grouping.
    pub package_name: String,
    /// Normalized version string (ordered via [`Format::compare_versions`]).
    pub version: String,
    /// Whether the version is currently listed.
    pub listed: bool,
    /// When the component was created (for `older_than_days`).
    pub created_at: DateTime<Utc>,
    /// Last download timestamp, or `None` if never downloaded.
    pub last_downloaded_at: Option<DateTime<Utc>>,
    /// Sum of this version's asset sizes, in bytes.
    pub size_bytes: u64,
}

/// One proxy cached version in the evaluation snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCandidate {
    /// `proxy_cached_version.id`.
    pub cached_version_id: i64,
    /// Lowercased package id, for prefix filtering and grouping.
    pub package_name: String,
    /// Normalized version string (ordered via [`Format::compare_versions`]).
    pub version: String,
    /// Whether the upstream lists the version (`keep_last_n` counts only
    /// listed versions).
    pub listed: bool,
    /// When the entry was first cached (fallback for "never pulled").
    pub first_seen_at: DateTime<Utc>,
    /// Last pull timestamp, or `None` if never pulled since caching.
    pub last_downloaded_at: Option<DateTime<Utc>>,
    /// Size of the locally cached version, in bytes.
    pub size_bytes: u64,
}

/// The action plus provenance the apply path / audit needs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Decision {
    /// `component.id` to act on.
    pub component_id: i64,
    /// Package id (echoed for the audit row).
    pub package_name: String,
    /// Normalized version (echoed for the audit row).
    pub version: String,
    /// The chosen action (highest severity across matching rules).
    pub action: Action,
    /// The id of the rule that produced the winning action.
    pub rule_id: String,
    /// Why this decision was made (matched triggers), for the audit `reason`.
    pub reason: DecisionReason,
}

/// A proxy eviction decision (always a delete).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProxyDecision {
    /// `proxy_cached_version.id` to evict.
    pub cached_version_id: i64,
    /// Package id (echoed for the audit row).
    pub package_name: String,
    /// Normalized version (echoed for the audit row).
    pub version: String,
    /// The id of the rule that produced this eviction.
    pub rule_id: String,
    /// Why this entry was evicted.
    pub reason: DecisionReason,
}

/// A package-repository size-budget plan after ordinary rules have run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSizeBudgetPlan {
    pub hosted: Vec<Decision>,
    pub proxy: Vec<ProxyDecision>,
    pub size_before: u64,
    pub size_after: u64,
    pub target_bytes: u64,
    pub target_reached: bool,
}

/// Structured explanation of why a version was selected, recorded on the audit
/// row's `reason` jsonb.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecisionReason {
    /// Whether `older_than_days` was a matched trigger (and its threshold).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub older_than_days: Option<u32>,
    /// Whether `not_downloaded_for_days` was a matched trigger.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_downloaded_for_days: Option<u32>,
    /// Whether `not_pulled_for_days` was a matched trigger (proxy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_pulled_for_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_budget: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Whether a **normalized** version string denotes a prerelease.
///
/// Format-agnostic heuristic: a normalized version carrying a prerelease label
/// renders it after a `-` (NuGet's `to_normalized_string`, SemVer 2.0.0). We do
/// not import a concrete format here, honoring the "order/classify via the seam"
/// rule. Build metadata (`+...`) is already stripped during normalization.
fn is_prerelease(normalized_version: &str) -> bool {
    normalized_version.contains('-')
}

/// Whether a rule's static filters (`release_type`, `package_name_prefix`)
/// admit a given component, independent of its triggers.
fn rule_filters_match(rule: &RetentionRule, package_name: &str, version: &str) -> bool {
    match rule.release_type {
        ReleaseType::Any => {}
        ReleaseType::Releases if is_prerelease(version) => return false,
        ReleaseType::Prereleases if !is_prerelease(version) => return false,
        _ => {}
    }
    if let Some(prefix) = &rule.package_name_prefix {
        // Case-insensitive prefix match. `package_name` is already lowercased by
        // the loader; lowercase the configured prefix to be safe.
        if !package_name.starts_with(&crate::format::lower_invariant(prefix)) {
            return false;
        }
    }
    true
}

/// Whole-days elapsed from `then` to `now` (floored). Negative spans (a
/// `created_at` in the future relative to `now`) yield 0.
fn days_since(now: DateTime<Utc>, then: DateTime<Utc>) -> i64 {
    let secs = (now - then).num_seconds();
    if secs <= 0 {
        0
    } else {
        secs / 86_400
    }
}

/// Evaluate the hosted `Criteria` triggers (ANDed) for one component. Returns
/// `Some(reason)` when **all present triggers** match, else `None`. A criteria
/// block with no triggers never selects (the rule was rejected at validation
/// time, but we stay defensive here).
fn triggers_match(
    c: &Criteria,
    now: DateTime<Utc>,
    cand: &CandidateComponent,
) -> Option<DecisionReason> {
    let mut any_trigger = false;
    let mut reason = DecisionReason {
        older_than_days: None,
        not_downloaded_for_days: None,
        not_pulled_for_days: None,
        size_budget: None,
        target_bytes: None,
        size_bytes: None,
        last_used_at: None,
    };

    if let Some(days) = c.older_than_days {
        any_trigger = true;
        if days_since(now, cand.created_at) < days as i64 {
            return None;
        }
        reason.older_than_days = Some(days);
    }

    if let Some(days) = c.not_downloaded_for_days {
        any_trigger = true;
        // Never downloaded counts from publication (as Nexus does, and as the
        // proxy rules count from `first_seen_at`): treating it as always cold
        // hard-deleted a version pushed minutes before the run.
        let reference = cand.last_downloaded_at.unwrap_or(cand.created_at);
        let cold = days_since(now, reference) >= days as i64;
        if !cold {
            return None;
        }
        reason.not_downloaded_for_days = Some(days);
    }

    if any_trigger {
        Some(reason)
    } else {
        None
    }
}

/// What a rule's protections look at in a candidate: a hosted component or a
/// proxy's cached version.
trait Protectable {
    fn package_name(&self) -> &str;
    fn version(&self) -> &str;
    fn listed(&self) -> bool;
    fn last_downloaded_at(&self) -> Option<DateTime<Utc>>;
}

impl Protectable for CandidateComponent {
    fn package_name(&self) -> &str {
        &self.package_name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn listed(&self) -> bool {
        self.listed
    }
    fn last_downloaded_at(&self) -> Option<DateTime<Utc>> {
        self.last_downloaded_at
    }
}

impl Protectable for ProxyCandidate {
    fn package_name(&self) -> &str {
        &self.package_name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn listed(&self) -> bool {
        self.listed
    }
    fn last_downloaded_at(&self) -> Option<DateTime<Utc>> {
        self.last_downloaded_at
    }
}

/// Group candidates by package name in one pass, in the order the packages
/// first appear (each group keeps its candidates' snapshot order).
fn group_by_package<C: Protectable>(candidates: &[C]) -> Vec<Vec<&C>> {
    let mut groups: Vec<Vec<&C>> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for cand in candidates {
        let i = *index.entry(cand.package_name()).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[i].push(cand);
    }
    groups
}

/// Compute which of a group's versions (indices into its newest-first
/// ordering) are **protected**: the union, over every rule of `scope`, of
/// that rule's `keep_last_n` / `keep_n_most_downloaded` protections.
///
/// Each rule's protections are computed over the versions the rule itself
/// governs — those its `release_type` / `package_name_prefix` filters admit —
/// never over the whole package. Otherwise a `releases`-only rule with
/// `keep_last_n: 3` would "protect" the three newest prereleases and leave
/// every stable release unprotected. `keep_last_n` further counts only
/// **listed** versions, so unlisted versions cannot use up its slots;
/// `keep_n_most_downloaded` ranks listed and unlisted versions alike by
/// download recency (see [`Criteria`]).
///
/// `ordered` is the group's candidates sorted newest-first (by version): a
/// hosted package's components, or a proxy package's cached versions.
fn protected_indices<C: Protectable>(
    policy: &RetentionPolicy,
    scope: Scope,
    ordered: &[&C],
) -> Vec<bool> {
    let mut protected = vec![false; ordered.len()];

    for rule in policy.rules.iter().filter(|r| r.scope == scope) {
        let c = &rule.criteria;
        if !c.has_protection() {
            continue;
        }
        // The rule's pool, still newest-first.
        let pool: Vec<usize> = (0..ordered.len())
            .filter(|&i| rule_filters_match(rule, ordered[i].package_name(), ordered[i].version()))
            .collect();

        if let Some(n) = c.keep_last_n {
            for &idx in pool
                .iter()
                .filter(|&&i| ordered[i].listed())
                .take(n as usize)
            {
                protected[idx] = true;
            }
        }

        if let Some(n) = c.keep_n_most_downloaded {
            // Order by download recency: most-recent first, nulls last. The
            // sort is stable, so ties keep the pool's version-desc order.
            let mut by_download = pool.clone();
            by_download.sort_by(|&a, &b| {
                match (
                    ordered[a].last_downloaded_at(),
                    ordered[b].last_downloaded_at(),
                ) {
                    (Some(x), Some(y)) => y.cmp(&x), // more recent first
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            });
            for &idx in by_download.iter().take(n as usize) {
                protected[idx] = true;
            }
        }
    }

    protected
}

/// Evaluate a hosted retention policy over a component snapshot, producing the
/// ordered set of decisions to apply. **Pure**: no I/O, `now` is injected.
///
/// `format` is used only to order versions within a package group. The cost is
/// linear in the snapshot plus sorting each package's versions, but it is
/// still CPU-bound on a large repository, so async callers run it on the
/// blocking pool.
pub fn evaluate(
    format: &dyn Format,
    now: DateTime<Utc>,
    policy: &RetentionPolicy,
    candidates: &[CandidateComponent],
) -> Vec<Decision> {
    if !policy.enabled {
        return Vec::new();
    }

    let mut decisions = Vec::new();

    for mut group in group_by_package(candidates) {
        // This group's components, newest-first by version.
        group.sort_by(|a, b| format.compare_versions(&b.version, &a.version)); // desc

        let protected = protected_indices(policy, Scope::Hosted, &group);

        for (idx, cand) in group.iter().enumerate() {
            if protected[idx] {
                continue; // protection always wins — never delete/unlist.
            }

            // Find the highest-severity action among rules that select it.
            let mut winning: Option<(&RetentionRule, DecisionReason)> = None;
            for rule in policy.rules.iter().filter(|r| r.scope == Scope::Hosted) {
                if !rule_filters_match(rule, &cand.package_name, &cand.version) {
                    continue;
                }
                let Some(reason) = triggers_match(&rule.criteria, now, cand) else {
                    continue;
                };
                let better = match &winning {
                    None => true,
                    Some((cur, _)) => rule.action.severity() > cur.action.severity(),
                };
                if better {
                    winning = Some((rule, reason));
                }
            }

            if let Some((rule, reason)) = winning {
                // Unlisting an already-unlisted version is a no-op: skip it
                // so a standing unlist rule does not re-touch `updated_at`
                // and append an audit row for the same versions every run.
                if rule.action == Action::Unlist && !cand.listed {
                    continue;
                }
                decisions.push(Decision {
                    component_id: cand.component_id,
                    package_name: cand.package_name.clone(),
                    version: cand.version.clone(),
                    action: rule.action,
                    rule_id: rule.id.clone(),
                    reason,
                });
            }
        }
    }

    decisions
}

/// Evaluate the proxy-cached eviction rules over a `proxy_cached_version`
/// snapshot. **Pure**: no I/O. Only `scope: proxy_cached` rules participate.
///
/// `format` orders each package's cached versions newest-first, for the
/// rules' `keep_last_n` protections; a version any proxy rule protects is
/// never evicted. Like [`evaluate`], async callers run it on the blocking
/// pool.
pub fn evaluate_proxy(
    format: &dyn Format,
    now: DateTime<Utc>,
    policy: &RetentionPolicy,
    candidates: &[ProxyCandidate],
) -> Vec<ProxyDecision> {
    if !policy.enabled {
        return Vec::new();
    }

    let mut decisions = Vec::new();

    for mut group in group_by_package(candidates) {
        // This package's cached versions, newest-first by version.
        group.sort_by(|a, b| format.compare_versions(&b.version, &a.version)); // desc

        let protected = protected_indices(policy, Scope::ProxyCached, &group);

        for (idx, cand) in group.iter().enumerate() {
            if protected[idx] {
                continue; // protection always wins — never evict.
            }

            let mut winning: Option<(&RetentionRule, u32)> = None;
            for rule in policy
                .rules
                .iter()
                .filter(|r| r.scope == Scope::ProxyCached)
            {
                // release_type / prefix filters apply to proxy entries too.
                if !rule_filters_match(rule, &cand.package_name, &cand.version) {
                    continue;
                }
                let Some(days) = rule.criteria.not_pulled_for_days else {
                    continue;
                };
                // Use last pull, else first-seen (never pulled since caching).
                let reference = cand.last_downloaded_at.unwrap_or(cand.first_seen_at);
                if days_since(now, reference) < days as i64 {
                    continue;
                }
                // All proxy rules delete; first matching rule is enough, but keep
                // the one with the smallest threshold for the most specific reason.
                let take = match &winning {
                    None => true,
                    Some((_, cur_days)) => days < *cur_days,
                };
                if take {
                    winning = Some((rule, days));
                }
            }

            if let Some((rule, days)) = winning {
                decisions.push(ProxyDecision {
                    cached_version_id: cand.cached_version_id,
                    package_name: cand.package_name.clone(),
                    version: cand.version.clone(),
                    rule_id: rule.id.clone(),
                    reason: DecisionReason {
                        older_than_days: None,
                        not_downloaded_for_days: None,
                        not_pulled_for_days: Some(days),
                        size_budget: None,
                        target_bytes: None,
                        size_bytes: None,
                        last_used_at: None,
                    },
                });
            }
        }
    }

    decisions
}

/// Add least-recently-used hard-delete decisions after package rules. The
/// newest listed hosted version and all rule protections remain protected.
pub fn evaluate_size_budget(
    format: &dyn Format,
    policy: &RetentionPolicy,
    hosted: &[CandidateComponent],
    proxy: &[ProxyCandidate],
    hosted_decisions: &[Decision],
    proxy_decisions: &[ProxyDecision],
    repository_size_bytes: u64,
) -> PackageSizeBudgetPlan {
    let Some(budget) = policy.size_budget else {
        return PackageSizeBudgetPlan {
            hosted: Vec::new(),
            proxy: Vec::new(),
            size_before: 0,
            size_after: 0,
            target_bytes: 0,
            target_reached: true,
        };
    };
    let target_bytes = budget.target_bytes();
    let size_before = repository_size_bytes;
    let mut size_after = size_before.saturating_sub(
        hosted_decisions
            .iter()
            .filter(|d| d.action == Action::HardDelete)
            .filter_map(|d| hosted.iter().find(|c| c.component_id == d.component_id))
            .map(|c| c.size_bytes)
            .chain(
                proxy_decisions
                    .iter()
                    .filter_map(|d| {
                        proxy
                            .iter()
                            .find(|c| c.cached_version_id == d.cached_version_id)
                    })
                    .map(|c| c.size_bytes),
            )
            .fold(0u64, u64::saturating_add),
    );
    let mut hosted_out = Vec::new();
    let mut proxy_out = Vec::new();
    if size_after > budget.max_bytes {
        let hosted_deleted: HashSet<i64> = hosted_decisions
            .iter()
            .filter(|d| d.action == Action::HardDelete)
            .map(|d| d.component_id)
            .collect();
        let proxy_deleted: HashSet<i64> = proxy_decisions
            .iter()
            .map(|d| d.cached_version_id)
            .collect();
        let mut eligible_hosted = Vec::new();
        for mut group in group_by_package(hosted) {
            group.sort_by(|a, b| format.compare_versions(&b.version, &a.version));
            let protected = protected_indices(policy, Scope::Hosted, &group);
            let newest_listed = group.iter().find(|c| c.listed).map(|c| c.component_id);
            for (idx, candidate) in group.into_iter().enumerate() {
                if !protected[idx]
                    && newest_listed != Some(candidate.component_id)
                    && !hosted_deleted.contains(&candidate.component_id)
                {
                    eligible_hosted.push(candidate);
                }
            }
        }
        eligible_hosted.sort_by(|a, b| {
            a.last_downloaded_at
                .unwrap_or(a.created_at)
                .cmp(&b.last_downloaded_at.unwrap_or(b.created_at))
                .then_with(|| a.created_at.cmp(&b.created_at))
                .then_with(|| format.compare_versions(&a.version, &b.version))
                .then_with(|| a.component_id.cmp(&b.component_id))
        });
        for candidate in eligible_hosted {
            if size_after <= target_bytes {
                break;
            }
            hosted_out.push(Decision {
                component_id: candidate.component_id,
                package_name: candidate.package_name.clone(),
                version: candidate.version.clone(),
                action: Action::HardDelete,
                rule_id: "size_budget".into(),
                reason: DecisionReason {
                    older_than_days: None,
                    not_downloaded_for_days: None,
                    not_pulled_for_days: None,
                    size_budget: Some(budget.max_bytes),
                    target_bytes: Some(target_bytes),
                    size_bytes: Some(candidate.size_bytes),
                    last_used_at: Some(
                        candidate.last_downloaded_at.unwrap_or(candidate.created_at),
                    ),
                },
            });
            size_after = size_after.saturating_sub(candidate.size_bytes);
        }
        let mut proxy_protected = HashSet::new();
        for mut group in group_by_package(proxy) {
            group.sort_by(|a, b| format.compare_versions(&b.version, &a.version));
            let protected = protected_indices(policy, Scope::ProxyCached, &group);
            proxy_protected.extend(
                group
                    .into_iter()
                    .zip(protected)
                    .filter(|(_, protected)| *protected)
                    .map(|(candidate, _)| candidate.cached_version_id),
            );
        }
        let mut eligible_proxy: Vec<&ProxyCandidate> = proxy
            .iter()
            .filter(|c| !proxy_deleted.contains(&c.cached_version_id))
            .filter(|c| !proxy_protected.contains(&c.cached_version_id))
            .collect();
        eligible_proxy.sort_by(|a, b| {
            a.last_downloaded_at
                .unwrap_or(a.first_seen_at)
                .cmp(&b.last_downloaded_at.unwrap_or(b.first_seen_at))
                .then_with(|| a.first_seen_at.cmp(&b.first_seen_at))
                .then_with(|| format.compare_versions(&a.version, &b.version))
                .then_with(|| a.cached_version_id.cmp(&b.cached_version_id))
        });
        for candidate in eligible_proxy {
            if size_after <= target_bytes {
                break;
            }
            proxy_out.push(ProxyDecision {
                cached_version_id: candidate.cached_version_id,
                package_name: candidate.package_name.clone(),
                version: candidate.version.clone(),
                rule_id: "size_budget".into(),
                reason: DecisionReason {
                    older_than_days: None,
                    not_downloaded_for_days: None,
                    not_pulled_for_days: None,
                    size_budget: Some(budget.max_bytes),
                    target_bytes: Some(target_bytes),
                    size_bytes: Some(candidate.size_bytes),
                    last_used_at: Some(
                        candidate
                            .last_downloaded_at
                            .unwrap_or(candidate.first_seen_at),
                    ),
                },
            });
            size_after = size_after.saturating_sub(candidate.size_bytes);
        }
    }
    PackageSizeBudgetPlan {
        hosted: hosted_out,
        proxy: proxy_out,
        size_before,
        size_after,
        target_bytes,
        target_reached: size_after <= target_bytes || size_after <= budget.max_bytes,
    }
}

/// IDs a size-budget pass must never remove because of existing package
/// protections or because they are the newest listed hosted versions.
pub fn size_budget_protected_ids(
    format: &dyn Format,
    policy: &RetentionPolicy,
    hosted: &[CandidateComponent],
    proxy: &[ProxyCandidate],
) -> (HashSet<i64>, HashSet<i64>) {
    let mut hosted_ids = HashSet::new();
    for mut group in group_by_package(hosted) {
        group.sort_by(|a, b| format.compare_versions(&b.version, &a.version));
        let protected = protected_indices(policy, Scope::Hosted, &group);
        let newest_listed = group.iter().find(|c| c.listed).map(|c| c.component_id);
        hosted_ids.extend(
            group
                .iter()
                .enumerate()
                .filter(|(i, c)| protected[*i] || newest_listed == Some(c.component_id))
                .map(|(_, c)| c.component_id),
        );
    }
    let mut proxy_ids = HashSet::new();
    for mut group in group_by_package(proxy) {
        group.sort_by(|a, b| format.compare_versions(&b.version, &a.version));
        let protected = protected_indices(policy, Scope::ProxyCached, &group);
        proxy_ids.extend(
            group
                .iter()
                .enumerate()
                .filter(|(i, _)| protected[*i])
                .map(|(_, c)| c.cached_version_id),
        );
    }
    (hosted_ids, proxy_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FormatError, ParsedUpload};
    use crate::format::ReadSeek;
    use crate::retention::model::POLICY_VERSION;
    use chrono::TimeZone;
    use std::cmp::Ordering;

    /// A self-contained [`Format`] for the evaluator's pure unit tests.
    ///
    /// We deliberately do **not** depend on `forge-format-nuget` here: pulling it in as
    /// a dev-dependency would create two copies of `forge-core` in the test
    /// graph (the cycle the lib's `tests/` integration crate tolerates but a
    /// `#[cfg(test)]` module cannot). Ordering only needs to be a correct
    /// version order for the small inputs used below: SemVer-ish numeric tuple,
    /// with a prerelease label (`-...`) sorting before the matching release.
    struct TestFormat;

    impl Format for TestFormat {
        fn id(&self) -> &'static str {
            "test"
        }
        fn parse_upload(&self, _f: &mut dyn ReadSeek) -> Result<ParsedUpload, FormatError> {
            unreachable!("evaluator tests never parse")
        }
        fn normalize_version(&self, raw: &str) -> Result<String, FormatError> {
            Ok(raw.trim().to_string())
        }
        fn compare_versions(&self, a: &str, b: &str) -> Ordering {
            let (an, ap) = a.split_once('-').map_or((a, None), |(n, p)| (n, Some(p)));
            let (bn, bp) = b.split_once('-').map_or((b, None), |(n, p)| (n, Some(p)));
            let nums =
                |s: &str| -> Vec<u64> { s.split('.').map(|c| c.parse().unwrap_or(0)).collect() };
            let ord = nums(an).cmp(&nums(bn));
            if ord != Ordering::Equal {
                return ord;
            }
            match (ap, bp) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater, // release > prerelease
                (Some(_), None) => Ordering::Less,
                (Some(x), Some(y)) => x.cmp(y),
            }
        }
        fn lower_id(&self, id: &str) -> String {
            id.to_lowercase()
        }
    }

    fn fmt() -> TestFormat {
        TestFormat
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap()
    }

    fn days_ago(n: i64) -> DateTime<Utc> {
        now() - chrono::Duration::days(n)
    }

    /// Build a hosted component candidate.
    fn comp(
        id: i64,
        name: &str,
        version: &str,
        created_days_ago: i64,
        last_dl_days_ago: Option<i64>,
    ) -> CandidateComponent {
        CandidateComponent {
            component_id: id,
            package_name: name.into(),
            version: version.into(),
            listed: true,
            created_at: days_ago(created_days_ago),
            last_downloaded_at: last_dl_days_ago.map(days_ago),
            size_bytes: 1,
        }
    }

    fn policy_with(rules: Vec<RetentionRule>) -> RetentionPolicy {
        RetentionPolicy {
            version: POLICY_VERSION,
            enabled: true,
            dry_run_only: false,
            min_run_interval_seconds: 3600,
            size_budget: None,
            rules,
        }
    }

    fn rule(id: &str, action: Action, criteria: Criteria) -> RetentionRule {
        RetentionRule {
            id: id.into(),
            action,
            scope: Scope::Hosted,
            release_type: ReleaseType::Any,
            package_name_prefix: None,
            criteria,
        }
    }

    fn deleted_versions(decisions: &[Decision]) -> Vec<&str> {
        let mut v: Vec<&str> = decisions.iter().map(|d| d.version.as_str()).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn is_prerelease_detects_label() {
        assert!(!is_prerelease("1.0.0"));
        assert!(is_prerelease("1.0.0-beta"));
        assert!(is_prerelease("2.1.0-rc.1"));
    }

    #[test]
    fn keep_last_n_protects_newest_and_deletes_older() {
        // 12 versions, all old enough; keep_last_n=10 → delete the 2 oldest.
        let mut cands = Vec::new();
        for i in 1..=12 {
            cands.push(comp(i, "lib", &format!("1.0.{i}"), 100, None));
        }
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                keep_last_n: Some(10),
                older_than_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.1", "1.0.2"]);
    }

    #[test]
    fn keep_last_n_orders_by_semver_not_insertion() {
        // Insertion order scrambled; protection must follow version order.
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, None),
            comp(2, "lib", "2.0.0", 100, None),
            comp(3, "lib", "1.5.0", 100, None),
        ];
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                keep_last_n: Some(2),
                older_than_days: Some(1),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        // newest two (2.0.0, 1.5.0) protected; 1.0.0 deleted.
        assert_eq!(deleted_versions(&d), vec!["1.0.0"]);
    }

    #[test]
    fn older_than_days_only_deletes_old_components() {
        let cands = vec![
            comp(1, "lib", "1.0.0", 10, None),  // young
            comp(2, "lib", "2.0.0", 100, None), // old
        ];
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                older_than_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["2.0.0"]);
    }

    #[test]
    fn not_downloaded_for_days_counts_never_downloaded_from_publication() {
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, None), // never downloaded, old → cold
            comp(2, "lib", "2.0.0", 100, Some(5)), // downloaded 5d ago → warm
            comp(3, "lib", "3.0.0", 100, Some(60)), // downloaded 60d ago → cold
            comp(4, "lib", "4.0.0", 0, None),   // pushed today, never downloaded → warm
        ];
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                not_downloaded_for_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.0", "3.0.0"]);
    }

    #[test]
    fn triggers_are_anded_within_a_rule() {
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, Some(60)), // old AND cold → delete
            comp(2, "lib", "2.0.0", 100, Some(5)),  // old but warm → keep
            comp(3, "lib", "3.0.0", 10, Some(60)),  // young but cold → keep
        ];
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                older_than_days: Some(30),
                not_downloaded_for_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.0"]);
    }

    #[test]
    fn keep_n_most_downloaded_protects_by_recency() {
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, Some(1)),  // most recent dl
            comp(2, "lib", "2.0.0", 100, Some(50)), // older dl
            comp(3, "lib", "3.0.0", 100, None),     // never dl
        ];
        // Trigger deletes all (old), but keep 1 most-downloaded → protect 1.0.0.
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                keep_n_most_downloaded: Some(1),
                older_than_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["2.0.0", "3.0.0"]);
    }

    #[test]
    fn release_type_releases_skips_prereleases() {
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, None),
            comp(2, "lib", "2.0.0-beta", 100, None),
        ];
        let p = policy_with(vec![RetentionRule {
            release_type: ReleaseType::Releases,
            ..rule(
                "r",
                Action::HardDelete,
                Criteria {
                    older_than_days: Some(30),
                    ..Default::default()
                },
            )
        }]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.0"]);
    }

    #[test]
    fn release_type_prereleases_skips_releases() {
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, None),
            comp(2, "lib", "2.0.0-beta", 100, None),
        ];
        let p = policy_with(vec![RetentionRule {
            release_type: ReleaseType::Prereleases,
            ..rule(
                "r",
                Action::HardDelete,
                Criteria {
                    older_than_days: Some(30),
                    ..Default::default()
                },
            )
        }]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["2.0.0-beta"]);
    }

    #[test]
    fn package_name_prefix_filters_groups() {
        let cands = vec![
            comp(1, "acme.core", "1.0.0", 100, None),
            comp(2, "other.lib", "1.0.0", 100, None),
        ];
        let p = policy_with(vec![RetentionRule {
            package_name_prefix: Some("acme.".into()),
            ..rule(
                "r",
                Action::HardDelete,
                Criteria {
                    older_than_days: Some(30),
                    ..Default::default()
                },
            )
        }]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].package_name, "acme.core");
    }

    #[test]
    fn protection_overrides_selection() {
        // keep_last_n=2 protects newest two even though the age rule selects all.
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, None),
            comp(2, "lib", "2.0.0", 100, None),
            comp(3, "lib", "3.0.0", 100, None),
        ];
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                keep_last_n: Some(2),
                older_than_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.0"]);
    }

    #[test]
    fn protection_in_one_rule_protects_against_another_rules_selection() {
        // Rule A protects newest 2; rule B (no protection) selects all old.
        // Protection is a UNION across rules → newest 2 stay protected.
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, None),
            comp(2, "lib", "2.0.0", 100, None),
            comp(3, "lib", "3.0.0", 100, None),
        ];
        let p = policy_with(vec![
            rule(
                "protect",
                Action::HardDelete,
                Criteria {
                    keep_last_n: Some(2),
                    older_than_days: Some(30),
                    ..Default::default()
                },
            ),
            rule(
                "sweep",
                Action::HardDelete,
                Criteria {
                    older_than_days: Some(1),
                    ..Default::default()
                },
            ),
        ]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.0"]);
    }

    #[test]
    fn hard_delete_beats_unlist_when_both_match() {
        let cands = vec![comp(1, "lib", "1.0.0", 100, None)];
        let p = policy_with(vec![
            rule(
                "u",
                Action::Unlist,
                Criteria {
                    older_than_days: Some(30),
                    ..Default::default()
                },
            ),
            rule(
                "d",
                Action::HardDelete,
                Criteria {
                    older_than_days: Some(30),
                    ..Default::default()
                },
            ),
        ]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].action, Action::HardDelete);
        assert_eq!(d[0].rule_id, "d");
    }

    #[test]
    fn unlist_only_when_no_delete_rule_matches() {
        let cands = vec![comp(1, "lib", "1.0.0", 100, None)];
        let p = policy_with(vec![rule(
            "u",
            Action::Unlist,
            Criteria {
                older_than_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].action, Action::Unlist);
    }

    #[test]
    fn unlist_skips_versions_that_are_already_unlisted() {
        let mut hidden = comp(1, "lib", "1.0.0", 100, None);
        hidden.listed = false;
        let cands = vec![hidden, comp(2, "lib", "1.1.0", 100, None)];
        let p = policy_with(vec![rule(
            "u",
            Action::Unlist,
            Criteria {
                older_than_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.1.0"]);

        // A hard-delete rule still reaches an unlisted version.
        let mut hidden = comp(1, "lib", "1.0.0", 100, None);
        hidden.listed = false;
        let p = policy_with(vec![rule(
            "d",
            Action::HardDelete,
            Criteria {
                older_than_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &[hidden]);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].action, Action::HardDelete);
    }

    #[test]
    fn disabled_policy_yields_no_decisions() {
        let cands = vec![comp(1, "lib", "1.0.0", 100, None)];
        let mut p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                older_than_days: Some(1),
                ..Default::default()
            },
        )]);
        p.enabled = false;
        assert!(evaluate(&fmt(), now(), &p, &cands).is_empty());
    }

    #[test]
    fn empty_candidate_set_yields_no_decisions() {
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                older_than_days: Some(1),
                ..Default::default()
            },
        )]);
        assert!(evaluate(&fmt(), now(), &p, &[]).is_empty());
    }

    #[test]
    fn protections_grouped_per_package_name() {
        // Two packages, keep_last_n=1 each: only the oldest of each group dies.
        let cands = vec![
            comp(1, "a", "1.0.0", 100, None),
            comp(2, "a", "2.0.0", 100, None),
            comp(3, "b", "1.0.0", 100, None),
            comp(4, "b", "2.0.0", 100, None),
        ];
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                keep_last_n: Some(1),
                older_than_days: Some(1),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        let mut pairs: Vec<(String, String)> = d
            .iter()
            .map(|x| (x.package_name.clone(), x.version.clone()))
            .collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![("a".into(), "1.0.0".into()), ("b".into(), "1.0.0".into())]
        );
    }

    // ---- protections are computed over each rule's own pool (M6) ----

    fn unlisted(mut c: CandidateComponent) -> CandidateComponent {
        c.listed = false;
        c
    }

    #[test]
    fn keep_last_n_counts_only_versions_the_rule_filters_admit() {
        // Regression (M6): a releases-only rule with keep_last_n=3 used to
        // "protect" the three newest versions of the whole package — here the
        // betas, which the rule never touches — and delete every stable
        // release. It must protect the three newest stable releases instead.
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, None),
            comp(2, "lib", "1.1.0", 100, None),
            comp(3, "lib", "1.2.0", 100, None),
            comp(4, "lib", "1.3.0", 100, None),
            comp(5, "lib", "2.0.0-beta.1", 100, None),
            comp(6, "lib", "2.0.0-beta.2", 100, None),
            comp(7, "lib", "2.0.0-beta.3", 100, None),
        ];
        let p = policy_with(vec![RetentionRule {
            release_type: ReleaseType::Releases,
            ..rule(
                "releases",
                Action::HardDelete,
                Criteria {
                    keep_last_n: Some(3),
                    older_than_days: Some(30),
                    ..Default::default()
                },
            )
        }]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.0"]);
    }

    #[test]
    fn keep_last_n_skips_unlisted_versions() {
        // Regression (M6): unlisted versions used to fill keep_last_n's slots,
        // so unlisting the two newest versions left no listed version
        // protected. The newest N *listed* versions are kept; unlisted ones
        // are neither counted nor protected.
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, None),
            comp(2, "lib", "1.1.0", 100, None),
            comp(3, "lib", "1.2.0", 100, None),
            unlisted(comp(4, "lib", "1.3.0", 100, None)),
            unlisted(comp(5, "lib", "1.4.0", 100, None)),
        ];
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                keep_last_n: Some(2),
                older_than_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.0", "1.3.0", "1.4.0"]);
    }

    #[test]
    fn keep_last_n_of_a_prefix_rule_does_not_protect_other_packages() {
        // A prefix-scoped rule's protection covers only the packages it
        // governs; it must not shield an unrelated package from a sweep.
        let cands = vec![
            comp(1, "acme.core", "1.0.0", 100, None),
            comp(2, "acme.core", "2.0.0", 100, None),
            comp(3, "other.lib", "1.0.0", 100, None),
            comp(4, "other.lib", "2.0.0", 100, None),
        ];
        let p = policy_with(vec![
            RetentionRule {
                package_name_prefix: Some("Acme.".into()),
                ..rule(
                    "acme",
                    Action::HardDelete,
                    Criteria {
                        keep_last_n: Some(5),
                        older_than_days: Some(30),
                        ..Default::default()
                    },
                )
            },
            rule(
                "sweep",
                Action::HardDelete,
                Criteria {
                    older_than_days: Some(30),
                    ..Default::default()
                },
            ),
        ]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        let mut pairs: Vec<(String, String)> = d
            .iter()
            .map(|x| (x.package_name.clone(), x.version.clone()))
            .collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                ("other.lib".into(), "1.0.0".into()),
                ("other.lib".into(), "2.0.0".into())
            ]
        );
    }

    #[test]
    fn protection_from_a_filtered_rule_still_shields_against_other_rules() {
        // The per-rule protected sets are unioned: the newest prerelease kept
        // by the prereleases rule survives the any-version sweep too.
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, None),
            comp(2, "lib", "2.0.0-beta.1", 100, None),
            comp(3, "lib", "2.0.0-beta.2", 100, None),
        ];
        let p = policy_with(vec![
            RetentionRule {
                release_type: ReleaseType::Prereleases,
                ..rule(
                    "pre",
                    Action::HardDelete,
                    Criteria {
                        keep_last_n: Some(1),
                        older_than_days: Some(30),
                        ..Default::default()
                    },
                )
            },
            rule(
                "sweep",
                Action::HardDelete,
                Criteria {
                    older_than_days: Some(30),
                    ..Default::default()
                },
            ),
        ]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.0", "2.0.0-beta.1"]);
    }

    #[test]
    fn keep_n_most_downloaded_ranks_only_versions_the_rule_filters_admit() {
        // Regression (M6, keep_n_most_downloaded): the most recently pulled
        // version overall is a beta the releases-only rule never touches; it
        // used to take the only slot, leaving every stable release exposed.
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, Some(50)),
            comp(2, "lib", "1.1.0", 100, Some(20)),
            comp(3, "lib", "2.0.0-beta", 100, Some(1)),
        ];
        let p = policy_with(vec![RetentionRule {
            release_type: ReleaseType::Releases,
            ..rule(
                "releases",
                Action::HardDelete,
                Criteria {
                    keep_n_most_downloaded: Some(1),
                    older_than_days: Some(30),
                    ..Default::default()
                },
            )
        }]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.0"]);
    }

    #[test]
    fn keep_n_most_downloaded_counts_unlisted_versions_in_use() {
        // Download recency, not listing, marks a version as in use: an
        // unlisted version still being restored by exact version keeps its
        // keep_n_most_downloaded slot.
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, Some(50)),
            unlisted(comp(2, "lib", "1.1.0", 100, Some(1))),
            comp(3, "lib", "1.2.0", 100, None),
        ];
        let p = policy_with(vec![rule(
            "r",
            Action::HardDelete,
            Criteria {
                keep_n_most_downloaded: Some(1),
                older_than_days: Some(30),
                ..Default::default()
            },
        )]);
        let d = evaluate(&fmt(), now(), &p, &cands);
        assert_eq!(deleted_versions(&d), vec!["1.0.0", "1.2.0"]);
    }

    // ---- scale ----

    #[test]
    fn large_interleaved_snapshot_decides_as_each_package_alone() {
        // Regression (#24): grouping re-scanned the whole snapshot once per
        // package (O(N·G)). 100k versions over 5,000 packages, interleaved so
        // no package's versions are adjacent, each package's arriving out of
        // version order, and first-appearance order differing from name
        // order. The single-pass grouping must decide exactly what evaluating
        // each package on its own decides, package by package in the order
        // the packages first appear.
        const PACKAGES: usize = 5_000;
        const VERSIONS: usize = 20;
        let mut all = Vec::with_capacity(PACKAGES * VERSIONS);
        let mut by_package: Vec<Vec<CandidateComponent>> = vec![Vec::new(); PACKAGES];
        for round in 0..VERSIONS {
            let v = (round * 7) % VERSIONS;
            for (p, group) in by_package.iter_mut().enumerate() {
                let name = format!("pkg{:04}", (p * 7919) % PACKAGES);
                let version = if v % 5 == 4 {
                    format!("1.{v}.0-beta")
                } else {
                    format!("1.{v}.0")
                };
                let last_dl = v.is_multiple_of(3).then_some(((v + p) % 60) as i64);
                let mut c = comp((p * VERSIONS + v) as i64, &name, &version, 100, last_dl);
                c.listed = !(v + p).is_multiple_of(7);
                all.push(c.clone());
                group.push(c);
            }
        }
        let p = policy_with(vec![
            RetentionRule {
                release_type: ReleaseType::Releases,
                ..rule(
                    "releases",
                    Action::HardDelete,
                    Criteria {
                        keep_last_n: Some(3),
                        older_than_days: Some(30),
                        ..Default::default()
                    },
                )
            },
            RetentionRule {
                release_type: ReleaseType::Prereleases,
                ..rule(
                    "prereleases",
                    Action::Unlist,
                    Criteria {
                        keep_n_most_downloaded: Some(1),
                        not_downloaded_for_days: Some(30),
                        ..Default::default()
                    },
                )
            },
            RetentionRule {
                package_name_prefix: Some("PKG1".into()),
                ..rule(
                    "prefix",
                    Action::HardDelete,
                    Criteria {
                        not_downloaded_for_days: Some(45),
                        ..Default::default()
                    },
                )
            },
        ]);

        let decisions = evaluate(&fmt(), now(), &p, &all);
        let expected: Vec<Decision> = by_package
            .iter()
            .flat_map(|group| evaluate(&fmt(), now(), &p, group))
            .collect();
        assert_eq!(decisions.len(), expected.len());
        assert!(
            decisions == expected,
            "decisions differ from per-package evaluation"
        );

        // Sanity: the policy did real work, and each package's three newest
        // listed releases survived.
        assert!(decisions.iter().any(|d| d.action == Action::Unlist));
        assert!(decisions.iter().any(|d| d.rule_id == "prefix"));
        let decided: std::collections::HashSet<i64> =
            decisions.iter().map(|d| d.component_id).collect();
        for group in &by_package {
            let mut releases: Vec<&CandidateComponent> = group
                .iter()
                .filter(|c| c.listed && !is_prerelease(&c.version))
                .collect();
            releases.sort_by(|a, b| fmt().compare_versions(&b.version, &a.version));
            for kept in releases.iter().take(3) {
                assert!(!decided.contains(&kept.component_id), "{kept:?}");
            }
        }
    }

    // ---- proxy ----

    fn proxy(
        id: i64,
        name: &str,
        version: &str,
        first_seen_days: i64,
        last_dl_days: Option<i64>,
    ) -> ProxyCandidate {
        ProxyCandidate {
            cached_version_id: id,
            package_name: name.into(),
            version: version.into(),
            listed: true,
            first_seen_at: days_ago(first_seen_days),
            last_downloaded_at: last_dl_days.map(days_ago),
            size_bytes: 1,
        }
    }

    fn proxy_rule(id: &str, days: u32) -> RetentionRule {
        RetentionRule {
            id: id.into(),
            action: Action::HardDelete,
            scope: Scope::ProxyCached,
            release_type: ReleaseType::Any,
            package_name_prefix: None,
            criteria: Criteria {
                not_pulled_for_days: Some(days),
                ..Default::default()
            },
        }
    }

    #[test]
    fn proxy_evicts_using_last_downloaded_else_first_seen() {
        let cands = vec![
            proxy(1, "lib", "1.0.0", 100, Some(60)), // pulled 60d ago → cold
            proxy(2, "lib", "2.0.0", 100, Some(5)),  // pulled 5d ago → warm
            proxy(3, "lib", "3.0.0", 100, None),     // never pulled, seen 100d ago → cold
            proxy(4, "lib", "4.0.0", 10, None),      // never pulled, seen 10d ago → warm
        ];
        let p = policy_with(vec![proxy_rule("evict", 30)]);
        let d = evaluate_proxy(&fmt(), now(), &p, &cands);
        let mut ids: Vec<i64> = d.iter().map(|x| x.cached_version_id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 3]);
        assert!(d.iter().all(|x| x.reason.not_pulled_for_days == Some(30)));
    }

    #[test]
    fn hosted_rules_ignored_by_proxy_evaluator_and_vice_versa() {
        let hosted_cands = vec![comp(1, "lib", "1.0.0", 100, None)];
        let proxy_cands = vec![proxy(1, "lib", "1.0.0", 100, None)];
        let p = policy_with(vec![
            rule(
                "h",
                Action::HardDelete,
                Criteria {
                    older_than_days: Some(1),
                    ..Default::default()
                },
            ),
            proxy_rule("p", 30),
        ]);
        // hosted evaluator only sees the hosted rule
        let hd = evaluate(&fmt(), now(), &p, &hosted_cands);
        assert_eq!(hd.len(), 1);
        assert_eq!(hd[0].rule_id, "h");
        // proxy evaluator only sees the proxy rule
        let pd = evaluate_proxy(&fmt(), now(), &p, &proxy_cands);
        assert_eq!(pd.len(), 1);
        assert_eq!(pd[0].rule_id, "p");
    }

    #[test]
    fn proxy_disabled_policy_yields_nothing() {
        let cands = vec![proxy(1, "lib", "1.0.0", 100, None)];
        let mut p = policy_with(vec![proxy_rule("p", 1)]);
        p.enabled = false;
        assert!(evaluate_proxy(&fmt(), now(), &p, &cands).is_empty());
    }

    /// A proxy rule evicting what nobody pulled for 30 days, keeping the
    /// newest `last` and the `pulled` most recently pulled versions.
    fn proxy_keep_rule(id: &str, last: Option<u32>, pulled: Option<u32>) -> RetentionRule {
        let mut rule = proxy_rule(id, 30);
        rule.criteria.keep_last_n = last;
        rule.criteria.keep_n_most_downloaded = pulled;
        rule
    }

    /// Five cached versions of `lib`, all cold (pulled 40+ days ago, seen 100
    /// days ago); 1.0.0 was pulled last, 5.0.0 first.
    fn cold_versions() -> Vec<ProxyCandidate> {
        vec![
            proxy(1, "lib", "1.0.0", 100, Some(40)),
            proxy(2, "lib", "2.0.0", 100, Some(50)),
            proxy(3, "lib", "3.0.0", 100, Some(60)),
            proxy(4, "lib", "4.0.0", 100, Some(70)),
            proxy(5, "lib", "5.0.0", 100, Some(80)),
        ]
    }

    fn evicted(p: &RetentionPolicy, cands: &[ProxyCandidate]) -> Vec<i64> {
        let mut ids: Vec<i64> = evaluate_proxy(&fmt(), now(), p, cands)
            .iter()
            .map(|d| d.cached_version_id)
            .collect();
        ids.sort_unstable();
        ids
    }

    #[test]
    fn proxy_keep_last_n_keeps_the_newest_cached_versions() {
        let p = policy_with(vec![proxy_keep_rule("evict", Some(2), None)]);
        assert_eq!(evicted(&p, &cold_versions()), vec![1, 2, 3]);
    }

    #[test]
    fn proxy_keep_n_most_downloaded_keeps_the_versions_pulled_last() {
        let p = policy_with(vec![proxy_keep_rule("evict", None, Some(2))]);
        assert_eq!(evicted(&p, &cold_versions()), vec![3, 4, 5]);
    }

    #[test]
    fn proxy_protections_of_one_rule_are_unioned() {
        // Newest 2 (5.0.0, 4.0.0) and pulled last 2 (1.0.0, 2.0.0).
        let p = policy_with(vec![proxy_keep_rule("evict", Some(2), Some(2))]);
        assert_eq!(evicted(&p, &cold_versions()), vec![3]);
    }

    #[test]
    fn proxy_keep_last_n_skips_versions_the_upstream_unlisted() {
        let mut cands = cold_versions();
        cands[4].listed = false; // 5.0.0
        let p = policy_with(vec![proxy_keep_rule("evict", Some(2), None)]);
        // 4.0.0 and 3.0.0 are the newest listed; the unlisted 5.0.0 goes.
        assert_eq!(evicted(&p, &cands), vec![1, 2, 5]);
    }

    #[test]
    fn proxy_protections_cover_the_versions_their_rule_filters_admit() {
        let mut cands = cold_versions();
        cands.push(proxy(6, "lib", "6.0.0-beta", 100, Some(90)));
        let mut releases = proxy_keep_rule("releases", Some(1), None);
        releases.release_type = ReleaseType::Releases;
        let p = policy_with(vec![releases]);
        // The newest release (5.0.0) is kept, not the newer prerelease,
        // which the releases-only rule does not act on at all.
        assert_eq!(evicted(&p, &cands), vec![1, 2, 3, 4]);
        // Each package is protected on its own.
        let mut two = cold_versions();
        two.push(proxy(7, "other", "1.0.0", 100, Some(90)));
        let p = policy_with(vec![proxy_keep_rule("evict", Some(1), None)]);
        assert_eq!(evicted(&p, &two), vec![1, 2, 3, 4]);
    }

    #[test]
    fn proxy_protection_of_one_rule_shields_from_another() {
        let keep = proxy_keep_rule("keep-newest", Some(1), None);
        let sweep = proxy_rule("sweep", 7);
        let p = policy_with(vec![keep, sweep]);
        assert_eq!(evicted(&p, &cold_versions()), vec![1, 2, 3, 4]);
    }

    #[test]
    fn proxy_protected_versions_are_ordered_by_the_format() {
        // Snapshot order must not matter: 10.0.0 is newer than 9.0.0.
        let cands = vec![
            proxy(1, "lib", "10.0.0", 100, Some(40)),
            proxy(2, "lib", "9.0.0", 100, Some(40)),
        ];
        let p = policy_with(vec![proxy_keep_rule("evict", Some(1), None)]);
        assert_eq!(evicted(&p, &cands), vec![2]);
    }

    #[test]
    fn size_budget_deletes_least_recently_used_and_keeps_newest_version() {
        let mut candidates = vec![
            comp(1, "lib", "1.0.0", 100, Some(90)),
            comp(2, "lib", "2.0.0", 50, Some(20)),
            comp(3, "lib", "3.0.0", 10, Some(1)),
        ];
        for candidate in &mut candidates {
            candidate.size_bytes = 40;
        }
        let mut policy = policy_with(vec![rule(
            "keep",
            Action::HardDelete,
            Criteria {
                keep_last_n: Some(1),
                ..Default::default()
            },
        )]);
        policy.size_budget = Some(crate::retention::model::SizeBudget {
            max_bytes: 100,
            target_bytes: Some(80),
        });
        let plan = evaluate_size_budget(&fmt(), &policy, &candidates, &[], &[], &[], 120);
        assert_eq!(
            plan.hosted
                .iter()
                .map(|d| d.component_id)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(plan.size_before, 120);
        assert_eq!(plan.size_after, 80);
        assert!(plan.target_reached);
    }

    #[test]
    fn proxy_size_budget_honors_rule_protections() {
        let mut candidates = cold_versions();
        for candidate in &mut candidates {
            candidate.size_bytes = 30;
        }
        let mut policy = policy_with(vec![proxy_keep_rule("keep", Some(1), None)]);
        policy.size_budget = Some(crate::retention::model::SizeBudget {
            max_bytes: 100,
            target_bytes: Some(80),
        });
        let plan = evaluate_size_budget(&fmt(), &policy, &[], &candidates, &[], &[], 150);
        assert_eq!(
            plan.proxy
                .iter()
                .map(|d| d.cached_version_id)
                .collect::<Vec<_>>(),
            vec![4, 3, 2]
        );
        assert_eq!(plan.size_after, 60);
        assert!(plan.target_reached);
        assert!(plan.proxy.iter().all(|d| d.rule_id == "size_budget"));
    }
}
