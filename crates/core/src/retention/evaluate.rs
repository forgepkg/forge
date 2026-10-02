//! The **pure** retention evaluator (design §3.6).
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
//!    (never-downloaded always matches).
//! 5. Protection overrides selection. Otherwise the highest-severity action
//!    wins (`hard_delete` > `unlist`).
//!
//! ## Proxy ([`evaluate_proxy`])
//!
//! `scope: proxy_cached` rules evict a cached version when `not_pulled_for_days`
//! is satisfied, comparing against `last_downloaded_at` or, when never pulled,
//! `first_seen_at`. Only versions whose bytes are cached locally are
//! candidates. Proxy entries are never unlisted — eviction always deletes the
//! cached bytes (the version stays listed and re-caches on the next pull).

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
}

/// One proxy cached version in the evaluation snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCandidate {
    /// `proxy_cached_version.id`.
    pub cached_version_id: i64,
    /// Lowercased package id, for prefix filtering.
    pub package_name: String,
    /// Normalized version string.
    pub version: String,
    /// When the entry was first cached (fallback for "never pulled").
    pub first_seen_at: DateTime<Utc>,
    /// Last pull timestamp, or `None` if never pulled since caching.
    pub last_downloaded_at: Option<DateTime<Utc>>,
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
        if !package_name.starts_with(&prefix.to_lowercase()) {
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
        let cold = match cand.last_downloaded_at {
            // Never downloaded ⇒ always a prime eviction target (Nexus parity).
            None => true,
            Some(ts) => days_since(now, ts) >= days as i64,
        };
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

/// Compute which of a group's versions (indices into its newest-first
/// ordering) are **protected**: the union, over every hosted rule, of that
/// rule's `keep_last_n` / `keep_n_most_downloaded` protections.
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
/// `ordered` is the group's components sorted newest-first (by version).
fn protected_indices(policy: &RetentionPolicy, ordered: &[&CandidateComponent]) -> Vec<bool> {
    let mut protected = vec![false; ordered.len()];

    for rule in policy.rules.iter().filter(|r| r.scope == Scope::Hosted) {
        let c = &rule.criteria;
        if !c.has_protection() {
            continue;
        }
        // The rule's pool, still newest-first.
        let pool: Vec<usize> = (0..ordered.len())
            .filter(|&i| rule_filters_match(rule, &ordered[i].package_name, &ordered[i].version))
            .collect();

        if let Some(n) = c.keep_last_n {
            for &idx in pool.iter().filter(|&&i| ordered[i].listed).take(n as usize) {
                protected[idx] = true;
            }
        }

        if let Some(n) = c.keep_n_most_downloaded {
            // Order by download recency: most-recent first, nulls last. The
            // sort is stable, so ties keep the pool's version-desc order.
            let mut by_download = pool.clone();
            by_download.sort_by(|&a, &b| {
                match (ordered[a].last_downloaded_at, ordered[b].last_downloaded_at) {
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
/// `format` is used only to order versions within a package group.
pub fn evaluate(
    format: &dyn Format,
    now: DateTime<Utc>,
    policy: &RetentionPolicy,
    candidates: &[CandidateComponent],
) -> Vec<Decision> {
    if !policy.enabled {
        return Vec::new();
    }

    // Group candidates by package name, preserving deterministic group order.
    let mut group_names: Vec<&str> = Vec::new();
    for cand in candidates {
        if !group_names.contains(&cand.package_name.as_str()) {
            group_names.push(&cand.package_name);
        }
    }

    let mut decisions = Vec::new();

    for name in group_names {
        // Collect this group's components, newest-first by version.
        let mut group: Vec<&CandidateComponent> = candidates
            .iter()
            .filter(|c| c.package_name == name)
            .collect();
        group.sort_by(|a, b| format.compare_versions(&b.version, &a.version)); // desc

        let protected = protected_indices(policy, &group);

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
pub fn evaluate_proxy(
    now: DateTime<Utc>,
    policy: &RetentionPolicy,
    candidates: &[ProxyCandidate],
) -> Vec<ProxyDecision> {
    if !policy.enabled {
        return Vec::new();
    }

    let mut decisions = Vec::new();

    for cand in candidates {
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
                },
            });
        }
    }

    decisions
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
    /// We deliberately do **not** depend on `forge-nuget` here: pulling it in as
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
        }
    }

    fn policy_with(rules: Vec<RetentionRule>) -> RetentionPolicy {
        RetentionPolicy {
            version: POLICY_VERSION,
            enabled: true,
            dry_run_only: false,
            min_run_interval_seconds: 3600,
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
    fn not_downloaded_for_days_treats_never_downloaded_as_cold() {
        let cands = vec![
            comp(1, "lib", "1.0.0", 100, None),     // never downloaded → cold
            comp(2, "lib", "2.0.0", 100, Some(5)),  // downloaded 5d ago → warm
            comp(3, "lib", "3.0.0", 100, Some(60)), // downloaded 60d ago → cold
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
            first_seen_at: days_ago(first_seen_days),
            last_downloaded_at: last_dl_days.map(days_ago),
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
        let d = evaluate_proxy(now(), &p, &cands);
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
        let pd = evaluate_proxy(now(), &p, &proxy_cands);
        assert_eq!(pd.len(), 1);
        assert_eq!(pd[0].rule_id, "p");
    }

    #[test]
    fn proxy_disabled_policy_yields_nothing() {
        let cands = vec![proxy(1, "lib", "1.0.0", 100, None)];
        let mut p = policy_with(vec![proxy_rule("p", 1)]);
        p.enabled = false;
        assert!(evaluate_proxy(now(), &p, &cands).is_empty());
    }
}
