//! Retention policy model + validation (the `repository.retention_policy` jsonb).
//!
//! The shape mirrors the `0002_retention.sql` migration:
//! a policy is a list of **rules**; a component is acted on if **any** rule
//! selects it (union), but `keep_last_n` / `keep_n_most_downloaded` protections
//! always win (a protected version is never deleted — see [`crate::retention::evaluate`]).
//! Each rule's protections are computed over the versions that rule's own
//! filters admit (see [`Criteria`]); the protected sets are then unioned.
//!
//! Parity subset of Nexus cleanup policies + Artifactory retention:
//!   * protections: `keep_last_n`, `keep_n_most_downloaded`
//!   * triggers (ANDed within a rule): `older_than_days`, `not_downloaded_for_days`
//!   * filters: `release_type` (release vs prerelease), `package_name_prefix`
//!   * proxy rules: `scope: proxy_cached` with `not_pulled_for_days`, and the
//!     same protections over each package's cached versions
//!
//! These types are **pure data** + a `validate_policy` function; no I/O. They are
//! (de)serialized straight to/from the jsonb column with serde.

use serde::{Deserialize, Serialize};

use crate::repo::RepoKind;

/// The current policy schema version. Bumped if the shape changes incompatibly.
pub const POLICY_VERSION: u32 = 1;

/// A repository's retention policy, stored as `repository.retention_policy` jsonb.
///
/// `None` policy column ⇒ no retention. An `enabled = false` policy is parsed
/// and stored but produces no decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    /// Policy schema version (must equal [`POLICY_VERSION`]).
    pub version: u32,
    /// Master switch; a disabled policy yields no decisions.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Safety flag: evaluate + audit but never apply (every decision forced to
    /// `dry_run = true`, apply skipped). Lets an operator stage a policy.
    #[serde(default)]
    pub dry_run_only: bool,
    /// Minimum seconds between automatic runs for this repo (advisory scheduling
    /// floor used by the worker; a manual trigger bypasses it). The worker
    /// never schedules runs less than 60 s apart, whatever this says.
    #[serde(default = "default_min_run_interval")]
    pub min_run_interval_seconds: u64,
    /// Optional repository-wide logical-size budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_budget: Option<SizeBudget>,
    /// The ordered list of rules. May be empty when a size budget is set.
    pub rules: Vec<RetentionRule>,
}

/// A logical repository-size limit with a lower target to avoid repeated churn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SizeBudget {
    pub max_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_bytes: Option<u64>,
}

impl SizeBudget {
    /// Target watermark, defaulting to 90% of the maximum.
    pub fn target_bytes(self) -> u64 {
        self.target_bytes
            .unwrap_or_else(|| (self.max_bytes / 10) * 9 + ((self.max_bytes % 10) * 9) / 10)
    }
}

fn default_true() -> bool {
    true
}

fn default_min_run_interval() -> u64 {
    3600
}

/// A single retention rule. Criteria within a rule are ANDed; a component is
/// acted on if **any** rule selects it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionRule {
    /// Stable, human-chosen id, recorded on every audit row this rule produces.
    pub id: String,
    /// What to do with a selected component.
    pub action: Action,
    /// Which targets this rule operates on. Defaults to hosted components,
    /// which is only valid on hosted repositories: a proxy repository's rules
    /// must all say `scope: proxy_cached` ([`PolicyError::HostedScopeOnProxy`]).
    #[serde(default)]
    pub scope: Scope,
    /// Restrict the rule to release / prerelease versions. Defaults to `Any`.
    #[serde(default)]
    pub release_type: ReleaseType,
    /// Optional case-insensitive package-id prefix filter (`None` ⇒ all ids).
    #[serde(default)]
    pub package_name_prefix: Option<String>,
    /// The protections + triggers for this rule.
    #[serde(default)]
    pub criteria: Criteria,
}

/// What a rule does with a selected version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Soft delete: hide from search/metadata but keep the blob downloadable.
    Unlist,
    /// Hard delete: remove rows and dereference blobs (driving the outbox).
    HardDelete,
}

impl Action {
    /// Severity ordering for "highest-severity action wins" when multiple rules
    /// match a version: `HardDelete` outranks `Unlist`.
    pub fn severity(self) -> u8 {
        match self {
            Action::Unlist => 1,
            Action::HardDelete => 2,
        }
    }
}

/// The set of targets a rule operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Hosted components (the default scope); only valid on hosted repos. A
    /// proxy's components are a cache of upstream bytes tracked by
    /// `proxy_cached_version`, so deleting them as if they were hosted would
    /// leave that row claiming the bytes are cached (see
    /// [`PolicyError::HostedScopeOnProxy`]).
    #[default]
    Hosted,
    /// Proxy cached versions (`proxy_cached_version` rows); only valid on proxy
    /// repos. Eviction deletes the locally cached bytes and leaves the version
    /// listed (re-fetched from upstream on the next pull); proxy entries are
    /// never "unlisted". Its rules trigger on `not_pulled_for_days` and may
    /// keep versions with the protections of [`Criteria`].
    ProxyCached,
}

/// Release-type filter for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseType {
    /// Match every version.
    #[default]
    Any,
    /// Match only stable releases (no prerelease label).
    Releases,
    /// Match only prerelease versions.
    Prereleases,
}

/// Protections + triggers for a rule. All fields optional; an empty `Criteria`
/// is rejected by [`validate_policy`] (a rule must do *something*).
///
/// **Protections** (`keep_last_n`, `keep_n_most_downloaded`) are computed per
/// rule and per package id, over that rule's *pool*: the package's versions
/// that the rule's own `release_type` and `package_name_prefix` filters admit.
/// A `releases`-only rule with `keep_last_n: 3` therefore protects the three
/// newest stable releases, never prereleases. The protected sets of all rules
/// are then **unioned**: a version protected by any rule is never unlisted or
/// deleted by any rule. On `scope: proxy_cached` rules the pool is the
/// package's *cached* versions, `listed` is whether the upstream lists them,
/// downloads are pulls, and a protected cached version is never evicted.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Criteria {
    /// Protection: the newest N **listed** versions (by format version order)
    /// of each package id in this rule's pool. Unlisted versions neither count
    /// toward N nor are protected by it, so after unlisting a broken newest
    /// release the N newest *resolvable* versions are still kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_last_n: Option<u32>,
    /// Protection: the N most-recently-downloaded versions of each package id
    /// in this rule's pool, listed or not (download recency, not listing, is
    /// what marks a version as in use, and unlisted versions stay restorable by
    /// exact version). Never-downloaded versions rank last, newest first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_n_most_downloaded: Option<u32>,
    /// Trigger: component age since `created_at` is at least this many days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub older_than_days: Option<u32>,
    /// Trigger: not downloaded for at least this many days (a version never
    /// downloaded counts from its publication).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_downloaded_for_days: Option<u32>,
    /// Proxy trigger: cached version not pulled for at least this many days
    /// (falls back to `first_seen_at` when never pulled). Only meaningful for
    /// `scope: proxy_cached` rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_pulled_for_days: Option<u32>,
}

impl Criteria {
    /// Whether this rule expresses any deletion **trigger** (as opposed to only
    /// protections). A rule of pure protections selects nothing, so it is
    /// rejected at validation time.
    pub fn has_trigger(&self) -> bool {
        self.older_than_days.is_some()
            || self.not_downloaded_for_days.is_some()
            || self.not_pulled_for_days.is_some()
    }

    /// Whether this rule defines any protection.
    pub fn has_protection(&self) -> bool {
        self.keep_last_n.is_some() || self.keep_n_most_downloaded.is_some()
    }
}

/// Validation errors for a [`RetentionPolicy`] against a repository kind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// `version` did not match [`POLICY_VERSION`].
    #[error("unsupported policy version {found} (expected {expected})")]
    UnsupportedVersion {
        /// The version found in the policy.
        found: u32,
        /// The version this build supports.
        expected: u32,
    },
    /// The policy had no rules.
    #[error("policy must contain at least one rule")]
    EmptyRules,
    /// The size budget is zero or has an invalid target.
    #[error("size_budget.max_bytes must be greater than zero and target_bytes must not exceed max_bytes")]
    InvalidSizeBudget,
    /// A rule uses the reserved budget audit id.
    #[error("rule id \"size_budget\" is reserved")]
    ReservedRuleId,
    /// Two rules shared the same `id`.
    #[error("duplicate rule id {0:?}")]
    DuplicateRuleId(String),
    /// A rule's `id` was empty.
    #[error("rule id must not be empty")]
    EmptyRuleId,
    /// A rule had no deletion trigger (only protections / nothing).
    #[error("rule {0:?} has no trigger criterion (older_than_days / not_downloaded_for_days / not_pulled_for_days)")]
    RuleHasNoTrigger(String),
    /// A `keep_*` count was zero (meaningless — protects nothing; use absence
    /// instead).
    #[error("rule {rule:?} field {field} must be greater than zero")]
    ZeroCount {
        /// The offending rule id.
        rule: String,
        /// The offending field name.
        field: &'static str,
    },
    /// A `*_days` value was zero (would match everything immediately; reject as
    /// almost certainly a mistake).
    #[error("rule {rule:?} field {field} must be greater than zero")]
    ZeroDays {
        /// The offending rule id.
        rule: String,
        /// The offending field name.
        field: &'static str,
    },
    /// A `scope: proxy_cached` rule was attached to a non-proxy repository.
    #[error("rule {0:?} uses scope=proxy_cached but the repository is not a proxy")]
    ProxyScopeOnNonProxy(String),
    /// A hosted-scope rule (the default when `scope` is omitted) was attached
    /// to a proxy repository. Deleting a proxy's components as hosted content
    /// would leave `proxy_cached_version.downloaded` set with no local copy,
    /// so the version could never be restored again.
    #[error(
        "rule {0:?} has scope=hosted (the default when \"scope\" is omitted), which is not \
         valid on a proxy repository; set \"scope\": \"proxy_cached\" and use \
         not_pulled_for_days to evict cached versions"
    )]
    HostedScopeOnProxy(String),
    /// A hosted-scope rule used the proxy-only `not_pulled_for_days` criterion.
    #[error("rule {0:?} uses not_pulled_for_days but scope is not proxy_cached")]
    NotPulledOnHostedScope(String),
    /// A proxy-scope rule used hosted-only criteria / fields that don't apply.
    #[error("rule {rule:?} uses {field} which is not valid for scope=proxy_cached")]
    HostedFieldOnProxyScope {
        /// The offending rule id.
        rule: String,
        /// The offending field name.
        field: &'static str,
    },
    /// Retention was configured on a group repository (groups own no content).
    #[error("retention policies are not supported on group repositories")]
    GroupRepoUnsupported,
    /// `min_run_interval_seconds` exceeded [`MAX_MIN_RUN_INTERVAL_SECONDS`].
    #[error("min_run_interval_seconds must be at most {max} (one year)")]
    RunIntervalTooLarge {
        /// The upper bound.
        max: u64,
    },
}

/// Upper bound on a policy's `min_run_interval_seconds` (one year). Larger
/// values are meaningless and would overflow the scheduler's date arithmetic.
pub const MAX_MIN_RUN_INTERVAL_SECONDS: u64 = 366 * 24 * 60 * 60;

/// Validate a policy against the repository kind it will attach to.
///
/// Rejects: wrong version, empty / duplicate rule ids, rules with no trigger,
/// zero counts/days, proxy-scope rules on non-proxy repos, hosted-scope rules
/// on proxy repos, proxy-only criteria on hosted-scope rules (and vice-versa),
/// and any policy on a group repo. A disabled policy is
/// still validated so a re-enable can't smuggle in a broken rule.
pub fn validate_policy(policy: &RetentionPolicy, repo_kind: RepoKind) -> Result<(), PolicyError> {
    if policy.version != POLICY_VERSION {
        return Err(PolicyError::UnsupportedVersion {
            found: policy.version,
            expected: POLICY_VERSION,
        });
    }
    if repo_kind == RepoKind::Group {
        return Err(PolicyError::GroupRepoUnsupported);
    }
    if policy.rules.is_empty() && policy.size_budget.is_none() {
        return Err(PolicyError::EmptyRules);
    }
    if let Some(budget) = policy.size_budget {
        if budget.max_bytes == 0
            || budget
                .target_bytes
                .is_some_and(|target| target > budget.max_bytes)
        {
            return Err(PolicyError::InvalidSizeBudget);
        }
    }
    if policy.min_run_interval_seconds > MAX_MIN_RUN_INTERVAL_SECONDS {
        return Err(PolicyError::RunIntervalTooLarge {
            max: MAX_MIN_RUN_INTERVAL_SECONDS,
        });
    }

    let mut seen_ids: Vec<&str> = Vec::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        if rule.id.trim().is_empty() {
            return Err(PolicyError::EmptyRuleId);
        }
        if rule.id == "size_budget" {
            return Err(PolicyError::ReservedRuleId);
        }
        if seen_ids.contains(&rule.id.as_str()) {
            return Err(PolicyError::DuplicateRuleId(rule.id.clone()));
        }
        seen_ids.push(&rule.id);

        validate_rule(rule, repo_kind)?;
    }
    Ok(())
}

fn validate_rule(rule: &RetentionRule, repo_kind: RepoKind) -> Result<(), PolicyError> {
    let c = &rule.criteria;

    // Scope/repo-kind coherence.
    match rule.scope {
        Scope::ProxyCached if repo_kind != RepoKind::Proxy => {
            return Err(PolicyError::ProxyScopeOnNonProxy(rule.id.clone()));
        }
        Scope::ProxyCached => {
            // Proxy rules trigger only on `not_pulled_for_days` (and keep what
            // their protections name); the hosted triggers are nonsensical
            // here and almost certainly a copy-paste mistake.
            if c.older_than_days.is_some() {
                return Err(PolicyError::HostedFieldOnProxyScope {
                    rule: rule.id.clone(),
                    field: "older_than_days",
                });
            }
            if c.not_downloaded_for_days.is_some() {
                return Err(PolicyError::HostedFieldOnProxyScope {
                    rule: rule.id.clone(),
                    field: "not_downloaded_for_days",
                });
            }
        }
        Scope::Hosted if repo_kind == RepoKind::Proxy => {
            return Err(PolicyError::HostedScopeOnProxy(rule.id.clone()));
        }
        Scope::Hosted => {
            if c.not_pulled_for_days.is_some() {
                return Err(PolicyError::NotPulledOnHostedScope(rule.id.clone()));
            }
        }
    }

    // Counts must be positive when present.
    if c.keep_last_n == Some(0) {
        return Err(PolicyError::ZeroCount {
            rule: rule.id.clone(),
            field: "keep_last_n",
        });
    }
    if c.keep_n_most_downloaded == Some(0) {
        return Err(PolicyError::ZeroCount {
            rule: rule.id.clone(),
            field: "keep_n_most_downloaded",
        });
    }
    // Days must be positive when present.
    if c.older_than_days == Some(0) {
        return Err(PolicyError::ZeroDays {
            rule: rule.id.clone(),
            field: "older_than_days",
        });
    }
    if c.not_downloaded_for_days == Some(0) {
        return Err(PolicyError::ZeroDays {
            rule: rule.id.clone(),
            field: "not_downloaded_for_days",
        });
    }
    if c.not_pulled_for_days == Some(0) {
        return Err(PolicyError::ZeroDays {
            rule: rule.id.clone(),
            field: "not_pulled_for_days",
        });
    }

    // Every rule must express at least one trigger; pure-protection rules
    // delete nothing and are almost certainly a config error.
    if !c.has_trigger() {
        return Err(PolicyError::RuleHasNoTrigger(rule.id.clone()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An example policy (hosted keep-recent + a proxy evict rule), built in
    /// code so tests can mutate it.
    fn example_hosted_rule() -> RetentionRule {
        RetentionRule {
            id: "keep-recent-releases".into(),
            action: Action::HardDelete,
            scope: Scope::Hosted,
            release_type: ReleaseType::Any,
            package_name_prefix: None,
            criteria: Criteria {
                keep_last_n: Some(10),
                keep_n_most_downloaded: None,
                older_than_days: Some(90),
                not_downloaded_for_days: Some(30),
                not_pulled_for_days: None,
            },
        }
    }

    fn example_proxy_rule() -> RetentionRule {
        RetentionRule {
            id: "proxy-evict-cold".into(),
            action: Action::HardDelete,
            scope: Scope::ProxyCached,
            release_type: ReleaseType::Any,
            package_name_prefix: None,
            criteria: Criteria {
                not_pulled_for_days: Some(30),
                ..Default::default()
            },
        }
    }

    fn minimal_valid() -> RetentionPolicy {
        RetentionPolicy {
            version: POLICY_VERSION,
            enabled: true,
            dry_run_only: false,
            min_run_interval_seconds: 3600,
            size_budget: None,
            rules: vec![example_hosted_rule()],
        }
    }

    #[test]
    fn roundtrips_the_design_example() {
        let policy = RetentionPolicy {
            version: 1,
            enabled: true,
            dry_run_only: false,
            min_run_interval_seconds: 3600,
            size_budget: None,
            rules: vec![example_hosted_rule(), example_proxy_rule()],
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: RetentionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn deserializes_compact_jsonc_shape() {
        // Mirrors the doc example with optional fields omitted (serde defaults).
        let json = r#"{
            "version": 1,
            "rules": [
                {
                    "id": "keep-recent",
                    "action": "hard_delete",
                    "criteria": { "keep_last_n": 10, "older_than_days": 90 }
                }
            ]
        }"#;
        let policy: RetentionPolicy = serde_json::from_str(json).unwrap();
        assert!(policy.enabled, "enabled defaults to true");
        assert!(!policy.dry_run_only);
        assert_eq!(policy.min_run_interval_seconds, 3600);
        assert_eq!(policy.rules.len(), 1);
        let r = &policy.rules[0];
        assert_eq!(r.scope, Scope::Hosted);
        assert_eq!(r.release_type, ReleaseType::Any);
        assert_eq!(r.criteria.keep_last_n, Some(10));
        validate_policy(&policy, RepoKind::Hosted).unwrap();
    }

    #[test]
    fn action_and_enums_use_snake_case_wire_form() {
        assert_eq!(
            serde_json::to_string(&Action::HardDelete).unwrap(),
            "\"hard_delete\""
        );
        assert_eq!(
            serde_json::to_string(&Action::Unlist).unwrap(),
            "\"unlist\""
        );
        assert_eq!(
            serde_json::to_string(&Scope::ProxyCached).unwrap(),
            "\"proxy_cached\""
        );
        assert_eq!(
            serde_json::to_string(&ReleaseType::Prereleases).unwrap(),
            "\"prereleases\""
        );
    }

    #[test]
    fn accepts_minimal_valid_policy() {
        validate_policy(&minimal_valid(), RepoKind::Hosted).unwrap();
    }

    #[test]
    fn rejects_wrong_version() {
        let mut p = minimal_valid();
        p.version = 2;
        assert_eq!(
            validate_policy(&p, RepoKind::Hosted),
            Err(PolicyError::UnsupportedVersion {
                found: 2,
                expected: 1
            })
        );
    }

    #[test]
    fn rejects_empty_rules() {
        let mut p = minimal_valid();
        p.rules.clear();
        assert_eq!(
            validate_policy(&p, RepoKind::Hosted),
            Err(PolicyError::EmptyRules)
        );
    }

    #[test]
    fn size_budget_can_be_the_only_policy_content() {
        let mut p = minimal_valid();
        p.rules.clear();
        p.size_budget = Some(SizeBudget {
            max_bytes: 100,
            target_bytes: None,
        });
        validate_policy(&p, RepoKind::Hosted).unwrap();
        assert_eq!(p.size_budget.unwrap().target_bytes(), 90);
    }

    #[test]
    fn rejects_invalid_size_budgets() {
        for budget in [
            SizeBudget {
                max_bytes: 0,
                target_bytes: None,
            },
            SizeBudget {
                max_bytes: 100,
                target_bytes: Some(101),
            },
        ] {
            let mut p = minimal_valid();
            p.size_budget = Some(budget);
            assert_eq!(
                validate_policy(&p, RepoKind::Hosted),
                Err(PolicyError::InvalidSizeBudget)
            );
        }
    }

    #[test]
    fn reserves_the_size_budget_audit_rule_id() {
        let mut p = minimal_valid();
        p.rules[0].id = "size_budget".into();
        assert_eq!(
            validate_policy(&p, RepoKind::Hosted),
            Err(PolicyError::ReservedRuleId)
        );
    }

    #[test]
    fn rejects_empty_rule_id() {
        let mut p = minimal_valid();
        p.rules[0].id = "  ".into();
        assert_eq!(
            validate_policy(&p, RepoKind::Hosted),
            Err(PolicyError::EmptyRuleId)
        );
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let mut p = minimal_valid();
        p.rules.push(example_hosted_rule());
        assert_eq!(
            validate_policy(&p, RepoKind::Hosted),
            Err(PolicyError::DuplicateRuleId("keep-recent-releases".into()))
        );
    }

    #[test]
    fn rejects_proxy_scope_on_hosted_repo() {
        let p = RetentionPolicy {
            rules: vec![example_proxy_rule()],
            ..minimal_valid()
        };
        assert_eq!(
            validate_policy(&p, RepoKind::Hosted),
            Err(PolicyError::ProxyScopeOnNonProxy("proxy-evict-cold".into()))
        );
    }

    #[test]
    fn accepts_proxy_scope_on_proxy_repo() {
        let p = RetentionPolicy {
            rules: vec![example_proxy_rule()],
            ..minimal_valid()
        };
        validate_policy(&p, RepoKind::Proxy).unwrap();
    }

    #[test]
    fn rejects_hosted_scope_on_proxy_repo() {
        // Regression (H2): the natural `{action: hard_delete, criteria:
        // {older_than_days: 30}}` omits `scope`, which defaults to `hosted`. On
        // a proxy that would delete cached components behind
        // `proxy_cached_version`'s back, so it must be rejected with a message
        // pointing the operator at `scope: "proxy_cached"`.
        let json = r#"{
            "version": 1,
            "rules": [
                { "id": "sweep", "action": "hard_delete", "criteria": { "older_than_days": 30 } }
            ]
        }"#;
        let p: RetentionPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(p.rules[0].scope, Scope::Hosted, "scope defaults to hosted");
        let err = validate_policy(&p, RepoKind::Proxy).unwrap_err();
        assert_eq!(err, PolicyError::HostedScopeOnProxy("sweep".into()));
        assert!(
            err.to_string().contains(r#""scope": "proxy_cached""#),
            "error must tell the operator what to use instead: {err}"
        );
        // The same rule is fine on a hosted repo.
        validate_policy(&p, RepoKind::Hosted).unwrap();
    }

    #[test]
    fn rejects_hosted_rule_mixed_into_proxy_policy() {
        // A valid proxy rule does not excuse a hosted-scope sibling.
        let p = RetentionPolicy {
            rules: vec![example_proxy_rule(), example_hosted_rule()],
            ..minimal_valid()
        };
        assert_eq!(
            validate_policy(&p, RepoKind::Proxy),
            Err(PolicyError::HostedScopeOnProxy(
                "keep-recent-releases".into()
            ))
        );
    }

    #[test]
    fn rejects_not_pulled_on_hosted_scope() {
        let mut rule = example_hosted_rule();
        rule.criteria.not_pulled_for_days = Some(10);
        let p = RetentionPolicy {
            rules: vec![rule],
            ..minimal_valid()
        };
        assert_eq!(
            validate_policy(&p, RepoKind::Hosted),
            Err(PolicyError::NotPulledOnHostedScope(
                "keep-recent-releases".into()
            ))
        );
    }

    #[test]
    fn rejects_hosted_fields_on_proxy_scope() {
        let mut rule = example_proxy_rule();
        rule.criteria.older_than_days = Some(5);
        let p = RetentionPolicy {
            rules: vec![rule],
            ..minimal_valid()
        };
        assert_eq!(
            validate_policy(&p, RepoKind::Proxy),
            Err(PolicyError::HostedFieldOnProxyScope {
                rule: "proxy-evict-cold".into(),
                field: "older_than_days",
            })
        );
    }

    #[test]
    fn accepts_protections_on_proxy_scope() {
        let mut rule = example_proxy_rule();
        rule.criteria.keep_last_n = Some(3);
        rule.criteria.keep_n_most_downloaded = Some(5);
        let p = RetentionPolicy {
            rules: vec![rule.clone()],
            ..minimal_valid()
        };
        validate_policy(&p, RepoKind::Proxy).unwrap();
        // Zero still protects nothing and is refused, as on hosted rules.
        rule.criteria.keep_last_n = Some(0);
        let p = RetentionPolicy {
            rules: vec![rule.clone()],
            ..minimal_valid()
        };
        assert!(matches!(
            validate_policy(&p, RepoKind::Proxy),
            Err(PolicyError::ZeroCount {
                field: "keep_last_n",
                ..
            })
        ));
        // A proxy rule still needs its trigger.
        rule.criteria.keep_last_n = Some(3);
        rule.criteria.not_pulled_for_days = None;
        let p = RetentionPolicy {
            rules: vec![rule],
            ..minimal_valid()
        };
        assert!(matches!(
            validate_policy(&p, RepoKind::Proxy),
            Err(PolicyError::RuleHasNoTrigger(_))
        ));
    }

    #[test]
    fn rejects_zero_counts() {
        let mut p = minimal_valid();
        p.rules[0].criteria.keep_last_n = Some(0);
        assert_eq!(
            validate_policy(&p, RepoKind::Hosted),
            Err(PolicyError::ZeroCount {
                rule: "keep-recent-releases".into(),
                field: "keep_last_n"
            })
        );
    }

    #[test]
    fn rejects_zero_days() {
        let mut p = minimal_valid();
        p.rules[0].criteria.older_than_days = Some(0);
        assert_eq!(
            validate_policy(&p, RepoKind::Hosted),
            Err(PolicyError::ZeroDays {
                rule: "keep-recent-releases".into(),
                field: "older_than_days"
            })
        );
    }

    #[test]
    fn rejects_rule_with_no_trigger() {
        // Only a protection, no trigger → meaningless rule.
        let rule = RetentionRule {
            id: "protect-only".into(),
            action: Action::HardDelete,
            scope: Scope::Hosted,
            release_type: ReleaseType::Any,
            package_name_prefix: None,
            criteria: Criteria {
                keep_last_n: Some(5),
                ..Default::default()
            },
        };
        let p = RetentionPolicy {
            rules: vec![rule],
            ..minimal_valid()
        };
        assert_eq!(
            validate_policy(&p, RepoKind::Hosted),
            Err(PolicyError::RuleHasNoTrigger("protect-only".into()))
        );
    }

    #[test]
    fn rejects_any_policy_on_group_repo() {
        assert_eq!(
            validate_policy(&minimal_valid(), RepoKind::Group),
            Err(PolicyError::GroupRepoUnsupported)
        );
    }

    #[test]
    fn disabled_policy_is_still_validated() {
        let mut p = minimal_valid();
        p.enabled = false;
        p.rules[0].criteria.keep_last_n = Some(0);
        // Even disabled, a broken rule is rejected so a later enable is safe.
        assert!(validate_policy(&p, RepoKind::Hosted).is_err());
    }
}
