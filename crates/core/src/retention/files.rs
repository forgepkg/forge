//! Retention of raw files.
//!
//! A raw repository's `retention_policy` has the envelope of a package
//! policy (`version`, `enabled`, `dry_run_only`, `min_run_interval_seconds`,
//! `rules`) with file rules. Each rule looks at the files under its
//! `path_prefix` (all files without one), directory by directory:
//!
//! * `keep_newest_per_directory` keeps the N most recently deployed files of
//!   each directory (among the rule's files);
//! * any other file goes when every trigger the rule sets holds:
//!   `older_than_days` since its content was deployed, and
//!   `not_downloaded_for_days` since its last download (or its deployment,
//!   when that is later or it was never downloaded).
//!
//! A rule with only `keep_newest_per_directory` keeps N files per directory.
//! A file goes when any rule selects it. On a proxy the same rules evict
//! cached files, which the upstream serves again on their next download.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use forge_db::model::RepoKind;
use forge_db::raw_dao::{self, RetentionFile};
use forge_db::retention_dao::{self, AuditRow, RunSummary};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::model::{SizeBudget, MAX_MIN_RUN_INTERVAL_SECONDS, POLICY_VERSION};

fn default_true() -> bool {
    true
}
fn default_interval() -> u64 {
    3600
}

/// A raw file retention policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRetentionPolicy {
    pub version: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub dry_run_only: bool,
    #[serde(default = "default_interval")]
    pub min_run_interval_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_budget: Option<SizeBudget>,
    pub rules: Vec<FileRule>,
}

/// One raw file retention rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRule {
    pub id: String,
    /// Only files whose path starts with this (e.g. `nightly/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// Files kept per directory: the most recently deployed ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_newest_per_directory: Option<u32>,
    /// Trigger: the file's content was deployed at least this many days ago.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub older_than_days: Option<u32>,
    /// Trigger: the file was not downloaded for this many days (counted from
    /// its deployment when that is later, or when it was never downloaded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_downloaded_for_days: Option<u32>,
}

impl FileRule {
    fn matches(&self, path: &str) -> bool {
        self.path_prefix
            .as_deref()
            .is_none_or(|prefix| path.starts_with(prefix))
    }
}

/// Validate a raw file policy for a repository of `kind`.
pub fn validate_file_policy(policy: &FileRetentionPolicy, kind: RepoKind) -> Result<(), String> {
    if kind == RepoKind::Group {
        return Err(
            "group repositories hold no files of their own; set retention on their members".into(),
        );
    }
    if policy.version != POLICY_VERSION {
        return Err(format!(
            "unsupported policy version {} (expected {POLICY_VERSION})",
            policy.version
        ));
    }
    if policy.min_run_interval_seconds > MAX_MIN_RUN_INTERVAL_SECONDS {
        return Err(format!(
            "min_run_interval_seconds must be at most {MAX_MIN_RUN_INTERVAL_SECONDS}"
        ));
    }
    if policy.rules.is_empty() && policy.size_budget.is_none() {
        return Err("a policy needs at least one rule".into());
    }
    if let Some(budget) = policy.size_budget {
        if budget.max_bytes == 0
            || budget
                .target_bytes
                .is_some_and(|target| target > budget.max_bytes)
        {
            return Err("size_budget.max_bytes must be greater than zero and target_bytes must not exceed max_bytes".into());
        }
    }
    let mut ids = HashSet::new();
    for rule in &policy.rules {
        if rule.id.trim().is_empty() {
            return Err("every rule needs an id".into());
        }
        if !ids.insert(rule.id.as_str()) {
            return Err(format!("duplicate rule id {:?}", rule.id));
        }
        if rule.id == "size_budget" {
            return Err("rule id \"size_budget\" is reserved".into());
        }
        if rule.keep_newest_per_directory.is_none()
            && rule.older_than_days.is_none()
            && rule.not_downloaded_for_days.is_none()
        {
            return Err(format!(
                "rule {:?} sets no criterion (keep_newest_per_directory, older_than_days or not_downloaded_for_days)",
                rule.id
            ));
        }
        for (field, value) in [
            ("keep_newest_per_directory", rule.keep_newest_per_directory),
            ("older_than_days", rule.older_than_days),
            ("not_downloaded_for_days", rule.not_downloaded_for_days),
        ] {
            if value == Some(0) {
                return Err(format!("rule {:?}: {field} must be at least 1", rule.id));
            }
        }
        if rule
            .path_prefix
            .as_deref()
            .is_some_and(|p| p.is_empty() || p.starts_with('/'))
        {
            return Err(format!(
                "rule {:?}: path_prefix is a path without a leading / (e.g. nightly/)",
                rule.id
            ));
        }
    }
    Ok(())
}

/// A file the policy deletes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileDecision {
    pub file_id: i64,
    pub path: String,
    pub blob_sha256: String,
    pub rule_id: String,
    pub reason: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBudgetSummary {
    pub size_before: u64,
    pub size_after: u64,
    pub target_bytes: u64,
    pub target_reached: bool,
}

/// The directory a path is in (`""`, or ending in `/`).
fn directory_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "",
    }
}

fn protected_file_ids(policy: &FileRetentionPolicy, files: &[RetentionFile]) -> HashSet<i64> {
    let mut protected = HashSet::new();
    for rule in &policy.rules {
        let mut directories: BTreeMap<&str, Vec<&RetentionFile>> = BTreeMap::new();
        for file in files.iter().filter(|f| rule.matches(&f.path)) {
            directories
                .entry(directory_of(&file.path))
                .or_default()
                .push(file);
        }
        let keep = rule.keep_newest_per_directory.unwrap_or(0) as usize;
        for group in directories.values_mut() {
            group.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then(a.path.cmp(&b.path)));
            protected.extend(group.iter().take(keep).map(|f| f.id));
        }
    }
    protected
}

/// Decide, purely, which of `files` (one repository's, or one directory's)
/// `policy` deletes as of `now`.
pub fn evaluate_files(
    now: DateTime<Utc>,
    policy: &FileRetentionPolicy,
    files: &[RetentionFile],
) -> Vec<FileDecision> {
    evaluate_files_with_budget(now, policy, files).0
}

fn evaluate_files_with_budget(
    now: DateTime<Utc>,
    policy: &FileRetentionPolicy,
    files: &[RetentionFile],
) -> (Vec<FileDecision>, Option<FileBudgetSummary>) {
    let days = |d: u32| Duration::days(i64::from(d));
    let mut by_directory: BTreeMap<&str, Vec<&RetentionFile>> = BTreeMap::new();
    for f in files {
        by_directory
            .entry(directory_of(&f.path))
            .or_default()
            .push(f);
    }
    let mut decided: HashSet<i64> = HashSet::new();
    let mut out = Vec::new();
    for rule in &policy.rules {
        for directory_files in by_directory.values() {
            let mut pool: Vec<&RetentionFile> = directory_files
                .iter()
                .copied()
                .filter(|f| rule.matches(&f.path))
                .collect();
            // Newest first; the path breaks ties so the order is stable.
            pool.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then(a.path.cmp(&b.path)));
            let keep = rule.keep_newest_per_directory.unwrap_or(0) as usize;
            for (rank, f) in pool.iter().enumerate() {
                if rank < keep || decided.contains(&f.id) {
                    continue;
                }
                let older = rule
                    .older_than_days
                    .is_none_or(|d| now - f.updated_at >= days(d));
                let unused = rule.not_downloaded_for_days.is_none_or(|d| {
                    let used = f
                        .last_downloaded_at
                        .map_or(f.updated_at, |t| t.max(f.updated_at));
                    now - used >= days(d)
                });
                if older && unused {
                    decided.insert(f.id);
                    out.push(FileDecision {
                        file_id: f.id,
                        path: f.path.clone(),
                        blob_sha256: f.blob_sha256.clone(),
                        rule_id: rule.id.clone(),
                        reason: serde_json::json!({
                            "rank": rank + 1,
                            "keep_newest_per_directory": rule.keep_newest_per_directory,
                            "older_than_days": rule.older_than_days,
                            "not_downloaded_for_days": rule.not_downloaded_for_days,
                            "deployed_at": f.updated_at,
                            "last_downloaded_at": f.last_downloaded_at,
                        }),
                    });
                }
            }
        }
    }
    let Some(budget) = policy.size_budget else {
        return (out, None);
    };
    let target_bytes = budget.target_bytes();
    let size_before = files
        .iter()
        .map(|f| u64::try_from(f.size).unwrap_or_default())
        .fold(0u64, u64::saturating_add);
    let already_deleted: HashSet<i64> = out.iter().map(|d| d.file_id).collect();
    let mut size_after = size_before.saturating_sub(
        files
            .iter()
            .filter(|f| already_deleted.contains(&f.id))
            .map(|f| u64::try_from(f.size).unwrap_or_default())
            .fold(0u64, u64::saturating_add),
    );
    let budget_triggered = size_after > budget.max_bytes;
    if budget_triggered {
        let protected = protected_file_ids(policy, files);
        let mut eligible: Vec<&RetentionFile> = files
            .iter()
            .filter(|f| !already_deleted.contains(&f.id) && !protected.contains(&f.id))
            .collect();
        eligible.sort_by(|a, b| {
            a.last_downloaded_at
                .unwrap_or(a.updated_at)
                .max(a.updated_at)
                .cmp(
                    &b.last_downloaded_at
                        .unwrap_or(b.updated_at)
                        .max(b.updated_at),
                )
                .then_with(|| a.updated_at.cmp(&b.updated_at))
                .then_with(|| a.path.cmp(&b.path))
        });
        for file in eligible {
            if size_after <= target_bytes {
                break;
            }
            let size = u64::try_from(file.size).unwrap_or_default();
            out.push(FileDecision {
                file_id: file.id,
                path: file.path.clone(),
                blob_sha256: file.blob_sha256.clone(),
                rule_id: "size_budget".into(),
                reason: serde_json::json!({
                    "size_budget": budget.max_bytes,
                    "target_bytes": target_bytes,
                    "size_bytes": size,
                    "last_used_at": file.last_downloaded_at
                        .unwrap_or(file.updated_at)
                        .max(file.updated_at),
                }),
            });
            size_after = size_after.saturating_sub(size);
        }
    }
    (
        out,
        Some(FileBudgetSummary {
            size_before,
            size_after,
            target_bytes,
            target_reached: !budget_triggered || size_after <= target_bytes,
        }),
    )
}

/// Snapshot a repository and evaluate `policy` on it. Returns the decisions
/// and how many files were inspected.
pub async fn evaluate_repository(
    pool: &PgPool,
    repository_id: i64,
    now: DateTime<Utc>,
    policy: &FileRetentionPolicy,
) -> sqlx::Result<(Vec<FileDecision>, u64, Option<FileBudgetSummary>)> {
    let files = raw_dao::retention_files(pool, repository_id).await?;
    let evaluated = files.len() as u64;
    let policy = policy.clone();
    let (decisions, budget) =
        tokio::task::spawn_blocking(move || evaluate_files_with_budget(now, &policy, &files))
            .await
            .map_err(|e| sqlx::Error::Protocol(format!("file retention evaluation failed: {e}")))?;
    Ok((decisions, evaluated, budget))
}

/// What a file retention run's decisions were made under, re-checked before
/// each batch of them is applied (see [`apply_files`]).
pub struct FileRunFence<'a> {
    /// The policy as stored when the run claimed the repository.
    pub stored_policy: &'a serde_json::Value,
    /// The same policy, parsed: re-evaluates a directory's files.
    pub policy: &'a FileRetentionPolicy,
    /// When the decisions were evaluated; ages are judged as of then.
    pub evaluated_at: DateTime<Utc>,
}

/// The most decisions of one directory applied in one transaction.
const FILE_BATCH: usize = 100;

/// Apply decisions (or, `dry_run`, only audit them).
///
/// Decisions are applied per directory, in batches of up to
/// [`FILE_BATCH`], one transaction each. With a `fence`, each batch first
/// checks that the run still owns its lease and that the stored policy is
/// still the one it evaluated, or the run stops (the next run evaluates the
/// rest). It then locks the directory's files and evaluates the policy on
/// them again: a decision their current state no longer produces (a file
/// downloaded or redeployed since, a newer one deleted meanwhile) is
/// skipped.
pub async fn apply_files(
    pool: &PgPool,
    repository_id: i64,
    run_id: uuid::Uuid,
    decisions: &[FileDecision],
    grace: Duration,
    dry_run: bool,
    fence: Option<&FileRunFence<'_>>,
) -> sqlx::Result<RunSummary> {
    let mut summary = RunSummary::default();
    let mut directories: Vec<(&str, Vec<&FileDecision>)> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for d in decisions {
        let dir = directory_of(&d.path);
        let i = *index.entry(dir).or_insert_with(|| {
            directories.push((dir, Vec::new()));
            directories.len() - 1
        });
        directories[i].1.push(d);
    }
    let mut remaining = decisions.len();
    for (dir, all) in &directories {
        for batch in all.chunks(FILE_BATCH) {
            let mut tx = pool.begin().await?;
            let mut decided_now: Option<HashSet<i64>> = None;
            if let Some(fence) = fence.filter(|_| !dry_run) {
                if !retention_dao::lock_run_fence(
                    &mut tx,
                    repository_id,
                    run_id,
                    fence.stored_policy,
                )
                .await?
                {
                    tracing::info!(
                        repository_id,
                        %run_id,
                        remaining,
                        "file retention run stopped: it lost its lease or its policy changed; \
                         the next run re-evaluates the rest"
                    );
                    summary.skipped += remaining as u64;
                    return Ok(summary);
                }
                let locked =
                    raw_dao::lock_directory_for_retention(&mut tx, repository_id, dir).await?;
                let mut decided: HashSet<i64> =
                    evaluate_files(fence.evaluated_at, fence.policy, &locked)
                        .into_iter()
                        .filter(|d| d.rule_id != "size_budget")
                        .map(|d| d.file_id)
                        .collect();
                let protected = protected_file_ids(fence.policy, &locked);
                decided.extend(
                    batch
                        .iter()
                        .filter(|d| d.rule_id == "size_budget")
                        .filter(|d| !protected.contains(&d.file_id))
                        .filter(|d| {
                            locked.iter().find(|f| f.id == d.file_id).is_some_and(|f| {
                                f.updated_at <= fence.evaluated_at
                                    && f.last_downloaded_at.is_none_or(|t| t <= fence.evaluated_at)
                            })
                        })
                        .map(|d| d.file_id),
                );
                decided_now = Some(decided);
            }
            // Blob rows are locked in hash order, as every other writer
            // takes them.
            let mut batch = batch.to_vec();
            batch.sort_by(|a, b| a.blob_sha256.cmp(&b.blob_sha256));
            for &d in &batch {
                let still = decided_now
                    .as_ref()
                    .is_none_or(|ids| ids.contains(&d.file_id));
                let deleted = if still && !dry_run {
                    raw_dao::delete_by_id(&mut tx, repository_id, d.file_id, grace).await?
                } else {
                    None
                };
                let applied = still && (dry_run || deleted.is_some());
                if applied {
                    summary.deleted += 1;
                } else {
                    summary.skipped += 1;
                }
                if deleted.as_ref().is_some_and(|f| f.delete_enqueued) {
                    summary.blobs_enqueued += 1;
                }
                retention_dao::insert_audit(
                    &mut *tx,
                    &AuditRow {
                        repository_id,
                        run_id,
                        rule_id: d.rule_id.clone(),
                        action: if applied { "hard_delete" } else { "skipped" }.into(),
                        target_kind: "raw_file".into(),
                        package_name: d.path.clone(),
                        version: d.blob_sha256.clone(),
                        component_id: None,
                        blob_sha256: deleted.as_ref().map(|f| f.blob_sha256.clone()),
                        ref_count_after: deleted.as_ref().and_then(|f| f.ref_count_after),
                        blob_delete_enqueued: deleted.as_ref().is_some_and(|f| f.delete_enqueued),
                        dry_run,
                        reason: d.reason.clone(),
                    },
                )
                .await?;
            }
            tx.commit().await?;
            remaining -= batch.len();
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(days_ago: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
            - Duration::days(days_ago)
    }
    fn file(id: i64, path: &str, deployed_days_ago: i64, downloaded: Option<i64>) -> RetentionFile {
        RetentionFile {
            id,
            path: path.into(),
            blob_sha256: format!("sha{id}"),
            size: 1,
            updated_at: at(deployed_days_ago),
            last_downloaded_at: downloaded.map(at),
        }
    }
    fn policy(rules: Vec<FileRule>) -> FileRetentionPolicy {
        FileRetentionPolicy {
            version: 1,
            enabled: true,
            dry_run_only: false,
            min_run_interval_seconds: 3600,
            size_budget: None,
            rules,
        }
    }
    fn rule(id: &str) -> FileRule {
        FileRule {
            id: id.into(),
            path_prefix: None,
            keep_newest_per_directory: None,
            older_than_days: None,
            not_downloaded_for_days: None,
        }
    }
    fn deleted(d: &[FileDecision]) -> Vec<&str> {
        let mut paths: Vec<&str> = d.iter().map(|d| d.path.as_str()).collect();
        paths.sort_unstable();
        paths
    }

    #[test]
    fn keeps_the_newest_files_per_directory() {
        let files = vec![
            file(1, "nightly/a/1.tgz", 30, None),
            file(2, "nightly/a/2.tgz", 20, None),
            file(3, "nightly/a/3.tgz", 10, None),
            file(4, "nightly/b/1.tgz", 30, None),
            file(5, "release/1.tgz", 90, None),
        ];
        let mut r = rule("keep2");
        r.keep_newest_per_directory = Some(2);
        r.path_prefix = Some("nightly/".into());
        let d = evaluate_files(at(0), &policy(vec![r]), &files);
        assert_eq!(deleted(&d), ["nightly/a/1.tgz"]);
    }

    #[test]
    fn triggers_hold_together() {
        let files = vec![
            // Old and never downloaded.
            file(1, "x/old-unused", 60, None),
            // Old, but downloaded yesterday.
            file(2, "x/old-used", 60, Some(1)),
            // Recent.
            file(3, "x/new", 2, None),
        ];
        let mut r = rule("stale");
        r.older_than_days = Some(30);
        r.not_downloaded_for_days = Some(14);
        let d = evaluate_files(at(0), &policy(vec![r]), &files);
        assert_eq!(deleted(&d), ["x/old-unused"]);
        let mut only_unused = rule("unused");
        only_unused.not_downloaded_for_days = Some(14);
        // Never downloaded: counted from its deployment two days ago.
        let d = evaluate_files(at(0), &policy(vec![only_unused]), &files);
        assert_eq!(deleted(&d), ["x/old-unused"]);
    }

    #[test]
    fn any_rule_deletes_once() {
        let files = vec![file(1, "a", 60, None), file(2, "b", 1, None)];
        let mut old = rule("old");
        old.older_than_days = Some(30);
        let mut keep = rule("keep1");
        keep.keep_newest_per_directory = Some(1);
        let d = evaluate_files(at(0), &policy(vec![old, keep]), &files);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].path, "a");
        assert_eq!(d[0].rule_id, "old");
    }

    #[test]
    fn validation() {
        let mut ok = rule("a");
        ok.keep_newest_per_directory = Some(3);
        assert!(validate_file_policy(&policy(vec![ok.clone()]), RepoKind::Hosted).is_ok());
        assert!(validate_file_policy(&policy(vec![ok.clone()]), RepoKind::Proxy).is_ok());
        assert!(validate_file_policy(&policy(vec![ok.clone()]), RepoKind::Group).is_err());
        assert!(validate_file_policy(&policy(vec![rule("empty")]), RepoKind::Hosted).is_err());
        let mut zero = rule("z");
        zero.older_than_days = Some(0);
        assert!(validate_file_policy(&policy(vec![zero]), RepoKind::Hosted).is_err());
        let mut slash = ok.clone();
        slash.path_prefix = Some("/nightly".into());
        assert!(validate_file_policy(&policy(vec![slash]), RepoKind::Hosted).is_err());
        assert!(
            validate_file_policy(&policy(vec![ok.clone(), ok]), RepoKind::Hosted).is_err(),
            "duplicate ids"
        );
        let parsed: Result<FileRetentionPolicy, _> = serde_json::from_value(
            serde_json::json!({"version": 1, "rules": [{"id": "x", "keep_last_n": 1}]}),
        );
        assert!(parsed.is_err(), "unknown fields are refused");
    }

    #[test]
    fn budget_only_file_policy_is_valid_and_budget_is_validated() {
        let mut p = policy(Vec::new());
        p.size_budget = Some(SizeBudget {
            max_bytes: 100,
            target_bytes: Some(80),
        });
        assert!(validate_file_policy(&p, RepoKind::Hosted).is_ok());
        p.size_budget.as_mut().unwrap().max_bytes = 0;
        assert!(validate_file_policy(&p, RepoKind::Hosted).is_err());
    }

    #[test]
    fn size_budget_deletes_oldest_file_but_keeps_each_directory_protection() {
        let mut files = vec![
            file(1, "dir/old", 100, Some(90)),
            file(2, "dir/mid", 50, Some(20)),
            file(3, "dir/new", 10, Some(1)),
        ];
        files[0].size = 3;
        files[1].size = 2;
        files[2].size = 1;
        let mut policy = policy(vec![{
            let mut keep = rule("keep");
            keep.keep_newest_per_directory = Some(1);
            keep.older_than_days = Some(1000);
            keep
        }]);
        policy.size_budget = Some(SizeBudget {
            max_bytes: 4,
            target_bytes: Some(2),
        });
        let decisions = evaluate_files(at(0), &policy, &files);
        assert_eq!(
            decisions.iter().map(|d| d.file_id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(decisions.iter().all(|d| d.rule_id == "size_budget"));
    }

    #[test]
    fn size_budget_reports_unreached_target_when_directory_protection_remains() {
        let mut files = vec![file(1, "dir/old", 100, None), file(2, "dir/new", 10, None)];
        files[0].size = 3;
        files[1].size = 2;
        let mut policy = policy(vec![{
            let mut keep = rule("keep");
            keep.keep_newest_per_directory = Some(1);
            keep.older_than_days = Some(1000);
            keep
        }]);
        policy.size_budget = Some(SizeBudget {
            max_bytes: 4,
            target_bytes: Some(1),
        });
        let (_, budget) = evaluate_files_with_budget(at(0), &policy, &files);
        let budget = budget.unwrap();
        assert_eq!(budget.size_after, 2);
        assert!(!budget.target_reached);
    }
}
