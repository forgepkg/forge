//! Retention of Docker / OCI images.
//!
//! A docker repository's `retention_policy` has the envelope of a package
//! policy (`version`, `enabled`, `dry_run_only`, `min_run_interval_seconds`,
//! `rules`) with image rules:
//!
//! * **Tag rules** delete tags: per image (optionally only those under an
//!   `image_prefix`), the `keep_last_n_tags` most recently pushed tags and the
//!   `protected_tags` stay; any other tag goes when every set trigger holds
//!   (`tag_older_than_days` since it was pushed, `tag_not_pulled_for_days`).
//!   A rule with only `keep_last_n_tags` keeps N tags per image.
//! * **Untagged rules** (`delete_untagged_after_days`) delete manifests that
//!   have had no tag for that long — unless something kept refers to them:
//!   the children of a kept index, and the referrers (signatures, SBOMs,
//!   attestations) of a kept manifest are kept with it.
//!
//! Deleting a manifest releases only its own blob reference; its layers stay
//! linked to the image until the registry sweeper finds no manifest naming
//! them, so a layer another image still uses is never removed.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use forge_db::model::RepoKind;
use forge_db::oci_dao::{self, RetentionManifest, RetentionTag};
use forge_db::retention_dao::{self, AuditRow, RunSummary};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::model::{MAX_MIN_RUN_INTERVAL_SECONDS, POLICY_VERSION};

fn default_true() -> bool {
    true
}
fn default_interval() -> u64 {
    3600
}

/// An image retention policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRetentionPolicy {
    pub version: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub dry_run_only: bool,
    #[serde(default = "default_interval")]
    pub min_run_interval_seconds: u64,
    pub rules: Vec<ImageRule>,
}

/// One image retention rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRule {
    pub id: String,
    /// Only images whose name starts with this (e.g. `team/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_prefix: Option<String>,
    /// Tags kept per image: the most recently pushed ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_last_n_tags: Option<u32>,
    /// Tags never deleted by this rule (e.g. `latest`, `stable`), kept in
    /// addition to the `keep_last_n_tags` newest others.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_tags: Vec<String>,
    /// Trigger: the tag was pushed at least this many days ago.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_older_than_days: Option<u32>,
    /// Trigger: its manifest was not pulled for this many days (or never,
    /// counted from the push).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_not_pulled_for_days: Option<u32>,
    /// Delete manifests untagged for this many days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_untagged_after_days: Option<u32>,
}

impl ImageRule {
    fn has_tag_criteria(&self) -> bool {
        self.keep_last_n_tags.is_some()
            || self.tag_older_than_days.is_some()
            || self.tag_not_pulled_for_days.is_some()
    }

    fn matches(&self, image: &str) -> bool {
        self.image_prefix
            .as_deref()
            .is_none_or(|p| image.starts_with(p))
    }
}

/// Validate an image policy for a repository of `kind`.
pub fn validate_image_policy(policy: &ImageRetentionPolicy, kind: RepoKind) -> Result<(), String> {
    if kind == RepoKind::Group {
        return Err(
            "group repositories hold no images of their own; set retention on their members".into(),
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
    if policy.rules.is_empty() {
        return Err("a policy needs at least one rule".into());
    }
    let mut ids = HashSet::new();
    for rule in &policy.rules {
        if rule.id.trim().is_empty() {
            return Err("every rule needs an id".into());
        }
        if !ids.insert(rule.id.as_str()) {
            return Err(format!("duplicate rule id {:?}", rule.id));
        }
        if !rule.has_tag_criteria() && rule.delete_untagged_after_days.is_none() {
            return Err(format!(
                "rule {:?} sets no criterion (keep_last_n_tags, tag_older_than_days, tag_not_pulled_for_days or delete_untagged_after_days)",
                rule.id
            ));
        }
        for (field, value) in [
            ("tag_older_than_days", rule.tag_older_than_days),
            ("tag_not_pulled_for_days", rule.tag_not_pulled_for_days),
            (
                "delete_untagged_after_days",
                rule.delete_untagged_after_days,
            ),
        ] {
            if value == Some(0) {
                return Err(format!("rule {:?}: {field} must be at least 1", rule.id));
            }
        }
        if !rule.protected_tags.is_empty() && !rule.has_tag_criteria() {
            return Err(format!(
                "rule {:?}: protected_tags needs a tag criterion",
                rule.id
            ));
        }
    }
    Ok(())
}

/// A tag the policy deletes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TagDecision {
    pub image: String,
    pub tag: String,
    pub manifest_id: i64,
    pub digest: String,
    pub rule_id: String,
    pub reason: serde_json::Value,
}

/// A manifest the policy deletes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestDecision {
    pub image: String,
    pub manifest_id: i64,
    pub digest: String,
    pub rule_id: String,
    pub reason: serde_json::Value,
}

/// What a policy decides for a repository.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ImageDecisions {
    pub tags: Vec<TagDecision>,
    pub manifests: Vec<ManifestDecision>,
}

/// Decide, purely, what `policy` deletes from `tags` and `manifests` (one
/// repository's snapshot) as of `now`.
pub fn evaluate_images(
    now: DateTime<Utc>,
    policy: &ImageRetentionPolicy,
    tags: &[RetentionTag],
    manifests: &[RetentionManifest],
) -> ImageDecisions {
    let mut decisions = ImageDecisions::default();
    let days = |d: u32| Duration::days(i64::from(d));

    // ── Tags ────────────────────────────────────────────────────────────────
    let mut by_image: HashMap<&str, Vec<&RetentionTag>> = HashMap::new();
    for t in tags {
        by_image.entry(t.image.as_str()).or_default().push(t);
    }
    let mut deleted_tags: HashSet<(&str, &str)> = HashSet::new();
    for rule in policy.rules.iter().filter(|r| r.has_tag_criteria()) {
        for (image, image_tags) in &by_image {
            if !rule.matches(image) {
                continue;
            }
            // Protected tags stay on top of the N kept ones.
            let mut ordered: Vec<&RetentionTag> = image_tags
                .iter()
                .copied()
                .filter(|t| !rule.protected_tags.iter().any(|p| p == &t.tag))
                .collect();
            ordered.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then(a.tag.cmp(&b.tag)));
            let keep = rule.keep_last_n_tags.unwrap_or(0) as usize;
            for (rank, t) in ordered.iter().enumerate() {
                if rank < keep {
                    continue;
                }
                if deleted_tags.contains(&(t.image.as_str(), t.tag.as_str())) {
                    continue;
                }
                let older = rule
                    .tag_older_than_days
                    .is_none_or(|d| now - t.updated_at >= days(d));
                let unpulled = rule.tag_not_pulled_for_days.is_none_or(|d| {
                    now - t.last_pulled_at.unwrap_or(t.updated_at).max(t.updated_at) >= days(d)
                });
                if older && unpulled {
                    deleted_tags.insert((t.image.as_str(), t.tag.as_str()));
                    decisions.tags.push(TagDecision {
                        image: t.image.clone(),
                        tag: t.tag.clone(),
                        manifest_id: t.manifest_id,
                        digest: t.digest.clone(),
                        rule_id: rule.id.clone(),
                        reason: serde_json::json!({
                            "rank": rank + 1,
                            "keep_last_n_tags": rule.keep_last_n_tags,
                            "tag_older_than_days": rule.tag_older_than_days,
                            "tag_not_pulled_for_days": rule.tag_not_pulled_for_days,
                            "pushed_at": t.updated_at,
                            "last_pulled_at": t.last_pulled_at,
                        }),
                    });
                }
            }
        }
    }

    // ── Untagged manifests ──────────────────────────────────────────────────
    let untagged_rules: Vec<&ImageRule> = policy
        .rules
        .iter()
        .filter(|r| r.delete_untagged_after_days.is_some())
        .collect();
    if untagged_rules.is_empty() {
        return decisions;
    }
    // Manifests that keep a tag after this run.
    let still_tagged: HashSet<i64> = tags
        .iter()
        .filter(|t| !deleted_tags.contains(&(t.image.as_str(), t.tag.as_str())))
        .map(|t| t.manifest_id)
        .collect();
    let mut per_image: HashMap<&str, Vec<&RetentionManifest>> = HashMap::new();
    for m in manifests {
        per_image.entry(m.image.as_str()).or_default().push(m);
    }
    for (image, image_manifests) in per_image {
        // The rule deleting each candidate (first matching rule wins).
        let mut candidates: HashMap<i64, &ImageRule> = HashMap::new();
        for m in &image_manifests {
            if still_tagged.contains(&m.id) {
                continue;
            }
            // Losing its last tag in this run starts its untagged clock now.
            let Some(since) = m.untagged_since else {
                continue;
            };
            if let Some(rule) = untagged_rules.iter().find(|r| {
                r.matches(image)
                    && now - since >= days(r.delete_untagged_after_days.unwrap_or(u32::MAX))
            }) {
                candidates.insert(m.id, rule);
            }
        }
        if candidates.is_empty() {
            continue;
        }
        // Everything not a candidate is kept, and keeps what it refers to.
        let by_digest: HashMap<&str, &RetentionManifest> = image_manifests
            .iter()
            .map(|m| (m.digest.as_str(), *m))
            .collect();
        let mut kept: HashSet<i64> = image_manifests
            .iter()
            .filter(|m| !candidates.contains_key(&m.id))
            .map(|m| m.id)
            .collect();
        loop {
            let mut grew = false;
            for m in &image_manifests {
                if kept.contains(&m.id) {
                    for child in &m.children {
                        if let Some(c) = by_digest.get(child.as_str()) {
                            grew |= kept.insert(c.id);
                        }
                    }
                } else if let Some(subject) = &m.subject_digest {
                    // A referrer of a kept manifest stays with it.
                    if by_digest
                        .get(subject.as_str())
                        .is_some_and(|s| kept.contains(&s.id))
                    {
                        grew |= kept.insert(m.id);
                    }
                }
            }
            if !grew {
                break;
            }
        }
        // Indexes before their children, so a child is unreferenced by the
        // time it is deleted.
        let mut doomed: Vec<&RetentionManifest> = image_manifests
            .iter()
            .copied()
            .filter(|m| candidates.contains_key(&m.id) && !kept.contains(&m.id))
            .collect();
        doomed.sort_by_key(|m| (m.children.is_empty(), m.id));
        for m in doomed {
            let rule = candidates[&m.id];
            decisions.manifests.push(ManifestDecision {
                image: m.image.clone(),
                manifest_id: m.id,
                digest: m.digest.clone(),
                rule_id: rule.id.clone(),
                reason: serde_json::json!({
                    "delete_untagged_after_days": rule.delete_untagged_after_days,
                    "untagged_since": m.untagged_since,
                }),
            });
        }
    }
    decisions
}

/// Snapshot a repository and evaluate `policy` on it. Returns the decisions
/// and how many tags and manifests were inspected.
pub async fn evaluate_repository(
    pool: &PgPool,
    repository_id: i64,
    now: DateTime<Utc>,
    policy: &ImageRetentionPolicy,
) -> sqlx::Result<(ImageDecisions, u64)> {
    let tags = oci_dao::retention_tags(pool, repository_id).await?;
    let manifests = oci_dao::retention_manifests(pool, repository_id).await?;
    let evaluated = (tags.len() + manifests.len()) as u64;
    let policy = policy.clone();
    let decisions =
        tokio::task::spawn_blocking(move || evaluate_images(now, &policy, &tags, &manifests))
            .await
            .map_err(|e| {
                sqlx::Error::Protocol(format!("image retention evaluation failed: {e}"))
            })?;
    Ok((decisions, evaluated))
}

/// Apply decisions (or, `dry_run`, only audit them), one transaction each.
pub async fn apply_images(
    pool: &PgPool,
    repository_id: i64,
    run_id: uuid::Uuid,
    decisions: &ImageDecisions,
    grace: Duration,
    dry_run: bool,
) -> sqlx::Result<RunSummary> {
    let mut summary = RunSummary::default();
    for d in &decisions.tags {
        let mut tx = pool.begin().await?;
        let applied = dry_run
            || oci_dao::delete_tag_if(&mut tx, repository_id, &d.image, &d.tag, d.manifest_id)
                .await?;
        retention_dao::insert_audit(
            &mut *tx,
            &AuditRow {
                repository_id,
                run_id,
                rule_id: d.rule_id.clone(),
                action: if applied { "delete_tag" } else { "skipped" }.into(),
                target_kind: "oci_tag".into(),
                package_name: d.image.clone(),
                version: d.tag.clone(),
                component_id: None,
                blob_sha256: None,
                ref_count_after: None,
                blob_delete_enqueued: false,
                dry_run,
                reason: d.reason.clone(),
            },
        )
        .await?;
        tx.commit().await?;
        if applied {
            summary.deleted += 1;
        } else {
            summary.skipped += 1;
        }
    }
    for d in &decisions.manifests {
        let mut tx = pool.begin().await?;
        let applied = dry_run
            || oci_dao::delete_untagged_manifest(&mut tx, repository_id, d.manifest_id, grace)
                .await?;
        retention_dao::insert_audit(
            &mut *tx,
            &AuditRow {
                repository_id,
                run_id,
                rule_id: d.rule_id.clone(),
                action: if applied {
                    "delete_manifest"
                } else {
                    "skipped"
                }
                .into(),
                target_kind: "oci_manifest".into(),
                package_name: d.image.clone(),
                version: d.digest.clone(),
                component_id: None,
                blob_sha256: None,
                ref_count_after: None,
                blob_delete_enqueued: false,
                dry_run,
                reason: d.reason.clone(),
            },
        )
        .await?;
        tx.commit().await?;
        if applied {
            summary.deleted += 1;
        } else {
            summary.skipped += 1;
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
    fn now() -> DateTime<Utc> {
        at(0)
    }
    fn tag(image: &str, tag: &str, manifest_id: i64, pushed_days_ago: i64) -> RetentionTag {
        RetentionTag {
            image: image.into(),
            tag: tag.into(),
            manifest_id,
            digest: format!("sha256:{manifest_id}"),
            updated_at: at(pushed_days_ago),
            last_pulled_at: None,
        }
    }
    fn manifest(
        image: &str,
        id: i64,
        untagged_days_ago: Option<i64>,
        children: &[i64],
        subject: Option<i64>,
    ) -> RetentionManifest {
        RetentionManifest {
            id,
            image: image.into(),
            digest: format!("sha256:{id}"),
            created_at: at(100),
            untagged_since: untagged_days_ago.map(at),
            last_pulled_at: None,
            subject_digest: subject.map(|s| format!("sha256:{s}")),
            children: children.iter().map(|c| format!("sha256:{c}")).collect(),
        }
    }
    fn policy(rules: Vec<ImageRule>) -> ImageRetentionPolicy {
        ImageRetentionPolicy {
            version: 1,
            enabled: true,
            dry_run_only: false,
            min_run_interval_seconds: 3600,
            rules,
        }
    }
    fn rule(id: &str) -> ImageRule {
        ImageRule {
            id: id.into(),
            image_prefix: None,
            keep_last_n_tags: None,
            protected_tags: Vec::new(),
            tag_older_than_days: None,
            tag_not_pulled_for_days: None,
            delete_untagged_after_days: None,
        }
    }

    #[test]
    fn keeps_the_newest_tags_per_image() {
        let tags = vec![
            tag("app", "1", 1, 30),
            tag("app", "2", 2, 20),
            tag("app", "3", 3, 10),
            tag("app", "latest", 3, 10),
            tag("other", "1", 9, 30),
        ];
        let mut r = rule("keep2");
        r.keep_last_n_tags = Some(2);
        r.protected_tags = vec!["latest".into()];
        r.image_prefix = Some("app".into());
        let d = evaluate_images(now(), &policy(vec![r]), &tags, &[]);
        let deleted: Vec<&str> = d.tags.iter().map(|t| t.tag.as_str()).collect();
        // `latest` is protected on top of the two newest others (3, 2).
        assert_eq!(deleted, vec!["1"]);
    }

    #[test]
    fn untagged_manifests_go_unless_something_kept_refers_to_them() {
        // 10: tagged index of 11 and 12. 11, 12 untagged children (kept).
        // 13: untagged old image (deleted); 14: its signature (deleted with it).
        // 15: signature of the tagged index (kept). 16: recently untagged.
        let tags = vec![tag("app", "v1", 10, 50)];
        let manifests = vec![
            manifest("app", 10, None, &[11, 12], None),
            manifest("app", 11, Some(50), &[], None),
            manifest("app", 12, Some(50), &[], None),
            manifest("app", 13, Some(40), &[], None),
            manifest("app", 14, Some(40), &[], Some(13)),
            manifest("app", 15, Some(40), &[], Some(10)),
            manifest("app", 16, Some(2), &[], None),
        ];
        let mut r = rule("untagged");
        r.delete_untagged_after_days = Some(7);
        let d = evaluate_images(now(), &policy(vec![r]), &tags, &manifests);
        let mut deleted: Vec<i64> = d.manifests.iter().map(|m| m.manifest_id).collect();
        deleted.sort();
        assert_eq!(deleted, vec![13, 14]);
        assert!(d.tags.is_empty());
    }

    #[test]
    fn a_tag_deleted_now_starts_its_manifests_untagged_clock() {
        let tags = vec![tag("app", "old", 1, 90), tag("app", "new", 2, 1)];
        let manifests = vec![
            manifest("app", 1, None, &[], None),
            manifest("app", 2, None, &[], None),
        ];
        let mut r = rule("r");
        r.keep_last_n_tags = Some(1);
        r.delete_untagged_after_days = Some(1);
        let d = evaluate_images(now(), &policy(vec![r]), &tags, &manifests);
        assert_eq!(d.tags.len(), 1);
        assert_eq!(d.tags[0].tag, "old");
        assert!(
            d.manifests.is_empty(),
            "the manifest is untagged only from now on"
        );
    }

    #[test]
    fn index_deleted_before_its_children() {
        let manifests = vec![
            manifest("app", 2, Some(30), &[], None),
            manifest("app", 1, Some(30), &[2], None),
        ];
        let mut r = rule("u");
        r.delete_untagged_after_days = Some(7);
        let d = evaluate_images(now(), &policy(vec![r]), &[], &manifests);
        let order: Vec<i64> = d.manifests.iter().map(|m| m.manifest_id).collect();
        assert_eq!(order, vec![1, 2]);
    }

    #[test]
    fn validation() {
        let ok = policy(vec![{
            let mut r = rule("a");
            r.keep_last_n_tags = Some(3);
            r
        }]);
        assert!(validate_image_policy(&ok, RepoKind::Hosted).is_ok());
        assert!(validate_image_policy(&ok, RepoKind::Group).is_err());
        assert!(validate_image_policy(&policy(vec![rule("empty")]), RepoKind::Hosted).is_err());
        let mut zero = rule("z");
        zero.delete_untagged_after_days = Some(0);
        assert!(validate_image_policy(&policy(vec![zero]), RepoKind::Proxy).is_err());
        let parsed: Result<ImageRetentionPolicy, _> = serde_json::from_value(
            serde_json::json!({"version": 1, "rules": [{"id": "x", "keep": 1}]}),
        );
        assert!(parsed.is_err(), "unknown fields are refused");
    }
}
