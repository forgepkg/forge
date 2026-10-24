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

use super::model::{SizeBudget, MAX_MIN_RUN_INTERVAL_SECONDS, POLICY_VERSION};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_budget: Option<SizeBudget>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageBudgetSummary {
    pub size_before: u64,
    pub size_after: u64,
    pub target_bytes: u64,
    pub target_reached: bool,
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

/// Apply the repository size budget after rule decisions, considering the
/// distinct blobs each remaining manifest holds.
pub fn evaluate_image_size_budget(
    policy: &ImageRetentionPolicy,
    tags: &[RetentionTag],
    manifests: &[RetentionManifest],
    manifest_objects: &[oci_dao::RetentionManifestObject],
    blob_refs: &[oci_dao::RetentionBlobRef],
    decisions: &ImageDecisions,
    size_before: u64,
) -> (ImageDecisions, Option<ImageBudgetSummary>) {
    let Some(budget) = policy.size_budget else {
        return (ImageDecisions::default(), None);
    };
    let target_bytes = budget.target_bytes();
    let mut object_sizes: HashMap<&str, u64> = HashMap::new();
    let mut manifest_blobs: HashMap<i64, HashSet<String>> = HashMap::new();
    for object in manifest_objects {
        let size = u64::try_from(object.size).unwrap_or_default();
        object_sizes.insert(&object.blob_sha256, size);
        manifest_blobs
            .entry(object.manifest_id)
            .or_default()
            .insert(object.blob_sha256.clone());
    }
    for reference in blob_refs {
        let size = u64::try_from(reference.size).unwrap_or_default();
        object_sizes.insert(&reference.blob_sha256, size);
        manifest_blobs
            .entry(reference.manifest_id)
            .or_default()
            .insert(reference.blob_sha256.clone());
    }
    let mut remaining: HashSet<i64> = manifests.iter().map(|m| m.id).collect();
    let mut references: HashMap<String, usize> = HashMap::new();
    for id in &remaining {
        if let Some(blobs) = manifest_blobs.get(id) {
            for blob in blobs {
                *references.entry(blob.clone()).or_default() += 1;
            }
        }
    }
    let mut size_after = size_before;
    let delete_rule_manifests: HashSet<i64> =
        decisions.manifests.iter().map(|m| m.manifest_id).collect();
    for manifest in manifests
        .iter()
        .filter(|m| delete_rule_manifests.contains(&m.id))
    {
        size_after = size_after.saturating_sub(remove_manifest_objects(
            manifest.id,
            &mut remaining,
            &manifest_blobs,
            &object_sizes,
            &mut references,
        ));
    }
    if size_after <= budget.max_bytes {
        return (
            ImageDecisions::default(),
            Some(ImageBudgetSummary {
                size_before,
                size_after,
                target_bytes,
                target_reached: true,
            }),
        );
    }
    let deleted_rule_tags: HashSet<(&str, &str)> = decisions
        .tags
        .iter()
        .map(|t| (t.image.as_str(), t.tag.as_str()))
        .collect();
    let mut remaining_tags: Vec<&RetentionTag> = tags
        .iter()
        .filter(|t| {
            !deleted_rule_tags.contains(&(t.image.as_str(), t.tag.as_str()))
                && remaining.contains(&t.manifest_id)
        })
        .collect();
    let protected_tags = budget_protected_tags(policy, tags);
    let manifest_by_id: HashMap<i64, &RetentionManifest> =
        manifests.iter().map(|m| (m.id, m)).collect();
    let manifest_by_digest: HashMap<(&str, &str), i64> = manifests
        .iter()
        .map(|m| ((m.image.as_str(), m.digest.as_str()), m.id))
        .collect();
    let mut budget_decisions = ImageDecisions::default();

    let mut untagged: Vec<&RetentionManifest> = manifests
        .iter()
        .filter(|m| remaining.contains(&m.id))
        .filter(|m| !remaining_tags.iter().any(|t| t.manifest_id == m.id))
        .collect();
    untagged.sort_by(|a, b| {
        a.last_pulled_at
            .unwrap_or(a.created_at)
            .max(a.created_at)
            .cmp(&b.last_pulled_at.unwrap_or(b.created_at).max(b.created_at))
            .then_with(|| a.created_at.cmp(&b.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    while size_after > target_bytes {
        let kept = protected_manifests(
            &remaining,
            &remaining_tags,
            &manifest_by_id,
            &manifest_by_digest,
        );
        let candidate = untagged.iter().copied().find(|m| {
            remaining.contains(&m.id)
                && !kept.contains(&m.id)
                && !manifests.iter().any(|parent| {
                    remaining.contains(&parent.id)
                        && parent.id != m.id
                        && parent.children.contains(&m.digest)
                })
        });
        let Some(manifest) = candidate else {
            break;
        };
        size_after = size_after.saturating_sub(remove_manifest_objects(
            manifest.id,
            &mut remaining,
            &manifest_blobs,
            &object_sizes,
            &mut references,
        ));
        budget_decisions.manifests.push(ManifestDecision {
            image: manifest.image.clone(),
            manifest_id: manifest.id,
            digest: manifest.digest.clone(),
            rule_id: "size_budget".into(),
            reason: serde_json::json!({
                "size_budget": budget.max_bytes,
                "target_bytes": target_bytes,
                "last_used_at": manifest.last_pulled_at.unwrap_or(manifest.created_at).max(manifest.created_at),
            }),
        });
    }

    let mut tag_candidates: Vec<&RetentionTag> = remaining_tags.clone();
    tag_candidates.sort_by(|a, b| {
        a.last_pulled_at
            .unwrap_or(a.updated_at)
            .max(a.updated_at)
            .cmp(&b.last_pulled_at.unwrap_or(b.updated_at).max(b.updated_at))
            .then_with(|| a.updated_at.cmp(&b.updated_at))
            .then_with(|| a.tag.cmp(&b.tag))
    });
    for tag in tag_candidates {
        if size_after <= target_bytes {
            break;
        }
        if protected_tags.contains(&(tag.image.clone(), tag.tag.clone())) {
            continue;
        }
        let image_tag_count = remaining_tags
            .iter()
            .filter(|t| t.image == tag.image)
            .count();
        if image_tag_count <= 1 {
            continue;
        }
        remaining_tags.retain(|t| !(t.image == tag.image && t.tag == tag.tag));
        budget_decisions.tags.push(TagDecision {
            image: tag.image.clone(),
            tag: tag.tag.clone(),
            manifest_id: tag.manifest_id,
            digest: tag.digest.clone(),
            rule_id: "size_budget".into(),
            reason: serde_json::json!({
                "size_budget": budget.max_bytes,
                "target_bytes": target_bytes,
                "last_used_at": tag.last_pulled_at.unwrap_or(tag.updated_at).max(tag.updated_at),
            }),
        });
        if !remaining_tags
            .iter()
            .any(|t| t.manifest_id == tag.manifest_id)
        {
            let kept = protected_manifests(
                &remaining,
                &remaining_tags,
                &manifest_by_id,
                &manifest_by_digest,
            );
            let can_delete = remaining.contains(&tag.manifest_id)
                && !kept.contains(&tag.manifest_id)
                && !manifests.iter().any(|parent| {
                    remaining.contains(&parent.id)
                        && parent.id != tag.manifest_id
                        && parent.children.contains(&tag.digest)
                });
            if can_delete {
                let manifest = manifest_by_id[&tag.manifest_id];
                size_after = size_after.saturating_sub(remove_manifest_objects(
                    manifest.id,
                    &mut remaining,
                    &manifest_blobs,
                    &object_sizes,
                    &mut references,
                ));
                budget_decisions.manifests.push(ManifestDecision {
                    image: manifest.image.clone(),
                    manifest_id: manifest.id,
                    digest: manifest.digest.clone(),
                    rule_id: "size_budget".into(),
                    reason: serde_json::json!({
                        "size_budget": budget.max_bytes,
                        "target_bytes": target_bytes,
                        "last_used_at": manifest.last_pulled_at.unwrap_or(manifest.created_at).max(manifest.created_at),
                    }),
                });
            }
        }
    }

    (
        budget_decisions,
        Some(ImageBudgetSummary {
            size_before,
            size_after,
            target_bytes,
            target_reached: size_after <= target_bytes || size_after <= budget.max_bytes,
        }),
    )
}

fn remove_manifest_objects(
    manifest_id: i64,
    remaining: &mut HashSet<i64>,
    manifest_blobs: &HashMap<i64, HashSet<String>>,
    object_sizes: &HashMap<&str, u64>,
    references: &mut HashMap<String, usize>,
) -> u64 {
    if !remaining.remove(&manifest_id) {
        return 0;
    }
    manifest_blobs
        .get(&manifest_id)
        .into_iter()
        .flatten()
        .filter_map(|blob| {
            let count = references.get_mut(blob)?;
            *count -= 1;
            (*count == 0).then(|| object_sizes.get(blob.as_str()).copied().unwrap_or_default())
        })
        .fold(0u64, u64::saturating_add)
}

fn budget_protected_tags(
    policy: &ImageRetentionPolicy,
    tags: &[RetentionTag],
) -> HashSet<(String, String)> {
    let mut protected = HashSet::new();
    let mut by_image: HashMap<&str, Vec<&RetentionTag>> = HashMap::new();
    for tag in tags {
        by_image.entry(&tag.image).or_default().push(tag);
    }
    for rule in &policy.rules {
        for (image, image_tags) in &by_image {
            if !rule.matches(image) {
                continue;
            }
            protected.extend(
                image_tags
                    .iter()
                    .filter(|t| rule.protected_tags.iter().any(|p| p == &t.tag))
                    .map(|t| (t.image.clone(), t.tag.clone())),
            );
            if let Some(keep) = rule.keep_last_n_tags {
                let mut ordered: Vec<_> = image_tags
                    .iter()
                    .filter(|t| !rule.protected_tags.iter().any(|p| p == &t.tag))
                    .copied()
                    .collect();
                ordered.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then(a.tag.cmp(&b.tag)));
                protected.extend(
                    ordered
                        .into_iter()
                        .take(keep as usize)
                        .map(|t| (t.image.clone(), t.tag.clone())),
                );
            }
        }
    }
    protected
}

fn protected_manifests(
    remaining: &HashSet<i64>,
    tags: &[&RetentionTag],
    by_id: &HashMap<i64, &RetentionManifest>,
    by_digest: &HashMap<(&str, &str), i64>,
) -> HashSet<i64> {
    let mut kept: HashSet<i64> = tags
        .iter()
        .map(|t| t.manifest_id)
        .filter(|id| remaining.contains(id))
        .collect();
    loop {
        let mut grew = false;
        for manifest in by_id.values().filter(|m| remaining.contains(&m.id)) {
            if kept.contains(&manifest.id) {
                for child in &manifest.children {
                    if let Some(id) = by_digest.get(&(manifest.image.as_str(), child.as_str())) {
                        grew |= kept.insert(*id);
                    }
                }
            } else if let Some(subject) = &manifest.subject_digest {
                if by_digest
                    .get(&(manifest.image.as_str(), subject.as_str()))
                    .is_some_and(|id| kept.contains(id))
                {
                    grew |= kept.insert(manifest.id);
                }
            }
        }
        if !grew {
            return kept;
        }
    }
}

/// Snapshot a repository and evaluate `policy` on it. Returns the decisions
/// and how many tags and manifests were inspected.
pub async fn evaluate_repository(
    pool: &PgPool,
    repository_id: i64,
    now: DateTime<Utc>,
    policy: &ImageRetentionPolicy,
) -> sqlx::Result<(ImageDecisions, u64, Option<ImageBudgetSummary>)> {
    let tags = oci_dao::retention_tags(pool, repository_id).await?;
    let manifests = oci_dao::retention_manifests(pool, repository_id).await?;
    let evaluated = (tags.len() + manifests.len()) as u64;
    let (manifest_objects, blob_refs, size_before) = if policy.size_budget.is_some() {
        let (objects, refs) = oci_dao::retention_manifest_objects(pool, repository_id).await?;
        let size = oci_dao::repository_size(pool, repository_id).await?;
        (objects, refs, Some(size))
    } else {
        (Vec::new(), Vec::new(), None)
    };
    let policy = policy.clone();
    let (decisions, budget) = tokio::task::spawn_blocking(move || {
        let mut decisions = evaluate_images(now, &policy, &tags, &manifests);
        let budget = size_before.and_then(|size| {
            let (budget_decisions, summary) = evaluate_image_size_budget(
                &policy,
                &tags,
                &manifests,
                &manifest_objects,
                &blob_refs,
                &decisions,
                size,
            );
            decisions.tags.extend(budget_decisions.tags);
            decisions.manifests.extend(budget_decisions.manifests);
            summary
        });
        (decisions, budget)
    })
    .await
    .map_err(|e| sqlx::Error::Protocol(format!("image retention evaluation failed: {e}")))?;
    Ok((decisions, evaluated, budget))
}

/// What an image retention run's decisions were made under, re-checked
/// before each batch of them is applied (see [`apply_images`]).
pub struct ImageRunFence<'a> {
    /// The policy as stored in `repository.retention_policy` when the run
    /// claimed the repository.
    pub stored_policy: &'a serde_json::Value,
    /// The same policy, parsed: re-evaluates an image's tags and manifests.
    pub policy: &'a ImageRetentionPolicy,
    /// When the decisions were evaluated. The re-evaluation judges ages as
    /// of then, so a tag pulled or pushed since is no longer old or unpulled.
    pub evaluated_at: DateTime<Utc>,
}

/// The most decisions of one image applied in one transaction: the image's
/// manifests and tags are locked and re-evaluated once per batch.
const IMAGE_BATCH: usize = 100;

/// A decision of either kind.
#[derive(Clone, Copy)]
enum ImageDecision<'a> {
    Tag(&'a TagDecision),
    Manifest(&'a ManifestDecision),
}

impl<'a> ImageDecision<'a> {
    fn image(self) -> &'a str {
        match self {
            ImageDecision::Tag(d) => &d.image,
            ImageDecision::Manifest(d) => &d.image,
        }
    }
}

/// What the policy decides for an image now: its doomed tags (with the
/// manifest each points at) and manifests.
struct DecidedNow {
    tags: HashSet<(String, i64)>,
    manifests: HashSet<i64>,
}

impl DecidedNow {
    fn contains(&self, d: ImageDecision<'_>) -> bool {
        match d {
            ImageDecision::Tag(d) => self.tags.contains(&(d.tag.clone(), d.manifest_id)),
            ImageDecision::Manifest(d) => self.manifests.contains(&d.manifest_id),
        }
    }
}

/// Apply decisions (or, `dry_run`, only audit them).
///
/// Decisions are applied per image, in batches of up to [`IMAGE_BATCH`]
/// (its tags first, then its manifests, indexes before their children),
/// one transaction each. With a `fence`, each batch first checks that the
/// run still owns its lease and that the stored policy is still the one it
/// evaluated, or the run stops: the rest is left to the next run, under the
/// policy as it is then. The batch then locks the image's manifests and
/// tags and evaluates the policy on them again; a decision their current
/// state no longer produces (a tag pulled or pushed since, newer tags
/// deleted meanwhile, a referrer whose subject was tagged again) is
/// skipped.
pub async fn apply_images(
    pool: &PgPool,
    repository_id: i64,
    run_id: uuid::Uuid,
    decisions: &ImageDecisions,
    grace: Duration,
    dry_run: bool,
    fence: Option<&ImageRunFence<'_>>,
) -> sqlx::Result<RunSummary> {
    let mut summary = RunSummary::default();
    let batches = image_batches(decisions);
    let mut remaining = decisions.tags.len() + decisions.manifests.len();
    for (image, batch) in &batches {
        let mut tx = pool.begin().await?;
        let mut decided = None;
        if let Some(fence) = fence.filter(|_| !dry_run) {
            if !retention_dao::lock_run_fence(&mut tx, repository_id, run_id, fence.stored_policy)
                .await?
            {
                tracing::info!(
                    repository_id,
                    %run_id,
                    remaining,
                    "image retention run stopped: it lost its lease or its policy changed; \
                     the next run re-evaluates the rest"
                );
                summary.skipped += remaining as u64;
                return Ok(summary);
            }
            decided = Some(decided_now(&mut tx, repository_id, image, fence, batch).await?);
        }
        for &d in batch {
            let still = decided.as_ref().is_none_or(|now| now.contains(d));
            let applied =
                apply_one(&mut tx, repository_id, run_id, d, grace, dry_run, still).await?;
            if applied {
                summary.deleted += 1;
            } else {
                summary.skipped += 1;
            }
        }
        tx.commit().await?;
        remaining -= batch.len();
    }
    Ok(summary)
}

/// `decisions` grouped by image, in the order the images first appear (an
/// image's tags before its manifests, each in decision order), and split
/// into batches of at most [`IMAGE_BATCH`].
fn image_batches(decisions: &ImageDecisions) -> Vec<(&str, Vec<ImageDecision<'_>>)> {
    let mut images: Vec<(&str, Vec<ImageDecision<'_>>)> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    let all = decisions
        .tags
        .iter()
        .map(ImageDecision::Tag)
        .chain(decisions.manifests.iter().map(ImageDecision::Manifest));
    for d in all {
        let i = *index.entry(d.image()).or_insert_with(|| {
            images.push((d.image(), Vec::new()));
            images.len() - 1
        });
        images[i].1.push(d);
    }
    images
        .into_iter()
        .flat_map(|(image, decisions)| {
            decisions
                .chunks(IMAGE_BATCH)
                .map(|batch| (image, batch.to_vec()))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// What evaluating `image`'s current manifests and tags (locked by this
/// call) under the run's policy decides now.
async fn decided_now(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repository_id: i64,
    image: &str,
    fence: &ImageRunFence<'_>,
    batch: &[ImageDecision<'_>],
) -> sqlx::Result<DecidedNow> {
    let (tags, manifests) = oci_dao::lock_image_for_retention(tx, repository_id, image).await?;
    let evaluated = evaluate_images(fence.evaluated_at, fence.policy, &tags, &manifests);
    let mut selected_tags: HashSet<(String, i64)> = evaluated
        .tags
        .iter()
        .map(|t| (t.tag.clone(), t.manifest_id))
        .collect();
    let mut selected_manifests: HashSet<i64> =
        evaluated.manifests.iter().map(|m| m.manifest_id).collect();
    let mut remaining_tags: Vec<&RetentionTag> = tags
        .iter()
        .filter(|t| !selected_tags.contains(&(t.tag.clone(), t.manifest_id)))
        .collect();
    let protected_tags = budget_protected_tags(fence.policy, &tags);
    for decision in batch {
        let ImageDecision::Tag(tag) = decision else {
            continue;
        };
        if tag.rule_id != "size_budget"
            || protected_tags.contains(&(tag.image.clone(), tag.tag.clone()))
            || remaining_tags
                .iter()
                .filter(|t| t.image == tag.image)
                .count()
                <= 1
        {
            continue;
        }
        let Some(current) = tags
            .iter()
            .find(|t| t.image == tag.image && t.tag == tag.tag && t.manifest_id == tag.manifest_id)
        else {
            continue;
        };
        if reason_time(&tag.reason).is_some_and(|cutoff| {
            current
                .last_pulled_at
                .unwrap_or(current.updated_at)
                .max(current.updated_at)
                > cutoff
        }) {
            continue;
        }
        selected_tags.insert((tag.tag.clone(), tag.manifest_id));
        remaining_tags.retain(|t| !(t.image == tag.image && t.tag == tag.tag));
    }
    let remaining_manifests: HashSet<i64> = manifests
        .iter()
        .map(|m| m.id)
        .filter(|id| !selected_manifests.contains(id))
        .collect();
    let manifest_by_id: HashMap<i64, &RetentionManifest> =
        manifests.iter().map(|m| (m.id, m)).collect();
    let manifest_by_digest: HashMap<(&str, &str), i64> = manifests
        .iter()
        .map(|m| ((m.image.as_str(), m.digest.as_str()), m.id))
        .collect();
    let protected = protected_manifests(
        &remaining_manifests,
        &remaining_tags,
        &manifest_by_id,
        &manifest_by_digest,
    );
    for decision in batch {
        let ImageDecision::Manifest(manifest) = decision else {
            continue;
        };
        if manifest.rule_id != "size_budget"
            || protected.contains(&manifest.manifest_id)
            || remaining_tags
                .iter()
                .any(|t| t.manifest_id == manifest.manifest_id)
        {
            continue;
        }
        let Some(current) = manifest_by_id.get(&manifest.manifest_id) else {
            continue;
        };
        if reason_time(&manifest.reason).is_some_and(|cutoff| {
            current
                .last_pulled_at
                .unwrap_or(current.created_at)
                .max(current.created_at)
                > cutoff
        }) {
            continue;
        }
        selected_manifests.insert(manifest.manifest_id);
    }
    Ok(DecidedNow {
        tags: selected_tags,
        manifests: selected_manifests,
    })
}

fn reason_time(reason: &serde_json::Value) -> Option<DateTime<Utc>> {
    reason
        .get("last_used_at")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

/// Apply one decision inside its batch's transaction (unless `dry_run`, or
/// it no longer `still` holds) and audit it. Returns whether it was applied.
async fn apply_one(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repository_id: i64,
    run_id: uuid::Uuid,
    d: ImageDecision<'_>,
    grace: Duration,
    dry_run: bool,
    still: bool,
) -> sqlx::Result<bool> {
    let (applied, done, row) = match d {
        ImageDecision::Tag(d) => {
            let applied = still
                && (dry_run
                    || oci_dao::delete_tag_if(tx, repository_id, &d.image, &d.tag, d.manifest_id)
                        .await?);
            let row = AuditRow {
                repository_id,
                run_id,
                rule_id: d.rule_id.clone(),
                action: String::new(),
                target_kind: "oci_tag".into(),
                package_name: d.image.clone(),
                version: d.tag.clone(),
                component_id: None,
                blob_sha256: None,
                ref_count_after: None,
                blob_delete_enqueued: false,
                dry_run,
                reason: d.reason.clone(),
            };
            (applied, "delete_tag", row)
        }
        ImageDecision::Manifest(d) => {
            let applied = still
                && (dry_run
                    || oci_dao::delete_untagged_manifest(tx, repository_id, d.manifest_id, grace)
                        .await?);
            let row = AuditRow {
                repository_id,
                run_id,
                rule_id: d.rule_id.clone(),
                action: String::new(),
                target_kind: "oci_manifest".into(),
                package_name: d.image.clone(),
                version: d.digest.clone(),
                component_id: None,
                blob_sha256: None,
                ref_count_after: None,
                blob_delete_enqueued: false,
                dry_run,
                reason: d.reason.clone(),
            };
            (applied, "delete_manifest", row)
        }
    };
    let action = if applied { done } else { "skipped" };
    retention_dao::insert_audit(
        &mut **tx,
        &AuditRow {
            action: action.into(),
            ..row
        },
    )
    .await?;
    Ok(applied)
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
            size_budget: None,
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

    #[test]
    fn budget_only_image_policy_is_valid_and_target_is_bounded() {
        let mut p = policy(Vec::new());
        p.size_budget = Some(SizeBudget {
            max_bytes: 100,
            target_bytes: Some(80),
        });
        assert!(validate_image_policy(&p, RepoKind::Hosted).is_ok());
        p.size_budget.as_mut().unwrap().target_bytes = Some(101);
        assert!(validate_image_policy(&p, RepoKind::Hosted).is_err());
    }

    #[test]
    fn size_budget_deletes_untagged_manifests_and_counts_shared_blobs_once() {
        let tags = vec![tag("app", "latest", 2, 1)];
        let manifests = vec![
            manifest("app", 1, Some(90), &[], None),
            manifest("app", 2, None, &[], None),
        ];
        let objects = vec![
            oci_dao::RetentionManifestObject {
                manifest_id: 1,
                blob_sha256: "manifest-1".into(),
                size: 10,
            },
            oci_dao::RetentionManifestObject {
                manifest_id: 2,
                blob_sha256: "manifest-2".into(),
                size: 10,
            },
        ];
        let blobs = vec![
            oci_dao::RetentionBlobRef {
                manifest_id: 1,
                blob_sha256: "shared".into(),
                size: 50,
            },
            oci_dao::RetentionBlobRef {
                manifest_id: 2,
                blob_sha256: "shared".into(),
                size: 50,
            },
            oci_dao::RetentionBlobRef {
                manifest_id: 1,
                blob_sha256: "unique".into(),
                size: 20,
            },
        ];
        let mut p = policy(Vec::new());
        p.size_budget = Some(SizeBudget {
            max_bytes: 80,
            target_bytes: Some(60),
        });
        let (decisions, summary) = evaluate_image_size_budget(
            &p,
            &tags,
            &manifests,
            &objects,
            &blobs,
            &ImageDecisions::default(),
            90,
        );
        assert!(decisions.tags.is_empty());
        assert_eq!(
            decisions
                .manifests
                .iter()
                .map(|m| m.manifest_id)
                .collect::<Vec<_>>(),
            vec![1]
        );
        let summary = summary.unwrap();
        assert_eq!(summary.size_after, 60);
        assert!(summary.target_reached);
    }

    #[test]
    fn size_budget_never_removes_an_images_last_tag() {
        let tags = vec![tag("app", "latest", 2, 1)];
        let manifests = vec![manifest("app", 2, None, &[], None)];
        let objects = vec![oci_dao::RetentionManifestObject {
            manifest_id: 2,
            blob_sha256: "manifest-2".into(),
            size: 100,
        }];
        let mut p = policy(Vec::new());
        p.size_budget = Some(SizeBudget {
            max_bytes: 10,
            target_bytes: Some(5),
        });
        let (decisions, summary) = evaluate_image_size_budget(
            &p,
            &tags,
            &manifests,
            &objects,
            &[],
            &ImageDecisions::default(),
            100,
        );
        assert!(decisions.tags.is_empty());
        assert!(decisions.manifests.is_empty());
        assert!(!summary.unwrap().target_reached);
    }
}
