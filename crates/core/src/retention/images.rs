//! Retention of Docker / OCI images.
//!
//! A docker repository's `retention_policy` has the envelope of a package
//! policy (`version`, `enabled`, `dry_run_only`, `min_run_interval_seconds`
//! or a `schedule` in a `schedule_timezone`, `max_run_seconds`, `rules`) with
//! image rules:
//!
//! * **Tag rules** delete tags: per image (optionally only those under an
//!   `image_prefix`), among the tags the rule looks at (those `tag_pattern`
//!   matches and `exclude_tag_pattern` does not, all without either), the
//!   `keep_last_n_tags` most recently pushed tags and the `protected_tags`
//!   (names or globs: `latest`, `release-*`) stay; any other tag goes when
//!   every set trigger holds (`tag_older_than_days` since it was pushed,
//!   `tag_not_pulled_for_days`). A rule with only `keep_last_n_tags` keeps N
//!   tags per image.
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
use globset::{GlobMatcher, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use super::model::{SizeBudget, SizeBudgetSummary, MAX_MIN_RUN_INTERVAL_SECONDS, POLICY_VERSION};

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
    /// A cron schedule, as for package policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_run_seconds: Option<u64>,
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
    /// Only tags this glob matches (`pr-*`); all tags without one. Tags are
    /// matched as written (case matters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_pattern: Option<String>,
    /// Never tags this glob matches (`v*`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_tag_pattern: Option<String>,
    /// Tags kept per image: the most recently pushed ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_last_n_tags: Option<u32>,
    /// Tags never deleted by this rule (e.g. `latest`, `stable`, or a glob
    /// such as `release-*`), kept in addition to the `keep_last_n_tags`
    /// newest others.
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

/// Compile a tag glob: `*`, `?`, `[…]` and `{a,b}` over the whole tag, case
/// sensitive (`pr-*`, `release-*`). A plain tag matches itself.
fn tag_glob(pattern: &str) -> Result<globset::Glob, globset::Error> {
    globset::GlobBuilder::new(pattern)
        .literal_separator(false)
        .build()
}

/// A tag rule's tag globs, compiled once per evaluation.
struct TagFilter {
    include: Option<GlobMatcher>,
    exclude: Option<GlobMatcher>,
    protected: GlobSet,
    /// A glob that does not compile (validation refuses one): the rule then
    /// deletes no tag.
    broken: bool,
}

impl TagFilter {
    fn new(rule: &ImageRule) -> Self {
        let mut broken = false;
        let mut matcher = |pattern: &Option<String>| match pattern.as_deref().map(tag_glob) {
            None => None,
            Some(Ok(glob)) => Some(glob.compile_matcher()),
            Some(Err(_)) => {
                broken = true;
                None
            }
        };
        let include = matcher(&rule.tag_pattern);
        let exclude = matcher(&rule.exclude_tag_pattern);
        let mut protected = GlobSetBuilder::new();
        for tag in &rule.protected_tags {
            match tag_glob(tag) {
                Ok(glob) => {
                    protected.add(glob);
                }
                Err(_) => broken = true,
            }
        }
        let protected = protected.build().unwrap_or_else(|_| {
            broken = true;
            GlobSet::empty()
        });
        TagFilter {
            include,
            exclude,
            protected,
            broken,
        }
    }

    /// Whether `protected_tags` names `tag`.
    fn protects(&self, tag: &str) -> bool {
        self.protected.is_match(tag)
    }

    /// Whether the rule looks at `tag`: its patterns admit it and it is not
    /// protected.
    fn in_pool(&self, tag: &str) -> bool {
        !self.broken
            && self.include.as_ref().is_none_or(|g| g.is_match(tag))
            && !self.exclude.as_ref().is_some_and(|g| g.is_match(tag))
            && !self.protects(tag)
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
    super::schedule::validate(
        policy.schedule.as_deref(),
        policy.schedule_timezone.as_deref(),
        policy.max_run_seconds,
        Utc::now(),
    )?;
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
        for (field, pattern) in [
            ("tag_pattern", &rule.tag_pattern),
            ("exclude_tag_pattern", &rule.exclude_tag_pattern),
        ] {
            let Some(pattern) = pattern else {
                continue;
            };
            if !rule.has_tag_criteria() {
                return Err(format!("rule {:?}: {field} needs a tag criterion", rule.id));
            }
            if pattern.trim().is_empty() {
                return Err(format!("rule {:?}: {field} is empty", rule.id));
            }
            if let Err(e) = tag_glob(pattern) {
                return Err(format!(
                    "rule {:?}: {field} is not a valid glob: {e}",
                    rule.id
                ));
            }
        }
        for tag in &rule.protected_tags {
            if tag.trim().is_empty() {
                return Err(format!("rule {:?}: a protected tag is empty", rule.id));
            }
            if let Err(e) = tag_glob(tag) {
                return Err(format!(
                    "rule {:?}: protected tag {tag:?} is not a valid glob: {e}",
                    rule.id
                ));
            }
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
        let filter = TagFilter::new(rule);
        for (image, image_tags) in &by_image {
            if !rule.matches(image) {
                continue;
            }
            // The tags the rule looks at; protected tags stay on top of the
            // N kept ones.
            let mut ordered: Vec<&RetentionTag> = image_tags
                .iter()
                .copied()
                .filter(|t| filter.in_pool(&t.tag))
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
) -> (ImageDecisions, Option<SizeBudgetSummary>) {
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
            Some(SizeBudgetSummary {
                size_before,
                size_after,
                target_bytes,
                target_attempted: false,
                target_reached: true,
            }),
        );
    }
    let deleted_rule_tags: HashSet<(&str, &str)> = decisions
        .tags
        .iter()
        .map(|t| (t.image.as_str(), t.tag.as_str()))
        .collect();
    let remaining_tags: Vec<&RetentionTag> = tags
        .iter()
        .filter(|t| {
            !deleted_rule_tags.contains(&(t.image.as_str(), t.tag.as_str()))
                && remaining.contains(&t.manifest_id)
        })
        .collect();
    let protected_tags = budget_protected_tags(policy, tags);
    let mut evictor = ImageBudgetEvictor::new(manifests, remaining, &remaining_tags);
    let mut budget_decisions = ImageDecisions::default();
    let mut budget_run = ImageBudgetRun {
        size_after,
        target_bytes,
        max_bytes: budget.max_bytes,
        manifest_blobs: &manifest_blobs,
        object_sizes: &object_sizes,
        references: &mut references,
    };
    evict_budget_manifests(&mut evictor, &mut budget_run, &mut budget_decisions);

    // Then tagged manifests, least recently used first. A tag is deleted only
    // with every other tag of its manifest, so that the manifest goes too: a
    // tag whose manifest stays frees nothing. A manifest that cannot go yet
    // (a tagged index lists it) waits until what keeps it is gone.
    let mut by_manifest: HashMap<i64, Vec<&RetentionTag>> = HashMap::new();
    for tag in remaining_tags {
        by_manifest.entry(tag.manifest_id).or_default().push(tag);
    }
    let mut groups: Vec<Vec<&RetentionTag>> = by_manifest.into_values().collect();
    groups.sort_by_cached_key(|group| {
        (
            group.iter().map(|t| tag_last_used(t)).max(),
            group.iter().map(|t| t.updated_at).max(),
            group[0].manifest_id,
        )
    });
    let deletable = |evictor: &ImageBudgetEvictor<'_>, group: &[&RetentionTag]| {
        !group
            .iter()
            .any(|t| protected_tags.contains(&(t.image.clone(), t.tag.clone())))
            && evictor.image_tag_count(&group[0].image) > group.len()
    };
    let mut waiting: Vec<Vec<&RetentionTag>> = Vec::new();
    for group in groups {
        if budget_run.size_after <= target_bytes {
            break;
        }
        if !deletable(&evictor, &group) {
            continue;
        }
        if !evictor.freed_by_untagging(group[0].manifest_id) {
            waiting.push(group);
            continue;
        }
        evict_tag_group(&mut evictor, &mut budget_run, &mut budget_decisions, &group);
        // Older manifests that waited for this one, least recently used first.
        while budget_run.size_after > target_bytes {
            let Some(i) = waiting.iter().position(|group| {
                deletable(&evictor, group) && evictor.freed_by_untagging(group[0].manifest_id)
            }) else {
                break;
            };
            let group = waiting.remove(i);
            evict_tag_group(&mut evictor, &mut budget_run, &mut budget_decisions, &group);
        }
    }

    (
        budget_decisions,
        Some(SizeBudgetSummary {
            size_before,
            size_after: budget_run.size_after,
            target_bytes,
            target_attempted: true,
            target_reached: budget_run.size_after <= target_bytes,
        }),
    )
}

/// When a tag was last used: its manifest's last pull or its own push,
/// whichever is later, as `tag_not_pulled_for_days` judges it.
fn tag_last_used(tag: &RetentionTag) -> DateTime<Utc> {
    tag.last_pulled_at
        .unwrap_or(tag.updated_at)
        .max(tag.updated_at)
}

/// When a manifest was last used: its last pull, or its push when never
/// pulled.
fn manifest_last_used(manifest: &RetentionManifest) -> DateTime<Utc> {
    manifest
        .last_pulled_at
        .unwrap_or(manifest.created_at)
        .max(manifest.created_at)
}

type ManifestCandidateKey = (DateTime<Utc>, DateTime<Utc>, i64);

struct ImageBudgetEvictor<'a> {
    remaining: HashSet<i64>,
    manifests: HashMap<i64, &'a RetentionManifest>,
    children: HashMap<i64, Vec<i64>>,
    outgoing: HashMap<i64, Vec<i64>>,
    referrers: HashMap<i64, Vec<i64>>,
    referrer_subject: HashMap<i64, i64>,
    parent_counts: HashMap<i64, usize>,
    tags_by_manifest: HashMap<i64, usize>,
    image_tag_counts: HashMap<String, usize>,
    remaining_tags: HashSet<(String, String)>,
    protection_roots: HashMap<i64, usize>,
    protected_incoming: HashMap<i64, usize>,
    protected: HashSet<i64>,
    candidates: std::collections::BTreeSet<ManifestCandidateKey>,
    candidate_keys: HashMap<i64, ManifestCandidateKey>,
}

struct ImageBudgetRun<'a, 'b> {
    size_after: u64,
    target_bytes: u64,
    max_bytes: u64,
    manifest_blobs: &'a HashMap<i64, HashSet<String>>,
    object_sizes: &'a HashMap<&'b str, u64>,
    references: &'a mut HashMap<String, usize>,
}

impl<'a> ImageBudgetEvictor<'a> {
    fn new(
        manifests: &'a [RetentionManifest],
        remaining: HashSet<i64>,
        tags: &[&RetentionTag],
    ) -> Self {
        let manifest_by_id: HashMap<i64, &RetentionManifest> = manifests
            .iter()
            .filter(|manifest| remaining.contains(&manifest.id))
            .map(|manifest| (manifest.id, manifest))
            .collect();
        let manifest_by_digest: HashMap<(&str, &str), i64> = manifest_by_id
            .values()
            .map(|manifest| {
                (
                    (manifest.image.as_str(), manifest.digest.as_str()),
                    manifest.id,
                )
            })
            .collect();
        let mut children: HashMap<i64, Vec<i64>> = HashMap::new();
        let mut outgoing: HashMap<i64, HashSet<i64>> = HashMap::new();
        let mut referrers: HashMap<i64, Vec<i64>> = HashMap::new();
        let mut referrer_subject = HashMap::new();
        let mut parent_counts = HashMap::new();
        for manifest in manifest_by_id.values() {
            for digest in &manifest.children {
                if let Some(child_id) =
                    manifest_by_digest.get(&(manifest.image.as_str(), digest.as_str()))
                {
                    children.entry(manifest.id).or_default().push(*child_id);
                    *parent_counts.entry(*child_id).or_default() += 1;
                    outgoing.entry(manifest.id).or_default().insert(*child_id);
                }
            }
            if let Some(subject) = &manifest.subject_digest {
                if let Some(subject_id) =
                    manifest_by_digest.get(&(manifest.image.as_str(), subject.as_str()))
                {
                    referrers.entry(*subject_id).or_default().push(manifest.id);
                    referrer_subject.insert(manifest.id, *subject_id);
                    outgoing.entry(*subject_id).or_default().insert(manifest.id);
                }
            }
        }
        let mut tags_by_manifest = HashMap::new();
        let mut image_tag_counts = HashMap::new();
        let mut remaining_tags = HashSet::new();
        let mut protection_roots = HashMap::new();
        for tag in tags {
            *tags_by_manifest.entry(tag.manifest_id).or_default() += 1;
            *image_tag_counts.entry(tag.image.clone()).or_default() += 1;
            remaining_tags.insert((tag.image.clone(), tag.tag.clone()));
            *protection_roots.entry(tag.manifest_id).or_default() += 1;
        }
        let mut evictor = Self {
            remaining,
            manifests: manifest_by_id,
            children,
            outgoing: outgoing
                .into_iter()
                .map(|(id, targets)| (id, targets.into_iter().collect()))
                .collect(),
            referrers,
            referrer_subject,
            parent_counts,
            tags_by_manifest,
            image_tag_counts,
            remaining_tags,
            protection_roots,
            protected_incoming: HashMap::new(),
            protected: HashSet::new(),
            candidates: std::collections::BTreeSet::new(),
            candidate_keys: HashMap::new(),
        };
        let roots: Vec<i64> = evictor.protection_roots.keys().copied().collect();
        for root in roots {
            evictor.update_protection(root, true);
        }
        let ids: Vec<i64> = evictor.remaining.iter().copied().collect();
        for id in ids {
            evictor.refresh_candidate(id);
        }
        evictor
    }

    /// Whether `id` goes once its own tags do: no remaining index lists it,
    /// no kept manifest refers to it, and the subject it refers to is gone.
    fn freed_by_untagging(&self, id: i64) -> bool {
        self.parent_counts.get(&id).copied().unwrap_or_default() == 0
            && self
                .protected_incoming
                .get(&id)
                .copied()
                .unwrap_or_default()
                == 0
            && !self
                .referrer_subject
                .get(&id)
                .is_some_and(|subject| self.remaining.contains(subject))
    }

    fn image_tag_count(&self, image: &str) -> usize {
        self.image_tag_counts
            .get(image)
            .copied()
            .unwrap_or_default()
    }

    fn remove_tag(&mut self, tag: &RetentionTag) {
        if !self
            .remaining_tags
            .remove(&(tag.image.clone(), tag.tag.clone()))
        {
            return;
        }
        if let Some(count) = self.tags_by_manifest.get_mut(&tag.manifest_id) {
            *count -= 1;
        }
        if let Some(count) = self.image_tag_counts.get_mut(&tag.image) {
            *count -= 1;
        }
        let root_count = self
            .protection_roots
            .get_mut(&tag.manifest_id)
            .expect("every active tag protects its manifest");
        *root_count -= 1;
        let should_unprotect = *root_count == 0
            && self
                .protected_incoming
                .get(&tag.manifest_id)
                .copied()
                .unwrap_or_default()
                == 0;
        let changed = if should_unprotect {
            self.update_protection(tag.manifest_id, false)
        } else {
            Vec::new()
        };
        self.refresh_candidate(tag.manifest_id);
        for id in changed {
            self.refresh_candidate(id);
        }
    }

    fn pop_candidate(&mut self) -> Option<i64> {
        let key = self.candidates.pop_first()?;
        self.candidate_keys.remove(&key.2);
        Some(key.2)
    }

    fn manifest_removed(&mut self, id: i64) {
        if let Some(key) = self.candidate_keys.remove(&id) {
            self.candidates.remove(&key);
        }
        let children = self.children.get(&id).cloned().unwrap_or_default();
        for child in children {
            if let Some(count) = self.parent_counts.get_mut(&child) {
                *count -= 1;
            }
            self.refresh_candidate(child);
        }
        let referrers = self.referrers.get(&id).cloned().unwrap_or_default();
        for referrer in referrers {
            self.refresh_candidate(referrer);
        }
    }

    fn refresh_candidate(&mut self, id: i64) {
        if let Some(key) = self.candidate_keys.remove(&id) {
            self.candidates.remove(&key);
        }
        let Some(manifest) = self.manifests.get(&id) else {
            return;
        };
        let subject_remains = self
            .referrer_subject
            .get(&id)
            .is_some_and(|subject| self.remaining.contains(subject));
        if !self.remaining.contains(&id)
            || self.tags_by_manifest.get(&id).copied().unwrap_or_default() > 0
            || self.parent_counts.get(&id).copied().unwrap_or_default() > 0
            || self.protected.contains(&id)
            || subject_remains
        {
            return;
        }
        let key = (manifest_last_used(manifest), manifest.created_at, id);
        self.candidates.insert(key);
        self.candidate_keys.insert(id, key);
    }

    fn update_protection(&mut self, id: i64, protect: bool) -> Vec<i64> {
        let mut changed = Vec::new();
        let mut pending = vec![(id, protect)];
        while let Some((current, add)) = pending.pop() {
            if !self.remaining.contains(&current) {
                continue;
            }
            if add {
                if !self.protected.insert(current) {
                    continue;
                }
                changed.push(current);
                for target in self.outgoing.get(&current).into_iter().flatten() {
                    let count = self.protected_incoming.entry(*target).or_default();
                    *count += 1;
                    if *count == 1
                        && self
                            .protection_roots
                            .get(target)
                            .copied()
                            .unwrap_or_default()
                            == 0
                    {
                        pending.push((*target, true));
                    }
                }
            } else {
                if !self.protected.remove(&current) {
                    continue;
                }
                changed.push(current);
                for target in self.outgoing.get(&current).into_iter().flatten() {
                    if let Some(count) = self.protected_incoming.get_mut(target) {
                        *count -= 1;
                        if *count == 0
                            && self
                                .protection_roots
                                .get(target)
                                .copied()
                                .unwrap_or_default()
                                == 0
                        {
                            pending.push((*target, false));
                        }
                    }
                }
            }
        }
        changed
    }
}

/// Delete every tag of one manifest, then the manifests that frees.
fn evict_tag_group(
    evictor: &mut ImageBudgetEvictor<'_>,
    budget: &mut ImageBudgetRun<'_, '_>,
    decisions: &mut ImageDecisions,
    group: &[&RetentionTag],
) {
    for tag in group {
        evictor.remove_tag(tag);
        decisions.tags.push(TagDecision {
            image: tag.image.clone(),
            tag: tag.tag.clone(),
            manifest_id: tag.manifest_id,
            digest: tag.digest.clone(),
            rule_id: "size_budget".into(),
            reason: serde_json::json!({
                "size_budget": budget.max_bytes,
                "target_bytes": budget.target_bytes,
                "last_used_at": tag_last_used(tag),
            }),
        });
    }
    evict_budget_manifests(evictor, budget, decisions);
}

fn evict_budget_manifests(
    evictor: &mut ImageBudgetEvictor<'_>,
    budget: &mut ImageBudgetRun<'_, '_>,
    decisions: &mut ImageDecisions,
) {
    while budget.size_after > budget.target_bytes {
        let Some(id) = evictor.pop_candidate() else {
            break;
        };
        let Some(manifest) = evictor.manifests.get(&id) else {
            continue;
        };
        let image = manifest.image.clone();
        let digest = manifest.digest.clone();
        let last_used_at = manifest_last_used(manifest);
        budget.size_after = budget.size_after.saturating_sub(remove_manifest_objects(
            id,
            &mut evictor.remaining,
            budget.manifest_blobs,
            budget.object_sizes,
            budget.references,
        ));
        evictor.manifest_removed(id);
        decisions.manifests.push(ManifestDecision {
            image,
            manifest_id: id,
            digest,
            rule_id: "size_budget".into(),
            reason: serde_json::json!({
                "size_budget": budget.max_bytes,
                "target_bytes": budget.target_bytes,
                "last_used_at": last_used_at,
            }),
        });
    }
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
        let filter = TagFilter::new(rule);
        for (image, image_tags) in &by_image {
            if !rule.matches(image) {
                continue;
            }
            protected.extend(
                image_tags
                    .iter()
                    .filter(|t| filter.protects(&t.tag))
                    .map(|t| (t.image.clone(), t.tag.clone())),
            );
            if let Some(keep) = rule.keep_last_n_tags {
                let mut ordered: Vec<_> = image_tags
                    .iter()
                    .filter(|t| filter.in_pool(&t.tag))
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
) -> sqlx::Result<(ImageDecisions, u64, Option<SizeBudgetSummary>)> {
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
/// With a `deadline`, the run stops before the first batch that would start
/// after it (the first batch always goes); the decisions left are
/// `deferred` to the next run.
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
#[allow(clippy::too_many_arguments)]
pub async fn apply_images(
    pool: &PgPool,
    repository_id: i64,
    run_id: uuid::Uuid,
    decisions: &ImageDecisions,
    grace: Duration,
    dry_run: bool,
    fence: Option<&ImageRunFence<'_>>,
    deadline: Option<std::time::Instant>,
) -> sqlx::Result<RunSummary> {
    let mut summary = RunSummary::default();
    let mut clock = super::schedule::RunClock::new(deadline);
    let batches = image_batches(decisions);
    let mut remaining = decisions.tags.len() + decisions.manifests.len();
    for (image, batch) in &batches {
        if clock.out_of_time() {
            tracing::info!(
                repository_id,
                %run_id,
                remaining,
                "image retention run stopped at its max_run_seconds; \
                 the next run goes on with the rest"
            );
            summary.deferred += remaining as u64;
            return Ok(summary);
        }
        let mut tx = forge_db::begin(pool).await?;
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
/// into batches of at most [`IMAGE_BATCH`]. The size budget's tags of one
/// manifest are never split: they go together or not at all.
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
    let budget_manifest = |d: ImageDecision<'_>| match d {
        ImageDecision::Tag(t) if t.rule_id == "size_budget" => Some(t.manifest_id),
        _ => None,
    };
    let mut batches: Vec<(&str, Vec<ImageDecision<'_>>)> = Vec::new();
    for (image, decisions) in images {
        let mut batch: Vec<ImageDecision<'_>> = Vec::new();
        for d in decisions {
            let same_group = batch
                .last()
                .and_then(|&last| budget_manifest(last))
                .is_some_and(|id| budget_manifest(d) == Some(id));
            if batch.len() >= IMAGE_BATCH && !same_group {
                batches.push((image, std::mem::take(&mut batch)));
            }
            batch.push(d);
        }
        if !batch.is_empty() {
            batches.push((image, batch));
        }
    }
    batches
}

/// What `image`'s current manifests and tags (locked by this call) still
/// warrant of `batch`: what evaluating the run's policy on them decides now,
/// and the size budget's decisions that still hold. Those are judged on what
/// survives the batch itself, not on what the policy would delete in a later
/// batch or run: a referrer goes only with its subject, and a manifest's tags
/// only when none is left on it.
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

    // The tags left once the batch's rule decisions that still hold apply.
    let deleted_by_rules: HashSet<(&str, i64)> = batch
        .iter()
        .filter_map(|d| match d {
            ImageDecision::Tag(t)
                if t.rule_id != "size_budget"
                    && selected_tags.contains(&(t.tag.clone(), t.manifest_id)) =>
            {
                Some((t.tag.as_str(), t.manifest_id))
            }
            _ => None,
        })
        .collect();
    let mut remaining_tags: Vec<&RetentionTag> = tags
        .iter()
        .filter(|t| !deleted_by_rules.contains(&(t.tag.as_str(), t.manifest_id)))
        .collect();

    // The budget's tags, per manifest: every tag the manifest still has goes,
    // or none does.
    let protected_tags = budget_protected_tags(fence.policy, &tags);
    let mut budget_groups: Vec<(i64, Vec<&TagDecision>)> = Vec::new();
    for decision in batch {
        let ImageDecision::Tag(tag) = decision else {
            continue;
        };
        if tag.rule_id != "size_budget" {
            continue;
        }
        match budget_groups
            .iter_mut()
            .find(|(id, _)| *id == tag.manifest_id)
        {
            Some((_, group)) => group.push(tag),
            None => budget_groups.push((tag.manifest_id, vec![tag])),
        }
    }
    for (manifest_id, group) in budget_groups {
        let current: Vec<&RetentionTag> = remaining_tags
            .iter()
            .copied()
            .filter(|t| t.manifest_id == manifest_id)
            .collect();
        let holds = !current.is_empty()
            && current.iter().all(|t| {
                !protected_tags.contains(&(t.image.clone(), t.tag.clone()))
                    && group.iter().any(|d| {
                        d.tag == t.tag
                            && reason_time(&d.reason).is_none_or(|cutoff| tag_last_used(t) <= cutoff)
                    })
            })
            // The image keeps a tag.
            && remaining_tags.iter().any(|t| t.manifest_id != manifest_id);
        if !holds {
            continue;
        }
        for t in &current {
            selected_tags.insert((t.tag.clone(), manifest_id));
        }
        remaining_tags.retain(|t| t.manifest_id != manifest_id);
    }

    let manifest_by_id: HashMap<i64, &RetentionManifest> =
        manifests.iter().map(|m| (m.id, m)).collect();
    let manifest_by_digest: HashMap<(&str, &str), i64> = manifests
        .iter()
        .map(|m| ((m.image.as_str(), m.digest.as_str()), m.id))
        .collect();
    let mut parents_by_digest: HashMap<(&str, &str), Vec<i64>> = HashMap::new();
    for parent in &manifests {
        for child in &parent.children {
            parents_by_digest
                .entry((parent.image.as_str(), child.as_str()))
                .or_default()
                .push(parent.id);
        }
    }
    let mut remaining_manifests: HashSet<i64> = manifests.iter().map(|m| m.id).collect();
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
        let Some(current) = manifest_by_id.get(&manifest.manifest_id) else {
            continue;
        };
        let tagged = remaining_tags.iter().any(|t| t.manifest_id == current.id);
        let parent_remains = parents_by_digest
            .get(&(current.image.as_str(), current.digest.as_str()))
            .is_some_and(|parents| {
                parents
                    .iter()
                    .any(|parent_id| remaining_manifests.contains(parent_id))
            });
        let holds = if manifest.rule_id == "size_budget" {
            let subject_remains = current
                .subject_digest
                .as_deref()
                .and_then(|subject| manifest_by_digest.get(&(current.image.as_str(), subject)))
                .is_some_and(|subject_id| remaining_manifests.contains(subject_id));
            !protected.contains(&current.id)
                && !tagged
                && !parent_remains
                && !subject_remains
                && reason_time(&manifest.reason)
                    .is_none_or(|cutoff| manifest_last_used(current) <= cutoff)
        } else {
            selected_manifests.contains(&current.id)
        };
        if !holds {
            continue;
        }
        selected_manifests.insert(current.id);
        // The delete goes through only for a manifest no tag and no index
        // keeps (`oci_dao::delete_untagged_manifest`).
        if !tagged && !parent_remains {
            remaining_manifests.remove(&current.id);
        }
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
            schedule: None,
            schedule_timezone: None,
            max_run_seconds: None,
            size_budget: None,
            rules,
        }
    }
    fn rule(id: &str) -> ImageRule {
        ImageRule {
            id: id.into(),
            image_prefix: None,
            tag_pattern: None,
            exclude_tag_pattern: None,
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
    fn tag_patterns_choose_the_tags_a_rule_looks_at() {
        let tags = vec![
            tag("app", "pr-12", 1, 30),
            tag("app", "pr-13", 2, 20),
            tag("app", "pr-14", 3, 1),
            tag("app", "pr-keep", 4, 30),
            tag("app", "v1.0", 5, 30),
            tag("app", "main", 6, 30),
        ];
        // Delete `pr-*` tags after 7 days, except `pr-keep`.
        let mut r = rule("prs");
        r.tag_pattern = Some("pr-*".into());
        r.exclude_tag_pattern = Some("*-keep".into());
        r.tag_older_than_days = Some(7);
        let d = evaluate_images(now(), &policy(vec![r.clone()]), &tags, &[]);
        let mut deleted: Vec<&str> = d.tags.iter().map(|t| t.tag.as_str()).collect();
        deleted.sort_unstable();
        assert_eq!(deleted, vec!["pr-12", "pr-13"]);

        // keep_last_n_tags counts only the tags the rule looks at: the newest
        // `pr-*` tag is kept, whatever `main` and `v1.0` are.
        r.tag_older_than_days = None;
        r.exclude_tag_pattern = None;
        r.keep_last_n_tags = Some(1);
        let d = evaluate_images(now(), &policy(vec![r]), &tags, &[]);
        let mut deleted: Vec<&str> = d.tags.iter().map(|t| t.tag.as_str()).collect();
        deleted.sort_unstable();
        assert_eq!(deleted, vec!["pr-12", "pr-13", "pr-keep"]);
    }

    #[test]
    fn protected_tags_take_globs_in_rules_and_the_budget() {
        let tags = vec![
            tag("app", "release-1", 1, 300),
            tag("app", "release-2", 2, 200),
            tag("app", "latest", 2, 200),
            tag("app", "build-7", 3, 100),
            tag("app", "build-8", 4, 90),
        ];
        let mut r = rule("old");
        r.tag_older_than_days = Some(30);
        r.protected_tags = vec!["release-*".into(), "latest".into()];
        let d = evaluate_images(now(), &policy(vec![r.clone()]), &tags, &[]);
        let mut deleted: Vec<&str> = d.tags.iter().map(|t| t.tag.as_str()).collect();
        deleted.sort_unstable();
        assert_eq!(deleted, vec!["build-7", "build-8"]);
        let kept = budget_protected_tags(&policy(vec![r]), &tags);
        let mut kept: Vec<&str> = kept.iter().map(|(_, t)| t.as_str()).collect();
        kept.sort_unstable();
        assert_eq!(kept, vec!["latest", "release-1", "release-2"]);
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
    fn deleting_one_tag_of_a_digest_leaves_its_other_tags_and_manifest() {
        // `1.0` and `1` name manifest 1; `1` was moved onto it recently.
        let tags = vec![
            tag("app", "1.0", 1, 30),
            tag("app", "1", 1, 2),
            tag("app", "2.0", 2, 1),
        ];
        let manifests = vec![
            manifest("app", 1, None, &[], None),
            manifest("app", 2, None, &[], None),
        ];
        let mut r = rule("r");
        r.tag_older_than_days = Some(7);
        r.delete_untagged_after_days = Some(1);
        let d = evaluate_images(now(), &policy(vec![r]), &tags, &manifests);
        let deleted: Vec<&str> = d.tags.iter().map(|t| t.tag.as_str()).collect();
        assert_eq!(deleted, vec!["1.0"]);
        assert!(d.manifests.is_empty(), "`1` keeps manifest 1");
    }

    #[test]
    fn the_same_digest_in_two_images_is_judged_per_image() {
        // `a` and `b` each hold a manifest of the same digest.
        let mut a = tag("a", "x", 1, 30);
        let mut b = tag("b", "x", 2, 30);
        let mut ma = manifest("a", 1, None, &[], None);
        let mut mb = manifest("b", 2, None, &[], None);
        for digest in [&mut a.digest, &mut b.digest, &mut ma.digest, &mut mb.digest] {
            *digest = "sha256:same".into();
        }
        let mut r = rule("r");
        r.image_prefix = Some("a".into());
        r.tag_older_than_days = Some(7);
        r.delete_untagged_after_days = Some(7);
        let d = evaluate_images(now(), &policy(vec![r]), &[a, b], &[ma, mb]);
        let deleted: Vec<(&str, i64)> = d
            .tags
            .iter()
            .map(|t| (t.image.as_str(), t.manifest_id))
            .collect();
        assert_eq!(deleted, vec![("a", 1)]);
        assert!(d.manifests.is_empty(), "the rule does not match `b`");
    }

    #[test]
    fn a_pull_of_one_tag_counts_for_every_tag_of_its_digest() {
        // `1` and `latest` name manifest 1, pulled (through `latest`)
        // yesterday; `0.9`'s manifest was never pulled.
        let mut tags = vec![
            tag("app", "0.9", 0, 60),
            tag("app", "1", 1, 60),
            tag("app", "latest", 1, 60),
        ];
        tags[1].last_pulled_at = Some(at(1));
        tags[2].last_pulled_at = Some(at(1));
        let mut r = rule("stale");
        r.tag_not_pulled_for_days = Some(30);
        let d = evaluate_images(now(), &policy(vec![r]), &tags, &[]);
        let deleted: Vec<&str> = d.tags.iter().map(|t| t.tag.as_str()).collect();
        assert_eq!(deleted, vec!["0.9"]);
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

        // Tag globs compile, are not empty, and need a tag criterion.
        let mut prs = rule("prs");
        prs.tag_pattern = Some("pr-*".into());
        prs.tag_older_than_days = Some(7);
        prs.protected_tags = vec!["release-*".into()];
        assert!(validate_image_policy(&policy(vec![prs.clone()]), RepoKind::Hosted).is_ok());
        for broken in ["pr-[", ""] {
            let mut bad = prs.clone();
            bad.tag_pattern = Some(broken.into());
            assert!(validate_image_policy(&policy(vec![bad]), RepoKind::Hosted).is_err());
            let mut bad = prs.clone();
            bad.protected_tags = vec![broken.into()];
            assert!(validate_image_policy(&policy(vec![bad]), RepoKind::Hosted).is_err());
        }
        let mut untagged = rule("untagged");
        untagged.delete_untagged_after_days = Some(7);
        untagged.exclude_tag_pattern = Some("v*".into());
        assert!(validate_image_policy(&policy(vec![untagged]), RepoKind::Hosted).is_err());

        // The schedule fields of the envelope.
        let mut scheduled = ok.clone();
        scheduled.schedule = Some("30 2 * * 0".into());
        scheduled.schedule_timezone = Some("America/New_York".into());
        scheduled.max_run_seconds = Some(1800);
        assert!(validate_image_policy(&scheduled, RepoKind::Hosted).is_ok());
        scheduled.schedule_timezone = Some("Nowhere/Land".into());
        assert!(validate_image_policy(&scheduled, RepoKind::Hosted).is_err());
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

    #[test]
    fn image_size_budget_reports_unreached_target_after_reaching_maximum() {
        let tags = vec![tag("app", "old", 1, 1), tag("app", "new", 2, 2)];
        let manifests = vec![
            manifest("app", 1, Some(90), &[], None),
            manifest("app", 2, None, &[], None),
        ];
        let objects = vec![
            oci_dao::RetentionManifestObject {
                manifest_id: 1,
                blob_sha256: "old".into(),
                size: 40,
            },
            oci_dao::RetentionManifestObject {
                manifest_id: 2,
                blob_sha256: "new".into(),
                size: 40,
            },
        ];
        let mut p = policy(Vec::new());
        p.size_budget = Some(SizeBudget {
            max_bytes: 60,
            target_bytes: Some(20),
        });
        let (decisions, summary) = evaluate_image_size_budget(
            &p,
            &tags,
            &manifests,
            &objects,
            &[],
            &ImageDecisions::default(),
            80,
        );
        assert_eq!(decisions.tags.len(), 1);
        let summary = summary.unwrap();
        assert_eq!(summary.size_after, 40);
        assert!(!summary.target_reached);
    }

    #[test]
    fn removing_a_tagged_index_reconsiders_its_newly_untagged_children() {
        let tags = vec![tag("app", "old-index", 1, 20), tag("app", "new", 3, 1)];
        let manifests = vec![
            manifest("app", 1, None, &[2], None),
            manifest("app", 2, Some(90), &[], None),
            manifest("app", 3, None, &[], None),
        ];
        let objects = [1, 2, 3]
            .into_iter()
            .map(|manifest_id| oci_dao::RetentionManifestObject {
                manifest_id,
                blob_sha256: format!("manifest-{manifest_id}"),
                size: if manifest_id == 1 { 10 } else { 40 },
            })
            .collect::<Vec<_>>();
        let mut p = policy(Vec::new());
        p.size_budget = Some(SizeBudget {
            max_bytes: 80,
            target_bytes: Some(50),
        });
        let (decisions, summary) = evaluate_image_size_budget(
            &p,
            &tags,
            &manifests,
            &objects,
            &[],
            &ImageDecisions::default(),
            90,
        );
        assert_eq!(
            decisions
                .tags
                .iter()
                .map(|t| t.tag.as_str())
                .collect::<Vec<_>>(),
            vec!["old-index"]
        );
        assert_eq!(
            decisions
                .manifests
                .iter()
                .map(|m| m.manifest_id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(summary.unwrap().size_after, 40);
    }

    #[test]
    fn size_budget_removes_an_untagged_subject_before_its_referrer() {
        let manifests = vec![
            manifest("app", 1, Some(90), &[], None),
            manifest("app", 2, Some(90), &[], Some(1)),
        ];
        let objects = [1, 2]
            .into_iter()
            .map(|manifest_id| oci_dao::RetentionManifestObject {
                manifest_id,
                blob_sha256: format!("manifest-{manifest_id}"),
                size: 30,
            })
            .collect::<Vec<_>>();
        let mut p = policy(Vec::new());
        p.size_budget = Some(SizeBudget {
            max_bytes: 50,
            target_bytes: Some(0),
        });
        let (decisions, summary) = evaluate_image_size_budget(
            &p,
            &[],
            &manifests,
            &objects,
            &[],
            &ImageDecisions::default(),
            60,
        );
        assert_eq!(
            decisions
                .manifests
                .iter()
                .map(|m| m.manifest_id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(summary.unwrap().size_after, 0);
    }

    fn manifest_objects(sizes: &[(i64, i64)]) -> Vec<oci_dao::RetentionManifestObject> {
        sizes
            .iter()
            .map(|&(manifest_id, size)| oci_dao::RetentionManifestObject {
                manifest_id,
                blob_sha256: format!("manifest-{manifest_id}"),
                size,
            })
            .collect()
    }

    #[test]
    fn size_budget_never_deletes_an_alias_that_frees_nothing() {
        // Both tags name the image's only manifest: deleting one of them
        // would free nothing, and the other is the image's last tag.
        let tags = vec![tag("app", "1.2.3", 2, 1), tag("app", "latest", 2, 1)];
        let manifests = vec![manifest("app", 2, None, &[], None)];
        let mut p = policy(Vec::new());
        p.size_budget = Some(SizeBudget {
            max_bytes: 50,
            target_bytes: Some(40),
        });
        let (decisions, summary) = evaluate_image_size_budget(
            &p,
            &tags,
            &manifests,
            &manifest_objects(&[(2, 100)]),
            &[],
            &ImageDecisions::default(),
            100,
        );
        assert!(decisions.tags.is_empty());
        assert!(decisions.manifests.is_empty());
        let summary = summary.unwrap();
        assert_eq!(summary.size_after, 100);
        assert!(!summary.target_reached);
    }

    #[test]
    fn size_budget_deletes_every_tag_of_a_manifest_together() {
        let tags = vec![
            tag("app", "1.0", 1, 30),
            tag("app", "1", 1, 30),
            tag("app", "2.0", 2, 1),
        ];
        let manifests = vec![
            manifest("app", 1, None, &[], None),
            manifest("app", 2, None, &[], None),
        ];
        let mut p = policy(Vec::new());
        p.size_budget = Some(SizeBudget {
            max_bytes: 50,
            target_bytes: Some(40),
        });
        let (decisions, summary) = evaluate_image_size_budget(
            &p,
            &tags,
            &manifests,
            &manifest_objects(&[(1, 40), (2, 40)]),
            &[],
            &ImageDecisions::default(),
            80,
        );
        let mut deleted: Vec<_> = decisions.tags.iter().map(|t| t.tag.as_str()).collect();
        deleted.sort_unstable();
        assert_eq!(deleted, vec!["1", "1.0"]);
        assert_eq!(
            decisions
                .manifests
                .iter()
                .map(|m| m.manifest_id)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert!(summary.unwrap().target_reached);
    }

    #[test]
    fn a_tagged_child_waits_for_its_index_and_goes_before_newer_content() {
        // `amd64` is used least recently, but its tagged index keeps it: it
        // goes right after the index, before the newer `new`.
        let tags = vec![
            tag("app", "multi", 1, 10),
            tag("app", "amd64", 2, 20),
            tag("app", "new", 3, 1),
        ];
        let manifests = vec![
            manifest("app", 1, None, &[2], None),
            manifest("app", 2, None, &[], None),
            manifest("app", 3, None, &[], None),
        ];
        let mut p = policy(Vec::new());
        p.size_budget = Some(SizeBudget {
            max_bytes: 50,
            target_bytes: Some(40),
        });
        let (decisions, summary) = evaluate_image_size_budget(
            &p,
            &tags,
            &manifests,
            &manifest_objects(&[(1, 10), (2, 40), (3, 40)]),
            &[],
            &ImageDecisions::default(),
            90,
        );
        assert_eq!(
            decisions
                .tags
                .iter()
                .map(|t| t.tag.as_str())
                .collect::<Vec<_>>(),
            vec!["multi", "amd64"]
        );
        assert_eq!(
            decisions
                .manifests
                .iter()
                .map(|m| m.manifest_id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(summary.unwrap().size_after, 40);
    }
}
