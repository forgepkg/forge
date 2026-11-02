//! The package delay of a proxy repository: which delay applies to a package,
//! and whether one of its versions has cleared it (#184).
//!
//! A proxy holds new upstream versions back for `package_delay_seconds`
//! (the *default*). Its `package_delay_overrides` (an ordered list on the
//! repository, see [`PackageDelayOverride`]) give some packages another delay:
//! the first entry that matches a package decides, and a package no entry
//! matches keeps the default. An entry matches by a content selector's
//! include/exclude globs (`selector`, by name: shared and edited in one
//! place) or by a glob of its own (`pattern`), both on the lowercased id. An
//! override of `0` exempts the packages it matches, a longer one holds them
//! back longer.
//!
//! An administrator can also release one version from the delay early
//! (`package_delay_release`): it is served at once, while the package's other
//! versions keep their delay. [`PackageGate`] is one package's delay together
//! with its released versions.
//!
//! The resolved delay is cached per instance, keyed by the repository row's
//! `updated_at`: every edit of the overrides, and every edit of a content
//! selector they name, touches the repository row, so each instance resolves
//! it again on its next request.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};

use chrono::{DateTime, Duration, Utc};
use forge_db::model::{PackageDelayOverride, Repository};
use serde::Serialize;
use sqlx::PgPool;

use crate::authz::{CompiledSelector, SelectorPatterns};

/// Where the delay of a package comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DelaySource {
    /// The repository's `package_delay_seconds`: no override matches.
    Default,
    /// An override naming a content selector.
    Selector {
        /// The selector's name.
        name: String,
    },
    /// An override with a glob of its own.
    Pattern {
        /// The glob.
        pattern: String,
    },
}

/// The delay that applies to one package, and where it comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppliedDelay {
    /// The delay, in seconds (`0`: none).
    pub delay_seconds: i32,
    /// The override that decided it, or the repository's default.
    pub source: DelaySource,
}

impl AppliedDelay {
    /// The delay as a duration.
    pub fn duration(&self) -> Duration {
        Duration::seconds(i64::from(self.delay_seconds.max(0)))
    }

    /// Whether a version first seen (or published upstream) at
    /// `first_seen_at` has waited out this delay at `now`.
    pub fn cleared(&self, first_seen_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        now - first_seen_at >= self.duration()
    }
}

/// One override, ready to match.
#[derive(Debug, Clone)]
struct Rule {
    source: DelaySource,
    delay_seconds: i32,
    /// `None` when the override cannot be evaluated: its selector does not
    /// exist (any more) or its globs do not compile. The admin API never
    /// lets that happen; should it all the same, the rule might match any
    /// package, so no package reaching it gets a delay shorter than its own.
    matcher: Option<CompiledSelector>,
}

/// The package delay of a proxy repository: its default and its overrides,
/// resolved.
#[derive(Debug, Clone)]
pub struct PackageDelay {
    default_seconds: i32,
    rules: Vec<Rule>,
}

impl PackageDelay {
    /// The delay of a repository without overrides.
    pub fn uniform(delay_seconds: i32) -> Self {
        PackageDelay {
            default_seconds: delay_seconds,
            rules: Vec::new(),
        }
    }

    /// The package delay of `overrides` over `default_seconds`, a selector
    /// override resolved through `selectors` (by name; one missing there
    /// cannot be evaluated, see [`Rule::matcher`]).
    pub fn new(
        default_seconds: i32,
        overrides: &[PackageDelayOverride],
        selectors: &HashMap<String, SelectorPatterns>,
    ) -> Self {
        let rules = overrides
            .iter()
            .filter_map(|o| {
                let (source, patterns) = match (&o.selector, &o.pattern) {
                    (Some(name), None) => (
                        DelaySource::Selector { name: name.clone() },
                        selectors.get(name).cloned(),
                    ),
                    (None, Some(pattern)) => (
                        DelaySource::Pattern {
                            pattern: pattern.clone(),
                        },
                        Some(SelectorPatterns {
                            includes: vec![pattern.clone()],
                            excludes: Vec::new(),
                        }),
                    ),
                    // Not an override the admin API writes.
                    _ => return None,
                };
                let matcher = patterns.and_then(|p| match p.compile() {
                    Ok(compiled) => Some(compiled),
                    Err(e) => {
                        tracing::warn!(error = %e, "a package-delay override does not compile");
                        None
                    }
                });
                if matcher.is_none() {
                    tracing::warn!(?source, "a package-delay override cannot be evaluated; it holds back every package that reaches it at least as long as it says");
                }
                Some(Rule {
                    source,
                    delay_seconds: o.delay_seconds,
                    matcher,
                })
            })
            .collect();
        PackageDelay {
            default_seconds,
            rules,
        }
    }

    /// The package delay of `repo`, its selector overrides resolved from
    /// `content_selector`. Cached per instance while the repository row's
    /// `updated_at` stays the same (see the module docs).
    pub async fn load(pool: &PgPool, repo: &Repository) -> sqlx::Result<Arc<PackageDelay>> {
        let overrides = repo.package_delay_overrides();
        if overrides.is_empty() {
            return Ok(Arc::new(Self::uniform(repo.package_delay_seconds)));
        }
        if let Some(cached) = cached(repo) {
            return Ok(cached);
        }
        let wanted: HashSet<&str> = overrides
            .iter()
            .filter_map(|o| o.selector.as_deref())
            .collect();
        let mut selectors = HashMap::new();
        if !wanted.is_empty() {
            for row in forge_db::authz_dao::list_content_selectors(pool).await? {
                if !wanted.contains(row.name.as_str()) {
                    continue;
                }
                let parsed = forge_db::authz_dao::SelectorRow {
                    id: row.id,
                    includes: row.includes,
                    excludes: row.excludes,
                }
                .patterns();
                match parsed {
                    Ok((includes, excludes)) => {
                        selectors.insert(row.name, SelectorPatterns { includes, excludes });
                    }
                    Err(e) => {
                        tracing::warn!(selector = %row.name, error = %e, "a content selector a package-delay override names does not read");
                    }
                }
            }
        }
        let delay = Arc::new(Self::new(
            repo.package_delay_seconds,
            &overrides,
            &selectors,
        ));
        remember(repo, delay.clone());
        Ok(delay)
    }

    /// The delay of package `lower_id`: the first override that matches it,
    /// else the default.
    pub fn for_package(&self, lower_id: &str) -> AppliedDelay {
        // The longest delay of an override passed that cannot be evaluated.
        let mut floor: Option<&Rule> = None;
        let at_least = |applied: AppliedDelay, floor: Option<&Rule>| match floor {
            Some(rule) if rule.delay_seconds > applied.delay_seconds => AppliedDelay {
                delay_seconds: rule.delay_seconds,
                source: rule.source.clone(),
            },
            _ => applied,
        };
        for rule in &self.rules {
            match &rule.matcher {
                Some(matcher) if matcher.matches(lower_id) => {
                    let applied = AppliedDelay {
                        delay_seconds: rule.delay_seconds,
                        source: rule.source.clone(),
                    };
                    return at_least(applied, floor);
                }
                Some(_) => {}
                None => {
                    if floor.is_none_or(|f| rule.delay_seconds > f.delay_seconds) {
                        floor = Some(rule);
                    }
                }
            }
        }
        at_least(
            AppliedDelay {
                delay_seconds: self.default_seconds,
                source: DelaySource::Default,
            },
            floor,
        )
    }

    /// Whether some package of the repository is delayed at all: the
    /// default or an override is longer than `0`.
    pub fn is_active(&self) -> bool {
        self.default_seconds > 0 || self.rules.iter().any(|r| r.delay_seconds > 0)
    }

    /// The shortest delay any package of the repository can have. A version
    /// first seen less than this long ago is inside every package's delay.
    pub fn shortest(&self) -> Duration {
        let seconds = self
            .rules
            .iter()
            .map(|r| r.delay_seconds)
            .chain([self.default_seconds])
            .min()
            .unwrap_or(0);
        Duration::seconds(i64::from(seconds.max(0)))
    }
}

/// One package's delay and its versions released early.
#[derive(Debug, Clone)]
pub struct PackageGate {
    /// The delay of the package.
    pub applied: AppliedDelay,
    /// Its versions (normalized) released from the delay early, and when.
    pub released: HashMap<String, DateTime<Utc>>,
}

impl PackageGate {
    /// The gate of package `lower_id` of a repository with package delay
    /// `delay`. Its releases are read only when it has a delay at all.
    pub async fn load(
        pool: &PgPool,
        repository_id: i64,
        delay: &PackageDelay,
        lower_id: &str,
    ) -> sqlx::Result<PackageGate> {
        let applied = delay.for_package(lower_id);
        let released = if applied.delay_seconds > 0 {
            forge_db::delay_release_dao::released_versions(pool, repository_id, lower_id)
                .await?
                .into_iter()
                .collect()
        } else {
            HashMap::new()
        };
        Ok(PackageGate { applied, released })
    }

    /// Whether `version`, first seen at `first_seen_at`, may be served at
    /// `now`: it waited out the package's delay, or was released early.
    pub fn cleared(&self, version: &str, first_seen_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        self.applied.cleared(first_seen_at, now) || self.released.contains_key(version)
    }

    /// Whether `version` is held back at all before it is seen: the package
    /// has a delay and the version was not released early.
    pub fn delays(&self, version: &str) -> bool {
        self.applied.delay_seconds > 0 && !self.released.contains_key(version)
    }
}

/// The resolved delays of the repositories with overrides, by id, with the
/// repository row's `updated_at` they were resolved for.
type DelayCache = HashMap<i64, (DateTime<Utc>, Arc<PackageDelay>)>;

static RESOLVED: LazyLock<Mutex<DelayCache>> = LazyLock::new(Default::default);

/// Repositories with overrides kept resolved at once (beyond this, the cache
/// starts over).
const RESOLVED_MAX: usize = 1024;

fn cached(repo: &Repository) -> Option<Arc<PackageDelay>> {
    let map = RESOLVED.lock().unwrap_or_else(|p| p.into_inner());
    map.get(&repo.id)
        .filter(|(updated_at, _)| *updated_at == repo.updated_at)
        .map(|(_, delay)| delay.clone())
}

fn remember(repo: &Repository, delay: Arc<PackageDelay>) {
    let mut map = RESOLVED.lock().unwrap_or_else(|p| p.into_inner());
    if map.len() >= RESOLVED_MAX && !map.contains_key(&repo.id) {
        map.clear();
    }
    map.insert(repo.id, (repo.updated_at, delay));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn by_pattern(pattern: &str, delay_seconds: i32) -> PackageDelayOverride {
        PackageDelayOverride {
            selector: None,
            pattern: Some(pattern.into()),
            delay_seconds,
        }
    }

    fn by_selector(name: &str, delay_seconds: i32) -> PackageDelayOverride {
        PackageDelayOverride {
            selector: Some(name.into()),
            pattern: None,
            delay_seconds,
        }
    }

    fn selectors() -> HashMap<String, SelectorPatterns> {
        HashMap::from([(
            "trusted-vendors".to_string(),
            SelectorPatterns {
                includes: vec!["microsoft.*".into(), "system.*".into()],
                excludes: vec!["system.risky".into()],
            },
        )])
    }

    #[test]
    fn the_first_matching_override_decides() {
        let delay = PackageDelay::new(
            86_400,
            &[
                by_selector("trusted-vendors", 0),
                by_pattern("Envisia.*", 0),
                by_pattern("some.risky.pkg", 1_209_600),
                by_pattern("microsoft.*", 3_600),
            ],
            &selectors(),
        );
        let microsoft = delay.for_package("microsoft.extensions.logging");
        assert_eq!(microsoft.delay_seconds, 0);
        assert_eq!(
            microsoft.source,
            DelaySource::Selector {
                name: "trusted-vendors".into()
            }
        );
        // Case-insensitive, like NuGet ids.
        assert_eq!(delay.for_package("envisia.core").delay_seconds, 0);
        assert_eq!(delay.for_package("ENVISIA.Core").delay_seconds, 0);
        // A longer override holds back longer.
        let risky = delay.for_package("some.risky.pkg");
        assert_eq!(risky.delay_seconds, 1_209_600);
        assert_eq!(
            risky.source,
            DelaySource::Pattern {
                pattern: "some.risky.pkg".into()
            }
        );
        // The selector's excludes apply: the default.
        let excluded = delay.for_package("system.risky");
        assert_eq!(excluded.delay_seconds, 86_400);
        assert_eq!(excluded.source, DelaySource::Default);
        assert_eq!(delay.for_package("newtonsoft.json").delay_seconds, 86_400);
        assert!(delay.is_active());
        assert_eq!(delay.shortest(), Duration::zero());
    }

    #[test]
    fn an_override_that_cannot_be_evaluated_never_shortens_the_delay() {
        // The selector is gone: its override might match anything.
        let delay = PackageDelay::new(
            3_600,
            &[by_selector("missing", 7_200), by_pattern("envisia.*", 0)],
            &HashMap::new(),
        );
        assert_eq!(delay.for_package("envisia.core").delay_seconds, 7_200);
        assert_eq!(delay.for_package("other").delay_seconds, 7_200);

        // One shorter than what applies changes nothing.
        let delay = PackageDelay::new(3_600, &[by_selector("missing", 0)], &HashMap::new());
        assert_eq!(delay.for_package("other").delay_seconds, 3_600);
        assert_eq!(delay.for_package("other").source, DelaySource::Default);
    }

    #[test]
    fn without_overrides_every_package_has_the_default() {
        let delay = PackageDelay::uniform(0);
        assert!(!delay.is_active());
        assert_eq!(delay.for_package("a").delay_seconds, 0);
        let delay = PackageDelay::uniform(60);
        assert!(delay.is_active());
        assert_eq!(delay.shortest(), Duration::seconds(60));
    }

    #[test]
    fn a_released_version_clears_the_gate() {
        let now = Utc::now();
        let gate = PackageGate {
            applied: AppliedDelay {
                delay_seconds: 3_600,
                source: DelaySource::Default,
            },
            released: HashMap::from([("1.0.1".to_string(), now)]),
        };
        assert!(gate.cleared("1.0.1", now, now));
        assert!(!gate.cleared("1.0.2", now, now));
        assert!(gate.cleared("1.0.2", now - Duration::hours(2), now));
        assert!(!gate.delays("1.0.1"));
        assert!(gate.delays("1.0.2"));
    }
}
