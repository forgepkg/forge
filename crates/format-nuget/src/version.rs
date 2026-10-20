//! NuGet version normalization and SemVer2 comparison.
//!
//! NuGet versions are `Major.Minor.Patch[.Revision][-prerelease][+build]`.
//! Normalization rules (matching NuGet's `NuGetVersion.ToNormalizedString`):
//!
//! - Missing minor/patch components default to zero (`1` → `1.0.0`,
//!   `1.0` → `1.0.0`).
//! - Leading zeroes in numeric components are stripped (`1.02.3` → `1.2.3`).
//! - A 4th (revision) component is preserved **unless it is zero**, in which
//!   case the version collapses to 3 parts (`1.0.0.0` → `1.0.0`,
//!   `1.2.3.4` → `1.2.3.4`).
//! - Build metadata (`+...`) is stripped entirely.
//! - The prerelease label is lowercased (`1.0.0-Beta` → `1.0.0-beta`), and
//!   leading zeroes in **numeric** prerelease identifiers are stripped
//!   (`1.0.0-rc.01` → `1.0.0-rc.1`).
//!
//! Comparison follows SemVer 2.0.0 precedence over the 4 numeric components
//! plus the prerelease, with the NuGet twist that a release version sorts
//! **after** any prerelease of the same numeric tuple, and prerelease
//! identifiers compare numerically when both are numeric, otherwise
//! lexically (ASCII case-insensitive, since labels are normalized lowercase).

use std::cmp::Ordering;

use forge_core::domain::FormatError;

/// A parsed NuGet version, retaining enough structure to normalize and compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NugetVersion {
    /// The four numeric components: major, minor, patch, revision.
    /// Missing components are zero; `has_revision` records whether the 4th
    /// component was meaningful (non-zero, hence kept on normalization).
    major: u64,
    minor: u64,
    patch: u64,
    revision: u64,
    /// Whether to render the revision component (true iff revision != 0).
    has_revision: bool,
    /// Normalized, lowercased prerelease identifiers (empty = release).
    prerelease: Vec<String>,
}

impl NugetVersion {
    /// Parse a raw version string per NuGet rules. Build metadata is discarded.
    pub fn parse(raw: &str) -> Result<NugetVersion, FormatError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(FormatError::InvalidVersion {
                value: raw.to_string(),
                reason: "empty version".into(),
            });
        }
        // Strip an optional leading 'v'/'V' as some feeds use it.
        let body = trimmed
            .strip_prefix(['v', 'V'])
            .filter(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
            .unwrap_or(trimmed);

        // Split off build metadata (`+...`) — discarded entirely.
        let (without_build, _build) = match body.split_once('+') {
            Some((v, b)) => (v, Some(b)),
            None => (body, None),
        };

        // Split off prerelease (`-...`).
        let (numeric_part, prerelease_part) = match without_build.split_once('-') {
            Some((v, p)) => (v, Some(p)),
            None => (without_build, None),
        };

        let nums = Self::parse_numeric(numeric_part, raw)?;
        let prerelease = match prerelease_part {
            Some(p) => Self::parse_prerelease(p, raw)?,
            None => Vec::new(),
        };

        let revision = nums.get(3).copied().unwrap_or(0);
        Ok(NugetVersion {
            major: nums[0],
            minor: nums.get(1).copied().unwrap_or(0),
            patch: nums.get(2).copied().unwrap_or(0),
            revision,
            has_revision: revision != 0,
            prerelease,
        })
    }

    fn parse_numeric(part: &str, raw: &str) -> Result<Vec<u64>, FormatError> {
        if part.is_empty() {
            return Err(FormatError::InvalidVersion {
                value: raw.to_string(),
                reason: "missing numeric version components".into(),
            });
        }
        let mut out = Vec::with_capacity(4);
        for (i, comp) in part.split('.').enumerate() {
            if i >= 4 {
                return Err(FormatError::InvalidVersion {
                    value: raw.to_string(),
                    reason: "too many version components (max 4)".into(),
                });
            }
            let n: u64 = comp.parse().map_err(|_| FormatError::InvalidVersion {
                value: raw.to_string(),
                reason: format!("non-numeric version component {comp:?}"),
            })?;
            out.push(n);
        }
        Ok(out)
    }

    fn parse_prerelease(part: &str, raw: &str) -> Result<Vec<String>, FormatError> {
        if part.is_empty() {
            return Err(FormatError::InvalidVersion {
                value: raw.to_string(),
                reason: "empty prerelease label".into(),
            });
        }
        let mut out = Vec::new();
        for ident in part.split('.') {
            if ident.is_empty() {
                return Err(FormatError::InvalidVersion {
                    value: raw.to_string(),
                    reason: "empty prerelease identifier".into(),
                });
            }
            // Identifiers must be alphanumeric or hyphen (SemVer2).
            if !ident
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(FormatError::InvalidVersion {
                    value: raw.to_string(),
                    reason: format!("invalid prerelease identifier {ident:?}"),
                });
            }
            let lower = ident.to_ascii_lowercase();
            // Strip leading zeroes on purely-numeric identifiers.
            let normalized = if lower.bytes().all(|b| b.is_ascii_digit()) {
                let stripped = lower.trim_start_matches('0');
                if stripped.is_empty() {
                    "0".to_string()
                } else {
                    stripped.to_string()
                }
            } else {
                lower
            };
            out.push(normalized);
        }
        Ok(out)
    }

    /// Check that NuGet clients can read `raw` as a package's own version,
    /// beyond what [`Self::parse`] accepts (which stays lenient for versions
    /// listed by upstream feeds): every numeric component fits NuGet's
    /// `int32`, numeric prerelease identifiers have no leading zero (NuGet
    /// keeps `rc.01` verbatim while Forge would normalize it to `rc.1`, so the
    /// package would live at a URL no client asks for), and build metadata is
    /// dot-separated `[0-9A-Za-z-]` identifiers.
    pub fn validate_publishable(raw: &str) -> Result<(), FormatError> {
        let invalid = |reason: String| FormatError::InvalidVersion {
            value: raw.to_string(),
            reason,
        };
        let parsed = Self::parse(raw)?;
        let max = i32::MAX as u64;
        if [parsed.major, parsed.minor, parsed.patch, parsed.revision]
            .iter()
            .any(|&n| n > max)
        {
            return Err(invalid(format!("a version component exceeds {max}")));
        }
        let trimmed = raw.trim();
        let (without_build, build) = match trimmed.split_once('+') {
            Some((v, b)) => (v, Some(b)),
            None => (trimmed, None),
        };
        if let Some((_, prerelease)) = without_build.split_once('-') {
            if prerelease.split('.').any(|ident| {
                ident.len() > 1
                    && ident.starts_with('0')
                    && ident.bytes().all(|b| b.is_ascii_digit())
            }) {
                return Err(invalid(
                    "a numeric prerelease identifier has a leading zero".into(),
                ));
            }
        }
        if let Some(build) = build {
            let valid = build.split('.').all(|ident| {
                !ident.is_empty()
                    && ident
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
            if !valid {
                return Err(invalid("invalid build metadata".into()));
            }
        }
        Ok(())
    }

    /// Render the canonical normalized string.
    pub fn to_normalized_string(&self) -> String {
        let mut s = if self.has_revision {
            format!(
                "{}.{}.{}.{}",
                self.major, self.minor, self.patch, self.revision
            )
        } else {
            format!("{}.{}.{}", self.major, self.minor, self.patch)
        };
        if !self.prerelease.is_empty() {
            s.push('-');
            s.push_str(&self.prerelease.join("."));
        }
        s
    }

    /// SemVer2 / NuGet precedence comparison.
    pub fn compare(&self, other: &NugetVersion) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then(self.revision.cmp(&other.revision))
            .then_with(|| cmp_prerelease(&self.prerelease, &other.prerelease))
    }
}

/// Compare two prerelease identifier lists. An empty list (release) sorts
/// **after** any non-empty list (prerelease).
fn cmp_prerelease(a: &[String], b: &[String]) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater, // release > prerelease
        (false, true) => Ordering::Less,    // prerelease < release
        (false, false) => {
            for (x, y) in a.iter().zip(b.iter()) {
                let ord = cmp_identifier(x, y);
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            // All shared identifiers equal: more identifiers => higher precedence.
            a.len().cmp(&b.len())
        }
    }
}

/// Compare a single pair of (already lowercased) prerelease identifiers.
/// Numeric identifiers compare numerically and always sort lower than
/// alphanumeric ones (SemVer2 rule 11.4.3).
fn cmp_identifier(a: &str, b: &str) -> Ordering {
    let a_num = a.bytes().all(|c| c.is_ascii_digit());
    let b_num = b.bytes().all(|c| c.is_ascii_digit());
    match (a_num, b_num) {
        (true, true) => {
            // Both numeric: compare by parsed value (lengths may differ).
            // Values are already leading-zero-stripped, so length then bytes works,
            // but parse to be safe against very long inputs by length-first compare.
            match a.len().cmp(&b.len()) {
                Ordering::Equal => a.cmp(b),
                ord => ord,
            }
        }
        (true, false) => Ordering::Less, // numeric < alphanumeric
        (false, true) => Ordering::Greater,
        (false, false) => a.cmp(b),
    }
}

/// Normalize a raw version string to its canonical NuGet form.
pub fn normalize(raw: &str) -> Result<String, FormatError> {
    Ok(NugetVersion::parse(raw)?.to_normalized_string())
}

/// Compare two **normalized** version strings. If either fails to parse the
/// comparison falls back to a byte comparison so the function is total.
pub fn compare(a: &str, b: &str) -> Ordering {
    match (NugetVersion::parse(a), NugetVersion::parse(b)) {
        (Ok(va), Ok(vb)) => va.compare(&vb),
        _ => a.cmp(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str) -> String {
        normalize(s).unwrap()
    }

    #[test]
    fn pads_missing_components() {
        assert_eq!(norm("1"), "1.0.0");
        assert_eq!(norm("1.0"), "1.0.0");
        assert_eq!(norm("1.2"), "1.2.0");
        assert_eq!(norm("1.2.3"), "1.2.3");
    }

    #[test]
    fn strips_leading_zeroes_in_numeric_components() {
        assert_eq!(norm("1.02.3"), "1.2.3");
        assert_eq!(norm("01.02.03"), "1.2.3");
    }

    #[test]
    fn strips_build_metadata() {
        assert_eq!(norm("1.0.0+abc"), "1.0.0");
        assert_eq!(norm("1.0.0+build.5"), "1.0.0");
        assert_eq!(norm("1.0.0-beta+sha.1234"), "1.0.0-beta");
    }

    #[test]
    fn lowercases_prerelease() {
        assert_eq!(norm("1.0.0-Beta"), "1.0.0-beta");
        assert_eq!(norm("1.0.0-RC.1"), "1.0.0-rc.1");
        assert_eq!(norm("2.0.0-Alpha.Beta"), "2.0.0-alpha.beta");
    }

    #[test]
    fn collapses_zero_revision_to_three_parts() {
        assert_eq!(norm("1.0.0.0"), "1.0.0");
        assert_eq!(norm("1.2.3.0"), "1.2.3");
    }

    #[test]
    fn keeps_nonzero_revision() {
        assert_eq!(norm("1.2.3.4"), "1.2.3.4");
        assert_eq!(norm("1.0.0.1"), "1.0.0.1");
    }

    #[test]
    fn strips_leading_zeroes_in_numeric_prerelease_identifiers() {
        assert_eq!(norm("1.0.0-rc.01"), "1.0.0-rc.1");
        assert_eq!(norm("1.0.0-0"), "1.0.0-0");
    }

    #[test]
    fn accepts_optional_v_prefix() {
        assert_eq!(norm("v1.2.3"), "1.2.3");
    }

    #[test]
    fn rejects_garbage() {
        assert!(normalize("").is_err());
        assert!(normalize("not-a-version").is_err());
        assert!(normalize("1.2.3.4.5").is_err());
        assert!(normalize("1.0.0-").is_err());
    }

    fn ord(a: &str, b: &str) -> Ordering {
        compare(&norm(a), &norm(b))
    }

    #[test]
    fn orders_numeric_components() {
        assert_eq!(ord("1.0.0", "2.0.0"), Ordering::Less);
        assert_eq!(ord("1.2.0", "1.1.9"), Ordering::Greater);
        assert_eq!(ord("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(ord("1.0.0.1", "1.0.0"), Ordering::Greater);
    }

    #[test]
    fn release_sorts_after_prerelease() {
        assert_eq!(ord("1.0.0-beta", "1.0.0"), Ordering::Less);
        assert_eq!(ord("1.0.0", "1.0.0-rc.1"), Ordering::Greater);
    }

    #[test]
    fn prerelease_numeric_vs_alpha() {
        // numeric identifiers sort lower than alphanumeric
        assert_eq!(ord("1.0.0-1", "1.0.0-alpha"), Ordering::Less);
        // numeric compared as numbers, not strings
        assert_eq!(ord("1.0.0-2", "1.0.0-10"), Ordering::Less);
        // fewer identifiers sorts lower when prefix equal
        assert_eq!(ord("1.0.0-alpha", "1.0.0-alpha.1"), Ordering::Less);
        // lexical alpha comparison
        assert_eq!(ord("1.0.0-alpha", "1.0.0-beta"), Ordering::Less);
    }

    #[test]
    fn semver2_spec_example_ordering() {
        // 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta
        //   < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for pair in chain.windows(2) {
            assert_eq!(
                ord(pair[0], pair[1]),
                Ordering::Less,
                "{} should be < {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn prerelease_compare_is_case_insensitive_via_normalization() {
        assert_eq!(ord("1.0.0-Beta", "1.0.0-beta"), Ordering::Equal);
    }
}
