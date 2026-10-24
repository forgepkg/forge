//! npm versions: SemVer 2.0.0, as node-semver cleans them.
//!
//! npm stores a version as `semver.clean` makes it: surrounding spaces and
//! one leading `v` or `=` dropped, and build metadata left out
//! (`1.2.3+build.5` is `1.2.3`). Versions order by SemVer precedence.

use std::cmp::Ordering;

/// The longest version read (the host's bound on versions).
pub const MAX_VERSION_LEN: usize = 256;

/// The normalized form of `raw`, or why it is no version.
pub fn normalize(raw: &str) -> Result<String, String> {
    if raw.len() > MAX_VERSION_LEN {
        return Err(format!("longer than {MAX_VERSION_LEN} characters"));
    }
    let trimmed = raw.trim();
    let trimmed = trimmed
        .strip_prefix('=')
        .or_else(|| trimmed.strip_prefix('v'))
        .unwrap_or(trimmed)
        .trim_start();
    let parsed = semver::Version::parse(trimmed).map_err(|e| e.to_string())?;
    Ok(format(&parsed))
}

/// `major.minor.patch[-pre]`, without build metadata.
fn format(v: &semver::Version) -> String {
    if v.pre.is_empty() {
        format!("{}.{}.{}", v.major, v.minor, v.patch)
    } else {
        format!("{}.{}.{}-{}", v.major, v.minor, v.patch, v.pre)
    }
}

/// Order two versions by SemVer precedence; a version that does not parse
/// sorts before every one that does, and among themselves by text.
pub fn compare(a: &str, b: &str) -> Ordering {
    match (semver::Version::parse(a), semver::Version::parse(b)) {
        (Ok(a), Ok(b)) => a.cmp_precedence(&b),
        (Ok(_), Err(_)) => Ordering::Greater,
        (Err(_), Ok(_)) => Ordering::Less,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

/// Whether a normalized version is a prerelease (`1.0.0-rc.1`).
pub fn is_prerelease(version: &str) -> bool {
    version.contains('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_like_semver_clean() {
        assert_eq!(normalize("1.2.3").unwrap(), "1.2.3");
        assert_eq!(normalize(" v1.2.3 ").unwrap(), "1.2.3");
        assert_eq!(normalize("=1.2.3").unwrap(), "1.2.3");
        assert_eq!(normalize("1.2.3+build.5").unwrap(), "1.2.3");
        assert_eq!(normalize("1.2.3-rc.1+x").unwrap(), "1.2.3-rc.1");
        assert!(normalize("1.2").is_err());
        assert!(normalize("01.2.3").is_err());
        assert!(normalize("latest").is_err());
        assert!(normalize("").is_err());
        assert!(normalize(&"1".repeat(300)).is_err());
    }

    #[test]
    fn orders_by_precedence() {
        let mut versions = vec![
            "1.10.0",
            "1.2.0",
            "1.2.0-beta.11",
            "1.2.0-beta.2",
            "1.2.0-alpha",
            "0.9.9",
            "2.0.0-rc.1",
        ];
        versions.sort_by(|a, b| compare(a, b));
        assert_eq!(
            versions,
            [
                "0.9.9",
                "1.2.0-alpha",
                "1.2.0-beta.2",
                "1.2.0-beta.11",
                "1.2.0",
                "1.10.0",
                "2.0.0-rc.1"
            ]
        );
        assert!(is_prerelease("2.0.0-rc.1"));
        assert!(!is_prerelease("2.0.0"));
    }
}
