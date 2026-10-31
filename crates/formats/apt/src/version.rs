//! Debian package versions: `[epoch:]upstream_version[-debian_revision]`,
//! ordered as dpkg orders them (Debian Policy 5.6.12, dpkg's `verrevcmp`).
//!
//! * The epoch is a number; without one it is 0.
//! * The upstream version starts with a digit and holds letters, digits and
//!   `.`, `+`, `~`, and `-` when there is a revision (the revision is what
//!   follows the last `-`).
//! * The revision holds letters, digits and `.`, `+`, `~`.
//!
//! Comparing two versions compares the epochs as numbers, then the upstream
//! versions, then the revisions: each alternates runs of non-digits, compared
//! character by character (`~` before the end of the string, before
//! everything else; letters before the other characters), and runs of
//! digits, compared as numbers. So `1.0~rc1` < `1.0` < `1.0+b1` < `1.0a`,
//! and `1.0-1` < `1.0-10`.

use std::cmp::Ordering;
use std::fmt;

/// The longest version accepted, in bytes (the host bounds them at 256).
pub const MAX_VERSION_BYTES: usize = 128;

/// A version, split into its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version<'a> {
    pub epoch: u32,
    pub upstream: &'a str,
    /// Empty when the version has no revision.
    pub revision: &'a str,
}

/// Why a version is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionError(pub String);

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'a> Version<'a> {
    /// Parse a version as a control file writes it.
    pub fn parse(version: &'a str) -> Result<Self, VersionError> {
        let fail = |why: &str| Err(VersionError(format!("{version:?}: {why}")));
        if version.is_empty() {
            return fail("empty");
        }
        if version.len() > MAX_VERSION_BYTES {
            return fail("longer than 128 bytes");
        }
        let (epoch, rest) = match version.split_once(':') {
            Some((epoch, rest)) => {
                if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
                    return fail("the epoch is not a number");
                }
                match epoch.parse::<u32>() {
                    Ok(epoch) => (epoch, rest),
                    Err(_) => return fail("the epoch is too large"),
                }
            }
            None => (0, version),
        };
        let (upstream, revision) = match rest.rsplit_once('-') {
            Some((upstream, revision)) => {
                if revision.is_empty() {
                    return fail("the revision after the last '-' is empty");
                }
                (upstream, revision)
            }
            None => (rest, ""),
        };
        if !upstream.starts_with(|c: char| c.is_ascii_digit()) {
            return fail("the upstream version does not start with a digit");
        }
        let upstream_ok = upstream
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~' | b'-'));
        if !upstream_ok {
            return fail(
                "the upstream version holds characters other than letters, digits and . + ~ -",
            );
        }
        let revision_ok = revision
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~'));
        if !revision_ok {
            return fail("the revision holds characters other than letters, digits and . + ~");
        }
        Ok(Version {
            epoch,
            upstream,
            revision,
        })
    }

    /// The version without its epoch, as Debian names files
    /// (`hello_2.10-3_amd64.deb`).
    pub fn without_epoch(&self) -> String {
        if self.revision.is_empty() {
            self.upstream.to_string()
        } else {
            format!("{}-{}", self.upstream, self.revision)
        }
    }
}

/// The normalized form of `version`, its identity in a repository: the
/// version as written, without an explicit epoch of 0 (`0:1.0` is `1.0`).
pub fn normalize(version: &str) -> Result<String, VersionError> {
    let parsed = Version::parse(version)?;
    Ok(if parsed.epoch == 0 {
        parsed.without_epoch()
    } else {
        format!("{}:{}", parsed.epoch, parsed.without_epoch())
    })
}

/// dpkg's order of two versions. A version that does not parse sorts
/// before every version that does, and such versions by their bytes.
pub fn compare(a: &str, b: &str) -> Ordering {
    match (Version::parse(a), Version::parse(b)) {
        (Ok(a), Ok(b)) => a
            .epoch
            .cmp(&b.epoch)
            .then_with(|| verrevcmp(a.upstream, b.upstream))
            .then_with(|| verrevcmp(a.revision, b.revision)),
        (Ok(_), Err(_)) => Ordering::Greater,
        (Err(_), Ok(_)) => Ordering::Less,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

/// The weight of a non-digit character in a version (`0` past its end):
/// `~` sorts before everything, even the end, letters before the rest.
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(b'~') => -1,
        Some(c) => i32::from(c) + 256,
    }
}

/// dpkg's `verrevcmp`: compare an upstream version or a revision.
fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    let digit = |s: &[u8], k: usize| s.get(k).is_some_and(u8::is_ascii_digit);
    while i < a.len() || j < b.len() {
        // A run of non-digits, character by character.
        while (i < a.len() && !digit(a, i)) || (j < b.len() && !digit(b, j)) {
            let (ac, bc) = (order(a.get(i).copied()), order(b.get(j).copied()));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        // A run of digits, as a number.
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while digit(a, i) && digit(b, j) {
            if first_diff == Ordering::Equal {
                first_diff = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if digit(a, i) {
            return Ordering::Greater;
        }
        if digit(b, j) {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lt(a: &str, b: &str) {
        assert_eq!(compare(a, b), Ordering::Less, "{a} < {b}");
        assert_eq!(compare(b, a), Ordering::Greater, "{b} > {a}");
    }

    fn eq(a: &str, b: &str) {
        assert_eq!(compare(a, b), Ordering::Equal, "{a} = {b}");
    }

    #[test]
    fn epochs_come_first() {
        lt("1.0", "1:0.1");
        lt("1:2.0", "2:1.0");
        lt("9:9.9", "10:0.1");
        eq("0:1.0", "1.0");
        lt("1.0-9", "1:1.0-1");
    }

    #[test]
    fn tilde_sorts_before_everything() {
        lt("1.0~rc1", "1.0");
        lt("1.0~~", "1.0~");
        lt("1.0~~a", "1.0~");
        lt("1.0~rc1", "1.0~rc2");
        lt("1.0~beta", "1.0~rc");
        lt("2.0~1", "2.0-1");
        lt("1.0-1~bpo1", "1.0-1");
        lt("1.0", "1.0+b1");
        lt("1.0", "1.0.1");
    }

    #[test]
    fn letters_sort_before_other_characters() {
        lt("1.0a", "1.0+");
        lt("1.0a", "1.0.");
        lt("1.0+", "1.0.");
        lt("1.0", "1.0a");
        lt("1.0A", "1.0a");
    }

    #[test]
    fn digits_compare_as_numbers() {
        lt("1.2", "1.10");
        lt("1.0-1", "1.0-10");
        lt("1.0-2", "1.0-10");
        lt("2.9", "2.10");
        eq("1.00", "1.0");
        eq("1.01", "1.1");
        lt("1.0", "1.0-1");
        eq("1.0", "1.0-0");
    }

    #[test]
    fn revisions_come_after_the_upstream_version() {
        lt("1.0-1", "1.0-2");
        lt("1.0-1", "1.1-1");
        lt("1.0-1ubuntu1", "1.0-1ubuntu2");
        lt("1.0-1", "1.0-1ubuntu1");
        lt("2.10-2", "2.10-3");
        // The revision is what follows the last hyphen.
        let v = Version::parse("1.0-beta-2").unwrap();
        assert_eq!((v.upstream, v.revision), ("1.0-beta", "2"));
    }

    #[test]
    fn a_sorted_list_matches_dpkg() {
        let mut versions = vec![
            "1.0-1",
            "1:0.9",
            "1.0~rc1-1",
            "1.0",
            "1.0+dfsg-1",
            "0.9.9",
            "1.0-1.1",
            "1.0-1~bpo11+1",
            "2.0~~",
            "2.0~",
            "2.0",
        ];
        versions.sort_by(|a, b| compare(a, b));
        assert_eq!(
            versions,
            vec![
                "0.9.9",
                "1.0~rc1-1",
                "1.0",
                "1.0-1~bpo11+1",
                "1.0-1",
                "1.0-1.1",
                "1.0+dfsg-1",
                "2.0~~",
                "2.0~",
                "2.0",
                "1:0.9",
            ]
        );
    }

    #[test]
    fn versions_are_validated() {
        for bad in [
            "",
            "a1.0",
            ":1.0",
            "x:1.0",
            "1.0-",
            "1.0_1",
            "1.0 1",
            "1.0/1",
            "-1",
            "1:",
            "1.0-a_b",
            "99999999999:1.0",
            "1.0-1:2",
        ] {
            assert!(Version::parse(bad).is_err(), "{bad:?}");
        }
        for good in [
            "1",
            "1.0",
            "1:1.0",
            "1.0-1",
            "1.0~rc1+dfsg-0ubuntu1~22.04.1",
            "2:1.2.3-4.5",
        ] {
            assert!(Version::parse(good).is_ok(), "{good:?}");
        }
        assert!(Version::parse(&"1".repeat(MAX_VERSION_BYTES + 1)).is_err());
    }

    #[test]
    fn normalizing_drops_a_zero_epoch_only() {
        assert_eq!(normalize("0:1.0-1").unwrap(), "1.0-1");
        assert_eq!(normalize("1.0-1").unwrap(), "1.0-1");
        assert_eq!(normalize("2:1.0").unwrap(), "2:1.0");
        assert_eq!(normalize("00:1.0").unwrap(), "1.0");
        assert_eq!(normalize("02:1.0").unwrap(), "2:1.0");
        assert!(normalize("bad").is_err());
    }

    #[test]
    fn unparsable_versions_sort_first() {
        lt("not a version", "0");
        lt("a", "b");
    }
}
