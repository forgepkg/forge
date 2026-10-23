//! SemVer 2.0.0, as Helm reads chart versions: a leading `v` and missing
//! minor/patch components are accepted and normalized away.

use std::cmp::Ordering;

/// The longest chart version, as written and normalized. Helm pushes a chart
/// to an OCI registry under its version as the tag (with `+` written `_`),
/// and a tag is at most 128 characters (the OCI distribution spec's
/// `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`), so no chart a Helm user can push to
/// an OCI registry has a longer version. Without a limit a multi-kilobyte
/// prerelease passed parsing and failed the `(repository_id, name, version)`
/// index insert in PostgreSQL, so a push answered 500 instead of 400. A
/// version is ASCII, so this counts bytes.
pub const MAX_VERSION_LENGTH: usize = 128;

/// A parsed version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<Ident>,
    build: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ident {
    Num(u64),
    Alpha(String),
}

impl Version {
    /// Parse `raw`, or say why it is not a version. A version longer than
    /// [`MAX_VERSION_LENGTH`], as written or normalized, is not one.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let written = raw.trim();
        // Before parsing, so an oversized version is not copied around first.
        if written.len() > MAX_VERSION_LENGTH {
            return Err(too_long(written));
        }
        let s = written.strip_prefix(['v', 'V']).unwrap_or(written);
        let (rest, build) = match s.split_once('+') {
            Some((rest, build)) => (rest, Some(build)),
            None => (s, None),
        };
        let (core, pre) = match rest.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (rest, None),
        };
        let mut parts = core.split('.');
        let mut number = |required: bool| -> Result<u64, String> {
            match parts.next() {
                Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p
                    .parse()
                    .map_err(|_| format!("version {raw:?}: {p} is too large")),
                Some(p) => Err(format!("version {raw:?}: {p:?} is not a number")),
                None if required => Err(format!("version {raw:?} has no major version")),
                None => Ok(0),
            }
        };
        let major = number(true)?;
        let minor = number(false)?;
        let patch = number(false)?;
        if parts.next().is_some() {
            return Err(format!("version {raw:?} has more than three numbers"));
        }
        let identifiers = |text: &str| -> Result<(), String> {
            let ok = text.split('.').all(|i| {
                !i.is_empty() && i.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
            if ok {
                Ok(())
            } else {
                Err(format!("version {raw:?}: invalid identifiers {text:?}"))
            }
        };
        let pre = match pre {
            Some(pre) => {
                identifiers(pre)?;
                pre.split('.')
                    .map(|i| {
                        // A number with a leading zero is not a numeric
                        // identifier; keep it as text rather than refuse it.
                        match i.parse::<u64>() {
                            Ok(n) if !(i.len() > 1 && i.starts_with('0')) => Ident::Num(n),
                            _ => Ident::Alpha(i.to_string()),
                        }
                    })
                    .collect()
            }
            None => Vec::new(),
        };
        let build = match build {
            Some(build) => {
                identifiers(build)?;
                build.to_string()
            }
            None => String::new(),
        };
        let version = Version {
            major,
            minor,
            patch,
            pre,
            build,
        };
        // Normalizing can lengthen a version (`1-x` → `1.0.0-x`).
        let normalized = version.to_string();
        if normalized.len() > MAX_VERSION_LENGTH {
            return Err(format!(
                "version {written:?} normalizes to {normalized:?}, longer than \
                 {MAX_VERSION_LENGTH} characters"
            ));
        }
        Ok(version)
    }
}

/// Why `written` is not a version: it is longer than [`MAX_VERSION_LENGTH`].
/// The reason names only its start.
fn too_long(written: &str) -> String {
    let start: String = written.chars().take(MAX_VERSION_LENGTH).collect();
    format!(
        "version {:?} is longer than {MAX_VERSION_LENGTH} characters",
        format!("{start}…")
    )
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (i, ident) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            match ident {
                Ident::Num(n) => write!(f, "{n}")?,
                Ident::Alpha(s) => f.write_str(s)?,
            }
        }
        if !self.build.is_empty() {
            write!(f, "+{}", self.build)?;
        }
        Ok(())
    }
}

impl Ord for Version {
    /// SemVer precedence; build metadata, which precedence ignores, breaks
    /// ties so that distinct versions never compare equal.
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let order = match (a, b) {
                            (Ident::Num(a), Ident::Num(b)) => a.cmp(b),
                            (Ident::Num(_), Ident::Alpha(_)) => Ordering::Less,
                            (Ident::Alpha(_), Ident::Num(_)) => Ordering::Greater,
                            (Ident::Alpha(a), Ident::Alpha(b)) => a.cmp(b),
                        };
                        if order != Ordering::Equal {
                            return order;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
            .then_with(|| self.build.cmp(&other.build))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn normalizes() {
        assert_eq!(v("v1.2.3").to_string(), "1.2.3");
        assert_eq!(v("1.2").to_string(), "1.2.0");
        assert_eq!(v("1").to_string(), "1.0.0");
        assert_eq!(v("01.002.3").to_string(), "1.2.3");
        assert_eq!(v("1.0.0-rc.01+build.5").to_string(), "1.0.0-rc.01+build.5");
        for bad in [
            "",
            "x",
            "1.2.3.4",
            "1..2",
            "1.0.0-",
            "1.0.0+",
            "1.0.0-a..b",
            "1.0.0-a_b",
        ] {
            assert!(Version::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn refuses_versions_longer_than_an_oci_tag() {
        let longest = format!("1.0.0-{}", "a".repeat(MAX_VERSION_LENGTH - 6));
        assert_eq!(longest.len(), MAX_VERSION_LENGTH);
        assert_eq!(v(&longest).to_string(), longest);
        // Surrounding whitespace is not part of the version.
        assert_eq!(v(&format!(" {longest}\n")).to_string(), longest);
        let err = Version::parse(&format!("{longest}a")).unwrap_err();
        assert!(err.contains("longer than 128 characters"), "{err}");
        // A multi-kilobyte prerelease, named only by its start.
        let err = Version::parse(&format!("1.0.0-{}", "x".repeat(4096))).unwrap_err();
        assert!(err.len() < 200, "{err}");
        // Normalized, `1-…` gains `.0.0`: the written form fits, not the
        // normalized one.
        let short = format!("1-{}", "a".repeat(MAX_VERSION_LENGTH - 2));
        assert_eq!(short.len(), MAX_VERSION_LENGTH);
        let err = Version::parse(&short).unwrap_err();
        assert!(err.contains("normalizes to"), "{err}");
        assert!(Version::parse(&format!("1-{}", "a".repeat(MAX_VERSION_LENGTH - 6))).is_ok());
    }

    #[test]
    fn orders_by_precedence() {
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.0+build",
            "1.9.0",
            "1.10.0",
            "2.0.0",
        ];
        for pair in ordered.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        // Forge's rule: a normalized version is a prerelease when it has a `-`.
        assert!(v("1.0.0-beta").to_string().contains('-'));
        assert!(!v("v1.0+build").to_string().contains('-'));
    }
}
