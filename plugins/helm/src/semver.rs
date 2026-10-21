//! SemVer 2.0.0, as Helm reads chart versions: a leading `v` and missing
//! minor/patch components are accepted and normalized away.

use std::cmp::Ordering;

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
    /// Parse `raw`, or say why it is not a version.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
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
        Ok(Version {
            major,
            minor,
            patch,
            pre,
            build,
        })
    }
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
