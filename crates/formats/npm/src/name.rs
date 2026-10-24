//! npm package names, as `validate-npm-package-name` reads them.
//!
//! A name is `name` or `@scope/name`. Both parts are URL-safe as they are
//! (what `encodeURIComponent` leaves alone), so a name is pasted into a URL
//! path without escaping, save the `/` of a scoped name, which the packument
//! URL escapes as `%2f`.
//!
//! The registry has two rules:
//!
//! * a name a **new** package may take ([`PackageName::parse_new`]): what a
//!   hosted repository accepts from a publish. Lowercase, at most 214
//!   characters, and no `~'!()*` in the name part.
//! * a name an **existing** package may have ([`PackageName::parse`]): what a
//!   proxy reads from its upstream, which still serves packages published
//!   before the stricter rule (`JSONStream`).
//!
//! Neither part may start with `.` or `_`, so no part is ever `.` or `..`.

use std::fmt;

/// The longest name a new package may take.
pub const MAX_NEW_NAME_LEN: usize = 214;

/// The longest name read at all (the host's bound on ids).
pub const MAX_NAME_LEN: usize = 512;

/// A valid npm package name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageName {
    scope: Option<String>,
    name: String,
}

/// Why a name is not one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidName(pub String);

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidName {}

/// Whether `c` is a character `encodeURIComponent` leaves as it is.
fn uri_safe(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')')
}

fn check_part(name: &str, part: &str, what: &str) -> Result<(), InvalidName> {
    if part.is_empty() {
        return Err(InvalidName(format!("{name:?}: the {what} is empty")));
    }
    if part.starts_with('.') || part.starts_with('_') {
        return Err(InvalidName(format!(
            "{name:?}: the {what} may not start with '.' or '_'"
        )));
    }
    if !part.chars().all(uri_safe) {
        return Err(InvalidName(format!(
            "{name:?}: the {what} may only contain URL-safe characters (letters, digits, '-', '_', '.', '!', '~', '*', ''', '(' and ')')"
        )));
    }
    Ok(())
}

impl PackageName {
    /// A name an existing package may have.
    pub fn parse(raw: &str) -> Result<Self, InvalidName> {
        if raw.len() > MAX_NAME_LEN {
            return Err(InvalidName(format!(
                "the name is longer than {MAX_NAME_LEN} characters"
            )));
        }
        if raw.trim() != raw {
            return Err(InvalidName(format!(
                "{raw:?}: the name has leading or trailing spaces"
            )));
        }
        if raw.eq_ignore_ascii_case("node_modules") || raw.eq_ignore_ascii_case("favicon.ico") {
            return Err(InvalidName(format!("{raw:?} is not a package name")));
        }
        match raw.strip_prefix('@') {
            Some(scoped) => {
                let Some((scope, name)) = scoped.split_once('/') else {
                    return Err(InvalidName(format!(
                        "{raw:?}: a scoped name is @scope/name"
                    )));
                };
                check_part(raw, scope, "scope")?;
                check_part(raw, name, "name")?;
                Ok(PackageName {
                    scope: Some(scope.to_string()),
                    name: name.to_string(),
                })
            }
            None => {
                check_part(raw, raw, "name")?;
                Ok(PackageName {
                    scope: None,
                    name: raw.to_string(),
                })
            }
        }
    }

    /// A name a new package may take (a publish to a hosted repository).
    pub fn parse_new(raw: &str) -> Result<Self, InvalidName> {
        let name = Self::parse(raw)?;
        if raw.len() > MAX_NEW_NAME_LEN {
            return Err(InvalidName(format!(
                "{raw:?}: a new package's name is at most {MAX_NEW_NAME_LEN} characters"
            )));
        }
        if raw.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(InvalidName(format!(
                "{raw:?}: a new package's name may not contain capital letters"
            )));
        }
        if name.name.contains(['~', '\'', '!', '(', ')', '*']) {
            return Err(InvalidName(format!(
                "{raw:?}: a new package's name may not contain ~'!()*"
            )));
        }
        Ok(name)
    }

    /// The scope, without its `@` (`None` for an unscoped name).
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// The name without its scope: what a tarball's file name starts with.
    pub fn unscoped(&self) -> &str {
        &self.name
    }

    /// The name as it is written in a URL path segment, `@scope%2fname` for
    /// a scoped name (npm's `escapedName`).
    pub fn escaped(&self) -> String {
        match &self.scope {
            Some(scope) => format!("@{scope}%2f{}", self.name),
            None => self.name.clone(),
        }
    }

    /// The file name of a version's tarball, `<name>-<version>.tgz`, as the
    /// npm registry names it.
    pub fn tarball_file(&self, version: &str) -> String {
        format!("{}-{version}.tgz", self.name)
    }

    /// The version a tarball file name `file` names, if it is one of this
    /// package's (`<name>-<version>.tgz`).
    pub fn version_of_tarball<'a>(&self, file: &'a str) -> Option<&'a str> {
        let version = file
            .strip_suffix(".tgz")?
            .strip_prefix(self.name.as_str())?
            .strip_prefix('-')?;
        (!version.is_empty()).then_some(version)
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.scope {
            Some(scope) => write!(f, "@{scope}/{}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_plain_and_scoped_names() {
        let plain = PackageName::parse("left-pad").unwrap();
        assert_eq!(plain.scope(), None);
        assert_eq!(plain.to_string(), "left-pad");
        assert_eq!(plain.escaped(), "left-pad");

        let scoped = PackageName::parse("@envisia/ui-kit").unwrap();
        assert_eq!(scoped.scope(), Some("envisia"));
        assert_eq!(scoped.unscoped(), "ui-kit");
        assert_eq!(scoped.to_string(), "@envisia/ui-kit");
        assert_eq!(scoped.escaped(), "@envisia%2fui-kit");
        assert_eq!(scoped.tarball_file("1.0.0"), "ui-kit-1.0.0.tgz");
        assert_eq!(
            scoped.version_of_tarball("ui-kit-1.0.0-rc.1.tgz"),
            Some("1.0.0-rc.1")
        );
        assert_eq!(scoped.version_of_tarball("other-1.0.0.tgz"), None);
        assert_eq!(scoped.version_of_tarball("ui-kit-.tgz"), None);
        assert_eq!(scoped.version_of_tarball("ui-kit-1.0.0.tar"), None);
    }

    #[test]
    fn old_names_stay_readable() {
        assert!(PackageName::parse("JSONStream").is_ok());
        assert!(PackageName::parse_new("JSONStream").is_err());
        assert!(PackageName::parse("highlight.js").is_ok());
        assert!(PackageName::parse("lodash.merge").is_ok());
        assert!(PackageName::parse("ok!").is_ok());
        assert!(PackageName::parse_new("ok!").is_err());
        assert!(PackageName::parse_new(&"a".repeat(214)).is_ok());
        assert!(PackageName::parse_new(&"a".repeat(215)).is_err());
        assert!(PackageName::parse(&"a".repeat(215)).is_ok());
    }

    #[test]
    fn refuses_what_is_no_name() {
        for bad in [
            "",
            " x",
            "x ",
            ".hidden",
            "_private",
            "..",
            ".",
            "a/b",
            "@scope",
            "@scope/",
            "@/x",
            "@sc/ope/x",
            "@.scope/x",
            "@scope/.x",
            "@scope/_x",
            "a b",
            "a%2fb",
            "a?b",
            "a#b",
            "a\\b",
            "ünicode",
            "node_modules",
            "favicon.ico",
        ] {
            assert!(PackageName::parse(bad).is_err(), "{bad:?}");
        }
    }
}
