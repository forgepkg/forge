//! Control data: the deb822 paragraphs of a package's `control` file and of
//! the `Packages` indexes (Debian Policy 5.1), and the names they hold.
//!
//! A paragraph is a list of fields, `Name: value`, each value continuing on
//! the following lines that start with a space or a tab. Field names are
//! compared without regard to case and appear once. A paragraph is parsed
//! strictly and written back in one canonical spelling, so that what a
//! package's control file says cannot add lines (or paragraphs) to an index.

use std::fmt;

/// The longest control file read from a package, in bytes.
pub const MAX_CONTROL_BYTES: usize = 1024 * 1024;

/// The longest package name (Debian has no limit; the host bounds ids).
pub const MAX_NAME_BYTES: usize = 128;

/// The longest architecture or component name.
pub const MAX_WORD_BYTES: usize = 64;

/// Why control data is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlError(pub String);

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn error<T>(message: impl Into<String>) -> Result<T, ControlError> {
    Err(ControlError(message.into()))
}

/// One field: its name as written, and its value. A value's first line is
/// trimmed; each following line keeps its leading space or tab and is
/// joined with `\n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub value: String,
}

/// A paragraph of fields, in the order they were written.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Paragraph {
    pub fields: Vec<Field>,
}

impl Paragraph {
    /// Parse a text holding exactly one paragraph (blank lines around it are
    /// allowed).
    pub fn parse_one(text: &str) -> Result<Paragraph, ControlError> {
        let mut paragraphs = Paragraph::parse_all(text)?;
        match paragraphs.len() {
            1 => Ok(paragraphs.remove(0)),
            0 => error("the control data holds no fields"),
            _ => error("the control data holds more than one paragraph"),
        }
    }

    /// Parse every paragraph of `text`.
    pub fn parse_all(text: &str) -> Result<Vec<Paragraph>, ControlError> {
        let mut paragraphs = Vec::new();
        let mut current = Paragraph::default();
        for (number, line) in text.split('\n').enumerate() {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.chars().any(|c| c.is_control() && c != '\t') {
                return error(format!("line {}: control characters", number + 1));
            }
            if line.trim().is_empty() {
                if !current.fields.is_empty() {
                    paragraphs.push(std::mem::take(&mut current));
                }
                continue;
            }
            if line.starts_with([' ', '\t']) {
                let Some(field) = current.fields.last_mut() else {
                    return error(format!(
                        "line {}: a continuation line without a field",
                        number + 1
                    ));
                };
                field.value.push('\n');
                field.value.push_str(line.trim_end());
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                return error(format!("line {}: not a field (`Name: value`)", number + 1));
            };
            if !valid_field_name(name) {
                return error(format!("line {}: {name:?} is not a field name", number + 1));
            }
            if current.get(name).is_some() {
                return error(format!("field {name} appears twice"));
            }
            current.fields.push(Field {
                name: name.to_string(),
                value: value.trim().to_string(),
            });
        }
        if !current.fields.is_empty() {
            paragraphs.push(current);
        }
        Ok(paragraphs)
    }

    /// The value of field `name` (any case), if present.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(|f| f.value.as_str())
    }

    /// The first line of field `name`, if present and not empty.
    pub fn first_line(&self, name: &str) -> Option<&str> {
        self.get(name)
            .map(|v| v.split('\n').next().unwrap_or(""))
            .filter(|v| !v.is_empty())
    }

    /// Remove field `name` (any case).
    pub fn remove(&mut self, name: &str) {
        self.fields.retain(|f| !f.name.eq_ignore_ascii_case(name));
    }

    /// Set field `name` to a one-line `value`, replacing it where it is or
    /// appending it.
    pub fn set(&mut self, name: &str, value: &str) {
        let value = value.replace(['\n', '\r'], " ");
        match self
            .fields
            .iter_mut()
            .find(|f| f.name.eq_ignore_ascii_case(name))
        {
            Some(field) => field.value = value,
            None => self.fields.push(Field {
                name: name.to_string(),
                value,
            }),
        }
    }

    /// The paragraph as text, each field on its lines, ending in `\n`.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for field in &self.fields {
            let mut lines = field.value.split('\n');
            let first = lines.next().unwrap_or("");
            out.push_str(&field.name);
            out.push(':');
            if !first.is_empty() {
                out.push(' ');
                out.push_str(first);
            }
            out.push('\n');
            for line in lines {
                // Parsed continuation lines start with a space or a tab and
                // are not empty; anything else is written as a continuation.
                if line.trim().is_empty() {
                    out.push_str(" .");
                } else {
                    if !line.starts_with([' ', '\t']) {
                        out.push(' ');
                    }
                    out.push_str(line);
                }
                out.push('\n');
            }
        }
        out
    }
}

/// Whether `name` may name a field: printable ASCII but space and `:`, not
/// starting with `#` or `-`.
fn valid_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with(['#', '-'])
        && name.bytes().all(|b| b.is_ascii_graphic() && b != b':')
}

/// Whether `name` is a binary package name: lowercase letters, digits and
/// `+ - .`, at least two characters, starting with a letter or a digit.
pub fn valid_package_name(name: &str) -> bool {
    name.len() >= 2
        && name.len() <= MAX_NAME_BYTES
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')
        })
}

/// Whether `arch` is a binary package's architecture: `all`, or a Debian
/// architecture name (lowercase letters, digits and `-`). `any` and
/// `source` name none.
pub fn valid_architecture(arch: &str) -> bool {
    !arch.is_empty()
        && arch.len() <= MAX_WORD_BYTES
        && arch != "any"
        && arch != "source"
        && arch.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && arch
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether `component` is a component name (`main`, `non-free-firmware`).
pub fn valid_component(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= MAX_WORD_BYTES
        && component.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && component.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.')
        })
}

/// The component a package's `Section` puts it in: the part before a `/`
/// (`contrib/net` is in `contrib`), else `main`.
pub fn component_of(section: Option<&str>) -> Result<String, ControlError> {
    match section.and_then(|s| s.split_once('/')) {
        Some((component, _)) if valid_component(component) => Ok(component.to_string()),
        Some((component, _)) => error(format!(
            "Section names the component {component:?}, which is not a component name"
        )),
        None => Ok("main".to_string()),
    }
}

/// The relations of a `Depends`-like field: each comma-separated clause,
/// as `(package, version constraint)` of its first alternative, the
/// alternatives kept in the name (`foo | bar`).
pub fn relations(value: &str) -> Vec<(String, Option<String>)> {
    value
        .split(',')
        .map(|clause| clause.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|clause| !clause.is_empty())
        .map(|clause| {
            if clause.contains('|') {
                return (clause, None);
            }
            match clause.split_once('(') {
                Some((name, constraint)) => (
                    name.trim().to_string(),
                    Some(constraint.trim_end_matches(')').trim().to_string())
                        .filter(|c| !c.is_empty()),
                ),
                None => (clause, None),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTROL: &str = "Package: hello\nVersion: 2.10-3\nArchitecture: amd64\n\
        Maintainer: Santiago Vila <sanvila@debian.org>\nInstalled-Size: 280\n\
        Depends: libc6 (>= 2.34)\nSection: devel\nPriority: optional\n\
        Homepage: https://www.gnu.org/software/hello/\n\
        Description: example package based on GNU hello\n The GNU hello program produces a familiar, friendly greeting.\n .\n Seriously.\n";

    #[test]
    fn a_control_file_round_trips() {
        let p = Paragraph::parse_one(CONTROL).unwrap();
        assert_eq!(p.get("package"), Some("hello"));
        assert_eq!(p.get("VERSION"), Some("2.10-3"));
        assert_eq!(
            p.first_line("Description"),
            Some("example package based on GNU hello")
        );
        assert_eq!(p.to_text(), CONTROL);
    }

    #[test]
    fn malformed_control_data_is_refused() {
        for bad in [
            " leading continuation\n",
            "Package hello\n",
            "Package: a\npackage: b\n",
            "Package: a\n\nPackage: b\n",
            "Package: a\x07\n",
            "#Comment: x\n",
            "-Field: x\n",
            ": empty\n",
            "",
        ] {
            assert!(Paragraph::parse_one(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn writing_cannot_inject_lines_or_paragraphs() {
        let mut p = Paragraph::parse_one("Package: a\nDescription: x\n y\n").unwrap();
        p.set("Filename", "pool/x\n\nPackage: evil");
        let text = p.to_text();
        assert_eq!(Paragraph::parse_all(&text).unwrap().len(), 1);
        assert!(text.contains("Filename: pool/x  Package: evil\n"));
        // Continuation lines that are not indented or empty are indented.
        let p = Paragraph {
            fields: vec![Field {
                name: "Description".into(),
                value: "short\nnot indented\n\n end".into(),
            }],
        };
        assert_eq!(p.to_text(), "Description: short\n not indented\n .\n end\n");
    }

    #[test]
    fn crlf_lines_are_read() {
        let p = Paragraph::parse_one("Package: a\r\nVersion: 1\r\n").unwrap();
        assert_eq!(p.get("Version"), Some("1"));
    }

    #[test]
    fn names_are_checked() {
        for good in ["hello", "libc6", "g++", "lib32stdc++6", "0ad", "python3.11"] {
            assert!(valid_package_name(good), "{good}");
        }
        for bad in [
            "a", "Hello", "-x", "+x", "a_b", "a b", "a/b", "a:b", "..", "",
        ] {
            assert!(!valid_package_name(bad), "{bad}");
        }
        for good in ["amd64", "all", "arm64", "hurd-i386", "ppc64el"] {
            assert!(valid_architecture(good), "{good}");
        }
        for bad in ["any", "source", "AMD64", "x/y", "", "-x", "a_b"] {
            assert!(!valid_architecture(bad), "{bad}");
        }
    }

    #[test]
    fn the_section_names_the_component() {
        assert_eq!(component_of(Some("contrib/net")).unwrap(), "contrib");
        assert_eq!(
            component_of(Some("non-free-firmware/kernel")).unwrap(),
            "non-free-firmware"
        );
        assert_eq!(component_of(Some("utils")).unwrap(), "main");
        assert_eq!(component_of(None).unwrap(), "main");
        assert!(component_of(Some("../x/y")).is_err());
        assert!(component_of(Some("Main/x")).is_err());
    }

    #[test]
    fn relations_split_into_clauses() {
        assert_eq!(
            relations("libc6 (>= 2.34), foo | bar,\n  baz"),
            vec![
                ("libc6".into(), Some(">= 2.34".into())),
                ("foo | bar".into(), None),
                ("baz".into(), None),
            ]
        );
    }
}
