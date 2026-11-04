//! Control data: the deb822 paragraphs of a package's `control` file and of
//! the `Packages` indexes (Debian Policy 5.1), and the names they hold.
//!
//! A paragraph is a list of fields, `Name: value`, each value continuing on
//! the following lines that start with a space or a tab. Field names are
//! compared without regard to case and appear once. A paragraph is parsed
//! strictly and written back in one canonical spelling, so that what a
//! package's control file says cannot add lines (or paragraphs) to an index.

use std::collections::HashSet;
use std::fmt;

/// The longest control file read from a package, in bytes.
pub const MAX_CONTROL_BYTES: usize = 1024 * 1024;

/// The most fields a paragraph may hold. Real paragraphs hold a few dozen:
/// a binary package's control file has the 20-odd fields of Debian Policy
/// 5.3 and a handful of `X-`/`XB-` ones, an index's `Packages` paragraph
/// adds its 5 or so, and a `Release` holds about 20. Ten times that leaves
/// room for any tool's extra fields and bounds what a paragraph costs to
/// read and to index.
pub const MAX_FIELDS: usize = 256;

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
        // The names of `current`'s fields, ASCII-lowercased: each duplicate
        // check takes constant time.
        let mut names = HashSet::new();
        for (number, line) in text.split('\n').enumerate() {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.chars().any(|c| c.is_control() && c != '\t') {
                return error(format!("line {}: control characters", number + 1));
            }
            if line.trim().is_empty() {
                if !current.fields.is_empty() {
                    paragraphs.push(std::mem::take(&mut current));
                    names.clear();
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
            if !names.insert(name.to_ascii_lowercase()) {
                return error(format!("field {name} appears twice"));
            }
            if current.fields.len() == MAX_FIELDS {
                return error(format!(
                    "line {}: a paragraph holds more than {MAX_FIELDS} fields",
                    number + 1
                ));
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

/// The architectures dpkg knows, sorted: what `dpkg-architecture -L` lists
/// (dpkg 1.22.6, from its `cputable`, `ostable` and `tupletable`). A hosted
/// repository takes packages of these and of `all` alone
/// ([`known_architecture`]): each architecture adds its indexes to every
/// component's, so a writer must not add them at will (#761).
pub const ARCHITECTURES: &[&str] = &[
    "aix-powerpc",
    "aix-ppc64",
    "alpha",
    "amd64",
    "arc",
    "arm",
    "arm64",
    "armeb",
    "armel",
    "armhf",
    "darwin-amd64",
    "darwin-arm",
    "darwin-arm64",
    "darwin-i386",
    "darwin-powerpc",
    "darwin-ppc64",
    "dragonflybsd-amd64",
    "freebsd-amd64",
    "freebsd-arm",
    "freebsd-arm64",
    "freebsd-i386",
    "freebsd-powerpc",
    "freebsd-ppc64",
    "hppa",
    "hurd-amd64",
    "hurd-i386",
    "i386",
    "ia64",
    "kfreebsd-amd64",
    "kfreebsd-i386",
    "kopensolaris-amd64",
    "kopensolaris-i386",
    "loong64",
    "m68k",
    "mint-m68k",
    "mips",
    "mips64",
    "mips64el",
    "mips64r6",
    "mips64r6el",
    "mipsel",
    "mipsn32",
    "mipsn32el",
    "mipsn32r6",
    "mipsn32r6el",
    "mipsr6",
    "mipsr6el",
    "musl-linux-alpha",
    "musl-linux-amd64",
    "musl-linux-arc",
    "musl-linux-arm",
    "musl-linux-arm64",
    "musl-linux-armeb",
    "musl-linux-armhf",
    "musl-linux-hppa",
    "musl-linux-i386",
    "musl-linux-ia64",
    "musl-linux-loong64",
    "musl-linux-m68k",
    "musl-linux-mips",
    "musl-linux-mips64",
    "musl-linux-mips64el",
    "musl-linux-mips64r6",
    "musl-linux-mips64r6el",
    "musl-linux-mipsel",
    "musl-linux-mipsr6",
    "musl-linux-mipsr6el",
    "musl-linux-nios2",
    "musl-linux-or1k",
    "musl-linux-powerpc",
    "musl-linux-powerpcel",
    "musl-linux-ppc64",
    "musl-linux-ppc64el",
    "musl-linux-riscv64",
    "musl-linux-s390",
    "musl-linux-s390x",
    "musl-linux-sh3",
    "musl-linux-sh3eb",
    "musl-linux-sh4",
    "musl-linux-sh4eb",
    "musl-linux-sparc",
    "musl-linux-sparc64",
    "netbsd-alpha",
    "netbsd-amd64",
    "netbsd-arc",
    "netbsd-arm",
    "netbsd-arm64",
    "netbsd-armeb",
    "netbsd-hppa",
    "netbsd-i386",
    "netbsd-ia64",
    "netbsd-loong64",
    "netbsd-m68k",
    "netbsd-mips",
    "netbsd-mips64",
    "netbsd-mips64el",
    "netbsd-mips64r6",
    "netbsd-mips64r6el",
    "netbsd-mipsel",
    "netbsd-mipsr6",
    "netbsd-mipsr6el",
    "netbsd-nios2",
    "netbsd-or1k",
    "netbsd-powerpc",
    "netbsd-powerpcel",
    "netbsd-ppc64",
    "netbsd-ppc64el",
    "netbsd-riscv64",
    "netbsd-s390",
    "netbsd-s390x",
    "netbsd-sh3",
    "netbsd-sh3eb",
    "netbsd-sh4",
    "netbsd-sh4eb",
    "netbsd-sparc",
    "netbsd-sparc64",
    "nios2",
    "openbsd-alpha",
    "openbsd-amd64",
    "openbsd-arc",
    "openbsd-arm",
    "openbsd-arm64",
    "openbsd-armeb",
    "openbsd-hppa",
    "openbsd-i386",
    "openbsd-ia64",
    "openbsd-loong64",
    "openbsd-m68k",
    "openbsd-mips",
    "openbsd-mips64",
    "openbsd-mips64el",
    "openbsd-mips64r6",
    "openbsd-mips64r6el",
    "openbsd-mipsel",
    "openbsd-mipsr6",
    "openbsd-mipsr6el",
    "openbsd-nios2",
    "openbsd-or1k",
    "openbsd-powerpc",
    "openbsd-powerpcel",
    "openbsd-ppc64",
    "openbsd-ppc64el",
    "openbsd-riscv64",
    "openbsd-s390",
    "openbsd-s390x",
    "openbsd-sh3",
    "openbsd-sh3eb",
    "openbsd-sh4",
    "openbsd-sh4eb",
    "openbsd-sparc",
    "openbsd-sparc64",
    "or1k",
    "powerpc",
    "powerpcel",
    "powerpcspe",
    "ppc64",
    "ppc64el",
    "riscv64",
    "s390",
    "s390x",
    "sh3",
    "sh3eb",
    "sh4",
    "sh4eb",
    "solaris-amd64",
    "solaris-i386",
    "solaris-sparc",
    "solaris-sparc64",
    "sparc",
    "sparc64",
    "uclibc-linux-alpha",
    "uclibc-linux-amd64",
    "uclibc-linux-arc",
    "uclibc-linux-arm",
    "uclibc-linux-arm64",
    "uclibc-linux-armeb",
    "uclibc-linux-armel",
    "uclibc-linux-hppa",
    "uclibc-linux-i386",
    "uclibc-linux-ia64",
    "uclibc-linux-loong64",
    "uclibc-linux-m68k",
    "uclibc-linux-mips",
    "uclibc-linux-mips64",
    "uclibc-linux-mips64el",
    "uclibc-linux-mips64r6",
    "uclibc-linux-mips64r6el",
    "uclibc-linux-mipsel",
    "uclibc-linux-mipsr6",
    "uclibc-linux-mipsr6el",
    "uclibc-linux-nios2",
    "uclibc-linux-or1k",
    "uclibc-linux-powerpc",
    "uclibc-linux-powerpcel",
    "uclibc-linux-ppc64",
    "uclibc-linux-ppc64el",
    "uclibc-linux-riscv64",
    "uclibc-linux-s390",
    "uclibc-linux-s390x",
    "uclibc-linux-sh3",
    "uclibc-linux-sh3eb",
    "uclibc-linux-sh4",
    "uclibc-linux-sh4eb",
    "uclibc-linux-sparc",
    "uclibc-linux-sparc64",
    "x32",
];

/// The most components a hosted repository holds. Each adds the indexes of
/// every architecture: with all of [`ARCHITECTURES`] and `all`, 8
/// components make 8 × 207 `Packages` lists of 6 files each (the list, its
/// two compressions, and a by-hash copy of each), 9,936 files, below the
/// host's 10,000 an index may hold (#761). Debian and Ubuntu publish 4.
pub const MAX_COMPONENTS: usize = 8;

/// Whether `arch` is an architecture a package may be built for: `all`, or
/// one of dpkg's [`ARCHITECTURES`]. A package's control file and an
/// import are checked against it; [`valid_architecture`] is the name's
/// syntax, which paths and ids are read with.
pub fn known_architecture(arch: &str) -> bool {
    arch == "all" || ARCHITECTURES.binary_search(&arch).is_ok()
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

    /// A paragraph of `n` distinct fields, `F0: x` to `F{n-1}: x`.
    fn fields(n: usize) -> String {
        (0..n).map(|i| format!("F{i}: x\n")).collect()
    }

    #[test]
    fn a_duplicate_field_is_refused_in_any_case() {
        for bad in [
            "Package: a\nPACKAGE: b\n",
            "Package: a\nVersion: 1\npackage: b\n",
            "X-Custom: a\nx-cUSTOM: b\n",
        ] {
            let err = Paragraph::parse_one(bad).unwrap_err().to_string();
            assert!(err.contains("appears twice"), "{bad:?}: {err}");
        }
        // The same field may appear once in each paragraph.
        let all = Paragraph::parse_all("Package: a\n\npackage: b\n").unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].get("Package"), Some("b"));
    }

    #[test]
    fn a_paragraph_holds_at_most_max_fields() {
        let p = Paragraph::parse_one(&fields(MAX_FIELDS)).unwrap();
        assert_eq!(p.fields.len(), MAX_FIELDS);
        let err = Paragraph::parse_one(&fields(MAX_FIELDS + 1)).unwrap_err();
        assert!(err.to_string().contains("more than 256 fields"), "{err}");
        // The bound is per paragraph: an index holds many.
        let index = [fields(MAX_FIELDS), fields(MAX_FIELDS)].join("\n");
        assert_eq!(Paragraph::parse_all(&index).unwrap().len(), 2);
    }

    #[test]
    fn a_control_file_of_many_fields_is_refused_quickly() {
        // A whole control file (1 MiB) of distinct short fields: about
        // 100,000 of them, which took ~20 s when each field was compared
        // with every earlier one.
        let mut text = String::new();
        let mut i = 0;
        while text.len() < MAX_CONTROL_BYTES - 16 {
            text.push_str(&format!("a{i}:\n"));
            i += 1;
        }
        let start = std::time::Instant::now();
        let err = Paragraph::parse_one(&text).unwrap_err();
        let elapsed = start.elapsed();
        assert!(err.to_string().contains("more than"), "{err}");
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "{elapsed:?}"
        );
        // Distinct fields spread over paragraphs under the bound are read
        // in linear time too.
        let mut text = String::new();
        while text.len() < MAX_CONTROL_BYTES - 8192 {
            text.push_str(&fields(MAX_FIELDS));
            text.push('\n');
        }
        let start = std::time::Instant::now();
        let all = Paragraph::parse_all(&text).unwrap();
        let elapsed = start.elapsed();
        assert!(all.len() > 100);
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn a_release_parses() {
        let release = "Origin: Debian\nLabel: Debian\nSuite: stable\nVersion: 12.7\n\
            Codename: bookworm\nChangelogs: https://metadata.ftp-master.debian.org/changelogs/@CHANGEPATH@_changelog\n\
            Date: Sat, 31 Aug 2024 10:49:36 UTC\nAcquire-By-Hash: yes\n\
            No-Support-for-Architecture-all: Packages\nArchitectures: all amd64 arm64\n\
            Components: main contrib non-free-firmware non-free\n\
            Description: Debian 12.7 Released 31 August 2024\n\
            MD5Sum:\n 0ed6d4c8891eb86358b94bb35d9e4da4  1484322 contrib/Contents-all\n\
            SHA256:\n 6eb3b4e2a8a0f1ce5c6a7a8b0c0b7f6e4a4e1c1d2b2c3d4e5f60718293a4b5c6  1484322 contrib/Contents-all\n";
        let p = Paragraph::parse_one(release).unwrap();
        assert_eq!(p.get("Codename"), Some("bookworm"));
        assert_eq!(p.fields.len(), 14);
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
    fn architectures_are_dpkgs() {
        assert!(
            ARCHITECTURES.windows(2).all(|w| w[0] < w[1]),
            "ARCHITECTURES is sorted, without duplicates"
        );
        assert!(ARCHITECTURES.iter().all(|a| valid_architecture(a)));
        for known in [
            "all",
            "amd64",
            "arm64",
            "armhf",
            "i386",
            "ppc64el",
            "riscv64",
            "s390x",
            "hurd-i386",
            "musl-linux-amd64",
            "x32",
            "loong64",
        ] {
            assert!(known_architecture(known), "{known}");
        }
        // Syntactically architecture names, but not dpkg's (#761).
        for unknown in [
            "a1",
            "foo",
            "amd65",
            "linux-amd64",
            "any",
            "source",
            "",
            "AMD64",
        ] {
            assert!(!known_architecture(unknown), "{unknown}");
        }
    }

    #[test]
    fn the_worst_case_index_fits_the_hosts_limit() {
        // Every component of every architecture and `all`: 6 files each,
        // plus Release, InRelease, Release.gpg, key.asc and key.gpg. The
        // host refuses an index of more than 10,000 files.
        let files = MAX_COMPONENTS * (ARCHITECTURES.len() + 1) * 6 + 5;
        assert!(files <= 10_000, "{files}");
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
