//! Repository names and manifest references of the distribution spec.

use crate::digest::{Digest, DigestError};

/// Longest accepted repository name, the whole `<name>` of a `/v2/<name>/…`
/// URL. The spec sets no limit; 255 is what Docker and most registries
/// enforce, and it bounds what reaches the database and upstream URLs.
pub const MAX_NAME_LEN: usize = 255;

/// Whether `name` matches the spec's repository-name grammar:
///
/// ```text
/// [a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*
/// ```
///
/// The grammar admits no `..`, no empty segment, no upper case and nothing
/// that changes meaning in a URL path, so a valid name can be pasted into an
/// upstream URL as is.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_LEN && name.split('/').all(valid_name_component)
}

/// One `/`-separated component of a repository name.
pub fn valid_name_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if bytes.is_empty() || !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        if alnum(bytes[i]) {
            i += 1;
            continue;
        }
        // A separator run: `.`, `_`, `__` or one or more `-`, followed by
        // an alphanumeric (the last byte is alphanumeric, checked above).
        let start = i;
        match bytes[i] {
            b'.' => i += 1,
            b'_' => {
                i += 1;
                if bytes.get(i) == Some(&b'_') {
                    i += 1;
                }
            }
            b'-' => {
                while bytes.get(i) == Some(&b'-') {
                    i += 1;
                }
            }
            _ => return false,
        }
        if i == start || !bytes.get(i).copied().is_some_and(alnum) {
            return false;
        }
    }
    true
}

/// Whether `tag` matches `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`.
pub fn valid_tag(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
        && bytes[1..]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The `<reference>` of a manifest URL: a tag or a digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reference {
    Tag(String),
    Digest(Digest),
}

/// Why a reference was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceError {
    InvalidTag,
    Digest(DigestError),
}

impl Reference {
    /// A digest when the reference contains a `:` (a tag never does),
    /// otherwise a tag.
    pub fn parse(s: &str) -> Result<Self, ReferenceError> {
        if s.contains(':') {
            Digest::parse(s)
                .map(Reference::Digest)
                .map_err(ReferenceError::Digest)
        } else if valid_tag(s) {
            Ok(Reference::Tag(s.to_string()))
        } else {
            Err(ReferenceError::InvalidTag)
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Reference::Tag(t) => t,
            Reference::Digest(d) => d.as_str(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_grammar() {
        for ok in [
            "a",
            "library/nginx",
            "team/app",
            "a.b_c__d-e---f",
            "x/y/z/0",
            "docker-hosted/team/app",
        ] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "/a",
            "a/",
            "a//b",
            "A",
            "a/B",
            "a..b",
            "a___b",
            "-a",
            "a-",
            "a.",
            "a/../b",
            "a/./b",
            "a%2fb",
            "a b",
            "a?b",
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert!(!valid_name(&"a".repeat(MAX_NAME_LEN + 1)));
    }

    #[test]
    fn tag_grammar() {
        for ok in ["latest", "1.0", "_x", "v1.2.3-rc.1", "A_b-C.d"] {
            assert!(valid_tag(ok), "{ok}");
        }
        for bad in ["", ".x", "-x", "a/b", "a:b", "a b"] {
            assert!(!valid_tag(bad), "{bad}");
        }
        assert!(valid_tag(&"a".repeat(128)));
        assert!(!valid_tag(&"a".repeat(129)));
    }

    #[test]
    fn reference_kinds() {
        assert_eq!(
            Reference::parse("latest").unwrap(),
            Reference::Tag("latest".into())
        );
        let d = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(matches!(Reference::parse(d).unwrap(), Reference::Digest(_)));
        assert!(Reference::parse("sha256:zz").is_err());
        assert_eq!(Reference::parse("-bad"), Err(ReferenceError::InvalidTag));
    }
}
