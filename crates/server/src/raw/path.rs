//! Paths in raw repositories: what a request names, and how it is stored.
//!
//! A stored path is a list of segments joined by `/`, without a leading or
//! trailing `/`: `pdfium/7350/pdfium-linux-x64.tgz`. A request names it
//! percent-encoded after `/raw/<repo>/`, and is refused when any decoded
//! segment is empty (`//`), `.` or `..` (also spelled `%2e%2e`), holds a `/`
//! (`%2F`), a backslash or a control character, or the path is too long.
//! Nothing is collapsed or resolved: a path that needs normalizing is
//! refused, so there is exactly one spelling of every stored path.

use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};

/// Longest stored path, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;

/// Longest path segment, in bytes.
pub const MAX_SEGMENT_BYTES: usize = 255;

/// What a request path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A directory: `""` (the root) or a path ending in `/`.
    Directory(String),
    /// A file.
    File(String),
}

/// Why a path is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("invalid path: empty segment (`//`)")]
    EmptySegment,
    #[error("invalid path: `.` and `..` segments are not allowed")]
    DotSegment,
    #[error("invalid path: backslashes are not allowed")]
    Backslash,
    #[error("invalid path: an encoded `/` (%2F) is not allowed in a segment")]
    EncodedSlash,
    #[error("invalid path: control characters are not allowed")]
    Control,
    #[error("invalid path: not valid percent-encoded UTF-8")]
    Encoding,
    #[error("invalid path: longer than {MAX_PATH_BYTES} bytes")]
    TooLong,
    #[error("invalid path: a segment is longer than {MAX_SEGMENT_BYTES} bytes")]
    SegmentTooLong,
}

/// Check one decoded segment.
pub fn validate_segment(segment: &str) -> Result<(), PathError> {
    if segment.is_empty() {
        return Err(PathError::EmptySegment);
    }
    if segment == "." || segment == ".." {
        return Err(PathError::DotSegment);
    }
    if segment.contains('/') {
        return Err(PathError::EncodedSlash);
    }
    if segment.contains('\\') {
        return Err(PathError::Backslash);
    }
    if segment.chars().any(char::is_control) {
        return Err(PathError::Control);
    }
    if segment.len() > MAX_SEGMENT_BYTES {
        return Err(PathError::SegmentTooLong);
    }
    Ok(())
}

/// Parse the percent-encoded rest of a request path (what follows
/// `/raw/<repo>/`): empty or ending in `/` names a directory, anything else
/// a file.
pub fn parse_request(encoded: &str) -> Result<Target, PathError> {
    if encoded.is_empty() {
        return Ok(Target::Directory(String::new()));
    }
    let (body, directory) = match encoded.strip_suffix('/') {
        Some(body) => (body, true),
        None => (encoded, false),
    };
    let mut segments = Vec::new();
    for raw in body.split('/') {
        if raw.contains('\\') {
            return Err(PathError::Backslash);
        }
        let decoded = percent_decode_str(raw)
            .decode_utf8()
            .map_err(|_| PathError::Encoding)?;
        validate_segment(&decoded)?;
        segments.push(decoded.into_owned());
    }
    let path = segments.join("/");
    if path.len() + usize::from(directory) > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    Ok(if directory {
        Target::Directory(format!("{path}/"))
    } else {
        Target::File(path)
    })
}

/// Normalize a path given unencoded (an upload's file name, a `directory`
/// form field, an admin API parameter): segments separated by `/`, leading
/// and trailing `/` ignored. Empty yields `""`.
pub fn normalize(raw: &str) -> Result<String, PathError> {
    let trimmed = raw.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    for segment in trimmed.split('/') {
        validate_segment(segment)?;
    }
    if trimmed.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    Ok(trimmed.to_string())
}

/// A normalized directory (`""`, or ending in `/`) from an unencoded
/// directory name.
pub fn normalize_directory(raw: &str) -> Result<String, PathError> {
    let dir = normalize(raw)?;
    Ok(if dir.is_empty() {
        dir
    } else {
        format!("{dir}/")
    })
}

/// `directory` (normalized, `""` or ending in `/`) joined with `name` (a
/// relative path, normalized).
pub fn join(directory: &str, name: &str) -> Result<String, PathError> {
    let name = normalize(name)?;
    if name.is_empty() {
        return Err(PathError::EmptySegment);
    }
    let path = format!("{directory}{name}");
    if path.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    Ok(path)
}

/// Characters percent-encoded in a URL path segment: everything but the
/// unreserved characters and the sub-delimiters, `:` and `@` that a
/// segment may carry as they are.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// `path` percent-encoded for a URL, segment by segment (a trailing `/`
/// kept).
pub fn encode(path: &str) -> String {
    path.split('/')
        .map(|segment| utf8_percent_encode(segment, SEGMENT).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// The last segment of a path (a directory's without its `/`).
pub fn file_name(path: &str) -> &str {
    let path = path.strip_suffix('/').unwrap_or(path);
    path.rsplit('/').next().unwrap_or(path)
}

/// The directory a file is in (`""` for the root, else ending in `/`).
pub fn parent(path: &str) -> &str {
    let path = path.strip_suffix('/').unwrap_or(path);
    match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_name_files_and_directories() {
        assert_eq!(parse_request(""), Ok(Target::Directory(String::new())));
        assert_eq!(
            parse_request("pdfium/7350/"),
            Ok(Target::Directory("pdfium/7350/".into()))
        );
        assert_eq!(
            parse_request("pdfium/7350/pdfium-linux-x64.tgz"),
            Ok(Target::File("pdfium/7350/pdfium-linux-x64.tgz".into()))
        );
        // Encoded characters are decoded once.
        assert_eq!(
            parse_request("a%20b/c%25d.txt"),
            Ok(Target::File("a b/c%d.txt".into()))
        );
        assert_eq!(parse_request("%C3%A4/x"), Ok(Target::File("ä/x".into())));
        assert_eq!(parse_request("..."), Ok(Target::File("...".into())));
        assert_eq!(parse_request(".hidden"), Ok(Target::File(".hidden".into())));
    }

    #[test]
    fn traversal_and_ambiguous_spellings_are_refused() {
        for (path, error) in [
            ("..", PathError::DotSegment),
            ("../etc/passwd", PathError::DotSegment),
            ("a/../b", PathError::DotSegment),
            ("a/./b", PathError::DotSegment),
            ("./a", PathError::DotSegment),
            ("a/..", PathError::DotSegment),
            ("a/../", PathError::DotSegment),
            ("%2e%2e/x", PathError::DotSegment),
            ("%2E%2E/x", PathError::DotSegment),
            ("a/%2e%2e/b", PathError::DotSegment),
            ("a/%2e/b", PathError::DotSegment),
            (".%2e/x", PathError::DotSegment),
            ("a//b", PathError::EmptySegment),
            ("//a", PathError::EmptySegment),
            ("/", PathError::EmptySegment),
            ("a//", PathError::EmptySegment),
            ("a\\b", PathError::Backslash),
            ("a%5cb", PathError::Backslash),
            ("..%5cx", PathError::Backslash),
            ("a%2fb", PathError::EncodedSlash),
            ("%2e%2e%2fx", PathError::EncodedSlash),
            ("a%00b", PathError::Control),
            ("a%0Ab", PathError::Control),
            ("a%ffb", PathError::Encoding),
        ] {
            assert_eq!(parse_request(path), Err(error), "{path}");
        }
        let long = format!("{}/x", "a".repeat(MAX_SEGMENT_BYTES + 1));
        assert_eq!(parse_request(&long), Err(PathError::SegmentTooLong));
        let deep = vec!["abcdefgh"; 200].join("/");
        assert_eq!(parse_request(&deep), Err(PathError::TooLong));
    }

    #[test]
    fn unencoded_names_normalize_their_slashes_only() {
        assert_eq!(normalize("/pdfium/7350/"), Ok("pdfium/7350".into()));
        assert_eq!(normalize(""), Ok(String::new()));
        assert_eq!(normalize("/"), Ok(String::new()));
        assert_eq!(normalize("a//b"), Err(PathError::EmptySegment));
        assert_eq!(normalize("a/../b"), Err(PathError::DotSegment));
        assert_eq!(normalize("C:\\fakepath\\x.txt"), Err(PathError::Backslash));
        // Percent signs are literal here.
        assert_eq!(normalize("a%2e%2e"), Ok("a%2e%2e".into()));
        assert_eq!(normalize_directory("x/y"), Ok("x/y/".into()));
        assert_eq!(normalize_directory(""), Ok(String::new()));
        assert_eq!(join("x/", "sub/f.bin"), Ok("x/sub/f.bin".into()));
        assert_eq!(join("", "f.bin"), Ok("f.bin".into()));
        assert_eq!(join("x/", ""), Err(PathError::EmptySegment));
        assert_eq!(join("x/", ".."), Err(PathError::DotSegment));
    }

    #[test]
    fn encoding_round_trips() {
        for path in [
            "a b/c%d.txt",
            "ä/x",
            "a?b#c/[x]",
            "pdfium/7350/x.tgz",
            "dir/",
        ] {
            let encoded = encode(path);
            let expected = if path.ends_with('/') {
                Target::Directory(path.to_string())
            } else {
                Target::File(path.to_string())
            };
            assert_eq!(parse_request(&encoded), Ok(expected), "{encoded}");
        }
        assert_eq!(encode("a b/x?.txt"), "a%20b/x%3F.txt");
        assert_eq!(file_name("a/b/c.txt"), "c.txt");
        assert_eq!(file_name("a/b/"), "b");
        assert_eq!(file_name("c.txt"), "c.txt");
        assert_eq!(parent("a/b/c.txt"), "a/b/");
        assert_eq!(parent("a/b/"), "a/");
        assert_eq!(parent("c.txt"), "");
    }
}
