//! Paths in files repositories: what a request names, and how a file is
//! stored.
//!
//! A stored path is a list of segments joined by `/`, without a leading or
//! trailing `/`: `pdfium/7350/pdfium-linux-x64.tgz`. A directory is `""` (the
//! root) or a path ending in `/`. A request names a path percent-encoded, and
//! is refused when any decoded segment is empty (`//`), `.` or `..` (also
//! spelled `%2e%2e`), holds a `/` (`%2F`), a backslash or a control
//! character, or the path is too long. Nothing is collapsed or resolved: a
//! path that needs normalizing is refused, so there is exactly one spelling
//! of every stored path.
//!
//! The host refuses every path a plugin names that breaks these rules
//! ([`validate_path`], [`validate_directory`]); a plugin parses its requests
//! with [`parse_request`] to refuse them with the reason.

use std::fmt;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    EmptySegment,
    DotSegment,
    Backslash,
    EncodedSlash,
    Control,
    Encoding,
    TooLong,
    SegmentTooLong,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathError::EmptySegment => "invalid path: empty segment (`//`)",
            PathError::DotSegment => "invalid path: `.` and `..` segments are not allowed",
            PathError::Backslash => "invalid path: backslashes are not allowed",
            PathError::EncodedSlash => {
                "invalid path: an encoded `/` (%2F) is not allowed in a segment"
            }
            PathError::Control => "invalid path: control characters are not allowed",
            PathError::Encoding => "invalid path: not valid percent-encoded UTF-8",
            PathError::TooLong => "invalid path: longer than 1024 bytes",
            PathError::SegmentTooLong => "invalid path: a segment is longer than 255 bytes",
        })
    }
}

impl std::error::Error for PathError {}

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

/// Check a stored file path: segments joined by `/`, no leading or trailing
/// `/`.
pub fn validate_path(path: &str) -> Result<(), PathError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    path.split('/').try_for_each(validate_segment)
}

/// Check a directory: `""`, or a file path followed by `/`.
pub fn validate_directory(directory: &str) -> Result<(), PathError> {
    if directory.is_empty() {
        return Ok(());
    }
    match directory.strip_suffix('/') {
        Some(path) if directory.len() <= MAX_PATH_BYTES => validate_path(path),
        Some(_) => Err(PathError::TooLong),
        None => Err(PathError::EmptySegment),
    }
}

/// `%XX`-decode a segment: an escape of two hex digits is decoded, a `%`
/// before anything else stays as it is.
fn decode_segment(segment: &str) -> Result<String, PathError> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'%')
            .then(|| segment.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| PathError::Encoding)
}

/// Parse a percent-encoded request path below a repository (without its
/// leading `/`): empty or ending in `/` names a directory, anything else a
/// file.
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
        let decoded = decode_segment(raw)?;
        validate_segment(&decoded)?;
        segments.push(decoded);
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

/// Normalize a path given unencoded (an upload's file name, a directory form
/// field, an admin API parameter): segments separated by `/`, leading and
/// trailing `/` ignored. Empty yields `""`.
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

/// Whether `byte` is percent-encoded in a URL path segment: everything but
/// the unreserved characters and the sub-delimiters, `:` and `@` that a
/// segment may carry as they are.
fn encoded_in_segment(byte: u8) -> bool {
    !(0x20..0x7f).contains(&byte) || b" \"#%/<>?[\\]^`{|}".contains(&byte)
}

/// `path` percent-encoded for a URL, segment by segment (a trailing `/`
/// kept).
pub fn encode(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (i, segment) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        for &byte in segment.as_bytes() {
            if encoded_in_segment(byte) {
                out.push_str(&format!("%{byte:02X}"));
            } else {
                out.push(char::from(byte));
            }
        }
    }
    out
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
        // A `%` without two hex digits is a `%`.
        assert_eq!(parse_request("a%zzb"), Ok(Target::File("a%zzb".into())));
        assert_eq!(parse_request("a%2"), Ok(Target::File("a%2".into())));
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
    fn stored_paths_and_directories_are_checked() {
        assert_eq!(validate_path("a/b.txt"), Ok(()));
        assert_eq!(validate_path(""), Err(PathError::EmptySegment));
        assert_eq!(validate_path("/a"), Err(PathError::EmptySegment));
        assert_eq!(validate_path("a/"), Err(PathError::EmptySegment));
        assert_eq!(validate_path("a/../b"), Err(PathError::DotSegment));
        assert_eq!(validate_path(&"a/".repeat(600)), Err(PathError::TooLong));
        assert_eq!(validate_directory(""), Ok(()));
        assert_eq!(validate_directory("a/b/"), Ok(()));
        assert_eq!(validate_directory("a/b"), Err(PathError::EmptySegment));
        assert_eq!(validate_directory("/"), Err(PathError::EmptySegment));
        assert_eq!(validate_directory("a//"), Err(PathError::EmptySegment));
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
        assert_eq!(encode("ä"), "%C3%A4");
        assert_eq!(encode("a:b@c!$&'()*+,;=-._~"), "a:b@c!$&'()*+,;=-._~");
        assert_eq!(file_name("a/b/c.txt"), "c.txt");
        assert_eq!(file_name("a/b/"), "b");
        assert_eq!(file_name("c.txt"), "c.txt");
        assert_eq!(parent("a/b/c.txt"), "a/b/");
        assert_eq!(parent("a/b/"), "a/");
        assert_eq!(parent("c.txt"), "");
    }
}
