//! Open-redirect guard for the post-login `redirect_to` target (slice 12.2, §6).
//!
//! After login we 302 the browser to a caller-supplied path. To prevent an
//! **open redirect** (`?redirect_to=https://evil.example`), we only ever honor a
//! **same-origin relative path**: it must begin with a single `/` and not with
//! `//` (protocol-relative), carry no scheme/authority, and contain no control
//! characters or backslashes (which some browsers normalise to `/`). Anything
//! else collapses to the safe default `/`.

/// The safe fallback target when no (or an unsafe) `redirect_to` is supplied.
const DEFAULT_TARGET: &str = "/";

/// Longest accepted `redirect_to` (bytes). It is stored in the flow row, so
/// an unbounded value would let anyone grow the table cheaply.
pub const MAX_REDIRECT_TO_BYTES: usize = 2048;

/// Sanitize a requested post-login target into a safe same-origin relative path.
///
/// Returns [`DEFAULT_TARGET`] (`/`) unless `raw` is a clean relative path:
/// * starts with exactly one `/` (not `//`, not `/\`),
/// * has no scheme/authority (no `://`, no leading scheme like `javascript:`),
/// * has no backslashes, whitespace, or ASCII control characters.
pub fn sanitize_redirect_to(raw: Option<&str>) -> String {
    let Some(candidate) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return DEFAULT_TARGET.to_string();
    };

    if candidate.len() > MAX_REDIRECT_TO_BYTES {
        return DEFAULT_TARGET.to_string();
    }
    // Must be an absolute path on this origin.
    if !candidate.starts_with('/') {
        return DEFAULT_TARGET.to_string();
    }
    // Reject protocol-relative `//host` and the `/\` browser-normalisation trick.
    let second = candidate.as_bytes().get(1).copied();
    if second == Some(b'/') || second == Some(b'\\') {
        return DEFAULT_TARGET.to_string();
    }
    // Reject anything with a backslash, control char, or whitespace anywhere —
    // these are the usual smuggling vectors for a bypass.
    if candidate
        .chars()
        .any(|c| c == '\\' || c.is_control() || c.is_whitespace())
    {
        return DEFAULT_TARGET.to_string();
    }
    // Belt-and-suspenders: no scheme separator may appear.
    if candidate.contains("://") {
        return DEFAULT_TARGET.to_string();
    }

    candidate.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_targets_default_to_root() {
        let long = format!("/{}", "a".repeat(MAX_REDIRECT_TO_BYTES));
        assert_eq!(sanitize_redirect_to(Some(&long)), "/");
        let fits = format!("/{}", "a".repeat(MAX_REDIRECT_TO_BYTES - 1));
        assert_eq!(sanitize_redirect_to(Some(&fits)), fits);
    }

    #[test]
    fn none_and_empty_default_to_root() {
        assert_eq!(sanitize_redirect_to(None), "/");
        assert_eq!(sanitize_redirect_to(Some("")), "/");
        assert_eq!(sanitize_redirect_to(Some("   ")), "/");
    }

    #[test]
    fn clean_relative_paths_pass_through() {
        assert_eq!(sanitize_redirect_to(Some("/")), "/");
        assert_eq!(sanitize_redirect_to(Some("/browse")), "/browse");
        assert_eq!(
            sanitize_redirect_to(Some("/admin/repositories?tab=2")),
            "/admin/repositories?tab=2"
        );
        // The admin UI's own paths (`/manage/*`) are ordinary same-origin
        // targets; a legacy `/admin/...` UI target is passed through and then
        // 302-redirected to `/manage/...` by `web_ui::legacy_admin_ui_redirect`.
        assert_eq!(
            sanitize_redirect_to(Some("/manage/repositories/feed?tab=2")),
            "/manage/repositories/feed?tab=2"
        );
        assert_eq!(
            sanitize_redirect_to(Some("/p/Newtonsoft.Json#top")),
            "/p/Newtonsoft.Json#top"
        );
    }

    #[test]
    fn absolute_urls_are_rejected() {
        assert_eq!(sanitize_redirect_to(Some("https://evil.example")), "/");
        assert_eq!(sanitize_redirect_to(Some("http://evil")), "/");
        assert_eq!(sanitize_redirect_to(Some("javascript:alert(1)")), "/");
    }

    #[test]
    fn protocol_relative_and_backslash_tricks_rejected() {
        assert_eq!(sanitize_redirect_to(Some("//evil.example")), "/");
        assert_eq!(sanitize_redirect_to(Some("/\\evil.example")), "/");
        assert_eq!(sanitize_redirect_to(Some("/path\\to")), "/");
    }

    #[test]
    fn non_absolute_paths_rejected() {
        assert_eq!(sanitize_redirect_to(Some("browse")), "/");
        assert_eq!(sanitize_redirect_to(Some("../etc")), "/");
    }

    #[test]
    fn interior_control_and_whitespace_rejected() {
        assert_eq!(sanitize_redirect_to(Some("/foo\nbar")), "/");
        assert_eq!(sanitize_redirect_to(Some("/foo bar")), "/");
        assert_eq!(sanitize_redirect_to(Some("/foo\tbar")), "/");
        assert_eq!(sanitize_redirect_to(Some("/foo\rbar")), "/");
    }

    #[test]
    fn trailing_whitespace_is_trimmed_not_rejected() {
        // Leading/trailing whitespace is trimmed up front; a clean path remains.
        assert_eq!(sanitize_redirect_to(Some("  /browse  ")), "/browse");
        assert_eq!(sanitize_redirect_to(Some("/browse\n")), "/browse");
    }
}
