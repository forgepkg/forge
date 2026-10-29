//! Checksum sidecars: `<file>.sha256`, `.sha512`, `.sha1` and `.md5`,
//! answered from a stored file's digests when no file of that name is
//! stored, as Nexus does. The body is the digest and the file name, as
//! `sha256sum` and friends print them, so `sha256sum -c` checks a download
//! against it.

use base64::Engine as _;
use forge_plugin_api::files;
use forge_plugin_api::{FileInfo, Repository, Request, Response};

use crate::listing::http_date;

/// Which digest a sidecar holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    Sha256,
    Sha512,
    Sha1,
    Md5,
}

impl Checksum {
    const ALL: [Checksum; 4] = [
        Checksum::Sha256,
        Checksum::Sha512,
        Checksum::Sha1,
        Checksum::Md5,
    ];

    fn extension(self) -> &'static str {
        match self {
            Checksum::Sha256 => ".sha256",
            Checksum::Sha512 => ".sha512",
            Checksum::Sha1 => ".sha1",
            Checksum::Md5 => ".md5",
        }
    }

    /// The digest of `file` as lowercase hex.
    pub fn hex(self, file: &FileInfo) -> String {
        match self {
            Checksum::Sha256 => file.sha256.clone(),
            Checksum::Sha512 => base64::engine::general_purpose::STANDARD
                .decode(&file.sha512)
                .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect())
                .unwrap_or_default(),
            Checksum::Sha1 => file.sha1.clone(),
            Checksum::Md5 => file.md5.clone(),
        }
    }
}

/// The file a sidecar path is the checksum of, and which checksum.
pub fn of(path: &str) -> Option<(&str, Checksum)> {
    Checksum::ALL.into_iter().find_map(|checksum| {
        let base = path.strip_suffix(checksum.extension())?;
        (!base.is_empty() && !base.ends_with('/')).then_some((base, checksum))
    })
}

/// Whether the request's preconditions say the client's copy is current
/// (`If-None-Match`, else `If-Modified-Since`): answer 304. `modified` is in
/// seconds since the epoch.
pub fn not_modified(req: &Request, etag: &str, modified: Option<u64>) -> bool {
    if let Some(value) = req.header("if-none-match") {
        // Weak comparison: `W/"x"` matches `"x"`.
        return value
            .split(',')
            .map(str::trim)
            .any(|tag| tag == "*" || tag.strip_prefix("W/").unwrap_or(tag) == etag);
    }
    let since = req
        .header("if-modified-since")
        .and_then(|v| httpdate::parse_http_date(v).ok());
    match (since, modified) {
        (Some(since), Some(modified)) => {
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(modified) <= since
        }
        _ => false,
    }
}

/// `Content-Disposition` of `file_path` in `repo`: a download
/// (`attachment`), or with the repository's `inline` option for display,
/// naming the file.
pub fn content_disposition(repo: &Repository, file_path: &str) -> String {
    let kind = if repo.inline { "inline" } else { "attachment" };
    let name = files::file_name(file_path);
    let plain = |c: char| c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\';
    if name.chars().all(plain) {
        format!("{kind}; filename=\"{name}\"")
    } else {
        // RFC 6266: an ASCII fallback, and the UTF-8 name.
        let fallback: String = name
            .chars()
            .map(|c| if plain(c) { c } else { '_' })
            .collect();
        format!(
            "{kind}; filename=\"{fallback}\"; filename*=UTF-8''{}",
            percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC)
        )
    }
}

/// Answer `GET`/`HEAD` of `path`, the `checksum` sidecar of `base`.
pub fn respond(
    repo: &Repository,
    req: &Request,
    path: &str,
    base: &FileInfo,
    checksum: Checksum,
) -> Response {
    let etag = format!(
        "\"{}{}\"",
        base.sha256,
        checksum.extension().replace('.', "-")
    );
    let modified = crate::listing::epoch_seconds(&base.modified);
    let validators = |response: Response| {
        let response = response.with_header("etag", &etag);
        match modified {
            Some(seconds) => response.with_header("last-modified", &http_date(seconds)),
            None => response,
        }
    };
    if not_modified(req, &etag, modified) {
        return validators(Response::empty(304));
    }
    let text = format!("{}  {}\n", checksum.hex(base), files::file_name(&base.path));
    validators(
        Response::text(200, &text)
            .with_header("content-disposition", &content_disposition(repo, path)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_plugin_api::RepositoryKind;

    fn file() -> FileInfo {
        FileInfo {
            path: "dir/file.tgz".into(),
            size: 10,
            content_type: "application/gzip".into(),
            sha256: "ab".repeat(32),
            // SHA-512 of nothing in particular: 64 zero bytes.
            sha512: base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
            sha1: "cd".repeat(20),
            md5: "ef".repeat(16),
            modified: "2026-10-01T12:00:00.250Z".into(),
            last_downloaded: None,
        }
    }

    #[test]
    fn sidecars_name_their_file() {
        assert_eq!(of("a/x.tgz.sha256"), Some(("a/x.tgz", Checksum::Sha256)));
        assert_eq!(of("x.md5"), Some(("x", Checksum::Md5)));
        assert_eq!(of(".sha1"), None);
        assert_eq!(of("a/.sha1"), None);
        assert_eq!(of("a/x.tgz"), None);
        let file = file();
        assert_eq!(Checksum::Sha512.hex(&file), "00".repeat(64));
        assert_eq!(Checksum::Md5.hex(&file), "ef".repeat(16));
    }

    #[test]
    fn preconditions() {
        let file = file();
        let modified = crate::listing::epoch_seconds(&file.modified);
        let tag = "\"x-sha256\"";
        let req = Request::new("GET", "/f.sha256");
        assert!(!not_modified(&req, tag, modified));
        let req =
            Request::new("GET", "/f.sha256").with_header("if-none-match", "\"y\", W/\"x-sha256\"");
        assert!(not_modified(&req, tag, modified));
        // An `If-None-Match` that fails decides; the date is not consulted.
        let date = http_date(modified.unwrap());
        let req = Request::new("GET", "/f.sha256")
            .with_header("if-none-match", "\"other\"")
            .with_header("if-modified-since", &date);
        assert!(!not_modified(&req, tag, modified));
        // Sub-second precision is not part of an HTTP date.
        let req = Request::new("GET", "/f.sha256").with_header("if-modified-since", &date);
        assert!(not_modified(&req, tag, modified));
        let earlier = http_date(modified.unwrap() - 5);
        let req = Request::new("GET", "/f.sha256").with_header("if-modified-since", &earlier);
        assert!(!not_modified(&req, tag, modified));
    }

    #[test]
    fn dispositions_name_the_file() {
        let mut repo = Repository {
            name: "r".into(),
            kind: RepositoryKind::Hosted,
            base_url: "https://forge.example.com/repository/r".into(),
            inline: false,
        };
        assert_eq!(
            content_disposition(&repo, "a/b.txt"),
            "attachment; filename=\"b.txt\""
        );
        repo.inline = true;
        assert_eq!(
            content_disposition(&repo, "a/\"ä\".txt"),
            "inline; filename=\"___.txt\"; filename*=UTF-8''%22%C3%A4%22%2Etxt"
        );
    }
}
