//! Raw file repositories for Forge: files under paths, like Nexus'
//! raw-hosted, raw-proxy and raw-group repositories.
//!
//! Served under a Forge repository's base URL (`/raw/<repository>`):
//!
//! * `GET` / `HEAD /<path>` — a file, which the host streams
//!   ([`Action::ServeFile`]: one range, validators, conditional requests);
//!   else the checksum sidecar `<path>` of a stored file
//!   (`.sha256`, `.sha512`, `.sha1`, `.md5`; [`sidecar`]); else, for a path
//!   that is a directory, a redirect to the directory;
//! * `GET` / `HEAD /<dir>/` — a listing, as HTML or JSON ([`listing`]);
//! * `PUT /<path>` — store the request body as the file;
//! * `POST /<dir>/` — store the files of a multipart form, Nexus' field names
//!   included ([`form`]);
//! * `DELETE /<path>` — delete a file.
//!
//! Paths follow [`forge_plugin_api::files`]: a path that needs normalizing
//! (`..`, `//`, an encoded `/`) is refused, never resolved. Everything else
//! a repository is, the host's file store keeps: the content-addressed
//! files and their digests, the deployment policy, package selectors on
//! paths, groups, and proxies, whose file `<path>` is the upstream's
//! `<remote_url>/<path>` ([`upstream_url`]).
//!
//! Forge links this plugin in ([`Raw`], [`PLUGIN_TOML`]), like NuGet.

pub mod form;
pub mod listing;
pub mod sidecar;

use forge_plugin_api::files::{self, Target};
use forge_plugin_api::{
    Action, Answer, DirectoryQuery, FetchResult, FileSource, FormatError, FormatPlugin, Loaded,
    NewFile, Query, Remote, Repository, RepositoryKind, Request, Response, StoreStatus,
    UpstreamAnswer, UpstreamOp, UpstreamStep,
};

/// This plugin's `plugin.toml`: its format id, name and version.
pub const PLUGIN_TOML: &str = forge_plugin_api::plugin_toml!();

/// The raw format.
#[derive(Debug, Clone, Copy, Default)]
pub struct Raw;

impl FormatPlugin for Raw {
    fn handle(&self, repo: &Repository, req: &Request) -> Action {
        let target = match target(req) {
            Ok(Some(target)) => target,
            // `/raw/<repository>`: the root listing is `/raw/<repository>/`.
            Ok(None) if is_read(req) => {
                return redirect(&format!("{}/", listing::base_path(&repo.base_url)))
            }
            Ok(None) => return respond(Response::text(404, "not found")),
            Err(e) => return respond(Response::text(400, &e.to_string())),
        };
        match (req.method.as_str(), target) {
            ("GET" | "HEAD", Target::File(path)) => {
                let mut queries = vec![Query::File(path.clone())];
                if let Some((base, _)) = sidecar::of(&path) {
                    queries.push(Query::File(base.to_string()));
                }
                Action::Load(queries)
            }
            ("GET" | "HEAD", Target::Directory(directory)) => {
                match listing::ListQuery::parse(&req.query) {
                    Ok(query) => Action::Load(vec![Query::Directory(DirectoryQuery {
                        directory,
                        limit: query.limit_for_host(),
                        after: query.after,
                    })]),
                    Err(message) => respond(Response::text(400, &message)),
                }
            }
            ("PUT", Target::File(path)) => Action::Load(vec![Query::Store(vec![NewFile {
                path,
                source: FileSource::Body,
                content_type: req.header("content-type").map(str::to_string),
            }])]),
            ("PUT", Target::Directory(_)) => respond(Response::text(
                400,
                "PUT uploads a file: name it in the path",
            )),
            ("POST", Target::Directory(_)) => Action::Load(vec![Query::Form]),
            ("POST", Target::File(_)) => respond(Response::text(
                400,
                "a form upload goes to a directory: end the path with /",
            )),
            ("DELETE", Target::File(path)) => Action::Load(vec![Query::Remove(path)]),
            ("DELETE", Target::Directory(_)) => respond(Response::text(
                400,
                "directories are deleted through the admin API (DELETE /admin/repositories/<name>/files?path=<dir>/)",
            )),
            _ => respond(
                Response::text(405, "method not allowed")
                    .with_header("allow", "GET, HEAD, PUT, POST, DELETE"),
            ),
        }
    }

    fn render(&self, repo: &Repository, req: &Request, data: &[Loaded]) -> Action {
        let Ok(Some(target)) = target(req) else {
            return unexpected("a request it did not load data for");
        };
        match (req.method.as_str(), target) {
            ("GET" | "HEAD", Target::File(path)) => file(repo, req, &path, data),
            ("GET" | "HEAD", Target::Directory(directory)) => {
                listing::render(repo, req, &directory, data)
            }
            ("PUT", Target::File(_)) => match stored(data) {
                Some([file]) if file.status == StoreStatus::Created => {
                    respond(Response::empty(201))
                }
                Some([_]) => respond(Response::empty(204)),
                _ => unexpected("a PUT without its stored file"),
            },
            ("POST", Target::Directory(directory)) => form::render(&directory, data),
            ("DELETE", Target::File(_)) => match data.last().map(|l| &l.answer) {
                Some(Answer::Removed(true)) => respond(Response::empty(204)),
                Some(Answer::Removed(false)) => respond(Response::text(404, "not found")),
                _ => unexpected("a DELETE without its outcome"),
            },
            _ => unexpected("a request it did not load data for"),
        }
    }

    fn upstream(
        &self,
        remote: &Remote,
        op: &UpstreamOp,
        _fetched: &[FetchResult],
    ) -> Result<UpstreamStep, FormatError> {
        Ok(UpstreamStep::Done(match op {
            // Nothing to resolve: a file's URL is the remote's and its path.
            UpstreamOp::Index => UpstreamAnswer::Index("{}".into()),
            UpstreamOp::File(path) => UpstreamAnswer::File(upstream_url(&remote.url, path)),
            _ => UpstreamAnswer::Failed("raw repositories hold files, not packages".into()),
        }))
    }
}

/// What a request's path names: `None` for the repository's URL without its
/// `/`.
fn target(req: &Request) -> Result<Option<Target>, files::PathError> {
    match req.path.strip_prefix('/') {
        Some(rest) => files::parse_request(rest).map(Some),
        None if req.path.is_empty() => Ok(None),
        None => files::parse_request(&req.path).map(Some),
    }
}

fn is_read(req: &Request) -> bool {
    matches!(req.method.as_str(), "GET" | "HEAD")
}

fn respond(response: Response) -> Action {
    Action::Respond(response)
}

/// A permanent redirect to `location`, a path within the repository: the
/// client stays on the host it asked.
fn redirect(location: &str) -> Action {
    respond(Response::empty(301).with_header("location", location))
}

/// A response for a conversation the host should not have started: the
/// plugin and the host disagree, which is a bug.
fn unexpected(what: &str) -> Action {
    respond(Response::text(
        500,
        &format!("raw: the host rendered {what}"),
    ))
}

/// The answer of the store a request asked for.
fn stored(data: &[Loaded]) -> Option<&[forge_plugin_api::StoredFile]> {
    data.iter().rev().find_map(|loaded| match &loaded.answer {
        Answer::Stored(files) => Some(files.as_slice()),
        _ => None,
    })
}

/// The answer to `query`, if it was loaded.
fn answer<'a>(data: &'a [Loaded], query: &Query) -> Option<&'a Answer> {
    data.iter()
        .find(|loaded| loaded.query == *query)
        .map(|loaded| &loaded.answer)
}

/// The file a `file` or `fetch-file` query found: `None` when it was not
/// asked, `Some(None)` when there is no such file.
fn found<'a>(data: &'a [Loaded], query: &Query) -> Option<Option<&'a forge_plugin_api::FileInfo>> {
    match answer(data, query)? {
        Answer::File(file) => Some(file.as_ref()),
        _ => None,
    }
}

/// `GET`/`HEAD` of a file path, round by round: the stored file, else the
/// checksum sidecar of a stored file, else (a proxy, or a group that may
/// have one) the upstream's file, else a redirect to the directory of that
/// name, else 404.
fn file(repo: &Repository, req: &Request, path: &str, data: &[Loaded]) -> Action {
    if let Some(Some(_)) = found(data, &Query::File(path.to_string())) {
        return Action::ServeFile(path.to_string());
    }
    if let Some((base, checksum)) = sidecar::of(path) {
        if let Some(Some(file)) = found(data, &Query::File(base.to_string())) {
            return respond(sidecar::respond(repo, req, path, file, checksum));
        }
    }
    match found(data, &Query::FetchFile(path.to_string())) {
        Some(Some(_)) => return Action::ServeFile(path.to_string()),
        None if repo.kind != RepositoryKind::Hosted => {
            return Action::Load(vec![Query::FetchFile(path.to_string())])
        }
        _ => {}
    }
    let directory = format!("{path}/");
    if directory.len() > files::MAX_PATH_BYTES {
        return respond(Response::text(404, "not found"));
    }
    let probe = Query::Directory(DirectoryQuery {
        directory: directory.clone(),
        after: None,
        limit: 1,
    });
    match answer(data, &probe) {
        None => Action::Load(vec![probe]),
        Some(Answer::Directory(Some(_))) => redirect(&format!(
            "{}/{}",
            listing::base_path(&repo.base_url),
            files::encode(&directory)
        )),
        Some(_) => respond(Response::text(404, "not found")),
    }
}

/// The upstream URL of `path`: `remote_url` (as a directory) with the path's
/// segments appended, each percent-encoded. `None` when `remote_url` is not
/// a URL with a path.
pub fn upstream_url(remote_url: &str, path: &str) -> Option<String> {
    let mut url = url::Url::parse(remote_url).ok()?;
    {
        let mut segments = url.path_segments_mut().ok()?;
        segments.pop_if_empty();
        for segment in path.split('/') {
            segments.push(segment);
        }
    }
    Some(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_urls_append_encoded_segments() {
        let base = "https://github.com/bblanchon/pdfium-binaries/releases/download/";
        assert_eq!(
            upstream_url(base, "chromium/7350/pdfium-linux-x64.tgz").unwrap(),
            "https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/7350/pdfium-linux-x64.tgz"
        );
        // Without a trailing slash the base is a directory all the same.
        assert_eq!(
            upstream_url("http://up.test/files", "a b/c?d#e.txt").unwrap(),
            "http://up.test/files/a%20b/c%3Fd%23e.txt"
        );
        assert_eq!(
            upstream_url("http://up.test", "x.bin").unwrap(),
            "http://up.test/x.bin"
        );
        assert_eq!(upstream_url("not a url", "x.bin"), None);
    }
}
