//! Directory pages of the file store (the `directory` query): what a
//! directory holds, a page at a time, for the format's plugin to render.
//!
//! A page holds at most `limit` entries (default 100, at most 1000) after
//! the entry named by `after`, in byte order of their names, a
//! subdirectory's name ending in `/`; `next` names where the following page
//! starts. A listing walks the index ([`raw_dao::walk_directory`]): a page
//! costs `limit` index probes, however many files are below the directory.
//!
//! Package selectors apply: a file outside the caller's selector is not
//! listed, and a subdirectory is listed only when it holds a file the
//! caller may see (looked for among its first files; a subdirectory none of
//! whose first [`SUBDIRECTORY_SCAN`] files is visible is left out). A
//! group lists the merged entries of the members the caller may read, the
//! highest-priority member's file first; a proxy lists what it has cached.
//!
//! Nothing a selector hides is named, not even by `next`: a page reads on
//! past hidden entries until it holds `limit` visible ones, and `next` is
//! the last of them. That walk is bounded ([`LISTING_SCAN`] entries): a
//! page that reaches the bound ends at its last visible entry, and the
//! listing ends where it found none. A directory exists for the caller
//! when it holds a visible entry, so one of hidden entries alone is not
//! found, whatever its size.

use std::collections::BTreeMap;

use forge_core::authz::PackageFilter;
use forge_db::model::{RepoKind, Repository};
use forge_db::raw_dao::{self, RawFile};
use forge_plugin::api::files;

use super::{FileError, Files};

/// Default page size.
pub const DEFAULT_LIMIT: usize = 100;

/// Largest page size.
pub const MAX_LIMIT: usize = 1000;

/// How many of a subdirectory's files a listing reads, at most, to find one
/// a selector-restricted caller may see.
pub const SUBDIRECTORY_SCAN: usize = 1000;

/// How many entries of a directory a page walks, at most, to find the
/// `limit` a selector-restricted caller may see (a page of `MAX_LIMIT`
/// walks one more, to know whether another follows).
pub const LISTING_SCAN: usize = 1000;

/// How many entries a selector-restricted page walks at once, at least.
const WALK_BATCH: usize = 100;

/// One entry of a page.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The entry's name in its directory; a subdirectory's ends in `/`.
    pub name: String,
    pub kind: EntryKind,
}

#[derive(Debug, Clone)]
pub enum EntryKind {
    File(Box<RawFile>),
    /// A subdirectory: its path, ending in `/`.
    Directory(String),
}

/// A page of a directory.
#[derive(Debug, Clone)]
pub struct Page {
    pub entries: Vec<Entry>,
    /// The `after` of the next page, if there is one.
    pub next: Option<String>,
}

/// Where a page starting after the entry `after` (a name in directory
/// `prefix`, a subdirectory's ending in `/`) resumes: the least path past
/// that entry (past all of a subdirectory's files: `'0'` follows `'/'`; past
/// a file: no path holds a control character).
fn resume_at(prefix: &str, after: Option<&str>) -> Result<String, FileError> {
    let Some(after) = after.filter(|a| !a.is_empty()) else {
        return Ok(prefix.to_string());
    };
    let name = after.strip_suffix('/').unwrap_or(after);
    files::validate_segment(name).map_err(|e| FileError::BadRequest(format!("after: {e}")))?;
    Ok(past(prefix, after))
}

/// The least path past the entry `entry` of directory `prefix`, a name
/// the walk read (see [`resume_at`]).
fn past(prefix: &str, entry: &str) -> String {
    match entry.strip_suffix('/') {
        Some(name) => format!("{prefix}{name}0"),
        None => format!("{prefix}{entry}\u{1}"),
    }
}

/// One repository's entries of a page: what it has after `from`, as far as
/// it read (`more`: it may have entries past the last one returned, and
/// has all of them up to and including the entry named `more`, which it
/// returned: a name the caller may see).
struct Partial {
    entries: Vec<Entry>,
    more: Option<String>,
}

impl Files<'_> {
    /// The entries of `prefix` in hosted or proxy `repo` from `from` on,
    /// visible through every one of `filters`: `limit` of them, walking
    /// past the hidden ones up to [`LISTING_SCAN`] entries.
    async fn list_local(
        &self,
        repo: &Repository,
        prefix: &str,
        from: &str,
        limit: usize,
        filters: &[PackageFilter],
    ) -> Result<Partial, FileError> {
        // One visible entry past the page says that another page follows.
        let wanted = limit + 1;
        let unfiltered = filters.iter().all(|f| matches!(f, PackageFilter::AllowAll));
        let bound = if unfiltered {
            wanted
        } else {
            wanted.max(LISTING_SCAN)
        };
        let mut entries = Vec::new();
        let mut walked_count = 0;
        let mut from = from.to_string();
        let mut ended = false;
        while entries.len() < wanted && walked_count < bound {
            let batch = if unfiltered {
                wanted - entries.len()
            } else {
                (wanted - entries.len()).max(WALK_BATCH)
            }
            .min(bound - walked_count);
            let walked = raw_dao::walk_directory(
                &self.state.pool,
                repo.id,
                prefix,
                &from,
                i64::try_from(batch).unwrap_or(i64::MAX),
            )
            .await?;
            ended = walked.len() < batch;
            walked_count += walked.len();
            let mut last = None;
            for walked in walked {
                if entries.len() == wanted {
                    break;
                }
                let rest = &walked.path[prefix.len()..];
                let (entry, key) = match (rest.find('/'), &walked.file) {
                    (None, Some(file)) => {
                        let visible = filters.iter().all(|f| f.allows(&file.path));
                        let entry = Entry {
                            name: rest.to_string(),
                            kind: EntryKind::File(Box::new(file.clone())),
                        };
                        (visible.then_some(entry), rest.to_string())
                    }
                    (Some(i), _) => {
                        let name = &rest[..i];
                        let dir = format!("{prefix}{name}/");
                        let visible = self.directory_visible(repo, &dir, filters).await?;
                        let entry = Entry {
                            name: format!("{name}/"),
                            kind: EntryKind::Directory(dir),
                        };
                        (visible.then_some(entry), format!("{name}/"))
                    }
                    // A file row vanished between the walk and the join.
                    (None, None) => (None, rest.to_string()),
                };
                entries.extend(entry);
                last = Some(key);
            }
            match last {
                Some(last) if !ended => from = past(prefix, &last),
                _ => break,
            }
        }
        // Past the page, at the walk's bound or at the directory's end, the
        // page ends at its last visible entry: never at a hidden one.
        let more = if entries.len() > limit {
            entries.truncate(limit);
            entries.last().map(|e| e.name.clone())
        } else if ended {
            None
        } else {
            entries.last().map(|e| e.name.clone())
        };
        Ok(Partial { entries, more })
    }

    /// Whether directory `dir` of `repo` holds a file visible through every
    /// one of `filters`.
    async fn directory_visible(
        &self,
        repo: &Repository,
        dir: &str,
        filters: &[PackageFilter],
    ) -> Result<bool, FileError> {
        if filters.iter().all(|f| matches!(f, PackageFilter::AllowAll)) {
            return Ok(true);
        }
        const BATCH: usize = 200;
        let mut after = String::new();
        let mut read = 0;
        while read < SUBDIRECTORY_SCAN {
            let paths =
                raw_dao::paths_under(&self.state.pool, repo.id, dir, &after, BATCH as i64).await?;
            if paths.iter().any(|p| filters.iter().all(|f| f.allows(p))) {
                return Ok(true);
            }
            if paths.len() < BATCH {
                return Ok(false);
            }
            read += paths.len();
            after = paths.last().cloned().unwrap_or_default();
        }
        Ok(false)
    }

    /// The entries of `prefix` in `repo` (any kind) from `from` on.
    fn list_in<'a>(
        &'a self,
        repo: &'a Repository,
        prefix: &'a str,
        from: &'a str,
        limit: usize,
        filters: Vec<PackageFilter>,
        depth: u32,
    ) -> futures_util::future::BoxFuture<'a, Result<Partial, FileError>> {
        Box::pin(async move {
            let mut filters = filters;
            filters.push(self.state.authz.package_filter(&self.principal, repo).await);
            if repo.kind() != RepoKind::Group {
                return self.list_local(repo, prefix, from, limit, &filters).await;
            }
            // A merge of the members' pages, complete up to the first point
            // a member stopped reading at.
            let mut merged: BTreeMap<String, Entry> = BTreeMap::new();
            let mut cutoff: Option<String> = None;
            for member in self.serving_members(repo, depth).await? {
                let part = self
                    .list_in(&member, prefix, from, limit, filters.clone(), depth + 1)
                    .await?;
                for entry in part.entries {
                    merged.entry(entry.name.clone()).or_insert(entry);
                }
                if let Some(more) = part.more {
                    if cutoff.as_ref().is_none_or(|c| more < *c) {
                        cutoff = Some(more);
                    }
                }
            }
            let mut entries: Vec<Entry> = merged
                .into_values()
                .filter(|e| cutoff.as_ref().is_none_or(|c| e.name <= *c))
                .collect();
            let more = if entries.len() > limit {
                entries.truncate(limit);
                entries.last().map(|e| e.name.clone())
            } else {
                cutoff
            };
            Ok(Partial { entries, more })
        })
    }

    /// A page of directory `prefix` of `repo` after the entry `after`, of
    /// `limit` entries (0: the default), `None` when it does not exist (a
    /// directory other than the root without visible entries, asked for
    /// without `after`).
    pub async fn list(
        &self,
        repo: &Repository,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Option<Page>, FileError> {
        files::validate_directory(prefix).map_err(|e| {
            FileError::Internal(format!("the format named directory {prefix:?}: {e}"))
        })?;
        let limit = if limit == 0 {
            DEFAULT_LIMIT
        } else {
            limit.min(MAX_LIMIT)
        };
        let from = resume_at(prefix, after)?;
        let partial = self
            .list_in(repo, prefix, &from, limit, Vec::new(), 0)
            .await?;
        if partial.entries.is_empty() && partial.more.is_none() && !prefix.is_empty() {
            // Past the end of an existing directory is an empty page, not a
            // missing directory.
            if after.is_none() {
                return Ok(None);
            }
        }
        Ok(Some(Page {
            entries: partial.entries,
            next: partial.more,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_resume_past_the_named_entry() {
        assert_eq!(resume_at("a/", None).unwrap(), "a/");
        assert_eq!(resume_at("a/", Some("")).unwrap(), "a/");
        assert_eq!(resume_at("a/", Some("x.bin")).unwrap(), "a/x.bin\u{1}");
        assert_eq!(resume_at("", Some("dir/")).unwrap(), "dir0");
        assert!(resume_at("a/", Some("../x")).is_err());
        assert!(resume_at("a/", Some("b/c")).is_err());
    }
}
