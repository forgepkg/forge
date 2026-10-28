//! The documentation site, and `cargo xtask docs`.
//!
//! The site is an mdBook ([`BOOK_TOML`]) of the pages [`SUMMARY`] lists, in
//! its order: the README (the start page), the guides under `docs/`, the
//! READMEs of the Helm chart, the Kubernetes manifests and the monitoring
//! examples under `deploy/`, and the changelog. The pages link each other and
//! the source tree relatively, as GitHub shows the repository, so the site is
//! built from a copy staged in [`STAGE`] whose links work there:
//!
//! * a link to another page goes to that page of the site;
//! * a link into the source tree (`../crates/…`, `../DEVELOPMENT.md`) goes to
//!   the file on GitHub, on [`BRANCH`], which the site is built from;
//! * a link to a file or to a heading that does not exist is an error, and so
//!   is a Markdown file directly under `docs/` that SUMMARY.md does not list.
//!
//! [`DOCS_INDEX`], the index GitHub shows for `docs/`, is no page of the site,
//! which has a start page and a sidebar of its own. Its links are checked as a
//! page's, and it must link every page, so that no guide is missing from it.
//!
//! `cargo xtask docs --check` stops after the staging, without mdBook.

use crate::changelog::repo_url;
use crate::proc::Cmd;
use crate::release::CHANGELOG;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// The directory of the guides, the table of contents and mdBook's config.
const DOCS: &str = "docs";
/// The table of contents: the site's pages, in their order.
const SUMMARY: &str = "docs/SUMMARY.md";
/// The index of the guides GitHub shows under the files of `docs/`. On the
/// site it would be `readme.md`, which mdBook turns into `index.md`, the
/// README's name there.
const DOCS_INDEX: &str = "docs/README.md";
/// mdBook's configuration, copied next to the staged pages.
const BOOK_TOML: &str = "docs/book.toml";
/// Where the pages are staged (`src/`, the book's `src`) and the site is
/// built (`book/`, mdBook's default build directory).
const STAGE: &str = "target/docs";
/// The branch the site is built from, which links into the source tree name.
const BRANCH: &str = "main";
/// The mdBook the site is built with; the Pages workflow installs the same.
const MDBOOK: &str = "0.5.4";

/// `cargo xtask docs [--check]`.
pub fn docs(args: &[String]) -> Result<(), String> {
    let check_only = match args {
        [] => false,
        [flag] if flag == "--check" => true,
        _ => return Err("usage: cargo xtask docs [--check]".into()),
    };
    let changelog = Disk.read(CHANGELOG)?;
    let repo = repo_url(&changelog).ok_or_else(|| {
        format!("docs: {CHANGELOG} names no repository (the `[Unreleased]: <repo>/compare/…` link at its bottom)")
    })?;
    let files = stage(&Disk, repo)?;
    if check_only {
        println!(
            "{} page(s) of the site, every link resolves.",
            files.len() - 1
        );
        return Ok(());
    }

    let src = Path::new(STAGE).join("src");
    if Path::new(STAGE).exists() {
        fs::remove_dir_all(STAGE).map_err(|e| format!("docs: remove {STAGE}: {e}"))?;
    }
    fs::create_dir_all(&src).map_err(|e| format!("docs: create {}: {e}", src.display()))?;
    for (name, text) in &files {
        let path = src.join(name);
        fs::write(&path, text).map_err(|e| format!("docs: write {}: {e}", path.display()))?;
    }
    let book_toml = Path::new(STAGE).join("book.toml");
    fs::copy(BOOK_TOML, &book_toml)
        .map_err(|e| format!("docs: copy {BOOK_TOML} to {}: {e}", book_toml.display()))?;

    Cmd::new("mdbook")
        .arg("build")
        .arg(STAGE)
        .run()
        .map_err(|e| {
            format!(
                "{e}; the site is built with mdBook {MDBOOK}: \
                 `cargo install mdbook --version {MDBOOK} --locked`"
            )
        })?;
    println!("Built the site into {STAGE}/book: open {STAGE}/book/index.html.");
    Ok(())
}

/// What a path of the repository is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    File,
    Dir,
}

/// The repository's files, as staging reads them: the disk, or a test's map.
trait Tree {
    /// What `path` (relative to the root, `/`-separated, `""` for the root)
    /// is, if it exists.
    fn entry(&self, path: &str) -> Option<Entry>;
    fn read(&self, path: &str) -> Result<String, String>;
    /// The Markdown files directly in `dir`, as repository paths, sorted.
    fn markdown_in(&self, dir: &str) -> Result<Vec<String>, String>;
}

/// The working tree; xtask runs at the repository's root.
struct Disk;

impl Tree for Disk {
    fn entry(&self, path: &str) -> Option<Entry> {
        if path.is_empty() {
            return Some(Entry::Dir);
        }
        let meta = fs::metadata(path).ok()?;
        Some(if meta.is_dir() {
            Entry::Dir
        } else {
            Entry::File
        })
    }

    fn read(&self, path: &str) -> Result<String, String> {
        fs::read_to_string(path).map_err(|e| format!("docs: read {path}: {e}"))
    }

    fn markdown_in(&self, dir: &str) -> Result<Vec<String>, String> {
        let entries = fs::read_dir(dir).map_err(|e| format!("docs: read {dir}: {e}"))?;
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("docs: read {dir}: {e}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".md") && entry.path().is_file() {
                files.push(format!("{dir}/{name}"));
            }
        }
        files.sort();
        Ok(files)
    }
}

/// The staged book: each page under its name on the site, and `SUMMARY.md`
/// last, every link rewritten. `Err` names every broken link, unlisted page
/// and clash at once.
fn stage(tree: &impl Tree, repo: &str) -> Result<Vec<(String, String)>, String> {
    let summary = tree.read(SUMMARY)?;
    let mut errors = Vec::new();

    // The pages: what SUMMARY.md links, under their names on the site.
    let mut pages: BTreeMap<String, String> = BTreeMap::new();
    let mut order = Vec::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    map_links(&summary, &mut |target| {
        let path = resolve(SUMMARY, target.split('#').next().unwrap_or(target));
        match path {
            Some(path) if path.ends_with(".md") && tree.entry(&path) == Some(Entry::File) => {
                let name = site_name(&path);
                if let Some(other) = names.insert(name.clone(), path.clone()) {
                    if other != path {
                        errors.push(format!(
                            "{SUMMARY}: {other} and {path} would both be {name} on the site"
                        ));
                    }
                }
                if !pages.contains_key(&path) {
                    order.push(path.clone());
                }
                pages.insert(path, name);
            }
            _ => errors.push(format!(
                "{SUMMARY}: lists {target}, which is no Markdown file"
            )),
        }
        target.to_string()
    });
    for path in tree.markdown_in(DOCS)? {
        if path != SUMMARY && path != DOCS_INDEX && !pages.contains_key(&path) {
            errors.push(format!("{path}: no page of the site; list it in {SUMMARY}"));
        }
    }

    let mut texts = BTreeMap::new();
    for path in &order {
        texts.insert(path.clone(), tree.read(path)?);
    }
    let site = Site {
        tree,
        repo,
        anchors: texts.iter().map(|(p, t)| (p.clone(), anchors(t))).collect(),
        pages,
    };
    let mut files = Vec::new();
    for path in &order {
        let text = site.rewrite(path, &texts[path], &mut errors);
        files.push((site.pages[path].clone(), text));
    }
    files.push((
        "SUMMARY.md".into(),
        site.rewrite(SUMMARY, &summary, &mut errors),
    ));

    // The index of docs/ is not staged: only its links and its list count.
    if tree.entry(DOCS_INDEX) == Some(Entry::File) {
        let index = tree.read(DOCS_INDEX)?;
        site.rewrite(DOCS_INDEX, &index, &mut errors);
        let mut linked = BTreeSet::new();
        map_links(&index, &mut |target| {
            linked.extend(resolve(
                DOCS_INDEX,
                target.split('#').next().unwrap_or(target),
            ));
            target.to_string()
        });
        for path in &order {
            if !linked.contains(path) {
                errors.push(format!(
                    "{DOCS_INDEX}: links no {path}, which {SUMMARY} lists"
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(files)
    } else {
        errors.sort();
        errors.dedup();
        Err(format!(
            "docs: {} problem(s):\n  {}",
            errors.len(),
            errors.join("\n  ")
        ))
    }
}

/// A page's name on the site: the README is the start page, the README of a
/// directory is named after the directory's path (`deploy/kubernetes/README.md`
/// → `deploy-kubernetes.md`), and every other page keeps its file name, in
/// lower case (`CHANGELOG.md` → `changelog.md`). The site is flat, since a
/// page's links name the other pages from the site's root.
fn site_name(path: &str) -> String {
    if path == "README.md" {
        return "index.md".into();
    }
    if let Some(dir) = path.strip_suffix("/README.md") {
        return format!("{}.md", dir.replace('/', "-").to_lowercase());
    }
    path.rsplit('/').next().unwrap_or(path).to_lowercase()
}

/// The pages being staged, and how their links resolve.
struct Site<'a, T: Tree> {
    tree: &'a T,
    /// The repository's URL on GitHub.
    repo: &'a str,
    /// Repository path → name on the site.
    pages: BTreeMap<String, String>,
    /// The headings' anchors of each page.
    anchors: BTreeMap<String, BTreeSet<String>>,
}

impl<T: Tree> Site<'_, T> {
    /// `text`, from `origin`, with every link rewritten for the site; a link
    /// that does not resolve is kept and reported in `errors`.
    fn rewrite(&self, origin: &str, text: &str, errors: &mut Vec<String>) -> String {
        map_links(text, &mut |target| match self.link(origin, target) {
            Ok(link) => link,
            Err(e) => {
                errors.push(e);
                target.to_string()
            }
        })
    }

    /// Where a link of `origin` to `target` goes on the site.
    fn link(&self, origin: &str, target: &str) -> Result<String, String> {
        if target.contains("://") || target.starts_with("mailto:") {
            return Ok(target.to_string());
        }
        let (path, anchor) = match target.split_once('#') {
            Some((path, anchor)) => (path, Some(anchor)),
            None => (target, None),
        };
        let resolved = if path.is_empty() {
            origin.to_string()
        } else {
            resolve(origin, path)
                .ok_or_else(|| format!("{origin}: {target} leads out of the repository"))?
        };
        let fragment = anchor.map(|a| format!("#{a}")).unwrap_or_default();

        if let Some(name) = self.pages.get(&resolved) {
            self.check_anchor(origin, target, &resolved, anchor)?;
            let page = if path.is_empty() { "" } else { name.as_str() };
            return Ok(format!("{page}{fragment}"));
        }
        match self.tree.entry(&resolved) {
            Some(Entry::Dir) => Ok(format!("{}/tree/{BRANCH}/{resolved}{fragment}", self.repo)),
            Some(Entry::File) => {
                if resolved.ends_with(".md") {
                    self.check_anchor(origin, target, &resolved, anchor)?;
                }
                Ok(format!("{}/blob/{BRANCH}/{resolved}{fragment}", self.repo))
            }
            None => Err(format!(
                "{origin}: {target} links to {resolved}, which does not exist"
            )),
        }
    }

    /// `Err` unless the Markdown file `path` has a heading for `anchor`.
    fn check_anchor(
        &self,
        origin: &str,
        target: &str,
        path: &str,
        anchor: Option<&str>,
    ) -> Result<(), String> {
        let Some(anchor) = anchor.filter(|a| !a.is_empty()) else {
            return Ok(());
        };
        let found = match self.anchors.get(path) {
            Some(anchors) => anchors.contains(anchor),
            None => anchors(&self.tree.read(path)?).contains(anchor),
        };
        if found {
            Ok(())
        } else {
            Err(format!(
                "{origin}: {target}: {path} has no heading #{anchor}"
            ))
        }
    }
}

/// `path`, relative to the directory of the repository file `origin`, as a
/// repository path; `None` when it leads out of the repository.
fn resolve(origin: &str, path: &str) -> Option<String> {
    let mut parts: Vec<&str> = origin.split('/').collect();
    parts.pop();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            segment => parts.push(segment),
        }
    }
    Some(parts.join("/"))
}

/// The anchors of the headings of a Markdown file, as GitHub (and mdBook)
/// make them: the heading's text in lower case, without punctuation, spaces
/// turned into `-`, and `-1`, `-2` … after a repeated one.
fn anchors(text: &str) -> BTreeSet<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut anchors = BTreeSet::new();
    let mut fence: Option<(char, usize)> = None;
    for line in text.lines() {
        if update_fence(line, &mut fence) || fence.is_some() {
            continue;
        }
        let Some(heading) = heading(line) else {
            continue;
        };
        let slug = slug(heading);
        let n = seen.entry(slug.clone()).or_insert(0);
        anchors.insert(if *n == 0 { slug } else { format!("{slug}-{n}") });
        *n += 1;
    }
    anchors
}

/// The text of an ATX heading (`## Text`), without its closing `#`s.
fn heading(line: &str) -> Option<&str> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let rest = &line[indent..];
    let level = rest.len() - rest.trim_start_matches('#').len();
    if !(1..=6).contains(&level) {
        return None;
    }
    let text = &rest[level..];
    if !(text.is_empty() || text.starts_with(' ') || text.starts_with('\t')) {
        return None;
    }
    let text = text.trim();
    let without_closing = text.trim_end_matches('#');
    Some(
        if without_closing.is_empty() || without_closing.ends_with(' ') {
            without_closing.trim_end()
        } else {
            text
        },
    )
}

/// A heading's anchor: its text (a link's text, not its target) in lower
/// case, letters, digits, `-` and `_` kept, spaces turned into `-`.
fn slug(heading: &str) -> String {
    let text = map_links(heading, &mut |_| String::new()).replace("]()", "]");
    let mut slug = String::new();
    for c in text.trim().chars() {
        if c.is_alphanumeric() || c == '-' || c == '_' {
            slug.extend(c.to_lowercase());
        } else if c == ' ' {
            slug.push('-');
        }
    }
    slug
}

/// Track fenced code blocks (```` ``` ```` or `~~~`): `true` when `line`
/// opens or closes one, which `fence` then records.
fn update_fence(line: &str, fence: &mut Option<(char, usize)>) -> bool {
    let trimmed = line.trim();
    let marker = match trimmed.chars().next() {
        Some(c @ ('`' | '~')) => c,
        _ => return false,
    };
    let run = trimmed.len() - trimmed.trim_start_matches(marker).len();
    match *fence {
        None if run >= 3 => {
            *fence = Some((marker, run));
            true
        }
        Some((open, len)) if open == marker && run >= len && trimmed.len() == run => {
            *fence = None;
            true
        }
        _ => false,
    }
}

/// `text` with the target of every link (`[text](target)`, and a reference
/// definition's `[label]: target`) replaced by `f(target)`, except in code
/// spans and fenced code blocks.
fn map_links(text: &str, f: &mut dyn FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(text.len());
    let mut fence = None;
    for line in text.split_inclusive('\n') {
        if update_fence(line, &mut fence) || fence.is_some() {
            out.push_str(line);
        } else {
            out.push_str(&map_line(line, f));
        }
    }
    out
}

fn map_line(line: &str, f: &mut dyn FnMut(&str) -> String) -> String {
    // A reference definition: `[label]: target`.
    let indent = line.len() - line.trim_start().len();
    if line[indent..].starts_with('[') {
        if let Some(end) = line[indent..].find("]: ") {
            let label = &line[indent..indent + end + 3];
            if !label[1..].contains('[') && !label.contains("](") {
                let rest = &line[indent + end + 3..];
                let target_len = rest.find(char::is_whitespace).unwrap_or(rest.len());
                return format!(
                    "{}{label}{}{}",
                    &line[..indent],
                    f(&rest[..target_len]),
                    &rest[target_len..]
                );
            }
        }
    }

    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(i) = rest.find(['`', ']']) {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        if rest.starts_with('`') {
            // A code span: copied as it is, up to the same run of backticks.
            let run = rest.len() - rest.trim_start_matches('`').len();
            let ticks = &rest[..run];
            let after = &rest[run..];
            match find_run(after, ticks) {
                Some(end) => {
                    let span = run + end + run;
                    out.push_str(&rest[..span]);
                    rest = &rest[span..];
                }
                None => {
                    out.push_str(ticks);
                    rest = after;
                }
            }
        } else if let Some(inner) = rest.strip_prefix("](") {
            match inner.find(')') {
                Some(close) => {
                    let inside = &inner[..close];
                    let target_len = inside.find(char::is_whitespace).unwrap_or(inside.len());
                    out.push_str("](");
                    out.push_str(&f(&inside[..target_len]));
                    out.push_str(&inside[target_len..]);
                    out.push(')');
                    rest = &inner[close + 1..];
                }
                None => {
                    out.push_str("](");
                    rest = inner;
                }
            }
        } else {
            out.push(']');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out
}

/// Where the first run of exactly `ticks` backticks starts in `text`.
fn find_run(text: &str, ticks: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = text[from..].find(ticks) {
        let start = from + i;
        let end = start + ticks.len();
        let before = text[..start].ends_with('`');
        let after = text[end..].starts_with('`');
        if !before && !after {
            return Some(start);
        }
        from = end + text[end..].len() - text[end..].trim_start_matches('`').len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repository in memory: its files, and the directories they imply.
    struct Mem(BTreeMap<&'static str, &'static str>);

    impl Tree for Mem {
        fn entry(&self, path: &str) -> Option<Entry> {
            if self.0.contains_key(path) {
                Some(Entry::File)
            } else if path.is_empty() || self.0.keys().any(|k| k.starts_with(&format!("{path}/"))) {
                Some(Entry::Dir)
            } else {
                None
            }
        }

        fn read(&self, path: &str) -> Result<String, String> {
            self.0
                .get(path)
                .map(|text| text.to_string())
                .ok_or_else(|| format!("no {path}"))
        }

        fn markdown_in(&self, dir: &str) -> Result<Vec<String>, String> {
            let prefix = format!("{dir}/");
            Ok(self
                .0
                .keys()
                .filter_map(|k| k.strip_prefix(&prefix).map(|name| (k, name)))
                .filter(|(_, name)| !name.contains('/') && name.ends_with(".md"))
                .map(|(k, _)| k.to_string())
                .collect())
        }
    }

    const REPO: &str = "https://github.com/o/r";

    fn repo(files: &[(&'static str, &'static str)]) -> Mem {
        Mem(files.iter().copied().collect())
    }

    fn page<'a>(files: &'a [(String, String)], name: &str) -> &'a str {
        &files.iter().find(|(n, _)| n == name).expect("staged").1
    }

    #[test]
    fn slugs_follow_github() {
        assert_eq!(slug("Without the exchange"), "without-the-exchange");
        assert_eq!(slug("The `oidc` username"), "the-oidc-username");
        assert_eq!(slug("1. The read-only role"), "1-the-read-only-role");
        assert_eq!(slug("Admin → Authentication"), "admin--authentication");
        assert_eq!(slug("[2.1.0]"), "210");
        assert_eq!(slug("See [the guide](guide.md) now"), "see-the-guide-now");
        assert_eq!(slug("api_key_ttl_seconds"), "api_key_ttl_seconds");
    }

    #[test]
    fn anchors_number_repeats_and_skip_code() {
        let text = "# Title\n## Fixed\n```\n# not a heading\n```\n## Fixed ##\n### Fixed\n";
        let got: Vec<_> = anchors(text).into_iter().collect();
        assert_eq!(got, ["fixed", "fixed-1", "fixed-2", "title"]);
    }

    #[test]
    fn links_in_code_are_left_alone() {
        let text = "[a](x.md) `[b](y.md)` ``[c](`z`)`` [d](w.md \"title\")\n```\n[e](v.md)\n```\n";
        let mut seen = Vec::new();
        let out = map_links(text, &mut |t| {
            seen.push(t.to_string());
            format!("<{t}>")
        });
        assert_eq!(seen, ["x.md", "w.md"]);
        assert!(out.starts_with("[a](<x.md>) `[b](y.md)` ``[c](`z`)`` [d](<w.md> \"title\")\n"));
        assert!(out.ends_with("```\n[e](v.md)\n```\n"));
    }

    #[test]
    fn stages_the_pages_with_links_for_the_site() {
        let tree = repo(&[
            (
                "docs/SUMMARY.md",
                "# Summary\n\n[Home](../README.md)\n\n- [Guide](guide.md)\n\n---\n\n[Changes](../CHANGELOG.md)\n",
            ),
            (
                "README.md",
                "# Home\n\nSee [the guide](./docs/guide.md#set-up), [the license](./LICENSE) \
                 and [the code](crates/x).\n",
            ),
            (
                "docs/guide.md",
                "# Guide\n\n## Set up\n\nBack [home](../README.md), [up](#set-up), \
                 [source](../crates/x/src/lib.rs#L3), [notes](../crates/x/README.md#use).\n",
            ),
            ("CHANGELOG.md", "# Changelog\n\n[1.0.0]: https://example.com/v1\n"),
            ("LICENSE", "MIT"),
            ("crates/x/src/lib.rs", ""),
            ("crates/x/README.md", "# X\n## Use\n"),
            ("docs/changes/README.md", "fragments, no page"),
        ]);
        let files = stage(&tree, REPO).expect("stages");
        let names: Vec<_> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["index.md", "guide.md", "changelog.md", "SUMMARY.md"]
        );
        assert_eq!(
            page(&files, "index.md"),
            "# Home\n\nSee [the guide](guide.md#set-up), \
             [the license](https://github.com/o/r/blob/main/LICENSE) \
             and [the code](https://github.com/o/r/tree/main/crates/x).\n"
        );
        assert_eq!(
            page(&files, "guide.md"),
            "# Guide\n\n## Set up\n\nBack [home](index.md), [up](#set-up), \
             [source](https://github.com/o/r/blob/main/crates/x/src/lib.rs#L3), \
             [notes](https://github.com/o/r/blob/main/crates/x/README.md#use).\n"
        );
        assert_eq!(
            page(&files, "SUMMARY.md"),
            "# Summary\n\n[Home](index.md)\n\n- [Guide](guide.md)\n\n---\n\n[Changes](changelog.md)\n"
        );
    }

    #[test]
    fn a_directory_readme_is_named_after_its_directory() {
        let tree = repo(&[
            (
                "docs/SUMMARY.md",
                "- [Guide](guide.md)\n- [Chart](../deploy/helm/x/README.md)\n",
            ),
            (
                "docs/guide.md",
                "# Guide\n\nInstall [the chart](../deploy/helm/x/README.md#values).\n",
            ),
            (
                "deploy/helm/x/README.md",
                "# Chart\n\n## Values\n\nSee [values](values.yaml), [the guide](../../../docs/guide.md) \
                 and [the templates](templates).\n",
            ),
            ("deploy/helm/x/values.yaml", ""),
            ("deploy/helm/x/templates/a.yaml", ""),
        ]);
        let files = stage(&tree, REPO).expect("stages");
        let names: Vec<_> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["guide.md", "deploy-helm-x.md", "SUMMARY.md"]);
        assert_eq!(
            page(&files, "guide.md"),
            "# Guide\n\nInstall [the chart](deploy-helm-x.md#values).\n"
        );
        assert_eq!(
            page(&files, "deploy-helm-x.md"),
            "# Chart\n\n## Values\n\n\
             See [values](https://github.com/o/r/blob/main/deploy/helm/x/values.yaml), \
             [the guide](guide.md) \
             and [the templates](https://github.com/o/r/tree/main/deploy/helm/x/templates).\n"
        );
        assert_eq!(
            page(&files, "SUMMARY.md"),
            "- [Guide](guide.md)\n- [Chart](deploy-helm-x.md)\n"
        );
    }

    #[test]
    fn broken_links_and_unlisted_pages_fail() {
        let tree = repo(&[
            (
                "docs/SUMMARY.md",
                "- [Guide](guide.md)\n- [Gone](gone.md)\n",
            ),
            (
                "docs/guide.md",
                "# Guide\n\n[a](missing.md) [b](#nowhere) [c](other.md#x) [d](../../out.md)\n",
            ),
            ("docs/other.md", "# Other\n"),
        ]);
        let err = stage(&tree, REPO).expect_err("broken");
        for problem in [
            "docs/SUMMARY.md: lists gone.md, which is no Markdown file",
            "docs/guide.md: missing.md links to docs/missing.md, which does not exist",
            "docs/guide.md: #nowhere: docs/guide.md has no heading #nowhere",
            "docs/guide.md: other.md#x: docs/other.md has no heading #x",
            "docs/guide.md: ../../out.md leads out of the repository",
            "docs/other.md: no page of the site; list it in docs/SUMMARY.md",
        ] {
            assert!(err.contains(problem), "{problem} missing from:\n{err}");
        }
    }

    #[test]
    fn the_docs_index_is_no_page_but_links_every_page() {
        let summary = "[Home](../README.md)\n\n- [Guide](guide.md)\n- [Other](other.md)\n";
        let pages = [
            ("docs/SUMMARY.md", summary),
            ("README.md", "# Home\n## Quickstart\n"),
            ("docs/guide.md", "# Guide\n"),
            ("docs/other.md", "# Other\n"),
        ];
        let tree = repo(
            &[
                &pages[..],
                &[(
                    "docs/README.md",
                    "# Guides\n\n[Home](../README.md#quickstart), [the guide](guide.md), \
                     [the other](other.md#other).\n",
                )],
            ]
            .concat(),
        );
        let files = stage(&tree, REPO).expect("stages");
        let names: Vec<_> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["index.md", "guide.md", "other.md", "SUMMARY.md"]);

        let tree = repo(
            &[
                &pages[..],
                &[(
                    "docs/README.md",
                    "# Guides\n\n[the guide](guide.md#set-up), [gone](gone.md).\n",
                )],
            ]
            .concat(),
        );
        let err = stage(&tree, REPO).expect_err("incomplete index");
        for problem in [
            "docs/README.md: guide.md#set-up: docs/guide.md has no heading #set-up",
            "docs/README.md: gone.md links to docs/gone.md, which does not exist",
            "docs/README.md: links no README.md, which docs/SUMMARY.md lists",
            "docs/README.md: links no docs/other.md, which docs/SUMMARY.md lists",
        ] {
            assert!(err.contains(problem), "{problem} missing from:\n{err}");
        }
        assert!(!err.contains("no page of the site"), "{err}");
    }

    #[test]
    fn resolves_relative_paths() {
        assert_eq!(
            resolve("docs/a.md", "../README.md").as_deref(),
            Some("README.md")
        );
        assert_eq!(
            resolve("README.md", "./docs/a.md").as_deref(),
            Some("docs/a.md")
        );
        assert_eq!(resolve("docs/a.md", "b.md").as_deref(), Some("docs/b.md"));
        assert_eq!(
            resolve("docs/a.md", "../crates/x/").as_deref(),
            Some("crates/x")
        );
        assert_eq!(resolve("docs/a.md", "../../x.md"), None);
    }
}
