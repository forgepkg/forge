//! Changelog fragments, and `cargo xtask changelog`.
//!
//! A change does not edit CHANGELOG.md: it describes itself in a fragment of
//! its own, `docs/changes/<milestone>/<ref>.<kind>.md`, so changes merged side
//! by side never conflict, and no entry lands under a release it is not part
//! of. `<milestone>` is the version the change is planned for (its GitHub
//! milestone, e.g. `1.2.0`); `<ref>` starts with the number of the issue it
//! fixes, which the entry links (`205`, `205-registry-tokens`), or is a short
//! name for a change without an issue; `<kind>` picks the `###` heading the
//! entry goes under ([`KINDS`]). The file holds the entry's text, which the
//! fold turns into a list item.
//!
//! `cargo xtask release <version>` folds `docs/changes/<version>/` into the
//! version's section and deletes it. `cargo xtask changelog <milestone>` folds
//! a milestone into `[Unreleased]` ahead of the release, to edit the notes in
//! a pull request of their own. `cargo xtask changelog --check` (CI) checks
//! every fragment, and that its milestone is not released yet.

use crate::release::{ends_section, is_release_version, CHANGELOG};
use std::cmp::Ordering;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Where the fragments live, in a directory per milestone.
pub const DIR: &str = "docs/changes";
/// The one file in [`DIR`] that is not a milestone's directory.
const README: &str = "README.md";
const CARGO_TOML: &str = "Cargo.toml";

/// A fragment's `<kind>` and the heading its entry goes under, in the order
/// of the sections in the release notes.
const KINDS: [(&str, &str); 6] = [
    ("upgrade", "Upgrade notes"),
    ("feature", "Features"),
    ("fixed", "Fixed"),
    ("security", "Security"),
    ("docs", "Documentation"),
    ("limitation", "Known limitations"),
];

/// One changelog entry, from `docs/changes/<milestone>/<ref>.<kind>.md`.
#[derive(Debug)]
pub struct Fragment {
    pub path: String,
    pub milestone: String,
    /// The issue the entry links: `<ref>`'s leading number.
    issue: Option<u32>,
    /// `<ref>`, which orders the entries of an issue, and those without one.
    name: String,
    /// Index into [`KINDS`].
    kind: usize,
    /// The entry's text, trimmed.
    text: String,
}

impl Fragment {
    /// The entry as the lines of a list item: `- ` before the first line, the
    /// others indented under it, and the issue's link last.
    fn entry(&self, repo: Option<&str>) -> Result<Vec<String>, String> {
        let mut lines: Vec<String> = self
            .text
            .lines()
            .map(str::trim_end)
            .enumerate()
            .map(|(i, line)| match (i, line.is_empty()) {
                (0, _) => format!("- {line}"),
                (_, true) => String::new(),
                (_, false) => format!("  {line}"),
            })
            .collect();
        if let Some(n) = self.issue {
            let repo = repo.ok_or_else(|| {
                format!(
                    "{}: links #{n}, but {CHANGELOG} names no repository (the \
                     `[Unreleased]: <repo>/compare/…` link at its bottom)",
                    self.path
                )
            })?;
            lines.push(format!("  ([#{n}]({repo}/issues/{n}))"));
        }
        Ok(lines)
    }
}

/// `cargo xtask changelog <milestone> | --check`.
pub fn changelog(args: &[String]) -> Result<(), String> {
    match args {
        [flag] if flag == "--check" => check(),
        [milestone] if !milestone.starts_with('-') => {
            fold_milestone(milestone.strip_prefix('v').unwrap_or(milestone))
        }
        _ => Err("usage: cargo xtask changelog <milestone> | --check".into()),
    }
}

/// Every file under [`DIR`] is a fragment, and no fragment's milestone is
/// released yet: the workspace version is the latest release, and a pull
/// request written before it and merged after it would otherwise leave its
/// entry under a milestone no release folds again.
fn check() -> Result<(), String> {
    let fragments = read_all()?;
    let released = workspace_version(&read(CARGO_TOML)?)?;
    let stale: Vec<&str> = fragments
        .iter()
        .filter(|f| cmp_versions(&f.milestone, &released) != Ordering::Greater)
        .map(|f| f.path.as_str())
        .collect();
    if !stale.is_empty() {
        return Err(format!(
            "changelog: {}: the milestone is released already ({CARGO_TOML} is at \
             {released}), so no release would publish the entry. Move it to the \
             milestone it ships in: `git mv {DIR}/<milestone>/<file> {DIR}/<next>/`",
            stale.join(", ")
        ));
    }
    println!(
        "{} changelog fragment(s) under {DIR}, all for milestones after {released}.",
        fragments.len()
    );
    Ok(())
}

/// Folds `milestone`'s fragments into `[Unreleased]` and deletes them.
fn fold_milestone(milestone: &str) -> Result<(), String> {
    let fragments: Vec<Fragment> = read_all()?
        .into_iter()
        .filter(|f| f.milestone == milestone)
        .collect();
    if fragments.is_empty() {
        return Err(format!("changelog: no fragments under {DIR}/{milestone}"));
    }
    let folded =
        fold(&read(CHANGELOG)?, &fragments).map_err(|e| format!("changelog: {CHANGELOG}: {e}"))?;
    fs::write(CHANGELOG, folded).map_err(|e| format!("changelog: write {CHANGELOG}: {e}"))?;
    for fragment in &fragments {
        fs::remove_file(&fragment.path)
            .map_err(|e| format!("changelog: delete {}: {e}", fragment.path))?;
    }
    let dir = format!("{DIR}/{milestone}");
    fs::remove_dir(&dir).map_err(|e| format!("changelog: delete {dir}: {e}"))?;
    println!(
        "Folded the {} fragment(s) of {dir} into [Unreleased] in {CHANGELOG} and deleted \
         them. Edit the notes, then commit both in a pull request; `cargo xtask release \
         {milestone}` folds whatever is merged under {dir} after it.",
        fragments.len()
    );
    Ok(())
}

/// `Err` naming the fragments of any milestone but `version`: their changes
/// are on the default branch, so they ship in this release, whose notes
/// would leave them out.
pub fn check_only_milestone(fragments: &[Fragment], version: &str) -> Result<(), String> {
    let others: Vec<&str> = fragments
        .iter()
        .filter(|f| f.milestone != version)
        .map(|f| f.path.as_str())
        .collect();
    if others.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{}: their changes ship in {version}, but its notes take {DIR}/{version} \
         alone. Move them there, or release their milestone instead",
        others.join(", ")
    ))
}

/// `changelog` with `fragments` added to its `[Unreleased]` section: each
/// entry under its kind's `###` heading, after the entries already there,
/// ordered by issue number. A missing heading is added in [`KINDS`]' order.
pub fn fold(changelog: &str, fragments: &[Fragment]) -> Result<String, String> {
    let lines: Vec<&str> = changelog.lines().collect();
    let start = lines
        .iter()
        .position(|l| *l == "## [Unreleased]")
        .ok_or("no `## [Unreleased]` section to add the entries to")?;
    let end = lines[start + 1..]
        .iter()
        .position(|l| ends_section(l))
        .map_or(lines.len(), |i| start + 1 + i);

    // The section: its text before the first `###` heading, then its
    // subsections.
    let mut intro: Vec<String> = Vec::new();
    let mut subsections: Vec<(String, Vec<String>)> = Vec::new();
    for line in &lines[start + 1..end] {
        if line.starts_with("### ") {
            subsections.push((line.to_string(), Vec::new()));
        } else if let Some((_, body)) = subsections.last_mut() {
            body.push(line.to_string());
        } else {
            intro.push(line.to_string());
        }
    }

    let rank = |heading: &str| {
        KINDS
            .iter()
            .position(|(_, title)| heading.strip_prefix("### ") == Some(*title))
    };
    let repo = repo_url(changelog);
    let mut sorted: Vec<&Fragment> = fragments.iter().collect();
    sorted.sort_by(|a, b| {
        (a.issue.is_none(), a.issue, &a.name).cmp(&(b.issue.is_none(), b.issue, &b.name))
    });
    for (kind, (_, title)) in KINDS.iter().enumerate() {
        let mut entries = Vec::new();
        for fragment in sorted.iter().filter(|f| f.kind == kind) {
            entries.extend(fragment.entry(repo)?);
        }
        if entries.is_empty() {
            continue;
        }
        let heading = format!("### {title}");
        if let Some((_, body)) = subsections.iter_mut().find(|(h, _)| *h == heading) {
            let kept = trimmed(body).len() + leading_blank(body);
            body.truncate(kept);
            body.extend(entries);
        } else {
            let at = subsections
                .iter()
                .position(|(h, _)| rank(h).is_some_and(|r| r > kind))
                .unwrap_or(subsections.len());
            subsections.insert(at, (heading, entries));
        }
    }

    let mut out: Vec<&str> = lines[..=start].to_vec();
    out.push("");
    let intro = trimmed(&intro);
    if !intro.is_empty() {
        out.extend(intro.iter().map(String::as_str));
        out.push("");
    }
    for (heading, body) in &subsections {
        out.push(heading);
        out.push("");
        let body = trimmed(body);
        if !body.is_empty() {
            out.extend(body.iter().map(String::as_str));
            out.push("");
        }
    }
    if end == lines.len() {
        while out.last() == Some(&"") {
            out.pop();
        }
    }
    out.extend(&lines[end..]);
    Ok(out.join("\n") + "\n")
}

/// `lines` without its leading and trailing blank lines.
fn trimmed(lines: &[String]) -> &[String] {
    let blank = |l: &String| l.trim().is_empty();
    let start = lines.iter().position(|l| !blank(l)).unwrap_or(lines.len());
    let end = lines
        .iter()
        .rposition(|l| !blank(l))
        .map_or(start, |i| i + 1);
    &lines[start..end]
}

/// How many blank lines `lines` starts with.
fn leading_blank(lines: &[String]) -> usize {
    lines.iter().take_while(|l| l.trim().is_empty()).count()
}

/// The repository's URL, from the `[Unreleased]: <repo>/compare/…` link at
/// the bottom of the changelog (`<repo>/commits/…` before the first release).
pub(crate) fn repo_url(changelog: &str) -> Option<&str> {
    changelog.lines().find_map(|line| {
        let url = line.strip_prefix("[Unreleased]: ")?;
        let (repo, _) = url
            .split_once("/compare/")
            .or_else(|| url.split_once("/commits/"))?;
        Some(repo)
    })
}

/// Every fragment under [`DIR`] (none when it does not exist); `Err` naming
/// every file there that is not one.
pub fn read_all() -> Result<Vec<Fragment>, String> {
    read_from(Path::new(DIR))
}

fn read_from(dir: &Path) -> Result<Vec<Fragment>, String> {
    let mut fragments = Vec::new();
    let mut errors = Vec::new();
    for (milestone, path) in entries(dir)? {
        if !path.is_dir() {
            if milestone != README {
                errors.push(format!(
                    "{DIR}/{milestone}: not a milestone's directory ({DIR}/<version>/)"
                ));
            }
            continue;
        }
        if !is_release_version(&milestone) {
            errors.push(format!(
                "{DIR}/{milestone}: a milestone's directory is named after its version, \
                 like its GitHub milestone (`1.2.0`)"
            ));
            continue;
        }
        for (file, path) in entries(&path)? {
            if path.is_dir() {
                errors.push(format!("{DIR}/{milestone}/{file}: not a fragment"));
                continue;
            }
            let content = fs::read_to_string(&path)
                .map_err(|e| format!("changelog: read {}: {e}", path.display()))?;
            match parse(&milestone, &file, &content) {
                Ok(fragment) => fragments.push(fragment),
                Err(e) => errors.push(e),
            }
        }
    }
    if errors.is_empty() {
        Ok(fragments)
    } else {
        Err(format!(
            "changelog: {}\n(see {DIR}/{README})",
            errors.join("\n")
        ))
    }
}

/// The entries of `dir` by name; none when it does not exist.
fn entries(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let read = match fs::read_dir(dir) {
        Ok(read) => read,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("changelog: read {}: {e}", dir.display())),
    };
    let mut entries = Vec::new();
    for entry in read {
        let path = entry
            .map_err(|e| format!("changelog: read {}: {e}", dir.display()))?
            .path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("changelog: {}: not a UTF-8 name", path.display()))?;
        entries.push((name.to_string(), path));
    }
    entries.sort();
    Ok(entries)
}

/// The fragment `<file>` of `<milestone>`, holding `content`.
fn parse(milestone: &str, file: &str, content: &str) -> Result<Fragment, String> {
    let path = format!("{DIR}/{milestone}/{file}");
    let shape = || {
        let kinds: Vec<&str> = KINDS.iter().map(|(kind, _)| *kind).collect();
        format!(
            "{path}: not <ref>.<kind>.md, <kind> one of {}",
            kinds.join(", ")
        )
    };
    let stem = file.strip_suffix(".md").ok_or_else(shape)?;
    let (name, kind) = stem.rsplit_once('.').ok_or_else(shape)?;
    let kind = KINDS
        .iter()
        .position(|(k, _)| *k == kind)
        .ok_or_else(shape)?;
    if name.is_empty()
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "{path}: <ref> is the issue's number (`205`, `205-short-name`), or a short \
             name of lowercase letters, digits and `-`"
        ));
    }
    let lead = name.split('-').next().unwrap_or(name);
    let issue = if lead.bytes().all(|b| b.is_ascii_digit()) {
        match lead.parse::<u32>() {
            Ok(n) if n > 0 && !lead.starts_with('0') => Some(n),
            _ => return Err(format!("{path}: `{lead}` is not an issue's number")),
        }
    } else {
        None
    };
    let text = content.trim();
    if text.is_empty() {
        return Err(format!("{path}: empty"));
    }
    if text.starts_with("- ") || text.starts_with("* ") || text.starts_with('#') {
        return Err(format!(
            "{path}: holds the entry's text alone; the fold makes it a list item \
             under its kind's heading"
        ));
    }
    Ok(Fragment {
        path,
        milestone: milestone.to_string(),
        issue,
        name: name.to_string(),
        kind,
        text: text.to_string(),
    })
}

/// The `version` of `[workspace.package]`: the latest release, which
/// `cargo xtask release` sets.
fn workspace_version(toml: &str) -> Result<String, String> {
    let mut in_section = false;
    for line in toml.lines() {
        if line.starts_with('[') {
            in_section = line.trim_end() == "[workspace.package]";
        } else if let Some((version, _)) = line
            .strip_prefix("version = \"")
            .and_then(|rest| rest.split_once('"'))
            .filter(|_| in_section)
        {
            return Ok(version.to_string());
        }
    }
    Err(format!(
        "changelog: {CARGO_TOML}: no `version` in [workspace.package]"
    ))
}

/// How SemVer orders two release versions ([`is_release_version`]).
fn cmp_versions(a: &str, b: &str) -> Ordering {
    fn split(v: &str) -> (Vec<u64>, Option<&str>) {
        let (core, pre) = match v.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (v, None),
        };
        (
            core.split('.').map(|n| n.parse().unwrap_or(0)).collect(),
            pre,
        )
    }
    fn cmp_identifiers(a: &str, b: &str) -> Ordering {
        match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(a), Ok(b)) => a.cmp(&b),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => a.cmp(b),
        }
    }
    let (core_a, pre_a) = split(a);
    let (core_b, pre_b) = split(b);
    core_a.cmp(&core_b).then_with(|| match (pre_a, pre_b) {
        (None, None) => Ordering::Equal,
        // A pre-release comes before its release.
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a), Some(b)) => a
            .split('.')
            .zip(b.split('.'))
            .map(|(a, b)| cmp_identifiers(a, b))
            .find(|o| o.is_ne())
            .unwrap_or_else(|| a.split('.').count().cmp(&b.split('.').count())),
    })
}

fn read(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("changelog: read {path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "https://github.com/o/r";

    fn fragment(milestone: &str, file: &str, content: &str) -> Fragment {
        parse(milestone, file, content).unwrap()
    }

    fn changelog(unreleased: &str) -> String {
        format!(
            "# Changelog\n\nIntro.\n\n## [Unreleased]\n{unreleased}\n## [1.0.0]\n\n- first\n\n\
             [Unreleased]: {REPO}/compare/v1.0.0...HEAD\n[1.0.0]: {REPO}/releases/tag/v1.0.0\n"
        )
    }

    #[test]
    fn fragment_names() {
        let f = fragment("1.2.0", "205.fixed.md", "A fix.\n");
        assert_eq!((f.issue, f.kind, f.text.as_str()), (Some(205), 2, "A fix."));
        assert_eq!(f.path, "docs/changes/1.2.0/205.fixed.md");
        let f = fragment("1.2.0", "201-registry-tokens.upgrade.md", "x");
        assert_eq!((f.issue, f.kind), (Some(201), 0));
        let f = fragment("1.2.0", "oidc-docs.docs.md", "x");
        assert_eq!((f.issue, f.kind), (None, 4));
        // A name that starts with digits but not with a number of its own.
        assert_eq!(fragment("1.2.0", "2fa.feature.md", "x").issue, None);

        for bad in [
            "205.md",
            "205.fix.md",
            "205.fixed.txt",
            "205.fixed",
            ".fixed.md",
            "-205.fixed.md",
            "Fix.fixed.md",
            "fix_it.fixed.md",
            "0205.fixed.md",
            "0.fixed.md",
            "99999999999.fixed.md",
            "README.md",
        ] {
            assert!(parse("1.2.0", bad, "x").is_err(), "{bad}");
        }
    }

    #[test]
    fn fragment_text_is_the_entry_alone() {
        for bad in ["", " \n\n", "- A fix.", "* A fix.", "### Fixed\n\n- A fix."] {
            assert!(parse("1.2.0", "1.fixed.md", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn entry_is_a_list_item_with_the_issue_link() {
        let f = fragment(
            "1.2.0",
            "205.fixed.md",
            "\nFirst line   \nsecond line.\n\nA paragraph:\n\n- nested\n",
        );
        assert_eq!(
            f.entry(Some(REPO)).unwrap(),
            [
                "- First line",
                "  second line.",
                "",
                "  A paragraph:",
                "",
                "  - nested",
                "  ([#205](https://github.com/o/r/issues/205))",
            ]
        );
        assert!(f.entry(None).is_err());
        let unlinked = fragment("1.2.0", "docs.docs.md", "Docs.");
        assert_eq!(unlinked.entry(None).unwrap(), ["- Docs."]);
    }

    #[test]
    fn fold_into_an_empty_unreleased() {
        let fragments = [
            fragment("1.2.0", "oidc.feature.md", "Named."),
            fragment("1.2.0", "30.fixed.md", "Thirty."),
            fragment("1.2.0", "4.fixed.md", "Four."),
            fragment("1.2.0", "7.upgrade.md", "Upgrade."),
            fragment("1.2.0", "7.feature.md", "Seven."),
        ];
        let out = fold(&changelog(""), &fragments).unwrap();
        assert_eq!(
            out,
            changelog(
                "\n### Upgrade notes\n\n- Upgrade.\n  ([#7](https://github.com/o/r/issues/7))\n\n\
                 ### Features\n\n- Seven.\n  ([#7](https://github.com/o/r/issues/7))\n- Named.\n\n\
                 ### Fixed\n\n- Four.\n  ([#4](https://github.com/o/r/issues/4))\n\
                 - Thirty.\n  ([#30](https://github.com/o/r/issues/30))\n"
            )
        );
    }

    #[test]
    fn fold_after_the_entries_already_there() {
        let before = changelog(
            "\nA release intro.\n\n### Features\n\n- Old feature.\n\n### Good to know\n\n\
             - Kept.\n\n### Known limitations\n\n- Old limit.\n",
        );
        let fragments = [
            fragment("1.2.0", "9.feature.md", "New feature."),
            fragment("1.2.0", "8.fixed.md", "New fix."),
            fragment("1.2.0", "x.limitation.md", "New limit."),
        ];
        let out = fold(&before, &fragments).unwrap();
        assert_eq!(
            out,
            changelog(
                "\nA release intro.\n\n### Features\n\n- Old feature.\n- New feature.\n  \
                 ([#9](https://github.com/o/r/issues/9))\n\n### Good to know\n\n- Kept.\n\n\
                 ### Fixed\n\n- New fix.\n  ([#8](https://github.com/o/r/issues/8))\n\n\
                 ### Known limitations\n\n- Old limit.\n- New limit.\n"
            )
        );
        // Then the release turns it into the version's section.
        let released = crate::release::release_changelog(&out, "1.2.0").unwrap();
        assert!(released.contains("## [Unreleased]\n\n## [1.2.0]\n\nA release intro."));
    }

    #[test]
    fn fold_into_the_last_section() {
        let only = "# Changelog\n\n## [Unreleased]\n";
        let out = fold(only, &[fragment("1.0.0", "x.feature.md", "First.")]).unwrap();
        assert_eq!(
            out,
            "# Changelog\n\n## [Unreleased]\n\n### Features\n\n- First.\n"
        );
        // A link needs the repository's URL.
        assert!(fold(only, &[fragment("1.0.0", "1.feature.md", "First.")]).is_err());
        assert!(fold("# Changelog\n", &[fragment("1.0.0", "x.feature.md", "x")]).is_err());
    }

    #[test]
    fn only_the_released_milestone() {
        let fragments = [
            fragment("1.2.0", "1.fixed.md", "x"),
            fragment("1.3.0", "2.fixed.md", "x"),
        ];
        assert!(check_only_milestone(&fragments[..1], "1.2.0").is_ok());
        let err = check_only_milestone(&fragments, "1.2.0").unwrap_err();
        assert!(err.starts_with("docs/changes/1.3.0/2.fixed.md:"), "{err}");
        assert!(check_only_milestone(&[], "1.2.0").is_ok());
    }

    #[test]
    fn versions_in_semver_order() {
        let ordered = [
            "0.9.9",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.2.0",
            "1.10.0",
            "2.0.0",
        ];
        for (i, a) in ordered.iter().enumerate() {
            for (j, b) in ordered.iter().enumerate() {
                assert_eq!(cmp_versions(a, b), i.cmp(&j), "{a} vs {b}");
            }
        }
    }

    #[test]
    fn workspace_version_of_the_workspace_package() {
        let toml = "[package]\nversion = \"9.9.9\"\n\n[workspace.package]\n\
                    edition = \"2021\"\nversion = \"1.1.0\"\n";
        assert_eq!(workspace_version(toml).unwrap(), "1.1.0");
        assert!(workspace_version("[package]\nversion = \"1.0.0\"\n").is_err());
    }

    #[test]
    fn read_a_tree_of_fragments() {
        let root = std::env::temp_dir().join(format!("xtask-changes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        assert!(read_from(&root).unwrap().is_empty());
        fs::create_dir_all(root.join("1.2.0")).unwrap();
        fs::write(root.join(README), "about").unwrap();
        fs::write(root.join("1.2.0/5.fixed.md"), "Five.").unwrap();
        fs::write(root.join("1.2.0/3.fixed.md"), "Three.").unwrap();
        let read = read_from(&root).unwrap();
        let names: Vec<&str> = read.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["3", "5"]);

        fs::write(root.join("notes.md"), "stray").unwrap();
        fs::create_dir_all(root.join("next")).unwrap();
        fs::write(root.join("1.2.0/5.fix.md"), "Five.").unwrap();
        let err = read_from(&root).unwrap_err();
        fs::remove_dir_all(&root).unwrap();
        for named in ["1.2.0/5.fix.md", "next:", "notes.md:"] {
            assert!(err.contains(named), "{named}: {err}");
        }
    }

    #[test]
    fn real_fragments_are_well_formed() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(DIR);
        read_from(&dir).unwrap();
    }
}
