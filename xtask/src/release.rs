//! `cargo xtask release <version>`: cut a release.
//!
//! Sets the version everywhere the release workflow checks it (the workspace
//! `Cargo.toml` and `Cargo.lock`, `web/package.json`, the image tag of the
//! Kubernetes base, and the Helm chart's `version` and `appVersion`), turns
//! the changelog's `[Unreleased]` section into the version's section, and
//! commits on a `release-<version>` branch off the default branch. Then,
//! through the GitHub CLI (`gh`), it opens a pull request, waits for its CI
//! run, merges it (with a merge queue: queues it and waits for it to land),
//! waits for the merge commit's CI run on the default branch (e2e and web-e2e
//! never run on the pull request), and creates and pushes the annotated
//! `v<version>` tag on the merge commit, which starts release.yml.
//! `--no-tag` only commits, on the current branch, and pushes nothing.
//! Every edit is computed before the first file is written, so a failed
//! precondition leaves the tree untouched.
//!
//! When the default branch already carries the version (a release pull
//! request merged by hand, or a run that stopped after the merge), nothing is
//! committed: the run waits for the CI run of the default branch's head and
//! tags that commit.
//!
//! Two changelog guards keep the release notes (the version's section alone)
//! whole. A release is refused while the changelog has a version section
//! whose tag was never created: a section drafted for a release that then got
//! another number would be left behind. It is also refused when the
//! version's section already exists and `[Unreleased]` still has entries.

use crate::proc::Cmd;
use std::fs;
use std::thread;
use std::time::{Duration, Instant};

const CARGO_TOML: &str = "Cargo.toml";
const PACKAGE_JSON: &str = "web/package.json";
const KUSTOMIZATION: &str = "deploy/kubernetes/base/kustomization.yaml";
const CHART: &str = "deploy/helm/forge/Chart.yaml";
const CHANGELOG: &str = "CHANGELOG.md";

/// The workflow whose runs gate the merge and the tag (release.yml requires
/// the tagged commit's run of it).
const CI_WORKFLOW: &str = "ci.yml";
/// How long a pushed commit's CI run may take to show up; release.yml waits
/// as long.
const RUN_APPEARS_WITHIN: Duration = Duration::from_secs(10 * 60);
/// How long a merged pull request may take to land (a merge queue runs CI
/// first).
const MERGE_LANDS_WITHIN: Duration = Duration::from_secs(90 * 60);
const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// A file's content with the version set.
type Edit = fn(&str, &str) -> Result<String, String>;

pub fn release(args: &[String]) -> Result<(), String> {
    let mut version = None;
    let mut publish = true;
    for arg in args {
        match arg.as_str() {
            "--no-tag" => publish = false,
            v if version.is_none() && !v.starts_with('-') => {
                version = Some(v.strip_prefix('v').unwrap_or(v).to_string())
            }
            other => return Err(format!("release: unexpected argument `{other}`")),
        }
    }
    let version = version.ok_or("usage: cargo xtask release <version> [--no-tag]")?;
    if !is_release_version(&version) {
        return Err(format!(
            "release: `{version}` is not MAJOR.MINOR.PATCH[-PRERELEASE]"
        ));
    }
    let tag_name = format!("v{version}");

    if !git(&["status", "--porcelain"])?.is_empty() {
        return Err("release: the working tree has uncommitted changes".into());
    }
    // The default branch, fetched with every tag: the release starts from
    // its head, and the tag checks below see the tags pushed from elsewhere.
    let base = if publish {
        let base = gh(&[
            "repo",
            "view",
            "--json",
            "defaultBranchRef",
            "--jq",
            ".defaultBranchRef.name",
        ])
        .map_err(|e| {
            format!(
                "release: {e}. Opening and merging the release pull request takes the \
                 GitHub CLI, logged in (`gh auth login`); --no-tag only commits"
            )
        })?;
        Cmd::new("git")
            .args(["fetch", "--tags", "origin", &base])
            .run()?;
        if git(&["rev-parse", "HEAD"])? != git(&["rev-parse", &format!("origin/{base}")])? {
            return Err(format!(
                "release: HEAD is not origin/{base}, where the release starts: \
                 `git switch {base} && git pull --ff-only` first"
            ));
        }
        Some(base)
    } else {
        None
    };
    if git(&[
        "rev-parse",
        "--quiet",
        "--verify",
        &format!("refs/tags/{tag_name}"),
    ])
    .is_ok()
    {
        return Err(format!("release: tag {tag_name} already exists"));
    }
    let changelog = read(CHANGELOG)?;
    let tags = git(&["tag", "--list", "v*"])?;
    check_sections_are_tagged(&changelog, &tags.lines().collect::<Vec<_>>(), &version)
        .map_err(|e| format!("release: {CHANGELOG}: {e}"))?;

    let edits: [(&str, Edit); 5] = [
        (CARGO_TOML, set_workspace_version),
        (PACKAGE_JSON, set_package_version),
        (KUSTOMIZATION, set_image_tag),
        (CHART, set_chart_version),
        (CHANGELOG, release_changelog),
    ];
    // Only the files the release changes.
    let mut contents = Vec::new();
    for (path, edit) in edits {
        let old = read(path)?;
        let new = edit(&old, &version).map_err(|e| format!("release: {path}: {e}"))?;
        if new != old {
            contents.push((path, new));
        }
    }

    let Some(base) = base else {
        commit(&contents, &tag_name)?;
        let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"])?;
        println!();
        println!(
            "Prepared {tag_name} on `{branch}`. Open a pull request; once it is merged and CI \
             on the merge commit (e2e and web-e2e included) is green, tag that commit:"
        );
        println!("  git tag -a {tag_name} -m {tag_name} <commit> && git push origin {tag_name}");
        return Ok(());
    };
    let target = if contents.is_empty() {
        println!("origin/{base} already carries {version}: tagging it once its CI run passed.");
        git(&["rev-parse", "HEAD"])?
    } else {
        let branch = format!("release-{version}");
        let ref_name = format!("refs/heads/{branch}");
        if git(&["rev-parse", "--quiet", "--verify", &ref_name]).is_ok()
            || !git(&["ls-remote", "--heads", "origin", &ref_name])?.is_empty()
        {
            return Err(format!(
                "release: branch `{branch}` already exists (here or on origin): delete it, \
                 or merge its pull request and run this again on an up-to-date `{base}`"
            ));
        }
        Cmd::new("git").args(["switch", "-c", &branch]).run()?;
        commit(&contents, &tag_name)?;
        let resume = format!(
            "once the pull request is merged, run `cargo xtask release {version}` again on an \
             up-to-date `{base}` to tag the merge commit"
        );
        merge_pull_request(&branch, &base, &tag_name)
            .map_err(|e| format!("{e}; nothing is tagged: {resume}"))?
    };

    println!("Waiting for the CI run of {} on `{base}`.", short(&target));
    wait_for_ci(&target, &base, "push").map_err(|e| {
        format!(
            "{e}; nothing is tagged: once a fix is merged, run `cargo xtask release {version}` \
             again on an up-to-date `{base}`"
        )
    })?;
    // The merge commit exists only on origin so far.
    Cmd::new("git").args(["fetch", "origin", &base]).run()?;
    Cmd::new("git")
        .args(["tag", "-a", &tag_name, "-m", &tag_name, &target])
        .run()?;
    Cmd::new("git").args(["push", "origin", &tag_name]).run()?;
    println!();
    println!(
        "Pushed {tag_name} on {}: release.yml builds and signs the image and the chart and \
         creates the GitHub release.",
        short(&target)
    );
    Ok(())
}

/// Writes `contents`, updates Cargo.lock and commits `release: <tag_name>`;
/// nothing to commit when the tree already carries the version.
fn commit(contents: &[(&str, String)], tag_name: &str) -> Result<(), String> {
    for (path, content) in contents {
        fs::write(path, content).map_err(|e| format!("release: write {path}: {e}"))?;
    }
    // Cargo.lock records every workspace crate's version; nothing else moves.
    Cmd::new("cargo").args(["update", "--workspace"]).run()?;

    Cmd::new("git")
        .arg("add")
        .args(contents.iter().map(|(path, _)| *path))
        .arg("Cargo.lock")
        .run()?;
    if git(&["diff", "--cached", "--quiet"]).is_err() {
        Cmd::new("git")
            .args(["commit", "-m", &format!("release: {tag_name}")])
            .run()?;
    }
    Ok(())
}

/// Pushes `branch`, opens its pull request into `base`, waits for the pull
/// request's CI run and merges it; the merge commit once it is on `base`.
fn merge_pull_request(branch: &str, base: &str, tag_name: &str) -> Result<String, String> {
    Cmd::new("git")
        .args(["push", "-u", "origin", branch])
        .run()?;
    let head = git(&["rev-parse", "HEAD"])?;
    let created = gh(&[
        "pr",
        "create",
        "--base",
        base,
        "--head",
        branch,
        "--title",
        &format!("release: {tag_name}"),
        "--body",
        &format!(
            "Release {tag_name}, prepared by `cargo xtask release`. It merges this pull request \
             once its CI run passed, and tags the merge commit {tag_name} once the merge \
             commit's CI run on `{base}` passed."
        ),
    ])?;
    // gh prints the pull request's URL last.
    let url = created.lines().last().unwrap_or_default().to_string();
    println!("Opened {url}. Waiting for its CI run.");
    wait_for_ci(&head, branch, "pull_request")
        .map_err(|e| format!("{e}. Push a fix to `{branch}` ({url})"))?;
    // Merges nothing but the commit whose CI run passed. With a merge queue,
    // gh queues it instead (the queue's merge method wins over `--merge`).
    Cmd::new("gh")
        .args(["pr", "merge", &url, "--merge", "--match-head-commit", &head])
        .run()
        .map_err(|e| format!("release: {e}"))?;
    poll(
        &format!("merge commit for {url}"),
        MERGE_LANDS_WITHIN,
        || {
            let view = gh(&[
                "pr",
                "view",
                &url,
                "--json",
                "state,mergeCommit",
                "--jq",
                r#"[.state, .mergeCommit.oid // ""] | join(" ")"#,
            ])?;
            merge_commit(&view).map_err(|e| format!("release: {url}: {e}"))
        },
    )
}

/// The merge commit from `<state> <merge commit>`; `None` while the pull
/// request is still open (in a merge queue).
fn merge_commit(view: &str) -> Result<Option<String>, String> {
    let view = view.trim();
    let (state, oid) = view.split_once(' ').unwrap_or((view, ""));
    match state {
        "MERGED" if !oid.is_empty() => Ok(Some(oid.to_string())),
        "MERGED" | "OPEN" => Ok(None),
        other => Err(format!("the pull request is {other}, not merged")),
    }
}

/// Waits for the newest CI run of `sha` on `branch`, triggered by `event`,
/// to finish; `Err` unless it succeeded.
fn wait_for_ci(sha: &str, branch: &str, event: &str) -> Result<(), String> {
    let run = poll(
        &format!("{CI_WORKFLOW} run of {} on `{branch}`", short(sha)),
        RUN_APPEARS_WITHIN,
        || {
            let ids = gh(&[
                "run",
                "list",
                "--workflow",
                CI_WORKFLOW,
                "--commit",
                sha,
                "--branch",
                branch,
                "--event",
                event,
                "--limit",
                "1",
                "--json",
                "databaseId",
                "--jq",
                ".[].databaseId",
            ])?;
            Ok(ids.lines().next().map(str::to_string))
        },
    )?;
    Cmd::new("gh")
        .args(["run", "watch", &run, "--exit-status", "--interval", "30"])
        .run()
        .map_err(|e| format!("release: the CI run of {} did not pass: {e}", short(sha)))
}

/// `check()` every [`POLL_INTERVAL`] until it finds something; `Err` once
/// `within` has passed without.
fn poll<T>(
    what: &str,
    within: Duration,
    mut check: impl FnMut() -> Result<Option<T>, String>,
) -> Result<T, String> {
    let start = Instant::now();
    loop {
        if let Some(found) = check()? {
            return Ok(found);
        }
        if start.elapsed() >= within {
            return Err(format!(
                "release: no {what} after {} minutes",
                within.as_secs() / 60
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}

/// `gh <args>` stdout (trimmed); `Err` on a non-zero exit.
fn gh(args: &[&str]) -> Result<String, String> {
    Cmd::new("gh").args(args).output_string()
}

/// `git <args>` stdout (trimmed); `Err` on a non-zero exit.
fn git(args: &[&str]) -> Result<String, String> {
    Cmd::new("git").args(args).output_string()
}

fn read(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("release: read {path}: {e}"))
}

/// `MAJOR.MINOR.PATCH` with an optional `-PRERELEASE`, as release.yml's
/// `v*.*.*` tags carry it.
fn is_release_version(v: &str) -> bool {
    let (core, pre) = match v.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (v, None),
    };
    let numbers: Vec<&str> = core.split('.').collect();
    numbers.len() == 3
        && numbers.iter().all(|n| {
            !n.is_empty()
                && n.bytes().all(|b| b.is_ascii_digit())
                && (*n == "0" || !n.starts_with('0'))
        })
        && pre.is_none_or(|pre| {
            pre.split('.').all(|id| {
                !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        })
}

/// `text` with the one line `edit` rewrites (it sees and returns the line
/// without its line ending); `Err` unless exactly one line matched.
fn replace_one_line(
    text: &str,
    what: &str,
    mut edit: impl FnMut(&str) -> Option<String>,
) -> Result<String, String> {
    let mut matched = 0;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        match edit(body) {
            Some(new) => {
                matched += 1;
                out.push_str(&new);
                out.push_str(&line[body.len()..]);
            }
            None => out.push_str(line),
        }
    }
    match matched {
        1 => Ok(out),
        0 => Err(format!("no {what} found")),
        n => Err(format!("{n} lines look like the {what}, expected one")),
    }
}

/// `version = "…"` in `[workspace.package]` (the line release.yml reads).
fn set_workspace_version(toml: &str, version: &str) -> Result<String, String> {
    let mut in_section = false;
    replace_one_line(toml, "`version` in [workspace.package]", |line| {
        if line.starts_with('[') {
            in_section = line.trim_end() == "[workspace.package]";
            return None;
        }
        (in_section && line.starts_with("version = \"")).then(|| format!("version = \"{version}\""))
    })
}

/// The top-level `"version"` of a package.json (two-space indented).
fn set_package_version(json: &str, version: &str) -> Result<String, String> {
    replace_one_line(json, "top-level \"version\"", |line| {
        let rest = line.strip_prefix("  \"version\": \"")?;
        let (_, tail) = rest.split_once('"')?;
        Some(format!("  \"version\": \"{version}\"{tail}"))
    })
}

/// The `newTag:` of the base's `images:` entry.
fn set_image_tag(kustomization: &str, version: &str) -> Result<String, String> {
    replace_one_line(kustomization, "`newTag:`", |line| {
        let value = line.trim_start();
        value.strip_prefix("newTag:")?;
        let indent = &line[..line.len() - value.len()];
        Some(format!("{indent}newTag: {version}"))
    })
}

/// The chart's own `version` and its `appVersion` (the image tag it deploys);
/// only top-level keys, never a dependency's indented `version:`.
fn set_chart_version(chart: &str, version: &str) -> Result<String, String> {
    let chart = replace_one_line(chart, "top-level `version:`", |line| {
        line.starts_with("version:")
            .then(|| format!("version: {version}"))
    })?;
    replace_one_line(&chart, "top-level `appVersion:`", |line| {
        line.starts_with("appVersion:")
            .then(|| format!("appVersion: \"{version}\""))
    })
}

/// The version a `## [<version>]` (or `## [<version>] …`) heading names;
/// `None` for `## [Unreleased]` and any other line.
fn section_version(line: &str) -> Option<&str> {
    let (name, rest) = line.strip_prefix("## [")?.split_once(']')?;
    (is_release_version(name) && (rest.is_empty() || rest.starts_with(' '))).then_some(name)
}

/// Whether `line` ends a section: the next `## [` heading, or the first link
/// reference definition (`[label]: <url>`) at the bottom, as release.yml
/// reads the notes.
fn ends_section(line: &str) -> bool {
    line.starts_with("## [")
        || line
            .strip_prefix('[')
            .and_then(|l| l.split_once("]: "))
            .is_some_and(|(label, _)| !label.is_empty() && !label.contains(']'))
}

/// `Err` naming every `## [x.y.z]` section, other than `version`'s own, whose
/// `vx.y.z` is not among `tags` (`git tag --list 'v*'`): a section drafted for
/// a release that never happened. Releasing under another number would leave
/// it behind, and its entries out of the published notes.
fn check_sections_are_tagged(changelog: &str, tags: &[&str], version: &str) -> Result<(), String> {
    let untagged: Vec<&str> = changelog
        .lines()
        .filter_map(section_version)
        .filter(|v| *v != version && !tags.iter().any(|t| t.strip_prefix('v') == Some(*v)))
        .collect();
    if untagged.is_empty() {
        return Ok(());
    }
    let missing: Vec<String> = untagged
        .iter()
        .map(|v| format!("`## [{v}]` has no tag v{v}"))
        .collect();
    Err(format!(
        "{}: drafted for a release that never happened. Fold the entries into \
         [Unreleased] and drop the section (`git fetch --tags` first if the tag \
         exists only on the remote)",
        missing.join("; ")
    ))
}

/// The changelog with a `## [<version>]` section: its non-empty `[Unreleased]`
/// section renamed (under a new, empty `[Unreleased]`) and the link
/// references at the bottom updated. A section drafted for the version is
/// kept as it is, but only while `[Unreleased]` is empty: the release notes
/// are that one section, so entries left under `[Unreleased]` would be
/// missing from them.
fn release_changelog(changelog: &str, version: &str) -> Result<String, String> {
    let heading = format!("## [{version}]");
    let lines: Vec<&str> = changelog.lines().collect();
    let start = lines.iter().position(|l| *l == "## [Unreleased]");
    let has_unreleased_entries = start.is_some_and(|start| {
        lines[start + 1..]
            .iter()
            .take_while(|l| !ends_section(l))
            .any(|l| !l.trim().is_empty())
    });
    if lines.iter().any(|l| section_version(l) == Some(version)) {
        if has_unreleased_entries {
            return Err(format!(
                "both `{heading}` and [Unreleased] have entries, and the release notes \
                 would be `{heading}` alone: move the [Unreleased] entries into it"
            ));
        }
        return Ok(changelog.to_string());
    }
    let start =
        start.ok_or_else(|| format!("neither a `{heading}` nor a `## [Unreleased]` section"))?;
    if !has_unreleased_entries {
        return Err("the [Unreleased] section is empty: nothing to release".into());
    }

    let mut out = String::with_capacity(changelog.len() + 128);
    for (i, line) in lines.iter().enumerate() {
        if i == start {
            out.push_str("## [Unreleased]\n\n");
            out.push_str(&heading);
        } else if let Some((repo, _)) = line.strip_prefix("[Unreleased]: ").and_then(|url| {
            url.split_once("/compare/")
                .or_else(|| url.split_once("/commits/"))
        }) {
            // `[Unreleased]: <repo>/compare/v<previous>...HEAD`, or before
            // the first release `<repo>/commits/<branch>`.
            out.push_str(&format!("[Unreleased]: {repo}/compare/v{version}...HEAD\n"));
            out.push_str(&format!("[{version}]: {repo}/releases/tag/v{version}"));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_versions() {
        for ok in ["0.1.0", "1.20.3", "2.0.0-rc.1", "1.0.0-beta-2"] {
            assert!(is_release_version(ok), "{ok}");
        }
        for bad in [
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.0.x",
            "1.0.0-",
            "1.0.0-a..b",
            "",
            "v1.0.0",
        ] {
            assert!(!is_release_version(bad), "{bad}");
        }
    }

    #[test]
    fn merge_commit_once_the_pull_request_is_merged() {
        assert_eq!(
            merge_commit("MERGED abc123\n").unwrap(),
            Some("abc123".into())
        );
        // Still in a merge queue, or merged but its commit not reported yet.
        assert_eq!(merge_commit("OPEN ").unwrap(), None);
        assert_eq!(merge_commit("MERGED ").unwrap(), None);
        let err = merge_commit("CLOSED ").unwrap_err();
        assert!(err.contains("CLOSED"), "{err}");
    }

    #[test]
    fn workspace_version_only_in_its_section() {
        let toml = "[workspace]\nmembers = []\n\n[workspace.package]\n\
                    version = \"0.1.0\"\nedition = \"2024\"\n\n\
                    [workspace.dependencies]\nserde = { version = \"1\" }\nversion = \"9\"\n";
        let out = set_workspace_version(toml, "0.2.0").unwrap();
        assert_eq!(
            out,
            toml.replace("version = \"0.1.0\"", "version = \"0.2.0\"")
        );
        assert!(set_workspace_version("[package]\nversion = \"1.0.0\"\n", "2.0.0").is_err());
    }

    #[test]
    fn package_json_top_level_version() {
        let json = "{\n  \"name\": \"web\",\n  \"version\": \"0.1.0\",\n  \"engines\": {\n    \
                    \"version\": \"x\"\n  }\n}\n";
        let out = set_package_version(json, "0.2.0-rc.1").unwrap();
        assert_eq!(out, json.replace("\"0.1.0\"", "\"0.2.0-rc.1\""));
    }

    #[test]
    fn image_tag_keeps_indentation() {
        let k = "images:\n  - name: ghcr.io/schmitch/forge\n    newTag: 0.1.0\n";
        assert_eq!(
            set_image_tag(k, "0.2.0").unwrap(),
            "images:\n  - name: ghcr.io/schmitch/forge\n    newTag: 0.2.0\n"
        );
        let two = format!("{k}  - name: other\n    newTag: 1.0.0\n");
        assert!(set_image_tag(&two, "0.2.0").is_err());
        assert!(set_image_tag("images: []\n", "0.2.0").is_err());
    }

    #[test]
    fn real_files_have_exactly_one_version_line() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
        let read = |p: &str| fs::read_to_string(format!("{root}/{p}")).unwrap();
        set_workspace_version(&read(CARGO_TOML), "9.9.9").unwrap();
        set_package_version(&read(PACKAGE_JSON), "9.9.9").unwrap();
        set_image_tag(&read(KUSTOMIZATION), "9.9.9").unwrap();
        set_chart_version(&read(CHART), "9.9.9").unwrap();
    }

    #[test]
    fn chart_version_and_app_version_only_at_the_top_level() {
        let chart = "apiVersion: v2\nname: forge\nversion: 0.1.0\nappVersion: \"0.1.0\"\n\
                     dependencies:\n  - name: redis\n    version: 1.0.0\n";
        assert_eq!(
            set_chart_version(chart, "0.2.0-rc.1").unwrap(),
            "apiVersion: v2\nname: forge\nversion: 0.2.0-rc.1\nappVersion: \"0.2.0-rc.1\"\n\
             dependencies:\n  - name: redis\n    version: 1.0.0\n"
        );
        assert!(set_chart_version("apiVersion: v2\nversion: 0.1.0\n", "0.2.0").is_err());
    }

    const CHANGELOG_FIXTURE: &str = "# Changelog\n\nIntro.\n\n## [Unreleased]\n\n### Fixed\n\n\
        - a bug\n\n## [0.1.0]\n\nFirst.\n\n\
        [Unreleased]: https://github.com/o/r/compare/v0.1.0...HEAD\n\
        [0.1.0]: https://github.com/o/r/releases/tag/v0.1.0\n";

    #[test]
    fn changelog_unreleased_becomes_the_version() {
        let out = release_changelog(CHANGELOG_FIXTURE, "0.2.0").unwrap();
        assert_eq!(
            out,
            "# Changelog\n\nIntro.\n\n## [Unreleased]\n\n## [0.2.0]\n\n### Fixed\n\n\
             - a bug\n\n## [0.1.0]\n\nFirst.\n\n\
             [Unreleased]: https://github.com/o/r/compare/v0.2.0...HEAD\n\
             [0.2.0]: https://github.com/o/r/releases/tag/v0.2.0\n\
             [0.1.0]: https://github.com/o/r/releases/tag/v0.1.0\n"
        );
    }

    #[test]
    fn first_release_links_compare_from_its_tag() {
        let first = "# Changelog\n\n## [Unreleased]\n\n- everything\n\n\
                     [Unreleased]: https://github.com/o/r/commits/main\n";
        assert_eq!(
            release_changelog(first, "1.0.0").unwrap(),
            "# Changelog\n\n## [Unreleased]\n\n## [1.0.0]\n\n- everything\n\n\
             [Unreleased]: https://github.com/o/r/compare/v1.0.0...HEAD\n\
             [1.0.0]: https://github.com/o/r/releases/tag/v1.0.0\n"
        );
    }

    #[test]
    fn changelog_with_the_section_and_unreleased_entries_is_refused() {
        // The notes would be `## [0.1.0]` alone, without "a bug".
        let err = release_changelog(CHANGELOG_FIXTURE, "0.1.0").unwrap_err();
        assert!(err.contains("[Unreleased]"), "{err}");
        let titled = CHANGELOG_FIXTURE.replace("## [0.1.0]\n", "## [0.1.0] — First\n");
        assert!(release_changelog(&titled, "0.1.0").is_err());
    }

    #[test]
    fn changelog_with_a_drafted_section_and_empty_unreleased_is_kept() {
        let drafted = "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] — Drafted\n\n\
                       - a feature\n\n## [0.1.0]\n\nFirst.\n\n\
                       [Unreleased]: https://github.com/o/r/compare/v0.2.0...HEAD\n\
                       [0.2.0]: https://github.com/o/r/releases/tag/v0.2.0\n";
        assert_eq!(release_changelog(drafted, "0.2.0").unwrap(), drafted);
        // No [Unreleased] section at all.
        let bare = "# Changelog\n\n## [0.2.0]\n\n- a feature\n";
        assert_eq!(release_changelog(bare, "0.2.0").unwrap(), bare);
    }

    #[test]
    fn changelog_without_unreleased_changes_is_refused() {
        let empty = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0]\n\nFirst.\n";
        assert!(release_changelog(empty, "0.2.0").is_err());
        assert!(release_changelog("# Changelog\n", "0.2.0").is_err());
        // Link references directly below [Unreleased] are not entries.
        let links_only = "# Changelog\n\n## [Unreleased]\n\n\
                          [Unreleased]: https://github.com/o/r/compare/v0.1.0...HEAD\n";
        assert!(release_changelog(links_only, "0.2.0").is_err());
    }

    #[test]
    fn untagged_release_section_is_refused() {
        // `## [0.1.0]` was drafted, but no v0.1.0 tag exists.
        let err = check_sections_are_tagged(CHANGELOG_FIXTURE, &[], "1.0.0").unwrap_err();
        assert!(err.contains("`## [0.1.0]` has no tag v0.1.0"), "{err}");
        let other_tags = ["v0.0.9", "v0.1.0-rc.1", "v0.1.00", "0.1.0"];
        assert!(check_sections_are_tagged(CHANGELOG_FIXTURE, &other_tags, "1.0.0").is_err());
        let titled = CHANGELOG_FIXTURE.replace("## [0.1.0]\n", "## [0.1.0] — First\n");
        assert!(check_sections_are_tagged(&titled, &[], "1.0.0").is_err());

        // Several: each untagged one is named, the tagged one is not.
        let several = "## [Unreleased]\n\n## [0.3.0]\n\n## [0.2.0-rc.1]\n\n## [0.1.0]\n";
        let err = check_sections_are_tagged(several, &["v0.1.0"], "1.0.0").unwrap_err();
        assert!(err.contains("`## [0.3.0]` has no tag v0.3.0"), "{err}");
        assert!(
            err.contains("`## [0.2.0-rc.1]` has no tag v0.2.0-rc.1"),
            "{err}"
        );
        assert!(!err.contains("v0.1.0"), "{err}");
    }

    #[test]
    fn tagged_and_own_sections_pass_the_tag_check() {
        assert!(check_sections_are_tagged(CHANGELOG_FIXTURE, &["v0.1.0"], "0.2.0").is_ok());
        // The section of the version being released has no tag yet.
        assert!(check_sections_are_tagged(CHANGELOG_FIXTURE, &[], "0.1.0").is_ok());
        let several = "## [Unreleased]\n\n## [1.0.0-rc.1]\n\n## [0.1.0]\n";
        assert!(check_sections_are_tagged(several, &["v0.1.0", "v1.0.0-rc.1"], "1.0.0").is_ok());
        // Only version headings count: not [Unreleased], a link reference or
        // other bracketed headings.
        let other = "## [Unreleased]\n\n## [Notes]\n\n### [0.1.0]\n\n\
                     [0.1.0]: https://github.com/o/r/releases/tag/v0.1.0\n";
        assert!(check_sections_are_tagged(other, &[], "1.0.0").is_ok());
        assert!(check_sections_are_tagged("# Changelog\n", &[], "1.0.0").is_ok());
    }
}
