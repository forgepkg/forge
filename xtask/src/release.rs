//! `cargo xtask release <version>`: cut a release.
//!
//! Sets the version everywhere the release workflow checks it (the workspace
//! `Cargo.toml` and `Cargo.lock`, `web/package.json`, the image tag of the
//! Kubernetes base, and the Helm chart's `version` and `appVersion`), turns
//! the changelog's `[Unreleased]` section into the version's section,
//! commits, and creates the annotated `v<version>` tag.
//! Pushing is left to the caller. Every edit is computed before the first
//! file is written, so a failed precondition leaves the tree untouched.
//!
//! Two changelog guards keep the release notes (the version's section alone)
//! whole. A release is refused while the changelog has a version section
//! whose tag was never created: a section drafted for a release that then got
//! another number would be left behind. It is also refused when the
//! version's section already exists and `[Unreleased]` still has entries.

use crate::proc::Cmd;
use std::fs;

const CARGO_TOML: &str = "Cargo.toml";
const PACKAGE_JSON: &str = "web/package.json";
const KUSTOMIZATION: &str = "deploy/kubernetes/base/kustomization.yaml";
const CHART: &str = "deploy/helm/forge/Chart.yaml";
const CHANGELOG: &str = "CHANGELOG.md";

pub fn release(args: &[String]) -> Result<(), String> {
    let mut version = None;
    let mut tag = true;
    for arg in args {
        match arg.as_str() {
            "--no-tag" => tag = false,
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
    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"])?;
    if tag && branch != "main" && branch != "master" {
        // release.yml only publishes tags on the default branch.
        return Err(format!(
            "release: on `{branch}`, not the default branch; use --no-tag to prepare the \
             release in a pull request and tag the merge commit"
        ));
    }

    let edits = [
        (
            CARGO_TOML,
            set_workspace_version(&read(CARGO_TOML)?, &version),
        ),
        (
            PACKAGE_JSON,
            set_package_version(&read(PACKAGE_JSON)?, &version),
        ),
        (
            KUSTOMIZATION,
            set_image_tag(&read(KUSTOMIZATION)?, &version),
        ),
        (CHART, set_chart_version(&read(CHART)?, &version)),
        (CHANGELOG, release_changelog(&changelog, &version)),
    ];
    let mut contents = Vec::new();
    for (path, edited) in edits {
        contents.push((path, edited.map_err(|e| format!("release: {path}: {e}"))?));
    }
    for (path, content) in &contents {
        fs::write(path, content).map_err(|e| format!("release: write {path}: {e}"))?;
    }
    // Cargo.lock records every workspace crate's version; nothing else moves.
    Cmd::new("cargo").args(["update", "--workspace"]).run()?;

    Cmd::new("git")
        .arg("add")
        .args(contents.iter().map(|(path, _)| *path))
        .arg("Cargo.lock")
        .run()?;
    // Nothing to commit when the tree already carries this version.
    if git(&["diff", "--cached", "--quiet"]).is_err() {
        Cmd::new("git")
            .args(["commit", "-m", &format!("release: {tag_name}")])
            .run()?;
    }
    println!();
    if tag {
        Cmd::new("git")
            .args(["tag", "-a", &tag_name, "-m", &tag_name])
            .run()?;
        println!(
            "Tagged {tag_name}. Publish it (release.yml builds and signs the image and the chart):"
        );
        println!("  git push --atomic origin {branch} {tag_name}");
    } else {
        println!(
            "Prepared {tag_name} on `{branch}`. Open a pull request; once it is merged and CI \
             on the merge commit (e2e and web-e2e included) is green, tag that commit:"
        );
        println!("  git tag -a {tag_name} -m {tag_name} <commit> && git push origin {tag_name}");
    }
    Ok(())
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
