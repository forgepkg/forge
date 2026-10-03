//! The release workflow's floating-tag decision,
//! `.github/scripts/release-channels.sh`, against a scratch git repository.

use std::path::{Path, PathBuf};
use std::process::Command;

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/scripts/release-channels.sh")
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "release-test")
        .env("GIT_AUTHOR_EMAIL", "release-test@example.invalid")
        .env("GIT_COMMITTER_NAME", "release-test")
        .env("GIT_COMMITTER_EMAIL", "release-test@example.invalid")
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?}");
}

fn commit_and_tag(dir: &Path, tag: &str) {
    git(dir, &["commit", "-q", "--allow-empty", "-m", tag]);
    git(dir, &["tag", tag]);
}

fn channels(dir: &Path, version: &str) -> String {
    let out = Command::new("bash")
        .arg(script())
        .args([version, "main"])
        .current_dir(dir)
        .output()
        .expect("run release-channels.sh");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn only_default_branch_tags_decide_the_floating_tags() {
    let dir = std::env::temp_dir().join(format!("forge-release-channels-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    git(&dir, &["init", "-q", "-b", "main"]);
    commit_and_tag(&dir, "v1.0.0");
    commit_and_tag(&dir, "v1.1.0");
    // Version tags pushed on another branch: never released, so they must
    // not keep 1.1.0 from becoming `latest` / `1.1`.
    git(&dir, &["checkout", "-q", "-b", "stray"]);
    commit_and_tag(&dir, "v9.0.0");
    commit_and_tag(&dir, "v1.1.7");
    git(&dir, &["checkout", "-q", "main"]);

    assert_eq!(channels(&dir, "1.1.0"), "latest=true\nline_latest=true\n");
    // An older line's newest release moves only its own line.
    assert_eq!(channels(&dir, "1.0.0"), "latest=false\nline_latest=true\n");
    // A prerelease moves neither.
    assert_eq!(
        channels(&dir, "1.2.0-rc.1"),
        "latest=false\nline_latest=false\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
