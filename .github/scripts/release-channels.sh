#!/usr/bin/env bash
# Decide which floating image tags a release may move (used by release.yml).
#
# Usage: release-channels.sh <version> <default-branch-ref>
# Prints `latest=<bool>` and `line_latest=<bool>` (GITHUB_OUTPUT lines).
#
# `latest` goes only to the highest non-prerelease version, and
# `<major>.<minor>` only to the highest non-prerelease version of its line, so
# a prerelease or a patch to an older line never moves them. Only tags on the
# default branch count: a version tag pushed on any other branch is never
# released (release.yml refuses it), and must not keep a real release from
# moving the floating tags either.
set -euo pipefail

version="$1"
base="$2"

stable_tags() {
  git tag --list 'v*.*.*' --merged "$base" | sed 's/^v//' | grep -Ev -- '-' | sort -V || true
}

latest=false
line_latest=false
case "$version" in
  *-*) echo "prerelease: neither :latest nor :<major>.<minor> moves" >&2 ;;
  *)
    highest=$(stable_tags | tail -n 1)
    line="${version%.*}"
    highest_in_line=$(stable_tags | grep -E "^${line//./\\.}\.[0-9]+$" | tail -n 1 || true)
    [ "$version" = "$highest" ] && latest=true
    [ "$version" = "$highest_in_line" ] && line_latest=true
    echo "highest=$highest highest_in_line=$highest_in_line" >&2
    ;;
esac
echo "latest=$latest"
echo "line_latest=$line_latest"
