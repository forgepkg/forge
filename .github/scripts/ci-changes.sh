#!/usr/bin/env bash
# Which job groups a change needs (ci.yml's `changes` job, #353). Writes
# `<group>=true|false` to $GITHUB_OUTPUT for every group below and a table to
# the job summary; without GitHub's files, it prints the lines.
#
# A pull request's merge commit is compared with its first parent, the base
# branch; a merge group with the base-branch commit it is built on
# (MERGE_GROUP_BASE), so the pull requests ahead of it in the queue count too.
# Any other event (a push, a manual run), or a diff that fails, needs every
# group.
#
# The groups are git pathspecs, each also covering the CI configuration
# (COMMON). Keep the `rules: changes` lists of .gitlab-ci.yml in step.
#
# Usage: ci-changes.sh   (env: EVENT, and MERGE_GROUP_BASE for merge groups)

# The group arrays are read by name, in changed().
# shellcheck disable=SC2034
set -uo pipefail

COMMON=(.github/workflows/ci.yml .github/scripts/ci-changes.sh)

# Rust: the workspace, what its build and tests read from outside the crates
# (web/index.html and docker/forge.docker.toml are compiled in; the release
# tests read the version lines of web/package.json, the Kubernetes base and
# the chart), and the scripts the Rust jobs run.
RUST=(
    Cargo.toml Cargo.lock rust-toolchain.toml .cargo
    crates plugins xtask migrations .sqlx fixtures
    web/index.html docker/forge.docker.toml
    web/package.json deploy/kubernetes/base/kustomization.yaml deploy/helm/forge/Chart.yaml
    .github/scripts
)
# fmt's second check: the changelog fragments.
CHANGELOG=(docs/changes)
AUDIT=(Cargo.lock .cargo/audit.toml)
WEB=(web)
# What the image is built from beyond the sources clippy, test and web check.
IMAGE=(
    Dockerfile .dockerignore docker LICENSE
    ':(glob)**/Cargo.toml' Cargo.lock rust-toolchain.toml .cargo
    web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml web/.npmrc
)
# The kubernetes job: the manifests and the chart, and what its digest-pin
# check reads besides them (Dockerfiles, the workflows, .gitlab-ci.yml).
KUBERNETES=(
    deploy
    ':(glob)**/Dockerfile' ':(glob)**/*.Dockerfile' ':(glob)**/Containerfile'
    .github/workflows .gitlab-ci.yml
    .github/scripts/image-pin-check.sh .github/scripts/kustomize-check.sh
    .github/scripts/helm-check.sh
)
JOB_GROUPS=(rust changelog audit web image kubernetes)

out=${GITHUB_OUTPUT:-/dev/stdout}
summary=${GITHUB_STEP_SUMMARY:-/dev/null}

base=
case ${EVENT:-} in
pull_request) base=HEAD^1 ;;
merge_group)
    if [ -n "${MERGE_GROUP_BASE:-}" ] &&
        git fetch --quiet --no-tags --depth=1 origin "$MERGE_GROUP_BASE"; then
        base=$MERGE_GROUP_BASE
    fi
    ;;
esac

# changed <GROUP>: whether the change touches the group's paths or COMMON.
# Without a base, or when the diff fails (exit status 128), it does.
changed() {
    local -n paths=$1
    [ -n "$base" ] || return 0
    ! git diff --quiet "$base" HEAD -- "${paths[@]}" "${COMMON[@]}"
}

{
    echo "| Group | Runs |"
    echo "|---|---|"
} >>"$summary"
for group in "${JOB_GROUPS[@]}"; do
    if changed "${group^^}"; then run=true; else run=false; fi
    echo "$group=$run" >>"$out"
    echo "| $group | $run |" >>"$summary"
done
if [ -z "$base" ]; then
    echo "Every group runs (${EVENT:-no event}, or no base to compare with)." >>"$summary"
else
    echo "Compared with $(git rev-parse --short "$base" 2>/dev/null || echo "$base")." >>"$summary"
fi
