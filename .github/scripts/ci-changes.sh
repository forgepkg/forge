#!/usr/bin/env bash
# Which job groups a change needs (ci.yml's `changes` job, #353). Writes
# `<group>=true|false` to $GITHUB_OUTPUT for every group below and a table to
# the job summary; without GitHub's files, it prints the lines.
#
# A pull request's merge commit is compared with its first parent, the base
# branch; a merge group with the commit it is built on (MERGE_GROUP_BASE):
# the base branch, or the merge group ahead of it in the queue. A group thus
# runs the jobs its own pull requests need. The ones ahead are checked by
# their own groups, and with "Only merge non-failing pull requests" the queue
# merges a group only once every group ahead of it passed as well. A push is
# compared with the branch's previous commit (PUSH_BEFORE), so a push to main
# runs the jobs of what it changed (#361): with the merge queue, the same
# commit already passed as a merge group. A push that sets a new workspace
# version (a release commit) needs every group, since the release gate wants
# every job of its run. A manual run given a base branch (DISPATCH_BASE, such
# as the default branch for a stacked pull request's branch) is
# compared with the commit it forked off that branch, as GitHub's compare API
# finds it. Any other event (a manual run without a base), a commit that
# cannot be fetched, or a diff that fails, needs every group.
#
# The groups are git pathspecs, each also covering this script (COMMON). A
# change to ci.yml counts for the groups of the jobs it changes (CI_JOB_GROUP).
#
# Usage: ci-changes.sh   (env: EVENT; MERGE_GROUP_BASE for a merge group,
#                          PUSH_BEFORE for a push, DISPATCH_BASE and GH_TOKEN
#                          for a manual run)

# The group arrays are read by name, in changed().
# shellcheck disable=SC2034
set -uo pipefail

COMMON=(.github/scripts/ci-changes.sh)

# ci.yml, sorted by job (#365): a change to a job's lines needs the group that
# runs the job, and with it that group's other jobs; a change to any other
# line (the triggers, the settings, the `changes` job) or to a job missing
# here needs every group. Blank and comment lines do not count, a `#` line of
# a `run:` script being a shell comment too. (A YAML anchor shared by several
# jobs would hide a change from the jobs using it; ci.yml has none.)
CI=.github/workflows/ci.yml
declare -A CI_JOB_GROUP=(
    [fmt]=changelog [clippy]=rust [audit]=audit [test]=rust
    [docker]=image [kubernetes]=kubernetes [web]=web [oci-e2e]=rust
    [raw-e2e]=rust [e2e]=rust [web-e2e]=web
)

# Rust: the workspace, what its build and tests read from outside the crates
# (web/index.html and docker/forge.docker.toml are compiled in), and the
# scripts the Rust jobs run. Not .cargo/audit.toml, which only cargo-audit
# reads.
RUST=(
    Cargo.toml Cargo.lock rust-toolchain.toml .cargo ':(exclude).cargo/audit.toml'
    crates xtask migrations .sqlx fixtures
    web/index.html docker/forge.docker.toml
    .github/scripts/test-parallel.sh .github/scripts/test-timings-runner.sh
    .github/scripts/test-timings-summary.sh .github/scripts/oci-e2e.sh
    .github/scripts/raw-e2e.sh
)
# fmt's second check: the changelog fragments.
CHANGELOG=(docs/changes)
# What xtask's tests, which fmt runs too (#363), read from outside xtask: the
# version lines `cargo xtask release` sets, and the release workflow's channel
# script.
RELEASE=(
    web/package.json deploy/kubernetes/base/kustomization.yaml deploy/helm/forge/Chart.yaml
    .github/scripts/release-channels.sh
)
AUDIT=(Cargo.lock .cargo/audit.toml)
WEB=(web)
# What the image is built from beyond the sources clippy, test and web check,
# and what its smoke test reads.
IMAGE=(
    Dockerfile .dockerignore docker LICENSE
    ':(glob)**/Cargo.toml' Cargo.lock rust-toolchain.toml .cargo ':(exclude).cargo/audit.toml'
    web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml web/.npmrc
    .github/scripts/image-smoke.sh fixtures/nuget/sample.lib.1.0.0.nupkg
)
# The kubernetes job: the manifests and the chart, and what its digest-pin
# check reads besides them (Dockerfiles, the workflows).
KUBERNETES=(
    deploy
    ':(glob)**/Dockerfile' ':(glob)**/*.Dockerfile' ':(glob)**/Containerfile'
    .github/workflows
    .github/scripts/image-pin-check.sh .github/scripts/kustomize-check.sh
    .github/scripts/helm-check.sh
)
JOB_GROUPS=(rust changelog release audit web image kubernetes)

out=${GITHUB_OUTPUT:-/dev/stdout}
summary=${GITHUB_STEP_SUMMARY:-/dev/null}

# use_base <commit>: compare with it, fetched unless the checkout has it.
# Fails for no commit (a new branch's push names 40 zeros) or one that cannot
# be fetched.
use_base() {
    [ -n "$1" ] && [ "$1" != 0000000000000000000000000000000000000000 ] || return 1
    git cat-file -e "$1^{commit}" 2>/dev/null ||
        git fetch --quiet --no-tags --depth=1 origin "$1" || return 1
    base=$1
}

base=
reason="${EVENT:-no event}, or no commit to compare with"
case ${EVENT:-} in
pull_request) base=HEAD^1 ;;
merge_group) use_base "${MERGE_GROUP_BASE:-}" ;;
push)
    if use_base "${PUSH_BEFORE:-}"; then
        # Captured, not piped into grep: with pipefail, grep -q stopping
        # early could fail the pipeline through git's SIGPIPE.
        manifest=$(git diff "$base" HEAD -- Cargo.toml)
        if grep -qE '^[-+]version = ' <<<"$manifest"; then
            base=
            reason="the push sets a new workspace version"
        fi
    fi
    ;;
workflow_dispatch)
    if [ -n "${DISPATCH_BASE:-}" ] &&
        fork=$(gh api "repos/$GITHUB_REPOSITORY/compare/$DISPATCH_BASE...$(git rev-parse HEAD)" \
            --jq .merge_base_commit.sha); then
        use_base "$fork"
    fi
    ;;
esac

# ci_lines <commit>: ci.yml's lines at the commit but the blank and comment
# ones, each after the job it belongs to, or `-` outside the jobs.
ci_lines() {
    git show "$1:$CI" | awk '
        /^[ \t]*(#|$)/ { next }
        /^[^ ]/ { jobs = /^jobs:/; job = "-" }
        jobs && /^  [^ ]/ { job = $1; sub(/:$/, "", job) }
        { print job "\t" $0 }'
}

# ci_jobs: the jobs whose lines the change of ci.yml changes, `-` for the
# lines outside the jobs. Fails when ci.yml cannot be read.
ci_jobs() {
    local old new
    old=$(ci_lines "$base") && new=$(ci_lines HEAD) || return 1
    # diff's status 1 means "different", not a failure.
    { diff <(printf '%s\n' "$old") <(printf '%s\n' "$new") || [ $? = 1 ]; } |
        awk -F '\t' '/^[<>] / { print substr($1, 3) }' | sort -u
}

# ci_groups: the groups the change of ci.yml needs, `all` for every group.
ci_groups=
ci_changes=
if [ -n "$base" ] && ! git diff --quiet "$base" HEAD -- "$CI"; then
    if jobs=$(ci_jobs); then
        for job in $jobs; do
            ci_groups+=" ${CI_JOB_GROUP[$job]:-all}"
            [ "$job" != - ] || job="lines outside the jobs"
            ci_changes+="${ci_changes:+, }$job"
        done
    else
        ci_changes="cannot be compared"
        ci_groups=all
    fi
fi

# changed <GROUP> <group>: whether the change touches the group's paths,
# COMMON, or a ci.yml job of the group. Without a base, or when the diff
# fails (exit status 128), it does.
changed() {
    local -n paths=$1
    [ -n "$base" ] || return 0
    case " $ci_groups " in *" all "* | *" $2 "*) return 0 ;; esac
    ! git diff --quiet "$base" HEAD -- "${paths[@]}" "${COMMON[@]}"
}

{
    echo "| Group | Runs |"
    echo "|---|---|"
} >>"$summary"
for group in "${JOB_GROUPS[@]}"; do
    if changed "${group^^}" "$group"; then run=true; else run=false; fi
    echo "$group=$run" >>"$out"
    echo "| $group | $run |" >>"$summary"
done
if [ -z "$base" ]; then
    echo "Every group runs ($reason)." >>"$summary"
else
    echo "Compared with $(git rev-parse --short "$base" 2>/dev/null || echo "$base")." >>"$summary"
    if [ -n "$ci_changes" ]; then
        echo "ci.yml changes: $ci_changes." >>"$summary"
    fi
fi
