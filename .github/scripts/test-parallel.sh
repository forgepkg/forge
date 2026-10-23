#!/usr/bin/env bash
# `cargo test` with the test binaries run side by side (ci.yml's test job,
# #340). cargo runs one test binary at a time, and every integration-test
# binary starts Postgres, versitygw and Redis containers of its own
# (tests/common), so a sequential run mostly waits for them. The binaries
# share no state, so they can run at the same time:
#
#   1. `cargo test` builds and runs the doc tests as usual, with this script
#      as its target runner: instead of running a test binary, it records how
#      cargo would have run it (working directory, environment, command line).
#   2. The recorded binaries then run FORGE_TEST_JOBS at a time (default: the
#      number of CPUs), each through the target runner set for cargo, if any
#      (CI: test-timings-runner.sh). A binary's output is printed in one piece
#      once it has finished, and the failed binaries are listed at the end.
#
# Usage: test-parallel.sh [cargo test arguments...]   e.g. --workspace
# Exits non-zero when the build, a doc test or a test binary failed.
set -uo pipefail

# Step 1, as cargo's target runner: record the invocation, run nothing.
# cargo runs its runner for one binary at a time, so the count numbers them.
if [ -n "${FORGE_TEST_RECORD:-}" ]; then
    run="$FORGE_TEST_RECORD/$(printf '%04d' "$(find "$FORGE_TEST_RECORD" -mindepth 1 -maxdepth 1 | wc -l)")"
    mkdir "$run" || exit 1
    pwd >"$run/cwd"
    env -0 >"$run/env"
    printf '%s\0' "$@" >"$run/argv"
    exit 0
fi

# The target runner cargo would have used, for step 2 (split at whitespace,
# as cargo splits it).
host=$(rustc -vV | sed -n 's/^host: //p')
runner_var="CARGO_TARGET_$(printf '%s' "$host" | tr '[:lower:]-' '[:upper:]_')_RUNNER"
read -ra runner <<<"${!runner_var:-}"
jobs=${FORGE_TEST_JOBS:-$(nproc)}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/runs"
: >"$work/lock"

# Step 1: build, run the doc tests, record the test binaries.
env "$runner_var=$(realpath "$0")" FORGE_TEST_RECORD="$work/runs" cargo test "$@"
cargo_status=$?
mapfile -t runs < <(find "$work/runs" -mindepth 1 -maxdepth 1 -type d | sort)
[ "${#runs[@]}" -gt 0 ] || exit "$cargo_status"

# Step 2: run one recorded binary as cargo would have, with the environment
# cargo gave it (minus the recording), and print its output in one piece.
run_one() {
    local run=$1 cwd entry name status start
    local -a vars=() recorded argv
    mapfile -d '' recorded <"$run/env"
    for entry in "${recorded[@]}"; do
        case $entry in
        FORGE_TEST_RECORD=* | "$runner_var"=*) ;;
        *) vars+=("$entry") ;;
        esac
    done
    [ -z "${!runner_var:-}" ] || vars+=("$runner_var=${!runner_var}")
    mapfile -d '' argv <"$run/argv"
    cwd=$(<"$run/cwd")
    name=${argv[0]#"$PWD"/}
    start=$SECONDS
    (cd "$cwd" && exec env -i "${vars[@]}" "${runner[@]}" "${argv[@]}") >"$run/out" 2>&1
    status=$?
    echo "$status" >"$run/status"
    {
        printf '\n     Running %s (%ds' "$name" "$((SECONDS - start))"
        [ "$status" -eq 0 ] && printf ')\n' || printf ', FAILED with %d)\n' "$status"
        cat "$run/out"
    } >"$run/block"
    flock "$work/lock" cat "$run/block"
}

printf '\nRunning the %d test binaries %d at a time.\n' "${#runs[@]}" "$jobs"
active=0
for run in "${runs[@]}"; do
    if [ "$active" -ge "$jobs" ]; then
        wait -n
        active=$((active - 1))
    fi
    run_one "$run" &
    active=$((active + 1))
done
wait

failed=()
for run in "${runs[@]}"; do
    if [ "$(cat "$run/status" 2>/dev/null)" != 0 ]; then
        mapfile -d '' argv <"$run/argv"
        failed+=("${argv[0]#"$PWD"/}")
    fi
done
echo
if [ "${#failed[@]}" -gt 0 ]; then
    printf 'error: %d of %d test binaries failed:\n' "${#failed[@]}" "${#runs[@]}"
    printf '  %s\n' "${failed[@]}"
    exit 101
fi
printf '%d test binaries passed.\n' "${#runs[@]}"
exit "$cargo_status"
