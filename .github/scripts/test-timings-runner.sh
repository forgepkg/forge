#!/usr/bin/env bash
# Cargo target runner for `cargo test` in CI (ci.yml sets
# CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER to it): runs each test binary
# with libtest's per-test timings and records them for
# test-timings-summary.sh.
#
#   - `--report-time` appends each test's duration to its result line
#     (`test foo ... ok <1.234s>`); the binary's output is copied to
#     $FORGE_TEST_TIMINGS/<binary>.<pid>.log and its wall time appended to
#     $FORGE_TEST_TIMINGS/binaries.tsv.
#   - `--report-time` is an unstable libtest option: RUSTC_BOOTSTRAP=1
#     unlocks it on the stable toolchain, set here for the test process
#     alone. Set for cargo itself, it would change every crate's fingerprint
#     and rebuild the workspace.
#
# Doctests are run by rustdoc, not through the runner, and keep libtest's
# plain output.
#
# Usage (by cargo): test-timings-runner.sh <test binary> [libtest args...]
set -uo pipefail

dir=${FORGE_TEST_TIMINGS:?set FORGE_TEST_TIMINGS to a directory for the timings}
mkdir -p "$dir"
name=$(basename "$1")
name=${name%-*} # cargo's metadata hash
log="$dir/$name.$$.log"

start=$(date +%s%N)
RUSTC_BOOTSTRAP=1 "$@" -Z unstable-options --report-time | tee "$log"
status=${PIPESTATUS[0]}
end=$(date +%s%N)

printf '%s\t%d\t%s\n' "$name" $(((end - start) / 1000000)) "$log" >>"$dir/binaries.tsv"
exit "$status"
