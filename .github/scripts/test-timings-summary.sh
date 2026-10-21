#!/usr/bin/env bash
# Markdown summary of the timings test-timings-runner.sh recorded: the
# slowest test binaries (wall time) and the slowest tests. ci.yml appends it
# to the job summary ($GITHUB_STEP_SUMMARY); .gitlab-ci.yml prints it to the
# job log.
#
# A test's time runs from its start to its result. The tests of one binary
# run in parallel, so their times overlap, and a test waiting on a lock its
# binary's other tests hold counts the wait.
#
# Usage: test-timings-summary.sh <timings dir> [rows per table, default 25]
# Needs bash, GNU sort and a POSIX awk (mawk is enough).
set -euo pipefail

dir=$1
rows=${2:-25}
if [ ! -s "$dir/binaries.tsv" ]; then
  echo "No test timings recorded in $dir."
  exit 0
fi

tests=$(mktemp)
binaries=$(mktemp)
trap 'rm -f "$tests" "$binaries"' EXIT

# $tests: <seconds> TAB <result> TAB <binary> TAB <test>, per timed test.
# $binaries: <milliseconds> TAB <binary> TAB <timed tests>, per binary.
while IFS=$'\t' read -r name ms log; do
  [ -f "$log" ] || continue
  awk -v bin="$name" -v ms="$ms" -v tests="$tests" -v binaries="$binaries" '
    # test <name> ... <result> <1.234s>
    /^test .* \.\.\. [^ ]+ <[0-9.]+s>$/ {
      line = substr($0, 6)
      i = index(line, " ... ")
      rest = substr(line, i + 5)
      j = index(rest, " <")
      printf "%s\t%s\t%s\t%s\n", substr(rest, j + 2, length(rest) - j - 3),
        substr(rest, 1, j - 1), bin, substr(line, 1, i - 1) >> tests
      n++
    }
    END { printf "%d\t%s\t%d\n", ms, bin, n >> binaries }' "$log"
done <"$dir/binaries.tsv"

awk -F'\t' '{ n += $3; ms += $1; b++ }
  END {
    printf "### Test timings\n\n"
    printf "%d timed tests in %d test binaries, which ran one after another for %dm %02ds.\n\n",
      n, b, ms / 60000, (ms % 60000) / 1000
  }' "$binaries"

echo "| Slowest test binaries | Wall time | Tests |"
echo "|---|--:|--:|"
LC_ALL=C sort -t$'\t' -k1,1nr "$binaries" | head -n "$rows" |
  awk -F'\t' '{ printf "| `%s` | %.1f s | %d |\n", $2, $1 / 1000, $3 }'
echo
echo "| Slowest tests | Time | Binary |"
echo "|---|--:|---|"
LC_ALL=C sort -t$'\t' -k1,1nr "$tests" | head -n "$rows" |
  awk -F'\t' '{ printf "| `%s`%s | %.1f s | `%s` |\n", $4, ($2 == "ok" ? "" : " (" $2 ")"), $1, $3 }'
echo
echo "A test's time includes waiting on locks its binary's other tests hold; doctests are not timed."
