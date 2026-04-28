#!/usr/bin/env bash
# Splice $2 into $1 between `<!-- BENCH-START -->` and `<!-- BENCH-END -->`
# markers. Idempotent: re-running with the same input leaves $1 unchanged.
set -euo pipefail

readme=${1:?usage: update-readme.sh README.md results.md}
results=${2:?usage: update-readme.sh README.md results.md}

start='<!-- BENCH-START -->'
end='<!-- BENCH-END -->'

tmp=$(mktemp "$(dirname "$readme")/.bench.XXXXXX")
trap 'rm -f "$tmp"' EXIT

awk -v start="$start" -v end="$end" -v results="$results" '
  $0 == start {
    print
    while ((getline line < results) > 0) print line
    close(results)
    seen_start = 1
    skip = 1
    next
  }
  $0 == end { seen_end = 1; skip = 0 }
  !skip
  END {
    if (!seen_start) { print "missing " start > "/dev/stderr"; exit 1 }
    if (!seen_end)   { print "missing " end   > "/dev/stderr"; exit 1 }
  }
' "$readme" > "$tmp"

mv "$tmp" "$readme"
trap - EXIT
