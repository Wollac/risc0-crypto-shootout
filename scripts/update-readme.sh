#!/usr/bin/env bash
# Splice the contents of $2 into $1 between `<!-- BENCH-START -->` and
# `<!-- BENCH-END -->` markers. Idempotent: re-running with the same input
# leaves the file unchanged.
set -euo pipefail

readme=${1:?usage: update-readme.sh README.md results.md}
results=${2:?usage: update-readme.sh README.md results.md}

start='<!-- BENCH-START -->'
end='<!-- BENCH-END -->'

grep -qF "$start" "$readme" || { echo "missing $start in $readme" >&2; exit 1; }
grep -qF "$end"   "$readme" || { echo "missing $end in $readme" >&2; exit 1; }

tmp=$(mktemp)
awk -v start="$start" -v end="$end" -v results="$results" '
  $0 == start {
    print
    while ((getline line < results) > 0) print line
    close(results)
    skip = 1
    next
  }
  $0 == end { skip = 0 }
  !skip
' "$readme" > "$tmp"

mv "$tmp" "$readme"
