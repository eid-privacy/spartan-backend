#!/bin/bash -e

# Compile every circuit with --deny-warnings so Noir compiler warnings (e.g.
# an unused public/private parameter) fail CI instead of silently piling up.
# `cargo`'s RUSTFLAGS="-D warnings" (see devbox's build-check script) doesn't
# reach nargo-t256, so circuits need this separate check.

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

# c9000_benchmark's src/const.nr is gitignored (benchmark.sh regenerates it
# per sweep step) and required for the circuit to compile at all, so a fresh
# checkout has nothing to compile until it's written.
"$DIR/benchmark.sh" --write-consts-only

for dir in circuits/c*/; do
  echo "$dir"
  (cd "$dir" && nargo-t256 compile --force --deny-warnings)
done
