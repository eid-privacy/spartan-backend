#!/usr/bin/env bash
# Time N `--prove` runs of the release backend on a circuit WITHOUT the
# precomputed artifact (setup + prep + prove each time), report avg and min.
#
# Usage: scripts/bench_no_precompute.sh [N] [circuit_dir]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
N="${1:-5}"
CIRCUIT_DIR="$(cd "${2:-$ROOT/circuits/c0200_swiyu_jwt}" && pwd)"
ARTIFACT="$CIRCUIT_DIR/target/precompute.bin"

( cd "$ROOT/spartan-backend" && cargo build --release -q )
BACKEND="$ROOT/spartan-backend/target/release/spartan-backend"

STASHED=""
if [[ -f "$ARTIFACT" ]]; then
  STASHED="$ARTIFACT.bench-stash"
  mv "$ARTIFACT" "$STASHED"
  trap 'mv "$STASHED" "$ARTIFACT"' EXIT
fi

TIMES=()
for i in $(seq 1 "$N"); do
  t0=$(python3 -c 'import time; print(time.perf_counter_ns())')
  "$BACKEND" "$CIRCUIT_DIR" --prove > /dev/null
  t1=$(python3 -c 'import time; print(time.perf_counter_ns())')
  t=$(python3 -c "print(f'{($t1-$t0)/1e9:.3f}')")
  echo "run $i: ${t}s"
  TIMES+=("$t")
done

python3 - "${TIMES[@]}" <<'PY'
import sys
t = [float(x) for x in sys.argv[1:]]
print(f"avg = {sum(t)/len(t):.3f}s  min = {min(t):.3f}s  (n={len(t)})")
PY
