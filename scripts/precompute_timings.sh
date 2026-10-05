#!/usr/bin/env bash
#
# Times the four phases of precomputed proving by running
# `spartan-backend --precompute` N times. That one command creates the
# pre-proof (setup + prep), writes it to <circuit_dir>/target/precompute.bin,
# reads it back and finalises it into the final proof. Prints the mean and
# minimum of each phase, then removes precompute.bin (it is >1 GiB for c0200).
#
# Usage:
#   scripts/precompute_timings.sh [RUNS]
#   CIRCUIT=circuits/c0201_sicpa_backend scripts/precompute_timings.sh 3
#
# Defaults: RUNS=5, CIRCUIT=circuits/c0200_swiyu_jwt.
#
# Note: the read happens right after the write in the same process, so it is
# most likely served from the OS page cache.
set -euo pipefail

RUNS="${1:-5}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_DIR="$(cd "${CIRCUIT:-$ROOT/circuits/c0200_swiyu_jwt}" && pwd)"
NAME="$(basename "$CIRCUIT_DIR")"
BIN="$ROOT/spartan-backend/target/release/spartan-backend"
LOG_DIR="$(mktemp -d)"

cleanup() {
    rm -f "$CIRCUIT_DIR/target/precompute.bin"
    rm -rf "$LOG_DIR"
}
trap cleanup EXIT

(cd "$ROOT/spartan-backend" && cargo build --release --quiet)

# Converts a Rust Duration debug string (e.g. 2.919s, 950.1ms, 12µs) to seconds.
to_seconds() {
    awk -v d="$1" 'BEGIN {
        if (d ~ /ms$/)      { sub(/ms$/, "", d); print d / 1e3 }
        else if (d ~ /µs$/) { sub(/µs$/, "", d); print d / 1e6 }
        else if (d ~ /ns$/) { sub(/ns$/, "", d); print d / 1e9 }
        else                { sub(/s$/, "", d);  print d }
    }'
}

# Extracts the duration that follows PATTERN on the first matching log line.
extract() {
    local pattern="$1" log="$2"
    to_seconds "$(grep -m1 -oE "$pattern[0-9.]+(ns|µs|ms|s)" "$log" | sed -E "s/^$pattern//")"
}

RESULTS="$LOG_DIR/results.tsv"
for i in $(seq 1 "$RUNS"); do
    log="$LOG_DIR/run_$i.log"
    RUST_LOG=info "$BIN" "$CIRCUIT_DIR" --precompute 2>"$log" >/dev/null

    create=$(extract "$NAME: precompute = " "$log")
    write=$(extract "to disk in " "$log")
    read=$(extract "from disk in " "$log")
    finalise=$(to_seconds "$(grep 'prove_precomputed{' "$log" | grep -m1 'spartan_backend: close' \
        | grep -oE 'time.busy=[0-9.]+(ns|µs|ms|s)' | sed 's/time.busy=//')")

    printf '%s\t%s\t%s\t%s\n' "$create" "$write" "$read" "$finalise" >>"$RESULTS"
    printf 'run %d/%d: create=%.3fs write=%.3fs read=%.3fs finalise=%.3fs\n' \
        "$i" "$RUNS" "$create" "$write" "$read" "$finalise"
done

SIZE_MIB=$(grep -m1 -oE '\([0-9.]+ MiB\)' "$LOG_DIR/run_1.log" | tr -d '()')
echo
echo "$NAME, $RUNS runs, precompute.bin = $SIZE_MIB"
awk -F'\t' '
    BEGIN { split("create write read finalise", names, " ") }
    {
        for (c = 1; c <= 4; c++) {
            sum[c] += $c
            if (NR == 1 || $c < min[c]) min[c] = $c
        }
    }
    END {
        printf "%-10s %10s %10s\n", "phase", "mean", "min"
        for (c = 1; c <= 4; c++)
            printf "%-10s %9.3fs %9.3fs\n", names[c], sum[c] / NR, min[c]
    }' "$RESULTS"
