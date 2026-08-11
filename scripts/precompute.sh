#!/usr/bin/env bash
#
# Run the offline ("prep") phase for a circuit and persist it to
# <circuit_dir>/target/precompute.bin, so that later `--prove` runs skip
# setup + prep entirely.
#
# This is the expensive step: it commits the whole invariant witness. Expect it
# to be slow and to write a multi-gigabyte artifact (the prover key and the
# prepared state dominate). The script therefore refuses to start unless enough
# free disk space is available.
#
# Usage:
#   scripts/precompute.sh                                  # c0201_sicpa_backend
#   scripts/precompute.sh circuits/c0200_swiyu_jwt
#   REQUIRED_GB=8 scripts/precompute.sh circuits/c0201_sicpa_backend
#
# Prerequisites (all cheap to check, see below):
#   * <circuit_dir>/target/<name>.json      — built with nargo-t256
#   * <circuit_dir>/target/<name>.gz        — solved witness (nargo-t256 execute)
#   * <circuit_dir>/verifier_input.json     — produced by the preprocessor
#   * <circuit_dir>/online.json             — the online/invariant partition
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_DIR="$(cd "${1:-$ROOT/circuits/c0201_sicpa_backend}" && pwd)"
NAME="$(basename "$CIRCUIT_DIR")"
BACKEND_DIR="$ROOT/spartan-backend"
REQUIRED_GB="${REQUIRED_GB:-6}"

echo ">> circuit: $NAME ($CIRCUIT_DIR)"

# --- prerequisites -----------------------------------------------------------
missing=0
for f in "target/$NAME.json" "target/$NAME.gz" "verifier_input.json"; do
  if [[ ! -f "$CIRCUIT_DIR/$f" ]]; then
    echo "!! missing $f — rebuild/execute the circuit and re-run the preprocessor" >&2
    missing=1
  fi
done
[[ $missing -eq 0 ]] || exit 1

if [[ ! -f "$CIRCUIT_DIR/online.json" ]]; then
  echo "!! no online.json: every witness would land in the online segment and the"
  echo "   precomputation would buy almost nothing. Declare the per-proof inputs first." >&2
  exit 1
fi

# --- cheap pre-flight: does the manifest produce a sound partition? ----------
# Walks the ACIR only; no synthesis, no proving. Skipped with SKIP_PREFLIGHT=1.
if [[ "${SKIP_PREFLIGHT:-0}" != "1" ]]; then
  echo ">> pre-flight: validating the online manifest / partition"
  (cd "$BACKEND_DIR" && cargo test --release --quiet noir::online:: -- --nocapture)
fi

# --- disk space --------------------------------------------------------------
avail_gb="$(df -g "$CIRCUIT_DIR" | awk 'NR==2 {print $4}')"
if [[ -n "$avail_gb" && "$avail_gb" -lt "$REQUIRED_GB" ]]; then
  echo "!! only ${avail_gb}GiB free on the target filesystem, need >= ${REQUIRED_GB}GiB" >&2
  echo "   (override with REQUIRED_GB=<n>)" >&2
  exit 1
fi

# --- the expensive part ------------------------------------------------------
echo ">> running setup + prep (this is the expensive step)"
cd "$BACKEND_DIR"
cargo build --release --quiet
time ./target/release/spartan-backend "$CIRCUIT_DIR" --precompute

ls -lh "$CIRCUIT_DIR/target/precompute.bin"
echo ">> done. Now prove with:"
echo "   ./target/release/spartan-backend $CIRCUIT_DIR --prove"
