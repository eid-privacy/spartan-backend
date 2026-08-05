#!/usr/bin/env bash
#
# Lever A end-to-end online-proving benchmark for c0200 with GENUINELY distinct
# challenges.
#
# For each extra challenge it:
#   1. signs a fresh 32-byte prehashed nonce with the holder device key,
#   2. patches circuits/c0200_swiyu_jwt/Prover.toml with the new
#      challenge_nonce + device_signature,
#   3. runs the c0200 preprocessing (recomputes the device Crescent triple and
#      verifier_input.json),
#   4. runs `nargo execute` to regenerate the solved witness (*.gz),
#   5. snapshots the whole circuit dir into a temp challenge directory.
#
# The committed circuit inputs are backed up first and restored at the end, so
# the repository is left unchanged. Finally it runs the backend once with
# `--online`, reusing a single prepared state across the primary (committed)
# circuit and every regenerated challenge via `--also`.
#
# PREREQUISITE — device signing key:
#   Each fresh challenge must be re-signed with the *device* private key that is
#   bound into the credential (the `cnf` JWK embedded in the SD-JWT payload).
#   For the committed c0200 credential that public key is `4Ch_SBDc...`, whose
#   private half is NOT stored in this repository, so the preprocessing step
#   (which verifies the device ECDSA signature) will reject signatures produced
#   with any other key and abort with "recovered r mismatch".
#
#   To run this end-to-end you must therefore either:
#     (a) supply the matching device private key JWK via DEVICE_JWK=<path>, or
#     (b) re-issue a fresh c0200 credential bound to a device key you control
#         (see scripts/sign_credential.py) and point this script at it.
#
#   Without the device secret, use the cheaper multi-directory reuse check
#   documented in plan-lever-a.md, which validates the identical online code
#   path with the committed (valid) challenge.
#
# Usage:
#   scripts/online_bench.sh [NUM_EXTRA_CHALLENGES]   # default 2
#   DEVICE_JWK=/path/to/device_private_key.jwk scripts/online_bench.sh 3
#
# Requirements: nargo, python3 + cryptography, cargo.
set -euo pipefail

EXTRA="${1:-2}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_DIR="$ROOT/circuits/c0200_swiyu_jwt"
PROVER_TOML="$CIRCUIT_DIR/Prover.toml"
VERIFIER_JSON="$CIRCUIT_DIR/verifier_input.json"
PREP_DIR="$ROOT/preprocessing/c0200_siyu_jwt"
BACKEND_DIR="$ROOT/spartan-backend"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/c0200_online.XXXXXX")"

echo ">> workspace: $WORK"

# --- back up committed inputs so the repo is left pristine -------------------
BACKUP="$WORK/backup"
mkdir -p "$BACKUP/target"
cp "$PROVER_TOML" "$BACKUP/Prover.toml"
cp "$VERIFIER_JSON" "$BACKUP/verifier_input.json" 2>/dev/null || true
cp "$CIRCUIT_DIR"/target/*.gz "$BACKUP/target/" 2>/dev/null || true

restore() {
  echo ">> restoring committed circuit inputs"
  cp "$BACKUP/Prover.toml" "$PROVER_TOML"
  cp "$BACKUP/verifier_input.json" "$VERIFIER_JSON" 2>/dev/null || true
  cp "$BACKUP"/target/*.gz "$CIRCUIT_DIR/target/" 2>/dev/null || true
}
trap restore EXIT

ALSO_ARGS=()
for i in $(seq 1 "$EXTRA"); do
  echo ">> === generating distinct challenge $i/$EXTRA ==="
  # Always start from the pristine Prover.toml (keeps jwt_signature present,
  # which the preprocessor consumes on each run).
  cp "$BACKUP/Prover.toml" "$PROVER_TOML"

  # 1. fresh prehashed signature
  SIGN_OUT="$(DEVICE_JWK="${DEVICE_JWK:-}" python3 "$ROOT/scripts/sign_prehashed_challenge.py")"
  NONCE_LINE="$(echo "$SIGN_OUT" | grep '^challenge_nonce = ')"
  SIG_LINE="$(echo "$SIGN_OUT" | grep '^device_signature = ')"

  # 2. patch Prover.toml (replace the two online lines)
  python3 - "$PROVER_TOML" "$NONCE_LINE" "$SIG_LINE" <<'PY'
import sys
path, nonce_line, sig_line = sys.argv[1], sys.argv[2], sys.argv[3]
out = []
for line in open(path):
    if line.startswith("challenge_nonce = "):
        out.append(nonce_line + "\n")
    elif line.startswith("device_signature = "):
        out.append(sig_line + "\n")
    else:
        out.append(line)
open(path, "w").writelines(out)
PY

  # 3. preprocessing: recompute device triple + verifier_input.json
  ( cd "$PREP_DIR" && cargo run --release --quiet )

  # 4. regenerate the solved witness
  ( cd "$CIRCUIT_DIR" && nargo execute --pedantic-solving >/dev/null )

  # 5. snapshot the circuit dir. The backend resolves target files as
  #    <dir>/target/<basename>.json, so the snapshot MUST keep the circuit's
  #    canonical directory name (c0200_swiyu_jwt).
  DEST="$WORK/challenge_$i/c0200_swiyu_jwt"
  mkdir -p "$DEST"
  cp -R "$CIRCUIT_DIR/." "$DEST/"
  ALSO_ARGS+=(--also "$DEST")
done

# Restore before proving so the PRIMARY circuit uses the committed inputs.
restore
trap - EXIT
rm -f "$WORK"/backup/Prover.toml

echo ">> === online proving: primary (committed) + $EXTRA distinct challenges ==="
( cd "$BACKEND_DIR" && cargo run --release --quiet -- \
    --online 1 --prep-dir "$WORK/prep" "${ALSO_ARGS[@]}" "$CIRCUIT_DIR" )

echo ">> done. temp dir: $WORK (safe to delete)"
