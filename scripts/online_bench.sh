#!/usr/bin/env bash
#
# Online-proving benchmark, driven by the backend's public CLI: `--precompute`
# once, then `--prove` N times.
#
# `--precompute` persists the offline phase (`setup` + `prep`, which commits the
# invariant credential witness) to <circuit_dir>/target/precompute.bin, and
# `--prove` picks it up automatically. Since every `--prove` is a separate
# process it re-reads that (large) artifact, so the reported wall clock is split
# into "artifact load" (from the backend's `precompute_load` log event) and
# "prove". A non-amortized baseline run gives the speedup.
#
# Usage:
#   scripts/online_bench.sh [NUM_PROOFS] [NUM_EXTRA_CHALLENGES]
#   scripts/online_bench.sh 5 0
#   CIRCUIT=circuits/c0201_sicpa_backend scripts/online_bench.sh 3 0
#   BASELINE=0 scripts/online_bench.sh          # skip the non-amortized run
#
# Defaults: NUM_PROOFS=3, NUM_EXTRA_CHALLENGES=2, CIRCUIT=circuits/c0200_swiyu_jwt.
#
# With NUM_EXTRA_CHALLENGES > 0 the script generates distinct challenges. For
# each one it signs a fresh 32-byte prehashed nonce with the holder device key
# (<circuit_dir>/data/holder_private_key.jwk, the `cnf` key bound into the
# credential), patches Prover.toml, re-runs the circuit's preprocessing and
# `nargo-t256 execute`, then snapshots the circuit dir into a temp directory.
# The committed circuit inputs are backed up and restored at the end. Each
# snapshot hard-links the primary precompute.bin instead of copying it, which is
# sound because its fingerprint covers only the ACIR bytecode and online.json.
#
# Requirements: nargo-t256, python3 + cryptography, cargo.
set -euo pipefail

PROOFS="${1:-3}"
EXTRA="${2:-2}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_DIR="$(cd "${CIRCUIT:-$ROOT/circuits/c0200_swiyu_jwt}" && pwd)"
NAME="$(basename "$CIRCUIT_DIR")"
PROVER_TOML="$CIRCUIT_DIR/Prover.toml"
VERIFIER_JSON="$CIRCUIT_DIR/verifier_input.json"
BACKEND_DIR="$ROOT/spartan-backend"
BACKEND="$BACKEND_DIR/target/release/spartan-backend"
ARTIFACT="$CIRCUIT_DIR/target/precompute.bin"
BASELINE="${BASELINE:-1}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/${NAME}_online.XXXXXX")"

# The preprocessing crate is only needed to regenerate challenges.
case "$NAME" in
  c0200_swiyu_jwt) DEFAULT_PREP="$ROOT/preprocessing/c0200_siyu_jwt" ;;
  *)               DEFAULT_PREP="$ROOT/preprocessing/$NAME" ;;
esac
PREP_DIR="${PREP_DIR:-$DEFAULT_PREP}"

echo ">> circuit:   $NAME ($CIRCUIT_DIR)"
echo ">> workspace: $WORK"
echo ">> proofs:    $PROOFS on the primary circuit + $EXTRA distinct challenge(s)"

if [[ ! -f "$CIRCUIT_DIR/online.json" ]]; then
  echo "!! $NAME has no online.json: everything would land in the online segment"
  echo "   and precomputing would buy nothing. Declare the per-proof inputs first." >&2
  exit 1
fi

# --- timing helpers ----------------------------------------------------------
# `date +%s%N` is GNU-only; fall back to python3 on stock macOS.
now_ms() {
  local t
  t="$(date +%s%N 2>/dev/null || true)"
  if [[ "$t" =~ ^[0-9]+$ ]]; then
    echo $((t / 1000000))
  else
    python3 -c 'import time; print(int(time.time()*1000))'
  fi
}

fmt_s() { python3 -c "print(f'{$1/1000:.3f}s')"; }

# Runs `--prove` on a circuit dir. Writes the base64 proof to $2 and echoes
# "<wall_ms> <load_ms>" where load_ms is the time the backend spent reading
# precompute.bin (0 when it proved without an artifact).
timed_prove() {
  local dir="$1" out="$2" log="$WORK/prove.log" start end wall load
  start="$(now_ms)"
  RUST_LOG="${RUST_LOG:-info}" "$BACKEND" "$dir" --prove >"$out" 2>"$log"
  end="$(now_ms)"
  wall=$((end - start))
  # e.g. `... precompute_load elapsed_ms=812 size_bytes=1647218688`
  load="$(sed -n 's/.*precompute_load.*elapsed_ms=\([0-9]*\).*/\1/p' "$log" | tail -1)"
  echo "$wall ${load:-0}"
}

report_prove() {
  local label="$1" wall="$2" load="$3"
  printf '   %-28s wall=%-9s load=%-9s prove=%s\n' \
    "$label" "$(fmt_s "$wall")" "$(fmt_s "$load")" "$(fmt_s $((wall - load)))"
}

# --- build -------------------------------------------------------------------
echo ">> building the backend (release)"
( cd "$BACKEND_DIR" && cargo build --release --quiet )

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

# --- generate distinct challenges -------------------------------------------
CHALLENGE_DIRS=()
for ((i = 1; i <= EXTRA; i++)); do
  echo ">> === generating distinct challenge $i/$EXTRA ==="
  # Always start from the pristine Prover.toml (keeps jwt_signature present,
  # which the preprocessor consumes on each run).
  cp "$BACKUP/Prover.toml" "$PROVER_TOML"

  # 1. fresh prehashed signature
  SIGN_OUT="$(python3 "$ROOT/scripts/sign_prehashed_challenge.py" --circuit "$CIRCUIT_DIR")"
  NONCE_LINE="$(echo "$SIGN_OUT" | grep '^challenge_nonce = ')"
  R_LINE="$(echo "$SIGN_OUT" | grep '^device_r = ')"
  S_LINE="$(echo "$SIGN_OUT" | grep '^device_s = ')"

  # 2. patch Prover.toml (replace the three online lines)
  python3 - "$PROVER_TOML" "$NONCE_LINE" "$R_LINE" "$S_LINE" <<'PY'
import sys
path, nonce_line, r_line, s_line = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
out = []
for line in open(path):
    if line.startswith("challenge_nonce = "):
        out.append(nonce_line + "\n")
    elif line.startswith("device_r = "):
        out.append(r_line + "\n")
    elif line.startswith("device_s = "):
        out.append(s_line + "\n")
    else:
        out.append(line)
open(path, "w").writelines(out)
PY

  # 3. preprocessing: recompute device triple + verifier_input.json
  ( cd "$PREP_DIR" && cargo run --release --quiet )

  # 4. regenerate the solved witness
  ( cd "$CIRCUIT_DIR" && nargo-t256 execute --force >/dev/null )

  # 5. snapshot the circuit dir. The backend resolves target files as
  #    <dir>/target/<basename>.json, so the snapshot MUST keep the circuit's
  #    canonical directory name. precompute.bin is excluded: it is linked in
  #    later instead of copied.
  DEST="$WORK/challenge_$i/$NAME"
  mkdir -p "$DEST"
  ( cd "$CIRCUIT_DIR" && tar --exclude='./target/precompute.bin' -cf - . ) \
    | ( cd "$DEST" && tar -xf - )
  CHALLENGE_DIRS+=("$DEST")
done

# Restore before proving so the PRIMARY circuit uses the committed inputs.
restore
trap - EXIT

# --- baseline: prove without the precomputed artifact ------------------------
BASE_WALL=0
if [[ "$BASELINE" == "1" ]]; then
  echo ">> === baseline: one --prove WITHOUT precompute.bin ==="
  STASHED=""
  if [[ -f "$ARTIFACT" ]]; then
    STASHED="$ARTIFACT.bench-stash"
    mv "$ARTIFACT" "$STASHED" # same filesystem: instant, even at 35 GiB
  fi
  read -r BASE_WALL _ < <(timed_prove "$CIRCUIT_DIR" "$WORK/baseline.b64")
  [[ -n "$STASHED" ]] && mv "$STASHED" "$ARTIFACT"
  echo "   baseline (setup + prep + prove) = $(fmt_s "$BASE_WALL")"
fi

# --- offline phase -----------------------------------------------------------
echo ">> === offline phase: --precompute (one-off) ==="
T0="$(now_ms)"
"$BACKEND" "$CIRCUIT_DIR" --precompute
T1="$(now_ms)"
PREP_WALL=$((T1 - T0))
ARTIFACT_MIB="$(python3 -c "import os;print(f'{os.path.getsize(\"$ARTIFACT\")/1048576:.1f}')")"
echo "   precompute wall = $(fmt_s "$PREP_WALL"), artifact = ${ARTIFACT_MIB} MiB"

# Link (never copy) the artifact into each challenge snapshot.
for ((idx = 0; idx < ${#CHALLENGE_DIRS[@]}; idx++)); do
  dir="${CHALLENGE_DIRS[$idx]}"
  ln "$ARTIFACT" "$dir/target/precompute.bin" 2>/dev/null \
    || ln -s "$ARTIFACT" "$dir/target/precompute.bin"
done

# --- online phase ------------------------------------------------------------
echo ">> === online phase: $PROOFS x --prove on the primary circuit ==="
FIRST_WALL=0; FIRST_LOAD=0
WARM_WALL=0;  WARM_LOAD=0
for ((i = 1; i <= PROOFS; i++)); do
  read -r W L < <(timed_prove "$CIRCUIT_DIR" "$WORK/proof_$i.b64")
  report_prove "proof $i/$PROOFS" "$W" "$L"
  if [[ "$i" == "1" ]]; then
    FIRST_WALL="$W"; FIRST_LOAD="$L"
  else
    WARM_WALL=$((WARM_WALL + W)); WARM_LOAD=$((WARM_LOAD + L))
  fi
done

for ((idx = 0; idx < ${#CHALLENGE_DIRS[@]}; idx++)); do
  dir="${CHALLENGE_DIRS[$idx]}"
  read -r W L < <(timed_prove "$dir" "$WORK/challenge_$((idx + 1)).b64")
  report_prove "distinct challenge $((idx + 1))" "$W" "$L"
done

# --- correctness -------------------------------------------------------------
echo ">> === verifying one proof per distinct circuit ==="
verify_one() {
  local dir="$1" proof="$2" label="$3" start end
  start="$(now_ms)"
  "$BACKEND" "$dir" --verify "$(cat "$proof")" >/dev/null 2>&1
  end="$(now_ms)"
  echo "   $label verified in $(fmt_s $((end - start))) (includes verifier setup)"
}
verify_one "$CIRCUIT_DIR" "$WORK/proof_1.b64" "primary"
for ((idx = 0; idx < ${#CHALLENGE_DIRS[@]}; idx++)); do
  verify_one "${CHALLENGE_DIRS[$idx]}" "$WORK/challenge_$((idx + 1)).b64" \
    "distinct challenge $((idx + 1))"
done

# --- summary -----------------------------------------------------------------
echo ">> === summary ($NAME) ==="
echo "   offline (--precompute, one-off) = $(fmt_s "$PREP_WALL"), ${ARTIFACT_MIB} MiB on disk"
report_prove "first online proof" "$FIRST_WALL" "$FIRST_LOAD"
if [[ "$PROOFS" -gt 1 ]]; then
  N=$((PROOFS - 1))
  report_prove "warm online avg ($N samples)" $((WARM_WALL / N)) $((WARM_LOAD / N))
fi
if [[ "$BASELINE" == "1" && "$FIRST_WALL" -gt 0 ]]; then
  python3 - "$BASE_WALL" "$FIRST_WALL" "$FIRST_LOAD" <<'PY'
import sys
base, wall, load = (int(x) for x in sys.argv[1:4])
prove = max(wall - load, 1)
print(f"   baseline (no precompute)        = {base/1000:.3f}s")
print(f"   speedup, proving only           = {base/prove:.2f}x")
print(f"   speedup, end-to-end incl. load  = {base/max(wall,1):.2f}x")
PY
fi
echo "   note: every --prove reuses the SAME saved prep (it is not rewritten),"
echo "         so these are N proofs from one prepared state, not N rerandomized ones."
echo ">> done. temp dir: $WORK (safe to delete)"
