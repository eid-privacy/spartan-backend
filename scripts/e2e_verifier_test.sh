#!/bin/bash -e

# True end-to-end check of `c020x_verifier`: for each circuit, (re)create
# Prover.toml, compile + execute the circuit, generate a real proof via the
# spartan-backend CLI, then feed that proof into c020x_verifier and confirm
# it accepts it. Unlike c020x_verifier's unit tests (which only exercise
# check_crescent_triple against Prover.toml fixtures), this exercises the
# full create -> preprocess -> compile -> prove -> verify pipeline against a
# proof nobody hand-crafted.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

circuits=(
  c0200_swiyu_jwt
  c0203_sicpa_backend_move
)

for name in "${circuits[@]}"; do
  circuit_dir="$repo_root/circuits/$name"
  echo "=== $name ==="

  # Circuits with a create-prover.py get a fresh Prover.toml (new SD-JWT,
  # signatures, nonce) each run, followed by the c0201_sicpa_backend
  # preprocessor (schema-compatible with every sicpa_backend variant), which
  # recovers the JWT issuer's ECDSA R/s_inv and folds the device signature's
  # r into the Crescent T/U triple. c0200_swiyu_jwt has no create-prover.py:
  # its Prover.toml is a static fixture produced by external SD-JWT tooling,
  # so it is used as committed.
  if [[ -f "$circuit_dir/create-prover.py" ]]; then
    (cd "$circuit_dir" && python3 create-prover.py)

    # now_date is a verifier-asserted public input (see verifier_input.json):
    # the verifier trusts its own idea of "today" rather than whatever the
    # prover claims. create-prover.py just stamped today's date into
    # Prover.toml, so verifier_input.json's committed now_date needs to be
    # refreshed too, or the proof gets rejected on a stale public input.
    python3 - "$circuit_dir/Prover.toml" "$circuit_dir/verifier_input.json" <<'PY'
import sys
import json
import tomllib

prover_path, verifier_path = sys.argv[1], sys.argv[2]
with open(prover_path, "rb") as f:
    prover = tomllib.load(f)
with open(verifier_path) as f:
    verifier = json.load(f)
verifier["now_date"] = prover["now_date"]
with open(verifier_path, "w") as f:
    json.dump(verifier, f, indent=2)
PY

    cargo run --manifest-path "$repo_root/preprocessing/c0201_sicpa_backend/Cargo.toml" --release -- \
      "$circuit_dir/Prover.toml"
  fi

  (cd "$circuit_dir" && nargo-t256 compile --force && nargo-t256 execute --force)

  # challenge_hash_hex is the circuit's challenge_nonce (already the hashed
  # challenge M, see c020x_verifier's --challenge-hash-hex docs), hex-encoded.
  challenge_hash_hex=$(python3 - "$circuit_dir/Prover.toml" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as f:
    data = tomllib.load(f)
print(bytes(data["challenge_nonce"]).hex())
PY
)

  proof_file="$(mktemp)"
  trap 'rm -f "$proof_file"' EXIT

  cargo run --manifest-path "$repo_root/spartan-backend/Cargo.toml" --release -- \
    "$circuit_dir" --prove > "$proof_file"

  cargo run --manifest-path "$repo_root/c020x_verifier/Cargo.toml" --release -- \
    --circuit-dir "$circuit_dir" \
    --challenge-hash-hex "$challenge_hash_hex" \
    < "$proof_file"

  rm -f "$proof_file"
  trap - EXIT
done
