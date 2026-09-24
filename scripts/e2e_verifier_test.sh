#!/bin/bash -e

# True end-to-end check of `c020x_verifier`: for each circuit, compile +
# execute it, generate a real proof via the spartan-backend CLI, then feed
# that proof into c020x_verifier and confirm it accepts it. Unlike
# c020x_verifier's unit tests (which only exercise check_crescent_triple
# against Prover.toml fixtures), this exercises the full
# compile -> prove -> verify pipeline against a proof nobody hand-crafted.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

circuits=(
  c0200_swiyu_jwt
  c0202_sicpa_backend_constant
)

for name in "${circuits[@]}"; do
  circuit_dir="$repo_root/circuits/$name"
  echo "=== $name ==="

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

  cargo run --manifest-path "$repo_root/spartan-backend/Cargo.toml" -- \
    "$circuit_dir" --prove > "$proof_file"

  cargo run --manifest-path "$repo_root/c020x_verifier/Cargo.toml" -- \
    --circuit-dir "$circuit_dir" \
    --challenge-hash-hex "$challenge_hash_hex" \
    < "$proof_file"

  rm -f "$proof_file"
  trap - EXIT
done
