#!/bin/bash -e

# None of these crates are combined into a Cargo workspace (each has its own
# Cargo.toml), so `cargo test` from the repo root wouldn't reach them. Run
# each one explicitly so their test suites can't silently go unrun in CI.

crates=(
  spartan-backend
  algebra-utils
  c020x_verifier
  preprocessing/c0200_siyu_jwt
  preprocessing/c0201_sicpa_backend
  preprocessing/ecdsa_pop
  preprocessing/ecdsa_pok
  preprocessing/zkattest_pok
)

for crate in "${crates[@]}"; do
  echo "=== $crate ==="
  (cd "$crate" && RUSTFLAGS="-D warnings" cargo test)
done
