# ecdsa_pok preprocessing

Precomputes the vanilla-ECDSA recovery witnesses for the
[`c0102_signature_vanilla_equation`](../../circuits/c0102_signature_vanilla_equation)
circuit.

Reads `../../circuits/c0102_signature_vanilla_equation/Prover.toml` and computes
the standard ECDSA point recovery over the issuer signature:

```
t = SHA-256(credential_string)          (scalar)
R = t·s⁻¹·G + r·s⁻¹·Q
```

and emits `R_x`, `R_y`, and `s_inv`. It sanity-checks that `R.x == r` before
emitting.

## Run

```bash
cd preprocessing/ecdsa_pok
cargo run --release
```

Prints the full, updated `Prover.toml` (with previously precomputed fields
stripped and the new ones appended) to **stdout**. Redirect it to update the
circuit input, e.g.:

```bash
cargo run --release > ../../circuits/c0102_signature_vanilla_equation/Prover.toml
```
