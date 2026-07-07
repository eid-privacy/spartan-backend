# zkattest_pok preprocessing

Precomputes the ZKAttest-style signature proof-of-knowledge witnesses for the
[`c0101_signature_pok_zkattest_style`](../../circuits/c0101_signature_pok_zkattest_style)
circuit.

Reads `../../circuits/c0101_signature_pok_zkattest_style/Prover.toml` and, from
the issuer signature over `SHA-256(credential_string)`, computes:

```
z   = s·r⁻¹                     (ZKAttest equation scalar)
R   = h·s⁻¹·G + r·s⁻¹·Q         (recovered ECDSA R point)
r⁻¹G = r⁻¹·G
```

and emits `z`, `R_x`, `R_y`, `rg_x`, `rg_y`. It sanity-checks that `R.x == r`
before emitting.

An accompanying [`preprocessing.sage`](preprocessing.sage) contains the
reference derivation.

## Run

```bash
cd preprocessing/zkattest_pok
cargo run --release
```

Prints the full, updated `Prover.toml` to **stdout**. Redirect it to update the
circuit input, e.g.:

```bash
cargo run --release > ../../circuits/c0101_signature_pok_zkattest_style/Prover.toml
```
