# Preprocessing tools

Off-circuit helpers that precompute the ECDSA-related values a circuit needs but
cannot (cheaply) derive inside the proof. Each tool reads the `Prover.toml` of a
specific circuit in [`../circuits`](../circuits), performs the elliptic-curve
math on the host (P-256 / secp256r1), and injects the precomputed witnesses back
into that circuit's inputs.

These are standalone Cargo crates (not part of a workspace). Run each one from
**inside its own directory** so the `../../circuits/...` relative paths resolve:

```bash
cd preprocessing/<tool>
cargo run --release
```

## Tools

| Directory                              | Target circuit                        | What it precomputes                                              | Output |
|----------------------------------------|---------------------------------------|-----------------------------------------------------------------|--------|
| [`c0200_siyu_jwt`](c0200_siyu_jwt)     | `c0200_swiyu_jwt`                      | JWT (issuer) ECDSA recovery + device ECDSA Crescent triple      | writes `Prover.toml` and `verifier_input.json` in place |
| [`ecdsa_pok`](ecdsa_pok)               | `c0102_signature_vanilla_equation`    | Vanilla ECDSA recovery point `R` and `s⁻¹`                      | prints updated `Prover.toml` to stdout |
| [`ecdsa_pop`](ecdsa_pop)               | `c0100_holder_binding_crescent_style` | Device-key proof-of-possession triple `(R, T, U)`               | writes `Prover.toml` in place |
| [`zkattest_pok`](zkattest_pok)         | `c0101_signature_pok_zkattest_style`  | ZKAttest-style `z = s·r⁻¹`, recovered `R`, and `r⁻¹·G`          | prints updated `Prover.toml` to stdout |

See each subdirectory's `README.md` for details.
