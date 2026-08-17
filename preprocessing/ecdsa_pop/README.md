# ecdsa_pop preprocessing

Precomputes the device-key **proof-of-possession** triple for the
[`c0100_holder_binding_crescent_style`](../../circuits/c0100_holder_binding_crescent_style)
circuit.

Reads `../../circuits/c0100_holder_binding_crescent_style/Prover.toml`,
extracts the device public key from `credential_string`, and — from the device
signature halves (`device_r`, `device_s`) and the `challenge_hash` — computes
the Crescent proof-of-possession triple `(R, T, U)`, emitting `R_x/y`, `T_x/y`,
`U_x/y`. Only `device_s` is a circuit input; `device_r` lives in `Prover.toml`
purely for this preprocessing step, which folds it into `T` and `U`.

It sanity-checks that the extracted holder key is a valid P-256 point before
computing. The `(R, T, U)` math lives in
[`src/pop_precomputation.rs`](src/pop_precomputation.rs).

## Run

```bash
cd preprocessing/ecdsa_pop
cargo run --release
```

Writes the precomputed fields back into `Prover.toml` in place (replacing any
existing `R/T/U` fields, or appending them on the first run).
