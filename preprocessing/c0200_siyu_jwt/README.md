# c0200_siyu_jwt preprocessing

Precomputes the ECDSA witnesses for the
[`c0200_swiyu_jwt`](../../circuits/c0200_swiyu_jwt) circuit (swiyu JWT holder
binding).

Reads `../../circuits/c0200_swiyu_jwt/Prover.toml` and computes:

- **JWT (issuer) ECDSA recovery**: `R_jwt_x`, `R_jwt_y`, `s_inv_jwt` — the
  recovered `R` point and `s⁻¹` for the issuer's signature over the JWT
  `payload` (with the fixed ES256 header).
- **Device ECDSA Crescent triple**: `R_dev_x/y`, `T_dev_x/y`, `U_dev_x/y` — the
  proof-of-possession triple for the device signature, built from its two
  halves `device_r` and `device_s`. Only `device_s` is a circuit input;
  `device_r` lives in `Prover.toml` purely for this step, which folds it into
  `T_dev`/`U_dev`.

The first run consumes the one-time `jwt_signature` field from `Prover.toml`;
subsequent runs proceed without it.

## Run

```bash
cd preprocessing/c0200_siyu_jwt
cargo run --release
```

Writes the precomputed fields back into
`../../circuits/c0200_swiyu_jwt/Prover.toml` and also produces
`../../circuits/c0200_swiyu_jwt/verifier_input.json`.
