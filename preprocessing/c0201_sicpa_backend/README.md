# c0201_sicpa_backend preprocessing

Precomputes the ECDSA witnesses for the
[`c0201_sicpa_backend`](../../circuits/c0201_sicpa_backend) circuit (SICPA
backend SD-JWT holder binding).

Reads `../../circuits/c0201_sicpa_backend/Prover.toml` and computes:

- **JWT (issuer) ECDSA recovery** (c0102 "vanilla equation" style): `R_jwt_x`,
  `R_jwt_y`, `s_inv_jwt` — the recovered `R` point and `s^-1` for the issuer's
  signature over the JWT signing input.
- **Device ECDSA Crescent triple** (c0100 style): `R_dev_x/y`, `T_dev_x/y`,
  `U_dev_x/y` — the proof-of-possession triple for the device signature over
  `challenge_nonce`, built from its two halves `device_r` and `device_s`. Only
  `device_s` is a circuit input; `device_r` lives in `Prover.toml` purely for
  this step, which folds it into `T_dev`/`U_dev`.

The first run consumes the one-time `jwt_signature` field from `Prover.toml`;
subsequent runs proceed without it.

## Difference from `c0200_siyu_jwt`

Unlike `c0200_swiyu_jwt`, which hardcodes the ES256 header as a compile-time
constant, the SICPA header carries the issuer key and is therefore a **public
`encoded_header` input** to the circuit. This preprocessor reads
`encoded_header` from `Prover.toml` to reconstruct the exact signing input
(`encoded_header || "." || base64url(payload)`) that was hashed and signed, and
matches the same value used by the circuit.

Note also that `Prover.toml` here is produced by `create-prover.py`
(`toml.dumps`), which writes the `BoundedVec` inputs as `[table]` sections. The
precompute scalars are therefore injected *before* the first table header (they
would otherwise be parsed as nested keys of the last table).

## Run

```bash
cd preprocessing/c0201_sicpa_backend
cargo run --release
```

Writes the precomputed fields back into
`../../circuits/c0201_sicpa_backend/Prover.toml`.
