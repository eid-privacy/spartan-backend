# Experiment Background

This repo contains an SD-JWT experiment. The SD-JWT (credential) is produced by a Python script and consumed by the Noir circuits.
The script `create-prover.py` sets up the specific credential structure used in the
SICPA backend, which includes the public key of the issuer in the SD-JWT header.
This is different from the Swiyu-SD-JWT, which has a generic header, and a Web3-DID
in the body of the SD-JWT.
If you have devbox installed, you can create a new SD-JWT which will be written
to Prover.toml:

```bash
devbox shell
# inside devbox:
python3 create-prover.py
```

Once the Prover.toml is written, you can use the scripts from the `zkp-pocs/noir/scripts`
directory to run all benchmarks.

# Signature verification (Crescent + vanilla equation)

This circuit does **not** use Noir's built-in `std::ecdsa_secp256r1::verify_signature`.
Instead, following `c0200_swiyu_jwt`, it verifies:

- the **issuer JWT signature** with the "vanilla equation" style (cf.
  `c0102_signature_vanilla_equation`), consuming precomputed `R_jwt_x/y` and
  `s_inv_jwt` (private), and
- the **device signature** on `challenge_nonce` with the "Crescent" style (cf.
  `c0100_holder_binding_crescent_style`), consuming the precomputed public triple
  `R_dev_x/y`, `T_dev_x/y`, `U_dev_x/y` together with the private scalar
  `device_s`. The other signature half, `device_r`, is not a circuit input: it
  is read from `Prover.toml` by the preprocessor and folded into
  `T_dev`/`U_dev`.

These precomputed witnesses cannot (cheaply) be derived in-circuit, so after
running `create-prover.py` you must run the off-circuit preprocessor to inject
them into `Prover.toml`:

```bash
cd ../../preprocessing/c0201_sicpa_backend
cargo run --release
```

The end-to-end flow is therefore: `create-prover.py` → preprocessor →
`nargo-t256 execute` (and prove/verify with the spartan backend).
