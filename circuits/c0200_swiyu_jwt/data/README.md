# c0200 test data

Everything in this directory is **test material for a demo credential issued by
the Swiyu *integration* environment**. The private keys below are throwaway demo
keys; they protect nothing and are committed on purpose so the benchmarks and
the challenge-resigning scripts run out of the box.

| File | What it is |
| --- | --- |
| `credential-sdjwt.txt` | The original SD-JWT (JWT + 24 disclosures) as handed out by the Swiyu E-ID demo issuer. Its `cnf` is the wallet's key, whose private half we do **not** have. |
| `sdjwt-payload.json` | The same payload with the `cnf` claim replaced by our own device (holder) public key. This is what the circuit actually proves over (`payload.storage` in `Prover.toml`). |
| `sdjwt-disclosures.json` | The disclosures of `credential-sdjwt.txt`, used to recover the `dob` salt/value pair that `Prover.toml` carries. |
| `holder_private_key.jwk` | P-256 private key of the device/holder key bound into `sdjwt-payload.json`'s `cnf`. Used to sign fresh challenges. |
| `holder_public_key.jwk` | Public half of the above; equals `cnf.x` / `cnf.y` byte for byte. |

## Provenance

The tooling lives in the sibling repository
[`eid-privacy/noir-experiments`](https://github.com/eid-privacy/noir-experiments),
under `circuits/tools` (a small Rust crate). The steps that produced the data
here were:

### 1. Key generation

```bash
cd noir-experiments/circuits/tools
cargo run --bin generate_keys -- device   # -> device.prv / device.pub (P-256, PKCS#8 PEM)
cargo run --bin generate_keys -- issuer   # -> issuer.prv / issuer.pub
```

* `device.{prv,pub}` is the holder / device-binding key. Its public point is
  `04:e0:28:7f:48:10:dc:55:…`, i.e. base64url
  `x = 4Ch_SBDcVSHipLePUBp8y5RH18VOlirVRtOt-tB-Y_Y`,
  `y = ePh6PDXQ2cbm53W6aL832Xr8LH5P-bScppq-5eMIl0A`.
* `issuer.{prv,pub}` re-signs the modified credential. Its public point is
  `04:a7:58:f2:69:ca:2d:2b:…`, which is exactly `issuer_pub_x` / `issuer_pub_y`
  in `../Prover.toml`.

### 2. Re-issuing the credential with our device key

`credential-sdjwt.txt`'s payload was copied to `sdjwt-payload.json` with `cnf`
(and its nested `cnf.jwk`) swapped for the `device.pub` coordinates, then
re-signed with the issuer key over the standard JWT signing input

```
base64url({"typ":"JWT","alg":"ES256"}) || "." || base64url(payload)
```

using the `generate_jwt_from_swiyu` / `sign_credential` bins of
`noir-experiments/circuits/tools` (ECDSA-P256-SHA256, normalised to low-s). The
resulting 64-byte `r||s` is `jwt_signature` in `../Prover.toml`, and the header
is hard-coded as `ENCODED_HEADER` in `../src/main.nr`.

Sanity check (from the circuit directory) — recomputes the signing input from
`Prover.toml` and verifies it against the committed issuer public key:

```bash
python3 - <<'PY'
import re, base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes

main = open("src/main.nr").read()
hdr = bytes(int(v) for v in re.search(
    r"global ENCODED_HEADER: \[u8; ENCODED_HEADER_LEN\] = \[(.*?)\];", main, re.S
).group(1).replace("\n", "").rstrip(",").split(","))

toml = open("Prover.toml").read()
arr = lambda n: bytes(int(v) for v in re.search(rf"^{n} = \[(.*?)\]", toml, re.S | re.M).group(1).split(","))
payload = arr(r"payload\.storage")[: int(re.search(r"payload.len = (\d+)", toml).group(1))]
sig, px, py = arr("jwt_signature"), arr("issuer_pub_x"), arr("issuer_pub_y")

pub = ec.EllipticCurvePublicNumbers(int.from_bytes(px, "big"), int.from_bytes(py, "big"),
                                    ec.SECP256R1()).public_key()
pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
           hdr + b"." + base64.urlsafe_b64encode(payload).rstrip(b"="),
           ec.ECDSA(hashes.SHA256()))
print("issuer signature over the modified payload: OK")
PY
```

### 3. PEM -> JWK conversion (how the two `.jwk` files here were written)

The Rust tooling emits PKCS#8 PEM; the Python signing scripts in `scripts/`
consume JWK (same convention as
`circuits/c0100_holder_binding_crescent_style/data`). The conversion was:

```bash
python3 - <<'PY'
import base64, json
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key

key = load_pem_private_key(Path("../noir-experiments/circuits/tools/device.prv").read_bytes(),
                           password=None)
pn = key.private_numbers()
b64 = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()
x, y, d = b64(pn.public_numbers.x), b64(pn.public_numbers.y), b64(pn.private_value)

data = Path("circuits/c0200_swiyu_jwt/data")
cnf = json.loads((data / "sdjwt-payload.json").read_text())["cnf"]
assert (cnf["x"], cnf["y"]) == (x, y), "key does not match the credential's cnf"

for name, jwk in (
    ("holder_private_key.jwk", {"crv": "P-256", "d": d, "ext": True, "key_ops": ["sign"],
                                "kty": "EC", "x": x, "y": y}),
    ("holder_public_key.jwk",  {"crv": "P-256", "ext": True, "key_ops": ["verify"],
                                "kty": "EC", "x": x, "y": y}),
):
    (data / name).write_text(json.dumps(jwk, indent=2, sort_keys=True) + "\n")
PY
```

(run from the repository root, with `noir-experiments` checked out next to
`spartan-backend`).

## Using the key

`scripts/sign_prehashed_challenge.py` picks this key up automatically — it reads
`<circuit_dir>/data/holder_private_key.jwk` and defaults to this circuit:

```bash
python3 scripts/sign_prehashed_challenge.py                     # random nonce
python3 scripts/sign_prehashed_challenge.py <hex_32B_nonce>     # fixed nonce
python3 scripts/sign_prehashed_challenge.py --circuit <dir>     # another circuit
```

It prints TOML-ready `challenge_nonce` and `device_signature` lines. The c0200
circuit uses `challenge_nonce` **directly** as the ECDSA message hash `e`, so the
nonce is signed as an already-computed digest (`Prehashed`), never hashed again.

This is what `scripts/online_bench.sh` does for every extra challenge, before
re-running `preprocessing/c0200_siyu_jwt` (which recomputes the device Crescent
triple and would reject a signature made with any other key) and
`nargo execute`.
