#!/usr/bin/env python3
"""
Sign a 32-byte *prehashed* challenge for the c0200 device ECDSA check.

The circuit and its preprocessing treat `e = challenge_nonce` directly as the
ECDSA message hash, so the nonce is signed as an already-computed digest
(Prehashed), not hashed again.

Usage:
    python scripts/sign_prehashed_challenge.py [hex_32_byte_nonce] [--circuit DIR]

Without a nonce a fresh random one (reduced mod the P-256 order) is used. Prints
TOML-ready `challenge_nonce` and `device_signature` (r||s, canonical low-s).

The signing key is the device key bound into the credential (the `cnf` JWK of the
SD-JWT payload), read from `<circuit_dir>/data/holder_private_key.jwk` with
`circuit_dir` defaulting to `circuits/c0200_swiyu_jwt`. See that directory's
`data/README.md` for how the key and the credential were generated.
"""

import sys
import json
import base64
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    Prehashed,
)
from cryptography.hazmat.primitives import hashes

P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
DEFAULT_CIRCUIT = "circuits/c0200_swiyu_jwt"


def b64url_to_int(s: str) -> int:
    padded = s + "=" * (-len(s) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")


def canonicalize_low_s(s: int) -> int:
    half = P256_ORDER // 2
    return s if s <= half else P256_ORDER - s


def load_private_key(jwk_path: Path):
    jwk = json.loads(jwk_path.read_text())
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("Only EC / P-256 keys are supported.")
    x = b64url_to_int(jwk["x"])
    y = b64url_to_int(jwk["y"])
    d = b64url_to_int(jwk["d"])
    pub = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    return ec.EllipticCurvePrivateNumbers(private_value=d, public_numbers=pub).private_key()


def main() -> None:
    root = Path(__file__).resolve().parent.parent

    args = sys.argv[1:]
    circuit = None
    if "--circuit" in args:
        i = args.index("--circuit")
        try:
            circuit = args[i + 1]
        except IndexError:
            print("Error: --circuit needs a directory argument", file=sys.stderr)
            sys.exit(1)
        del args[i : i + 2]

    circuit_dir = Path(circuit) if circuit else root / DEFAULT_CIRCUIT
    if not circuit_dir.is_absolute():
        circuit_dir = (Path.cwd() / circuit_dir).resolve()
    jwk_path = circuit_dir / "data" / "holder_private_key.jwk"
    if not jwk_path.exists():
        print(f"Error: holder private key not found at {jwk_path}", file=sys.stderr)
        sys.exit(1)

    if args:
        e = int(args[0], 16) % P256_ORDER
    else:
        e = secrets.randbelow(P256_ORDER - 1) + 1
    e_bytes = e.to_bytes(32, "big")

    key = load_private_key(jwk_path)
    # Sign the 32-byte nonce as a precomputed digest (e = challenge_nonce).
    der = key.sign(e_bytes, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    s = canonicalize_low_s(s)
    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")
    sig = list(r_bytes + s_bytes)

    print("challenge_nonce = " + str(list(e_bytes)))
    print("device_signature = " + str(sig))


if __name__ == "__main__":
    main()
