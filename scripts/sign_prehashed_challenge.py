#!/usr/bin/env python3
"""
Sign a 32-byte *prehashed* challenge for the c0200 device ECDSA check.

The c0200 circuit / preprocessing treats `e = challenge_nonce` directly as the
ECDSA message hash (a 32-byte scalar), so a device signature is produced by
signing the challenge as an already-computed digest (Prehashed), NOT by hashing
it again.

Usage:
    python scripts/sign_prehashed_challenge.py [hex_32_byte_nonce]

If no nonce is given, a fresh random one (reduced mod the P-256 order) is used.
Prints TOML-ready `challenge_nonce` and `device_signature` byte arrays (r||s,
canonical low-s).

IMPORTANT — key selection:
    The signature must be produced with the *device* private key bound into the
    credential (the `cnf` JWK in the SD-JWT payload). Set the key path via the
    DEVICE_JWK environment variable. If unset, this falls back to the c0100
    holder key, which does NOT match the committed c0200 credential's device
    key, so the c0200 preprocessing will reject the signature. See
    scripts/online_bench.sh for the full pipeline and prerequisites.
"""

import os
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
    env_jwk = os.environ.get("DEVICE_JWK")
    if env_jwk:
        jwk_path = Path(env_jwk)
    else:
        jwk_path = (
            root
            / "circuits"
            / "c0100_holder_binding_crescent_style"
            / "data"
            / "holder_private_key.jwk"
        )
    if not jwk_path.exists():
        print(f"Error: JWK not found at {jwk_path}", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) >= 2:
        e = int(sys.argv[1], 16) % P256_ORDER
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
