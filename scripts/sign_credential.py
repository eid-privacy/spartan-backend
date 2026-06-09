#!/usr/bin/env python3
"""
Sign the fixed credential stored in data/fixed_credential.txt using the
issuer's private key from data/issuer_private_key.jwk.

Usage:
    python scripts/sign_credential.py

The credential is read as raw bytes (the file content, newlines stripped).
Signing: ECDSA-P256-SHA256, low-s canonical form.

Requires: cryptography  (pip install cryptography)
"""

import json
import sys
import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Order of the NIST P-256 (secp256r1) base point.
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def b64url_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def b64url_to_int(s: str) -> int:
    return int.from_bytes(b64url_decode(s), "big")


def fmt_hex(b: bytes) -> str:
    return b.hex()


def fmt_array(b: bytes) -> str:
    return str(list(b))


def canonicalize_low_s(s: int) -> int:
    """Return canonical low-s value for P-256 ECDSA signatures."""
    half_order = P256_ORDER // 2
    return s if s <= half_order else P256_ORDER - s


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def load_private_key(jwk_path: Path) -> ec.EllipticCurvePrivateKey:
    with open(jwk_path) as f:
        jwk = json.load(f)

    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("Only EC / P-256 keys are supported.")

    x = b64url_to_int(jwk["x"])
    y = b64url_to_int(jwk["y"])
    d = b64url_to_int(jwk["d"])

    pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    priv_numbers = ec.EllipticCurvePrivateNumbers(private_value=d, public_numbers=pub_numbers)
    return priv_numbers.private_key()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    scripts_dir = Path(__file__).resolve().parent
    data_dir = scripts_dir / "data"

    jwk_path = data_dir / "issuer_private_key.jwk"
    credential_path = data_dir / "fixed_credential.txt"

    for p in (jwk_path, credential_path):
        if not p.exists():
            print(f"Error: file not found at {p}", file=sys.stderr)
            sys.exit(1)

    # Read credential as raw bytes (strip trailing newline).
    credential = credential_path.read_bytes().rstrip(b"\n")

    # Load keys.
    private_key = load_private_key(jwk_path)
    public_key = private_key.public_key()
    pub_nums = public_key.public_numbers()

    pub_x = pub_nums.x.to_bytes(32, "big")
    pub_y = pub_nums.y.to_bytes(32, "big")

    # Sign with ECDSA P-256 + SHA-256, then enforce low-s.
    der_sig = private_key.sign(credential, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    s = canonicalize_low_s(s)
    der_sig = encode_dss_signature(r, s)
    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")
    sig_raw = r_bytes + s_bytes  # 64-byte raw (r || s), canonical low-s

    # Compute the SHA-256 digest of the credential for display.
    digest_ctx = hashes.Hash(hashes.SHA256())
    digest_ctx.update(credential)
    credential_hash = digest_ctx.finalize()

    # Sanity check: verify the produced signature.
    try:
        public_key.verify(der_sig, credential, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("Error: generated signature failed verification.", file=sys.stderr)
        sys.exit(1)

    # ---------------------------------------------------------------------------
    # Display
    # ---------------------------------------------------------------------------

    sep = "-" * 60

    print(sep)
    print("ISSUER PUBLIC KEY  (P-256, raw x || y, 64 bytes)")
    print(sep)
    print(f"  x    hex   : {fmt_hex(pub_x)}")
    print(f"  y    hex   : {fmt_hex(pub_y)}")
    print(f"  x    bytes : {fmt_array(pub_x)}")
    print(f"  y    bytes : {fmt_array(pub_y)}")

    print()
    print(sep)
    print("CREDENTIAL  (reference)")
    print(sep)
    print(f"  repr       : {credential!r}")

    print()
    print(sep)
    print("CREDENTIAL HASH  (SHA-256)")
    print(sep)
    print(f"  hex        : {fmt_hex(credential_hash)}")
    print(f"  bytes      : {fmt_array(credential_hash)}")

    print()
    print(sep)
    print("SIGNATURE  (ECDSA-P256-SHA256, raw r || s, 64 bytes, low-s)")
    print(sep)
    print(f"  full hex   : {fmt_hex(sig_raw)}")
    print(f"  full bytes : {fmt_array(sig_raw)}")
    print(f"  r    hex   : {fmt_hex(r_bytes)}")
    print(f"  s    hex   : {fmt_hex(s_bytes)}")
    print(f"  r    bytes : {fmt_array(r_bytes)}")
    print(f"  s    bytes : {fmt_array(s_bytes)}")
    print(sep)
    print("Signature verification: OK")


if __name__ == "__main__":
    main()
