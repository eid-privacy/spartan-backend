#!/usr/bin/env python3
"""
Sign a base64-encoded challenge using the holder's private key from a JWK file.

Usage:
    python scripts/sign_challenge.py <base64_encoded_challenge>

The JWK file is expected at:
    circuits/c0100_holder_binding_crescent_style/data/holder_private_key.jwk
(relative to the workspace root, i.e. the parent directory of scripts/)

Requires: cryptography  (pip install cryptography  –– ships with most Python distros)
"""

import sys
import json
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
    """Decode a base64url string (with or without padding)."""
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
    if len(sys.argv) != 2:
        print("Usage: python sign_challenge.py <base64_encoded_challenge>")
        sys.exit(1)

    # Locate the JWK relative to this script's parent (workspace root)
    workspace_root = Path(__file__).resolve().parent.parent
    jwk_path = workspace_root / "circuits" / "c0100_holder_binding_crescent_style" / "data" / "holder_private_key.jwk"

    if not jwk_path.exists():
        print(f"Error: JWK file not found at {jwk_path}", file=sys.stderr)
        sys.exit(1)

    # Decode the challenge (accept standard or URL-safe base64, with or without padding)
    raw_b64 = sys.argv[1]
    try:
        challenge = base64.b64decode(raw_b64 + "=" * (-len(raw_b64) % 4))
    except Exception:
        try:
            challenge = b64url_decode(raw_b64)
        except Exception as exc:
            print(f"Error decoding challenge: {exc}", file=sys.stderr)
            sys.exit(1)

    # Load keys
    private_key = load_private_key(jwk_path)
    public_key = private_key.public_key()
    pub_nums = public_key.public_numbers()

    pub_x = pub_nums.x.to_bytes(32, "big")
    pub_y = pub_nums.y.to_bytes(32, "big")
    pub_uncompressed = b"\x04" + pub_x + pub_y

    # Sign with ECDSA P-256 + SHA-256.
    der_sig = private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    s = canonicalize_low_s(s)
    der_sig = encode_dss_signature(r, s)
    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")
    sig_raw = r_bytes + s_bytes  # 64-byte raw (r || s), canonical low-s

    # Compute digest for display (signing remains ECDSA(SHA-256) over challenge bytes).
    digest_ctx = hashes.Hash(hashes.SHA256())
    digest_ctx.update(challenge)
    challenge_hash = digest_ctx.finalize()

    # Sanity check: the freshly produced signature must verify with the public key.
    try:
        public_key.verify(der_sig, challenge, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("Error: generated signature failed verification.", file=sys.stderr)
        sys.exit(1)

    # ---------------------------------------------------------------------------
    # Display
    # ---------------------------------------------------------------------------

    sep = "-" * 60

    print(sep)
    print("PUBLIC KEY  (P-256, uncompressed 04 || x || y, 65 bytes)")
    print(sep)
    print(f"  full hex   : {fmt_hex(pub_uncompressed)}")
    print(f"  full bytes : {fmt_array(pub_uncompressed)}")
    print(f"  x    hex   : {fmt_hex(pub_x)}")
    print(f"  y    hex   : {fmt_hex(pub_y)}")
    print(f"  x    bytes : {fmt_array(pub_x)}")
    print(f"  y    bytes : {fmt_array(pub_y)}")

    print()
    print(sep)
    print("CHALLENGE  (reference)")
    print(sep)
    print(f"  base64     : {raw_b64}")
    print(f"  repr       : {challenge!r}")

    print()
    print(sep)
    print("CHALLENGE HASH  (SHA-256)")
    print(sep)
    print(f"  hex        : {fmt_hex(challenge_hash)}")
    print(f"  bytes      : {fmt_array(challenge_hash)}")

    print()
    print(sep)
    print("SIGNATURE  (ECDSA-P256-SHA256, raw r || s, 64 bytes)")
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



