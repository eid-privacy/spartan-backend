"""
create-prover.py

Helper script for creating an SD-JWT issuance (using the `sd_jwt` library),
extracting disclosures and JWT internals, and writing those values into a
TOML file suitable for use in an external proving circuit.

This module performs the following high-level steps:
- Generates an issuer and holder P-256 key pair.
- Builds a set of user claims and issues an SD-JWT (compact serialization).
- Generates a nonce, hashes it and has the holder sign the nonce.
- Parses the combined SD-JWT+disclosures, finds offsets for certain values
  (e.g. the disclosure hash and JWK x/y fields).
- Exports a layout of binary/vector data into a TOML file for use by a circuit.

Notes:
- This file monkey-patches `json.dumps` usage inside `sd_jwt.issuer` and
  `sd_jwt.disclosure` modules to force compact JSON formatting (no spaces).
  This is done at runtime (in-memory) before creating SD-JWT objects so the
  underlying library produces compact JSON strings used by the SD-JWT format.
- The code focuses on interoperability with a downstream consumer that expects
  binary data represented as lists of integers in TOML.
"""
import base64
import json
from datetime import datetime
from functools import partial
from typing import Union, Tuple, Optional

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from jwcrypto.jwk import JWK
from sd_jwt.common import SDObj
from sd_jwt.issuer import SDJWTIssuer
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
import toml
import secrets
import hashlib

# Import sd_jwt internals so we can monkey-patch their `dumps` symbol.
# This allows us to control the JSON formatting used internally by the library
# without modifying files in site-packages.
import sd_jwt.issuer as issuer_module
import sd_jwt.disclosure as disclosure_module

# -----------------------------------------------------------------------------
# Constants and configuration
# -----------------------------------------------------------------------------

# 'N' is the exact curve order for the NIST P-256 (secp256r1) elliptic curve.
# We use this to canonicalize ECDSA 's' values to the lower half-order (prevent malleability).
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
HALF_N = N // 2

# Output / vector sizing constraints used for the TOML structure.
PAYLOAD_MAX_LEN = 2048
DOB_SALT_MAX_LEN = 32
DOB_VALUE_MAX_LEN = 16
ENCODED_HEADER_MAX_LEN = 128

# -----------------------------------------------------------------------------
# Monkey-patch sd_jwt JSON dumps to produce compact JSON (no extra spaces)
# -----------------------------------------------------------------------------
# The sd_jwt library imports `dumps` from `json` in its modules. Replacing
# those symbols causes subsequent library calls to produce compact JSON
# without spaces after separators. This is a runtime-only change.
issuer_module.dumps = partial(json.dumps, separators=(',', ':'))
disclosure_module.dumps = partial(json.dumps, separators=(',', ':'))


class Disclosure:
    """
    Minimal local representation of an SD-JWT disclosure.

    This mirrors the structure produced by the sd_jwt library disclosures:
      - raw_data: the base64url-encoded disclosure string (padless).
      - salt, name, value: parsed JSON array elements inside the disclosure.

    The class provides:
      - a textual repr,
      - a `hash()` method that returns the base64url-encoded SHA-256 digest
        of the raw disclosure bytes (matching the sd-jwt spec usage).
    """

    def __init__(self, raw_data: str):
        self.raw_data = raw_data
        self.salt, self.name, self.value = json.loads(b64url_decode_nopad(raw_data).decode('utf-8'))

    def __str__(self) -> str:
        return f"Disclosure(salt={self.salt}, name={self.name}, value={self.value})"

    def __repr__(self) -> str:
        return str(self)

    def hash(self) -> str:
        """
        Compute the base64url (no padding) SHA-256 hash of the disclosure
        (the same representation used by the SD-JWT internals).
        Returns:
            A string containing the base64url (padless) digest.
        """
        return encode_base64_nopad(hashlib.sha256(self.raw_data.encode('utf-8')).digest())


def b64url_decode_nopad(encoded_str: str) -> bytes:
    """Decode a Base64 URL-safe string without padding."""
    padded_str = encoded_str + '=' * (-len(encoded_str) % 4)
    return base64.urlsafe_b64decode(padded_str)


def encode_base64_nopad(data: bytes) -> str:
    """Encode a Base64 URL-safe string without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def key_to_jwk(key: Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]) -> Optional[JWK]:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return JWK.from_pem(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    elif isinstance(key, ec.EllipticCurvePublicKey):
        return JWK.from_pem(
            key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    return None


def issue_credential(issuer_key: ec.EllipticCurvePrivateKey, holder_key: ec.EllipticCurvePublicKey) -> str:
    user_claims = {
        SDObj("given_name"): "John",
        SDObj("family_name"): "Doe",
        SDObj("birth_date"): "1990-01-01",
        SDObj("address"): {
            SDObj("street_address"): "Rue de Lausanne 1",
            SDObj("locality"): "Lausanne",
            SDObj("region"): "VD",
            SDObj("country"): "CH",
        }
    }

    issuer_jwk = key_to_jwk(issuer_key)
    holder_jwk_pub = key_to_jwk(holder_key)

    issuer = SDJWTIssuer(
        user_claims=user_claims,
        issuer_key=issuer_jwk,
        holder_key=holder_jwk_pub,
        add_decoy_claims=True,
        serialization_format="compact",
        extra_header_parameters={
            "typ": "vc+sd-jwt",
            "kid": "did:example:issuer#key-1"
        }
    )

    print("SD-JWT at issuer:\n", issuer.sd_jwt_issuance)
    return issuer.sd_jwt_issuance


def signature(message: bytes, jwk: ec.EllipticCurvePrivateKey) -> bytes:
    sig_der = jwk.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig_der)
    # fix malleability by ensuring s is in the lower half of the curve order
    if s > HALF_N:
        s = N - s
    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")
    return r_bytes + s_bytes


def fix_malleability(signature: bytes) -> bytes:
    s_int = int.from_bytes(signature[32:], byteorder='big')
    if s_int > HALF_N:
        return signature[:32] + (N - s_int).to_bytes(32, "big")
    else:
        return signature  # no need for change


def find_disclosure(name: str, payload: bytes, disclosures: list[str]) -> Tuple[Disclosure, int]:
    for disclosure in disclosures:
        d = Disclosure(disclosure)
        if d.name == name:
            return d, payload.find(d.hash().encode())
    raise ValueError(f"Disclosure with name '{name}' not found in credential.")


def find_key_offsets(payload: bytes) -> Tuple[int, int]:
    data = json.loads(payload.decode())
    key_x = data["cnf"]["jwk"]["x"]
    key_y = data["cnf"]["jwk"]["y"]
    x_offset = payload.find(f"\"x\":\"{key_x}".encode())
    y_offset = payload.find(f"\"y\":\"{key_y}".encode())
    return x_offset, y_offset


def bounded_vec(data: bytes, capacity: int) -> dict:
    return {
        "len": len(data),
        "storage": list(data) + [0] * (capacity - len(data)),
    }


def write_toml(filename: str) -> None:
    encoded_header_bytes = encoded_header.encode()
    now_date = datetime.today().strftime("%Y%m%d")
    issuer_public_numbers = issuer_key.public_key().public_numbers()

    data = {
        "payload": bounded_vec(payload, PAYLOAD_MAX_LEN),
        "jwt_signature": list(fix_malleability(b64url_decode_nopad(encoded_signature))),
        "dob_salt": bounded_vec(dob_disclosure.salt.encode(), DOB_SALT_MAX_LEN),
        "dob_value": bounded_vec(dob_disclosure.value.encode(), DOB_VALUE_MAX_LEN),
        "dob_sd_offset": dob_offset,
        "x_offset": x_offset,
        "y_offset": y_offset,
        "device_signature": list(holder_signature),
        "encoded_header": bounded_vec(encoded_header_bytes, ENCODED_HEADER_MAX_LEN),
        "issuer_pub_x": list(issuer_public_numbers.x.to_bytes(32, 'big')),
        "issuer_pub_y": list(issuer_public_numbers.y.to_bytes(32, 'big')),
        "now_date": int(now_date),
        "challenge_nonce": list(nonce_hash),
    }
    with open(filename, mode="w", encoding="utf-8") as f:
        f.write(toml.dumps(data))


if __name__ == "__main__":
    # Generate keys for issuer and holder
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    holder_key = ec.generate_private_key(ec.SECP256R1())

    # issue a credential
    credential = issue_credential(issuer_key, holder_key.public_key())

    # generate random nonce and sign it
    nonce = secrets.token_bytes(32)
    nonce_hash = hashlib.sha256(nonce).digest()
    holder_signature = signature(nonce, holder_key)

    # parse the credential
    disclosures = credential.split("~")
    jwt = disclosures.pop(0)  # Skip the JWT part
    encoded_header, encoded_payload, encoded_signature = jwt.split(".")
    payload = b64url_decode_nopad(encoded_payload)

    # find the key offsets
    x_offset, y_offset = find_key_offsets(payload)

    # find the disclosure for birth_date
    dob_disclosure, dob_offset = find_disclosure("birth_date", payload, disclosures)

    # write data to TOML file for use in noir circuit
    write_toml("Prover.toml")
