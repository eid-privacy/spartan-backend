use eid::{constants};
use eid::field_utils::{array_to_field};
use std::field::t256::{T256Scalar, T256Point, t256_msm, t256_ec_add};
use sha256::sha256_var;

pub global G: T256Point = T256Point {
    x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
};

fn main(
    // Private inputs
    credential_string: str<constants::CREDENTIAL_LEN>,
    // issuer_signature: [u8; 64],
    pubkey_issuer_x: pub [u8; 32],
    pubkey_issuer_y: pub [u8; 32],
    R_x: [u8; 32],
    R_y: [u8; 32],
    s_inv: Field,
) {

    let R = T256Point { x: array_to_field(R_x), y: array_to_field(R_y) };
    let Q = T256Point { x: array_to_field(pubkey_issuer_x), y: array_to_field(pubkey_issuer_y) };

    // Step 1: Calculate the credential hash (scalar t)
    let credential_hash: [u8; 32] =
        sha256_var(credential_string.as_bytes(), constants::CREDENTIAL_LEN).into();
    let t = T256Scalar { hi: 0, lo: array_to_field(credential_hash) };

    // Step 2: Compute s^-1G and s^-1Q in-circuit (s_inv is the only precomputed scalar)
    let s_inv_scalar = T256Scalar { hi: 0, lo: s_inv };
    let sG = t256_msm([G], [s_inv_scalar]);
    let sQ = t256_msm([Q], [s_inv_scalar]);

    // Step 3: Compute ts^-1G = t * (s^-1G) and rs^-1Q = r * (s^-1Q) in-circuit,
    // where r = R.x (mod the P-256 scalar order, here reused as a scalar).
    let tsG = t256_msm([sG], [t]);
    let r = T256Scalar { hi: 0, lo: R.x };
    let rsQ = t256_msm([sQ], [r]);

    // Verification equation: R = ts^-1G + rs^-1Q
    let rhs = t256_ec_add(tsG, rsQ);

    assert(R.x == rhs.x);
    assert(R.y == rhs.y);
}
