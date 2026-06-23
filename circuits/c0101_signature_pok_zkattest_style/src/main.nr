use eid::{constants};
use eid::field_utils::{array_to_field};
use std::field::t256::{T256Scalar, T256Point, t256_msm, t256_ec_add};
use sha256::sha256_var;

fn main(
    // Private inputs
    credential_string: str<constants::CREDENTIAL_LEN>,
    // issuer_signature: [u8; 64],
    pubkey_issuer_x: [u8; 32],
    pubkey_issuer_y: [u8; 32],
    rg_x: Field,
    rg_y: Field,
    R_x: [u8; 32],
    R_y: [u8; 32],
    z: Field,
) {

    let R = T256Point { x: array_to_field(R_x), y: array_to_field(R_y) };
    let rG = T256Point { x: rg_x, y: rg_y };
    let Q = T256Point { x: array_to_field(pubkey_issuer_x), y: array_to_field(pubkey_issuer_y) };

    // Step 1: Calculate the credential hash (scalar t)
    let credential_hash: [u8; 32] =
        sha256_var(credential_string.as_bytes(), constants::CREDENTIAL_LEN).into();
    let t = T256Scalar { hi: 0, lo: array_to_field(credential_hash) };

    // Step 2: Compute tr⁻¹G = t · (r⁻¹G) in-circuit
    let trG = t256_msm([rG], [t]);

    // ZKAttest equation: zR - tr⁻¹G = Q
    // We express it as zR = Q + tr⁻¹G
    let zR = t256_msm([R], [T256Scalar { hi: 0, lo: z}]);
    let rhs = t256_ec_add(Q, trG);

    assert(zR.x == rhs.x);
    assert(zR.y == rhs.y);
}
