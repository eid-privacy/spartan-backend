use eid::{constants, decode_hex_32};
use eid::field_utils::{array_to_field, split_point};
use std::field::t256::{T256Point, T256Scalar, t256_msm, t256_ec_add};

fn main(
    // Private inputs
    credential_string: str<constants::CREDENTIAL_LEN>,
    signature_device: [u8; 64],
    // Public input
    challenge_hash: pub [u8; 32],
    R_x: pub [u8; 32],
    R_y: pub [u8; 32],
    T_x: pub [u8; 32],
    T_y: pub [u8; 32],
    U_x: pub [u8; 32],
    U_y: pub [u8; 32],
) {
    // Step 1: Verify device signature on the challenge hash
    // Extract public key from credential_raw from hex encoded values in position
    // 74 to 138 (32 bytes X, 32 bytes Y).
    let pubkey_device_x = decode_hex_32(
        credential_string.as_bytes(),
        constants::CREDENTIAL_POS_DEVICE_PUB_X,
    );
    let pubkey_device_y = decode_hex_32(
        credential_string.as_bytes(),
        constants::CREDENTIAL_POS_DEVICE_PUB_Y,
    );

    // Safety: this is computation on public inputs, can be verified out-of-circuit
    let s_scalar = unsafe {
        let (_, s) = split_point(signature_device);
        T256Scalar {
            lo: s,
            hi: 0,
        }
    };
    let T_point = T256Point { x: array_to_field(T_x), y: array_to_field(T_y) };
    let R_point = T256Point { x: array_to_field(R_x), y: array_to_field(R_y) };
    let U_point = T256Point { x: array_to_field(U_x), y: array_to_field(U_y) };

    let pubkey_x_field = array_to_field(pubkey_device_x);
    // The core verification equation from Crescent: T^sU = Q, Crescent impl. checks only x coordinate
    assert(pubkey_x_field == t256_ec_add(t256_msm([T_point], [s_scalar]), U_point).x);
}
