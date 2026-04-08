use eid::{constants, decode_hex_32};
use eid::field_utils::{array_to_field, split_point};
use std::field::t256::{T256Point, T256Scalar, t256_msm, t256_ec_add};

fn main(
    // Private inputs
    credential_string: str<constants::CREDENTIAL_LEN>,
    signature_device: [u8; 64],
    // Public input
    challenge_hash: pub [u8; 32],
    R: pub [u8; 64],
    T: pub [u8; 64],
    U: pub [u8; 64],
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
    // Safety: this is computation on public inputs, can be verified out-of-circuit
    let T_point = unsafe {
        let (Tx, Ty) = split_point(T);
        T256Point { x: Tx, y: Ty }
    };

    // Safety: this is computation on public inputs, can be verified out-of-circuit
    let U_point = unsafe {
        let (Ux, Uy) = split_point(U);
        T256Point { x: Ux, y: Uy }
    };

    let pubkey_x_field = array_to_field(pubkey_device_x);
    // The core verification equation from Crescent: T^sU = Q, Crescent impl. checks only x coordinate
    assert(pubkey_x_field == t256_ec_add(t256_msm([T_point], [s_scalar]), U_point).x);

    let signature_device_valid = std::ecdsa_secp256r1::verify_signature(
        pubkey_device_x,
        pubkey_device_y,
        signature_device,
        challenge_hash,
    );
    assert(signature_device_valid);
}