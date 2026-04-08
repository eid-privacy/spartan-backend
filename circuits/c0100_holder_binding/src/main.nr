use eid::{constants, decode_hex_32};

fn main(
    // Private inputs
    credential_string: str<constants::CREDENTIAL_LEN>,
    signature_device: [u8; 64],
    // Public input
    challenge_hash: pub [u8; 32],
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

    let signature_device_valid = std::ecdsa_secp256r1::verify_signature(
        pubkey_device_x,
        pubkey_device_y,
        signature_device,
        challenge_hash,
    );
    assert(signature_device_valid);
}
