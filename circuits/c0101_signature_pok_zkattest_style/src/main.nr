use eid::{constants};
use eid::field_utils::{array_to_field};
use std::field::t256::{T256Point, t256_msm, t256_ec_add};
use sha256::sha256_var;

fn main(
    // Private inputs
    credential_string: str<constants::CREDENTIAL_LEN>,
    issuer_signature: [u8, 64],
    pubkey_issuer_x: [u8, 32],
    pubkey_issuer_y: [u8, 32],
    trg_x: FieldElement,
    trg_y: FieldElement,
    R_x: [u8; 32],
    R_y: [u8; 32],
    zrs_inv: FieldElement,
    // Public input
    com_trg_x: pub [u8; 32], //FieldElement ?
    com_trg_y: pub [u8; 32], //FieldElement ?
    com_zrs_inv: pub [u8; 32],
) {
    // TODO: prove that coms == com(private inputs)

    let R_point = T256Point { x: array_to_field(R_x), y: array_to_field(R_y) };

    // Step 1: Calculate the credential hash
    // TODO: impl. this in spartan backend
    let credential_hash: [u8; 32] =
        sha256_var(credential_string.as_bytes(), constants::CREDENTIAL_LEN).into();

    // Step 2: Verify ECDSA signature on the credential hash
    // TODO: replace with ZKAttest equation: zR - tr^(-1)G = Q
    let signature_valid = std::ecdsa_secp256r1::verify_signature(
        pubkey_issuer_x,
        pubkey_issuer_y,
        issuer_signature,
        credential_hash,
    );
    assert(signature_valid);

//    let signature_device_valid = std::ecdsa_secp256r1::verify_signature(
//        pubkey_device_x,
//        pubkey_device_y,
//        signature_device,
//        challenge_hash,
//    );
//    assert(signature_device_valid);
}
