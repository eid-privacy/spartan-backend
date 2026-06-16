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
    t: Field,
    ts_inv: Field,
    rs_inv: Field,

    // Public input
    // com_trg_x: pub [u8; 32], //FieldElement ?
    // com_trg_y: pub [u8; 32], //FieldElement ?
    // com_zrs_inv: pub [u8; 32],
) {
    // TODO: prove that coms == com(private inputs)

    let R = T256Point { x: array_to_field(R_x), y: array_to_field(R_y) };
    let Q = T256Point { x: array_to_field(pubkey_issuer_x), y: array_to_field(pubkey_issuer_y) };

    // ts_inv = t * s_inv  mod  P-256 scalar order, precomputed off-circuit
    // because the multiplication cannot be carried out in the native field
    // without modular reduction. Binding ts_inv / rs_inv to t / s_inv / R.x
    // must therefore be done with a non-native arithmetic gadget (TODO).

    // Verification equation: R = ts^(-1)G + rs^(-1)Q
    let tsG = t256_msm([G], [T256Scalar { hi: 0, lo: ts_inv }]);
    let rsQ = t256_msm([Q], [T256Scalar { hi: 0, lo: rs_inv }]);
    let rhs = t256_ec_add(tsG, rsQ);

    // Step 1: Calculate the credential hash
    // TODO: impl. this in spartan backend
//    let credential_hash: [u8; 32] =
//        sha256_var(credential_string.as_bytes(), constants::CREDENTIAL_LEN).into();

    // Step 2: Verify ECDSA signature on the credential hash
    // let signature_valid = std::ecdsa_secp256r1::verify_signature(
    //     pubkey_issuer_x,
    //     pubkey_issuer_y,
    //     issuer_signature,
    //    credential_hash,
    // );

    assert(R.x == rhs.x);
    assert(R.y == rhs.y);
}
