use eid::{constants, decode_hex_32};

// P-256 generators to compute U as in Crescent. The arthimetic takes place in T-256 however.
global P256_GENERATOR_X: Field = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
global P256_GENERATOR_Y: Field = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;

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

    // Safety: prover code to derive public values from their inputs
    unsafe {
        let (r,s) = split_signature(signature_device);
        let message_digest: Field = array_to_field(challenge_hash);
    }

    let signature_device_valid = std::ecdsa_secp256r1::verify_signature(
        pubkey_device_x,
        pubkey_device_y,
        signature_device,
        challenge_hash,
    );
    assert(signature_device_valid);
}


// returns r,s as field elements
unconstrained fn split_signature(signature: [u8; 64]) -> (Field, Field) {
    let mut r_bytes: [u8; 32] = [0; 32];
    let mut s_bytes: [u8; 32] = [0; 32];

    for i in 0..32 {
        r_bytes[i] = signature[i];
        s_bytes[i] = signature[i + 32];
    }

    (array_to_field(r_bytes), array_to_field(s_bytes))
}

unconstrained fn array_to_field(arr: [u8; 32]) -> Field {
    let mut field_value: Field = 0;
    for i in 0..32 {
        field_value = field_value * 256 + arr[i] as Field;
    }
    field_value
}

unconstrained fn buildR(
    message_digest: Field,
    r: Field,
    s: Field,
    pubkey_device_x: [u8; 32],
    pubkey_device_y: [u8; 32],
) -> (Field, Field) {
    let s_inv = s.pow_32(-1);
    let u = message_digest*s_inv;
    let v = r*s_inv;

    // make it the correct scalar multiplication when I figure out the blackbox thing
    let R = (u*P256_GENERATOR_X + v*array_to_field(pubkey_device_x), u*P256_GENERATOR_Y + v*array_to_field(pubkey_device_y));

    let r_inv = s.pow_32(-1);
    let T = (r_inv*R.0, r_inv*R.1);
    let U = (u*P256_GENERATOR_X, u*P256_GENERATOR_Y);
}

unconstrained fn buildT(
    r: Field,
) -> (Field, Field) {
//    let r_inv = r.invert().unwrap();
//    let u = -d * r_inv;
//    let T = (R * r_inv).to_affine();
//    let U = (G * u).to_affine();

}
