use noir_base64::{BASE64_URL_DECODER, BASE64_URL_ENCODER};
use sha256::sha256_var;

use eid::fast_base64::encode_url_into;
use eid::field_utils::{array_to_field, split_point};
use std::field::t256::{T256Point, T256Scalar, t256_msm, t256_ec_add};

mod constants;
use constants::{
    COORD_BASE64_LEN, DISCLOSURE_MAX_LEN, DOB_CLAIM_NAME, DOB_SALT_MAX_LEN, DOB_VALUE_MAX_LEN,
    ENCODED_HEADER_LEN, MIN_AGE_YEARS, PAYLOAD_MAX_LEN,
};

pub global G: T256Point = T256Point {
    x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
};

// Matches the number of bytes `encode_url_into` writes: ((n + 2) / 3) * 4.
global ENCODED_PAYLOAD_MAX_LEN: u32 = ((PAYLOAD_MAX_LEN + 2) / 3) * 4;


global SIGNING_INPUT_MAX_LEN: u32 = ENCODED_HEADER_LEN + 1 + ENCODED_PAYLOAD_MAX_LEN;

global ASCII_DOT: u8 = 46;
global ASCII_X: u8 = 120; // 'x'
// global ASCII_Y: u8 = 121; // 'y'

fn build_dob_disclosure<let S: u32, let V: u32>(
    salt: BoundedVec<u8, S>,
    value: BoundedVec<u8, V>,
) -> BoundedVec<u8, DISCLOSURE_MAX_LEN> {
    // Builds: ["salt","birth_date","value"]
    let mut disclosure: BoundedVec<u8, DISCLOSURE_MAX_LEN> = BoundedVec::new();
    disclosure.extend_from_array("[\"".as_bytes());
    disclosure.extend_from_bounded_vec(salt);
    disclosure.extend_from_array("\",\"".as_bytes());
    disclosure.extend_from_array(DOB_CLAIM_NAME);
    disclosure.extend_from_array("\",\"".as_bytes());
    disclosure.extend_from_bounded_vec(value);
    disclosure.extend_from_array("\"]".as_bytes());
    disclosure
}

fn extract_coord_for_key<let N: u32>(
    payload_storage: [u8; N],
    key_offset: u32,
    key_ascii: u8,
) -> [u8; COORD_BASE64_LEN] {
    // Expects the JSON pattern "k":"<43 base64url chars> where k is key_ascii
    let expected_prefix: [u8; 5] = [34, key_ascii, 34, 58, 34];
    for i in 0..5 {
        assert(payload_storage[key_offset + i] == expected_prefix[i], "Key not found");
    }

    let mut coord_bytes: [u8; COORD_BASE64_LEN] = [0; COORD_BASE64_LEN];
    for i in 0..COORD_BASE64_LEN {
        coord_bytes[i] = payload_storage[key_offset + 5 + i];
    }
    coord_bytes
}

fn birth_date_as_int(value: BoundedVec<u8, DOB_VALUE_MAX_LEN>) -> u32 {
    // YYYY-MM-DD: dashes at indices 4 and 7 are skipped
    let d = value.storage();
    (d[0] as u32 - 48) * 10_000_000
        + (d[1] as u32 - 48) * 1_000_000
        + (d[2] as u32 - 48) * 100_000
        + (d[3] as u32 - 48) * 10_000
        + (d[5] as u32 - 48) * 1_000
        + (d[6] as u32 - 48) * 100
        + (d[8] as u32 - 48) * 10
        + (d[9] as u32 - 48)
}

fn is_at_least_25_years_old(birth_date: u32, now_date: u32) -> bool {
    now_date >= birth_date + MIN_AGE_YEARS * 10_000
}

fn main(
    // Private inputs
    payload: BoundedVec<u8, PAYLOAD_MAX_LEN>,
    dob_salt: BoundedVec<u8, DOB_SALT_MAX_LEN>,
    dob_value: BoundedVec<u8, DOB_VALUE_MAX_LEN>,
    dob_sd_offset: u32,
    x_offset: u32,
    // y_offset: u32, UNUSED
    device_signature: [u8; 64],
    // JWT/issuer ECDSA precompute (c0102 "vanilla equation" style):
    // R_jwt and s_inv_jwt s.t. R_jwt = t*s^-1*G + r*s^-1*Q_iss where
    // t = sha256(signing_input), r = R_jwt.x, s = jwt_signature[32..].
    // Kept private: t is derived from the private payload in-circuit, and the
    // equation itself is the soundness check (cf. c0102). The raw
    // jwt_signature is consumed off-circuit by the preprocessor.
    R_jwt_x: [u8; 32],
    R_jwt_y: [u8; 32],
    s_inv_jwt: Field,
    // Public inputs
    encoded_header: pub [u8; ENCODED_HEADER_LEN],
    issuer_pub_x: pub [u8; 32],
    issuer_pub_y: pub [u8; 32],
    now_date: pub u32,
    // challenge_nonce: pub [u8; 32], UNUSED
    // Device ECDSA precompute (c0100 "Crescent" style):
    // T_dev = R_dev*r^-1, U_dev = -e*r^-1*G with e = challenge_nonce,
    // r = device_signature[..32], s = device_signature[32..].
    // These MUST be public: the verifier validates (R_dev, T_dev, U_dev) is
    // consistent with the public challenge_nonce off-circuit; the in-circuit
    // equation only binds device_pub.x to (T*s + U).x.
    // R_dev_x: pub [u8; 32], UNUSED
    // R_dev_y: pub [u8; 32], UNUSED
    T_dev_x: pub [u8; 32],
    T_dev_y: pub [u8; 32],
    U_dev_x: pub [u8; 32],
    U_dev_y: pub [u8; 32],
) {
    // Constructing the signing input directly into a fixed-size buffer.
    //
    // Unlike c0200, the SICPA header is not a compile-time constant: it is the
    // public `encoded_header` input (it embeds the issuer key). We copy the
    // variable-length header, append '.', then base64url-encode the payload
    // directly after it. We use `eid::fast_base64::encode_url_into` rather than
    // `BASE64_URL_ENCODER::encode_var` because the latter's alphabet lookup
    // costs ~400 R1CS aux per output character (~2.7k chars here).
    let mut signing_input_storage: [u8; SIGNING_INPUT_MAX_LEN] = [0; SIGNING_INPUT_MAX_LEN];
    for i in 0..ENCODED_HEADER_LEN {
        signing_input_storage[i] = encoded_header[i];
    }
    signing_input_storage[ENCODED_HEADER_LEN] = ASCII_DOT;
    let payload_storage = payload.storage();
    let payload_len = payload.len();
    let encoded_payload_len: u32 = encode_url_into(
        payload_storage,
        payload_len,
        &mut signing_input_storage,
        ENCODED_HEADER_LEN + 1,
    );
    let signing_input_len: u32 = ENCODED_HEADER_LEN + 1 + encoded_payload_len;

    // ECDSA verification of the issuer JWT signature (c0102 "vanilla equation").
    // We assert that R_jwt = t*s^-1*G + r*s^-1*Q_iss with r := R_jwt.x. Equivalent
    // to standard ECDSA: it binds R_jwt.x to the signature root, given the
    // prover commits to R_jwt and s_inv off-circuit.
    let signing_digest: [u8; 32] = sha256_var(signing_input_storage, signing_input_len);
    let t_jwt = T256Scalar { hi: 0, lo: array_to_field(signing_digest) };
    let R_jwt = T256Point { x: array_to_field(R_jwt_x), y: array_to_field(R_jwt_y) };
    let Q_iss = T256Point { x: array_to_field(issuer_pub_x), y: array_to_field(issuer_pub_y) };
    let s_inv_scalar_jwt = T256Scalar { hi: 0, lo: s_inv_jwt };
    let sG_jwt = t256_msm([G], [s_inv_scalar_jwt]);
    let sQ_jwt = t256_msm([Q_iss], [s_inv_scalar_jwt]);
    let tsG_jwt = t256_msm([sG_jwt], [t_jwt]);
    let r_jwt_scalar = T256Scalar { hi: 0, lo: R_jwt.x };
    let rsQ_jwt = t256_msm([sQ_jwt], [r_jwt_scalar]);
    let rhs_jwt = t256_ec_add(tsG_jwt, rsQ_jwt);
    assert(R_jwt.x == rhs_jwt.x, "Invalid JWT signature (x)");
    assert(R_jwt.y == rhs_jwt.y, "Invalid JWT signature (y)");

    let dob_disclosure = build_dob_disclosure(dob_salt, dob_value);
    let encoded_disclosure = BASE64_URL_ENCODER::encode_var(dob_disclosure);

    let expected_digest: [u8; COORD_BASE64_LEN] = BASE64_URL_ENCODER::encode(sha256_var(
        encoded_disclosure.storage(),
        encoded_disclosure.len(),
    ));

    for i in 0..COORD_BASE64_LEN {
        assert(
            payload_storage[dob_sd_offset + i] == expected_digest[i],
            "DOB disclosure digest mismatch",
        );
    }
    assert(
        is_at_least_25_years_old(birth_date_as_int(dob_value), now_date),
        "User must be 25 or older",
    );

    let device_key_x_bytes = extract_coord_for_key(payload_storage, x_offset, ASCII_X);
    // let device_key_y_bytes = extract_coord_for_key(payload_storage, y_offset, ASCII_Y);

    let device_pub_x: [u8; 32] = BASE64_URL_DECODER::decode(device_key_x_bytes);

    // ECDSA verification of the device signature on challenge_nonce (c0100
    // "Crescent" style). The device pubkey is derived in-circuit from the
    // private payload, so we keep s in-circuit (split from device_signature)
    // and only precompute T_dev = R*r^-1 and U_dev = -e*r^-1*G. The .x check
    // binds the equation to the device pubkey derived above.
    //
    // Safety: the unconstrained split_point only reinterprets the already
    // constrained device_signature bytes; the equation below is what enforces
    // soundness.
    let s_dev_scalar = unsafe {
        let (_, s) = split_point(device_signature);
        T256Scalar { lo: s, hi: 0 }
    };
    let T_dev = T256Point { x: array_to_field(T_dev_x), y: array_to_field(T_dev_y) };
    let U_dev = T256Point { x: array_to_field(U_dev_x), y: array_to_field(U_dev_y) };
    let device_pub_x_field = array_to_field(device_pub_x);
    assert(
        device_pub_x_field == t256_ec_add(t256_msm([T_dev], [s_dev_scalar]), U_dev).x,
        "Invalid device signature on challenge nonce",
    );
}

// The end-to-end verification (issuer JWT vanilla-equation + device Crescent
// checks) is validated with real, on-curve key material via `nargo execute`
// against the preprocessed Prover.toml (see preprocessing/c0201_sicpa_backend).
// The unit tests below cover the age-gate logic in isolation.

#[test]
fn test_age_gate_exactly_25_on_birthday() {
    assert(is_at_least_25_years_old(19880619, 20130619), "Expected user to be 25 on birthday");
}

#[test]
fn test_age_gate_one_day_before_25_fails() {
    assert(
        !is_at_least_25_years_old(19880619, 20130618),
        "Expected user to be under 25 one day before birthday",
    );
}
