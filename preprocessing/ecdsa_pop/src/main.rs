// want the non-snake case to make sense of the mathematical notation
#![allow(non_snake_case)]

mod pop_precomputation;

use algebra_utils::ecdsa::Point;
use hex::decode;
use serde::Deserialize;
use std::{fs, path::PathBuf};

type FieldRepr = [u8; 32];

#[derive(Deserialize)]
struct ProverToml {
    credential_string: String,
    /// signature_device is 64 bytes: first 32 = r, last 32 = s
    signature_device: Vec<u8>,
    /// challenge_hash is the message digest (32 bytes)
    challenge_hash: Vec<u8>,
}

const CREDENTIAL_POS_DEVICE_PUB_X: usize = 74;
const CREDENTIAL_POS_DEVICE_PUB_Y: usize = 138;
const CREDENTIAL_LEN_DEVICE_PUB_COORD_HEX: usize = 64;

fn decode_hex_32_at(credential_hex: &str, start: usize) -> FieldRepr {
    let end = start + CREDENTIAL_LEN_DEVICE_PUB_COORD_HEX;
    assert!(
        credential_hex.len() >= end,
        "credential_string too short for coordinate extraction"
    );

    let coord_hex = &credential_hex[start..end];
    let decoded = decode(coord_hex).expect("invalid hex in credential_string coordinate");
    decoded
        .as_slice()
        .try_into()
        .expect("decoded coordinate must be exactly 32 bytes")
}

fn to_field_repr(v: &[u8]) -> FieldRepr {
    v.try_into().expect("expected exactly 32 bytes")
}

fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn field_repr_to_toml_array(label: &str, f: &FieldRepr) -> String {
    let entries: Vec<String> = f.iter().map(|b| b.to_string()).collect();
    format!("{} = [{}]\n", label, entries.join(", "))
}

fn is_precompute_key_line(line: &str) -> bool {
    let key = line.trim_start();
    key.starts_with("R_x =")
        || key.starts_with("R_y =")
        || key.starts_with("T_x =")
        || key.starts_with("T_y =")
        || key.starts_with("U_x =")
        || key.starts_with("U_y =")
}

fn strip_existing_precompute_fields(content: &str) -> (String, bool) {
    let mut removed_any = false;
    let kept: Vec<&str> = content
        .lines()
        .filter(|line| {
            let keep = !is_precompute_key_line(line);
            if !keep {
                removed_any = true;
            }
            keep
        })
        .collect();
    (kept.join("\n"), removed_any)
}

fn main() {
    let toml_path = PathBuf::from("../../circuits/c0100_holder_binding_crescent_style/Prover.toml");

    let content = fs::read_to_string(&toml_path).expect("cannot read Prover.toml");
    let prover: ProverToml = toml::from_str(&content).expect("cannot parse Prover.toml");

    let q = Point {
        x: decode_hex_32_at(&prover.credential_string, CREDENTIAL_POS_DEVICE_PUB_X),
        y: decode_hex_32_at(&prover.credential_string, CREDENTIAL_POS_DEVICE_PUB_Y),
    };

    // Sanity check: (x, y) must be a valid point on the P-256 curve
    {
        use halo2curves::secp256r1::Secp256r1Affine;
        use halo2curves::CurveAffine;
        use num_bigint::BigUint;

        type Fp = <spartan2::provider::P256HyraxEngine as spartan2::traits::Engine>::Base;

        let x = algebra_utils::big_to_ff::<Fp>(&BigUint::from_bytes_be(&q.x));
        let y = algebra_utils::big_to_ff::<Fp>(&BigUint::from_bytes_be(&q.y));

        assert!(
            bool::from(Secp256r1Affine::from_xy(x, y).is_some()),
            "holder key extracted from credential_string is NOT a valid point on the P-256 curve"
        );
    }

    assert_eq!(
        prover.signature_device.len(),
        64,
        "signature_device must be 64 bytes"
    );
    let r: FieldRepr = to_field_repr(&prover.signature_device[..32]);
    let s: FieldRepr = to_field_repr(&prover.signature_device[32..]);

    let digest_hex = bytes_to_hex(&prover.challenge_hash);

    let (R, T, U) = pop_precomputation::compute_RTU_from_hex(&q, &r, &s, &digest_hex);

    let mut append = String::new();
    append.push_str(&field_repr_to_toml_array("R_x", &R.x));
    append.push_str(&field_repr_to_toml_array("R_y", &R.y));
    append.push_str(&field_repr_to_toml_array("T_x", &T.x));
    append.push_str(&field_repr_to_toml_array("T_y", &T.y));
    append.push_str(&field_repr_to_toml_array("U_x", &U.x));
    append.push_str(&field_repr_to_toml_array("U_y", &U.y));

    let (base, replaced_existing) = strip_existing_precompute_fields(&content);
    let mut full = base;
    if !full.ends_with('\n') {
        full.push('\n');
    }
    full.push('\n');
    full.push_str(&append);
    fs::write(&toml_path, full).expect("cannot write Prover.toml");

    if replaced_existing {
        println!("R, T, U replaced in Prover.toml");
    } else {
        println!("R, T, U appended to Prover.toml");
    }
}
