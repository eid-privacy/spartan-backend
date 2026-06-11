// want the non-snake case to make sense of the mathematical notation
#![allow(non_snake_case)]

use algebra_utils::{big_to_ff, ff_to_big};
use group::Curve;
use halo2curves::{CurveAffine, ff::Field, secp256r1::Secp256r1Affine};
use num_bigint::BigUint;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use spartan2::{provider::P256HyraxEngine, traits::Engine};
use std::{fs, path::PathBuf};

type Fq = <P256HyraxEngine as Engine>::Scalar;
type Fp = <P256HyraxEngine as Engine>::Base;
type GE = <P256HyraxEngine as Engine>::GE;
type FieldRepr = [u8; 32];

#[derive(Deserialize)]
struct ProverToml {
    credential_string: String,
    /// 64 bytes: first 32 = r, last 32 = s
    signature_issuer: Vec<u8>,
    pubkey_issuer_x: Vec<u8>,
    pubkey_issuer_y: Vec<u8>,
}

/// Convert a field element to big-endian bytes.
/// `ff_to_big` returns a BigUint from the LE repr; `to_bytes_be` normalises it for output.
fn ff_to_be<FF: halo2curves::ff::PrimeField>(f: &FF) -> FieldRepr {
    let bytes = ff_to_big(f).to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn fmt_array(label: &str, bytes: &FieldRepr) -> String {
    let entries: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    format!("{} = [{}]\n", label, entries.join(", "))
}

fn fmt_field(label: &str, bytes: &FieldRepr) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{label} = \"0x{hex}\"\n")
}

fn main() {
    let toml_path = PathBuf::from("../circuits/c0101_signature_pok_zkattest_style/Prover.toml");

    let content = fs::read_to_string(&toml_path).expect("cannot read Prover.toml");
    let prover: ProverToml = toml::from_str(&content).expect("cannot parse Prover.toml");

    // credential_hash = SHA-256(credential_string as bytes)
    let credential_hash: FieldRepr = Sha256::digest(prover.credential_string.as_bytes()).into();

    assert_eq!(
        prover.signature_issuer.len(),
        64,
        "signature_issuer must be 64 bytes"
    );
    let r_bytes: FieldRepr = prover.signature_issuer[..32].try_into().unwrap();
    let s_bytes: FieldRepr = prover.signature_issuer[32..].try_into().unwrap();
    let pubkey_x: FieldRepr = prover.pubkey_issuer_x.as_slice().try_into().unwrap();
    let pubkey_y: FieldRepr = prover.pubkey_issuer_y.as_slice().try_into().unwrap();

    let r = big_to_ff::<Fq>(&BigUint::from_bytes_be(&r_bytes));
    let s = big_to_ff::<Fq>(&BigUint::from_bytes_be(&s_bytes));
    let h = big_to_ff::<Fq>(&BigUint::from_bytes_be(&credential_hash));

    let Q = Secp256r1Affine::from_xy(
        big_to_ff::<Fp>(&BigUint::from_bytes_be(&pubkey_x)),
        big_to_ff::<Fp>(&BigUint::from_bytes_be(&pubkey_y)),
    )
    .expect("invalid issuer public key");

    let G = GE::generator();

    let r_inv = r.invert().unwrap();
    let s_inv = s.invert().unwrap();

    // z = s · r⁻¹  (ZKAttest equation scalar)
    let z = s * r_inv;

    // R = h · s⁻¹ · G + r · s⁻¹ · Q  (ECDSA recovered-R point)
    let R = (G * (h * s_inv) + Q * (r * s_inv)).to_affine();

    // Sanity check: R.x should equal r for a valid signature
    assert_eq!(
        ff_to_be::<Fp>(&R.x),
        r_bytes,
        "ECDSA signature invalid: R.x != r"
    );

    // tr⁻¹G = h · r⁻¹ · G
    let tr1g = (G * (h * r_inv)).to_affine();

    let mut out = content;
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    // z (scalar) and tr⁻¹G coordinates are FieldElement in the circuit; R is [u8; 32]
    out.push_str(&fmt_field("zrs_inv", &ff_to_be::<Fq>(&z)));
    out.push_str(&fmt_array("R_x", &ff_to_be::<Fp>(&R.x)));
    out.push_str(&fmt_array("R_y", &ff_to_be::<Fp>(&R.y)));
    out.push_str(&fmt_field("trg_x", &ff_to_be::<Fp>(&tr1g.x)));
    out.push_str(&fmt_field("trg_y", &ff_to_be::<Fp>(&tr1g.y)));

    print!("{out}");
}
