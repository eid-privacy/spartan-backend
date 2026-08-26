// want the non-snake-case to match the mathematical notation
#![allow(non_snake_case)]

use algebra_utils::{big_to_ff, ff_to_big};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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

const COORD_BASE64_LEN: usize = 43;

#[derive(Deserialize)]
struct BoundedVec {
    len: usize,
    storage: Vec<u8>,
}

#[derive(Deserialize)]
struct ProverToml {
    payload: BoundedVec,
    /// The variable-length base64url JWT header. Unlike c0200 (which hardcodes
    /// the ES256 header), the SICPA header carries the issuer key, so it is a
    /// public circuit input and must be read here to reconstruct the signing
    /// input that was hashed and signed.
    encoded_header: BoundedVec,
    /// Optional: only present on the first run. After the preprocessor strips
    /// it from Prover.toml, subsequent runs proceed without it.
    jwt_signature: Option<Vec<u8>>,
    issuer_pub_x: Vec<u8>,
    issuer_pub_y: Vec<u8>,
    x_offset: usize,
    y_offset: usize,
    /// The 32-byte r half of the device signature. Preprocessing only: the
    /// circuit never sees it, it is folded into T_dev/U_dev here.
    device_r: Vec<u8>,
    /// The s half of the device signature, as the `0x…` field literal the
    /// circuit consumes directly.
    device_s: String,
    challenge_nonce: Vec<u8>,
}

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

fn to_field_repr(v: &[u8]) -> FieldRepr {
    v.try_into().expect("expected exactly 32 bytes")
}

/// Parse a Noir field literal (`"0x…"`, big-endian, at most 32 bytes) written
/// in Prover.toml back into its 32-byte big-endian representation.
fn field_literal_to_repr(literal: &str) -> FieldRepr {
    let trimmed = literal.trim();
    let hex_digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .expect("field literal must be 0x-prefixed hexadecimal");
    let padded = format!("{hex_digits:0>64}");
    assert_eq!(padded.len(), 64, "field literal exceeds 32 bytes");
    let value = BigUint::parse_bytes(padded.as_bytes(), 16).expect("invalid hex in field literal");
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Strip previously written precompute keys + the now-unused jwt_signature.
/// Handles both single-line and multi-line array values.
fn strip_precomputed_fields(content: &str) -> String {
    let precomputed_keys: &[&str] = &[
        "R_jwt_x =",
        "R_jwt_y =",
        "s_inv_jwt =",
        "R_dev_x =",
        "R_dev_y =",
        "T_dev_x =",
        "T_dev_y =",
        "U_dev_x =",
        "U_dev_y =",
    ];
    let mut result: Vec<&str> = Vec::new();
    let mut in_multiline_array = false;

    for line in content.lines() {
        if in_multiline_array {
            if line.contains(']') {
                in_multiline_array = false;
            }
            continue;
        }
        let trimmed = line.trim_start();
        // Drop the section comments we emit so repeated runs don't accumulate them.
        if trimmed.starts_with("# Precomputed (c0201_sicpa_backend)") {
            continue;
        }
        let is_precomputed = precomputed_keys.iter().any(|key| trimmed.starts_with(key));
        if is_precomputed {
            if trimmed.contains('[') && !trimmed.contains(']') {
                in_multiline_array = true;
            }
            continue;
        }
        result.push(line);
    }
    result.join("\n")
}

/// ECDSA recover: given digest d, signature (r, s), pubkey Q,
/// returns R = (G * (d*s^-1) + Q * (r*s^-1)).to_affine() and s_inv.
fn ecdsa_recover(
    digest: &FieldRepr,
    r: &FieldRepr,
    s: &FieldRepr,
    Q: &Secp256r1Affine,
) -> (Secp256r1Affine, Fq) {
    let r_fq = big_to_ff::<Fq>(&BigUint::from_bytes_be(r));
    let s_fq = big_to_ff::<Fq>(&BigUint::from_bytes_be(s));
    let d_fq = big_to_ff::<Fq>(&BigUint::from_bytes_be(digest));

    assert_ne!(s_fq, Fq::ZERO, "signature s is zero");
    let s_inv = s_fq.invert().unwrap();

    let G = GE::generator();
    let R = (G * (d_fq * s_inv) + (*Q) * (r_fq * s_inv)).to_affine();

    // Sanity: ECDSA verifies iff R.x (as integer) reduces to r in Fq.
    let r_recovered = big_to_ff::<Fq>(&ff_to_big::<Fp>(&R.x));
    assert_eq!(r_recovered, r_fq, "ECDSA signature invalid: recovered r mismatch");

    (R, s_inv)
}

fn affine_to_repr(p: &Secp256r1Affine) -> (FieldRepr, FieldRepr) {
    (ff_to_be::<Fp>(&p.x), ff_to_be::<Fp>(&p.y))
}

fn main() {
    let toml_path = PathBuf::from("../../circuits/c0201_sicpa_backend/Prover.toml");
    let content = fs::read_to_string(&toml_path).expect("cannot read Prover.toml");
    let prover: ProverToml = toml::from_str(&content).expect("cannot parse Prover.toml");

    // 1. Reconstruct the JWT signing input: encoded_header + "." + base64url(payload).
    //    The header is variable-length (SICPA header embeds the issuer key), so
    //    we take exactly `encoded_header.len` bytes from its storage.
    let header_bytes = &prover.encoded_header.storage[..prover.encoded_header.len];
    let payload_bytes = &prover.payload.storage[..prover.payload.len];
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload_bytes);
    let mut signing_input: Vec<u8> =
        Vec::with_capacity(header_bytes.len() + 1 + encoded_payload.len());
    signing_input.extend_from_slice(header_bytes);
    signing_input.push(b'.');
    signing_input.extend_from_slice(encoded_payload.as_bytes());

    // 2. SHA-256 of the signing input is the message digest.
    let digest_jwt: FieldRepr = Sha256::digest(&signing_input).into();

    // 3. Parse JWT signature + issuer pubkey.
    let jwt_sig = prover.jwt_signature.as_deref().expect(
        "jwt_signature missing from Prover.toml; the preprocessor needs it as input",
    );
    assert_eq!(jwt_sig.len(), 64, "jwt_signature must be 64 bytes");
    let r_jwt = to_field_repr(&jwt_sig[..32]);
    let s_jwt = to_field_repr(&jwt_sig[32..]);
    let issuer_x = to_field_repr(&prover.issuer_pub_x);
    let issuer_y = to_field_repr(&prover.issuer_pub_y);
    let Q_iss = Secp256r1Affine::from_xy(
        big_to_ff::<Fp>(&BigUint::from_bytes_be(&issuer_x)),
        big_to_ff::<Fp>(&BigUint::from_bytes_be(&issuer_y)),
    )
    .expect("issuer public key is not on curve");

    let (R_jwt, s_inv_jwt) = ecdsa_recover(&digest_jwt, &r_jwt, &s_jwt, &Q_iss);
    let (R_jwt_x, R_jwt_y) = affine_to_repr(&R_jwt);

    // 4. Extract device pubkey from payload at x_offset+5 and y_offset+5
    //    (43 base64url chars each, following the JWK `"x":"` / `"y":"` prefix).
    assert!(
        prover.x_offset + 5 + COORD_BASE64_LEN <= prover.payload.len,
        "x_offset coord exceeds payload length"
    );
    assert!(
        prover.y_offset + 5 + COORD_BASE64_LEN <= prover.payload.len,
        "y_offset coord exceeds payload length"
    );
    let dev_x_b64 =
        &prover.payload.storage[prover.x_offset + 5..prover.x_offset + 5 + COORD_BASE64_LEN];
    let dev_y_b64 =
        &prover.payload.storage[prover.y_offset + 5..prover.y_offset + 5 + COORD_BASE64_LEN];
    let dev_pub_x_bytes = URL_SAFE_NO_PAD
        .decode(dev_x_b64)
        .expect("device pub x base64url decode failed");
    let dev_pub_y_bytes = URL_SAFE_NO_PAD
        .decode(dev_y_b64)
        .expect("device pub y base64url decode failed");
    assert_eq!(dev_pub_x_bytes.len(), 32);
    assert_eq!(dev_pub_y_bytes.len(), 32);
    let dev_pub_x = to_field_repr(&dev_pub_x_bytes);
    let dev_pub_y = to_field_repr(&dev_pub_y_bytes);

    let Q_dev = Secp256r1Affine::from_xy(
        big_to_ff::<Fp>(&BigUint::from_bytes_be(&dev_pub_x)),
        big_to_ff::<Fp>(&BigUint::from_bytes_be(&dev_pub_y)),
    )
    .expect("device public key is not on curve");

    // 5. Device signature recovery (e = challenge_nonce, already 32 bytes).
    assert_eq!(prover.device_r.len(), 32);
    assert_eq!(prover.challenge_nonce.len(), 32);
    let r_dev = to_field_repr(&prover.device_r);
    let s_dev = field_literal_to_repr(&prover.device_s);
    let e_dev = to_field_repr(&prover.challenge_nonce);

    let (R_dev, _s_inv_dev) = ecdsa_recover(&e_dev, &r_dev, &s_dev, &Q_dev);
    let (R_dev_x, R_dev_y) = affine_to_repr(&R_dev);

    // T_dev = R_dev * r^-1, U_dev = G * (-e * r^-1).
    let r_dev_fq = big_to_ff::<Fq>(&BigUint::from_bytes_be(&r_dev));
    let e_dev_fq = big_to_ff::<Fq>(&BigUint::from_bytes_be(&e_dev));
    assert_ne!(r_dev_fq, Fq::ZERO);
    let r_dev_inv = r_dev_fq.invert().unwrap();
    let T_dev = (R_dev * r_dev_inv).to_affine();
    let U_dev = (GE::generator() * (-e_dev_fq * r_dev_inv)).to_affine();
    let (T_dev_x, T_dev_y) = affine_to_repr(&T_dev);
    let (U_dev_x, U_dev_y) = affine_to_repr(&U_dev);

    // 6. Strip old precompute lines and inject fresh ones. The Prover.toml
    //    (produced by create-prover.py / toml.dumps) writes the BoundedVec
    //    inputs as `[table]` sections, which must come after all top-level
    //    keys. So we insert the precompute scalars *before* the first table
    //    header rather than appending at the end (which would nest them under
    //    the last table).
    let stripped = strip_precomputed_fields(&content);

    let mut block = String::new();
    block.push_str("# Precomputed (c0201_sicpa_backend): JWT (issuer) ECDSA recovery\n");
    block.push_str(&fmt_array("R_jwt_x", &R_jwt_x));
    block.push_str(&fmt_array("R_jwt_y", &R_jwt_y));
    block.push_str(&fmt_field("s_inv_jwt", &ff_to_be::<Fq>(&s_inv_jwt)));
    block.push_str("# Precomputed (c0201_sicpa_backend): device ECDSA Crescent triple\n");
    block.push_str(&fmt_array("R_dev_x", &R_dev_x));
    block.push_str(&fmt_array("R_dev_y", &R_dev_y));
    block.push_str(&fmt_array("T_dev_x", &T_dev_x));
    block.push_str(&fmt_array("T_dev_y", &T_dev_y));
    block.push_str(&fmt_array("U_dev_x", &U_dev_x));
    block.push_str(&fmt_array("U_dev_y", &U_dev_y));

    let out = match stripped.find("\n[") {
        // Insert just after the newline that precedes the first table header.
        Some(idx) => {
            let split_at = idx + 1;
            format!("{}\n{}{}", &stripped[..split_at], block, &stripped[split_at..])
        }
        // No table sections: safe to append at the end.
        None => {
            let mut s = stripped;
            if !s.ends_with('\n') {
                s.push('\n');
            }
            s.push('\n');
            s.push_str(&block);
            s
        }
    };

    fs::write(&toml_path, out).expect("cannot write Prover.toml");

    println!(
        "c0201_sicpa_backend: wrote R_jwt, s_inv_jwt, R_dev, T_dev, U_dev to {}",
        toml_path.display()
    );
}
