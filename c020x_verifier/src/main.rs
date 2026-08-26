use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
};

use algebra_utils::scalar_to_biguint;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::Parser;
use noirc_abi::AbiVisibility;
use p256::{
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar as P256Scalar,
    elliptic_curve::{
        Field, Group, PrimeField,
        sec1::FromEncodedPoint,
    },
};
use spartan_backend::{
    E, Scalar, instantiate_circuit_from_dir,
    noir::{circuit::CircuitParameters, synthesis::circuit_synthesizer::NoirCircuitSynthesizer},
    verify_circuit_from_base64,
};
use vega_prover::{traits::snark::R1CSSNARKTrait, vega_sc_zkp::VegaZkSNARK};

#[derive(Parser)]
#[command(
    version,
    about = "Verifier for c020x circuits with extra Crescent triple checks"
)]
struct Cli {
    /// Path to the circuit directory (e.g. ../circuits/c0200_swiyu_jwt)
    #[arg(long = "circuit-dir")]
    circuit_dir: PathBuf,

    /// Challenge nonce as 32-byte hex (0x-prefixed or raw hex)
    #[arg(long = "challenge-nonce-hex")]
    challenge_nonce_hex: String,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let circuit = instantiate_circuit_from_dir(&cli.circuit_dir);

    let mut proof_base64 = String::new();
    std::io::stdin()
        .read_to_string(&mut proof_base64)
        .map_err(|e| format!("failed to read proof from stdin: {e}"))?;
    if proof_base64.trim().is_empty() {
        return Err("stdin did not contain a base64 proof".to_string());
    }

    verify_circuit_from_base64(&circuit, &proof_base64)
        .map_err(|e| format!("spartan-backend verification failed: {e:?}"))?;

    let public_values = extract_public_values_from_proof(&circuit, &proof_base64)?;
    let challenge_nonce = parse_hex_32(&cli.challenge_nonce_hex)?;
    verify_crescent_triple_checks(&circuit, &public_values, &challenge_nonce)?;

    println!("Verification successful (including Crescent triple checks).");
    Ok(())
}

fn extract_public_values_from_proof(
    circuit: &CircuitParameters,
    proof_base64: &str,
) -> Result<Vec<Scalar>, String> {
    let proof_bytes = BASE64
        .decode(proof_base64.trim())
        .map_err(|e| format!("failed to base64-decode proof: {e}"))?;
    let proof: VegaZkSNARK<E> = bincode::deserialize(&proof_bytes)
        .map_err(|e| format!("failed to deserialize proof: {e}"))?;

    let verifier_circuit = NoirCircuitSynthesizer::new(
        circuit.program_artifact.clone(),
        circuit.verifier_inputs.clone(),
        &circuit.online_seeds,
    );
    let (_, vk) = VegaZkSNARK::<E>::setup(verifier_circuit)
        .map_err(|e| format!("failed to setup verifier key: {e:?}"))?;

    proof
        .verify(&vk)
        .map_err(|e| format!("proof.verify failed: {e:?}"))
}

fn verify_crescent_triple_checks(
    circuit: &CircuitParameters,
    public_values: &[Scalar],
    challenge_nonce: &[u8; 32],
) -> Result<(), String> {
    let ranges = public_param_ranges(circuit);
    let [tx, ty, ux, uy] = [
        extract_public_param_32(public_values, &ranges, "T_dev_x")?,
        extract_public_param_32(public_values, &ranges, "T_dev_y")?,
        extract_public_param_32(public_values, &ranges, "U_dev_x")?,
        extract_public_param_32(public_values, &ranges, "U_dev_y")?,
    ];

    let t = decode_affine_point(tx, ty).map_err(|e| format!("invalid T_dev point: {e}"))?;
    let u = decode_affine_point(ux, uy).map_err(|e| format!("invalid U_dev point: {e}"))?;

    if bool::from(t.is_identity()) {
        return Err("invalid T_dev point: identity point is not allowed".to_string());
    }
    if bool::from(u.is_identity()) {
        return Err("invalid U_dev point: identity point is not allowed".to_string());
    }

    let r = scalar_from_be_bytes(tx).map_err(|e| format!("invalid T_dev_x scalar r: {e}"))?;
    if bool::from(r.is_zero()) {
        return Err("invalid T_dev_x scalar r: zero is not allowed".to_string());
    }
    let Some(r_inv) = Option::<P256Scalar>::from(r.invert()) else {
        return Err("invalid T_dev_x scalar r: non-invertible".to_string());
    };
    let e = scalar_from_be_bytes(*challenge_nonce)
        .map_err(|err| format!("invalid challenge nonce scalar: {err}"))?;
    let coeff = -(e * r_inv);
    let expected_u = (ProjectivePoint::GENERATOR * coeff).to_affine();

    if u != expected_u {
        return Err(
            "Crescent check failed: U_dev does not match challenge_nonce and T_dev_x".to_string(),
        );
    }

    let relation = (ProjectivePoint::from(t) * e) + (ProjectivePoint::from(u) * r);
    if !bool::from(relation.is_identity()) {
        return Err("Crescent check failed: e*T_dev + r*U_dev != O".to_string());
    }

    Ok(())
}

fn public_param_ranges(circuit: &CircuitParameters) -> HashMap<String, std::ops::Range<usize>> {
    let mut ranges = HashMap::new();
    let mut cursor = 0usize;

    for param in &circuit.program_artifact.abi.parameters {
        if param.visibility != AbiVisibility::Public {
            continue;
        }
        let width = param.typ.field_count() as usize;
        ranges.insert(param.name.clone(), cursor..cursor + width);
        cursor += width;
    }

    ranges
}

fn extract_public_param_32(
    public_values: &[Scalar],
    ranges: &HashMap<String, std::ops::Range<usize>>,
    name: &str,
) -> Result<[u8; 32], String> {
    let range = ranges
        .get(name)
        .ok_or_else(|| format!("missing public parameter '{name}' in ABI"))?;
    if range.len() != 32 {
        return Err(format!(
            "parameter '{name}' has width {}, expected 32",
            range.len()
        ));
    }
    if range.end > public_values.len() {
        return Err(format!(
            "proof public values too short for '{name}' (need {}, got {})",
            range.end,
            public_values.len()
        ));
    }

    let mut out = [0u8; 32];
    for (i, value) in public_values[range.start..range.end].iter().enumerate() {
        out[i] = scalar_to_byte(value)
            .map_err(|e| format!("parameter '{name}' has non-byte field value at index {i}: {e}"))?;
    }
    Ok(out)
}

fn scalar_to_byte(value: &Scalar) -> Result<u8, String> {
    let n = scalar_to_biguint(value);
    if n.bits() > 8 {
        return Err(format!("value {n} does not fit in one byte"));
    }
    Ok(n.to_bytes_be().first().copied().unwrap_or(0u8))
}

fn parse_hex_32(input: &str) -> Result<[u8; 32], String> {
    let normalized = input
        .trim()
        .strip_prefix("0x")
        .or_else(|| input.trim().strip_prefix("0X"))
        .unwrap_or(input.trim());
    let bytes = hex::decode(normalized).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "challenge nonce must be exactly 32 bytes (got {})",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_affine_point(x: [u8; 32], y: [u8; 32]) -> Result<AffinePoint, String> {
    let x_fb: FieldBytes = x.into();
    let y_fb: FieldBytes = y.into();
    let encoded = EncodedPoint::from_affine_coordinates(&x_fb, &y_fb, false);
    let point = AffinePoint::from_encoded_point(&encoded);
    Option::<AffinePoint>::from(point).ok_or_else(|| "point is not on P-256".to_string())
}

fn scalar_from_be_bytes(bytes: [u8; 32]) -> Result<P256Scalar, String> {
    let fb: FieldBytes = bytes.into();
    let scalar = P256Scalar::from_repr(fb);
    Option::<P256Scalar>::from(scalar)
        .ok_or_else(|| "not a canonical scalar modulo group order".to_string())
}

#[allow(dead_code)]
fn _default_c0200_dir() -> &'static Path {
    Path::new("../circuits/c0200_swiyu_jwt")
}
