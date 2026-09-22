use std::{collections::HashMap, io::Read, path::PathBuf};

use algebra_utils::scalar_to_biguint;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::Parser;
use noirc_abi::AbiVisibility;
use p256::{
    AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar as P256Scalar,
    elliptic_curve::{Field, ops::Reduce, sec1::FromEncodedPoint},
};
use spartan_backend::{
    E, Scalar, instantiate_verifier_circuit_from_dir,
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

    /// Hashed challenge `M` as 32-byte hex (0x-prefixed or raw hex).
    /// This is the `challenge_nonce` entry of the circuit's `Prover.toml`, it is hashed already.
    #[arg(long = "challenge-hash-hex")]
    challenge_hash_hex: String,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let circuit = instantiate_verifier_circuit_from_dir(&cli.circuit_dir);

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
    let challenge_hash = parse_hex_32(&cli.challenge_hash_hex)?;
    verify_crescent_triple_checks(&circuit, &public_values, &challenge_hash)?;

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

/// Off-circuit Crescent device-binding check following the Crescent paper
/// (ECDSA Signature Proof section), the device
/// signature `(r, s)` on the public message `M` is proven in-circuit as
/// `T^s * U == Q`, with the precomputed public points
///
/// ```text
/// r = f(R) = R.x    T = R * r^-1    U = G * (-M * r^-1)
/// ```
///
/// `R` is revealed by the prover as the public inputs `R_dev_x` / `R_dev_y`
/// carried by the proof itself, and the verifier recomputes `T` and `U`,
/// comparing them against the public `T_dev` / `U_dev`.
fn verify_crescent_triple_checks(
    circuit: &CircuitParameters,
    public_values: &[Scalar],
    challenge_hash: &[u8; 32],
) -> Result<(), String> {
    let ranges = public_param_ranges(circuit);
    let [tx, ty, ux, uy, r_dev_x, r_dev_y] = [
        extract_public_param_32(public_values, &ranges, "T_dev_x")?,
        extract_public_param_32(public_values, &ranges, "T_dev_y")?,
        extract_public_param_32(public_values, &ranges, "U_dev_x")?,
        extract_public_param_32(public_values, &ranges, "U_dev_y")?,
        extract_public_param_32(public_values, &ranges, "R_dev_x")?,
        extract_public_param_32(public_values, &ranges, "R_dev_y")?,
    ];

    check_crescent_triple(tx, ty, ux, uy, r_dev_x, r_dev_y, challenge_hash)
}

#[allow(clippy::too_many_arguments)]
fn check_crescent_triple(
    tx: [u8; 32],
    ty: [u8; 32],
    ux: [u8; 32],
    uy: [u8; 32],
    r_dev_x: [u8; 32],
    r_dev_y: [u8; 32],
    challenge_hash: &[u8; 32],
) -> Result<(), String> {
    let t = decode_affine_point(tx, ty).map_err(|e| format!("invalid T_dev point: {e}"))?;
    let u = decode_affine_point(ux, uy).map_err(|e| format!("invalid U_dev point: {e}"))?;
    let r_point =
        decode_affine_point(r_dev_x, r_dev_y).map_err(|e| format!("invalid R_dev point: {e}"))?;

    if bool::from(t.is_identity()) {
        return Err("invalid T_dev point: identity point is not allowed".to_string());
    }
    if bool::from(u.is_identity()) {
        return Err("invalid U_dev point: identity point is not allowed".to_string());
    }
    if bool::from(r_point.is_identity()) {
        return Err("invalid R_dev point: identity point is not allowed".to_string());
    }

    // r = f(R) = R.x, reduced modulo the group order as ECDSA does.
    let r = scalar_reduce_be_bytes(r_dev_x);
    if bool::from(r.is_zero()) {
        return Err("invalid R_dev: its x-coordinate reduces to zero mod n".to_string());
    }
    let Some(r_inv) = Option::<P256Scalar>::from(r.invert()) else {
        return Err("invalid R_dev: its x-coordinate is non-invertible mod n".to_string());
    };
    let m = scalar_reduce_be_bytes(*challenge_hash);

    let expected_t = (ProjectivePoint::from(r_point) * r_inv).to_affine();
    if t != expected_t {
        return Err(
            "Crescent check failed: T_dev in the proof does not match R_dev * r^-1 recomputed \
             from the revealed R_dev"
                .to_string(),
        );
    }

    let expected_u = (ProjectivePoint::GENERATOR * -(m * r_inv)).to_affine();
    if u != expected_u {
        return Err(
            "Crescent check failed: U_dev in the proof does not match G * (-M * r^-1) recomputed \
             from the challenge hash and the revealed R_dev"
                .to_string(),
        );
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
        out[i] = scalar_to_byte(value).map_err(|e| {
            format!("parameter '{name}' has non-byte field value at index {i}: {e}")
        })?;
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

/// Converts a 32-byte big-endian value into a P-256 scalar, reducing modulo
/// the group order.
fn scalar_reduce_be_bytes(bytes: [u8; 32]) -> P256Scalar {
    let fb: FieldBytes = bytes.into();
    P256Scalar::reduce_bytes(&fb)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every c020x circuit's `Prover.toml` carries the whole Crescent triple
    /// (`R_dev`, `T_dev`, `U_dev`) plus the hashed challenge, so the check can
    /// be exercised against real data without producing a proof.
    struct Triple {
        tx: [u8; 32],
        ty: [u8; 32],
        ux: [u8; 32],
        uy: [u8; 32],
        rx: [u8; 32],
        ry: [u8; 32],
        challenge_hash: [u8; 32],
    }

    const CIRCUITS: [&str; 4] = [
        "c0200_swiyu_jwt",
        "c0201_sicpa_backend",
        "c0202_sicpa_backend_constant",
        "c0203_sicpa_backend_move",
    ];

    fn circuit_dir(name: &str) -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../circuits")
            .join(name)
    }

    /// Test-only: the verifier itself never reads `Prover.toml`, it takes
    /// `R_dev` from the proof's public inputs. The file is just a convenient
    /// source of real fixtures here.
    fn read_toml_byte_array(value: &toml::Value, key: &str) -> [u8; 32] {
        let array = value
            .get(key)
            .unwrap_or_else(|| panic!("'{key}' is missing"))
            .as_array()
            .unwrap_or_else(|| panic!("'{key}' is not an array"));
        assert_eq!(array.len(), 32, "'{key}' must have 32 entries");
        std::array::from_fn(|i| {
            u8::try_from(array[i].as_integer().expect("integer")).expect("byte")
        })
    }

    fn load_triple(name: &str) -> Triple {
        let path = circuit_dir(name).join("Prover.toml");
        let contents = std::fs::read_to_string(&path).expect("Prover.toml is readable");
        let value: toml::Value = toml::from_str(&contents).expect("Prover.toml parses");
        let get = |key: &str| read_toml_byte_array(&value, key);
        Triple {
            tx: get("T_dev_x"),
            ty: get("T_dev_y"),
            ux: get("U_dev_x"),
            uy: get("U_dev_y"),
            rx: get("R_dev_x"),
            ry: get("R_dev_y"),
            challenge_hash: get("challenge_nonce"),
        }
    }

    fn check(t: &Triple) -> Result<(), String> {
        check_crescent_triple(t.tx, t.ty, t.ux, t.uy, t.rx, t.ry, &t.challenge_hash)
    }

    #[test]
    fn accepts_every_c020x_circuit_precompute() {
        for name in CIRCUITS {
            let triple = load_triple(name);
            assert_eq!(check(&triple), Ok(()), "{name} should verify");
        }
    }

    #[test]
    fn rejects_challenge_hash_from_another_circuit() {
        let mut triple = load_triple("c0203_sicpa_backend_move");
        triple.challenge_hash = load_triple("c0201_sicpa_backend").challenge_hash;
        let err = check(&triple).expect_err("a foreign challenge must be rejected");
        assert!(err.contains("U_dev"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_r_dev_from_another_circuit() {
        let other = load_triple("c0201_sicpa_backend");
        let mut triple = load_triple("c0203_sicpa_backend_move");
        triple.rx = other.rx;
        triple.ry = other.ry;
        let err = check(&triple).expect_err("a foreign R_dev must be rejected");
        assert!(err.contains("T_dev"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_identity_r_dev() {
        let mut triple = load_triple("c0203_sicpa_backend_move");
        triple.rx = [0u8; 32];
        triple.ry = [0u8; 32];
        let err = check(&triple).expect_err("the identity is not a valid R_dev");
        assert!(err.contains("R_dev"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_off_curve_r_dev() {
        let mut triple = load_triple("c0203_sicpa_backend_move");
        triple.rx[31] ^= 0x01;
        let err = check(&triple).expect_err("an off-curve R_dev must be rejected");
        assert!(
            err.contains("invalid R_dev point"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_tampered_u_dev() {
        let mut triple = load_triple("c0203_sicpa_backend_move");
        triple.ux = triple.tx;
        triple.uy = triple.ty;
        let err = check(&triple).expect_err("a swapped U_dev must be rejected");
        assert!(err.contains("U_dev"), "unexpected error: {err}");
    }
}
