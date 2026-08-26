mod circuit_instance;
mod nizk_prover;
mod nizk_verifier;
pub mod noir;
pub mod online_prover;
pub mod precompute;
mod trivial_circuit;
pub mod types;
mod utils;

use std::env;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bellpepper_core::{ConstraintSystem, num::AllocatedNum, test_cs::TestConstraintSystem};
use tracing::info_span;
pub use types::{E, Scalar};
use vega_prover::{errors::VegaError, traits::circuit::VegaCircuit, vega_sc_zkp::VegaZkSNARK};

pub use crate::circuit_instance::{
    instantiate_circuit_from_dir, instantiate_circuit_with_name,
};
use crate::{
    nizk_prover::prove,
    nizk_verifier::{ExpectedPublicValue, verify},
    noir::{
        circuit::CircuitParameters, circuit_reader::types::input_wire::InputWire,
        synthesis::circuit_synthesizer::NoirCircuitSynthesizer,
    },
};

/// Generate a Vega zkSNARK proof for the given Noir circuit parameters.
pub fn prove_circuit(circuit: &CircuitParameters) -> Result<VegaZkSNARK<E>, VegaError> {
    let _total_span = info_span!("prove", circuit = ?circuit.name).entered();

    tracing::info!("Running prover for {:?}", circuit.name);
    tracing::debug!("ProgramArtifact loaded: {:?}", &circuit.program_artifact);
    tracing::debug!("Prover inputs {:?}", &circuit.prover_inputs);

    let prover_circuit = {
        let _span = info_span!("prover_circuit_synthesis").entered();
        NoirCircuitSynthesizer::new(
            circuit.program_artifact.clone(),
            circuit.prover_inputs.clone(),
            &circuit.online_seeds,
        )
    };

    if env::var("SPARTAN_BACKEND_DEBUG_CS").is_ok() {
        let _span = info_span!("debug_constraint_system").entered();
        debug_constraint_system(&prover_circuit);
    }

    let proof: Result<VegaZkSNARK<E>, VegaError> = {
        let _span = info_span!("proof_creation").entered();
        prove(prover_circuit)
    };

    match proof {
        Ok(_) => tracing::info!("Proof created successfully."),
        Err(ref e) => tracing::error!("Proof creation failed: {:?}", e),
    }

    proof
}

/// Verify a Vega zkSNARK proof against the given Noir circuit parameters.
pub fn verify_circuit(circuit: &CircuitParameters, proof: VegaZkSNARK<E>) -> Result<(), VegaError> {
    let _total_span = info_span!("verify", circuit = ?circuit.name).entered();

    tracing::info!("Running verifier for {:?}", circuit.name);
    tracing::debug!("ProgramArtifact loaded: {:?}", &circuit.program_artifact);
    tracing::debug!("Verifier inputs {:?}", &circuit.verifier_inputs);

    let verifier_circuit = {
        let _span = info_span!("verifier_circuit_synthesis").entered();
        NoirCircuitSynthesizer::new(
            circuit.program_artifact.clone(),
            circuit.verifier_inputs.clone(),
            &circuit.online_seeds,
        )
    };
    let expected_public_values = expected_public_values(&circuit.verifier_inputs);

    let _span = info_span!("verification").entered();
    verify(verifier_circuit, proof, &expected_public_values)?;
    Ok(())
}

fn expected_public_values(
    verifier_inputs: &[InputWire<Option<Scalar>>],
) -> Vec<ExpectedPublicValue<Scalar>> {
    let mut public_wires: Vec<InputWire<Option<Scalar>>> = verifier_inputs
        .iter()
        .copied()
        .filter(|wire| wire.public)
        .collect();

    public_wires.sort_by_key(|wire| wire.witness.witness_index());

    public_wires
        .into_iter()
        .enumerate()
        .map(|(position, wire)| ExpectedPublicValue {
            position,
            witness_index: wire.witness.witness_index(),
            configured_value: wire.value,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use acir::native_types::Witness;
    use ff::Field;

    use super::{Scalar, expected_public_values};
    use crate::noir::circuit_reader::types::input_wire::InputWire;

    #[test]
    fn expected_public_values_keep_missing_public_slots() {
        let inputs = vec![
            InputWire::new(true, Witness(5), None),
            InputWire::new(false, Witness(2), Some(Scalar::from(7u64))),
            InputWire::new(true, Witness(1), Some(Scalar::from(11u64))),
            InputWire::new(true, Witness(9), Some(Scalar::from(13u64))),
        ];

        let expected = expected_public_values(&inputs);
        assert_eq!(expected.len(), 3);
        assert_eq!(expected[0].position, 0);
        assert_eq!(expected[0].witness_index, 1);
        assert_eq!(expected[0].configured_value, Some(Scalar::from(11u64)));
        assert_eq!(expected[1].position, 1);
        assert_eq!(expected[1].witness_index, 5);
        assert_eq!(expected[1].configured_value, None);
        assert_eq!(expected[2].position, 2);
        assert_eq!(expected[2].witness_index, 9);
        assert_eq!(expected[2].configured_value, Some(Scalar::from(13u64)));
    }

    #[test]
    fn expected_public_values_are_sorted_by_witness_index() {
        let inputs = vec![
            InputWire::new(true, Witness(10), Some(Scalar::ONE)),
            InputWire::new(true, Witness(3), Some(Scalar::from(2u64))),
            InputWire::new(true, Witness(7), Some(Scalar::from(3u64))),
        ];

        let expected = expected_public_values(&inputs);
        assert_eq!(
            expected.iter().map(|v| v.witness_index).collect::<Vec<_>>(),
            vec![3, 7, 10]
        );
        assert_eq!(
            expected.iter().map(|v| v.position).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }
}

/// Runs only the prover for the given circuit and returns the proof as a
/// base64-encoded, bincode-serialized string (bincode 1.3, the same serializer
/// spartan2 uses internally).
pub fn prove_circuit_to_base64(circuit: &CircuitParameters) -> Result<String, VegaError> {
    let proof = prove_circuit(circuit)?;
    Ok(proof_to_base64(&proof))
}

/// Encodes a proof the way the CLI transports it: bincode 1.3 then base64.
pub fn proof_to_base64(proof: &VegaZkSNARK<E>) -> String {
    let bytes = bincode::serialize(proof).expect("failed to serialize proof");
    BASE64.encode(bytes)
}

/// Runs only the verifier for the given circuit against a proof provided as a
/// base64-encoded, bincode-serialized string (as produced by
/// [`prove_circuit_to_base64`]).
pub fn verify_circuit_from_base64(
    circuit: &CircuitParameters,
    proof_base64: &str,
) -> Result<(), VegaError> {
    let bytes = BASE64
        .decode(proof_base64.trim())
        .expect("failed to base64-decode proof");
    let proof: VegaZkSNARK<E> = bincode::deserialize(&bytes).expect("failed to deserialize proof");
    verify_circuit(circuit, proof)
}

/// Creates a proof for the circuit and reports its serialized size in bytes.
/// Uses bincode 1.3, the same serializer vega uses internally, so the
/// byte count reflects the realistic wire size.
pub fn report_proof_size(circuit: CircuitParameters) {
    let _span = info_span!("proof_size", circuit = ?circuit.name).entered();

    let proof = prove_circuit(&circuit);
    let bytes =
        bincode::serialize(&proof.expect("create proof")).expect("failed to serialize proof");

    tracing::info!(proof_size_bytes = bytes.len(), "proof_size");
    println!("{}: proof_size={} bytes", circuit.name, bytes.len());
}

/// Synthesizes the prover circuit into a [`TestConstraintSystem`] and reports
/// the first unsatisfied constraint, if any. Used to localise R1CS bugs:
/// enable with `SPARTAN_BACKEND_DEBUG_CS=1`.
fn debug_constraint_system(circuit: &NoirCircuitSynthesizer) {
    let mut cs = TestConstraintSystem::<Scalar>::new();

    // Mirror the VegaCircuit invocation order: shared -> precommitted -> synthesize.
    let shared: Vec<AllocatedNum<Scalar>> = circuit
        .shared(&mut cs.namespace(|| "shared"))
        .expect("shared synthesis failed");
    let precommitted: Vec<AllocatedNum<Scalar>> = circuit
        .precommitted(&mut cs.namespace(|| "precommitted"), &shared)
        .expect("precommitted synthesis failed");
    circuit
        .synthesize(
            &mut cs.namespace(|| "synthesize"),
            &shared,
            &precommitted,
            None,
        )
        .expect("synthesize failed");

    tracing::warn!(
        "DEBUG CS: {} constraints, {} inputs, {} aux witnesses",
        cs.num_constraints(),
        cs.num_inputs(),
        cs.scalar_aux().len(),
    );
    match cs.which_is_unsatisfied() {
        None => tracing::warn!("DEBUG CS: all constraints satisfied"),
        Some(path) => {
            tracing::error!("DEBUG CS: first unsatisfied constraint = {path}");
        }
    }
}
