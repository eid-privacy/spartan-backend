mod circuit_instance;
mod nizk_prover;
mod nizk_verifier;
pub mod noir;
mod trivial_circuit;
pub mod types;
mod utils;

use bellpepper_core::ConstraintSystem;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::test_cs::TestConstraintSystem;
use std::env;
pub use types::{E, Scalar};

pub use crate::circuit_instance::{instantiate_circuit_from_dir, instantiate_circuit_with_name};
use crate::nizk_prover::prove;
use crate::nizk_verifier::verify;
use crate::noir::circuit::CircuitParameters;
use crate::noir::synthesis::circuit_synthesizer::NoirCircuitSynthesizer;
use spartan2::spartan::SpartanSNARK;
use spartan2::traits::circuit::SpartanCircuit;
use tracing::info_span;

/// Run the Spartan2 prover and verifier for the given Noir circuit parameters.
pub fn run_proof_and_verification(circuit: CircuitParameters) {
    let _total_span = info_span!("total", circuit = ?circuit.name).entered();

    tracing::info!("Running prover and verifier for {:?}", circuit.name);
    tracing::debug!("ProgramArtifact loaded: {:?}", &circuit.program_artifact);
    tracing::debug!("Prover inputs {:?}", &circuit.prover_inputs);
    tracing::debug!("Verifier inputs {:?}", &circuit.verifier_inputs);
    let prover_circuit = {
        let _span = info_span!("prover_circuit_synthesis").entered();
        NoirCircuitSynthesizer::new(circuit.program_artifact.clone(), circuit.prover_inputs)
    };

    if env::var("SPARTAN_BACKEND_DEBUG_CS").is_ok() {
        let _span = info_span!("debug_constraint_system").entered();
        debug_constraint_system(&prover_circuit);
    }

    let proof: SpartanSNARK<E> = {
        let _span = info_span!("proof_creation").entered();
        prove(prover_circuit)
    };

    let verifier_circuit = {
        let _span = info_span!("verifier_circuit_synthesis").entered();
        NoirCircuitSynthesizer::new(circuit.program_artifact, circuit.verifier_inputs)
    };

    let verification_result = {
        let _span = info_span!("verification").entered();
        verify(verifier_circuit, proof)
    };

    verification_result.expect("verify failed");
    tracing::info!("Verification successful.");
}

/// Synthesizes the prover circuit into a [`TestConstraintSystem`] and reports
/// the first unsatisfied constraint, if any. Used to localise R1CS bugs:
/// enable with `SPARTAN_BACKEND_DEBUG_CS=1`.
fn debug_constraint_system(circuit: &NoirCircuitSynthesizer) {
    let mut cs = TestConstraintSystem::<Scalar>::new();

    // Mirror the SpartanCircuit invocation order: shared -> precommitted.
    let shared: Vec<AllocatedNum<Scalar>> = circuit
        .shared(&mut cs.namespace(|| "shared"))
        .expect("shared synthesis failed");
    let _ = circuit
        .precommitted(&mut cs.namespace(|| "precommitted"), &shared)
        .expect("precommitted synthesis failed");

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
