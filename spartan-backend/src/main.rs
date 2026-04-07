mod utils;
mod trivial_circuit;
mod nizk_prover;
mod nizk_verifier;
pub mod noir;
mod circuit_instance;
pub mod types;

use std::env;
use spartan2::spartan::SpartanSNARK;
use tracing::info_span;
use crate::nizk_prover::prove;
use crate::nizk_verifier::verify;
use crate::noir::synthesis::circuit_synthesizer::NoirCircuitSynthesizer;
use crate::circuit_instance::instantiate_circuit;
use crate::noir::circuit::CircuitParameters;
use crate::types::{E, Scalar};

fn run_proof_and_verification(circuit: CircuitParameters) {
    let _total_span = info_span!("total", circuit = ?circuit.name).entered();

    tracing::info!("Running prover and verifier for {:?}", circuit.name);
    tracing::debug!("ProgramArtifact loaded: {:?}", &circuit.program_artifact);
    tracing::debug!("Prover inputs {:?}", &circuit.verifier_inputs);
    let prover_circuit = {
        let _span = info_span!("prover_circuit_synthesis").entered();
        NoirCircuitSynthesizer::new(circuit.program_artifact.clone(), circuit.prover_inputs)
    };

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

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    let args: Vec<String> = env::args().collect();

    let circuit_names: Vec<String> = if args.len() == 1 || args[1] == "all" {
        vec![
            "c0000_trivial".to_string(),
            "c0001_trivial_with_range".to_string(),
            "c0002_trivial_with_strings".to_string(),
            "c0003_trivial_with_brillig".to_string(),
        ]
    } else {
        args[1..].to_vec()
    };

    for name in circuit_names {
        let circuit = instantiate_circuit(name.as_str());
        run_proof_and_verification(circuit);
    }
}