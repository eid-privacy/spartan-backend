mod utils;
mod trivial_circuit;
mod nizk_prover;
mod nizk_verifier;
pub mod noir;

use std::collections::HashMap;
use ff::Field;
use spartan2::provider::T256HyraxEngine;
use spartan2::spartan::SpartanSNARK;
use spartan2::traits::Engine;
use crate::nizk_prover::prove;
use crate::nizk_verifier::verify;
use crate::noir::circuit::CircuitParameters;
use crate::noir::circuit_reader::read_noir_circuit;
use crate::noir::circuit_synthesizer::NoirCircuitSynthesizer;

type E = T256HyraxEngine;

fn circuit_path(name: &str) -> String {
    format!("../circuits/{}/target/{}.json", name, name)
}

#[allow(unused)]
fn instantiate_trivial_circuit() ->  CircuitParameters {
    let program_artifact = read_noir_circuit(circuit_path("c0000_trivial").as_str())
        .expect("Failed to read noir circuit");

    let map_input = |public: <E as Engine>::Scalar, private: Option<<E as Engine>::Scalar>| HashMap::from([
        (String::from("public_number"), Some(public)),
        (String::from("private_number"), private),
    ]);

    let verifier_inputs = map_input(<E as Engine>::Scalar::ONE, None);
    let prover_inputs = map_input(<E as Engine>::Scalar::ONE, Some(<E as Engine>::Scalar::ONE));

    CircuitParameters {
        program_artifact,
        verifier_inputs,
        prover_inputs,
    }
}

#[allow(unused)]
fn instantiate_trivial_circuit_with_range() ->  CircuitParameters {
    let program_artifact = read_noir_circuit(circuit_path("c0001_trivial_with_range").as_str())
        .expect("Failed to read noir circuit");

    let map_input = |public: <E as Engine>::Scalar, private: Option<<E as Engine>::Scalar>| HashMap::from([
        (String::from("public_number"), Some(public)),
        (String::from("private_number"), private),
    ]);

    // Input passing the RANGE test
    let verifier_inputs = map_input(<E as Engine>::Scalar::ONE, None);
    let prover_inputs = map_input(<E as Engine>::Scalar::ONE, Some(<E as Engine>::Scalar::ONE));

    // Inputs failing the RANGE test.
    // let max_input = <E as Engine>::Scalar::ZERO - <E as Engine>::Scalar::ONE;
    // let verifier_inputs = map_input(max_input, None);
    // let prover_inputs = map_input(max_input, Some(max_input));

    CircuitParameters {
        program_artifact,
        verifier_inputs,
        prover_inputs,
    }
}

#[allow(unused)]
fn instantiate_trivial_circuit_with_strings() ->  CircuitParameters {
    let program_artifact = read_noir_circuit(circuit_path("c0002_trivial_with_strings").as_str())
        .expect("Failed to read noir circuit");

    let map_input = |public: <E as Engine>::Scalar, private: Option<<E as Engine>::Scalar>| HashMap::from([
        (String::from("public_number"), Some(public)),
        (String::from("private_number"), private),
    ]);

    let verifier_inputs = map_input(<E as Engine>::Scalar::ONE, None);
    let prover_inputs = map_input(<E as Engine>::Scalar::ONE, Some(<E as Engine>::Scalar::ONE));


    CircuitParameters {
        program_artifact,
        verifier_inputs,
        prover_inputs,
    }
}


fn main() {
    env_logger::init();

    // let circuit = instantiate_trivial_circuit();
    let circuit = instantiate_trivial_circuit_with_range();
    // let circuit = instantiate_trivial_circuit_with_strings();

    log::info!("ProgramArtifact loaded: {:?}", &circuit.program_artifact);
    let prover_circuit = NoirCircuitSynthesizer::new(
        circuit.program_artifact.clone(),
        circuit.prover_inputs,
    );

    let verifier_circuit = NoirCircuitSynthesizer::new(
        circuit.program_artifact,
        circuit.verifier_inputs,
    );

    let proof: SpartanSNARK<E> = prove(prover_circuit);

    let verification_result = verify(verifier_circuit, proof);
    verification_result.expect("verify failed");
    log::info!("Verification successful.");
}