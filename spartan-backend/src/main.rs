mod circuit_instance;
mod nizk_prover;
mod nizk_verifier;
pub mod noir;
mod trivial_circuit;
mod utils;

use crate::circuit_instance::{instantiate_circuit, instantiate_circuit_from_dir};
use crate::nizk_prover::prove;
use crate::nizk_verifier::verify;
use crate::noir::circuit::CircuitParameters;
use crate::noir::circuit_synthesizer::NoirCircuitSynthesizer;
use clap::Parser;
use noir::circuit_reader::input_mapping::InputWireMapping;
use spartan2::provider::T256HyraxEngine;
use spartan2::spartan::SpartanSNARK;
use spartan2::traits::Engine;
use std::path::PathBuf;
#[allow(unused_imports)]
use std::time::Instant;

type E = T256HyraxEngine;
type Scalar = <E as Engine>::Scalar;

/// Spartan2 backend for Noir circuits — prove and verify.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to a circuit directory (containing target/*.json and *_input.json).
    /// When omitted, all built-in circuits are run.
    circuit_dir: Option<PathBuf>,

    /// Enable info-level logging (default is warn; use RUST_LOG for finer control).
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn run_proof_and_verification(circuit: CircuitParameters) {
    log::info!("Running prover and verifier for {:?}", circuit.name);
    log::debug!("ProgramArtifact loaded: {:?}", &circuit.program_artifact);
    log::debug!("Prover inputs {:?}", &circuit.verifier_inputs);

    let prover_circuit =
        NoirCircuitSynthesizer::new(circuit.program_artifact.clone(), circuit.prover_inputs);

    let proof_start = Instant::now();
    let proof: SpartanSNARK<E> = prove(prover_circuit);
    let proof_duration = proof_start.elapsed();
    log::info!("Proof creation took {:?}", proof_duration);

    let verifier_circuit =
        NoirCircuitSynthesizer::new(circuit.program_artifact, circuit.verifier_inputs);

    let verify_start = Instant::now();
    let verification_result = verify(verifier_circuit, proof);
    let verify_duration = verify_start.elapsed();
    log::info!("Proof verification took {:?}", verify_duration);

    verification_result.expect("verify failed");
    log::info!("Verification successful.");
}

fn main() {
    let cli = Cli::parse();

    // Honour -v unless the user already set RUST_LOG explicitly.
    if std::env::var("RUST_LOG").is_err() {
        if cli.verbose {
            // SAFETY: called before any other threads are spawned.
            unsafe { std::env::set_var("RUST_LOG", "info") };
        }
    }
    env_logger::init();

    match cli.circuit_dir {
        Some(dir) => {
            log::info!("Running circuit from directory {}", dir.display());
            let circuit = instantiate_circuit_from_dir(&dir);
            run_proof_and_verification(circuit);
        }
        None => {
            let default_circuits = [
                "c0000_trivial",
                "c0001_trivial_with_range",
                "c0002_trivial_with_strings",
            ];
            for name in default_circuits {
                log::info!("Running circuit {name}");
                let circuit = instantiate_circuit(name);
                run_proof_and_verification(circuit);
            }
        }
    }
}
