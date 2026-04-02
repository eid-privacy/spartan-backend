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
use tracing::{debug, info, info_span};

type E = T256HyraxEngine;
type Scalar = <E as Engine>::Scalar;

/// Spartan2 backend for Noir circuits — prove and verify.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to a noir circuit directory
    /// When omitted, all built-in circuits are run.
    circuit_dir: Option<PathBuf>,

    /// Enable info-level logging (default is warn; use RUST_LOG for finer control).
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn run_proof_and_verification(circuit: CircuitParameters) {
    let _total_span = info_span!("total", circuit = ?circuit.name).entered();

    info!("Running prover and verifier for {:?}", circuit.name);
    debug!("ProgramArtifact loaded: {:?}", &circuit.program_artifact);
    debug!("Prover inputs {:?}", &circuit.prover_inputs);
    debug!("Prover inputs {:?}", &circuit.verifier_inputs);

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
    info!("Verification successful.");
}

fn main() {
    let cli = Cli::parse();

    // Honour -v unless the user already set RUST_LOG explicitly.
    if std::env::var("RUST_LOG").is_err() {
        if cli.verbose {
            // SAFETY: called before any other threads are spawned.
            unsafe { std::env::set_var("RUST_LOG", "warn,spartan_backend=info") };
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    match cli.circuit_dir {
        Some(dir) => {
            info!("Running circuit from directory {}", dir.display());
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
                info!("Running circuit {name}");
                let circuit = instantiate_circuit(name);
                run_proof_and_verification(circuit);
            }
        }
    }
}
