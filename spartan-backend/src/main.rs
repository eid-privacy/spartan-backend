mod utils;
mod trivial_circuit;
mod nizk_prover;
mod nizk_verifier;
pub mod noir;
mod circuit_instance;
pub mod types;

use std::env;
use std::path::PathBuf;
use spartan2::spartan::SpartanSNARK;
use tracing::info_span;
use clap::Parser;
use crate::nizk_prover::prove;
use crate::nizk_verifier::verify;
use crate::noir::synthesis::circuit_synthesizer::NoirCircuitSynthesizer;
use crate::circuit_instance::{instantiate_circuit_from_dir, instantiate_circuit_with_name};
use crate::noir::circuit::CircuitParameters;
use crate::types::{E, Scalar};

/// Spartan2 backend for Noir circuits — prove and verify.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to a circuit directory (containing target/*.json and *_input.json).Expand commentComment on line R29Resolved
    /// When omitted, all built-in circuits are run.
    circuit_dir: Option<PathBuf>,

    /// Enable info-level logging (default is warn; use RUST_LOG for finer control).
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn run_proof_and_verification(circuit: CircuitParameters) {
    let _total_span = info_span!("total", circuit = ?circuit.name).entered();

    tracing::info!("Running prover and verifier for {:?}", circuit.name);
    tracing::debug!("ProgramArtifact loaded: {:?}", &circuit.program_artifact);
    tracing::debug!("Prover inputs {:?}", &circuit.prover_inputs);
    tracing::debug!("Verifier inputs {:?}", &circuit.verifier_inputs);
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
    let cli = Cli::parse();

    // Honor -v unless the user already set RUST_LOG explicitly.
    if env::var("RUST_LOG").is_err() {
        if cli.verbose {
            // SAFETY: called before any other threads are spawned.
            unsafe { env::set_var("RUST_LOG", "info") };
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();


    match cli.circuit_dir {
        Some(dir) => {
            tracing::info!("Running circuit from directory {}", dir.display());
            let circuit = instantiate_circuit_from_dir(&dir);
            run_proof_and_verification(circuit);
        }
        None => {
            let default_circuits = [
                "c0000_trivial",
                "c0001_trivial_with_range",
                "c0002_trivial_with_strings",
                "c0003_trivial_with_brillig",
                "c0004_trivial_elliptic_curve_add",
                "c0005_trivial_msm",
            ];
            for name in default_circuits {
                tracing::info!("Running circuit {name}");
                let circuit = instantiate_circuit_with_name(name);
                run_proof_and_verification(circuit);
            }
        }
    }
}