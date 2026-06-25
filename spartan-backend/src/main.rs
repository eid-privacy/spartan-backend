mod circuit_instance;
mod nizk_prover;
mod nizk_verifier;
pub mod noir;
mod trivial_circuit;
pub mod types;
mod utils;

use crate::types::Scalar;
use clap::Parser;
use spartan_backend::{
    instantiate_circuit_from_dir, instantiate_circuit_with_name, run_proof_and_verification,
};
use std::env;
use std::path::PathBuf;

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
                "c0100_holder_binding_crescent_style",
            ];
            for name in default_circuits {
                tracing::info!("Running circuit {name}");
                let circuit = instantiate_circuit_with_name(name);
                run_proof_and_verification(circuit);
            }
        }
    }
}
