use clap::Parser;
use spartan_backend::noir::circuit::CircuitParameters;
use spartan_backend::noir::synthesis::circuit_synthesizer::NoirCircuitSynthesizer;
use spartan_backend::{
    E, instantiate_circuit_from_dir, instantiate_circuit_with_name, prove_circuit, verify_circuit,
};
use spartan2::bellpepper::r1cs::SpartanShape;
use spartan2::bellpepper::shape_cs::ShapeCS;
use std::env;
use std::path::PathBuf;
use tracing::info_span;

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

    /// Only synthesize the circuit and report R1CS constraint counts; skip prove/verify.
    #[arg(short = 'c', long = "count-constraints")]
    count_constraints: bool,
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

    let circuits: Vec<CircuitParameters> = match cli.circuit_dir {
        Some(dir) => {
            vec![instantiate_circuit_from_dir(&dir)]
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
            default_circuits
                .map(|name| instantiate_circuit_with_name(name))
                .into()
        }
    };

    for circuit in circuits {
        if cli.count_constraints {
            count_constraints(circuit);
        } else {
            tracing::info!("Running circuit {}", circuit.name);
            let proof = prove_circuit(&circuit);
            verify_circuit(&circuit, proof);
        }
    }
}

/// Synthesizes the circuit into a [`ShapeCS`] and reports the resulting R1CS
/// sizes without running prove/verify. Uses spartan2's own accounting so the
/// numbers match what `SpartanSNARK::setup` sees.
fn count_constraints(circuit: CircuitParameters) {
    let _span = info_span!("count_constraints", circuit = ?circuit.name).entered();

    // The verifier inputs are enough to build the synthesizer: ShapeCS records
    // linear-combination structure without evaluating witness values, and
    // NoirCircuitSynthesizer defaults unassigned private wires to zero.
    let synth = NoirCircuitSynthesizer::new(
        circuit.program_artifact.clone(),
        circuit.verifier_inputs.clone(),
    );

    let shape = ShapeCS::<E>::r1cs_shape(&synth).expect("failed to synthesize R1CS shape");
    let [
        num_cons_unpadded,
        num_shared_unpadded,
        num_precommitted_unpadded,
        num_rest_unpadded,
        num_cons,
        num_shared,
        num_precommitted,
        num_rest,
        num_public,
        num_challenges,
    ] = shape.sizes();

    tracing::info!(
        num_cons_unpadded,
        num_cons,
        num_shared_unpadded,
        num_shared,
        num_precommitted_unpadded,
        num_precommitted,
        num_rest_unpadded,
        num_rest,
        num_public,
        num_challenges,
        "circuit_sizes"
    );

    println!(
        "{}: constraints={} (padded={}), shared={} (padded={}), precommitted={} (padded={}), rest={} (padded={}), public={}, challenges={}",
        circuit.name,
        num_cons_unpadded,
        num_cons,
        num_shared_unpadded,
        num_shared,
        num_precommitted_unpadded,
        num_precommitted,
        num_rest_unpadded,
        num_rest,
        num_public,
        num_challenges,
    );
}
