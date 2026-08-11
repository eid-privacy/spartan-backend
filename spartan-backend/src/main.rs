use std::{env, path::PathBuf};

use clap::Parser;
use spartan_backend::{
    E, instantiate_circuit_from_dir, instantiate_circuit_with_name,
    noir::{circuit::CircuitParameters, synthesis::circuit_synthesizer::NoirCircuitSynthesizer},
    prove_circuit, prove_circuit_to_base64, report_proof_size, verify_circuit,
    verify_circuit_from_base64,
};
use tracing::info_span;
use vega_prover::bellpepper::{r1cs::VegaShape, shape_cs::ShapeCS};

/// Vega zkSNARK backend for Noir circuits — prove and verify.
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

    /// Create a proof and report its serialized size in bytes; skip verify.
    #[arg(short = 's', long = "proof-size")]
    proof_size: bool,

    /// Only run the prover and print the base64-encoded (bincode) proof to stdout; skip verify.
    #[arg(short = 'p', long = "prove")]
    prove: bool,

    /// Only run the verifier against a base64-encoded (bincode) proof passed as
    /// the value (as produced by `--prove`); skip prove.
    #[arg(long = "verify", value_name = "BASE64_PROOF")]
    verify: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Honor -v unless the user already set RUST_LOG explicitly.
    if env::var("RUST_LOG").is_err() {
        if cli.verbose {
            // SAFETY: called before any other threads are spawned.
            unsafe { env::set_var("RUST_LOG", "info") };
        }
    }

    // Logs go to stderr so that stdout carries only the program's output (e.g.
    // the base64 proof printed by `--prove`), keeping the CLI pipeable. ANSI
    // colours are only emitted when stderr is a terminal, so redirected logs
    // stay greppable.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
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
        } else if cli.proof_size {
            report_proof_size(circuit);
        } else if cli.prove {
            let proof_b64 = prove_circuit_to_base64(&circuit).expect("Proof creation failed.");
            println!("{}", proof_b64);
        } else if let Some(proof_base64) = &cli.verify {
            verify_circuit_from_base64(&circuit, proof_base64).expect("Proof verification failed");
            tracing::info!("Verification successful.");
        } else {
            tracing::info!("Running circuit {}", circuit.name);
            let proof = prove_circuit(&circuit).expect("Proof creation failed");

            verify_circuit(&circuit, proof).expect("Proof verification failed");
            tracing::info!("Verification successful.");
        }
    }

    Ok(())
}

/// Synthesizes the circuit into a [`ShapeCS`] and reports the resulting R1CS
/// sizes without running prove/verify. Uses vega's own accounting so the
/// numbers match what `VegaZkSNARK::setup` sees.
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
