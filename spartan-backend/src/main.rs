use std::{env, path::PathBuf, time::Instant};

use clap::Parser;
use spartan_backend::{
    E, instantiate_circuit_from_dir, instantiate_circuit_with_name,
    instantiate_prover_circuit_from_dir, instantiate_prover_circuit_with_name,
    noir::{circuit::CircuitParameters, synthesis::circuit_synthesizer::NoirCircuitSynthesizer},
    online_prover::OnlineProver,
    precompute, proof_to_base64, prove_circuit, prove_circuit_to_base64, report_proof_size,
    verify_circuit, verify_circuit_from_base64,
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
    /// Transparently reuses `<circuit_dir>/target/precompute.bin` when present (see
    /// `--precompute`).
    #[arg(short = 'p', long = "prove")]
    prove: bool,

    /// Run the offline phase (setup + prep) once and persist it to
    /// `<circuit_dir>/target/precompute.bin` so later `--prove` runs can skip it.
    #[arg(long = "precompute")]
    precompute: bool,

    /// Only run the verifier against a base64-encoded (bincode) proof passed as
    /// the value (as produced by `--prove`); skip prove.
    #[arg(long = "verify", value_name = "BASE64_PROOF")]
    verify: Option<String>,
}

/// Which operation the CLI was asked to perform, resolved once from [`Cli`].
enum Mode {
    /// Default: full prove + verify cycle. Circuit includes verifier inputs.
    ProveAndVerify,
    /// `--count-constraints`: synthesize and report R1CS sizes only.
    CountConstraints,
    /// `--precompute`: run offline phase and persist to disk.
    Precompute,
    /// `--proof-size`: prove and report serialized proof size.
    ProofSize,
    /// `--prove`: produce a base64 proof on stdout. No verifier inputs needed.
    Prove,
    /// `--verify <b64>`: verify the given proof. Circuit includes verifier inputs.
    Verify(String),
}

impl Mode {
    fn from_cli(cli: &Cli) -> Self {
        if cli.count_constraints {
            Mode::CountConstraints
        } else if cli.precompute {
            Mode::Precompute
        } else if cli.proof_size {
            Mode::ProofSize
        } else if cli.prove {
            Mode::Prove
        } else if let Some(proof) = cli.verify.clone() {
            Mode::Verify(proof)
        } else {
            Mode::ProveAndVerify
        }
    }

    fn needs_verifier_inputs(&self) -> bool {
        matches!(self, Mode::ProveAndVerify | Mode::Verify(_))
    }
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

    let mode = Mode::from_cli(&cli);
    let circuits = load_circuits(&cli.circuit_dir, mode.needs_verifier_inputs());

    for circuit in circuits {
        run_mode(&mode, circuit);
    }

    Ok(())
}

fn load_circuits(
    circuit_dir: &Option<PathBuf>,
    with_verifier_inputs: bool,
) -> Vec<CircuitParameters> {
    const DEFAULT_CIRCUITS: [&str; 7] = [
        "c0000_trivial",
        "c0001_trivial_with_range",
        "c0002_trivial_with_strings",
        "c0003_trivial_with_brillig",
        "c0004_trivial_elliptic_curve_add",
        "c0005_trivial_msm",
        "c0100_holder_binding_crescent_style",
    ];

    let load_by_dir = if with_verifier_inputs {
        instantiate_circuit_from_dir
    } else {
        instantiate_prover_circuit_from_dir
    };
    let load_by_name = if with_verifier_inputs {
        instantiate_circuit_with_name
    } else {
        instantiate_prover_circuit_with_name
    };

    match circuit_dir {
        Some(dir) => vec![load_by_dir(dir)],
        None => DEFAULT_CIRCUITS.map(load_by_name).into(),
    }
}

fn run_mode(mode: &Mode, circuit: CircuitParameters) {
    match mode {
        Mode::CountConstraints => count_constraints(circuit),
        Mode::Precompute => run_precompute(&circuit),
        Mode::ProofSize => report_proof_size(circuit),
        Mode::Prove => {
            let proof_b64 = prove_with_precompute(&circuit);
            println!("{}", proof_b64);
        }
        Mode::Verify(proof_base64) => {
            verify_circuit_from_base64(&circuit, proof_base64).expect("Proof verification failed");
            tracing::info!("Verification successful.");
        }
        Mode::ProveAndVerify => {
            tracing::info!("Running circuit {}", circuit.name);
            let proof = prove_circuit(&circuit).expect("Proof creation failed");
            verify_circuit(&circuit, proof).expect("Proof verification failed");
            tracing::info!("Verification successful.");
        }
    }
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
        &circuit.online_seeds,
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

/// Runs the offline phase (`setup` + `prep_prove`) once and persists it to
/// `<circuit_dir>/target/precompute.bin`, which `--prove` then picks up.
fn run_precompute(circuit: &CircuitParameters) {
    let _span = info_span!("precompute", circuit = ?circuit.name).entered();

    if circuit.online_seeds.is_empty() {
        println!(
            "{}: no online.json — every witness lands in the rest segment, so only `setup` \
             is saved and the witness commitment is redone on every proof.",
            circuit.name
        );
    }

    let t_setup = Instant::now();
    let prover = OnlineProver::setup(circuit).expect("precompute (setup + prep) failed");
    let setup_elapsed = t_setup.elapsed();

    let (path, size) = precompute::save(circuit, &prover).expect("failed to write precompute.bin");

    println!(
        "{}: precompute = {:.3?}, wrote {} ({:.1} MiB)",
        circuit.name,
        setup_elapsed,
        path.display(),
        size as f64 / (1024.0 * 1024.0),
    );
}

/// Produces a base64 proof, reusing `target/precompute.bin` when it is present
/// and still matches the circuit, otherwise falling back to monolithic proving.
fn prove_with_precompute(circuit: &CircuitParameters) -> String {
    match precompute::load(circuit) {
        Some(mut prover) => {
            let _span = info_span!("prove_precomputed", circuit = ?circuit.name).entered();
            let proof = prover
                .prove_online(circuit)
                .expect("Proof creation from precomputed state failed.");
            proof_to_base64(&proof)
        }
        None => prove_circuit_to_base64(circuit).expect("Proof creation failed."),
    }
}
