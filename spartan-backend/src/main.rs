use std::{env, path::PathBuf, time::Instant};

use clap::Parser;
use spartan_backend::{
    E, instantiate_circuit_from_dir, instantiate_circuit_with_name,
    noir::{circuit::CircuitParameters, synthesis::circuit_synthesizer::NoirCircuitSynthesizer},
    online_prover::{OnlineProver, expected_public_values, persistence, verify_online},
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

    /// online-proving benchmark: run `setup`+`prep` once, then produce
    /// and verify N proofs reusing the prepared state, reporting per-proof
    /// timings and the amortized speedup vs. the one-off prep cost.
    #[arg(long = "online", value_name = "N")]
    online: Option<usize>,

    /// Optional directory to persist (`pk.bin`/`vk.bin`/`prep.bin`) after prep
    /// and reload before proving, demonstrating cold-start reuse. Only used with
    /// `--online`.
    #[arg(long = "prep-dir", value_name = "DIR")]
    prep_dir: Option<PathBuf>,

    /// Additional circuit directories to prove online, reusing the SAME prepared
    /// state as the primary circuit. Use for genuinely distinct challenges: each
    /// dir must share the invariant credential inputs and differ only in the
    /// online (manifest-declared) inputs. Repeatable. Only used with `--online`.
    #[arg(long = "also", value_name = "DIR")]
    also: Vec<PathBuf>,
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
        } else if cli.precompute {
            run_precompute(&circuit);
        } else if let Some(n) = cli.online {
            run_online(circuit, n, cli.prep_dir.as_deref(), &cli.also);
        } else if cli.proof_size {
            report_proof_size(circuit);
        } else if cli.prove {
            let proof_b64 = prove_with_precompute(&circuit);
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
/// `<circuit_dir>/target/precompute.bin`. A later `--prove` picks it up
/// automatically.
fn run_precompute(circuit: &CircuitParameters) {
    let _span = info_span!("precompute", circuit = ?circuit.name).entered();

    if circuit.online_seeds.is_empty() {
        println!(
            "{}: no online manifest (online.json) — every witness is in the rest segment; \
             the precomputed state still saves `setup`, but the witness commitment is redone \
             on every proof. Add an online.json to get the full benefit.",
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
/// and still matches the circuit. Falls back to the regular monolithic prover
/// otherwise.
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

/// Online-proving benchmark. Runs `setup`+`prep` once (the amortized
/// cost, dominated by committing the invariant witness) and then produces and
/// verifies proofs that reuse the prepared state. With `prep_dir` set, the
/// artifacts are persisted after prep and reloaded before proving to exercise
/// the cold-start path.
///
/// The primary `circuit` is proven `n` times. Each directory in `also` is a
/// genuinely distinct challenge (same credential, different online inputs) and
/// is proven once, reusing the very same prepared state — this is the real
/// multi-challenge online path. To generate such directories, regenerate the
/// circuit's online inputs per challenge (see `scripts/online_bench.sh` and
/// `preprocessing/c0200_siyu_jwt`), keeping the invariant credential inputs
/// fixed.
fn run_online(
    circuit: CircuitParameters,
    n: usize,
    prep_dir: Option<&std::path::Path>,
    also: &[PathBuf],
) {
    let _span = info_span!("online", circuit = ?circuit.name).entered();

    if circuit.online_seeds.is_empty() {
        println!(
            "{}: no online manifest (online.json) — every witness is in the rest segment; \
             prep reuse yields no benefit. Add an online.json to enable pre-computation.",
            circuit.name
        );
    }

    // --- setup + prep (amortized once) -----------------------------------
    let t_setup = Instant::now();
    let mut prover = OnlineProver::setup(&circuit).expect("online setup/prep failed");
    let setup_prep_elapsed = t_setup.elapsed();
    println!(
        "{}: setup+prep = {:.3?} (one-off, reused across all online proofs)",
        circuit.name, setup_prep_elapsed
    );

    // --- optional persistence round-trip (cold start) --------------------
    if let Some(dir) = prep_dir {
        let t_save = Instant::now();
        persistence::save_all(
            dir,
            prover.prover_key(),
            prover.verifier_key(),
            prover.prep(),
        )
        .expect("failed to persist prep artifacts");
        let save_elapsed = t_save.elapsed();

        let t_load = Instant::now();
        let (pk, vk, prep) = persistence::load_all(dir).expect("failed to reload prep artifacts");
        let load_elapsed = t_load.elapsed();
        prover = OnlineProver::from_parts(pk, vk, prep);

        println!(
            "{}: persisted prep to {} (save={:.3?}, load={:.3?})",
            circuit.name,
            dir.display(),
            save_elapsed,
            load_elapsed
        );
    }

    let expected = expected_public_values(&circuit);

    // --- online proofs of the primary circuit (reuse prep) ---------------
    let mut first: Option<std::time::Duration> = None;
    let mut warm_total = std::time::Duration::ZERO;
    for i in 0..n {
        let t_prove = Instant::now();
        let proof = prover.prove_online(&circuit).expect("online prove failed");
        let prove_elapsed = t_prove.elapsed();

        verify_online(prover.verifier_key(), &proof, &expected).expect("online verify failed");

        if i == 0 {
            first = Some(prove_elapsed);
        } else {
            warm_total += prove_elapsed;
        }
        println!(
            "{}: online proof {}/{} prove={:.3?} (verified)",
            circuit.name,
            i + 1,
            n,
            prove_elapsed
        );
    }

    if let Some(first) = first {
        println!(
            "{}: first prove (caches rest MSM) = {:.3?}",
            circuit.name, first
        );
    }
    if n > 1 {
        let warm_avg = warm_total / (n as u32 - 1);
        println!(
            "{}: warm prove avg (delta MSM, {} samples) = {:.3?}",
            circuit.name,
            n - 1,
            warm_avg
        );
    }

    // --- distinct-challenge circuits (reuse the same prep) ---------------
    for dir in also {
        let other = instantiate_circuit_from_dir(dir);
        if other.online_seeds != circuit.online_seeds {
            eprintln!(
                "warning: {} has a different online manifest than the primary circuit; \
                 prep reuse assumes an identical partition",
                other.name
            );
        }
        let other_expected = expected_public_values(&other);
        let t_prove = Instant::now();
        let proof = prover
            .prove_online(&other)
            .expect("online prove (distinct challenge) failed");
        let prove_elapsed = t_prove.elapsed();
        verify_online(prover.verifier_key(), &proof, &other_expected)
            .expect("online verify (distinct challenge) failed");
        println!(
            "{}: distinct-challenge online proof prove={:.3?} (verified, reused prep from {})",
            other.name, prove_elapsed, circuit.name
        );
    }
}
