//! Persist the offline ("prep") phase of a proof next to the circuit so that a
//! later `--prove` run can skip `setup` + `prep_prove` entirely.
//!
//! The artifact is a single bincode file, `<circuit_dir>/target/precompute.bin`.
//! It embeds a [`Fingerprint`] of what actually invalidates a prepared state:
//! the ACIR bytecode and the online seed witnesses. Input *values* are excluded
//! — changing them between proofs is the entire point of the online path. A
//! mismatch is a warning, not an error: we fall back to monolithic proving.
//!
//! `Snark::prove` returns a rerandomized prep which we deliberately do not write
//! back: the file is read-only at prove time and every run reuses the same prep.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    noir::circuit::CircuitParameters,
    online_prover::{OnlineProver, PrepSnark, ProverKey, VerifierKey},
};

/// Name of the artifact written inside the circuit's `target/` directory.
pub const PRECOMPUTE_FILE: &str = "precompute.bin";

/// Bumped whenever the on-disk layout changes, so older files are ignored
/// instead of being mis-deserialized.
const FORMAT_VERSION: u32 = 1;

/// Cheap staleness marker for a precomputed artifact. Not a security boundary.
pub type Fingerprint = u64;

/// The on-disk contents of `target/precompute.bin`.
#[derive(Serialize, Deserialize)]
pub struct PrecomputeFile {
    pub version: u32,
    pub fingerprint: Fingerprint,
    pub pk: ProverKey,
    pub vk: VerifierKey,
    pub prep: PrepSnark,
}

/// Borrowed mirror of [`PrecomputeFile`] used for writing, so we never clone the
/// (large) prover key and prepared state. bincode is positional, so the field
/// order must stay identical.
#[derive(Serialize)]
struct PrecomputeFileRef<'a> {
    version: u32,
    fingerprint: Fingerprint,
    pk: &'a ProverKey,
    vk: &'a VerifierKey,
    prep: &'a PrepSnark,
}

/// Path of the precompute artifact for a circuit directory.
pub fn precompute_path(circuit_dir: &Path) -> PathBuf {
    circuit_dir.join("target").join(PRECOMPUTE_FILE)
}

/// Path of the precompute artifact for a circuit.
pub fn path_for(circuit: &CircuitParameters) -> PathBuf {
    precompute_path(&circuit.dir)
}

/// Fingerprint of everything that invalidates a prepared state: the ACIR
/// bytecode and the online partition seeds.
pub fn fingerprint(circuit: &CircuitParameters) -> Fingerprint {
    let mut hasher = DefaultHasher::new();

    let bytecode = bincode::serialize(&circuit.program_artifact.bytecode)
        .expect("ACIR bytecode must be serializable");
    bytecode.hash(&mut hasher);

    let mut seeds: Vec<u32> = circuit.online_seeds.iter().copied().collect();
    seeds.sort_unstable();
    seeds.hash(&mut hasher);

    hasher.finish()
}

fn to_io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

/// Write the prover's reusable artifacts to `target/precompute.bin` inside the
/// circuit directory. Returns the path written and its size in bytes.
pub fn save(circuit: &CircuitParameters, prover: &OnlineProver) -> io::Result<(PathBuf, u64)> {
    let path = path_for(circuit);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = PrecomputeFileRef {
        version: FORMAT_VERSION,
        fingerprint: fingerprint(circuit),
        pk: prover.prover_key(),
        vk: prover.verifier_key(),
        prep: prover.prep(),
    };

    let bytes = bincode::serialize(&file).map_err(to_io_err)?;
    let len = bytes.len() as u64;
    std::fs::write(&path, bytes)?;
    Ok((path, len))
}

/// Load a previously saved [`OnlineProver`] for this circuit.
///
/// Returns `None` — after logging the reason — when the file is absent, stale or
/// unreadable; callers then fall back to the regular proving path.
pub fn load(circuit: &CircuitParameters) -> Option<OnlineProver> {
    let path = path_for(circuit);
    let started = std::time::Instant::now();

    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            tracing::debug!("No precomputed artifact at {}", path.display());
            return None;
        }
        Err(e) => {
            tracing::warn!("Failed to read {}: {e}", path.display());
            return None;
        }
    };

    let size_bytes = bytes.len() as u64;
    let file: PrecomputeFile = match bincode::deserialize(&bytes) {
        Ok(file) => file,
        Err(e) => {
            tracing::warn!(
                "Failed to deserialize {}: {e}; ignoring the precomputed artifact",
                path.display()
            );
            return None;
        }
    };

    if file.version != FORMAT_VERSION {
        tracing::warn!(
            "{} was written by format version {} (expected {}); ignoring it",
            path.display(),
            file.version,
            FORMAT_VERSION
        );
        return None;
    }

    let expected = fingerprint(circuit);
    if file.fingerprint != expected {
        tracing::warn!(
            "{} is stale (fingerprint {:#x}, circuit is {:#x}); re-run --precompute. \
             Falling back to regular proving.",
            path.display(),
            file.fingerprint,
            expected
        );
        return None;
    }

    tracing::info!("Loaded precomputed artifact from {}", path.display());
    // Machine-parsable counterpart, parsed by scripts/online_bench.sh.
    tracing::info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        size_bytes,
        "precompute_load"
    );
    Some(OnlineProver::from_parts(file.pk, file.vk, file.prep))
}
