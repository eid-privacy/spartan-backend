//! Persist the offline ("prep") phase of a proof next to the circuit so that a
//! later `--prove` run can skip `setup` + `prep_prove` entirely.
//!
//! The whole thing lives in a single file, `<circuit_dir>/target/precompute.bin`,
//! serialized with bincode 1.3 (the same serializer Vega uses internally).
//!
//! ## Staleness
//! The file embeds a [`Fingerprint`] computed from *only* what actually
//! invalidates the prepared state: the circuit's ACIR bytecode and the set of
//! witness indices declared online by `online.json`. The **values** of the
//! online inputs (challenge nonce, device signature, ...) are deliberately not
//! part of the fingerprint — changing them between proofs is the entire point of
//! the online path. Prover/verifier input values are excluded for the same
//! reason. A mismatch is a warning, not an error: we fall back to the regular
//! monolithic proving path.
//!
//! ## Prep rerandomization
//! `Snark::prove` consumes the prepared state and returns a rerandomized one.
//! We intentionally do **not** write that refreshed state back to disk: the file
//! is read-only at prove time and every run reuses the same prep. This is a
//! deliberate design choice, not an oversight.

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

/// Bumped whenever the on-disk layout changes; an older file is then ignored
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

/// Borrowed mirror of [`PrecomputeFile`] used for writing, so we never have to
/// clone the (large) prover key and prepared state. The field order must stay
/// identical: bincode is positional.
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
/// bytecode and the online partition seeds. Input *values* are excluded on
/// purpose (see the module docs).
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
/// Returns `None` — after logging the reason — when the file is absent, was
/// written by another format version, does not match the circuit's current
/// fingerprint, or cannot be deserialized. Callers are expected to fall back to
/// the regular proving path.
pub fn load(circuit: &CircuitParameters) -> Option<OnlineProver> {
    let path = path_for(circuit);

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
    Some(OnlineProver::from_parts(file.pk, file.vk, file.prep))
}
