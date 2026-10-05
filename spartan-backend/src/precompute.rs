//! Persist the offline ("prep") phase of a proof next to the circuit so that a
//! later `--prove` run can skip `setup` + `prep_prove` entirely.
//!
//! The artifact is `<circuit_dir>/target/precompute.bin`. It embeds a
//! [`Fingerprint`] of what actually invalidates a prepared state: the ACIR
//! bytecode and the online seed witnesses. Input *values* are excluded —
//! changing them between proofs is the entire point of the online path. A
//! mismatch is a warning, not an error: we fall back to monolithic proving.
//!
//! The format is private to this module and the file is trusted, so it is
//! laid out for load speed and size only:
//!
//! ```text
//! version: u32 | fingerprint: u64 | pk_len: u64
//! bincode(pk) | bincode(prep)
//! ```
//!
//! - The verifier key is not stored: `--prove` never reads it.
//! - There is no outer compression. vega's `raw_serde` already stores every
//!   large vector — the R1CS matrices, the cached `Az`/`Bz`/`Cz` products, the
//!   witness — as zstd-framed raw memory inside the bincode stream, and
//!   decompresses it straight into its final allocation. What is left of the
//!   stream is metadata and small vectors.
//! - The prep scratch buffers are `#[serde(skip)]` in vega: `Snark::prove`
//!   clears and refills them before every use.
//! - The two blobs are decoded on two threads.
//!
//! `Snark::prove` returns a rerandomized prep which we deliberately do not write
//! back: the file is read-only at prove time and every run reuses the same prep.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    io,
    path::{Path, PathBuf},
};

use crate::{
    noir::circuit::CircuitParameters,
    online_prover::{OnlineProver, PrepSnark, ProverKey},
};

/// Name of the artifact written inside the circuit's `target/` directory.
pub const PRECOMPUTE_FILE: &str = "precompute.bin";

/// Bumped whenever the on-disk layout changes, so older files are ignored
/// instead of being mis-deserialized.
const FORMAT_VERSION: u32 = 3;

/// Cheap staleness marker for a precomputed artifact. Not a security boundary.
pub type Fingerprint = u64;

/// Fixed-size header in front of the two bincode blobs.
struct Header {
    version: u32,
    fingerprint: Fingerprint,
    pk_len: u64,
}

impl Header {
    const SIZE: usize = 4 + 2 * 8;

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
        for v in [self.fingerprint, self.pk_len] {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn read(bytes: &[u8]) -> Option<Self> {
        let header = bytes.get(..Self::SIZE)?;
        let u64_at = |i: usize| u64::from_le_bytes(header[4 + 8 * i..][..8].try_into().unwrap());
        Some(Self {
            version: u32::from_le_bytes(header[..4].try_into().unwrap()),
            fingerprint: u64_at(0),
            pk_len: u64_at(1),
        })
    }
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

/// Encodes the prover's reusable artifacts in the `precompute.bin` format.
pub fn encode(fingerprint: Fingerprint, pk: &ProverKey, prep: &PrepSnark) -> io::Result<Vec<u8>> {
    let (pk, prep) = std::thread::scope(|s| {
        let pk = s.spawn(|| bincode::serialize(pk).map_err(to_io_err));
        let prep = bincode::serialize(prep).map_err(to_io_err);
        (pk.join().expect("pk encoder panicked"), prep)
    });
    let (pk, prep) = (pk?, prep?);

    let mut out = Vec::with_capacity(Header::SIZE + pk.len() + prep.len());
    Header {
        version: FORMAT_VERSION,
        fingerprint,
        pk_len: pk.len() as u64,
    }
    .write(&mut out);
    out.extend_from_slice(&pk);
    out.extend_from_slice(&prep);
    Ok(out)
}

/// Why [`decode`] rejected an artifact.
#[derive(Debug)]
pub enum DecodeError {
    Version(u32),
    Stale(Fingerprint),
    Corrupt(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Version(v) => {
                write!(
                    f,
                    "written by format version {v} (expected {FORMAT_VERSION})"
                )
            }
            DecodeError::Stale(fp) => write!(f, "stale (fingerprint {fp:#x})"),
            DecodeError::Corrupt(e) => write!(f, "corrupt: {e}"),
        }
    }
}

/// Decodes a `precompute.bin`, rejecting it before the expensive part when its
/// version or fingerprint does not match.
pub fn decode(bytes: &[u8], expected: Fingerprint) -> Result<(ProverKey, PrepSnark), DecodeError> {
    let corrupt = |e: &dyn std::fmt::Display| DecodeError::Corrupt(e.to_string());
    let header = Header::read(bytes).ok_or_else(|| corrupt(&"truncated header"))?;
    if header.version != FORMAT_VERSION {
        return Err(DecodeError::Version(header.version));
    }
    if header.fingerprint != expected {
        return Err(DecodeError::Stale(header.fingerprint));
    }
    let frames = &bytes[Header::SIZE..];
    if header.pk_len > frames.len() as u64 {
        return Err(corrupt(&"truncated prover key"));
    }
    let (pk, prep) = frames.split_at(header.pk_len as usize);

    std::thread::scope(|s| {
        let pk = s.spawn(|| -> Result<ProverKey, DecodeError> {
            bincode::deserialize(pk).map_err(|e| corrupt(&e))
        });
        let prep: PrepSnark = bincode::deserialize(prep).map_err(|e| corrupt(&e))?;
        Ok((pk.join().expect("pk decoder panicked")?, prep))
    })
}

/// Write the prover's reusable artifacts to `target/precompute.bin` inside the
/// circuit directory. Returns the path written and its size in bytes.
pub fn save(circuit: &CircuitParameters, prover: &OnlineProver) -> io::Result<(PathBuf, u64)> {
    let path = path_for(circuit);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let bytes = encode(fingerprint(circuit), prover.prover_key(), prover.prep())?;
    let len = bytes.len() as u64;
    std::fs::write(&path, bytes)?;
    Ok((path, len))
}

/// Load a previously saved [`OnlineProver`] for this circuit.
///
/// Returns `None` — after logging the reason — when the file is absent, stale or
/// unreadable; callers then fall back to the regular proving path.
pub fn load(circuit: &CircuitParameters, path: PathBuf) -> Option<OnlineProver> {
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
    let (pk, prep) = match decode(&bytes, fingerprint(circuit)) {
        Ok(parts) => parts,
        Err(DecodeError::Stale(found)) => {
            tracing::warn!(
                "{} is stale (fingerprint {:#x}, circuit is {:#x}); re-run --precompute. \
                 Falling back to regular proving.",
                path.display(),
                found,
                fingerprint(circuit)
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(
                "{} is {e}; ignoring the precomputed artifact",
                path.display()
            );
            return None;
        }
    };

    tracing::info!("Loaded precomputed artifact from {}", path.display());
    // Machine-parsable counterpart, parsed by scripts/online_bench.sh.
    tracing::info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        size_bytes,
        "precompute_load"
    );
    Some(OnlineProver::from_parts(pk, prep))
}
