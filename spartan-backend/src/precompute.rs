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
//! version: u32 | fingerprint: u64 | pk_len: u64 | prep_len: u64 | pk_zstd_len: u64
//! zstd(bincode(pk)) | zstd(bincode(prep) without scratch buffers)
//! ```
//!
//! - The verifier key is not stored: `--prove` never reads it.
//! - The prep scratch buffers ([`SCRATCH_FIELDS`]) are cleared by
//!   `Snark::prove` before every use, so they are spliced out of the bincode
//!   stream as empty `Vec`s (their fields are private to vega, hence the
//!   splice instead of a `#[serde(skip)]`).
//! - Most scalars are small (bits, bytes, ±1 coefficients), so zstd shrinks
//!   the rest ~40x, and the two blobs are decoded on two threads.
//!
//! `Snark::prove` returns a rerandomized prep which we deliberately do not write
//! back: the file is read-only at prove time and every run reuses the same prep.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    io,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    bincode_profile::BincodeProfiler,
    noir::circuit::CircuitParameters,
    online_prover::{OnlineProver, PrepSnark, ProverKey},
};

/// Name of the artifact written inside the circuit's `target/` directory.
pub const PRECOMPUTE_FILE: &str = "precompute.bin";

/// Bumped whenever the on-disk layout changes, so older files are ignored
/// instead of being mis-deserialized.
const FORMAT_VERSION: u32 = 2;

/// zstd level: higher levels barely shrink the file and slow down saving.
const ZSTD_LEVEL: i32 = 1;

/// Top-level `PrepSnark` fields that `Snark::prove` clears before use.
pub const SCRATCH_FIELDS: [&str; 5] = [
    "scratch_az",
    "scratch_bz",
    "scratch_cz",
    "z_buffer",
    "evals_rx_buffer",
];

/// Cheap staleness marker for a precomputed artifact. Not a security boundary.
pub type Fingerprint = u64;

/// Fixed-size header in front of the two zstd frames.
struct Header {
    version: u32,
    fingerprint: Fingerprint,
    pk_len: u64,
    prep_len: u64,
    pk_zstd_len: u64,
}

impl Header {
    const SIZE: usize = 4 + 4 * 8;

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
        for v in [
            self.fingerprint,
            self.pk_len,
            self.prep_len,
            self.pk_zstd_len,
        ] {
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
            prep_len: u64_at(2),
            pk_zstd_len: u64_at(3),
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

/// bincode of `prep` with every [`SCRATCH_FIELDS`] `Vec` replaced by an empty
/// one. If vega renames a field it is simply kept: bigger, still correct.
fn prep_bytes(prep: &PrepSnark) -> io::Result<Vec<u8>> {
    let bytes = bincode::serialize(prep).map_err(to_io_err)?;
    let mut profiler = BincodeProfiler::ranges(&SCRATCH_FIELDS);
    prep.serialize(&mut profiler).map_err(to_io_err)?;
    if profiler.pos != bytes.len() as u64 {
        return Err(to_io_err("bincode profiler disagrees with bincode"));
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    for (start, end) in profiler.ranges {
        out.extend_from_slice(&bytes[at..start as usize]);
        out.extend_from_slice(&0u64.to_le_bytes()); // length of an empty Vec
        at = end as usize;
    }
    out.extend_from_slice(&bytes[at..]);
    Ok(out)
}

/// Encodes the prover's reusable artifacts in the `precompute.bin` format.
pub fn encode(fingerprint: Fingerprint, pk: &ProverKey, prep: &PrepSnark) -> io::Result<Vec<u8>> {
    let compress = |raw: Vec<u8>| -> io::Result<(u64, Vec<u8>)> {
        Ok((raw.len() as u64, zstd::bulk::compress(&raw, ZSTD_LEVEL)?))
    };
    let (pk, prep) = std::thread::scope(|s| {
        let pk = s.spawn(|| bincode::serialize(pk).map_err(to_io_err).and_then(compress));
        let prep = prep_bytes(prep).and_then(compress);
        (pk.join().expect("pk encoder panicked"), prep)
    });
    let ((pk_len, pk), (prep_len, prep)) = (pk?, prep?);

    let mut out = Vec::with_capacity(Header::SIZE + pk.len() + prep.len());
    Header {
        version: FORMAT_VERSION,
        fingerprint,
        pk_len,
        prep_len,
        pk_zstd_len: pk.len() as u64,
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
    if header.pk_zstd_len > frames.len() as u64 {
        return Err(corrupt(&"truncated prover key"));
    }
    let (pk, prep) = frames.split_at(header.pk_zstd_len as usize);

    let unpack = |frame: &[u8], len: u64| -> Result<Vec<u8>, DecodeError> {
        zstd::bulk::decompress(frame, len as usize).map_err(|e| corrupt(&e))
    };
    std::thread::scope(|s| {
        let pk = s.spawn(|| -> Result<ProverKey, DecodeError> {
            bincode::deserialize(&unpack(pk, header.pk_len)?).map_err(|e| corrupt(&e))
        });
        let prep: PrepSnark =
            bincode::deserialize(&unpack(prep, header.prep_len)?).map_err(|e| corrupt(&e))?;
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
