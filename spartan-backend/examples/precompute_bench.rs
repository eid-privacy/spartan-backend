//! Measures loading of a `target/precompute.bin` artifact, split into the raw
//! file read and the decode (zstd + bincode), plus a per-field size breakdown
//! of the uncompressed bincode streams and a per-scalar micro-benchmark.
//!
//! ```text
//! cargo run --release -- --precompute ../circuits/c0200_swiyu_jwt
//! cargo run --release --example precompute_bench -- ../circuits/c0200_swiyu_jwt [RUNS]
//! ```
//!
//! The read is served from the OS page cache after the first run; on macOS
//! `sudo purge` beforehand gives a cold-cache number.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use ff::PrimeField;
use halo2curves::serde::SerdeObject;
use serde::Serialize;
use spartan_backend::{
    bincode_profile::BincodeProfiler,
    precompute::{self, SCRATCH_FIELDS, precompute_path},
};
use vega_prover::traits::Engine;

type F = <spartan_backend::E as Engine>::Scalar;

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn best<T>(runs: usize, mut f: impl FnMut() -> T) -> (Duration, T) {
    let mut best = Duration::MAX;
    let mut out = None;
    for _ in 0..runs {
        let t = Instant::now();
        let v = f();
        best = best.min(t.elapsed());
        out = Some(v);
    }
    (best, out.unwrap())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(
        args.next()
            .expect("usage: precompute_bench <circuit_dir> [RUNS]"),
    );
    let runs: usize = args
        .next()
        .map_or(3, |r| r.parse().expect("RUNS must be a number"));
    let path = precompute_path(&dir);

    println!("== {}", path.display());
    let (read, bytes) = best(runs, || std::fs::read(&path).expect("read precompute.bin"));
    println!(
        "read        {:>8.1} MiB  {read:>9.3?}",
        mib(bytes.len() as u64)
    );
    // The fingerprint needs the compiled circuit; take it from the header so
    // the benchmark only depends on the artifact.
    let fingerprint = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
    let (decode, (pk, prep)) = best(runs, || {
        precompute::decode(&bytes, fingerprint).expect("decode precompute.bin")
    });
    println!("decode                     {decode:>9.3?}  (zstd + bincode, pk || prep)");
    let (encode, _) = best(1, || {
        precompute::encode(fingerprint, &pk, &prep).expect("encode")
    });
    println!("encode                     {encode:>9.3?}");
    drop(bytes);

    println!("\n== uncompressed bincode by struct-field path (>= 0.1%)");
    let mut profiler = BincodeProfiler::sizes(4);
    pk.serialize(&mut profiler).expect("profile pk");
    let pk_total = profiler.pos;
    print_sizes("pk", &profiler);
    let mut profiler = BincodeProfiler::sizes(4);
    prep.serialize(&mut profiler).expect("profile prep");
    print_sizes("prep", &profiler);
    println!(
        "total {:.1} MiB (pk {:.1} + prep {:.1}); scratch fields {SCRATCH_FIELDS:?} are empty",
        mib(pk_total + profiler.pos),
        mib(pk_total),
        mib(profiler.pos)
    );

    scalar_micro();
}

fn print_sizes(root: &str, profiler: &BincodeProfiler) {
    for (field, size) in &profiler.sizes {
        if *size * 1000 >= profiler.pos {
            println!(
                "{:>8.1} MiB {:>5.1}%  {root}.{field}",
                mib(*size),
                100.0 * *size as f64 / profiler.pos as f64
            );
        }
    }
}

/// Per-scalar cost of the serde path vs. what a raw, unchecked path (needs a
/// vega patch) would cost.
fn scalar_micro() {
    let n = 4usize << 20;
    println!("\n== {}M scalars", n >> 20);
    let v: Vec<F> = (0..n as u64)
        .map(|i| F::from(i) * F::from(0x1234_5678_9abc_def1))
        .collect();
    let b = bincode::serialize(&v).unwrap();
    let (t, _) = best(3, || -> Vec<F> { bincode::deserialize(&b).unwrap() });
    println!("bincode Vec<F>                 {t:>9.3?}");
    let (t, _) = best(3, || -> Vec<[u8; 32]> { bincode::deserialize(&b).unwrap() });
    println!("bincode Vec<[u8; 32]>          {t:>9.3?}  (serde per-byte overhead)");
    let (t, _) = best(3, || -> Vec<F> {
        b[8..]
            .chunks_exact(32)
            .map(|c| F::from_repr(c.try_into().unwrap()).unwrap())
            .collect()
    });
    println!("raw canonical + from_repr      {t:>9.3?}  (checked, Montgomery conversion)");
    let raw: Vec<u8> = v.iter().flat_map(|x| x.to_raw_bytes()).collect();
    let (t, _) = best(3, || -> Vec<F> {
        raw.chunks_exact(32)
            .map(F::from_raw_bytes_unchecked)
            .collect()
    });
    println!("raw Montgomery, unchecked      {t:>9.3?}");
}
