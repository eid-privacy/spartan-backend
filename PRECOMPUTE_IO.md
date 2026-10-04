# Shrinking and speeding up `target/precompute.bin`

Measurements and an implementation plan for the save/load path of
`spartan-backend/src/precompute.rs`. The on-disk format is private to
spartan-backend (only `--prove` reads it back) and the data is trusted, so
format compatibility and validation on load do not matter.

## Benchmark

`spartan-backend/examples/precompute_bench.rs`:

```bash
cd spartan-backend
cargo run --release -- --precompute ../circuits/c0200_swiyu_jwt     # writes the artifact
cargo run --release --example precompute_bench -- ../circuits/c0200_swiyu_jwt 3
```

It reports read vs. deserialize time, a per-field byte breakdown (via a
counting serde `Serializer` that mirrors bincode 1.3's sizes), the
"slim layout" prototype below, and a per-scalar micro-benchmark. File reads
are warm-cache; run `sudo purge` first for a cold number.

## Baseline (c0200_swiyu_jwt, 2²² padded constraints, Apple Silicon)

| step | time |
|---|---|
| `fs::read` 2084.5 MiB | 0.25 s |
| `bincode::deserialize` | **2.10 s** |
| `bincode::serialize` | 1.28 s |

Deserialization, not I/O, dominates the load time. Where the bytes go:

| field | MiB | note |
|---|---|---|
| `pk` (`pk.S` = R1CS matrices A/B/C) | 498 | needed |
| `vk` (contains a second copy of `S`) | 498 | **never used by `--prove`** |
| `prep.scratch_az/bz/cz`, `prep.z_buffer` | 512 | **dead: `clear()`ed before use** (`vega r1cs/mod.rs` `multiply_vec_incremental_into`, `vega_sc_zkp.rs` `z.clear()`) |
| `prep.cached_az/bz/cz` | 384 | needed |
| `prep.ps.W` + `prep.ps.cs.aux_assignment` | 193 | needed |

Per scalar (4M-element `Vec`), the cost breaks down like this:

| path | 4M scalars |
|---|---|
| bincode `Vec<Fq>` (serde, today) | 145 ms |
| bincode `Vec<[u8;32]>` (the serde per-byte visiting alone) | 259 ms |
| raw canonical bytes + `from_repr` (checked, Montgomery mult) | 68 ms |
| raw Montgomery limbs, `from_raw_bytes_unchecked` | **3 ms** |

So ~33 ns per scalar goes to serde visiting 32 single bytes plus the
canonical check and Montgomery conversion inside halo2curves' `Deserialize`.
A trusted raw path is ~50× faster.

## Tier 1: no vega changes (implemented)

1. **Don't store `vk`.** Nothing on the `--prove` path reads it
   (`OnlineProver::verifier_key()` has no callers). Drop the `vk` field from
   `OnlineProver` (or make it `Option`) and from `PrecomputeFile`.
2. **Cut out the scratch buffers.** Their fields are private, so splice the
   bincode stream instead. Serialize `prep` with bincode, find the byte ranges
   of the top-level fields `scratch_az`, `scratch_bz`, `scratch_cz`,
   `z_buffer` and `evals_rx_buffer` (the benchmark's `SizeProfiler` with
   `track` does this), and replace each range with `0u64` (an empty `Vec`).
   Plain `bincode::deserialize` then yields a prep with empty scratch `Vec`s,
   which `prove` refills. The benchmark asserts the profiler's total equals
   bincode's length, and round-trips the result. If vega renames a field, the
   splice just doesn't happen (still correct, only bigger).
3. **pk and prep as two blobs, decoded on two threads.**
4. **zstd level 1 per blob** (`zstd` crate). lz4_flex was both bigger and
   slower here.

Measured on c0200:

| layout | size | load (decompress + deserialize) |
|---|---|---|
| baseline | 2084.5 MiB | 0.25 s + 2.10 s |
| slim (1 + 2), sequential | 1074.7 MiB | 1.03 s |
| slim, pk ‖ prep | 1074.7 MiB | 0.68 s |
| **slim, pk ‖ prep, zstd -1** | **27.8 MiB** | **0.74 s** (read of 28 MiB is negligible) |
| slim, pk ‖ prep, zstd -3 | 25.8 MiB | 0.74 s |

That gives **75× smaller and ~3× faster to load**, and saving gets faster too:
compressing takes 0.43 s, but the write drops from 2 GiB to 28 MiB. The parallel
decode is limited by prep (577 MiB) being the larger half.

**Status: implemented** (`FORMAT_VERSION` 2, `src/precompute.rs`,
splice helper in `src/bincode_profile.rs`). End to end on c0200:
`--precompute` writes 27.8 MiB (was 2084.5 MiB) at the same total time
(~7 s), `precompute_load` takes 0.89 s including the fingerprint, and the
proof from the loaded artifact verifies. c0101 also passes precompute,
prove and verify. Old v1 files are rejected by version and fall back to
regular proving. The benchmark now measures the v2 format.

## Tier 2: patch vega-prover (fork + `[patch.crates-io]`)

This gets most of the remaining 0.7 s, because the data is trusted:
- `#[serde(skip)]` on the five scratch fields (replaces the splice hack).
- Serialize every large `Vec<E::Scalar>` (`SparseMatrix::data`, `cached_*`,
  `ps.W`, `cs.aux_assignment`, …) with a `serde(with = …)` helper that emits
  one `serialize_bytes` blob of raw Montgomery limbs (`SerdeObject::to_raw_bytes`
  or a slice cast). Decode with `from_raw_bytes_unchecked`, with no canonical
  check, no Montgomery conversion and no per-byte visitor: ~3 ms per 4M
  scalars instead of 145 ms.
- Optionally `Vec<usize>` → `u32` for `indices`/`indptr` (zstd already
  removes most of that redundancy).

Expected: deserialize ~29M scalars in tens of ms, so load becomes bounded by
zstd decompression of ~1 GiB (~0.3–0.4 s single-threaded; use several
independent zstd frames decoded in parallel, or skip compression if size
matters less than time). Cost: maintaining a vega fork, like the noir fork
already maintained under `eid-privacy`.
