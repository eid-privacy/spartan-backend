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

## Tier 2: patch vega-prover (fork + `[patch.crates-io]`) — plan

Tier 1's 0.7 s goes almost entirely to serde, not to zstd (measured below:
unzstd 200 ms vs. bincode 1050 ms, single-threaded). Most of that is
halo2curves' per-scalar `Deserialize`. Nothing outside vega can avoid it,
because the scalars sit in private vega fields, so this tier needs a fork.
Because the data is trusted, the fork can store every large vector as raw
memory and decompress it straight into its final allocation. That leaves no
per-element work and no big intermediate buffer.

### Design

1. **`#[serde(skip)]` on the five scratch fields** (`scratch_az`,
   `scratch_bz`, `scratch_cz`, `z_buffer`, `evals_rx_buffer`). This replaces
   the bincode splice in `precompute::prep_bytes` and
   `bincode_profile::BincodeProfiler::ranges`, which can be deleted.
2. **A `serde(with = "zstd_raw")` helper for large `Vec<T>`**, where `T` is
   plain data (`E::Scalar`, `usize`). Apply it to `SparseMatrix::{data,
   indices, indptr}` (the three matrices in `pk.S`), `cached_az/bz/cz`,
   `ps.W` and `cs.aux_assignment`, i.e. the fields of the size table above.
   - **Serialize:** take the `Vec`'s memory as bytes and cut it into frames
     of about 1M elements, a multiple of `size_of::<T>()`. Compress the
     frames in parallel with `zstd` level 1 (rayon, which vega already
     depends on). Emit one `serialize_bytes` holding: element count, frame
     count, each frame's `(raw_len, zstd_len)`, then the frames.
   - **Deserialize:** read that blob as borrowed bytes (bincode from a slice
     calls `visit_borrowed_bytes`, so nothing is copied). Allocate the final
     `Vec<T>` with its length, split its byte view at the frame boundaries,
     and run `zstd::bulk::decompress_to_buffer` on each frame in parallel
     (`par_iter`). Check that each frame decompresses to exactly `raw_len`.
     The helper never allocates more than the result.
   - **Memory-layout assumption:** a halo2curves field is
     `pub struct Fq(pub [u64; 4])`, a single-field struct *without*
     `#[repr(transparent)]`, so its layout is only de facto `[u64; 4]`. Guard
     the helper with `const` asserts on `size_of::<T>()` and
     `align_of::<T>()` and with `cfg(target_endian = "little")`, and add a
     round-trip unit test per `T`. The bytes are Montgomery limbs, which is
     what `SerdeObject::to_raw_bytes` produces, so no conversion is needed.
3. **No outer zstd.** The big vectors are already compressed inside the
   bincode stream, and what's left (metadata and small vectors) is small.
   Keep the `pk ‖ prep` two-thread decode. Bump `FORMAT_VERSION` to 3. The
   header no longer needs the uncompressed lengths, only `pk_len`, so the
   two blobs can be split.
4. The fork adds `zstd` as a vega dependency, behind a feature (for example
   `raw-serde`), so upstream builds are unchanged.

### Expected result

From the experiment below, the scalars take ~34 ms to load on 8 threads
(10.5 MiB on disk) instead of ~1 s of serde, and the `usize` indices behave
the same way. Total load should therefore drop from 0.74 s to well under
0.1 s. The file should grow from 27.8 MiB to roughly 33 MiB, because
Montgomery limbs compress worse than canonical bytes. Peak memory during
load is the decoded prover state plus the 33 MiB file, with no 1 GiB
intermediate buffer. Cost: maintaining a vega fork, like the noir fork
already maintained under `eid-privacy`.

### Rejected alternatives

- **Compact scalars without zstd** (a tag byte plus the significant bytes of
  `x` or `-x`): 44 ms with a lookup table, but 63 MiB on disk for the scalars
  alone. The 176 MiB of `usize` indices would then need their own encoding
  (u32 or delta-varint), or the file grows to ~240 MiB. It also needs a
  hand-written decoder with sign handling.
- **Compact + zstd:** the smallest option (2.8 MiB of scalars), but 55 ms,
  and it needs a ±255 lookup table: building small values with
  `F::from(u64)` costs a Montgomery multiplication each (~21 ns, 630 ms for
  29M). Worth revisiting only if file size matters more than simplicity.
- **Raw limbs through an intermediate buffer** (decompress, then copy):
  52 ms instead of 34 ms, and a temporary ~0.9 GiB extra peak.
- `Vec<usize>` → `u32` is unnecessary: zstd removes the zero upper halves.

## Experiment: how to encode the scalars

`spartan-backend/examples/scalar_compact_bench.rs` backs the Tier 2 plan:

```bash
cargo run --release --example scalar_compact_bench -- ../circuits/c0200_swiyu_jwt
```

It pulls every field element out of the stored `pk` and `prep` (29.4M
scalars, 898 MiB of the 1075 MiB of bincode; the remaining 176 MiB are mostly
`usize` indices) and decodes them in several ways. Every result is checked
against the original.

**Where Tier 1's load time goes** (single-threaded):

| blob | raw → zstd | unzstd | bincode |
|---|---|---|---|
| pk | 498 → 22.7 MiB | 140 ms | 400 ms |
| prep | 577 → 5.2 MiB | 60 ms | 655 ms |

**Scalar values** (byte length of `x` or `-x`, whichever is shorter): 51% are
0, 43% fit in 1 byte (34.5% positive, 8.8% negative, e.g. −1), 2% need 2–8
bytes and 4% need 9–32 bytes.

**Scalars only, bytes on disk → `Vec<F>`:**

| encoding | size | 1 thread | 8 threads |
|---|---|---|---|
| canonical 32 B + zstd, `from_repr` (≈ Tier 1 without serde overhead) | 5.8 MiB | 520 ms | |
| Montgomery limbs + zstd, via intermediate buffer | 10.5 MiB | 110 ms | 52 ms |
| **Montgomery limbs + zstd, frames decompressed in place (Tier 2)** | 10.5 MiB | | **34 ms** |
| compact, no zstd, `F::from(u64)` | 62.6 MiB | 395 ms | 110 ms |
| compact, no zstd, lookup table | 62.6 MiB | | 44 ms |
| compact + zstd, `F::from(u64)` | 2.8 MiB | 415 ms | 125 ms |
| compact + zstd, lookup table | 2.8 MiB | 137 ms | 55 ms |

zstd already removes the leading zeros well: a compact encoding saves at
most ~3 MiB of Tier 1's 27.8 MiB, and most of the file is the pk's index
arrays. For speed, what matters is how each `F` is built, not the byte
layout. Copying memory straight into place beats everything else.
