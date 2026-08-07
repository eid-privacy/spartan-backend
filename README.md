# Progress tracker: Spartan backend for Noir

⚠️ **This is demo code, do not use for production or sensitive applications** ⚠️

This repository contains a set of Noir circuits meant to be incrementally complicated.
They track the evolution of our Spartan backend for Noir.

**Note: the "target" directory are intentionally versioned since changes to `nargo` and the resulting changes to the
bytecode are important to track.**

## Implementation status

| pass | circuit                             | noir commit                              |
|------|-------------------------------------|------------------------------------------|
| ✅    | c0000_trivial                       | t256-v0.22 |
| ✅    | c0001_trivial_with_range            | t256-v0.22|
| ✅    | c0002_trivial_with_strings          | t256-v0.22|
| ✅    | c0003_trivial_with_brillig          | t256-v0.22|
| ✅    | c0004_trivial_elliptic_curve_add    | t256-v0.22|
| ✅    | c0005_trivial_msm                   | t256-v0.22|
| ✅    | c0006_sha256                        | t256-v0.22|
| ✅    | c0100_holder_binding_crescent_style | t256-v0.22|
| ✅    | c0101_signature_pok_zkattest_style  | t256-v0.22|
| ✅    | c0102_signature_vanilla_equation    | t256-v0.22|

## Reproducing the results

### Run proofs and verifications with Spartan

1. Make sure inputs are set in `prover_input.json` and `verifier_input.json` for the circuit(s) you want to run.
2. In `spartan-backend/`: `cargo run [--release] <circuit_name>` where the circuit name is the directory name within
   the `circuits` directory.

*Note: `cargo run [--release]` (without circuit name) will run all known passing circuits (hardcoded for now).*
*Note: provide `RUST_LOG` levels to get an output. e.g., `RUST_LOG=DEBUG cargo run`*

### Pre-computing the offline phase (`--precompute`)

Proving is split into an offline phase (`setup` + `prep`, which commits the
invariant part of the witness) and an online phase (the actual proof). The
offline phase can be run ahead of time and reused:

```sh
# offline, once per circuit build
cargo run --release -- ../circuits/c0200_swiyu_jwt --precompute

# online, any number of times — picks the artifact up automatically
cargo run --release -- ../circuits/c0200_swiyu_jwt --prove
```

* `--precompute` writes a single git-ignored file,
  `<circuit_dir>/target/precompute.bin` (prover key, verifier key and prepared
  state). It can exceed a gigabyte for the bigger circuits.
* `--prove` loads that file when it exists, otherwise it falls back to the usual
  monolithic proving. The base64 proof is the same either way.
* The file records a fingerprint of the circuit's ACIR bytecode and of the
  online partition declared in `online.json`. Rebuilding the circuit or editing
  `online.json` makes it stale, so `--prove` warns and falls back to regular
  proving; re-run `--precompute`. Changing the **values** of online inputs
  (challenge nonce, device signature, …) never invalidates the artifact — that
  is the whole point of the online path.
* Circuits without an `online.json` still work; the precomputed state saves
  `setup`, but the witness commitment is redone on every proof.

Two scripts drive this from the repository root:

* `scripts/precompute.sh [circuit_dir]` — checks the prerequisites (built ACIR,
  solved witness, `verifier_input.json`, `online.json`), validates the partition
  with a cheap ACIR-only pre-flight, checks free disk space, then runs the
  expensive offline phase.
* `scripts/online_bench.sh [NUM_PROOFS] [NUM_EXTRA_CHALLENGES]` — the
  online-proving benchmark. It times a non-amortized baseline, then
  `--precompute` once, then `NUM_PROOFS` × `--prove`, splitting each measurement
  into artifact load vs. proving, and verifies the proofs. With
  `NUM_EXTRA_CHALLENGES > 0` it also regenerates genuinely distinct challenges,
  re-signing each with the circuit's device key
  (`<circuit_dir>/data/holder_private_key.jwk`). Example on c0200:

  ```
  offline (--precompute, one-off) = 4.149s, 1570.6 MiB on disk
  first online proof           wall=2.640s    load=1.628s    prove=1.012s
  warm online avg (2 samples)  wall=2.686s    load=1.610s    prove=1.076s
  baseline (no precompute)        = 3.799s
  speedup, proving only           = 3.75x
  speedup, end-to-end incl. load  = 1.44x
  ```

  The gap between the two speedups is the cost of re-reading the artifact in a
  fresh process; a long-lived prover process would pay it once.

### (Optional) Setup nargo

This is required if you need to compile/re-compile/execute circuits.

* `nargo build` needs to produce an ACIR in which coefficients and constants are embedded into T-256
* `nargo execute` needs to use the T-256 Blackbox Solver to compute intermediate and output witnesses and those need
  to then be embedded in the T-256 field.

1. Download our fork of Noir: <https://github.com/eid-privacy/noir>
2. Checkout the "noir commit" indicated in the table
3. Build `nargo_cli`
4. Put it in your path, this README.md assumes it is named "nargo-t256" to distinguish from the original Noir distribution
5. Build the circuit you're interested in with `nargo-t256 build`

Keep circuit sources **ASCII-only** (comments included): the T-256 fork rejects
non-ASCII characters with `Invalid comment character: only ASCII is currently
supported`.

### Preprocessing (ECDSA precompute)

Some circuits need ECDSA-related witnesses that are computed off-circuit on the
host. The [`preprocessing/`](preprocessing) directory holds one small Cargo tool
per such circuit; each reads that circuit's `Prover.toml`, does the elliptic-curve
math, and injects the precomputed values. See
[`preprocessing/README.md`](preprocessing/README.md) for the full list and usage.

## Benchmarks

Times in seconds. Rows: ASSERTS; sub-rows per cell: BB prove / Spartan proof / Spartan verify. Columns: INPUT_SIZE.

<!-- BENCHMARK_TABLE_START -->
```
+------------+-------+-------+-------+-------+--------+
| ASRT \ INP |    10 |   100 |  1000 | 10000 | 100000 |
+------------+-------+-------+-------+-------+--------+
| 10         | 0.08s |   n/a |   n/a |   n/a |    n/a |
|            | 0.06s |   n/a |   n/a |   n/a |    n/a |
|            | 0.04s |   n/a |   n/a |   n/a |    n/a |
+------------+-------+-------+-------+-------+--------+
| 100        |   n/a | 0.09s |   n/a |   n/a |    n/a |
|            |   n/a | 0.06s |   n/a |   n/a |    n/a |
|            |   n/a | 0.04s |   n/a |   n/a |    n/a |
+------------+-------+-------+-------+-------+--------+
| 1000       |   n/a |   n/a | 0.12s |   n/a |    n/a |
|            |   n/a |   n/a | 0.11s |   n/a |    n/a |
|            |   n/a |   n/a | 0.06s |   n/a |    n/a |
+------------+-------+-------+-------+-------+--------+
| 10000      |   n/a |   n/a |   n/a | 0.33s |    n/a |
|            |   n/a |   n/a |   n/a | 0.46s |    n/a |
|            |   n/a |   n/a |   n/a | 0.26s |    n/a |
+------------+-------+-------+-------+-------+--------+
| 100000     |   n/a |   n/a |   n/a |   n/a |  2.20s |
|            |   n/a |   n/a |   n/a |   n/a |  4.00s |
|            |   n/a |   n/a |   n/a |   n/a |  2.07s |
+------------+-------+-------+-------+-------+--------+
```
<!-- BENCHMARK_TABLE_END -->

### Benchmarking one circuit across commits

The table above sweeps the parametric `c9000_benchmark` circuit
(`./scripts/benchmark.sh`). To instead track how spartan-backend changes affect a
single **fixed** circuit across a history of commits, use
[`scripts/benchmark_commits.sh`](scripts/benchmark_commits.sh):

```bash
./scripts/benchmark_commits.sh <bb_circuit_code> <circuit_code> [commit ...]
# or via devbox:
devbox run benchmark-commits <bb_circuit_code> <circuit_code> [commit ...]

# example: spartan on the signature circuit, Barretenberg on a standard-field circuit
./scripts/benchmark_commits.sh c0000_trivial c0101_signature_pok_zkattest_style 8c257bb 217b46f f605158 16df669
```

* `<circuit_code>` (the spartan circuit) and `<bb_circuit_code>` (the Barretenberg
  circuit) are directory names under `circuits/`. They are **separate** because
  Barretenberg cannot process the t256-only spartan circuits, so it needs its own
  standard-field circuit. Commits may be given in any order; if none are given,
  `HEAD` is used.
* Each commit is checked out into a throwaway `git worktree` (in a `mktemp`
  directory, so your working tree is never touched), spartan-backend is built there,
  and `<circuit_code>`'s proof/verification is timed `N` times (default `N=5`).
* Results are written to `benchmarks/<circuit_code>/` (the spartan circuit), one CSV
  per run, named with a two-digit index so a plain sort follows git history (oldest
  first). Each file has the schema `metric,min,max,mean,stddev`:
  * `stats-00-barretenberg.csv` — `write_vk` / `prove` / `verify` for
    `<bb_circuit_code>`, run **once** from the **current working tree** (not any
    benchmarked commit), since Barretenberg depends only on the circuit, not the
    spartan-backend code. The circuit is recompiled in place to get a valid witness
    and the tracked `target/` is restored afterward. Skipped if `<bb_circuit_code>`
    is also t256-only and doesn't compile with standard `nargo`.
  * `stats-01-<sha>.csv`, `stats-02-<sha>.csv`, … — one per commit, oldest first,
    with the spartan-only metrics: `spartan_proof` / `spartan_verify` (timings),
    plus `spartan_constraints` (R1CS constraint count, via `--count-constraints`)
    and `spartan_proof_size` (serialized proof size in bytes, via `--proof-size`).
    The last two are deterministic single values (stddev `0`) and are recorded only
    for commits whose backend supports the corresponding flag; they are skipped on
    older commits that predate it.

Plot the collected runs with
[`scripts/plot_benchmark_commits.py`](scripts/plot_benchmark_commits.py):

```bash
python3 ./scripts/plot_benchmark_commits.py benchmarks/<circuit_code>
# or via devbox:
devbox run plot-commits benchmarks/<circuit_code>
```

This writes `benchmarks/<circuit_code>/benchmarks.png` with commits on the x-axis
(oldest → newest); values below `1×` are improvements. The timing series
`spartan_proof`/`spartan_verify` are shown relative to the **first commit's**
`spartan_proof` mean, and `spartan_proof_size` relative to its **own first available
value**. `spartan_constraints` is drawn differently — as `frac(log2(c) + 0.5) - 0.5`
offset onto the baseline, i.e. the signed distance (in log₂ octaves) to the nearest
power of two, so the line crossing the baseline marks constraints crossing a
power-of-two boundary (where the R1CS padding jumps). Commits lacking a metric are
skipped. When a `stats-00-barretenberg.csv` is present, its `prove`/`verify` times
are drawn as constant horizontal reference lines.

## Profiling

To find hotspots in the Spartan backend while proving/verifying a circuit, use
[samply](https://github.com/mstange/samply):

```bash
./scripts/samply.sh <circuit-match>   # e.g. ./scripts/samply.sh 06
```

This records a profile and opens a flamegraph in the browser. See
[SAMPLY.md](SAMPLY.md) for details.

### Troubleshooting

* On some Macs it might happen that the `nargo` binary gets killed instantly on invocation.
  It requires re-signing: `codesign --sign - --force --preserve-metadata=entitlements $(which nargo-t256)`

# Using devbox

If you want to use devbox for this repo, make sure to have the following
lines in your `/etc/nix/nix.conf`:

```
experimental-features = nix-command flakes
sandbox = relaxed
filter-syscalls = false
extra-substituters = https://eid-privacy.cachix.org
extra-trusted-public-keys = eid-privacy.cachix.org-1:lxRzvjcWd/A6Wew1tq0IK6OIMVWNJKUTy4s7EKb6C2A=
```

this will allow to download the nargo-t256 binaries from cachix and also help
running it in a docker environment.
