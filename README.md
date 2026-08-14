# Progress tracker: Spartan backend for Noir

⚠️ **This is demo code, do not use for production or sensitive applications** ⚠️

This repository contains a set of Noir circuits meant to be incrementally complicated.
They track the evolution of our Spartan backend for Noir.

**Note: the "target" directory are intentionally versioned since changes to `nargo` and the resulting changes to the
bytecode are important to track.**

## Setup

### Using devbox (recommended)

This repo uses [devbox](https://www.jetify.com/devbox) to pin the exact `rustc`,
`nargo-t256`, and `barretenberg` versions the code is tested against (see
`devbox.json`), so it's the preferred way to get a working environment — no
manual toolchain installation needed.

1. Make sure your `/etc/nix/nix.custom.conf` has these lines (needed to fetch the
   `nargo-t256` binaries from cachix, and to run devbox inside a docker
   environment):
   ```
   experimental-features = nix-command flakes
   sandbox = relaxed
   filter-syscalls = false
   extra-substituters = https://eid-privacy.cachix.org
   extra-trusted-public-keys = eid-privacy.cachix.org-1:lxRzvjcWd/A6Wew1tq0IK6OIMVWNJKUTy4s7EKb6C2A=
   ```
2. `devbox shell` — installs and puts `rustup`, `nargo-t256`, and the other
   pinned tools on your `PATH`.
3. Use the scripts in `devbox.json` (`devbox run build`, `devbox run test`,
   `devbox run start`, etc.) instead of invoking `cargo`/`nargo-t256` directly;
   they already set the right working directory and flags. See the sections
   below for which script maps to which manual command.
4. If the flakes have been updated after the first run of `devbox`, the cache
   of nix needs to be refreshed:

```bash
nix flake metadata github:eid-privacy/flakes --refresh
```

### Manual setup (without devbox)

Only needed if you're not using devbox. Install Rust via
[rustup](https://rustup.rs), and see "Manual nargo setup" below if you need to
compile or re-compile circuits — you'll be responsible for tracking the
`nargo-t256`/noir/barretenberg versions yourself instead of getting them
pinned automatically.

## Reproducing the results

### Run proofs and verifications with Spartan

1. Make sure inputs are set in `prover_input.json` and `verifier_input.json` for the circuit(s) you want to run.
2. In `spartan-backend/`: `cargo run [--release] <circuit_name>` where the circuit name is the directory name within
   the `circuits` directory (or via devbox: `devbox run start` to run all known passing circuits).

*Note: `cargo run [--release]` (without circuit name) will run all known passing circuits (hardcoded for now).*
*Note: provide `RUST_LOG` levels to get an output. e.g., `RUST_LOG=DEBUG cargo run`*

### Manual nargo setup (skip if using devbox)

`devbox shell` already puts a matching `nargo-t256` on your `PATH` — only
follow this if you're not using devbox. Required if you need to
compile/re-compile/execute circuits.

* `nargo build` needs to produce an ACIR in which coefficients and constants are embedded into T-256
* `nargo execute` needs to use the T-256 Blackbox Solver to compute intermediate and output witnesses and those need
  to then be embedded in the T-256 field.

1. Download our fork of Noir: <https://github.com/eid-privacy/noir>
2. Checkout the tag matching the `t256-v0.N` tag used in `spartan-backend/Cargo.toml`
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

### Benchmarking noir/barretenberg vs. spartan across commits

The table above sweeps the parametric `c9000_benchmark` circuit
(`./scripts/benchmark.sh`). To instead track two things over the same commit
timeline — how noir/barretenberg itself improves across the commits that bump the
`noir-versions`/`barretenberg-versions`/`nargo-t256-versions` flake pins in
`devbox.json`, and how spartan-backend improves across our own commits — use
[`scripts/benchmark_commits.sh`](scripts/benchmark_commits.sh), driven by a
git-tracked config file such as
[`benchmarks/swiyu_jwt/config.yaml`](benchmarks/swiyu_jwt/config.yaml).

Run the driver from a **plain shell**, not from inside `devbox shell` — nesting
devbox environments is unsupported. The script itself has no devbox dependency; for
each commit it checks out a single reused `git worktree` at `benchmarks/checkout/`
and calls `devbox run` inside it, so every commit is measured with its own pinned
toolchain:

```bash
./scripts/benchmark_commits.sh benchmarks/swiyu_jwt/config.yaml [options]

  --force            re-run every leg, ignoring stored results
  --only <ref>       run only this commit (both of its legs), ignoring stored results
  --runs <n>         override `runs:` from the config
  --dry-run          print the work plan and exit
```

* The config lists two (possibly overlapping) sets of commits — `noir_commits` and
  `spartan_commits` — plus which circuit under `circuits/` to use for each (a
  standard-field `noir_circuit` for barretenberg, a t256 `spartan_circuit` for
  spartan-backend). Add entries over time; already-measured entries are never
  re-run, and removing an entry from the config only removes it from the plot — its
  result file on disk is kept.
* Results are written to `<config_dir>/results/<leg>-<shortsha>.csv` (`leg` is
  `noir` or `spartan`), one file per (leg, commit), written atomically so an
  interrupted run never leaves a half-written file behind. Each file has the schema
  `metric,min,max,mean,stddev,samples`, plus `#`-prefixed metadata lines recording
  the commit, run count, host, and the checked-out commit's flake pins.
* A failing commit prints a warning and does not stop the rest of the run.

Plot the collected runs with
[`scripts/plot_benchmark_commits.py`](scripts/plot_benchmark_commits.py), run from
**inside devbox** (needs matplotlib + pyyaml):

```bash
devbox run plot-commits benchmarks/swiyu_jwt/config.yaml
```

This writes `benchmarks/swiyu_jwt/benchmarks.png`. The two commit lists share one
x-axis, the union of both in git topological order (oldest → newest); a commit
present in both lists sits at a single x position with both series' markers, and
each series is drawn only where it has a result, without interpolating through
gaps. The left y-axis is relative to the baseline — the **first** `noir_commits`
entry's `bb_write_vk` + `bb_prove` mean — with `bb_verify`/`spartan_verify` drawn as
thin dashed lines. The right y-axis shows `bb_proof_size`/`spartan_proof_size` in
bytes on a log scale, with spartan points annotated by `spartan_constraints`.

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
