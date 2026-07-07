# Progress tracker: Spartan backend for Noir

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
| 10         | 0.10s | 0.11s | 0.15s | 0.44s |  3.18s |
|            | 0.06s | 0.07s | 0.12s | 0.55s |  5.22s |
|            | 0.04s | 0.04s | 0.07s | 0.31s |  2.45s |
+------------+-------+-------+-------+-------+--------+
| 100        |   n/a | 0.10s | 0.15s | 0.44s |  2.88s |
|            |   n/a | 0.07s | 0.12s | 0.53s |  4.43s |
|            |   n/a | 0.04s | 0.07s | 0.30s |  2.33s |
+------------+-------+-------+-------+-------+--------+
| 1000       |   n/a |   n/a | 0.15s | 0.45s |  2.88s |
|            |   n/a |   n/a | 0.11s | 0.55s |  4.39s |
|            |   n/a |   n/a | 0.07s | 0.31s |  2.40s |
+------------+-------+-------+-------+-------+--------+
| 10000      |   n/a |   n/a |   n/a | 0.44s |  3.07s |
|            |   n/a |   n/a |   n/a | 0.53s |  4.71s |
|            |   n/a |   n/a |   n/a | 0.31s |  2.39s |
+------------+-------+-------+-------+-------+--------+
| 100000     |   n/a |   n/a |   n/a |   n/a |  3.17s |
|            |   n/a |   n/a |   n/a |   n/a |  4.83s |
|            |   n/a |   n/a |   n/a |   n/a |  2.47s |
+------------+-------+-------+-------+-------+--------+
```
<!-- BENCHMARK_TABLE_END -->

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
