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
| ✅    | c0006_sha256 | t256-v0.22|
| ✅    | c0100_holder_binding_crescent_style | t256-v0.22|
| ✅    | c0101_signature_pok_zkattest_style | t256-v0.22|
| ✅    | c0102_signature_vanilla_equation | t256-v0.22|

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

## Benchmarks

Times in seconds. Rows: ASSERTS; sub-rows per cell: BB prove / Spartan proof / Spartan verify. Columns: INPUT_SIZE.

<!-- BENCHMARK_TABLE_START -->
```
+------------+-------+-------+-------+-------+--------+
| ASRT \ INP |    10 |   100 |  1000 | 10000 | 100000 |
+------------+-------+-------+-------+-------+--------+
| 10         | 0.08s |   n/a |   n/a |   n/a |    n/a |
|            | 0.08s |   n/a |   n/a |   n/a |    n/a |
|            | 0.04s |   n/a |   n/a |   n/a |    n/a |
+------------+-------+-------+-------+-------+--------+
| 100        |   n/a | 0.09s |   n/a |   n/a |    n/a |
|            |   n/a | 0.08s |   n/a |   n/a |    n/a |
|            |   n/a | 0.04s |   n/a |   n/a |    n/a |
+------------+-------+-------+-------+-------+--------+
| 1000       |   n/a |   n/a | 0.11s |   n/a |    n/a |
|            |   n/a |   n/a | 0.12s |   n/a |    n/a |
|            |   n/a |   n/a | 0.05s |   n/a |    n/a |
+------------+-------+-------+-------+-------+--------+
| 10000      |   n/a |   n/a |   n/a | 0.33s |    n/a |
|            |   n/a |   n/a |   n/a | 0.42s |    n/a |
|            |   n/a |   n/a |   n/a | 0.23s |    n/a |
+------------+-------+-------+-------+-------+--------+
| 100000     |   n/a |   n/a |   n/a |   n/a |  2.19s |
|            |   n/a |   n/a |   n/a |   n/a |  3.62s |
|            |   n/a |   n/a |   n/a |   n/a |  1.93s |
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
