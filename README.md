# Progress tracker: Spartan backend for Noir

This repository contains a set of Noir circuits meant to be incrementally complicated.
They track the evolution of our Spartan backend for Noir.

**Note: the "target" directory are intentionally versioned since changes to `nargo` and the resulting changes to the
bytecode are important to track.**

## Implementation status

| pass | circuit                    | noir commit                              |
|------|----------------------------|------------------------------------------|
| ✅    | c0000_trivial              | aac6859426c78b03358de4128a7ae0e68546f31a |
| ✅    | c0001_trivial_with_range   | aac6859426c78b03358de4128a7ae0e68546f31a |
| ✅    | c0002_trivial_with_strings | aac6859426c78b03358de4128a7ae0e68546f31a |
| ✅    | c0003_trivial_with_brillig | aac6859426c78b03358de4128a7ae0e68546f31a |

## Reproducing the results

### Run proofs and verifications with Spartan

1. Make sure inputs are set in `prover_input.json` and `verifier_input.json` for the circuit(s) you want to run.
2. In `spartan-backend/`: `cargo run [--release] <circuit_name>` where the circuit name is the directory name within
   the `circuits` directory.

*Note: `cargo run [--release]` (without circuit name) will run all known passing circuits (hardcoded for now).*
*Note: provide `RUST_LOG` levels to get an output. e.g., `RUST_LOG=DEBUG cargo run`*

### (Optional) Setup nargo

This is only required if you need to compile/re-compile circuits.
Even then, with our current implementation surface,
afaik using vanilla nargo should still result in a circuit we can read for Spartan.

1. Download our fork of Noir: https://github.com/eid-privacy/noir
2. Checkout the "noir commit" indicated in the table
3. Build `nargo_cli`
4. Put it in your path, this README.md assumes it is named "nargo-t256" to distinguish from the original Noir distribution
5. Build the circuit you're interested in with `nargo-t256 build`
