# Progress tracker: Spartan backend for Noir

This repository contains a set of Noir circuits meant to be incrementally complicated.
They track the evolution of our Spartan backend for Noir.

**Note: the "target" directory are intentionally versioned since changes to `nargo` and the resulting changes to the
bytecode are important to track.**

## Meta-TODO

* Test Spartan2 before over-engineering the crescent-fork
* Implement a more generic test bench in the crescent fork to limit manual changes when testing a circuit
* Implement a way to output the implementation status table

## Implementation status

| pass | circuit                    | noir commit                              | spartan commit                           |
|------|----------------------------|------------------------------------------|------------------------------------------|
| ✅    | c0000_trivial              | 76f7b6daae0e43a03ba41adb223517dad9e9f66f | 1d9a742b6de9955c9d2761bc2244063d3b399cc8 |
| ✅    | c0001_trivial_with_range   | 76f7b6daae0e43a03ba41adb223517dad9e9f66f | 1d9a742b6de9955c9d2761bc2244063d3b399cc8 |
| ⏳    | c0001_trivial_with_strings | 76f7b6daae0e43a03ba41adb223517dad9e9f66f | 1d9a742b6de9955c9d2761bc2244063d3b399cc8 |

## Reproducing the results

### Setup nargo

1. Download our fork of Noir: https://github.com/eid-privacy/noir
2. Checkout the "noir commit" indicated in the table
3. Build `nargo_cli`
4. Put it in your path, this README.md assumes it is named "nargo-t256" to distinguish from the original Noir distribution

### Setup Spartan

1. Download our fork of Crescent (containing Spartan): https://github.com/eid-privacy/crescent-fork
2. Checkout the "spartan commit" indicated in the table
3. In this repository go to the target circuit directory and `nargo-t256 build`
4. Copy the target json in the spartan fork (in `test-circuit/circuits`).
5. Adjust any parameters that require it in `main.rs`
6. Run the main method.