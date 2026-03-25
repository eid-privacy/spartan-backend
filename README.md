# Progress tracker: Spartan backend for Noir

This repository contains a set of Noir circuits meant to be incrementally complicated.
They track the evolution of our Spartan backend for Noir.

**Note: the "target" directory are intentionally versioned since changes to `nargo` and the resulting changes to the
bytecode are important to track.**

## Meta-TODO

* Implement a more generic test bench in the crescent fork to limit manual changes when testing a circuit
* Implement a way to output the implementation status table

## Implementation status

| pass | circuit                    | noir commit                              |
|------|----------------------------|------------------------------------------|
| ✅    | c0000_trivial              | 76f7b6daae0e43a03ba41adb223517dad9e9f66f |
| ✅    | c0001_trivial_with_range   | 76f7b6daae0e43a03ba41adb223517dad9e9f66f |
| ⏳    | c0001_trivial_with_strings | 76f7b6daae0e43a03ba41adb223517dad9e9f66f |

## Reproducing the results

### Setup nargo

1. Download our fork of Noir: https://github.com/eid-privacy/noir
2. Checkout the "noir commit" indicated in the table
3. Build `nargo_cli`
4. Put it in your path, this README.md assumes it is named "nargo-t256" to distinguish from the original Noir distribution

### Setup Spartan

In `spartan-backend/`:

1. Adjust any parameters that require it in `main.rs`
2. Run the main method.