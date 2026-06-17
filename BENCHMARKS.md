# Benchmarks

This is the first step to have some benchmarks and compare 
noir / barretenberg with their UltraHonk prover backend to
the shiny new Spartan backend.

The benchmark in [./circuits/c9000_benchmark/src/main.nr] allows
us to check a simple benchmark with two parameters:
- private input size
- number of assertions

It takes the private data, creates a sum of it, and does the
indicated number of assertions.

## Running it

The simplest way is to run it with:

```bash
devbox run benchmark
```

It will:
- create the `src/const.nr` file with the requested values
- create the `Prover.toml` file
- execute and prove the circuit with the vanilla noir and
  Barretenberg prover backend
- execute and prove the circuit with `noir-t256` and the
  Spartan backend

## Parameter sweep

The script iterates over all combinations of:

| Parameter | Values |
|-----------|--------|
| `NBR_INPUTS_PRIVATE` | 10, 100, 1 000, 10 000, 100 000 |
| `NBR_ASSERTS` | 10, 100, 1 000, 10 000, 100 000 |

Combinations where `NBR_ASSERTS > NBR_INPUTS_PRIVATE` are automatically
skipped (the circuit requires `NBR_ASSERTS ≤ NBR_INPUTS_PRIVATE`).

# Work done

Most of the commit should be clear - the one which requires most of
Clement's attention is the following one:

- commit 2388699169d819959271e488956ffeaa63c604e9 - Add reading of Prover.toml    
    This is Claude generated code to allow reading the inputs from the
    Prover.toml and target/circuit_name.gz.
    I have to admit that besides some smoketests I have no idea if this
    is correct or not!

As written in the commit, it is 100% Claude Code generated.
My goal was to have an automatic way of using the Prover.toml instead of the
json files.
Claude started adding the witness to fill out the full inputs - there might
be some duplication code in that.

This benchmark has been done on a Apple M2 Max MacBook Pro with 64GB
of RAM:

```
The three lines are:

bb.prf - proof time using Barretenberg UltraHonk
sp.prf - proof time using our simple SPARTAN implementation
sp.ver - verification time for SPARTAN

The verification time for Barretenberg is a constant 0.02s!

+------------+-------+-------+-------+-------+--------+
| ASRT \ INP |    10 |   100 |  1000 | 10000 | 100000 |
+------------+-------+-------+-------+-------+--------+
| 10         | 0.10s | 0.10s | 0.17s | 0.39s |  3.62s |
|            | 0.05s | 0.04s | 0.10s | 0.77s |  9.05s |
|            | 0.04s | 0.02s | 0.06s | 0.54s |  6.83s |
+------------+-------+-------+-------+-------+--------+
| 100        |   n/a | 0.10s | 0.17s | 0.39s |  3.70s |
|            |   n/a | 0.04s | 0.12s | 0.78s |  8.87s |
|            |   n/a | 0.02s | 0.06s | 0.54s |  6.64s |
+------------+-------+-------+-------+-------+--------+
| 1000       |   n/a |   n/a | 0.13s | 0.41s |  3.73s |
|            |   n/a |   n/a | 0.12s | 0.78s |  9.03s |
|            |   n/a |   n/a | 0.06s | 0.57s |  6.71s |
+------------+-------+-------+-------+-------+--------+
| 10000      |   n/a |   n/a |   n/a | 0.39s |  3.53s |
|            |   n/a |   n/a |   n/a | 0.79s |  8.79s |
|            |   n/a |   n/a |   n/a | 0.56s |  6.66s |
+------------+-------+-------+-------+-------+--------+
| 100000     |   n/a |   n/a |   n/a |   n/a |  3.91s |
|            |   n/a |   n/a |   n/a |   n/a |  8.29s |
|            |   n/a |   n/a |   n/a |   n/a |  6.33s |
+------------+-------+-------+-------+-------+--------+
```
