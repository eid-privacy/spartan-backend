# Benchmarks

This is the first step to have some benchmarks and compare 
noir / barretenberg with their UltraHonk prover backend to
the shiny new Spartan backend.

The benchmark in [./circuits/c0003_benchmark/src/main.nr] allows
us to check a simple benchmark with two parameters:
- private input size
- number of assertions

It takes the private data, creates a sum of it, and does the
indicated number of assertions.

## Running it

The simplest way is to run it with:

```bach
devbox run benchmark
```

It will:
- create the `src/const.nr` file with the requested values
- create the `Prover.toml` file
- execute and prove the circuit with the vanilla noir and
  Barretenberg prover backend
- execute and prove the circuit with `noir-t256` and the
  Spartan backend

## Questions

- It fails if the input size and the number of assertions
  are bigger than 23, but I have no idea why!
- The speed with an input size of 23 looks like Spartan is
  slower than Barretenberg - I hope this will change with
  bigger circuit sizes...

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
