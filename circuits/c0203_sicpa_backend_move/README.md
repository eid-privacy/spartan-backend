# Experiment Background

This is based on [c0201_sicpa_backend](../c0201_sicpa_backend) and 
experiments how to keep variable-length header witnesses with a reasonable
constraint size.

Claude proposed a `barrel shifter` trick in the method `move_right`, 
which allows to reduce the constraints to a little factor.
Instead of shifting by a variable length, which is very expensive, the shift
is done conditionally on powers of two of the variable length.
There is a comparison with a `move_right_simple` method which does a shift
based on common software wisdom.
However, this latter is still very expensive!
Here is Claude's explanation of why:

> The core issue: variable array indices are expensive in a circuit.

> In a circuit, "array index" isn't a pointer lookup like in normal code — the compiler has to turn it into arithmetic constraints. If the index is a
> compile-time constant, that's free: it's just wiring `out[3] = src[1]`, decided at compile time. But if the index is a runtime value (a witness, unknown
> until the prover runs), the circuit can't "jump" to that slot. It has to build logic that says, for every possible index value, "is this the one? if
> so, copy it" — effectively a scan over all N positions for every single output element.
> 
> - `move_right_simple` does `src[k - shift]` where `shift` is a runtime input. That's a variable index, so for each of the N output bytes, the compiler emits
> an ~N-sized selector over all possible source positions. N outputs × N-sized lookup each ≈ O(N²) constraints. Your `SIGNING_INPUT_MAX_LEN` is in the
> thousands of bytes, so N² blows up fast.
> - `move_right` never does a variable-index read. It decomposes the shift into its bits (LOG of them, since shift is bounded — here at most 128, i.e. 8
> bits). At each bit-step it shifts by a fixed power of two (1, 2, 4, 8, ...), and those are compile-time constants baked into the unrolled loop (step
> doubles each iteration, LOG is a compile-time generic, so the outer loop is fully unrolled at compile time). Indexing by a constant offset is free. The
> only "runtime" part is a cheap `if bit == 1 { from } else { cur[i] }` select per byte per step — O(N) work, done LOG times, so O(N·LOG) total — roughly
> N·8 instead of N².
> 
> This is the classic "barrel shifter" trick: instead of one big variable shift (expensive random access), do log2(max_shift) small conditional shifts by
> fixed powers of two (cheap, since each is a constant-offset copy plus a select). Same result, dramatically fewer constraints.
