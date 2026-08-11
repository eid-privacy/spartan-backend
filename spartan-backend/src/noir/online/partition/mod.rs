//! Value-independent taint analysis that will split a single ACIR function into
//! an invariant (Vega `precommitted`) segment and an online (Vega `rest`)
//! segment, given the set of online "seed" witnesses.
//!
//! The analysis depends only on the circuit structure and the seed set, never
//! on witness *values*, so it is guaranteed identical at `setup` (ShapeCS) and
//! at `prove` (SatisfyingAssignment).
//!
//! This module holds the witness half of it: [`witness_taint`] answers *which
//! witnesses are online*, by propagating the seeds through the circuit to a
//! fixpoint, expressed over the syntactic helpers in [`witness_refs`]. Turning
//! that taint set into a per-opcode segment assignment follows.

pub mod witness_refs;
pub mod witness_taint;

#[cfg(test)]
mod test_support;
