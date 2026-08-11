//! Value-independent taint closure that partitions a single ACIR function into
//! an invariant (Vega `precommitted`) segment and an online (Vega `rest`)
//! segment, given the set of online "seed" witnesses.
//!
//! The partition depends only on the circuit structure and the seed set, never
//! on witness *values*, so it is guaranteed identical at `setup` (ShapeCS) and
//! at `prove` (SatisfyingAssignment).
//!
//! It is derived in two stages, one per submodule:
//!
//! 1. [`witness_taint`] answers *which witnesses are online*, by propagating the
//!    seeds through the circuit to a fixpoint;
//! 2. [`opcode_taint`] answers *where each opcode goes* given that taint set,
//!    and derives the cut set between the two segments.
//!
//! Both are expressed over the syntactic helpers in [`witness_refs`].

use std::collections::HashSet;

use acir::{FieldElement, circuit::Circuit};

pub mod opcode_taint;
#[cfg(test)]
mod test_support;
pub mod witness_refs;
pub mod witness_taint;

use witness_taint::TaintSet;

/// Error produced when the declared online seeds lead to an inconsistent
/// partition (typically an under-declared manifest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionError {
    /// A rest (online) opcode writes a witness that the closure marked
    /// invariant — the taint propagation is inconsistent.
    RestWritesInvariant(u32),
    /// An invariant (precommitted) opcode reads a tainted witness — it should
    /// have been classified as rest.
    InvariantReadsTainted(u32),
}

impl std::fmt::Display for PartitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartitionError::RestWritesInvariant(w) => {
                write!(f, "rest opcode writes invariant witness {w}")
            }
            PartitionError::InvariantReadsTainted(w) => {
                write!(f, "invariant opcode reads tainted witness {w}")
            }
        }
    }
}

impl std::error::Error for PartitionError {}

/// Structural split of an ACIR function into invariant / online segments.
#[derive(Debug, Clone)]
pub struct Partition {
    /// For each opcode (by position), `true` if it belongs to the invariant
    /// (precommitted) segment and `false` if it belongs to the online (rest)
    /// segment.
    pub opcode_is_invariant: Vec<bool>,
    /// Invariant witness indices, sorted ascending.
    pub invariant_witnesses: Vec<u32>,
    /// Online (tainted) witness indices, sorted ascending.
    pub rest_witnesses: Vec<u32>,
    /// Invariant witnesses that must cross the precommitted → synthesize
    /// boundary (read by a rest opcode, or an invariant public input), sorted
    /// ascending. This is the ordered cut set returned by `precommitted`.
    pub cut_set: Vec<u32>,
    /// All public-input witness indices, sorted ascending. Every one of these
    /// is `inputize`d in `synthesize`, in this order.
    pub public_witnesses: Vec<u32>,
    /// Largest witness index referenced by the circuit (for `WitnessMap` sizing).
    pub max_witness_index: u32,
}

impl Partition {
    /// Build the trivial "everything online" partition: every opcode and
    /// witness is in the rest segment, nothing crosses the boundary. This
    /// reproduces the original monolithic synthesis behaviour and is used when
    /// no manifest is present.
    pub fn all_rest(circuit: &Circuit<FieldElement>, public_witnesses: &HashSet<u32>) -> Self {
        let all = witness_refs::all_witnesses(circuit);
        let max_witness_index = all.iter().copied().max().unwrap_or(0);
        let mut public: Vec<u32> = public_witnesses.iter().copied().collect();
        public.sort_unstable();
        let mut rest: Vec<u32> = all.into_iter().collect();
        rest.sort_unstable();

        Partition {
            opcode_is_invariant: vec![false; circuit.opcodes.len()],
            invariant_witnesses: Vec::new(),
            rest_witnesses: rest,
            cut_set: Vec::new(),
            public_witnesses: public,
            max_witness_index,
        }
    }

    /// Compute the partition from the online seed witnesses: taint the
    /// witnesses, classify the opcodes against that taint set, then read off
    /// the cut set and the per-segment witness lists.
    pub fn compute(
        circuit: &Circuit<FieldElement>,
        online_seeds: &HashSet<u32>,
        public_witnesses: &HashSet<u32>,
    ) -> Result<Self, PartitionError> {
        let taint = TaintSet::compute(circuit, online_seeds);
        let opcode_is_invariant = opcode_taint::classify_opcodes(circuit, &taint);
        let cut_set =
            opcode_taint::cut_set(circuit, &taint, &opcode_is_invariant, public_witnesses);
        opcode_taint::validate(circuit, &taint, &opcode_is_invariant)?;

        let all = witness_refs::all_witnesses(circuit);
        let max_witness_index = all.iter().copied().max().unwrap_or(0);
        let mut invariant: Vec<u32> = all
            .iter()
            .copied()
            .filter(|w| !taint.is_tainted(*w))
            .collect();
        invariant.sort_unstable();
        let mut rest: Vec<u32> = taint.witnesses().iter().copied().collect();
        // Keep only witnesses actually referenced by the circuit.
        rest.retain(|w| all.contains(w));
        rest.sort_unstable();
        let mut public: Vec<u32> = public_witnesses.iter().copied().collect();
        public.sort_unstable();

        Ok(Partition {
            opcode_is_invariant,
            invariant_witnesses: invariant,
            rest_witnesses: rest,
            cut_set,
            public_witnesses: public,
            max_witness_index,
        })
    }

    /// Number of opcodes assigned to the invariant (precommitted) segment.
    pub fn invariant_opcode_count(&self) -> usize {
        self.opcode_is_invariant.iter().filter(|&&b| b).count()
    }

    /// Number of opcodes assigned to the online (rest) segment.
    pub fn rest_opcode_count(&self) -> usize {
        self.opcode_is_invariant.iter().filter(|&&b| !b).count()
    }
}
