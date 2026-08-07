//! Value-independent taint closure that partitions a single ACIR function into
//! an invariant (Vega `precommitted`) segment and an online (Vega `rest`)
//! segment, given the set of online "seed" witnesses.
//!
//! The partition depends only on the circuit structure and the seed set, never
//! on witness *values*, so it is guaranteed identical at `setup` (ShapeCS) and
//! at `prove` (SatisfyingAssignment).

use std::collections::{BTreeSet, HashSet};

use acir::{
    FieldElement,
    circuit::{
        Circuit, Opcode,
        brillig::{BrilligInputs, BrilligOutputs},
        opcodes::MemOpKind,
    },
    native_types::{Expression, Witness},
};

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
        let all = all_witnesses(circuit);
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

    /// Compute the partition from the online seed witnesses via a forward taint
    /// closure over the opcodes (run to a fixpoint to handle memory blocks).
    pub fn compute(
        circuit: &Circuit<FieldElement>,
        online_seeds: &HashSet<u32>,
        public_witnesses: &HashSet<u32>,
    ) -> Result<Self, PartitionError> {
        let opcodes = &circuit.opcodes;

        // An `AssertZero` has no declared outputs, but the ACVM solves a witness
        // from it, so it taints like any other writer.
        let defined_by_assert_zero = assert_zero_definitions(circuit);

        let mut tainted: HashSet<u32> = online_seeds.clone();
        // Memory blocks whose contents are (possibly) challenge-dependent.
        let mut block_tainted: HashSet<u32> = HashSet::new();

        loop {
            let mut changed = false;
            for (opcode_index, opcode) in opcodes.iter().enumerate() {
                match opcode {
                    Opcode::AssertZero(expr) => {
                        let reads_tainted = expression_witnesses(expr)
                            .iter()
                            .any(|w| tainted.contains(&w.witness_index()));
                        if reads_tainted {
                            for w in &defined_by_assert_zero[opcode_index] {
                                if tainted.insert(*w) {
                                    changed = true;
                                }
                            }
                        }
                    }
                    Opcode::MemoryInit { block_id, init, .. } => {
                        if init.iter().any(|w| tainted.contains(&w.witness_index()))
                            && block_tainted.insert(block_id.0)
                        {
                            changed = true;
                        }
                    }
                    Opcode::MemoryOp { block_id, op } => {
                        let idx_tainted = tainted.contains(&op.index.witness_index());
                        let val_tainted = tainted.contains(&op.value.witness_index());
                        match op.operation {
                            MemOpKind::Write => {
                                if (idx_tainted || val_tainted) && block_tainted.insert(block_id.0)
                                {
                                    changed = true;
                                }
                            }
                            MemOpKind::Read => {
                                // A tainted (dynamic) index makes the whole
                                // block's addressing challenge-dependent.
                                if idx_tainted && block_tainted.insert(block_id.0) {
                                    changed = true;
                                }
                                // Reading a tainted block yields a tainted value.
                                if (idx_tainted || block_tainted.contains(&block_id.0))
                                    && tainted.insert(op.value.witness_index())
                                {
                                    changed = true;
                                }
                            }
                        }
                    }
                    _ => {
                        let reads_tainted = opcode_reads(opcode)
                            .iter()
                            .any(|w| tainted.contains(&w.witness_index()));
                        if reads_tainted {
                            for w in opcode_writes(opcode) {
                                if tainted.insert(w.witness_index()) {
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }

        let mut opcode_is_invariant = Vec::with_capacity(opcodes.len());
        for opcode in opcodes {
            let reads_tainted = opcode_reads(opcode)
                .iter()
                .any(|w| tainted.contains(&w.witness_index()));
            let is_rest = match opcode {
                Opcode::MemoryInit { block_id, .. } => block_tainted.contains(&block_id.0),
                Opcode::MemoryOp { block_id, .. } => {
                    block_tainted.contains(&block_id.0) || reads_tainted
                }
                _ => reads_tainted,
            };
            opcode_is_invariant.push(!is_rest);
        }

        // Cut set: invariant witnesses read by rest opcodes...
        let mut cut: BTreeSet<u32> = BTreeSet::new();
        for (i, opcode) in opcodes.iter().enumerate() {
            if opcode_is_invariant[i] {
                continue;
            }
            for w in opcode_reads(opcode) {
                let idx = w.witness_index();
                if !tainted.contains(&idx) {
                    cut.insert(idx);
                }
            }
        }
        // ...plus every invariant public input (its committed copy must cross
        // so it can be `inputize`d in `synthesize`).
        for &pubw in public_witnesses {
            if !tainted.contains(&pubw) {
                cut.insert(pubw);
            }
        }

        for (i, opcode) in opcodes.iter().enumerate() {
            if opcode_is_invariant[i] {
                for w in opcode_reads(opcode) {
                    if tainted.contains(&w.witness_index()) {
                        return Err(PartitionError::InvariantReadsTainted(w.witness_index()));
                    }
                }
            } else {
                for w in opcode_writes(opcode) {
                    if !tainted.contains(&w.witness_index()) {
                        return Err(PartitionError::RestWritesInvariant(w.witness_index()));
                    }
                }
                for w in &defined_by_assert_zero[i] {
                    if !tainted.contains(w) {
                        return Err(PartitionError::RestWritesInvariant(*w));
                    }
                }
            }
        }

        let all = all_witnesses(circuit);
        let max_witness_index = all.iter().copied().max().unwrap_or(0);
        let mut invariant: Vec<u32> = all
            .iter()
            .copied()
            .filter(|w| !tainted.contains(w))
            .collect();
        invariant.sort_unstable();
        let mut rest: Vec<u32> = tainted.iter().copied().collect();
        // Keep only witnesses actually referenced by the circuit.
        rest.retain(|w| all.contains(w));
        rest.sort_unstable();
        let mut public: Vec<u32> = public_witnesses.iter().copied().collect();
        public.sort_unstable();

        Ok(Partition {
            opcode_is_invariant,
            invariant_witnesses: invariant,
            rest_witnesses: rest,
            cut_set: cut.into_iter().collect(),
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

/// Witnesses appearing in an [`Expression`] (mul-term and linear factors).
fn expression_witnesses(expr: &Expression<FieldElement>) -> Vec<Witness> {
    let mut witnesses = Vec::new();
    witnesses.extend(expr.mul_terms.iter().flat_map(|(_, l, r)| [*l, *r]));
    witnesses.extend(expr.linear_combinations.iter().map(|(_, w)| *w));
    witnesses
}

/// For every opcode, the witnesses the ACVM would *solve* from it when it is an
/// [`Opcode::AssertZero`] (empty for all other opcodes).
///
/// Replays the solver's walk: opcodes in order against the set of already-known
/// witnesses (circuit inputs plus everything written earlier). This is purely
/// structural, so the result is identical at `setup` and at `prove`. Expressions
/// with several unknowns are attributed all of them, which over-approximates the
/// online segment — sound, unlike the reverse.
fn assert_zero_definitions(circuit: &Circuit<FieldElement>) -> Vec<Vec<u32>> {
    let mut known: HashSet<u32> = HashSet::new();
    known.extend(
        circuit
            .public_parameters
            .0
            .iter()
            .map(|w| w.witness_index()),
    );
    known.extend(circuit.private_parameters.iter().map(|w| w.witness_index()));

    let mut definitions = Vec::with_capacity(circuit.opcodes.len());
    for opcode in &circuit.opcodes {
        let mut defined = Vec::new();
        if let Opcode::AssertZero(expr) = opcode {
            for w in expression_witnesses(expr) {
                let idx = w.witness_index();
                if known.insert(idx) {
                    defined.push(idx);
                }
            }
        }
        for w in opcode_writes(opcode) {
            known.insert(w.witness_index());
        }
        definitions.push(defined);
    }
    definitions
}

/// Witnesses an opcode *reads* (its inputs).
fn opcode_reads(opcode: &Opcode<FieldElement>) -> Vec<Witness> {
    match opcode {
        Opcode::AssertZero(expr) => expression_witnesses(expr),
        Opcode::BlackBoxFuncCall(call) => call.get_input_witnesses().into_iter().collect(),
        Opcode::MemoryInit { init, .. } => init.clone(),
        Opcode::MemoryOp { op, .. } => match op.operation {
            MemOpKind::Read => vec![op.index],
            MemOpKind::Write => vec![op.index, op.value],
        },
        Opcode::BrilligCall {
            inputs, predicate, ..
        } => {
            let mut witnesses = Vec::new();
            for input in inputs {
                match input {
                    BrilligInputs::Single(expr) => witnesses.extend(expression_witnesses(expr)),
                    BrilligInputs::Array(exprs) => {
                        for expr in exprs {
                            witnesses.extend(expression_witnesses(expr));
                        }
                    }
                    BrilligInputs::MemoryArray(_) => {}
                }
            }
            witnesses.extend(expression_witnesses(predicate));
            witnesses
        }
        Opcode::Call {
            inputs, predicate, ..
        } => {
            let mut witnesses = inputs.clone();
            witnesses.extend(expression_witnesses(predicate));
            witnesses
        }
    }
}

/// Witnesses an opcode *writes* (its outputs).
fn opcode_writes(opcode: &Opcode<FieldElement>) -> Vec<Witness> {
    match opcode {
        Opcode::AssertZero(_) => Vec::new(),
        Opcode::BlackBoxFuncCall(call) => call.get_outputs_vec(),
        Opcode::MemoryInit { .. } => Vec::new(),
        Opcode::MemoryOp { op, .. } => match op.operation {
            MemOpKind::Read => vec![op.value],
            MemOpKind::Write => Vec::new(),
        },
        Opcode::BrilligCall { outputs, .. } => {
            let mut witnesses = Vec::new();
            for output in outputs {
                match output {
                    BrilligOutputs::Simple(w) => witnesses.push(*w),
                    BrilligOutputs::Array(ws) => witnesses.extend(ws.iter().copied()),
                }
            }
            witnesses
        }
        Opcode::Call { outputs, .. } => outputs.clone(),
    }
}

/// Every witness referenced (read or written) anywhere in the circuit.
fn all_witnesses(circuit: &Circuit<FieldElement>) -> HashSet<u32> {
    let mut all = HashSet::new();
    for opcode in &circuit.opcodes {
        for w in opcode_reads(opcode) {
            all.insert(w.witness_index());
        }
        for w in opcode_writes(opcode) {
            all.insert(w.witness_index());
        }
    }
    all
}
