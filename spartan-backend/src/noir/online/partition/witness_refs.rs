//! Purely syntactic view of an ACIR circuit in terms of witnesses.
//!
//! Nothing here looks at witness *values*: each helper answers a structural
//! question about an opcode ("which witnesses does it read / write?") or about
//! the circuit as a whole. Both the witness layer
//! ([`super::witness_taint`], which propagates taint along these edges) and the
//! opcode layer ([`super::opcode_taint`], which classifies and validates
//! opcodes against the resulting taint set) are built on top of them.

use std::collections::HashSet;

use acir::{
    FieldElement,
    circuit::{
        Circuit, Opcode,
        brillig::{BrilligInputs, BrilligOutputs},
        opcodes::MemOpKind,
    },
    native_types::{Expression, Witness},
};

/// Witnesses appearing in an [`Expression`] (mul-term and linear factors).
pub fn expression_witnesses(expr: &Expression<FieldElement>) -> Vec<Witness> {
    let mut witnesses = Vec::new();
    witnesses.extend(expr.mul_terms.iter().flat_map(|(_, l, r)| [*l, *r]));
    witnesses.extend(expr.linear_combinations.iter().map(|(_, w)| *w));
    witnesses
}

/// Witnesses an opcode *reads* (its inputs).
pub fn opcode_reads(opcode: &Opcode<FieldElement>) -> Vec<Witness> {
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
pub fn opcode_writes(opcode: &Opcode<FieldElement>) -> Vec<Witness> {
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
pub fn all_witnesses(circuit: &Circuit<FieldElement>) -> HashSet<u32> {
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

/// For every opcode, the witnesses the ACVM would *solve* from it when it is an
/// [`Opcode::AssertZero`] (empty for all other opcodes).
///
/// Replays the solver's walk: opcodes in order against the set of already-known
/// witnesses (circuit inputs plus everything written earlier). This is purely
/// structural, so the result is identical at `setup` and at `prove`. Expressions
/// with several unknowns are attributed all of them, which over-approximates the
/// online segment — sound, unlike the reverse.
pub fn assert_zero_definitions(circuit: &Circuit<FieldElement>) -> Vec<Vec<u32>> {
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

#[cfg(test)]
mod tests {
    use acir::{
        circuit::{
            Opcode,
            opcodes::{BlockId, BlockType, MemOp, MemOpKind},
        },
        native_types::Witness,
    };

    use super::{
        super::test_support::{brillig, circuit, linear},
        all_witnesses, assert_zero_definitions, opcode_reads, opcode_writes,
    };

    fn indices(witnesses: Vec<Witness>) -> Vec<u32> {
        witnesses.iter().map(|w| w.witness_index()).collect()
    }

    /// An `AssertZero` reads every witness of its expression and declares no write.
    #[test]
    fn assert_zero_reads_its_expression_and_writes_nothing() {
        let opcode = linear(1, 2, 3);
        assert_eq!(indices(opcode_reads(&opcode)), vec![1, 2, 3]);
        assert!(opcode_writes(&opcode).is_empty());
    }

    /// A memory read reads its index and writes its value; a write reads both.
    #[test]
    fn memory_op_direction_depends_on_kind() {
        let op = |operation| Opcode::MemoryOp {
            block_id: BlockId::new(0),
            op: MemOp {
                operation,
                index: Witness(1),
                value: Witness(2),
            },
        };
        let read = op(MemOpKind::Read);
        assert_eq!(indices(opcode_reads(&read)), vec![1]);
        assert_eq!(indices(opcode_writes(&read)), vec![2]);

        let write = op(MemOpKind::Write);
        assert_eq!(indices(opcode_reads(&write)), vec![1, 2]);
        assert!(opcode_writes(&write).is_empty());
    }

    /// A `MemoryInit` only reads: the block contents are not witness writes.
    #[test]
    fn memory_init_only_reads() {
        let opcode: Opcode<acir::FieldElement> = Opcode::MemoryInit {
            block_id: BlockId::new(0),
            init: vec![Witness(4), Witness(5)],
            block_type: BlockType::Memory,
        };
        assert_eq!(indices(opcode_reads(&opcode)), vec![4, 5]);
        assert!(opcode_writes(&opcode).is_empty());
    }

    /// Both directions of every opcode contribute to the referenced witnesses.
    #[test]
    fn all_witnesses_covers_reads_and_writes() {
        let c = circuit(vec![linear(1, 2, 3), brillig(3, &[9])], &[1, 2]);
        let mut all: Vec<u32> = all_witnesses(&c).into_iter().collect();
        all.sort_unstable();
        assert_eq!(all, vec![1, 2, 3, 9]);
    }

    /// The solver walk attributes a witness to the *first* opcode that could
    /// define it, and never to a later one.
    #[test]
    fn assert_zero_definitions_follow_the_solver_order() {
        let c = circuit(
            vec![linear(1, 2, 3), linear(3, 1, 4), linear(1, 2, 3)],
            &[1, 2],
        );
        let definitions = assert_zero_definitions(&c);
        assert_eq!(definitions, vec![vec![3], vec![4], vec![]]);
    }

    /// A witness written by an earlier declared writer is already known, so a
    /// later `AssertZero` reading it defines nothing.
    #[test]
    fn declared_writes_make_witnesses_known() {
        let c = circuit(vec![brillig(1, &[7]), linear(1, 7, 8)], &[1]);
        assert_eq!(assert_zero_definitions(&c), vec![vec![], vec![8]]);
    }
}
