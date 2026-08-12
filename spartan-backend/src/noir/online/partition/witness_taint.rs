//! Witness layer of the partition: which witnesses are *online*.
//!
//! [`TaintSet::compute`] seeds the online (tainted) set with the witnesses
//! declared per-proof by the manifest and propagates taint forward along the
//! read → write edges of the circuit until a fixpoint. The result is a
//! value-independent answer to "is this witness challenge-dependent?", which
//! the opcode layer ([`super::opcode_taint`]) then turns into a segment
//! assignment.
//!
//! Two subtleties drive the shape of the closure:
//!
//! * An [`Opcode::AssertZero`] declares no outputs, yet the ACVM *solves* a
//!   witness from it. Those implicit definitions come from
//!   [`witness_refs::assert_zero_definitions`] and taint like any other write.
//! * A tainted (dynamic) index taints a whole memory block, and reading a
//!   tainted block yields a tainted value, so blocks are tracked alongside
//!   witnesses and the propagation is iterated to a fixpoint rather than run in
//!   a single pass.

use std::collections::HashSet;

use acir::{
    FieldElement,
    circuit::{Circuit, Opcode, opcodes::MemOpKind},
};

use super::witness_refs;

/// The online (challenge-dependent) witnesses of a circuit, together with the
/// memory blocks whose contents are online and the implicit `AssertZero`
/// definitions the closure was built from.
#[derive(Debug, Clone)]
pub struct TaintSet {
    tainted: HashSet<u32>,
    tainted_blocks: HashSet<u32>,
    assert_zero_definitions: Vec<Vec<u32>>,
}

impl TaintSet {
    /// Propagate the online seeds through the circuit to a fixpoint.
    pub fn compute(circuit: &Circuit<FieldElement>, online_seeds: &HashSet<u32>) -> Self {
        let assert_zero_definitions = witness_refs::assert_zero_definitions(circuit);

        let mut tainted: HashSet<u32> = online_seeds.clone();
        // Memory blocks whose contents are (possibly) challenge-dependent.
        let mut tainted_blocks: HashSet<u32> = HashSet::new();

        loop {
            let mut changed = false;
            for (opcode_index, opcode) in circuit.opcodes.iter().enumerate() {
                match opcode {
                    Opcode::AssertZero(expr) => {
                        let reads_tainted = witness_refs::expression_witnesses(expr)
                            .iter()
                            .any(|w| tainted.contains(&w.witness_index()));
                        if reads_tainted {
                            for w in &assert_zero_definitions[opcode_index] {
                                if tainted.insert(*w) {
                                    changed = true;
                                }
                            }
                        }
                    }
                    Opcode::MemoryInit { block_id, init, .. } => {
                        if init.iter().any(|w| tainted.contains(&w.witness_index()))
                            && tainted_blocks.insert(block_id.as_u32())
                        {
                            changed = true;
                        }
                    }
                    Opcode::MemoryOp { block_id, op } => {
                        let idx_tainted = tainted.contains(&op.index.witness_index());
                        let val_tainted = tainted.contains(&op.value.witness_index());
                        match op.operation {
                            MemOpKind::Write => {
                                if (idx_tainted || val_tainted)
                                    && tainted_blocks.insert(block_id.as_u32())
                                {
                                    changed = true;
                                }
                            }
                            MemOpKind::Read => {
                                // A tainted (dynamic) index makes the whole
                                // block's addressing challenge-dependent.
                                if idx_tainted && tainted_blocks.insert(block_id.as_u32()) {
                                    changed = true;
                                }
                                // Reading a tainted block yields a tainted value.
                                if (idx_tainted || tainted_blocks.contains(&block_id.as_u32()))
                                    && tainted.insert(op.value.witness_index())
                                {
                                    changed = true;
                                }
                            }
                        }
                    }
                    _ => {
                        let reads_tainted = witness_refs::opcode_reads(opcode)
                            .iter()
                            .any(|w| tainted.contains(&w.witness_index()));
                        if reads_tainted {
                            for w in witness_refs::opcode_writes(opcode) {
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

        TaintSet {
            tainted,
            tainted_blocks,
            assert_zero_definitions,
        }
    }

    /// Is this witness online?
    pub fn is_tainted(&self, witness: u32) -> bool {
        self.tainted.contains(&witness)
    }

    /// Are the contents of this memory block online?
    pub fn is_block_tainted(&self, block_id: u32) -> bool {
        self.tainted_blocks.contains(&block_id)
    }

    /// All online witnesses, including seeds the circuit never references.
    pub fn witnesses(&self) -> &HashSet<u32> {
        &self.tainted
    }

    /// Per-opcode witnesses implicitly solved from an `AssertZero`, as used to
    /// build the closure (see [`witness_refs::assert_zero_definitions`]).
    pub fn assert_zero_definitions(&self) -> &[Vec<u32>] {
        &self.assert_zero_definitions
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use acir::{
        circuit::{
            Opcode,
            opcodes::{BlockId, BlockType, MemOp, MemOpKind},
        },
        native_types::Witness,
    };

    use super::{
        super::test_support::{brillig, circuit, linear},
        TaintSet,
    };

    fn seeds(ws: &[u32]) -> HashSet<u32> {
        ws.iter().copied().collect()
    }

    /// Taint flows along a chain of solved `AssertZero` opcodes and stops at the
    /// constraints that read nothing online.
    #[test]
    fn assert_zero_chain_propagates_to_solved_witnesses() {
        // 1,2 are inputs; 3 = 1+2 (invariant); 4 is a seed; 5 = 3+4 (online).
        let c = circuit(vec![linear(1, 2, 3), linear(3, 4, 5)], &[1, 2, 4]);
        let taint = TaintSet::compute(&c, &seeds(&[4]));

        assert!(taint.is_tainted(4));
        assert!(taint.is_tainted(5), "witness solved from a seed is online");
        assert!(
            !taint.is_tainted(3),
            "witness solved from inputs stays invariant"
        );
        assert!(!taint.is_tainted(1) && !taint.is_tainted(2));
    }

    /// An `AssertZero` that only *constrains* already-known witnesses defines
    /// nothing, so it must not extend the online set.
    #[test]
    fn assert_zero_without_new_witness_defines_nothing() {
        let c = circuit(vec![linear(1, 2, 3), linear(1, 2, 3)], &[1, 2]);
        let taint = TaintSet::compute(&c, &seeds(&[1]));

        assert_eq!(taint.assert_zero_definitions()[0], vec![3]);
        assert!(
            taint.assert_zero_definitions()[1].is_empty(),
            "the second constraint re-reads only known witnesses"
        );
        assert!(taint.is_tainted(3));
    }

    /// A declared writer taints all of its outputs as soon as any of its inputs
    /// is online.
    #[test]
    fn declared_outputs_inherit_input_taint() {
        let c = circuit(vec![brillig(1, &[10, 11]), brillig(2, &[20])], &[1, 2]);
        let taint = TaintSet::compute(&c, &seeds(&[1]));

        assert!(taint.is_tainted(10) && taint.is_tainted(11));
        assert!(!taint.is_tainted(20));
    }

    /// Writing an online value into a block taints the block, and every read
    /// from it yields an online value — including reads that appear *earlier*
    /// in the opcode list, which is why the closure runs to a fixpoint.
    #[test]
    fn tainted_write_taints_block_and_earlier_reads() {
        let block = BlockId::new(7);
        let c = circuit(
            vec![
                Opcode::MemoryInit {
                    block_id: block,
                    init: vec![Witness(1), Witness(2)],
                    block_type: BlockType::Memory,
                },
                Opcode::MemoryOp {
                    block_id: block,
                    op: MemOp {
                        operation: MemOpKind::Read,
                        index: Witness(3),
                        value: Witness(30),
                    },
                },
                Opcode::MemoryOp {
                    block_id: block,
                    op: MemOp {
                        operation: MemOpKind::Write,
                        index: Witness(4),
                        value: Witness(40),
                    },
                },
            ],
            &[1, 2, 3, 4],
        );
        let taint = TaintSet::compute(&c, &seeds(&[40]));

        assert!(taint.is_block_tainted(block.as_u32()));
        assert!(
            taint.is_tainted(30),
            "the earlier read must be revisited once the block is tainted"
        );
    }

    /// A dynamic (online) index taints the addressing of the whole block, so
    /// values read from it are online even though its contents are not.
    #[test]
    fn tainted_index_taints_block_addressing() {
        let block = BlockId::new(1);
        let c = circuit(
            vec![
                Opcode::MemoryInit {
                    block_id: block,
                    init: vec![Witness(1), Witness(2)],
                    block_type: BlockType::Memory,
                },
                Opcode::MemoryOp {
                    block_id: block,
                    op: MemOp {
                        operation: MemOpKind::Read,
                        index: Witness(50),
                        value: Witness(51),
                    },
                },
            ],
            &[1, 2],
        );
        let taint = TaintSet::compute(&c, &seeds(&[50]));

        assert!(taint.is_block_tainted(block.as_u32()));
        assert!(taint.is_tainted(51));
    }

    /// Without seeds nothing is online, which is what makes a circuit shipping
    /// no manifest entirely invariant at the witness level.
    #[test]
    fn no_seeds_taints_nothing() {
        let c = circuit(vec![linear(1, 2, 3), linear(3, 4, 5)], &[1, 2, 4]);
        let taint = TaintSet::compute(&c, &HashSet::new());

        assert!(taint.witnesses().is_empty());
    }
}
