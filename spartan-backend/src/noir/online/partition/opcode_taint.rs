//! Opcode layer of the partition: where each opcode goes, given the taint set.
//!
//! Once [`TaintSet`] has settled which witnesses are online, an opcode is
//! *online* iff it reads an online witness (or touches an online memory block),
//! and *invariant* otherwise. From that assignment follow the two things the
//! synthesizer needs:
//!
//! * the [`cut_set`]: the invariant witnesses whose committed value has to cross
//!   the precommitted → online boundary;
//! * a [`validate`] pass rejecting splits that the synthesizer could not honour
//!   (an online opcode defining an invariant witness, or the converse).

use std::collections::{BTreeSet, HashSet};

use acir::{
    FieldElement,
    circuit::{Circuit, Opcode},
};

use super::{PartitionError, witness_refs, witness_taint::TaintSet};

/// For each opcode (by position), `true` if it belongs to the invariant
/// (precommitted) segment and `false` if it belongs to the online (rest) one.
pub fn classify_opcodes(circuit: &Circuit<FieldElement>, taint: &TaintSet) -> Vec<bool> {
    let mut opcode_is_invariant = Vec::with_capacity(circuit.opcodes.len());
    for opcode in &circuit.opcodes {
        let reads_tainted = witness_refs::opcode_reads(opcode)
            .iter()
            .any(|w| taint.is_tainted(w.witness_index()));
        let is_rest = match opcode {
            Opcode::MemoryInit { block_id, .. } => taint.is_block_tainted(block_id.0),
            Opcode::MemoryOp { block_id, .. } => {
                taint.is_block_tainted(block_id.0) || reads_tainted
            }
            _ => reads_tainted,
        };
        opcode_is_invariant.push(!is_rest);
    }
    opcode_is_invariant
}

/// Invariant witnesses that must cross the precommitted → online boundary,
/// sorted ascending.
///
/// These are the invariant witnesses read by an online opcode, plus every
/// invariant public input: its committed copy has to cross so that it can be
/// `inputize`d in `synthesize`.
pub fn cut_set(
    circuit: &Circuit<FieldElement>,
    taint: &TaintSet,
    opcode_is_invariant: &[bool],
    public_witnesses: &HashSet<u32>,
) -> Vec<u32> {
    let mut cut: BTreeSet<u32> = BTreeSet::new();
    for (i, opcode) in circuit.opcodes.iter().enumerate() {
        if opcode_is_invariant[i] {
            continue;
        }
        for w in witness_refs::opcode_reads(opcode) {
            let idx = w.witness_index();
            if !taint.is_tainted(idx) {
                cut.insert(idx);
            }
        }
    }
    for &pubw in public_witnesses {
        if !taint.is_tainted(pubw) {
            cut.insert(pubw);
        }
    }
    cut.into_iter().collect()
}

/// Check that the segment assignment agrees with the taint set.
///
/// Both directions are failures of the taint propagation rather than of the
/// circuit, and in practice signal an under-declared manifest.
pub fn validate(
    circuit: &Circuit<FieldElement>,
    taint: &TaintSet,
    opcode_is_invariant: &[bool],
) -> Result<(), PartitionError> {
    for (i, opcode) in circuit.opcodes.iter().enumerate() {
        if opcode_is_invariant[i] {
            for w in witness_refs::opcode_reads(opcode) {
                if taint.is_tainted(w.witness_index()) {
                    return Err(PartitionError::InvariantReadsTainted(w.witness_index()));
                }
            }
        } else {
            for w in witness_refs::opcode_writes(opcode) {
                if !taint.is_tainted(w.witness_index()) {
                    return Err(PartitionError::RestWritesInvariant(w.witness_index()));
                }
            }
            for w in &taint.assert_zero_definitions()[i] {
                if !taint.is_tainted(*w) {
                    return Err(PartitionError::RestWritesInvariant(*w));
                }
            }
        }
    }
    Ok(())
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
        TaintSet, classify_opcodes, cut_set, validate,
    };

    fn seeds(ws: &[u32]) -> HashSet<u32> {
        ws.iter().copied().collect()
    }

    /// An opcode is online exactly when it reads an online witness.
    #[test]
    fn opcodes_reading_online_witnesses_go_to_rest() {
        // 3 = 1+2 is invariant; 5 = 3+4 reads the seed 4, so it is online.
        let c = circuit(vec![linear(1, 2, 3), linear(3, 4, 5)], &[1, 2, 4]);
        let taint = TaintSet::compute(&c, &seeds(&[4]));

        assert_eq!(classify_opcodes(&c, &taint), vec![true, false]);
    }

    /// An invariant witness read by an online opcode has to cross the boundary.
    #[test]
    fn cut_set_holds_invariant_witnesses_read_online() {
        let c = circuit(vec![linear(1, 2, 3), linear(3, 4, 5)], &[1, 2, 4]);
        let taint = TaintSet::compute(&c, &seeds(&[4]));
        let classes = classify_opcodes(&c, &taint);

        // Witness 3 is invariant but feeds the online constraint; 4 and 5 are
        // online and so are not part of the cut.
        assert_eq!(cut_set(&c, &taint, &classes, &HashSet::new()), vec![3]);
    }

    /// Invariant public inputs cross the boundary too, so they can be
    /// `inputize`d in the online segment.
    #[test]
    fn cut_set_holds_invariant_public_inputs() {
        let c = circuit(vec![linear(1, 2, 3)], &[1, 2]);
        let taint = TaintSet::compute(&c, &HashSet::new());
        let classes = classify_opcodes(&c, &taint);

        assert_eq!(cut_set(&c, &taint, &classes, &seeds(&[1, 3])), vec![1, 3]);
    }

    /// Touching an online memory block puts an opcode online even when none of
    /// its own witnesses is online.
    #[test]
    fn online_block_pulls_its_opcodes_online() {
        let block = BlockId(3);
        let c = circuit(
            vec![
                Opcode::MemoryInit {
                    block_id: block,
                    init: vec![Witness(1)],
                    block_type: BlockType::Memory,
                },
                Opcode::MemoryOp {
                    block_id: block,
                    op: MemOp {
                        operation: MemOpKind::Write,
                        index: Witness(2),
                        value: Witness(40),
                    },
                },
                Opcode::MemoryOp {
                    block_id: block,
                    op: MemOp {
                        operation: MemOpKind::Read,
                        index: Witness(2),
                        value: Witness(50),
                    },
                },
            ],
            &[1, 2],
        );
        let taint = TaintSet::compute(&c, &seeds(&[40]));

        assert_eq!(classify_opcodes(&c, &taint), vec![false, false, false]);
    }

    /// A consistent partition validates.
    #[test]
    fn consistent_partition_validates() {
        let c = circuit(vec![linear(1, 2, 3), brillig(3, &[9])], &[1, 2]);
        let taint = TaintSet::compute(&c, &seeds(&[1]));
        let classes = classify_opcodes(&c, &taint);

        assert!(validate(&c, &taint, &classes).is_ok());
    }

    /// A hand-forced misclassification is caught: an opcode declared invariant
    /// while reading an online witness cannot be synthesized precommitted.
    #[test]
    fn invariant_opcode_reading_online_witness_is_rejected() {
        let c = circuit(vec![linear(1, 2, 3), linear(3, 4, 5)], &[1, 2, 4]);
        let taint = TaintSet::compute(&c, &seeds(&[4]));

        let err = validate(&c, &taint, &[true, true]).unwrap_err();
        assert_eq!(
            err,
            super::PartitionError::InvariantReadsTainted(4),
            "reading seed 4 from an invariant opcode must be reported"
        );
    }

    /// The converse: an opcode declared online while defining an invariant
    /// witness would leave that witness out of the precommitted segment.
    #[test]
    fn online_opcode_defining_invariant_witness_is_rejected() {
        let c = circuit(vec![linear(1, 2, 3)], &[1, 2]);
        let taint = TaintSet::compute(&c, &HashSet::new());

        let err = validate(&c, &taint, &[false]).unwrap_err();
        assert_eq!(err, super::PartitionError::RestWritesInvariant(3));
    }
}
