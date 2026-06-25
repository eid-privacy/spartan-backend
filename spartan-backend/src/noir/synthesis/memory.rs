//! Synthesis support for ACIR's memory opcodes (`MemoryInit` / `MemoryOp`).
//!
//! ACIR represents arrays with non-constant indexing via dedicated opcodes:
//! - [`Opcode::MemoryInit`] initializes a block of memory from a list of witnesses.
//! - [`Opcode::MemoryOp`] reads from or writes to that block at a witness-provided index.
//!
//! This module turns those high-level operations into R1CS constraints using a
//! standard selector-based encoding: for a block of length N, every op
//! introduces N boolean selectors `s_i` with `Σ s_i = 1` and `Σ i·s_i = index`,
//! so that exactly the selector at position `index` is set. Reads then enforce
//! `Σ s_i · cell_i = value`; writes produce a fresh cell vector through a
//! single per-cell R1CS gate `(value − cell) · s = new_cell − cell`.
//!
//! The cost is O(N) constraints per op; this is acceptable for the circuits we
//! currently target and is a deliberate simple-first design. A lookup-argument
//! based encoding would be a future optimisation.

use crate::noir::synthesis::allocation_support::{AllocatedWire, WitnessMap};
use crate::types::Scalar;
use acir::circuit::opcodes::{BlockId, BlockType, MemOp, MemOpKind};
use acir::native_types::Witness;
use bellpepper_core::boolean::AllocatedBit;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField};
use std::collections::HashMap;

/// Symbolic contents of an ACIR memory block.
///
/// `cells` is updated in-place on writes: each entry is the [`AllocatedNum`]
/// currently bound to that cell index. Initialisation populates it from the
/// witnesses listed in the corresponding `MemoryInit` opcode.
pub(crate) struct MemoryBlock {
    cells: Vec<AllocatedNum<Scalar>>,
}

/// Per-circuit registry of [`MemoryBlock`]s, keyed by ACIR [`BlockId`].
#[derive(Default)]
pub(crate) struct MemoryStore {
    blocks: HashMap<u32, MemoryBlock>,
}

impl MemoryStore {
    pub(crate) fn block_len(
        &self,
        block_id: acvm::acir::circuit::opcodes::BlockId,
    ) -> Option<usize> {
        self.blocks.get(&block_id.0).map(|b| b.cells.len())
    }
    pub(crate) fn new() -> Self {
        Self {
            blocks: HashMap::new(),
        }
    }
}

/// Resolve a [`Witness`] to its already-allocated [`AllocatedNum`].
///
/// All witnesses are pre-allocated by `build_allocation_store` before opcodes
/// are processed, so a miss here indicates a malformed circuit or a missing
/// assignment on the verifier side.
fn resolve_witness<'a>(
    allocation_store: &'a WitnessMap<AllocatedWire<Scalar>>,
    witness: Witness,
) -> Result<&'a AllocatedNum<Scalar>, SynthesisError> {
    let wire = allocation_store
        .get(&witness.witness_index())
        .ok_or(SynthesisError::AssignmentMissing)?;
    wire.allocation
        .as_ref()
        .map_err(|_| SynthesisError::AssignmentMissing)
}

/// Best-effort conversion from a field element to a `usize` index, used only
/// to populate the prover-side witness values for selector bits. Constraints
/// remain authoritative; if conversion fails the selector values are left as
/// `None` and bellpepper will surface an `AssignmentMissing` during proving.
fn scalar_to_usize(v: Scalar) -> Option<usize> {
    let repr = v.to_repr();
    let bytes = repr.as_ref();
    if bytes.len() < 8 {
        return None;
    }
    // The supported scalar fields are little-endian; verify by checking that
    // all bytes beyond the first 8 are zero, otherwise the index would not
    // fit in a usize anyway and we bail.
    for b in &bytes[8..] {
        if *b != 0 {
            return None;
        }
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    let v = u64::from_le_bytes(buf);
    usize::try_from(v).ok()
}

/// Allocate `length` boolean selectors `s_i` such that exactly one is set,
/// and the position of the set selector equals the value of `index`.
///
/// Constraints emitted:
/// - `s_i * (s_i - 1) = 0` (already enforced by [`AllocatedBit::alloc`])
/// - `Σ s_i = 1`
/// - `Σ i · s_i = index`
fn build_selectors<CS>(
    cs: &mut CS,
    length: usize,
    index: &AllocatedNum<Scalar>,
) -> Result<Vec<AllocatedBit>, SynthesisError>
where
    CS: ConstraintSystem<Scalar>,
{
    let target = index.get_value().and_then(scalar_to_usize);

    let selectors: Vec<AllocatedBit> = (0..length)
        .map(|i| {
            let value = target.map(|t| t == i);
            AllocatedBit::alloc(cs.namespace(|| format!("selector {i}")), value)
        })
        .collect::<Result<_, _>>()?;

    // Σ s_i = 1
    cs.enforce(
        || "selectors sum to one",
        |lc| selectors.iter().fold(lc, |acc, s| acc + s.get_variable()),
        |lc| lc + CS::one(),
        |lc| lc + CS::one(),
    );

    // Σ i · s_i = index
    cs.enforce(
        || "selectors encode index",
        |lc| {
            selectors.iter().enumerate().fold(lc, |acc, (i, s)| {
                acc + (Scalar::from(i as u64), s.get_variable())
            })
        },
        |lc| lc + CS::one(),
        |lc| lc + index.get_variable(),
    );

    Ok(selectors)
}

/// Handle [`Opcode::MemoryInit`]: register a new memory block populated with
/// the allocated values of its initial witnesses.
pub(crate) fn handle_memory_init(
    store: &mut MemoryStore,
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    block_id: BlockId,
    init: &[Witness],
    block_type: &BlockType,
) -> Result<(), SynthesisError> {
    if !matches!(block_type, BlockType::Memory) {
        tracing::error!(
            "Unsupported MemoryInit block type {:?} for block {}",
            block_type,
            block_id
        );
        return Err(SynthesisError::Unsatisfiable);
    }

    if store.blocks.contains_key(&block_id.0) {
        tracing::error!("MemoryInit called twice for block {}", block_id);
        return Err(SynthesisError::Unsatisfiable);
    }

    let cells = init
        .iter()
        .map(|w| resolve_witness(allocation_store, *w).cloned())
        .collect::<Result<Vec<_>, _>>()?;

    tracing::debug!(
        "Initialised memory block {} with {} cells",
        block_id,
        cells.len()
    );
    store.blocks.insert(block_id.0, MemoryBlock { cells });
    Ok(())
}

/// Handle [`Opcode::MemoryOp`]: enforce a read or write against the previously
/// initialised block, using selector-based addressing.
pub(crate) fn handle_memory_op<CS>(
    cs: &mut CS,
    store: &mut MemoryStore,
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    block_id: BlockId,
    op: &MemOp,
) -> Result<(), SynthesisError>
where
    CS: ConstraintSystem<Scalar>,
{
    let block = store.blocks.get(&block_id.0).ok_or_else(|| {
        tracing::error!("MemoryOp on uninitialised block {}", block_id);
        SynthesisError::Unsatisfiable
    })?;
    let length = block.cells.len();
    if length == 0 {
        tracing::error!("MemoryOp on empty block {}", block_id);
        return Err(SynthesisError::Unsatisfiable);
    }

    let index = resolve_witness(allocation_store, op.index)?.clone();
    let value = resolve_witness(allocation_store, op.value)?.clone();

    let selectors = build_selectors(&mut cs.namespace(|| "selectors"), length, &index)?;

    match op.operation {
        MemOpKind::Read => {
            // For each cell, allocate t_i = s_i · cell_i and require Σ t_i = value.
            // Splitting like this keeps every R1CS constraint quadratic.
            let mut products = Vec::with_capacity(length);
            for (i, (s, cell)) in selectors.iter().zip(block.cells.iter()).enumerate() {
                let s_value = s.get_value();
                let cell_value = cell.get_value();
                let t_value = match (s_value, cell_value) {
                    (Some(b), Some(c)) => Some(if b { c } else { Scalar::ZERO }),
                    _ => None,
                };
                let t = AllocatedNum::alloc(cs.namespace(|| format!("read product {i}")), || {
                    t_value.ok_or(SynthesisError::AssignmentMissing)
                })?;
                cs.enforce(
                    || format!("read product {i} = s · cell"),
                    |lc| lc + s.get_variable(),
                    |lc| lc + cell.get_variable(),
                    |lc| lc + t.get_variable(),
                );
                products.push(t);
            }

            cs.enforce(
                || "read selects value",
                |lc| products.iter().fold(lc, |acc, t| acc + t.get_variable()),
                |lc| lc + CS::one(),
                |lc| lc + value.get_variable(),
            );
        }
        MemOpKind::Write => {
            // Slim write encoding: a single R1CS gate per cell.
            //
            //     (value - cell) · s = new_cell - cell
            //
            // - If s = 1: new_cell = value.
            // - If s = 0: new_cell = cell.
            //
            // Soundness: `AllocatedBit::alloc` already enforces s · (s - 1) = 0,
            // so `s` is constrained to {0, 1}. No selector-mirror auxiliary
            // wire and no `conditionally_select2` intermediate is needed —
            // we save 1 constraint + 1 aux witness per touched cell vs. the
            // previous encoding.
            let mut new_cells = Vec::with_capacity(length);
            for (i, (s, cell)) in selectors.iter().zip(block.cells.iter()).enumerate() {
                let new_cell_value = match (s.get_value(), cell.get_value(), value.get_value()) {
                    (Some(b), Some(c), Some(v)) => Some(if b { v } else { c }),
                    _ => None,
                };
                let new_cell =
                    AllocatedNum::alloc(cs.namespace(|| format!("write cell {i}")), || {
                        new_cell_value.ok_or(SynthesisError::AssignmentMissing)
                    })?;
                cs.enforce(
                    || format!("write cell {i} select"),
                    |lc| lc + value.get_variable() - cell.get_variable(),
                    |lc| lc + s.get_variable(),
                    |lc| lc + new_cell.get_variable() - cell.get_variable(),
                );
                new_cells.push(new_cell);
            }

            // Now mutate the block.
            let block_mut = store
                .blocks
                .get_mut(&block_id.0)
                .expect("block existence already checked");
            block_mut.cells = new_cells;
        }
    }

    Ok(())
}
