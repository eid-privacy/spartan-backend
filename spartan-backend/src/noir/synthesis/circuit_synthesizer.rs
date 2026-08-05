use std::collections::HashSet;

use acir::{circuit::Opcode, native_types::Witness};
use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use ff::Field;
use noirc_artifacts::program::ProgramArtifact;
use vega_prover::{provider::T256HyraxEngine, traits::circuit::VegaCircuit};

use crate::{
    noir::{
        circuit_reader::{read_witnesses, types::input_wire::InputWire},
        online::partition::Partition,
        synthesis::{
            allocation_support::{AllocatedWire, WitnessMap, allocate_input, allocate_witness},
            assert_zero::handle_assert_zero,
            blackbox::router::BlackboxRouter,
            memory::{MemoryStore, handle_memory_init, handle_memory_op},
        },
    },
    types::Scalar,
};

#[derive(Clone)]
pub struct NoirCircuitSynthesizer {
    program_artifact: ProgramArtifact,
    split_inputs: Vec<InputWire<Scalar>>,
    partition: Partition,
}

impl NoirCircuitSynthesizer {
    /// `online_seeds` are the witness
    /// indices of the ABI parameters that change between proofs;
    /// everything not reachable from them becomes Vega's `precommitted` segment.
    ///
    /// An empty seed set falls back to the trivial all-online partition.
    pub fn new(
        program_artifact: ProgramArtifact,
        split_inputs: Vec<InputWire<Option<Scalar>>>,
        online_seeds: &HashSet<u32>,
    ) -> Self {
        let split_inputs = Self::default_inputs(split_inputs);

        let circuit = program_artifact
            .bytecode
            .functions
            .first()
            .expect("program must have at least one function");

        let public_witnesses: HashSet<u32> = split_inputs
            .iter()
            .filter(|w| w.public)
            .map(|w| w.witness.witness_index())
            .collect();

        let partition = if online_seeds.is_empty() {
            Partition::all_rest(circuit, &public_witnesses)
        } else {
            Partition::compute(circuit, online_seeds, &public_witnesses)
                .expect("circuit partition failed (check the online manifest)")
        };

        Self {
            program_artifact,
            split_inputs,
            partition,
        }
    }

    /// Read-only access to the computed partition (used by CLI reporting/tests).
    pub fn partition(&self) -> &Partition {
        &self.partition
    }

    // for some reason we cannot provide unassigned wires for the private inputs with Spartan2.
    // This defaults them to 0 to keep a clear interface with None
    fn default_inputs(inputs: Vec<InputWire<Option<Scalar>>>) -> Vec<InputWire<Scalar>> {
        inputs
            .into_iter()
            .map(|wire| {
                wire.clone_with_value(if let Some(v) = wire.value {
                    v
                } else {
                    Scalar::ZERO
                })
            })
            .collect::<Vec<InputWire<Scalar>>>()
    }

    /// Index `split_inputs` by witness index for O(1) value lookup.
    fn indexed_inputs(&self) -> Vec<Option<InputWire<Scalar>>> {
        let mut indexed: Vec<Option<InputWire<Scalar>>> =
            vec![None; self.partition.max_witness_index as usize + 1];
        for wire in &self.split_inputs {
            let idx = wire.witness.witness_index() as usize;
            if idx < indexed.len() {
                indexed[idx] = Some(*wire);
            }
        }
        indexed
    }

    /// Value assigned to a witness (from the solved witness map), defaulting to
    /// zero for witnesses without an explicit assignment.
    fn value_of(indexed: &[Option<InputWire<Scalar>>], idx: u32) -> Scalar {
        indexed
            .get(idx as usize)
            .and_then(|w| w.map(|w| w.value))
            .unwrap_or(Scalar::ZERO)
    }

    /// Allocate the given witnesses as committed (aux) variables into a fresh
    /// store sized for the whole circuit.
    fn allocate_committed<CS>(
        &self,
        cs: &mut CS,
        witnesses: &[u32],
        indexed: &[Option<InputWire<Scalar>>],
    ) -> Result<WitnessMap<AllocatedWire<Scalar>>, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        let mut store = WitnessMap::new(self.partition.max_witness_index);
        for &idx in witnesses {
            let allocated = allocate_witness(
                &mut cs.namespace(|| format!("allocate witness {idx}")),
                Witness(idx),
                Some(Self::value_of(indexed, idx)),
            )
            .map_err(|_| SynthesisError::AssignmentMissing)?;
            store.insert(idx, allocated);
        }
        Ok(store)
    }

    /// Process the opcodes belonging to one segment (invariant when
    /// `want_invariant` is true, otherwise the online/rest segment) against an
    /// allocation store that already contains every witness they reference.
    fn process_segment<CS>(
        &self,
        cs: &mut CS,
        store: &WitnessMap<AllocatedWire<Scalar>>,
        want_invariant: bool,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        let mut blackbox_router = BlackboxRouter::new(store);
        let mut memory_store = MemoryStore::new();

        for (i, opcode) in self.program_artifact.bytecode.functions[0]
            .opcodes
            .iter()
            .enumerate()
        {
            if self.partition.opcode_is_invariant[i] != want_invariant {
                continue;
            }
            match opcode {
                Opcode::AssertZero(expr) => {
                    handle_assert_zero(
                        &mut cs.namespace(|| format!("assert_zero_{i}")),
                        store,
                        expr,
                    )?;
                }
                Opcode::BlackBoxFuncCall(call) => {
                    blackbox_router.route(
                        &mut cs.namespace(|| format!("enforce blackbox opcode {i}")),
                        call,
                    )?;
                }
                Opcode::MemoryInit {
                    block_id,
                    init,
                    block_type,
                } => {
                    handle_memory_init(&mut memory_store, store, *block_id, init, block_type)?;
                }
                Opcode::MemoryOp { block_id, op, .. } => {
                    handle_memory_op(
                        &mut cs.namespace(|| format!("memory op {i}")),
                        &mut memory_store,
                        store,
                        *block_id,
                        op,
                    )?;
                }
                Opcode::BrilligCall { .. } => {
                    tracing::debug!("Skipping Brillig call at opcode {i}");
                }
                Opcode::Call { .. } => {
                    tracing::error!("Unsupported opcode Call at index {i}: {:?}", opcode);
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
        }
        Ok(())
    }
}

impl VegaCircuit<T256HyraxEngine> for NoirCircuitSynthesizer {
    // This is used by Vega when building the transcript. We need the values at that point.
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut sorted_witnesses: Vec<_> = self
            .split_inputs
            .iter()
            .filter(|wire| wire.public)
            .collect();

        sorted_witnesses.sort_by_key(|wire| wire.witness.witness_index());

        Ok(sorted_witnesses
            .into_iter()
            .map(|wire| wire.value)
            .collect())
    }

    // Doc from library: Allocated variables in the circuit that are shared with other circuits.
    // Single-circuit use has no cross-instance sharing.
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    // Precommitted variables are committed before the verifier's challenge and,
    // crucially, reused across proofs via Vega's `prep_snark`.
    // we allocate every invariant witness, enforce every invariant opcode, and return the
    // cut set (invariant witnesses read by the online segment, plus committed
    // copies of the invariant public inputs) so it can cross into `synthesize`.
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let indexed = self.indexed_inputs();
        let store = self.allocate_committed(cs, &self.partition.invariant_witnesses, &indexed)?;

        self.process_segment(cs, &store, true)?;

        // Return the cut set in the canonical sorted order so `synthesize` can
        // re-associate the crossing AllocatedNums with their witness indices.
        let mut cut = Vec::with_capacity(self.partition.cut_set.len());
        for &idx in &self.partition.cut_set {
            let wire = store.get(&idx).ok_or(SynthesisError::AssignmentMissing)?;
            let allocation = wire
                .allocation
                .as_ref()
                .map_err(|_| SynthesisError::AssignmentMissing)?;
            cut.push(allocation.clone());
        }
        Ok(cut)
    }

    fn num_challenges(&self) -> usize {
        0
    }

    // Vega re-runs `synthesize` at prove time (after truncating the constraint
    // system back to the shared+precommitted prefix) and reads the public IO
    // from it. So the online (rest) segment is built here: re-associate the
    // crossing cut-set wires, allocate the online witnesses, `inputize` *all*
    // public inputs in witness-index order (matching `public_values`), and
    // enforce the online opcodes.
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        precommitted: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>, // challenges from the verifier (unused: num_challenges == 0)
    ) -> Result<(), SynthesisError> {
        if precommitted.len() != self.partition.cut_set.len() {
            tracing::error!(
                "precommitted cut-set size mismatch: got {}, expected {}",
                precommitted.len(),
                self.partition.cut_set.len()
            );
            return Err(SynthesisError::Unsatisfiable);
        }

        let indexed = self.indexed_inputs();
        let mut store = WitnessMap::new(self.partition.max_witness_index);

        // 1. Re-associate the crossing cut-set AllocatedNums with their witness
        //    indices (same sorted order as `precommitted` produced).
        for (&idx, allocation) in self.partition.cut_set.iter().zip(precommitted.iter()) {
            store.insert(
                idx,
                AllocatedWire {
                    witness: Witness(idx),
                    allocation: Ok(allocation.clone()),
                },
            );
        }

        // 2. Allocate every online (rest) witness as a committed variable.
        for &idx in &self.partition.rest_witnesses {
            let allocated = allocate_witness(
                &mut cs.namespace(|| format!("allocate witness {idx}")),
                Witness(idx),
                Some(Self::value_of(&indexed, idx)),
            )
            .map_err(|_| SynthesisError::AssignmentMissing)?;
            store.insert(idx, allocated);
        }

        // 3. Inputize all public inputs in witness-index order. Online publics
        //    inputize their own online witness; invariant publics inputize the
        //    crossing committed copy (which adds the linking equality for free).
        for &idx in &self.partition.public_witnesses {
            let wire = store.get(&idx).ok_or(SynthesisError::AssignmentMissing)?;
            let allocation = wire
                .allocation
                .as_ref()
                .map_err(|_| SynthesisError::AssignmentMissing)?;
            allocation.inputize(&mut cs.namespace(|| format!("inputize public {idx}")))?;
        }

        // 4. Enforce the online (rest) opcodes.
        self.process_segment(cs, &store, false)?;

        Ok(())
    }
}
