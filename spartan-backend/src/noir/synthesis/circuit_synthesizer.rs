use crate::noir::circuit_reader::read_witnesses;
use crate::noir::circuit_reader::types::input_wire::InputWire;
use crate::noir::synthesis::allocation_support::{
    AllocatedWire, WitnessMap, allocate_input, allocate_witness,
};
use crate::noir::synthesis::assert_zero::handle_assert_zero;
use crate::noir::synthesis::blackbox::router::BlackboxRouter;
use crate::types::Scalar;
use acir::circuit::Opcode;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::Field;
use noirc_artifacts::program::ProgramArtifact;
use spartan2::provider::T256HyraxEngine;
use spartan2::traits::circuit::SpartanCircuit;

#[derive(Clone)]
pub struct NoirCircuitSynthesizer {
    program_artifact: ProgramArtifact,
    split_inputs: Vec<InputWire<Scalar>>,
}

impl NoirCircuitSynthesizer {
    pub(crate) fn new(
        program_artifact: ProgramArtifact,
        split_inputs: Vec<InputWire<Option<Scalar>>>,
    ) -> Self {
        Self {
            program_artifact,
            split_inputs: Self::default_inputs(split_inputs),
        }
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

    fn build_allocation_store<CS>(
        &self,
        cs: &mut CS,
    ) -> Result<WitnessMap<AllocatedWire<Scalar>>, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        let mut all_the_witnesses_we_like = read_witnesses(&self.program_artifact);
        all_the_witnesses_we_like.sort_by_key(|w| w.witness_index());

        let max_index = all_the_witnesses_we_like
            .last()
            .map_or(0, |w| w.witness_index());

        let mut allocation_store = WitnessMap::new(max_index);

        let mut indexed_inputs: Vec<Option<InputWire<Scalar>>> = vec![None; max_index as usize + 1];
        for wire in &self.split_inputs {
            indexed_inputs[wire.witness.witness_index() as usize] = Some(*wire);
        }

        for witness in all_the_witnesses_we_like {
            let wire = indexed_inputs[witness.witness_index() as usize]
                .unwrap_or(InputWire {
                    public: false,
                    witness,
                    value: Scalar::ZERO,
                });

            let allocated = if wire.public {
                allocate_input(
                    &mut cs
                        .namespace(|| format!("allocate input {}", wire.witness.witness_index())),
                    wire.witness,
                    wire.value,
                )
            } else {
                allocate_witness(
                    &mut cs
                        .namespace(|| format!("allocate witness {}", wire.witness.witness_index())),
                    wire.witness,
                    // this gymnastic is because I wish the API offered a way to assign None
                    // to witnesses when synthesizing the verifier side but Spartan2 does not allow
                    // for that
                    Some(wire.value),
                )
            }
            .map_err(|_| SynthesisError::AssignmentMissing)?;

            allocation_store.insert(wire.witness.witness_index(), allocated);
        }

        Ok(allocation_store)
    }
}

impl SpartanCircuit<T256HyraxEngine> for NoirCircuitSynthesizer {
    // This is used by Spartan when building the transcript. We need the values at that point.
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

    // Doc from library: Allocated variables in the circuit that are shared with other circuits
    // Sha256 example does not have any of this
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    // This is the place where everything is available and assignments are supposed to happen
    // -> the old "synthesize" should be here (see Sha256 example again).
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let allocation_store = self.build_allocation_store(cs)?;
        tracing::debug!("Allocation map: {:?}", allocation_store);
        let mut blackbox_router = BlackboxRouter::new(&allocation_store);

        // at this point we have the correct mapping from wire to allocated variable and can
        // compute the constraints from the opcodes.
        for (i, opcode) in self.program_artifact.bytecode.functions[0]
            .opcodes
            .iter()
            .enumerate()
        {
            tracing::debug!("Processing opcode {}", opcode);
            match opcode {
                Opcode::AssertZero(expr) => {
                    tracing::debug!("Handling AssertZero: {:?}", opcode);
                    handle_assert_zero(
                        &mut cs.namespace(|| format!("assert_zero_{}", i)),
                        &allocation_store,
                        expr,
                    )?;
                }
                Opcode::BlackBoxFuncCall(call) => {
                    tracing::debug!("Handling BLACKBOX call {}", call);
                    blackbox_router.route(
                        &mut cs.namespace(|| format!("enforce blackbox opcode {}", i)),
                        call,
                    )?;
                }
                Opcode::BrilligCall { .. } => {
                    tracing::debug!("Skipping Brillig call {:?}.", opcode);
                }
                _ => {
                    return Err(SynthesisError::Unsatisfiable); // waiting for a better error system
                }
            }
        }

        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>, // challenges from the verifier
    ) -> Result<(), SynthesisError> {
        tracing::debug!("Call to synthesize");
        Ok(())
    }
}
