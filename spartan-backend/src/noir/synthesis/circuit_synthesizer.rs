use std::collections::HashMap;
use acir::circuit::{Opcode};
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use bellpepper_core::num::AllocatedNum;
use ff::Field;
use noirc_artifacts::program::ProgramArtifact;
use spartan2::provider::T256HyraxEngine;
use spartan2::traits::circuit::SpartanCircuit;
use crate::noir::circuit_reader::read_witnesses;
use crate::noir::circuit_reader::types::input_wire::InputWire;
use crate::noir::scalar_conversion::to_spartan_scalar;
use crate::noir::synthesis::allocation_support::{allocate_input, allocate_witness, AllocatedWire, WitnessMap};
use crate::noir::synthesis::assert_zero::handle_assert_zero;
use crate::noir::synthesis::blackbox::router::BlackboxRouter;
use crate::types::Scalar;

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
        inputs.into_iter().map(|wire|
            wire.clone_with_value(
                if let Some(v) = wire.value { v } else { Scalar::ZERO }
            )
        ).collect::<Vec<InputWire<Scalar>>>()
    }

    fn build_allocation_store<CS>(
        &self,
        cs: &mut CS,
    ) -> Result<WitnessMap<AllocatedWire<Scalar>>, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        let mut allocation_store = WitnessMap::new();

        let mut all_the_witnesses_we_like = read_witnesses(&self.program_artifact);
        all_the_witnesses_we_like.sort_by_key(|w| w.witness_index());

        let indexed_inputs: HashMap<u32, InputWire<Scalar>> = self
            .split_inputs
            .iter()
            .map(|wire| (wire.witness.witness_index(), *wire))
            .collect();

        for witness in all_the_witnesses_we_like {
            let wire = indexed_inputs
                .get(&witness.witness_index())
                .copied()
                .unwrap_or(InputWire { public: false, witness, value: Scalar::ZERO});

            let allocated = if wire.public {
                allocate_input(
                    &mut cs.namespace(|| format!("allocate input {}", wire.witness.witness_index())),
                    wire.witness,
                    wire.value,
                )
            } else {
                allocate_witness(
                    &mut cs.namespace(|| format!("allocate witness {}", wire.witness.witness_index())),
                    wire.witness,
                    // this gymnastic is because I wish the API offered a way to assign None
                    // to witnesses when synthesizing the verifier side but Spartan2 does not allow
                    // for that
                    Some(wire.value),
                )
            }.map_err(|_| SynthesisError::AssignmentMissing)?;

            allocation_store.insert(wire.witness.witness_index(), allocated);
        }

        Ok(allocation_store)
    }
}

impl SpartanCircuit<T256HyraxEngine> for NoirCircuitSynthesizer {
    // This is used by Spartan when building the transcript. We need the values at that point.
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut sorted_witnesses: Vec<_> = self.split_inputs.iter()
            .filter(|wire| wire.public)
            .collect();

        sorted_witnesses.sort_by_key(|wire| wire.witness.witness_index());

        Ok(
            sorted_witnesses.into_iter()
                .map(|wire| wire.value)
                .collect()
        )
    }

    // Doc from library: Allocated variables in the circuit that are shared with other circuits
    // Sha256 example does not have any of this
    fn shared<CS: ConstraintSystem<Scalar>>(&self, _: &mut CS) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
         Ok(vec![])
    }

    // This is the place where everything is available and assignments are supposed to happen
    // -> the old "synthesize" should be here (see Sha256 example again).
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self, cs: &mut CS,
        _: &[AllocatedNum<Scalar>]
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let allocation_store = self.build_allocation_store(
            cs,
        )?;
        log::debug!("Allocation map: {:?}", allocation_store);
        let mut blackbox_router = BlackboxRouter::new(&allocation_store);

        // at this point we have the correct mapping from wire to allocated variable and can
        // compute the constraints from the opcodes.
        for (i, opcode) in self.program_artifact.bytecode.functions[0].opcodes.iter().enumerate() {
            match opcode {
                Opcode::AssertZero(expr) => {
                    log::debug!("Handling AssertZero: {:?}", opcode);
                    handle_assert_zero(
                        cs,
                        &allocation_store,
                        expr,
                        format!("enforce AssertZero for opcode {}", i).as_str(),
                    )?;
                },
                Opcode::BlackBoxFuncCall(call) => {
                    log::debug!("Handling BLACKBOX call {}", call);
                    blackbox_router.route(
                        cs,
                        call,
                        format!("enforce blackbox opcode {}", i).as_str(),
                    )?;
                },
                Opcode::BrilligCall { .. } => {
                    log::debug!("Skipping Brillig call {:?}.", opcode);
                },
                _ => {
                    return Err(SynthesisError::Unsatisfiable) // waiting for a better error system
                }
            }
        }

        Ok(vec![])
    }

    fn num_challenges(&self) -> usize { 0 }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>, // challenges from the verifier
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}