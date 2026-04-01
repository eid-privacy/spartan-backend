use crate::InputWireMapping;
use crate::noir::allocation_support::{
    AllocatedWire, WitnessMap, allocate_input, allocate_witness,
};
use crate::noir::blackbox::range::{field_into_allocated_bits_le, powers_of_two};
use crate::utils::hex_to_ff;
use acir::AcirField;
use acir::circuit::Opcode;
use acir::circuit::opcodes::BlackBoxFuncCall::RANGE;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use ff::Field;
use ff::derive::bitvec::macros::internal::funty::Fundamental;
use noirc_artifacts::program::ProgramArtifact;
use spartan2::provider::T256HyraxEngine;
use spartan2::traits::Engine;
use spartan2::traits::circuit::SpartanCircuit;

type Scalar = <T256HyraxEngine as Engine>::Scalar;

#[derive(Clone)]
pub struct NoirCircuitSynthesizer {
    program_artifact: ProgramArtifact,
    split_inputs: InputWireMapping<Scalar>,
}

impl NoirCircuitSynthesizer {
    pub(crate) fn new(
        program_artifact: ProgramArtifact,
        split_inputs: InputWireMapping<Option<Scalar>>,
    ) -> Self {
        Self {
            program_artifact,
            split_inputs: Self::default_inputs(split_inputs),
        }
    }

    // for some reason we cannot provide unassigned wires for the private inputs with Spartan2.
    // This defaults them to 0 to keep a clear interface with None
    fn default_inputs(inputs: InputWireMapping<Option<Scalar>>) -> InputWireMapping<Scalar> {
        inputs
            .into_iter()
            .map(|(visible, witness, value)| {
                (
                    visible,
                    witness,
                    if let Some(v) = value { v } else { Scalar::ZERO },
                )
            })
            .collect::<InputWireMapping<Scalar>>()
    }

    fn build_allocation_store<CS>(
        &self,
        cs: &mut CS,
    ) -> Result<WitnessMap<AllocatedWire<Scalar>>, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        let mut allocation_store = WitnessMap::<AllocatedWire<Scalar>>::new();

        // the loop absolutely needs to be order-stable to ensure the same circuit cannot produce
        // different prover/verifier keys across different executions.
        let mut sorted_witnesses: Vec<_> = self.split_inputs.iter().collect();
        sorted_witnesses.sort_by_key(|(_, witness, _)| witness.witness_index());
        for (visible, witness, value) in sorted_witnesses {
            let allocated = if *visible {
                allocate_input(
                    &mut cs.namespace(|| format!("allocate input {}", witness.witness_index())),
                    *witness,
                    *value,
                )
            } else {
                allocate_witness(
                    &mut cs.namespace(|| format!("allocate witness {}", witness.witness_index())),
                    *witness,
                    // this gymnastic is because I wish the API offered a way to assign None
                    // to witnesses when synthesizing the verifier side but Spartan2 does not allow
                    // for that
                    Some(*value),
                )
            }
            .map_err(|_| SynthesisError::AssignmentMissing)?;

            allocation_store.insert(witness.witness_index(), allocated);
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
            .filter(|(visible, _, _)| *visible)
            .collect();

        sorted_witnesses.sort_by_key(|(_, witness, _)| witness.witness_index());

        Ok(sorted_witnesses
            .into_iter()
            .map(|(_, _, value)| *value)
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

        // at this point we have the correct mapping from wire to allocated variable and can
        // compute the constraints from the opcodes.
        for (i, opcode) in self.program_artifact.bytecode.functions[0]
            .opcodes
            .iter()
            .enumerate()
        {
            match opcode {
                Opcode::AssertZero(expr) => {
                    // TODO: account for the multiplicands (mul_terms) in Plonk-ish constraints
                    let linear_combinations = &expr.linear_combinations;
                    let constant = expr.q_c;
                    tracing::debug!("AssertZero: {:?}", opcode);

                    let mut lin_comb = LinearCombination::<Scalar>::zero();
                    for (field_element, witness) in linear_combinations {
                        tracing::debug!("LC term: {:?} * {:?}", field_element, witness);
                        let allocated = allocation_store
                            .get(&witness.witness_index())
                            .ok_or_else(|| SynthesisError::AssignmentMissing)?;

                        let allocated_num = &allocated
                            .allocation
                            .as_ref()
                            .map_err(|_| SynthesisError::AssignmentMissing)?;

                        lin_comb = lin_comb
                            + (
                                // unfortunate translation from arkworks fields to halo2curves
                                hex_to_ff(field_element.to_hex().as_str()),
                                allocated_num.get_variable(),
                            );
                    }

                    // Include the constant term q_c: the full expression is sum(lc) + q_c = 0
                    let q_c: Scalar = hex_to_ff(constant.to_hex().as_str());
                    cs.enforce(
                        || format!("enforce AssertZero for opcode {}", i),
                        |lc| lc + &lin_comb + (q_c, CS::one()),
                        |lc| lc + CS::one(),
                        |lc| lc + &LinearCombination::<Scalar>::zero(),
                    )
                }
                Opcode::BlackBoxFuncCall(call) => {
                    match call {
                        RANGE { input, num_bits } => {
                            let witness_index = input.to_witness().witness_index();
                            let allocated_wire = allocation_store
                                .get(&witness_index)
                                .ok_or_else(|| SynthesisError::AssignmentMissing)?;

                            let allocated = allocated_wire
                                .allocation
                                .as_ref()
                                .map_err(|_| SynthesisError::AssignmentMissing)?;
                            let le_assigned_bits = field_into_allocated_bits_le(
                                cs,
                                allocated.get_value(),
                                num_bits.as_usize(),
                                witness_index,
                            )?;
                            let powers_of_two = powers_of_two(num_bits.as_usize());
                            let lin_comb = le_assigned_bits.iter().zip(powers_of_two).fold(
                                LinearCombination::<Scalar>::zero(),
                                |acc, (bit, power_of_two)| acc + (power_of_two, bit.get_variable()),
                            );

                            // truncated bit decomposition must equal variable
                            cs.enforce(
                                || format!("enforce lin_comb for opcode {}", i),
                                |lc| lc + &lin_comb,
                                |lc| lc + CS::one(),
                                |lc| lc + allocated.get_variable(),
                            )
                        }
                        _ => {
                            return Err(SynthesisError::Unsatisfiable); // waiting for a better error system
                        }
                    }
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
        Ok(())
    }
}
