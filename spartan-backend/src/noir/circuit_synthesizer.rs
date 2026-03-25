use std::collections::HashMap;
use acir::AcirField;
use acir::circuit::Opcode;
use acir::circuit::opcodes::BlackBoxFuncCall::RANGE;
use acir::native_types::Witness;
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use bellpepper_core::num::AllocatedNum;
use ff::derive::bitvec::macros::internal::funty::Fundamental;
use ff::Field;
use noirc_artifacts::program::ProgramArtifact;
use spartan2::provider::T256HyraxEngine;
use spartan2::traits::circuit::SpartanCircuit;
use spartan2::traits::{Engine};
use crate::noir::allocation_support::{allocate_input, allocate_witness, AllocatedWire, FunctionParameter, WitnessMap};
use crate::noir::blackbox::range::{field_into_allocated_bits_le, powers_of_two};
use crate::utils::hex_to_ff;

type Scalar = <T256HyraxEngine as Engine>::Scalar;

#[derive(Clone)]
pub struct NoirCircuitSynthesizer {
    program_artifact: ProgramArtifact,
    inputs: HashMap<String, Option<Scalar>>,
    witness_map: WitnessMap<FunctionParameter<Scalar>>,
}

impl NoirCircuitSynthesizer {
    pub(crate) fn new(
        program_artifact: ProgramArtifact,
        inputs: HashMap<String, Option<Scalar>>,
    ) -> Self {
        Self {
            witness_map: Self::build_witness_map(&program_artifact, &inputs),
            program_artifact,
            inputs: Self::default_inputs(inputs),
        }
    }

    // for some reason we cannot provide unassigned wires for the private inputs with Spartan2.
    // This defaults them to 0 to keep a clear interface with None
    fn default_inputs(inputs: HashMap<String, Option<Scalar>>) -> HashMap<String, Option<Scalar>> {
        inputs.into_iter().map(|(k, v)|
            (k, if let None = v { Some(Scalar::ZERO) } else { v })
        ).collect::<HashMap<String, Option<Scalar>>>()
    }

    fn build_witness_map(
        program_artifact: &ProgramArtifact,
        inputs: &HashMap<String, Option<Scalar>>,
    ) -> WitnessMap<FunctionParameter<Scalar>> {
        let parameters: HashMap<_, _> = program_artifact.abi.parameters.iter().enumerate()
            .map(|(i, param)| {
                (i as u32, param)
            })
            .collect();

        // assuming a single function for now
        let function = program_artifact.bytecode.functions
            .first()
            .expect("No functions in bytecode");

        let function_param = |p: &Witness, public: bool| -> FunctionParameter<Scalar> {
            let idx = p.witness_index();
            let name = parameters[&idx].name.clone();
            let value = inputs.get(&name).expect("Missing input");
            FunctionParameter::<Scalar>::new(idx, *p, name, public, *value)
        };

        // for now, assume order of parameters matches order of witnesses
        let mut witness_map: WitnessMap<FunctionParameter<Scalar>> = WitnessMap::new();
        for p in function.public_parameters.0.iter() {
            witness_map.insert(p.witness_index(), function_param(p, true));
        }
        for p in function.private_parameters.iter() {
            witness_map.insert(p.witness_index(), function_param(p, false));
        }

        witness_map
    }

    fn build_allocation_store<CS>(
        &self,
        cs: &mut CS,
        witness_map: &WitnessMap<FunctionParameter<Scalar>>,
    ) -> Result<WitnessMap<AllocatedWire<Scalar>>, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        let mut allocation_store = WitnessMap::<AllocatedWire<Scalar>>::new();

        // this loops absolutely needs to be order-stable to ensure the same circuit cannot produce
        // different prover/verifier keys across different executions.
        let mut params: Vec<&FunctionParameter<Scalar>> = witness_map.values().collect();
        params.sort_by_key(|p| p.index);
        for param in params {
            let value = self
                .inputs
                .get(&param.name)
                .ok_or_else(|| SynthesisError::AssignmentMissing)? // first unwrap -> parameter might be missing
                .ok_or_else(|| SynthesisError::AssignmentMissing)?; // second unwrap -> parameter might not have been assigned a value

            let allocated = if param.public {
                let public_value = value;
                allocate_input(
                    &mut cs.namespace(|| format!("allocate input {}", param.name)),
                    param.witness,
                    public_value,
                )
            } else {
                allocate_witness(
                    &mut cs.namespace(|| format!("allocate witness {}", param.name)),
                    param.witness,
                    // this gymnastic is because I wish the API offered a way to assign None
                    // to witnesses when synthesizing the verifier side but Spartan2 does not allow
                    // for that
                    Some(value),
                )
            }.map_err(|_| SynthesisError::AssignmentMissing)?;

            allocation_store.insert(param.witness.witness_index(), allocated);
        }

        Ok(allocation_store)
    }
}

impl SpartanCircuit<T256HyraxEngine> for NoirCircuitSynthesizer {
    // This is used by Spartan when building the transcript. We need the values at that point.
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut public_inputs: Vec<&FunctionParameter<Scalar>> = self
            .witness_map
            .values()
            .filter(|input| input.public)
            .collect();
        public_inputs.sort_by_key(|input| input.index);

        public_inputs
            .into_iter()
            .map(|input| {
                input
                    .value
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
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
            &self.witness_map,
        )?;
        log::debug!("Allocation map: {:?}", allocation_store);

        // at this point we have the correct mapping from wire to allocated variable and can
        // compute the constraints from the opcodes.
        for (i, opcode) in self.program_artifact.bytecode.functions[0].opcodes.iter().enumerate() {
            match opcode {
                Opcode::AssertZero(expr) => {
                    // TODO: account for the multiplicands and the constant in Plonk-ish constraints
                    // let multiplicands = &expr.mul_terms;
                    let linear_combinations = &expr.linear_combinations;
                    // let constant = expr.q_c;
                    log::debug!("AssertZero: {:?}", opcode);

                    let mut lin_comb = LinearCombination::<Scalar>::zero();
                    for (field_element, witness) in linear_combinations {
                        log::debug!("LC term: {:?} * {:?}", field_element, witness);
                        let allocated = allocation_store
                            .get(&witness.witness_index())
                            .ok_or_else(|| SynthesisError::AssignmentMissing)?;

                        let allocated_num = &allocated.allocation.as_ref()
                            .map_err(|_| SynthesisError::AssignmentMissing)?;

                        lin_comb = lin_comb
                            + (
                                // unfortunate translation from arkworks fields to halo2curves
                                hex_to_ff(field_element.to_hex().as_str()),
                                // TODO: manage unallocated witnesses later (if it becomes relevant)
                                allocated_num.get_variable(),
                            );
                    }

                    cs.enforce(
                        || format!("enforce AssertZero for opcode {}", i),
                        |lc| lc + &lin_comb,
                        |lc| lc + CS::one(),
                        |lc| lc + &LinearCombination::<Scalar>::zero(),
                    )
                },
                Opcode::BlackBoxFuncCall(call) => {
                    match call {
                        RANGE { input, num_bits } => {
                            let witness_index = input.to_witness().witness_index();
                            let allocated_wire = allocation_store
                                .get(&witness_index)
                                .ok_or_else(|| SynthesisError::AssignmentMissing)?;

                            let allocated = allocated_wire.allocation.as_ref()
                                .map_err(|_| SynthesisError::AssignmentMissing)?;
                            let le_assigned_bits = field_into_allocated_bits_le(cs, allocated.get_value(), num_bits.as_usize(), witness_index)?;
                            let powers_of_two = powers_of_two(num_bits.as_usize());
                            let lin_comb = le_assigned_bits.iter().zip(powers_of_two)
                                .fold(
                                    LinearCombination::<Scalar>::zero(),
                                    |acc, (bit, power_of_two)| acc + (power_of_two , bit.get_variable())
                                );

                            // truncated bit decomposition must equal variable
                            cs.enforce(
                                || format!("enforce lin_comb for opcode {}", i),
                                |lc| lc + &lin_comb,
                                |lc| lc + CS::one(),
                                |lc| lc + allocated.get_variable()
                            )
                        },
                        _ => {
                            return Err(SynthesisError::Unsatisfiable) // waiting for a better error system
                        }
                    }
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