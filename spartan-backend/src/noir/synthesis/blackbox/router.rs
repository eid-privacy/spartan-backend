use acir::circuit::opcodes::BlackBoxFuncCall;
use acir::circuit::opcodes::BlackBoxFuncCall::RANGE;
use acir::FieldElement;
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use ff::derive::bitvec::macros::internal::funty::Fundamental;
use crate::noir::synthesis::allocation_support::{AllocatedWire, WitnessMap};
use crate::noir::synthesis::blackbox::ec_add::handle_ec_add;
use crate::noir::synthesis::blackbox::range::{field_into_allocated_bits_le, powers_of_two};
use crate::types::Scalar;

pub struct BlackboxRouter<'a> {
    allocation_store: &'a WitnessMap<AllocatedWire<Scalar>>,
}

impl <'a> BlackboxRouter<'a> {
    pub fn new(
        allocation_store: &'a WitnessMap<AllocatedWire<Scalar>>,
    ) -> Self {
        BlackboxRouter {
            allocation_store,
        }
    }

    pub fn route<CS: ConstraintSystem<Scalar>>(
        &mut self,
        cs: &mut CS,
        call: &BlackBoxFuncCall<FieldElement>,
    ) -> Result<(), SynthesisError> {
        match call {
            RANGE { input, num_bits } => {
                let witness_index = input.to_witness().witness_index();
                let allocated_wire = self.allocation_store
                    .get(&witness_index)
                    .ok_or_else(|| SynthesisError::AssignmentMissing)?;

                let allocated = allocated_wire.allocation.as_ref()
                    .map_err(|_| SynthesisError::AssignmentMissing)?;
                let le_assigned_bits = field_into_allocated_bits_le(cs, allocated.get_value(), num_bits.as_usize(), witness_index)?;
                let powers_of_two = powers_of_two(num_bits.as_usize());
                let lin_comb = le_assigned_bits.iter().zip(powers_of_two)
                    .fold(
                        LinearCombination::<Scalar>::zero(),
                        |acc, (bit, power_of_two)| acc + (power_of_two, bit.get_variable())
                    );

                // truncated bit decomposition must equal variable
                cs.enforce(
                    || "RANGE lin. comb. equality",
                    |lc| lc + &lin_comb,
                    |lc| lc + CS::one(),
                    |lc| lc + allocated.get_variable()
                );

                Ok(())
            },
            BlackBoxFuncCall::EmbeddedCurveAdd {
                input1,
                input2,
                predicate: _,
                outputs
            } => {
                handle_ec_add(
                    self.allocation_store,
                    &mut cs.namespace(|| "EC ADD"),
                    input1,
                    input2,
                    outputs,
                )
            },
            _ => {
                tracing::error!("Unsupported blackbox function: {}", call);
                Err(SynthesisError::Unsatisfiable) // waiting for a better error system
            }
        }
    }
}