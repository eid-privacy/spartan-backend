// Helpers around FunctionInput<_> from Noir

use crate::noir::scalar_conversion::to_spartan_scalar;
use crate::noir::synthesis::allocation_support::{AllocatedWire, WitnessMap};
use crate::types::Scalar;
use acir::FieldElement;
use acir::circuit::opcodes::FunctionInput;
use acir::native_types::Witness;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};

pub fn allocate_or_get<CS: ConstraintSystem<Scalar>>(
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    cs: &mut CS,
    input: &FunctionInput<FieldElement>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    // Must handle the case when function inputs are not witnesses.
    // TODO: Constants won't be reused with this method -> might lead to later optimization
    match input {
        FunctionInput::Constant(constant) => {
            AllocatedNum::alloc(cs, || Ok(to_spartan_scalar(&constant)))
        }
        FunctionInput::Witness(witness) => get_witness_assignment(allocation_store, witness),
    }
}

pub fn get_witness_assignment(
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    input: &Witness,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    allocation_store
        .get(&input.witness_index())
        .ok_or(SynthesisError::AssignmentMissing)?
        .allocation
        .as_ref()
        .map(|n| n.clone())
        .map_err(|_| SynthesisError::AssignmentMissing)
}
