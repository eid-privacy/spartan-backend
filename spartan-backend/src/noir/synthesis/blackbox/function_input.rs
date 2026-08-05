// Helpers around FunctionInput<_> from Noir

use acir::{FieldElement, circuit::opcodes::FunctionInput, native_types::Witness};
use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};

use crate::{
    noir::{
        scalar_conversion::to_spartan_scalar,
        synthesis::allocation_support::{AllocatedWire, WitnessMap},
    },
    types::Scalar,
};

pub fn allocate_or_get<CS: ConstraintSystem<Scalar>>(
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    cs: &mut CS,
    input: &FunctionInput<FieldElement>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    // Must handle the case when function inputs are not witnesses.
    match input {
        // Constrain the allocated variable to equal the constant value; allocating
        // it unconstrained would let a malicious prover assign anything.
        FunctionInput::Constant(constant) => {
            crate::noir::synthesis::constraints_utils::alloc_constant(
                cs.namespace(|| "constant input"),
                to_spartan_scalar(constant),
            )
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
