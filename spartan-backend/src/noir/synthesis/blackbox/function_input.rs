// Helpers around FunctionInput<_> from Noir

use acir::{FieldElement, circuit::opcodes::FunctionInput, native_types::Witness};
use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};

use crate::{
    noir::{
        scalar_conversion::to_spartan_scalar,
        synthesis::{
            allocated_point::AllocatedPoint,
            allocation_support::{AllocatedWire, WitnessMap},
            constraints_utils::is_zero,
        },
    },
    types::Scalar,
};

/// The (x, y) coordinate pair of a curve point, as raw ACIR inputs.
///
/// ACIR hands `EmbeddedCurveAdd` an owned `Box<[FunctionInput; 2]>` and
/// `MultiScalarMul` a `Vec`; borrowing the pair as an array covers both
/// (`&Box<T>` deref-coerces to `&T`) without any heap allocation.
pub type WrappedPoint = [FunctionInput<FieldElement>; 2];

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

pub fn unwrap_point<CS: ConstraintSystem<Scalar>>(
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    cs: &mut CS,
    point: &WrappedPoint,
    label: &str,
) -> Result<AllocatedPoint<Scalar>, SynthesisError> {
    let x = allocate_or_get(
        allocation_store,
        &mut cs.namespace(|| format!("{label} x")),
        &point[0],
    )?;
    let y = allocate_or_get(
        allocation_store,
        &mut cs.namespace(|| format!("{label} y")),
        &point[1],
    )?;

    // ACIR encodes the point at infinity as (0, 0)
    let x_is_zero = is_zero(cs.namespace(|| format!("{label} x is zero")), &x)?;
    let y_is_zero = is_zero(cs.namespace(|| format!("{label} y is zero")), &y)?;

    let is_infinity = x_is_zero.mul(cs.namespace(|| format!("{label} is_infinity")), &y_is_zero)?;

    Ok(AllocatedPoint { x, y, is_infinity })
}
