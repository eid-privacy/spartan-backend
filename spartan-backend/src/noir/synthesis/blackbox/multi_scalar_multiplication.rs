use crate::noir::synthesis::allocated_point::AllocatedPoint;
use crate::noir::synthesis::allocation_support::{AllocatedWire, WitnessMap};
use crate::noir::synthesis::blackbox::function_input::{allocate_or_get, get_witness_assignment};
use crate::types::Scalar;
use crate::utils::enforce_equal;
use acir::FieldElement;
use acir::circuit::opcodes::FunctionInput;
use acir::native_types::Witness;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};

pub fn handle_msm<CS: ConstraintSystem<Scalar>>(
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    cs: &mut CS,
    points: &[FunctionInput<FieldElement>],
    scalars: &[FunctionInput<FieldElement>],
    outputs: &(Witness, Witness),
) -> Result<(), SynthesisError> {
    assert_eq!(
        2,
        points.len(),
        "Only single point multiplication is supported"
    );
    assert_eq!(
        2,
        scalars.len(),
        "Only single point multiplication is supported"
    );

    let point = AllocatedPoint {
        x: allocate_or_get(allocation_store, &mut *cs, &points[0])?,
        y: allocate_or_get(allocation_store, &mut *cs, &points[1])?,
        is_infinity: AllocatedNum::alloc(cs.namespace(|| "point is_infinity"), || Ok(Scalar::zero()))?,
    };

    let scalar = allocate_or_get(
        allocation_store,
        &mut *cs,
        // low part of the scalar. We don't need the high part for T-256-P-256 since the field
        // sizes play nicely to our advantage. No recomposition needed.
        &scalars[0],
    )?;

    let result = point.scalar_mul(&mut *cs, &scalar)?;

    enforce_equal(
        cs.namespace(|| "MSM x is correct"),
        &result.x,
        &get_witness_assignment(allocation_store, &outputs.0)?,
    );
    enforce_equal(
        cs.namespace(|| "MSM y is correct"),
        &result.y,
        &get_witness_assignment(allocation_store, &outputs.1)?,
    );

    Ok(())
}


