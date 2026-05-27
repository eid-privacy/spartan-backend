use crate::noir::scalar_conversion::to_spartan_scalar;
use crate::noir::synthesis::allocated_point::AllocatedPoint;
use crate::noir::synthesis::allocation_support::{AllocatedWire, WitnessMap};
use crate::types::Scalar;
use crate::utils::enforce_equal;
use acir::FieldElement;
use acir::circuit::opcodes::FunctionInput;
use acir::native_types::Witness;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};

type WrappedPoint = Box<[FunctionInput<FieldElement>; 2]>;

pub fn handle_ec_add<CS: ConstraintSystem<Scalar>>(
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    cs: &mut CS,
    p1: &WrappedPoint,
    p2: &WrappedPoint,
    outputs: &(Witness, Witness),
) -> Result<(), SynthesisError> {
    let p1_allocated = unwrap_point(allocation_store, &mut *cs, p1)?;
    let p2_allocated = unwrap_point(allocation_store, &mut *cs, p2)?;

    let sum = p1_allocated.add(&mut *cs, &p2_allocated)?;

    // TODO: dedup with the local one in unwrap_point
    let get = |input: Witness| -> Result<AllocatedNum<Scalar>, SynthesisError> {
        allocation_store
            .get(&input.witness_index())
            .ok_or(SynthesisError::AssignmentMissing)?
            .allocation
            .as_ref()
            .map(|n| n.clone())
            .map_err(|_| SynthesisError::AssignmentMissing)
    };

    let expected_x = get(outputs.0)?;
    let expected_y = get(outputs.1)?;
    enforce_equal(cs.namespace(|| "ec add: x is correct"), &sum.x, &expected_x);
    enforce_equal(cs.namespace(|| "ec add: y is correct"), &sum.y, &expected_y);

    Ok(())
}

fn unwrap_point<CS: ConstraintSystem<Scalar>>(
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    cs: &mut CS,
    point: &WrappedPoint,
) -> Result<AllocatedPoint<Scalar>, SynthesisError> {
    Ok(AllocatedPoint {
        x: allocate_or_get(allocation_store, &mut *cs, &point[0])?,
        y: allocate_or_get(allocation_store, &mut *cs, &point[1])?,
        is_infinity: AllocatedNum::alloc(cs, || Ok(Scalar::zero()))?,
    })
}

fn allocate_or_get<CS: ConstraintSystem<Scalar>>(
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    cs: &mut CS,
    input: &FunctionInput<FieldElement>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let get_witness = |w: &Witness| -> Result<AllocatedNum<Scalar>, SynthesisError> {
        allocation_store
            .get(&w.witness_index())
            .ok_or(SynthesisError::AssignmentMissing)?
            .allocation
            .as_ref()
            .map(|n| n.clone())
            .map_err(|_| SynthesisError::AssignmentMissing)
    };

    // Must handle the case when function inputs are not witnesses.
    // TODO: Constants won't be reused with this method -> might lead to later optimization
    match input {
        FunctionInput::Constant(constant) => {
            AllocatedNum::alloc(cs, || Ok(to_spartan_scalar(&constant)))
        }
        FunctionInput::Witness(witness) => get_witness(witness),
    }
}

