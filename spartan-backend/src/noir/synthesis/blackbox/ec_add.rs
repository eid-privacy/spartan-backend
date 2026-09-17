use acir::native_types::Witness;
use bellpepper_core::{ConstraintSystem, SynthesisError};

use crate::{
    noir::synthesis::{
        allocation_support::{AllocatedWire, WitnessMap},
        blackbox::function_input::{WrappedPoint, get_witness_assignment, unwrap_point},
    },
    types::Scalar,
    utils::enforce_equal,
};

pub fn handle_ec_add<CS: ConstraintSystem<Scalar>>(
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    cs: &mut CS,
    p1: &WrappedPoint,
    p2: &WrappedPoint,
    outputs: &(Witness, Witness),
) -> Result<(), SynthesisError> {
    let p1_allocated = unwrap_point(allocation_store, &mut *cs, p1, "p1")?;
    let p2_allocated = unwrap_point(allocation_store, &mut *cs, p2, "p2")?;

    let sum = p1_allocated.add(&mut *cs, &p2_allocated)?;

    let expected_x = get_witness_assignment(allocation_store, &outputs.0)?;
    let expected_y = get_witness_assignment(allocation_store, &outputs.1)?;
    enforce_equal(cs.namespace(|| "ec add: x is correct"), &sum.x, &expected_x);
    enforce_equal(cs.namespace(|| "ec add: y is correct"), &sum.y, &expected_y);

    Ok(())
}
