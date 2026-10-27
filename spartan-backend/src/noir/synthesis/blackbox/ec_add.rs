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

#[cfg(test)]
mod tests {
    use acir::{AcirField, FieldElement, circuit::opcodes::FunctionInput};
    use bellpepper_core::{ConstraintSystem, test_cs::TestConstraintSystem};
    use ff::Field;

    use super::*;
    use crate::noir::synthesis::{
        allocation_support::{WitnessMap, allocate_witness},
        constant_point::ConstantPoint,
    };

    const P1_X_W: Witness = Witness(0);
    const OUTPUT_X_W: Witness = Witness(1);
    const OUTPUT_Y_W: Witness = Witness(2);

    fn synthesize_p_plus_infinity(
        x: Scalar,
        y: Scalar,
        y_input: FieldElement,
    ) -> TestConstraintSystem<Scalar> {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let mut allocations = WitnessMap::new(OUTPUT_Y_W.witness_index());
        for (witness, value) in [(P1_X_W, x), (OUTPUT_X_W, x), (OUTPUT_Y_W, y)] {
            allocations.insert(
                witness.witness_index(),
                allocate_witness(&mut cs, witness, Some(value)).unwrap(),
            );
        }

        let p = [
            FunctionInput::Witness(P1_X_W),
            FunctionInput::Constant(y_input),
        ];
        let infinity = [
            FunctionInput::Constant(FieldElement::from(0u128)),
            FunctionInput::Constant(FieldElement::from(0u128)),
        ];

        handle_ec_add(
            &allocations,
            &mut cs.namespace(|| "ec add"),
            &p,
            &infinity,
            &(OUTPUT_X_W, OUTPUT_Y_W),
        )
        .unwrap();
        cs
    }

    #[test]
    fn ec_add_accepts_valid_mixed_point_and_infinity() {
        let generator = ConstantPoint::<Scalar>::p256_generator();
        let generator_y = FieldElement::from_hex(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .unwrap();
        let cs = synthesize_p_plus_infinity(generator.x, generator.y, generator_y);
        assert!(
            cs.is_satisfied(),
            "valid P-256 point plus infinity must remain satisfiable: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn ec_add_rejects_off_curve_mixed_point() {
        let cs = synthesize_p_plus_infinity(Scalar::ONE, Scalar::ONE, FieldElement::from(1u128));
        assert!(
            !cs.is_satisfied(),
            "EC addition must reject an off-curve input point"
        );
    }
}
