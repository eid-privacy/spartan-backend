use acir::{FieldElement, circuit::opcodes::FunctionInput, native_types::Witness};
use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::Field;

use crate::{
    noir::{
        scalar_conversion::to_spartan_scalar,
        synthesis::{
            allocated_point::AllocatedPoint,
            allocation_support::{AllocatedWire, WitnessMap},
            blackbox::function_input::{allocate_or_get, get_witness_assignment, unwrap_point},
            constant_point::ConstantPoint,
        },
    },
    types::Scalar,
    utils::enforce_equal,
};

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

    // The high limb of the scalar is ignored (T-256/P-256 field sizes make
    // recomposition unnecessary), but it must be constrained to zero so a prover
    // cannot smuggle a value through it.
    match &scalars[1] {
        FunctionInput::Constant(c) => {
            if to_spartan_scalar::<Scalar>(c) != Scalar::ZERO {
                tracing::error!("MSM with a non-zero constant high scalar limb is unsupported");
                return Err(SynthesisError::Unsatisfiable);
            }
        }
        FunctionInput::Witness(w) => {
            let hi = get_witness_assignment(allocation_store, w)?;
            cs.enforce(
                || "MSM high scalar limb is zero",
                |lc| lc + hi.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc,
            );
        }
    }

    // Fixed-base fast path: the base point is a circuit constant and the scalar
    // is a witness, so every 2^i*base is known at synthesis time and the ~254
    // in-circuit doublings of the variable-base ladder can be dropped.
    if let (FunctionInput::Constant(px), FunctionInput::Constant(py), FunctionInput::Witness(sw)) =
        (&points[0], &points[1], &scalars[0])
    {
        let base = ConstantPoint::new(to_spartan_scalar(px), to_spartan_scalar(py));
        // y == 0 covers the (0, 0) infinity encoding and order-2 points, whose
        // native doubling chain is undefined; fall through to the generic path.
        if base.y != Scalar::ZERO {
            let scalar = get_witness_assignment(allocation_store, sw)?;
            let result = AllocatedPoint::scalar_mul_fixed_base(
                cs.namespace(|| "fixed-base scalar mul"),
                &base,
                &scalar,
            )?;
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
            return Ok(());
        }
    }

    let point = unwrap_point(
        allocation_store,
        &mut *cs,
        points.first_chunk().ok_or(SynthesisError::Unsatisfiable)?,
        "MSM point",
    )?;

    let scalar = allocate_or_get(
        allocation_store,
        &mut cs.namespace(|| "scalar lo"),
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashSet};

    use acir::circuit::{Circuit, Opcode, Program, PublicInputs, opcodes::BlackBoxFuncCall};
    use bellpepper_core::{ConstraintSystem, num::AllocatedNum, test_cs::TestConstraintSystem};
    use noirc_abi::Abi;
    use noirc_artifacts::{debug::ProgramDebugInfo, program::ProgramArtifact};
    use vega_prover::traits::circuit::VegaCircuit;

    use super::*;
    use crate::noir::{
        circuit_reader::types::input_wire::InputWire,
        synthesis::circuit_synthesizer::NoirCircuitSynthesizer,
    };

    const BASE_X_W: Witness = Witness(0);
    const BASE_Y_W: Witness = Witness(1);
    const SCALAR_W: Witness = Witness(2);
    const OUTPUT_X_W: Witness = Witness(3);
    const OUTPUT_Y_W: Witness = Witness(4);

    /// Variable-base MSM over witness coordinates, forcing the generic path.
    fn artifact() -> ProgramArtifact {
        let circuit = Circuit {
            function_name: "msm_on_infinity".to_owned(),
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul {
                points: vec![
                    FunctionInput::Witness(BASE_X_W),
                    FunctionInput::Witness(BASE_Y_W),
                ],
                scalars: vec![
                    FunctionInput::Witness(SCALAR_W),
                    FunctionInput::Constant(FieldElement::from(0u128)),
                ],
                predicate: FunctionInput::Constant(FieldElement::from(1u128)),
                outputs: (OUTPUT_X_W, OUTPUT_Y_W),
            })],
            private_parameters: BTreeSet::new(),
            public_parameters: PublicInputs(BTreeSet::from([
                BASE_X_W, BASE_Y_W, SCALAR_W, OUTPUT_X_W, OUTPUT_Y_W,
            ])),
            return_values: PublicInputs::default(),
            assert_messages: vec![],
        };

        ProgramArtifact {
            noir_version: "infinity-regression".to_owned(),
            hash: 0,
            abi: Abi::default(),
            bytecode: Program {
                functions: vec![circuit],
                unconstrained_functions: vec![],
            },
            debug_symbols: ProgramDebugInfo::default(),
            file_map: BTreeMap::new(),
        }
    }

    fn synthesize(scalar: Scalar, out_x: Scalar, out_y: Scalar) -> TestConstraintSystem<Scalar> {
        let synth = NoirCircuitSynthesizer::new(
            artifact(),
            vec![
                // ACIR's canonical point at infinity.
                InputWire::new(true, BASE_X_W, Some(Scalar::ZERO)),
                InputWire::new(true, BASE_Y_W, Some(Scalar::ZERO)),
                InputWire::new(true, SCALAR_W, Some(scalar)),
                InputWire::new(true, OUTPUT_X_W, Some(out_x)),
                InputWire::new(true, OUTPUT_Y_W, Some(out_y)),
            ],
            &HashSet::new(),
        );

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let shared: Vec<AllocatedNum<Scalar>> =
            synth.shared(&mut cs.namespace(|| "shared")).unwrap();
        let pre = synth
            .precommitted(&mut cs.namespace(|| "pre"), &shared)
            .unwrap();
        synth
            .synthesize(&mut cs.namespace(|| "online"), &shared, &pre, None)
            .unwrap();
        cs
    }

    #[test]
    fn msm_on_infinity_yields_canonical_infinity() {
        for scalar in [
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::from(2),
            Scalar::from(0xdead_beef_u64),
        ] {
            let cs = synthesize(scalar, Scalar::ZERO, Scalar::ZERO);
            assert!(
                cs.is_satisfied(),
                "k * infinity must be provable for k = {scalar:?}, unsatisfied: {:?}",
                cs.which_is_unsatisfied()
            );
        }
    }

    #[test]
    fn msm_on_infinity_rejects_a_finite_output() {
        // The dummy base must not leak into the result: claiming the generator
        // (the dummy) as the output of 1 * infinity has to be rejected.
        let dummy =
            crate::noir::synthesis::constant_point::ConstantPoint::<Scalar>::p256_generator();
        let cs = synthesize(Scalar::ONE, dummy.x, dummy.y);
        assert!(
            !cs.is_satisfied(),
            "a finite output for k * infinity must be rejected"
        );
    }
}
