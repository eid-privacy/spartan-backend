use acir::FieldElement;
use acir::native_types::Expression;
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use crate::noir::scalar_conversion::to_spartan_scalar;
use crate::noir::synthesis::allocation_support::{AllocatedWire, WitnessMap};
use crate::types::Scalar;

pub(crate) fn handle_assert_zero<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    expr: &Expression<FieldElement>,
    constraint_label: &str,
) -> Result<(), SynthesisError> {
    // TODO: account for the multiplicands and the constant in Plonk-ish constraints
    let _multiplicands = &expr.mul_terms;
    assert_eq!(_multiplicands.len(), 0, "Unhandled non-empty multiplicands");
    let linear_combinations = &expr.linear_combinations;
    let constant = expr.q_c;

    let mut lin_comb = LinearCombination::<Scalar>::zero();
    for (field_element, witness) in linear_combinations {
        tracing::debug!("LC term: {:?} * {:?}", field_element, witness);
        let allocated = allocation_store
            .get(&witness.witness_index())
            .ok_or_else(|| SynthesisError::AssignmentMissing)?;

        let allocated_num = &allocated.allocation.as_ref()
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        lin_comb = lin_comb
            + (
            to_spartan_scalar(field_element),
            // TODO: manage unallocated witnesses later (if it becomes relevant)
            allocated_num.get_variable(),
        );
    }
    cs.enforce(
        || constraint_label,
        |lc| lc + &lin_comb + (to_spartan_scalar(&constant), CS::one()),
        |lc| lc + CS::one(),
        |lc| lc + &LinearCombination::<Scalar>::zero(),
    );
    
    Ok(())
}