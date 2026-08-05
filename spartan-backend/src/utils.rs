use bellpepper_core::{ConstraintSystem, num::AllocatedNum};
use ff::PrimeField;

pub fn enforce_equal<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
) {
    cs.enforce(
        || "check a == b",
        |lc| lc + a.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + b.get_variable(),
    );
}
