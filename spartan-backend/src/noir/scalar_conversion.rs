use acir::{AcirField, FieldElement};
use ff::PrimeField;
use crate::utils::hex_to_ff;

/// unfortunate translation from arkworks field representations to halo2curves'
pub(crate) fn to_spartan_scalar<Scalar: PrimeField>(field_element: &FieldElement) -> Scalar {
    hex_to_ff(field_element.to_hex().as_str())
}