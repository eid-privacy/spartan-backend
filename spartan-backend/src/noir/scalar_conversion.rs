use acir::{AcirField, FieldElement};
use ff::PrimeField;
use num_bigint::BigUint;
use algebra_utils::hex_to_big;

/// "negative" values (those > modulus/2 in the source
/// field) must be re-negated in the target field to preserve their semantic sign.
pub(crate) fn to_spartan_scalar<Scalar: PrimeField>(field_element: &FieldElement) -> Scalar {
    let acir_modulus = FieldElement::modulus();
    let half_modulus = &acir_modulus / BigUint::from(2u64);

    let value = hex_to_big(&field_element.to_hex());

    if value > half_modulus {
        // This represents a negative number: -(acir_modulus - value)
        let abs_value = &acir_modulus - &value;
        let positive = Scalar::from_str_vartime(&abs_value.to_str_radix(10)).unwrap();
        positive.neg()
    } else {
        Scalar::from_str_vartime(&value.to_str_radix(10)).unwrap()
    }
}