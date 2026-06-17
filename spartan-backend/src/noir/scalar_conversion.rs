use acir::{AcirField, FieldElement};
use algebra_utils::hex_to_big;
use ff::PrimeField;
use num_bigint::BigUint;

/// Convert an ACIR **coefficient/constant** into a Spartan scalar, preserving
/// signed semantics.
///
/// ACIR coefficients are small integers that may be negative; a value `c` in
/// the source field with `c > p_acir/2` represents the negative integer
/// `c - p_acir`. To embed that into the (different) target field we map it to
/// `-(p_acir - c)`. This is required because the ACIR field modulus and the
/// Spartan scalar field modulus are different primes.
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

/// Convert an ACIR **witness value** into a Spartan scalar by direct embedding.
///
/// Unlike coefficients, witness values are genuine canonical field elements in
/// `[0, p_acir)` and must NOT be reinterpreted as signed. Applying the signed
/// heuristic here corrupts any value above `p_acir/2` (e.g. full-width P-256
/// coordinates such as `T_x`), which previously broke the `array_to_field`
/// recomposition constraints and produced `InvalidSumcheckProof`.
pub(crate) fn to_spartan_scalar_value<Scalar: PrimeField>(field_element: &FieldElement) -> Scalar {
    let value = hex_to_big(&field_element.to_hex());
    Scalar::from_str_vartime(&value.to_str_radix(10)).unwrap()
}
