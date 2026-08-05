use std::sync::OnceLock;

use acir::{AcirField, FieldElement};
use algebra_utils::hex_to_big;
use ff::PrimeField;
use num_bigint::BigUint;

fn acir_modulus() -> &'static BigUint {
    static MOD: OnceLock<BigUint> = OnceLock::new();
    MOD.get_or_init(|| FieldElement::modulus())
}

fn half_acir_modulus() -> &'static BigUint {
    static HALF: OnceLock<BigUint> = OnceLock::new();
    HALF.get_or_init(|| FieldElement::modulus() / BigUint::from(2u64))
}

fn biguint_to_scalar<Scalar: PrimeField>(n: &BigUint) -> Scalar {
    let bytes_le = n.to_bytes_le();
    let mut repr = Scalar::Repr::default();
    let out = repr.as_mut();
    let len = out.len().min(bytes_le.len());
    out[..len].copy_from_slice(&bytes_le[..len]);
    Option::from(Scalar::from_repr(repr)).expect("value out of range for scalar field")
}

/// Convert an ACIR **coefficient/constant** into a Spartan scalar, preserving
/// signed semantics.
///
/// ACIR coefficients are small integers that may be negative; a value `c` in
/// the source field with `c > p_acir/2` represents the negative integer
/// `c - p_acir`. To embed that into the (different) target field we map it to
/// `-(p_acir - c)`. This is required because the ACIR field modulus and the
/// Spartan scalar field modulus are different primes.
pub(crate) fn to_spartan_scalar<Scalar: PrimeField>(field_element: &FieldElement) -> Scalar {
    let value = hex_to_big(&field_element.to_hex());

    if value > *half_acir_modulus() {
        // This represents a negative number: -(acir_modulus - value)
        let abs_value = acir_modulus() - &value;
        biguint_to_scalar::<Scalar>(&abs_value).neg()
    } else {
        biguint_to_scalar::<Scalar>(&value)
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
