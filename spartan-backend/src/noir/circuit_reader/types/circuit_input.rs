use crate::Scalar;
use crate::noir::scalar_conversion::to_spartan_scalar_value;
use acvm::FieldElement;
use algebra_utils::biguint_to_scalar;
use num_bigint::BigUint;

#[derive(Clone, Copy, Debug)]
pub enum CircuitInput {
    Byte(u8),
    FieldElement(FieldElement),
    Number(u64), // TODO: add other options
    Missing,
}

impl CircuitInput {
    pub(crate) fn to_scalar(self) -> Option<Scalar> {
        match self {
            CircuitInput::Byte(b) => Some(biguint_to_scalar(&BigUint::from(b))),
            CircuitInput::FieldElement(field) => Some(to_spartan_scalar_value(&field)),
            CircuitInput::Number(number) => Some(biguint_to_scalar(&BigUint::from(number))),
            CircuitInput::Missing => None,
        }
    }
}
