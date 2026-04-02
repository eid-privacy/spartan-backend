use acvm::FieldElement;
use num_bigint::BigUint;
use crate::noir::scalar_conversion::to_spartan_scalar;
use crate::Scalar;
use crate::utils::{biguint_to_scalar};

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
            CircuitInput::FieldElement(field) => Some(to_spartan_scalar(&field)),
            CircuitInput::Number(number) => Some(biguint_to_scalar(&BigUint::from(number))),
            CircuitInput::Missing => None,
        }
    }
}