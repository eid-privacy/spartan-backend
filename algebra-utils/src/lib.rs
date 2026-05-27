use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::Num;
use p256::elliptic_curve::PrimeField;
use spartan2::provider::T256HyraxEngine;
use spartan2::traits::Engine;

pub mod ecdsa;

// Aliases mostly used to tie the typing to our Spartan backend
pub type P256Fp = <T256HyraxEngine as Engine>::Scalar;
pub type Scalar = P256Fp;

/// converts a hex-encoded string into a Scalar
pub fn hex_to_ff<Scalar : PrimeField>(hex: &str) -> Scalar {
    let b = hex_to_big(hex);
    Scalar::from_str_vartime(&b.to_str_radix(10)).unwrap()
}
//
pub fn big_to_ff<FF: PrimeField>(u : &BigUint) -> FF {
    FF::from_str_vartime(&u.to_str_radix(10)).unwrap()
}
pub fn ff_to_big<FF: PrimeField>(i : &FF) -> BigUint {
    let repr = i.to_repr();
    let i_bytes : &[u8] = repr.as_ref();
    BigUint::from_bytes_le(i_bytes)
}
/// converts a hex-encoded string into a BigUint
pub fn hex_to_big(hex: &str) -> BigUint {
    let hex = if hex.len() % 2 != 0 {
        &format!("0{hex}")
    } else {
        hex
    };

    BigUint::from_str_radix(hex, 16).unwrap()
}

pub fn scalar_to_biguint<Scalar: PrimeField>(x : &Scalar) -> BigUint {
    BigUint::from_bytes_le(x.to_repr().as_ref())
}

pub fn scalar_to_bigint<Scalar: PrimeField>(x : &Scalar) -> BigInt {
  scalar_to_biguint(x).to_bigint().unwrap()
}

pub fn biguint_to_scalar<Scalar:PrimeField>(x : &BigUint) -> Scalar {
    Scalar::from_str_vartime(&x.to_str_radix(10)).unwrap()
}