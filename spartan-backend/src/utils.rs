use ff::PrimeField;
use num_bigint::BigUint;
use num_traits::Num;

// #![allow(unused)]
//
// //! This module implements various low-level gadgets
//
// use std::io::Write;
// // use bellpepper::gadgets::Assignment;
// use bellpepper_core::{
//   boolean::{AllocatedBit, Boolean},
//   num::AllocatedNum,
//   ConstraintSystem, LinearCombination, SynthesisError,
// };
// // use bincode::Error;
// use ff::{PrimeField, PrimeFieldBits};
// // use flate2::Compression;
// // use flate2::write::{ZlibDecoder, ZlibEncoder};
// // use num_bigint::{BigInt, BigUint, ToBigInt};
// // use num_traits::Num;
// // use spartan_t256::bellpepper::r1cs::R1CSShape;
// // use spartan_t256::{NIZKGens, NIZK};
//
// //
// // pub fn encode_proof(proof: NIZK) -> Vec<u8> {
// //   let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
// //   bincode::serialize_into(&mut encoder, &proof).unwrap();
// //   encoder.finish().unwrap()
// // }
// //
// // pub fn decode_proof(encoded_proof: Vec<u8>) -> Result<NIZK, Error> {
// //   let mut decoder = ZlibDecoder::new(Vec::new());
// //   decoder.write_all(encoded_proof.as_slice())?;
// //   let writer = decoder.finish()?;
// //   bincode::deserialize(&writer)
// // }
//
// // everything below this line was stolen from "ecdsa-pop" module in Crescent
//

// // Check that two numbers are equal and return a bit
// // pub fn alloc_num_equals<F: PrimeField, CS: ConstraintSystem<F>>(
// //   mut cs: CS,
// //   a: &AllocatedNum<F>,
// //   b: &AllocatedNum<F>,
// // ) -> Result<AllocatedBit, SynthesisError> {
// //   // Allocate and constrain `r`: result boolean bit.
// //   // It equals `true` if `a` equals `b`, `false` otherwise
// //   let r_value = match (a.get_value(), b.get_value()) {
// //     (Some(a), Some(b)) => Some(a == b),
// //     _ => None,
// //   };
// //
// //   let r = AllocatedBit::alloc(cs.namespace(|| "r"), r_value)?;
// //
// //   // Allocate t s.t. t=1 if z1 == z2 else 1/(z1 - z2)
// //
// //   let t = AllocatedNum::alloc(cs.namespace(|| "t"), || {
// //     Ok(if *a.get_value().get()? == *b.get_value().get()? {
// //       F::ONE
// //     } else {
// //       (*a.get_value().get()? - *b.get_value().get()?)
// //         .invert()
// //         .unwrap()
// //     })
// //   })?;
// //
// //   cs.enforce(
// //     || "t*(a - b) = 1 - r",
// //     |lc| lc + t.get_variable(),
// //     |lc| lc + a.get_variable() - b.get_variable(),
// //     |lc| lc + CS::one() - r.get_variable(),
// //   );
// //
// //   cs.enforce(
// //     || "r*(a - b) = 0",
// //     |lc| lc + r.get_variable(),
// //     |lc| lc + a.get_variable() - b.get_variable(),
// //     |lc| lc,
// //   );
// //
// //   Ok(r)
// // }
//
// pub fn enforce_equal<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   b: &AllocatedNum<F>
// ) {
//       cs.enforce(
//         || "check a == b",
//         |lc| lc + a.get_variable(),
//         |lc| lc + CS::one(),
//         |lc| lc + b.get_variable(),
//       );
// }
//
// /// If condition return a otherwise b
// pub fn conditionally_select<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   b: &AllocatedNum<F>,
//   condition: &Boolean,
// ) -> Result<AllocatedNum<F>, SynthesisError> {
//   let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
//     if *condition.get_value().get()? {
//       Ok(*a.get_value().get()?)
//     } else {
//       Ok(*b.get_value().get()?)
//     }
//   })?;
//
//   // a * condition + b*(1-condition) = c ->
//   // a * condition - b*condition = c - b
//   cs.enforce(
//     || "conditional select constraint",
//     |lc| lc + a.get_variable() - b.get_variable(),
//     |_| condition.lc(CS::one(), F::ONE),
//     |lc| lc + c.get_variable() - b.get_variable(),
//   );
//
//   Ok(c)
// }
//
// /// If condition return a otherwise b
// pub fn conditionally_select_vec<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &[AllocatedNum<F>],
//   b: &[AllocatedNum<F>],
//   condition: &Boolean,
// ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
//   a.iter()
//     .zip(b.iter())
//     .enumerate()
//     .map(|(i, (a, b))| {
//       conditionally_select(cs.namespace(|| format!("select_{i}")), a, b, condition)
//     })
//     .collect::<Result<Vec<AllocatedNum<F>>, SynthesisError>>()
// }
//
// /// Same as the above but Condition is an `AllocatedNum` that needs to be
// /// 0 or 1. 1 => True, 0 => False
// pub fn conditionally_select2<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   b: &AllocatedNum<F>,
//   condition: &AllocatedNum<F>,
// ) -> Result<AllocatedNum<F>, SynthesisError> {
//   let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
//     if *condition.get_value().get()? == F::ONE {
//       Ok(*a.get_value().get()?)
//     } else {
//       Ok(*b.get_value().get()?)
//     }
//   })?;
//
//   // a * condition + b*(1-condition) = c ->
//   // a * condition - b*condition = c - b
//   cs.enforce(
//     || "conditional select constraint",
//     |lc| lc + a.get_variable() - b.get_variable(),
//     |lc| lc + condition.get_variable(),
//     |lc| lc + c.get_variable() - b.get_variable(),
//   );
//
//   Ok(c)
// }
//
// /// If condition set to 0 otherwise a. Condition is an allocated num
// pub fn select_zero_or_num2<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   condition: &AllocatedNum<F>,
// ) -> Result<AllocatedNum<F>, SynthesisError> {
//   let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
//     if *condition.get_value().get()? == F::ONE {
//       Ok(F::ZERO)
//     } else {
//       Ok(*a.get_value().get()?)
//     }
//   })?;
//
//   // a * (1 - condition) = c
//   cs.enforce(
//     || "conditional select constraint",
//     |lc| lc + a.get_variable(),
//     |lc| lc + CS::one() - condition.get_variable(),
//     |lc| lc + c.get_variable(),
//   );
//
//   Ok(c)
// }
//
// /// If condition set to a otherwise 0. Condition is an allocated num
// pub fn select_num_or_zero2<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   condition: &AllocatedNum<F>,
// ) -> Result<AllocatedNum<F>, SynthesisError> {
//   let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
//     if *condition.get_value().get()? == F::ONE {
//       Ok(*a.get_value().get()?)
//     } else {
//       Ok(F::ZERO)
//     }
//   })?;
//
//   cs.enforce(
//     || "conditional select constraint",
//     |lc| lc + a.get_variable(),
//     |lc| lc + condition.get_variable(),
//     |lc| lc + c.get_variable(),
//   );
//
//   Ok(c)
// }
//
// /// If condition set to a otherwise 0
// pub fn select_num_or_zero<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   condition: &Boolean,
// ) -> Result<AllocatedNum<F>, SynthesisError> {
//   let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
//     if *condition.get_value().get()? {
//       Ok(*a.get_value().get()?)
//     } else {
//       Ok(F::ZERO)
//     }
//   })?;
//
//   cs.enforce(
//     || "conditional select constraint",
//     |lc| lc + a.get_variable(),
//     |_| condition.lc(CS::one(), F::ONE),
//     |lc| lc + c.get_variable(),
//   );
//
//   Ok(c)
// }
//
// /// If condition set to 1 otherwise a
// pub fn select_one_or_num2<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   condition: &AllocatedNum<F>,
// ) -> Result<AllocatedNum<F>, SynthesisError> {
//   let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
//     if *condition.get_value().get()? == F::ONE {
//       Ok(F::ONE)
//     } else {
//       Ok(*a.get_value().get()?)
//     }
//   })?;
//
//   cs.enforce(
//     || "conditional select constraint",
//     |lc| lc + CS::one() - a.get_variable(),
//     |lc| lc + condition.get_variable(),
//     |lc| lc + c.get_variable() - a.get_variable(),
//   );
//   Ok(c)
// }
//
// /// If condition set to 1 otherwise a - b
// pub fn select_one_or_diff2<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   b: &AllocatedNum<F>,
//   condition: &AllocatedNum<F>,
// ) -> Result<AllocatedNum<F>, SynthesisError> {
//   let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
//     if *condition.get_value().get()? == F::ONE {
//       Ok(F::ONE)
//     } else {
//       Ok(*a.get_value().get()? - *b.get_value().get()?)
//     }
//   })?;
//
//   cs.enforce(
//     || "conditional select constraint",
//     |lc| lc + CS::one() - a.get_variable() + b.get_variable(),
//     |lc| lc + condition.get_variable(),
//     |lc| lc + c.get_variable() - a.get_variable() + b.get_variable(),
//   );
//   Ok(c)
// }
//
// /// If condition set to a otherwise 1 for boolean conditions
// pub fn select_num_or_one<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   condition: &Boolean,
// ) -> Result<AllocatedNum<F>, SynthesisError> {
//   let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
//     if *condition.get_value().get()? {
//       Ok(*a.get_value().get()?)
//     } else {
//       Ok(F::ONE)
//     }
//   })?;
//
//   cs.enforce(
//     || "conditional select constraint",
//     |lc| lc + a.get_variable() - CS::one(),
//     |_| condition.lc(CS::one(), F::ONE),
//     |lc| lc + c.get_variable() - CS::one(),
//   );
//
//   Ok(c)
// }
//
// /// Check that two numbers are equal and return result as field element in {0,1}
// pub fn alloc_num_equals_constant<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   b: u64,
// ) -> Result<AllocatedNum<F>, SynthesisError> {
//   // Convert b to AllocatedNum
//   let b_scalar = F::from_u128(b as u128);
//   let b_allocated = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(b_scalar))?;
//
//   // Allocate and constrain `r`: a bit encoding the comparison result, as a scalar.
//   // It equals 1 if `a` equals `b`, 0 otherwise
//   let r = AllocatedNum::alloc(cs.namespace(|| "r"), || {
//     if a.get_value().is_some() {
//       if a.get_value().unwrap() == b_scalar {
//         Ok(F::ONE)
//       } else {
//         Ok(F::ZERO)
//       }
//     } else {
//       Err(SynthesisError::AssignmentMissing)
//     }
//   })?;
//   cs.enforce(
//     || "r is a bit",
//     |lc| lc + r.get_variable(),
//     |lc| lc + CS::one() - r.get_variable(),
//     |lc| lc,
//   );
//
//   // Allocate t s.t. t=1 if z1 == z2 else 1/(z1 - z2)
//   let t = AllocatedNum::alloc(cs.namespace(|| "t"), || {
//     Ok(
//       if *a.get_value().get()? == *b_allocated.get_value().get()? {
//         F::ONE
//       } else {
//         (*a.get_value().get()? - *b_allocated.get_value().get()?)
//           .invert()
//           .unwrap()
//       },
//     )
//   })?;
//
//   cs.enforce(
//     || "t*(a - b) = 1 - r",
//     |lc| lc + t.get_variable(),
//     |lc| lc + a.get_variable() - b_allocated.get_variable(),
//     |lc| lc + CS::one() - r.get_variable(),
//   );
//
//   cs.enforce(
//     || "r*(a - b) = 0",
//     |lc| lc + r.get_variable(),
//     |lc| lc + a.get_variable() - b_allocated.get_variable(),
//     |lc| lc,
//   );
//
//   Ok(r)
// }
//
// // Computes a*b + c
// pub fn mul_add<F: PrimeField, CS: ConstraintSystem<F>>(
//   mut cs: CS,
//   a: &AllocatedNum<F>,
//   b: &AllocatedNum<F>,
//   c: &AllocatedNum<F>,
// ) -> Result<AllocatedNum<F>, SynthesisError> {
//   let r = AllocatedNum::alloc(cs.namespace(|| "a*b + c"), {
//     || {
//       if a.get_value().is_some() {
//         Ok(a.get_value().unwrap() * b.get_value().unwrap() + c.get_value().unwrap())
//       } else {
//         Err(SynthesisError::AssignmentMissing)
//       }
//     }
//   })?;
//
//   // Constrain: r = ab + c  as  r - c = a * b
//   cs.enforce(
//     || "multiplication constraint",
//     |lc| lc + a.get_variable(),
//     |lc| lc + b.get_variable(),
//     |lc| lc + r.get_variable() - c.get_variable(),
//   );
//
//   Ok(r)
// }
//
// // pub fn scalar_to_biguint<Scalar: PrimeField>(x : &Scalar) -> BigUint {
// //   BigUint::from_bytes_le(x.to_repr().as_ref())
// // }
// // pub fn scalar_to_bigint<Scalar: PrimeField>(x : &Scalar) -> BigInt {
// //   scalar_to_biguint(x).to_bigint().unwrap()
// // }
// //
pub fn biguint_to_scalar<Scalar:PrimeField>(x : &BigUint) -> Scalar {
  Scalar::from_str_vartime(&x.to_str_radix(10)).unwrap()
}
//
// // pub fn mod_inverse(a: &BigUint, p: &BigUint) -> BigUint {
// //   let two = BigUint::from(2u8);
// //   a.modpow(&(p - two), p)
// // }

/// converts a hex-encoded string into a Scalar
pub fn hex_to_ff<Scalar : PrimeField>(hex: &str) -> Scalar {
  let b = hex_to_big(hex);
  Scalar::from_str_vartime(&b.to_str_radix(10)).unwrap()
}
//
// // pub fn big_to_ff<FF: PrimeField>(u : &BigUint) -> FF {
// //   FF::from_str_vartime(&u.to_str_radix(10)).unwrap()
// // }
// // pub fn ff_to_big<FF: PrimeField>(i : &FF) -> BigUint {
// //   let repr = i.to_repr();
// //   let i_bytes : &[u8] = repr.as_ref();
// //   BigUint::from_bytes_le(i_bytes)
// // }
/// converts a hex-encoded string into a BigUint
pub fn hex_to_big(hex: &str) -> BigUint {
  let hex = if hex.len() % 2 != 0 {
    &format!("0{hex}")
  } else {
    hex
  };

  BigUint::from_str_radix(hex, 16).unwrap()
}