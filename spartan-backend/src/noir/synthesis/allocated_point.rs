//! This module implements various elliptic curve gadgets
//! This module was copied from Crescent's implementation
#![allow(non_snake_case)]
use bellpepper::gadgets::Assignment;
use bellpepper_core::{
    ConstraintSystem, LinearCombination, SynthesisError,
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
};
use ff::{PrimeField, PrimeFieldBits};

use crate::noir::synthesis::{
    constant_point::ConstantPoint,
    constraints_utils::{
        alloc_constant, alloc_num_equals, alloc_one, alloc_zero, conditionally_select,
        conditionally_select2, select_num_or_one, select_num_or_zero, select_num_or_zero2,
        select_one_or_diff2, select_one_or_num2, select_zero_or_num2,
    },
};

/// Extracts the `AllocatedBit` from a `Boolean`. `AllocatedNum::to_bits_le`
/// only ever yields `Boolean::Is`, so the other variants are unreachable here.
fn as_bit(b: &Boolean) -> &AllocatedBit {
    match b {
        Boolean::Is(bit) => bit,
        _ => unreachable!("to_bits_le only produces Boolean::Is"),
    }
}

/// `AllocatedPoint` provides an elliptic curve abstraction inside a circuit.
#[derive(Clone)]
pub struct AllocatedPoint<Scalar>
where
    Scalar: PrimeField,
{
    pub(crate) x: AllocatedNum<Scalar>,
    pub(crate) y: AllocatedNum<Scalar>,
    pub(crate) is_infinity: AllocatedNum<Scalar>,
}

impl<Scalar> AllocatedPoint<Scalar>
where
    Scalar: PrimeField + PrimeFieldBits,
{
    /// Allocates a new point on the curve using coordinates provided by
    /// `coords`. If coords = None, it allocates the default infinity point
    pub fn _alloc<CS>(
        mut cs: CS,
        coords: Option<(Scalar, Scalar, bool)>,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
            Ok(coords.map_or(Scalar::ZERO, |c| c.0))
        })?;
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            Ok(coords.map_or(Scalar::ZERO, |c| c.1))
        })?;
        let is_infinity = AllocatedNum::alloc(cs.namespace(|| "is_infinity"), || {
            Ok(if coords.is_none_or(|c| c.2) {
                Scalar::ONE
            } else {
                Scalar::ZERO
            })
        })?;
        cs.enforce(
            || "is_infinity is bit",
            |lc| lc + is_infinity.get_variable(),
            |lc| lc + CS::one() - is_infinity.get_variable(),
            |lc| lc,
        );

        Ok(AllocatedPoint { x, y, is_infinity })
    }

    pub fn _inputize<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
    ) -> Result<(), SynthesisError> {
        self.x.inputize(cs.namespace(|| "x"))?;
        self.y.inputize(cs.namespace(|| "y"))?;
        self.is_infinity.inputize(cs.namespace(|| "is_infinity"))?;
        Ok(())
    }

    /// Allocates a default point on the curve.
    pub fn default<CS>(mut cs: CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        let zero = alloc_zero(cs.namespace(|| "zero"))?;
        let one = alloc_one(cs.namespace(|| "one"))?;

        Ok(AllocatedPoint {
            x: zero.clone(),
            y: zero,
            is_infinity: one,
        })
    }

    #[allow(unused)]
    /// Returns coordinates associated with the point.
    pub const fn get_coordinates(
        &self,
    ) -> (
        &AllocatedNum<Scalar>,
        &AllocatedNum<Scalar>,
        &AllocatedNum<Scalar>,
    ) {
        (&self.x, &self.y, &self.is_infinity)
    }

    /// Negates the provided point
    pub fn negate<CS: ConstraintSystem<Scalar>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(-*self.y.get_value().get()?))?;

        cs.enforce(
            || "check y = - self.y",
            |lc| lc + self.y.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc - y.get_variable(),
        );

        Ok(Self {
            x: self.x.clone(),
            y,
            is_infinity: self.is_infinity.clone(),
        })
    }

    /// Add two points (may be equal)
    pub fn add<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        other: &AllocatedPoint<Scalar>,
    ) -> Result<Self, SynthesisError> {
        // Compute boolean equal indicating if self = other

        let equal_x = alloc_num_equals(
            cs.namespace(|| "check self.x == other.x"),
            &self.x,
            &other.x,
        )?;

        let equal_y = alloc_num_equals(
            cs.namespace(|| "check self.y == other.y"),
            &self.y,
            &other.y,
        )?;

        // Compute the result of the addition and the result of double self
        let result_from_add =
            self.add_internal(cs.namespace(|| "add internal"), other, &equal_x)?;
        let result_from_double = self.double(cs.namespace(|| "double"))?;

        // Output:
        // If (self == other) {
        //  return double(self)
        // }else {
        //  if (self.x == other.x){
        //      return infinity [negation]
        //  } else {
        //      return add(self, other)
        //  }
        // }
        let result_for_equal_x = AllocatedPoint::select_point_or_infinity(
            cs.namespace(|| "equal_y ? result_from_double : infinity"),
            &result_from_double,
            &Boolean::from(equal_y),
        )?;

        AllocatedPoint::conditionally_select(
            cs.namespace(|| "equal ? result_from_double : result_from_add"),
            &result_for_equal_x,
            &result_from_add,
            &Boolean::from(equal_x),
        )
    }

    /// Adds other point to this point and returns the result. Assumes that the
    /// two points are different and that both `other.is_infinity` and
    /// `this.is_infinty` are bits
    pub fn add_internal<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        other: &AllocatedPoint<Scalar>,
        equal_x: &AllocatedBit,
    ) -> Result<Self, SynthesisError> {
        //************************************************************************/
        // lambda = (other.y - self.y) * (other.x - self.x).invert().unwrap();
        //************************************************************************/
        // First compute (other.x - self.x).inverse()
        // If either self or other are the infinity point or self.x = other.x  then
        // compute bogus values Specifically,
        // x_diff = self != inf && other != inf && self.x == other.x ? (other.x -
        // self.x) : 1

        // Compute self.is_infinity OR other.is_infinity =
        // NOT(NOT(self.is_ifninity) AND NOT(other.is_infinity))
        let at_least_one_inf = AllocatedNum::alloc(cs.namespace(|| "at least one inf"), || {
            Ok(Scalar::ONE
                - (Scalar::ONE - *self.is_infinity.get_value().get()?)
                    * (Scalar::ONE - *other.is_infinity.get_value().get()?))
        })?;
        cs.enforce(
            || "1 - at least one inf = (1-self.is_infinity) * (1-other.is_infinity)",
            |lc| lc + CS::one() - self.is_infinity.get_variable(),
            |lc| lc + CS::one() - other.is_infinity.get_variable(),
            |lc| lc + CS::one() - at_least_one_inf.get_variable(),
        );

        // Now compute x_diff_is_actual = at_least_one_inf OR equal_x
        let x_diff_is_actual =
            AllocatedNum::alloc(cs.namespace(|| "allocate x_diff_is_actual"), || {
                Ok(if *equal_x.get_value().get()? {
                    Scalar::ONE
                } else {
                    *at_least_one_inf.get_value().get()?
                })
            })?;
        cs.enforce(
            || "1 - x_diff_is_actual = (1-equal_x) * (1-at_least_one_inf)",
            |lc| lc + CS::one() - at_least_one_inf.get_variable(),
            |lc| lc + CS::one() - equal_x.get_variable(),
            |lc| lc + CS::one() - x_diff_is_actual.get_variable(),
        );

        // x_diff = 1 if either self.is_infinity or other.is_infinity or self.x =
        // other.x else self.x - other.x
        let x_diff = select_one_or_diff2(
            cs.namespace(|| "Compute x_diff"),
            &other.x,
            &self.x,
            &x_diff_is_actual,
        )?;

        let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
            let x_diff_inv = if *x_diff_is_actual.get_value().get()? == Scalar::ONE {
                // Set to default
                Scalar::ONE
            } else {
                // Set to the actual inverse
                (*other.x.get_value().get()? - *self.x.get_value().get()?)
                    .invert()
                    .unwrap()
            };

            Ok((*other.y.get_value().get()? - *self.y.get_value().get()?) * x_diff_inv)
        })?;
        cs.enforce(
            || "Check that lambda is correct",
            |lc| lc + lambda.get_variable(),
            |lc| lc + x_diff.get_variable(),
            |lc| lc + other.y.get_variable() - self.y.get_variable(),
        );

        //************************************************************************/
        // x = lambda * lambda - self.x - other.x;
        //************************************************************************/
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
            Ok(*lambda.get_value().get()? * lambda.get_value().get()?
                - *self.x.get_value().get()?
                - *other.x.get_value().get()?)
        })?;
        cs.enforce(
            || "check that x is correct",
            |lc| lc + lambda.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| lc + x.get_variable() + self.x.get_variable() + other.x.get_variable(),
        );

        //************************************************************************/
        // y = lambda * (self.x - x) - self.y;
        //************************************************************************/
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            Ok(
                *lambda.get_value().get()? * (*self.x.get_value().get()? - *x.get_value().get()?)
                    - *self.y.get_value().get()?,
            )
        })?;

        cs.enforce(
            || "Check that y is correct",
            |lc| lc + lambda.get_variable(),
            |lc| lc + self.x.get_variable() - x.get_variable(),
            |lc| lc + y.get_variable() + self.y.get_variable(),
        );

        //************************************************************************/
        // We only return the computed x, y if neither of the points is infinity
        // and self.x != other.y if self.is_infinity return other.clone()
        // elif other.is_infinity return self.clone()
        // elif self.x == other.x return infinity
        // Otherwise return the computed points.
        //************************************************************************/
        // Now compute the output x

        let x1 = conditionally_select2(
            cs.namespace(|| "x1 = other.is_infinity ? self.x : x"),
            &self.x,
            &x,
            &other.is_infinity,
        )?;

        let x = conditionally_select2(
            cs.namespace(|| "x = self.is_infinity ? other.x : x1"),
            &other.x,
            &x1,
            &self.is_infinity,
        )?;

        let y1 = conditionally_select2(
            cs.namespace(|| "y1 = other.is_infinity ? self.y : y"),
            &self.y,
            &y,
            &other.is_infinity,
        )?;

        let y = conditionally_select2(
            cs.namespace(|| "y = self.is_infinity ? other.y : y1"),
            &other.y,
            &y1,
            &self.is_infinity,
        )?;

        let is_infinity1 = select_num_or_zero2(
            cs.namespace(|| "is_infinity1 = other.is_infinity ? self.is_infinity : 0"),
            &self.is_infinity,
            &other.is_infinity,
        )?;

        let is_infinity = conditionally_select2(
            cs.namespace(|| "is_infinity = self.is_infinity ? other.is_infinity : is_infinity1"),
            &other.is_infinity,
            &is_infinity1,
            &self.is_infinity,
        )?;

        Ok(Self { x, y, is_infinity })
    }

    /// Doubles the supplied point.
    pub fn double<CS: ConstraintSystem<Scalar>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
        //*************************************************************/
        // Compute lambda = (3x^2 + a) / 2y
        /************************************************************ */

        // Compute denom = 2*y ? self != inf : 1
        let denom_actual = AllocatedNum::alloc(cs.namespace(|| "denom_actual"), || {
            Ok(*self.y.get_value().get()? + *self.y.get_value().get()?)
        })?;
        cs.enforce(
            || "check denom_actual",
            |lc| lc + CS::one() + CS::one(),
            |lc| lc + self.y.get_variable(),
            |lc| lc + denom_actual.get_variable(),
        );
        let denom = select_one_or_num2(cs.namespace(|| "denom"), &denom_actual, &self.is_infinity)?;

        // Compute `numerator = x^2 + a`,  ASSUMES A = -3 (True for P256r1)
        let numerator = AllocatedNum::alloc(cs.namespace(|| "alloc numerator"), || {
            Ok(
                Scalar::from(3) * self.x.get_value().get()? * self.x.get_value().get()?
                    - Scalar::from(3),
            )
        })?;
        cs.enforce(
            || "Check numerator",
            |lc| lc + (Scalar::from(3), self.x.get_variable()),
            |lc| lc + self.x.get_variable(),
            |lc| lc + numerator.get_variable() + CS::one() + CS::one() + CS::one(),
        );

        let lambda = AllocatedNum::alloc(cs.namespace(|| "alloc lambda"), || {
            let tmp_inv = if *self.is_infinity.get_value().get()? == Scalar::ONE {
                // Return default value 1
                Scalar::ONE
            } else {
                // Return the actual inverse
                (*denom.get_value().get()?).invert().unwrap()
            };
            Ok(tmp_inv * *numerator.get_value().get()?)
        })?;

        cs.enforce(
            || "Check lambda",
            |lc| lc + denom.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| lc + numerator.get_variable(),
        );

        /************************************************************ */
        //          x = lambda * lambda - self.x - self.x;
        /************************************************************ */

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
            Ok(
                ((*lambda.get_value().get()?) * (*lambda.get_value().get()?))
                    - *self.x.get_value().get()?
                    - self.x.get_value().get()?,
            )
        })?;
        cs.enforce(
            || "Check x",
            |lc| lc + lambda.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| lc + x.get_variable() + self.x.get_variable() + self.x.get_variable(),
        );

        /************************************************************ */
        //        y = lambda * (self.x - x) - self.y;
        /************************************************************ */

        let y =
            AllocatedNum::alloc(cs.namespace(|| "y"), || {
                Ok((*lambda.get_value().get()?)
                    * (*self.x.get_value().get()? - x.get_value().get()?)
                    - self.y.get_value().get()?)
            })?;
        cs.enforce(
            || "Check y",
            |lc| lc + lambda.get_variable(),
            |lc| lc + self.x.get_variable() - x.get_variable(),
            |lc| lc + y.get_variable() + self.y.get_variable(),
        );

        /************************************************************ */
        // Only return the computed x and y if the point is not infinity
        /************************************************************ */

        // x
        let x = select_zero_or_num2(cs.namespace(|| "final x"), &x, &self.is_infinity)?;

        // y
        let y = select_zero_or_num2(cs.namespace(|| "final y"), &y, &self.is_infinity)?;

        // is_infinity
        let is_infinity = self.is_infinity.clone();

        Ok(Self { x, y, is_infinity })
    }

    /// A gadget for scalar multiplication, optimized to use incomplete addition
    /// law. The optimization here is analogous to <https://github.com/arkworks-rs/r1cs-std/blob/6d64f379a27011b3629cf4c9cb38b7b7b695d5a0/src/groups/curves/short_weierstrass/mod.rs#L295>,
    /// except we use complete addition law over affine coordinates instead of
    /// projective coordinates for the tail bits
    pub fn scalar_mul<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        s: &AllocatedNum<Scalar>,
    ) -> Result<Self, SynthesisError> {
        let scalar_bits = s.to_bits_le(cs.namespace(|| "scalar_bits"))?;

        let split_len = core::cmp::min(scalar_bits.len(), (Scalar::NUM_BITS - 2) as usize);
        let (incomplete_bits, complete_bits) = scalar_bits.split_at(split_len);

        // we convert AllocatedPoint into AllocatedPointNonInfinity; we deal with
        // the case where self.is_infinity = 1 below
        let mut p = AllocatedPointNonInfinity::from_allocated_point(self);

        // we assume the first bit to be 1, so we must initialize acc to self and
        // double it we remove this assumption below
        let mut acc = p;
        p = acc.double_incomplete(cs.namespace(|| "double"))?;

        // perform the double-and-add loop to compute the scalar mul using
        // incomplete addition law
        for (i, bit) in incomplete_bits.iter().enumerate().skip(1) {
            let temp = acc.add_incomplete(cs.namespace(|| format!("add {i}")), &p)?;
            acc = AllocatedPointNonInfinity::conditionally_select(
                cs.namespace(|| format!("acc_iteration_{i}")),
                &temp,
                &acc,
                &bit.clone(),
            )?;

            p = p.double_incomplete(cs.namespace(|| format!("double {i}")))?;
        }

        // convert back to AllocatedPoint
        let res = {
            // we set acc.is_infinity = self.is_infinity
            let acc = acc.to_allocated_point(&self.is_infinity)?;

            // we remove the initial slack if bits[0] is as not as assumed (i.e., it
            // is not 1)
            let acc_minus_initial = {
                let neg = self.negate(cs.namespace(|| "negate"))?;
                acc.add(cs.namespace(|| "res minus self"), &neg)
            }?;

            AllocatedPoint::conditionally_select(
                cs.namespace(|| "remove slack if necessary"),
                &acc,
                &acc_minus_initial,
                &scalar_bits[0].clone(),
            )?
        };

        // when self.is_infinity = 1, return the default point, else return res
        // we already set res.is_infinity to be self.is_infinity, so we do not need
        // to set it here
        let default = Self::default(cs.namespace(|| "default"))?;
        let x = conditionally_select2(
            cs.namespace(|| "check if self.is_infinity is zero (x)"),
            &default.x,
            &res.x,
            &self.is_infinity,
        )?;

        let y = conditionally_select2(
            cs.namespace(|| "check if self.is_infinity is zero (y)"),
            &default.y,
            &res.y,
            &self.is_infinity,
        )?;

        // we now perform the remaining scalar mul using complete addition law
        let mut acc = AllocatedPoint {
            x,
            y,
            is_infinity: res.is_infinity,
        };
        let mut p_complete = p.to_allocated_point(&self.is_infinity)?;

        for (i, bit) in complete_bits.iter().enumerate() {
            let temp = acc.add(cs.namespace(|| format!("add_complete {i}")), &p_complete)?;
            acc = AllocatedPoint::conditionally_select(
                cs.namespace(|| format!("acc_complete_iteration_{i}")),
                &temp,
                &acc,
                &bit.clone(),
            )?;

            p_complete = p_complete.double(cs.namespace(|| format!("double_complete {i}")))?;
        }

        Ok(acc)
    }

    /// Scalar multiplication `s * base` for a base point whose coordinates are
    /// circuit CONSTANTS, using width-2 windows. All `2^i * base` are
    /// precomputed natively, so there are no in-circuit doublings. Semantics
    /// match [`scalar_mul`]: `s` is interpreted as its full integer value (not
    /// reduced modulo the group order), and the result is the point at infinity
    /// `(0, 0, 1)` iff `s * base` is the identity.
    ///
    /// Requires `base.y != 0` (checked by the dispatcher in `handle_msm`).
    ///
    /// The scalar bits are grouped into 2-bit windows. Window `j` (bits
    /// `b0, b1`, value `v_j = b0 + 2*b1`) contributes the constant point
    /// `v_j * 2^{2j} * base`. To keep the incomplete-addition law valid (no
    /// operand ever hits the identity or shares an x-coordinate with the
    /// accumulator) each window's 4-entry table is offset by a distinct
    /// nothing-up-my-sleeve point `K_j = 2^j * Z`, so table entry `d` is
    /// `T_j[d] = d * 2^{2j} * base + K_j`. Selecting among the four constant
    /// table points is a multilinear function of `(b0, b1)`:
    ///
    /// ```text
    ///   T = T0 + b0*(T1-T0) + b1*(T2-T0) + b0*b1*(T3-T1-T2+T0)
    /// ```
    ///
    /// so it collapses to a single linear combination plus one bit-product
    /// (`b0*b1`) per window, added to the accumulator with no doublings. The
    /// total offset `sum_j K_j` is removed at the end with one complete
    /// addition.
    ///
    /// A shared offset (`K_j = Z` for all `j`) would be unsound: an all-zero
    /// first window makes the accumulator equal the next window's table entry
    /// `0`, a degenerate incomplete add. Distinct `K_j` make every such
    /// collision imply a discrete-log relation between `Z` and `base`.
    ///
    /// The width is fixed at 2 (the constraint-per-bit optimum: 2 constraints
    /// per scalar bit). The generic width-`w` reference implementation lives in
    /// the test module and is proven equivalent to this one for `w = 2`.
    pub fn scalar_mul_fixed_base<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        base: &ConstantPoint<Scalar>,
        s: &AllocatedNum<Scalar>,
    ) -> Result<Self, SynthesisError> {
        let bits = s.to_bits_le(cs.namespace(|| "scalar_bits"))?;
        let nbits = bits.len();
        assert!(
            nbits % 2 == 0,
            "fixed-base w=2 requires an even scalar bit-length, got {nbits}"
        );
        let num_windows = nbits / 2;

        // Native precomputation (depends only on the constant base, so the
        // prover and verifier shape passes build identical tables).
        let b = base.recover_b();
        let z = ConstantPoint::derive_offset(b, base);
        // D_j = 2^{2j} * base, K_j = 2^j * Z.
        let mut d_pows = Vec::with_capacity(num_windows);
        let mut k_offsets = Vec::with_capacity(num_windows);
        {
            let mut d = *base;
            let mut k = z;
            for _ in 0..num_windows {
                d_pows.push(d);
                k_offsets.push(k);
                d = d.double().double(); // *2^2
                k = k.double();
            }
        }
        // K_total = sum_j K_j = (2^num_windows - 1) * Z.
        let mut k_total = k_offsets[0];
        for k in &k_offsets[1..] {
            k_total = k_total.add(k);
        }

        let mut acc: Option<AllocatedPointNonInfinity<Scalar>> = None;
        for j in 0..num_windows {
            let b0 = as_bit(&bits[2 * j]);
            let b1 = as_bit(&bits[2 * j + 1]);

            // Constant 4-entry table T_j[d] = d * D_j + K_j.
            let t0 = k_offsets[j];
            let t1 = t0.add(&d_pows[j]);
            let t2 = t1.add(&d_pows[j]);
            let t3 = t2.add(&d_pows[j]);

            // The single bit-product a 2-bit window needs.
            let p = AllocatedBit::and(cs.namespace(|| format!("window {j} b0b1")), b0, b1)?;

            // Multilinear selection collapsed to one linear combination:
            //   T = T0 + b0*(T1-T0) + b1*(T2-T0) + b0b1*(T3-T1-T2+T0).
            let mut x_lc = LinearCombination::<Scalar>::zero();
            let mut y_lc = LinearCombination::<Scalar>::zero();
            x_lc = x_lc + (t0.x, CS::one()) + (t1.x - t0.x, b0.get_variable());
            y_lc = y_lc + (t0.y, CS::one()) + (t1.y - t0.y, b0.get_variable());
            x_lc = x_lc + (t2.x - t0.x, b1.get_variable());
            y_lc = y_lc + (t2.y - t0.y, b1.get_variable());
            x_lc = x_lc + (t3.x - t1.x - t2.x + t0.x, p.get_variable());
            y_lc = y_lc + (t3.y - t1.y - t2.y + t0.y, p.get_variable());

            // Native selected value for the witness closures (None in a shape
            // pass, where the closures are never evaluated).
            let selected = match (b0.get_value(), b1.get_value()) {
                (Some(v0), Some(v1)) => {
                    let t = [t0, t1, t2, t3][usize::from(v0) + 2 * usize::from(v1)];
                    Some((t.x, t.y))
                }
                _ => None,
            };

            acc = Some(match acc {
                None => {
                    // First window seeds the accumulator directly from the LC.
                    let ax = AllocatedNum::alloc(cs.namespace(|| "seed x"), || {
                        selected
                            .map(|v| v.0)
                            .ok_or(SynthesisError::AssignmentMissing)
                    })?;
                    let ay = AllocatedNum::alloc(cs.namespace(|| "seed y"), || {
                        selected
                            .map(|v| v.1)
                            .ok_or(SynthesisError::AssignmentMissing)
                    })?;
                    cs.enforce(
                        || "seed x matches selection",
                        |lc| lc + ax.get_variable(),
                        |lc| lc + CS::one(),
                        |lc| lc + &x_lc,
                    );
                    cs.enforce(
                        || "seed y matches selection",
                        |lc| lc + ay.get_variable(),
                        |lc| lc + CS::one(),
                        |lc| lc + &y_lc,
                    );
                    AllocatedPointNonInfinity::new(ax, ay)
                }
                Some(prev) => prev.add_incomplete_lc(
                    cs.namespace(|| format!("window {j} add")),
                    &x_lc,
                    &y_lc,
                    selected,
                )?,
            });
        }

        let acc = acc.expect("at least one window");

        // Remove the accumulated offset with one complete addition of the
        // constant -K_total. The complete law yields infinity when
        // s == 0 (mod the group order), matching `scalar_mul` for that case.
        let zero = alloc_zero(cs.namespace(|| "zero"))?;
        let neg_k = k_total.negate();
        let minus_k = AllocatedPoint {
            x: alloc_constant(cs.namespace(|| "minus offset x"), neg_k.x)?,
            y: alloc_constant(cs.namespace(|| "minus offset y"), neg_k.y)?,
            is_infinity: zero.clone(),
        };
        let acc_point = acc.to_allocated_point(&zero)?;
        acc_point.add(cs.namespace(|| "subtract offset"), &minus_k)
    }

    /// If condition outputs a otherwise outputs b
    pub fn conditionally_select<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        a: &Self,
        b: &Self,
        condition: &Boolean,
    ) -> Result<Self, SynthesisError> {
        let x = conditionally_select(cs.namespace(|| "select x"), &a.x, &b.x, condition)?;

        let y = conditionally_select(cs.namespace(|| "select y"), &a.y, &b.y, condition)?;

        let is_infinity = conditionally_select(
            cs.namespace(|| "select is_infinity"),
            &a.is_infinity,
            &b.is_infinity,
            condition,
        )?;

        Ok(Self { x, y, is_infinity })
    }

    /// If condition outputs a otherwise infinity
    pub fn select_point_or_infinity<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        a: &Self,
        condition: &Boolean,
    ) -> Result<Self, SynthesisError> {
        let x = select_num_or_zero(cs.namespace(|| "select x"), &a.x, condition)?;

        let y = select_num_or_zero(cs.namespace(|| "select y"), &a.y, condition)?;

        let is_infinity = select_num_or_one(
            cs.namespace(|| "select is_infinity"),
            &a.is_infinity,
            condition,
        )?;

        Ok(Self { x, y, is_infinity })
    }

    /// Compare two points and constrain them to be equal
    #[allow(dead_code)]
    pub fn enforce_equal<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        point1: &AllocatedPoint<Scalar>,
        point2: &AllocatedPoint<Scalar>,
    ) -> Result<(), SynthesisError> {
        // Ensure x are the same
        cs.enforce(
            || "check point1.x == point2.x",
            |lc| lc + point1.x.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + point2.x.get_variable(),
        );
        // Ensure y are the same
        cs.enforce(
            || "check point1.y == point2.y",
            |lc| lc + point1.y.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + point2.y.get_variable(),
        );

        Ok(())
    }
}

#[derive(Clone)]
/// `AllocatedPoint` but one that is guaranteed to be not infinity
pub struct AllocatedPointNonInfinity<Scalar>
where
    Scalar: PrimeField,
{
    x: AllocatedNum<Scalar>,
    y: AllocatedNum<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> AllocatedPointNonInfinity<Scalar> {
    #[allow(unused)]
    /// Creates a new `AllocatedPointNonInfinity` from the specified coordinates
    pub const fn new(x: AllocatedNum<Scalar>, y: AllocatedNum<Scalar>) -> Self {
        Self { x, y }
    }

    #[allow(unused)]
    /// Allocates a new point on the curve using coordinates provided by
    /// `coords`.
    pub fn alloc<CS>(mut cs: CS, coords: Option<(Scalar, Scalar)>) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
            coords.map_or(Err(SynthesisError::AssignmentMissing), |c| Ok(c.0))
        })?;
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            coords.map_or(Err(SynthesisError::AssignmentMissing), |c| Ok(c.1))
        })?;

        Ok(Self { x, y })
    }

    /// Turns an `AllocatedPoint` into an `AllocatedPointNonInfinity` (assumes it
    /// is not infinity)
    pub fn from_allocated_point(p: &AllocatedPoint<Scalar>) -> Self {
        Self {
            x: p.x.clone(),
            y: p.y.clone(),
        }
    }

    /// Returns an `AllocatedPoint` from an `AllocatedPointNonInfinity`
    pub fn to_allocated_point(
        &self,
        is_infinity: &AllocatedNum<Scalar>,
    ) -> Result<AllocatedPoint<Scalar>, SynthesisError> {
        Ok(AllocatedPoint {
            x: self.x.clone(),
            y: self.y.clone(),
            is_infinity: is_infinity.clone(),
        })
    }

    #[allow(unused)]
    /// Returns coordinates associated with the point.
    pub const fn get_coordinates(&self) -> (&AllocatedNum<Scalar>, &AllocatedNum<Scalar>) {
        (&self.x, &self.y)
    }

    /// Add two points assuming self != +/- other
    pub fn add_incomplete<CS>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        // allocate a free variable that an honest prover sets to lambda =
        // (y2-y1)/(x2-x1)
        let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
            if *other.x.get_value().get()? == *self.x.get_value().get()? {
                Ok(Scalar::ONE)
            } else {
                Ok((*other.y.get_value().get()? - *self.y.get_value().get()?)
                    * (*other.x.get_value().get()? - *self.x.get_value().get()?)
                        .invert()
                        .unwrap())
            }
        })?;
        cs.enforce(
            || "Check that lambda is computed correctly",
            |lc| lc + lambda.get_variable(),
            |lc| lc + other.x.get_variable() - self.x.get_variable(),
            |lc| lc + other.y.get_variable() - self.y.get_variable(),
        );

        //************************************************************************/
        // x = lambda * lambda - self.x - other.x;
        //************************************************************************/
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
            Ok(*lambda.get_value().get()? * lambda.get_value().get()?
                - *self.x.get_value().get()?
                - *other.x.get_value().get()?)
        })?;
        cs.enforce(
            || "check that x is correct",
            |lc| lc + lambda.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| lc + x.get_variable() + self.x.get_variable() + other.x.get_variable(),
        );

        //************************************************************************/
        // y = lambda * (self.x - x) - self.y;
        //************************************************************************/
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            Ok(
                *lambda.get_value().get()? * (*self.x.get_value().get()? - *x.get_value().get()?)
                    - *self.y.get_value().get()?,
            )
        })?;

        cs.enforce(
            || "Check that y is correct",
            |lc| lc + lambda.get_variable(),
            |lc| lc + self.x.get_variable() - x.get_variable(),
            |lc| lc + y.get_variable() + self.y.get_variable(),
        );

        Ok(Self { x, y })
    }

    /// Adds a point supplied as linear combinations (over already-constrained
    /// selector variables and constants) to this point using the incomplete
    /// addition law. `other_value` holds the native `(x, y)` of that point and
    /// is used only in the witness closures. Assumes `self != +/- other`.
    pub fn add_incomplete_lc<CS>(
        &self,
        mut cs: CS,
        other_x_lc: &LinearCombination<Scalar>,
        other_y_lc: &LinearCombination<Scalar>,
        other_value: Option<(Scalar, Scalar)>,
    ) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        // lambda = (other.y - self.y) / (other.x - self.x)
        let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
            let (ox, oy) = other_value.ok_or(SynthesisError::AssignmentMissing)?;
            let x1 = *self.x.get_value().get()?;
            if ox == x1 {
                Ok(Scalar::ONE)
            } else {
                Ok((oy - *self.y.get_value().get()?) * (ox - x1).invert().unwrap())
            }
        })?;
        cs.enforce(
            || "Check that lambda is computed correctly",
            |lc| lc + lambda.get_variable(),
            |lc| lc + other_x_lc - self.x.get_variable(),
            |lc| lc + other_y_lc - self.y.get_variable(),
        );

        // x = lambda^2 - self.x - other.x
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
            let (ox, _) = other_value.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(*lambda.get_value().get()? * lambda.get_value().get()?
                - *self.x.get_value().get()?
                - ox)
        })?;
        cs.enforce(
            || "check that x is correct",
            |lc| lc + lambda.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| lc + x.get_variable() + self.x.get_variable() + other_x_lc,
        );

        // y = lambda * (self.x - x) - self.y
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            Ok(
                *lambda.get_value().get()? * (*self.x.get_value().get()? - *x.get_value().get()?)
                    - *self.y.get_value().get()?,
            )
        })?;
        cs.enforce(
            || "Check that y is correct",
            |lc| lc + lambda.get_variable(),
            |lc| lc + self.x.get_variable() - x.get_variable(),
            |lc| lc + y.get_variable() + self.y.get_variable(),
        );

        Ok(Self { x, y })
    }

    /// doubles the point; since this is called with a point not at infinity, it
    /// is guaranteed to be not infinity
    pub fn double_incomplete<CS>(&self, mut cs: CS) -> Result<Self, SynthesisError>
    where
        CS: ConstraintSystem<Scalar>,
    {
        // ASSUMES A = -3
        // lambda = (3 x^2 + a) / 2 * y

        let x_sq = self.x.square(cs.namespace(|| "x_sq"))?;

        let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
            let n = Scalar::from(3) * x_sq.get_value().get()? - Scalar::from(3);
            let d = Scalar::from(2) * *self.y.get_value().get()?;
            if d == Scalar::ZERO {
                Ok(Scalar::ONE)
            } else {
                Ok(n * d.invert().unwrap())
            }
        })?;
        cs.enforce(
            || "Check that lambda is computed correctly",
            |lc| lc + lambda.get_variable(),
            |lc| lc + (Scalar::from(2), self.y.get_variable()),
            |lc| lc - CS::one() - CS::one() - CS::one() + (Scalar::from(3), x_sq.get_variable()),
        );

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
            Ok(*lambda.get_value().get()? * *lambda.get_value().get()?
                - *self.x.get_value().get()?
                - *self.x.get_value().get()?)
        })?;

        cs.enforce(
            || "check that x is correct",
            |lc| lc + lambda.get_variable(),
            |lc| lc + lambda.get_variable(),
            |lc| lc + x.get_variable() + (Scalar::from(2), self.x.get_variable()),
        );

        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            Ok(
                *lambda.get_value().get()? * (*self.x.get_value().get()? - *x.get_value().get()?)
                    - *self.y.get_value().get()?,
            )
        })?;

        cs.enforce(
            || "Check that y is correct",
            |lc| lc + lambda.get_variable(),
            |lc| lc + self.x.get_variable() - x.get_variable(),
            |lc| lc + y.get_variable() + self.y.get_variable(),
        );

        Ok(Self { x, y })
    }

    /// If condition outputs a otherwise outputs b
    pub fn conditionally_select<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        a: &Self,
        b: &Self,
        condition: &Boolean,
    ) -> Result<Self, SynthesisError> {
        let x = conditionally_select(cs.namespace(|| "select x"), &a.x, &b.x, condition)?;
        let y = conditionally_select(cs.namespace(|| "select y"), &a.y, &b.y, condition)?;

        Ok(Self { x, y })
    }
}

#[cfg(test)]
mod tests {
    use algebra_utils::hex_to_ff;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use ff::Field;

    use super::*;
    use crate::types::Scalar;

    /// Generic width-`w` fixed-base scalar multiplication. This is the original
    /// (pre-specialization) implementation, kept verbatim as an equivalence
    /// oracle for the production `scalar_mul_fixed_base` (which is
    /// hardcoded to `w = 2`). See the module history / the plan for context.
    fn scalar_mul_fixed_base_windowed_generic<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        base: &ConstantPoint<Scalar>,
        s: &AllocatedNum<Scalar>,
        w: usize,
    ) -> Result<AllocatedPoint<Scalar>, SynthesisError> {
        assert!(w >= 1, "window width must be at least 1");
        let bits = s.to_bits_le(cs.namespace(|| "scalar_bits"))?;
        let nbits = bits.len();
        let num_windows = nbits.div_ceil(w);

        // Native precomputation (depends only on the constant base, so the
        // prover and verifier shape passes build identical tables).
        let b = base.recover_b();
        let z = ConstantPoint::derive_offset(b, base);
        // D_j = 2^{j*w} * base, K_j = 2^j * Z.
        let mut d_pows = Vec::with_capacity(num_windows);
        let mut k_offsets = Vec::with_capacity(num_windows);
        {
            let mut d = *base;
            let mut k = z;
            for _ in 0..num_windows {
                d_pows.push(d);
                k_offsets.push(k);
                for _ in 0..w {
                    d = d.double();
                }
                k = k.double();
            }
        }
        // K_total = sum_j K_j = (2^num_windows - 1) * Z.
        let mut k_total = k_offsets[0];
        for k in &k_offsets[1..] {
            k_total = k_total.add(k);
        }

        let mut acc: Option<AllocatedPointNonInfinity<Scalar>> = None;
        for j in 0..num_windows {
            let start = j * w;
            let wj = core::cmp::min(w, nbits - start);
            let table_size = 1usize << wj;

            // Table T_j[d] = d * D_j + K_j.
            let mut table = Vec::with_capacity(table_size);
            table.push(k_offsets[j]);
            for d in 1..table_size {
                table.push(table[d - 1].add(&d_pows[j]));
            }

            let wbits: Vec<&AllocatedBit> = (0..wj).map(|k| as_bit(&bits[start + k])).collect();

            // Bit-product variables for masks with popcount >= 2, built in
            // increasing mask order so `rest` (mask with its lowest set bit
            // cleared, always < mask) is available first.
            let mut prod: Vec<Option<AllocatedBit>> = (0..table_size).map(|_| None).collect();
            for mask in 1..table_size {
                if mask.count_ones() >= 2 {
                    let lb = mask.trailing_zeros() as usize;
                    let rest = mask & !(1usize << lb);
                    let a = if rest.count_ones() == 1 {
                        wbits[rest.trailing_zeros() as usize].clone()
                    } else {
                        prod[rest]
                            .clone()
                            .expect("lower-popcount product built first")
                    };
                    let p = AllocatedBit::and(
                        cs.namespace(|| format!("window {j} product {mask}")),
                        &a,
                        wbits[lb],
                    )?;
                    prod[mask] = Some(p);
                }
            }

            // Selection linear combinations via multilinear (Möbius) inversion:
            // coeff for mask m is sum_{sub subset of m} (-1)^{|m|-|sub|} T_j[sub].
            let mut x_lc = LinearCombination::<Scalar>::zero();
            let mut y_lc = LinearCombination::<Scalar>::zero();
            for m in 0..table_size {
                let (mut cx, mut cy) = (Scalar::ZERO, Scalar::ZERO);
                let mut sub = m;
                loop {
                    let even = (m.count_ones() - sub.count_ones()) % 2 == 0;
                    if even {
                        cx += table[sub].x;
                        cy += table[sub].y;
                    } else {
                        cx -= table[sub].x;
                        cy -= table[sub].y;
                    }
                    if sub == 0 {
                        break;
                    }
                    sub = (sub - 1) & m;
                }
                let var = if m == 0 {
                    CS::one()
                } else if m.count_ones() == 1 {
                    wbits[m.trailing_zeros() as usize].get_variable()
                } else {
                    prod[m].as_ref().unwrap().get_variable()
                };
                x_lc = x_lc + (cx, var);
                y_lc = y_lc + (cy, var);
            }

            // Native selected value for the witness closures (None in a shape
            // pass, where the closures are never evaluated).
            let selected = {
                let mut d = 0usize;
                let mut known = true;
                for k in 0..wj {
                    match wbits[k].get_value() {
                        Some(true) => d |= 1usize << k,
                        Some(false) => {}
                        None => {
                            known = false;
                            break;
                        }
                    }
                }
                known.then(|| (table[d].x, table[d].y))
            };

            acc = Some(match acc {
                None => {
                    // First window seeds the accumulator directly from the LC.
                    let ax = AllocatedNum::alloc(cs.namespace(|| "seed x"), || {
                        selected
                            .map(|v| v.0)
                            .ok_or(SynthesisError::AssignmentMissing)
                    })?;
                    let ay = AllocatedNum::alloc(cs.namespace(|| "seed y"), || {
                        selected
                            .map(|v| v.1)
                            .ok_or(SynthesisError::AssignmentMissing)
                    })?;
                    cs.enforce(
                        || "seed x matches selection",
                        |lc| lc + ax.get_variable(),
                        |lc| lc + CS::one(),
                        |lc| lc + &x_lc,
                    );
                    cs.enforce(
                        || "seed y matches selection",
                        |lc| lc + ay.get_variable(),
                        |lc| lc + CS::one(),
                        |lc| lc + &y_lc,
                    );
                    AllocatedPointNonInfinity::new(ax, ay)
                }
                Some(prev) => prev.add_incomplete_lc(
                    cs.namespace(|| format!("window {j} add")),
                    &x_lc,
                    &y_lc,
                    selected,
                )?,
            });
        }

        let acc = acc.expect("at least one window");

        // Remove the accumulated offset with one complete addition of the
        // constant -K_total. The complete law yields infinity when
        // s == 0 (mod the group order), matching `scalar_mul` for that case.
        let zero = alloc_zero(cs.namespace(|| "zero"))?;
        let neg_k = k_total.negate();
        let minus_k = AllocatedPoint {
            x: alloc_constant(cs.namespace(|| "minus offset x"), neg_k.x)?,
            y: alloc_constant(cs.namespace(|| "minus offset y"), neg_k.y)?,
            is_infinity: zero.clone(),
        };
        let acc_point = acc.to_allocated_point(&zero)?;
        acc_point.add(cs.namespace(|| "subtract offset"), &minus_k)
    }

    fn generator() -> ConstantPoint<Scalar> {
        ConstantPoint::new(
            hex_to_ff("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            hex_to_ff("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        )
    }

    /// Little-endian bit decomposition of `s` from its canonical representation.
    fn bits_le(s: &Scalar) -> Vec<bool> {
        let repr = s.to_repr();
        let bytes = repr.as_ref();
        let mut bits = Vec::with_capacity(bytes.len() * 8);
        for byte in bytes {
            for i in 0..8 {
                bits.push((byte >> i) & 1 == 1);
            }
        }
        bits
    }

    /// Complete-group-law reference for `s * base`, interpreting `s` as its full
    /// integer value (matching the gadget). `None` denotes the point at infinity.
    fn native_mul(base: &ConstantPoint<Scalar>, s: &Scalar) -> Option<ConstantPoint<Scalar>> {
        let complete_add = |p: Option<ConstantPoint<Scalar>>, q: &ConstantPoint<Scalar>| match p {
            None => Some(*q),
            Some(pp) => {
                if pp.x == q.x {
                    if pp.y == q.y {
                        Some(pp.double())
                    } else {
                        None // p == -q
                    }
                } else {
                    Some(pp.add(q))
                }
            }
        };

        let mut result: Option<ConstantPoint<Scalar>> = None;
        let mut addend = *base;
        for bit in bits_le(s) {
            if bit {
                result = complete_add(result, &addend);
            }
            addend = addend.double();
        }
        result
    }

    fn run_fixed(
        base: &ConstantPoint<Scalar>,
        s: Scalar,
    ) -> (TestConstraintSystem<Scalar>, AllocatedPoint<Scalar>) {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let s_alloc = AllocatedNum::alloc(cs.namespace(|| "s"), || Ok(s)).unwrap();
        let res =
            AllocatedPoint::scalar_mul_fixed_base(cs.namespace(|| "mul"), base, &s_alloc).unwrap();
        (cs, res)
    }

    fn run_variable(
        base: &ConstantPoint<Scalar>,
        s: Scalar,
    ) -> (TestConstraintSystem<Scalar>, AllocatedPoint<Scalar>) {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let x = AllocatedNum::alloc(cs.namespace(|| "bx"), || Ok(base.x)).unwrap();
        let y = AllocatedNum::alloc(cs.namespace(|| "by"), || Ok(base.y)).unwrap();
        let is_infinity = alloc_zero(cs.namespace(|| "binf")).unwrap();
        let point = AllocatedPoint { x, y, is_infinity };
        let s_alloc = AllocatedNum::alloc(cs.namespace(|| "s"), || Ok(s)).unwrap();
        let res = point.scalar_mul(cs.namespace(|| "mul"), &s_alloc).unwrap();
        (cs, res)
    }

    /// P-256 group order n, and a full-width and boundary-aligned test value.
    fn test_scalars() -> Vec<Scalar> {
        let n: Scalar =
            hex_to_ff("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        vec![
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::from(2),
            Scalar::from(3),
            Scalar::from(0xdead_beef_u64),
            hex_to_ff("123456789abcdef0fedcba9876543210deadbeefcafebabe0123456789abcdef"),
            n - Scalar::ONE,
            n,
            n + Scalar::ONE,
            hex_to_ff("8000000000000000000000000000000000000000000000000000000000000000"),
            Scalar::from(0x1230_u64),                // low nibble zero
            Scalar::from(256_u64),                   // 2^8 (window boundary)
            Scalar::from(0xffff_ffff_ffff_ffff_u64), // run of set bits
            Scalar::from(0x5555_5555_u64),           // alternating windows
            hex_to_ff("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00"), // low byte zero
        ]
    }

    #[test]
    fn fixed_base_matches_native() {
        let g = generator();
        for s in test_scalars() {
            let (cs, res) = run_fixed(&g, s);
            assert!(cs.is_satisfied(), "unsatisfied for s = {s:?}");
            match native_mul(&g, &s) {
                Some(p) => {
                    assert_eq!(res.x.get_value().unwrap(), p.x, "x mismatch s = {s:?}");
                    assert_eq!(res.y.get_value().unwrap(), p.y, "y mismatch s = {s:?}");
                    assert_eq!(res.is_infinity.get_value().unwrap(), Scalar::ZERO);
                }
                None => {
                    assert_eq!(res.x.get_value().unwrap(), Scalar::ZERO);
                    assert_eq!(res.y.get_value().unwrap(), Scalar::ZERO);
                    assert_eq!(res.is_infinity.get_value().unwrap(), Scalar::ONE);
                }
            }
        }
    }

    #[test]
    fn fixed_base_matches_variable_base() {
        let g = generator();
        for s in test_scalars() {
            let (cs_f, res_f) = run_fixed(&g, s);
            let (cs_v, res_v) = run_variable(&g, s);
            assert!(cs_f.is_satisfied() && cs_v.is_satisfied());
            assert_eq!(res_f.x.get_value(), res_v.x.get_value(), "x s = {s:?}");
            assert_eq!(res_f.y.get_value(), res_v.y.get_value(), "y s = {s:?}");
            assert_eq!(
                res_f.is_infinity.get_value(),
                res_v.is_infinity.get_value(),
                "is_infinity s = {s:?}"
            );
        }
    }

    #[test]
    fn fixed_base_constraint_count() {
        let g = generator();
        let s = Scalar::from(0xdead_beef_u64);
        let (cs_f, _) = run_fixed(&g, s);
        let (cs_v, _) = run_variable(&g, s);
        let fixed = cs_f.num_constraints();
        let variable = cs_v.num_constraints();
        println!("fixed-base constraints: {fixed}, variable-base constraints: {variable}");
        assert!(
            fixed <= 1600,
            "fixed-base constraint count regressed: {fixed}"
        );
        assert!(
            fixed < variable,
            "fixed-base ({fixed}) not cheaper than variable-base ({variable})"
        );
    }

    #[test]
    fn fixed_base_window_sweep() {
        let g = generator();
        let sample = [
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::from(0xdead_beef_u64),
            hex_to_ff("123456789abcdef0fedcba9876543210deadbeefcafebabe0123456789abcdef"),
        ];
        let mut counts: Vec<(usize, usize)> = Vec::new();
        for w in 1..=4usize {
            for &s in &sample {
                let mut cs = TestConstraintSystem::<Scalar>::new();
                let s_alloc = AllocatedNum::alloc(cs.namespace(|| "s"), || Ok(s)).unwrap();
                let res =
                    scalar_mul_fixed_base_windowed_generic(cs.namespace(|| "mul"), &g, &s_alloc, w)
                        .unwrap();
                assert!(cs.is_satisfied(), "unsatisfied w={w} s={s:?}");
                match native_mul(&g, &s) {
                    Some(p) => {
                        assert_eq!(res.x.get_value().unwrap(), p.x, "w={w} s={s:?}");
                        assert_eq!(res.y.get_value().unwrap(), p.y, "w={w} s={s:?}");
                    }
                    None => assert_eq!(res.is_infinity.get_value().unwrap(), Scalar::ONE),
                }
            }
            // Measure with a fixed representative scalar.
            let mut cs = TestConstraintSystem::<Scalar>::new();
            let s_alloc =
                AllocatedNum::alloc(cs.namespace(|| "s"), || Ok(Scalar::from(0xdead_beef_u64)))
                    .unwrap();
            scalar_mul_fixed_base_windowed_generic(cs.namespace(|| "mul"), &g, &s_alloc, w)
                .unwrap();
            counts.push((w, cs.num_constraints()));
        }
        println!("window-width constraint counts: {counts:?}");
        let w2 = counts.iter().find(|(w, _)| *w == 2).unwrap().1;
        assert!(w2 <= 850, "w=2 count {w2} over budget");
        assert!(
            counts.iter().all(|(_, c)| w2 <= *c),
            "w=2 is not the minimum: {counts:?}"
        );
    }

    /// The specialized production gadget and the generic reference at `w = 2`
    /// must produce identical result points on every representative scalar.
    #[test]
    fn optimized_matches_generic_w2() {
        let g = generator();
        for s in test_scalars() {
            // Production (w=2-specialized) path.
            let (cs_opt, res_opt) = run_fixed(&g, s);
            // Generic reference forced to w=2.
            let mut cs_gen = TestConstraintSystem::<Scalar>::new();
            let s_alloc = AllocatedNum::alloc(cs_gen.namespace(|| "s"), || Ok(s)).unwrap();
            let res_gen =
                scalar_mul_fixed_base_windowed_generic(cs_gen.namespace(|| "mul"), &g, &s_alloc, 2)
                    .unwrap();

            assert!(cs_opt.is_satisfied(), "optimized unsatisfied s={s:?}");
            assert!(cs_gen.is_satisfied(), "generic unsatisfied s={s:?}");
            assert_eq!(res_opt.x.get_value(), res_gen.x.get_value(), "x s={s:?}");
            assert_eq!(res_opt.y.get_value(), res_gen.y.get_value(), "y s={s:?}");
            assert_eq!(
                res_opt.is_infinity.get_value(),
                res_gen.is_infinity.get_value(),
                "is_infinity s={s:?}"
            );
        }
    }

    /// The specialization must emit the *same* R1CS as the generic w=2 path, not
    /// merely the same result: identical constraint count proves the w=2
    /// rewrite is cost-preserving.
    #[test]
    fn optimized_constraint_count_matches_generic_w2() {
        let g = generator();
        let s = Scalar::from(0xdead_beef_u64);

        let (cs_opt, _) = run_fixed(&g, s);

        let mut cs_gen = TestConstraintSystem::<Scalar>::new();
        let s_alloc = AllocatedNum::alloc(cs_gen.namespace(|| "s"), || Ok(s)).unwrap();
        scalar_mul_fixed_base_windowed_generic(cs_gen.namespace(|| "mul"), &g, &s_alloc, 2)
            .unwrap();

        assert_eq!(
            cs_opt.num_constraints(),
            cs_gen.num_constraints(),
            "optimized w=2 constraint count differs from generic w=2"
        );
    }

    /// Inspectable check of the 2-bit multilinear selection formula
    ///   T = T0 + b0*(T1-T0) + b1*(T2-T0) + b0*b1*(T3-T1-T2+T0)
    /// against a ground-truth table lookup for all four `(b0, b1)` patterns.
    /// A wrong coefficient in the production `x_lc`/`y_lc` would break this.
    #[test]
    fn optimized_selection_exhaustive() {
        let g = generator();
        let z = ConstantPoint::derive_offset(g.recover_b(), &g);
        // A window table T[d] = d * base + Z (first window: D_0 = base, K_0 = Z).
        let t0 = z;
        let t1 = t0.add(&g);
        let t2 = t1.add(&g);
        let t3 = t2.add(&g);
        let t = [t0, t1, t2, t3];

        for d in 0..4usize {
            let b0 = Scalar::from((d & 1) as u64);
            let b1 = Scalar::from(((d >> 1) & 1) as u64);

            let sel_x = t0.x
                + b0 * (t1.x - t0.x)
                + b1 * (t2.x - t0.x)
                + b0 * b1 * (t3.x - t1.x - t2.x + t0.x);
            let sel_y = t0.y
                + b0 * (t1.y - t0.y)
                + b1 * (t2.y - t0.y)
                + b0 * b1 * (t3.y - t1.y - t2.y + t0.y);

            assert_eq!(sel_x, t[d].x, "x selection wrong for d={d}");
            assert_eq!(sel_y, t[d].y, "y selection wrong for d={d}");
        }
    }
}
