//! Native affine elliptic-curve arithmetic over the circuit field, used to
//! precompute constant points (multiples of a fixed base, nothing-up-my-sleeve
//! offsets) at synthesis time.
//!
//! The formulas here MUST match the ones enforced in-circuit by
//! `AllocatedPoint`/`AllocatedPointNonInfinity` (short Weierstrass, a = -3,
//! chord-and-tangent over affine coordinates), so that a precomputed value is
//! bit-for-bit identical to what the gadget would compute. We therefore do NOT
//! use the `p256`/`halo2curves` group API here.

use ff::PrimeField;

/// An affine point with constant coordinates on a short-Weierstrass curve with
/// `a = -3`, over the circuit field `F`. Never the point at infinity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConstantPoint<F: PrimeField> {
    pub x: F,
    pub y: F,
}

impl<F: PrimeField> ConstantPoint<F> {
    pub const fn new(x: F, y: F) -> Self {
        Self { x, y }
    }

    /// `(x, -y)`
    pub fn negate(&self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
        }
    }

    /// Recovers `b = y^2 - x^3 + 3x` from the point itself. The group-law
    /// formulas never reference `b`, so recovering it makes the gadget
    /// semantically identical to the variable-base ladder for ANY constant
    /// input point (not just the P-256 generator).
    pub fn recover_b(&self) -> F {
        let x = self.x;
        self.y * self.y - x * x * x + F::from(3) * x
    }

    /// Tangent doubling with `a = -3`: `lambda = (3x^2 - 3) / (2y)`.
    /// Panics if `y == 0` (an order-2 point); the dispatcher guarantees
    /// `y != 0`, and the doubling chain of an odd-order point never produces
    /// `y == 0`.
    pub fn double(&self) -> Self {
        let two_y = self.y + self.y;
        assert!(
            bool::from(!two_y.is_zero()),
            "ConstantPoint::double called on a point with y == 0"
        );
        let lambda = (F::from(3) * self.x * self.x - F::from(3)) * two_y.invert().unwrap();
        let x = lambda * lambda - self.x - self.x;
        let y = lambda * (self.x - x) - self.y;
        Self { x, y }
    }

    /// Chord addition: `lambda = (y2 - y1) / (x2 - x1)`. Panics if
    /// `x1 == x2` (a degenerate case: either doubling or the point at
    /// infinity). See the fixed-base soundness note in `allocated_point.rs`:
    /// this is unreachable without knowing the discrete log of the offset
    /// point, so a panic here signals a construction bug rather than a
    /// runtime-reachable input.
    pub fn add(&self, other: &Self) -> Self {
        let dx = other.x - self.x;
        assert!(
            bool::from(!dx.is_zero()),
            "ConstantPoint::add on points sharing an x-coordinate (degenerate)"
        );
        let lambda = (other.y - self.y) * dx.invert().unwrap();
        let x = lambda * lambda - self.x - other.x;
        let y = lambda * (self.x - x) - self.y;
        Self { x, y }
    }

    /// Deterministic "nothing-up-my-sleeve" point with unknown discrete log
    /// relative to any given base, on the curve `y^2 = x^3 - 3x + b`. Uses
    /// try-and-increment: for `x = 1, 2, 3, ...` take the first `x` for which
    /// `x^3 - 3x + b` is a square and `x != avoid.x` (so the result is never
    /// `+/- avoid`), picking the canonical (even) square root. Panics after a
    /// bounded number of attempts — statistically unreachable (~half of all
    /// `x` yield a point).
    pub fn derive_offset(b: F, avoid: &Self) -> Self {
        let mut x = F::ONE;
        for _ in 0..1000u32 {
            let rhs = x * x * x - F::from(3) * x + b;
            if let Some(mut y) = Option::<F>::from(rhs.sqrt()) {
                if bool::from(y.is_odd()) {
                    y = -y;
                }
                if x != avoid.x {
                    return Self { x, y };
                }
            }
            x += F::ONE;
        }
        panic!("derive_offset: no suitable point found within the attempt bound");
    }
}

#[cfg(test)]
mod tests {
    use algebra_utils::hex_to_ff;

    use super::*;
    use crate::types::Scalar;

    fn generator() -> ConstantPoint<Scalar> {
        ConstantPoint::new(
            hex_to_ff("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            hex_to_ff("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        )
    }

    #[test]
    fn recover_b_matches_p256() {
        let b: Scalar =
            hex_to_ff("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
        assert_eq!(generator().recover_b(), b);
    }

    #[test]
    fn double_matches_known_2g() {
        let two_g = ConstantPoint::new(
            hex_to_ff("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"),
            hex_to_ff("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"),
        );
        assert_eq!(generator().double(), two_g);
    }

    #[test]
    fn add_matches_known_3g() {
        let g = generator();
        let three_g = ConstantPoint::new(
            hex_to_ff("5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"),
            hex_to_ff("8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"),
        );
        assert_eq!(g.add(&g.double()), three_g);
    }

    #[test]
    fn derive_offset_is_on_curve_and_deterministic() {
        let g = generator();
        let b = g.recover_b();
        let z = ConstantPoint::derive_offset(b, &g);
        // on the curve
        assert_eq!(z.recover_b(), b);
        // distinct from the base (so Z != +/- base)
        assert_ne!(z.x, g.x);
        // deterministic
        assert_eq!(z, ConstantPoint::derive_offset(b, &g));
    }
}
