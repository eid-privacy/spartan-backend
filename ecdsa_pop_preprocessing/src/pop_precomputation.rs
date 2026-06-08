use halo2curves::secp256r1::Secp256r1Affine;
use halo2curves::CurveAffine;
use halo2curves::ff::Field;
use group::Curve;
use num_bigint::BigUint;
use spartan2::provider::P256HyraxEngine;
use spartan2::traits::Engine;
use algebra_utils::{big_to_ff, ff_to_big, hex_to_ff};
use algebra_utils::ecdsa::Point;
use crate::FieldRepr;

pub(crate) fn compute_RTU_from_hex(
    q: &Point<FieldRepr>,
    r: &FieldRepr,
    s: &FieldRepr,
    digest : &str,
) -> (Point<FieldRepr>, Point<FieldRepr>, Point<FieldRepr>) {
    let (R, T, U)  = compute_RTU(
        &from_field_repr(q),
        &field_repr_to_biguint(r),
        &field_repr_to_biguint(s),
        &digest
    );

    (
        to_field_repr(&R),
        to_field_repr(&T),
        to_field_repr(&U),
    )
}

fn field_repr_to_biguint(f: &FieldRepr) -> BigUint {
    BigUint::from_bytes_be(f)
}

fn from_field_repr(p: &Point<FieldRepr>) -> Point<BigUint> {
    Point {
        x: BigUint::from_bytes_be(&p.x),
        y: BigUint::from_bytes_be(&p.y),
    }
}

fn to_field_repr(p: &Point<BigUint>) -> Point<FieldRepr> {
    Point {
        x: p.x.to_bytes_be().try_into().expect("x must be 32 bytes"),
        y: p.y.to_bytes_be().try_into().expect("y must be 32 bytes"),
    }
}

fn compute_RTU(
    q: &Point<BigUint>,
    r: &BigUint,
    s: &BigUint,
    digest : &str,
) -> (Point<BigUint>, Point<BigUint>, Point<BigUint>) {
    // Aliases for the P256 fields, might get renamed to match other pieces of code
    type Fq = <P256HyraxEngine as Engine>::Scalar;
    type Fp = <P256HyraxEngine as Engine>::Base;

    // TODO: check endian-ness of Noir representation
    let r = big_to_ff::<Fq>(r);
    let s = big_to_ff::<Fq>(s);
    let d = hex_to_ff::<Fq>(digest);

    let G = <P256HyraxEngine as Engine>::GE::generator();

    let x = big_to_ff::<Fp>(&q.x);
    let y = big_to_ff::<Fp>(&q.y);
    let Q = Secp256r1Affine::from_xy(x, y).unwrap();

    assert_ne!(s, Fq::ZERO);
    let s_inv = s.invert().unwrap();

    // Recover R as a point
    let u = d * s_inv;
    let v = r * s_inv;
    let R = (G * u + Q * v).to_affine();
    assert_eq!(ff_to_big::<Fq>(&r), ff_to_big::<Fp>(&R.x));  // Signature verifies

    // Compute T and U for the modified verification equation
    assert_ne!(s, Fq::ZERO);
    let r_inv = r.invert().unwrap();
    let u = -d * r_inv;
    let T = (R * r_inv).to_affine();
    let U = (G * u).to_affine();

    (
        to_point(&R),
        to_point(&T),
        to_point(&U),
    )
}

fn to_point(p: &Secp256r1Affine) -> Point<BigUint> {
    Point {
        x: ff_to_big(&p.x),
        y: ff_to_big(&p.y),
    }
}