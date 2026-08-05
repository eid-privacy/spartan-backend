use acir::{
    FieldElement,
    native_types::{Expression, Witness},
};
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError, num::AllocatedNum};
use ff::Field;

use crate::{
    noir::{
        scalar_conversion::to_spartan_scalar,
        synthesis::allocation_support::{AllocatedWire, WitnessMap},
    },
    types::Scalar,
};

fn resolve<'a>(
    allocation_store: &'a WitnessMap<AllocatedWire<Scalar>>,
    witness: &Witness,
) -> Result<&'a AllocatedNum<Scalar>, SynthesisError> {
    let wire = allocation_store
        .get(&witness.witness_index())
        .ok_or(SynthesisError::AssignmentMissing)?;
    wire.allocation
        .as_ref()
        .map_err(|_| SynthesisError::AssignmentMissing)
}

pub(crate) fn handle_assert_zero<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    expr: &Expression<FieldElement>,
) -> Result<(), SynthesisError> {
    let multiplicands = &expr.mul_terms;
    let linear_combinations = &expr.linear_combinations;
    let constant = expr.q_c;

    // R1CS constraints are A * B = C. ACIR's AssertZero expression can carry
    // multiple bilinear (`q * w_i * w_j`) terms, which cannot be folded into a
    // single A * B = C constraint. We materialise each such product as an
    // intermediate witness `m_k = q_k * w_ik * w_jk` via a dedicated quadratic
    // constraint, then enforce the final assertion as a single linear
    // constraint summing `Σ m_k + Σ q * w + q_c = 0`.
    let mut lin_comb = LinearCombination::<Scalar>::zero();

    for (k, (coeff, w_i, w_j)) in multiplicands.iter().enumerate() {
        let coeff_scalar = to_spartan_scalar(coeff);
        let a = resolve(allocation_store, w_i)?;
        let b = resolve(allocation_store, w_j)?;

        let m_value = match (a.get_value(), b.get_value()) {
            (Some(av), Some(bv)) => Some(coeff_scalar * av * bv),
            _ => None,
        };
        let m = AllocatedNum::alloc(cs.namespace(|| format!("mul term {k}")), || {
            m_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce (coeff * a) * b = m, i.e. A = coeff·a, B = b, C = m.
        cs.enforce(
            || format!("mul term {k} = coeff * a * b"),
            |lc| lc + (coeff_scalar, a.get_variable()),
            |lc| lc + b.get_variable(),
            |lc| lc + m.get_variable(),
        );

        lin_comb = lin_comb + m.get_variable();
    }

    for (field_element, witness) in linear_combinations {
        tracing::debug!("LC term: {:?} * {:?}", field_element, witness);
        let allocated_num = resolve(allocation_store, witness)?;
        lin_comb = lin_comb
            + (
                to_spartan_scalar(field_element),
                allocated_num.get_variable(),
            );
    }

    lin_comb = lin_comb + (to_spartan_scalar(&constant), CS::one());

    cs.enforce(
        || "enforce linear combination",
        |lc| lc + &lin_comb,
        |lc| lc + CS::one(),
        |lc| lc,
    );

    // Local sanity check: if all witness values are known, verify the
    // expression actually evaluates to zero. This makes mis-handled opcodes
    // localisable far more cheaply than waiting for the global sumcheck.
    if std::env::var("SPARTAN_BACKEND_CHECK_ASSERT_ZERO").is_ok() {
        let mut acc = Scalar::ZERO;
        let mut all_known = true;
        for (coeff, w_i, w_j) in multiplicands.iter() {
            let coeff_s = to_spartan_scalar::<Scalar>(coeff);
            let av = resolve(allocation_store, w_i)?.get_value();
            let bv = resolve(allocation_store, w_j)?.get_value();
            match (av, bv) {
                (Some(a), Some(b)) => acc += coeff_s * a * b,
                _ => {
                    all_known = false;
                    break;
                }
            }
        }
        if all_known {
            for (coeff, w) in linear_combinations.iter() {
                let coeff_s = to_spartan_scalar::<Scalar>(coeff);
                match resolve(allocation_store, w)?.get_value() {
                    Some(v) => acc += coeff_s * v,
                    None => {
                        all_known = false;
                        break;
                    }
                }
            }
        }
        if all_known {
            acc += to_spartan_scalar::<Scalar>(&constant);
            if acc != Scalar::ZERO {
                tracing::error!(
                    "AssertZero violated: {:?} (q_c={:?}, residual={:?})",
                    expr,
                    constant,
                    acc
                );
                for (coeff, w_i, w_j) in multiplicands.iter() {
                    let av = resolve(allocation_store, w_i)?.get_value();
                    let bv = resolve(allocation_store, w_j)?.get_value();
                    tracing::error!(
                        "  mul: {:?} * w{} (={:?}) * w{} (={:?})",
                        coeff,
                        w_i.witness_index(),
                        av,
                        w_j.witness_index(),
                        bv
                    );
                }
                for (coeff, w) in linear_combinations.iter() {
                    let v = resolve(allocation_store, w)?.get_value();
                    tracing::error!("  lin: {:?} * w{} (={:?})", coeff, w.witness_index(), v);
                }
            }
        }
    }

    Ok(())
}
