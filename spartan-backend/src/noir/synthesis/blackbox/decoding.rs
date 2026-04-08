use acir::FieldElement;
use acir::circuit::opcodes::FunctionInput;
use acir::circuit::opcodes::FunctionInput::Constant;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use ff::Field;

use crate::noir::scalar_conversion::to_spartan_scalar;
use crate::noir::synthesis::allocation_support::{AllocatedWire, WitnessMap};
use crate::noir::synthesis::blackbox::range::{field_into_allocated_bits_le, powers_of_two};
use crate::types::Scalar;

/// Decodes inputs into allocated byte variables and enforces each is 8-bit.
pub(crate) fn decode_bytes_constrained<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    inputs: &[FunctionInput<FieldElement>],
    label: &str,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    let mut out = Vec::with_capacity(inputs.len());

    for (i, input) in inputs.iter().enumerate() {
        let byte_num = match input {
            Constant(fe) => alloc_constant(
                &mut cs.namespace(|| format!("{label}_const_byte_{i}")),
                to_spartan_scalar::<Scalar>(fe),
            )?,
            FunctionInput::Witness(w) => {
                let wire = allocation_store
                    .get(&w.witness_index())
                    .ok_or(SynthesisError::AssignmentMissing)?;
                wire.allocation
                    .as_ref()
                    .map_err(|_| SynthesisError::AssignmentMissing)?
                    .clone()
            }
        };

        enforce_is_8bit(
            &mut cs.namespace(|| format!("{label}_range_byte_{i}")),
            &byte_num,
            i as u32,
        )?;

        out.push(byte_num);
    }

    Ok(out)
}

/// Recompose x = sum_{i=0..31} bytes[i] * 256^i (little-endian), enforced by constraint.
pub(crate) fn recompose_u256_le<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    bytes: &[AllocatedNum<Scalar>],
    label: &str,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    if bytes.len() != 32 {
        return Err(SynthesisError::Unsatisfiable);
    }

    let value_opt = {
        let mut coeff = Scalar::ONE;
        let radix = scalar_256();
        let mut acc = Scalar::ZERO;
        let mut complete = true;

        for b in bytes {
            if let Some(v) = b.get_value() {
                acc += coeff * v;
                coeff *= radix;
            } else {
                complete = false;
                break;
            }
        }

        if complete { Some(acc) } else { None }
    };

    let recomposed =
        AllocatedNum::alloc(cs.namespace(|| format!("{label}_recomposed_u256")), || {
            value_opt.ok_or(SynthesisError::AssignmentMissing)
        })?;

    let mut coeff = Scalar::ONE;
    let radix = scalar_256();
    let mut lc = LinearCombination::<Scalar>::zero();
    for b in bytes {
        lc = lc + (coeff, b.get_variable());
        coeff *= radix;
    }

    cs.enforce(
        || format!("{label}: radix-256 recomposition"),
        |lc_in| lc_in + &lc,
        |lc_in| lc_in + CS::one(),
        |lc_in| lc_in + recomposed.get_variable(),
    );

    Ok(recomposed)
}

fn alloc_constant<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    c: Scalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let num = AllocatedNum::alloc(cs.namespace(|| "alloc_constant"), || Ok(c))?;
    cs.enforce(
        || "enforce constant equality",
        |lc| lc + num.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + (c, CS::one()),
    );
    Ok(num)
}

fn enforce_is_8bit<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    byte: &AllocatedNum<Scalar>,
    witness_index_for_labels: u32,
) -> Result<(), SynthesisError> {
    let bits = field_into_allocated_bits_le(
        &mut cs.namespace(|| "decompose_8bits"),
        byte.get_value(),
        8,
        witness_index_for_labels,
    )?;

    for (j, bit) in bits.iter().enumerate() {
        // bit * (bit - 1) = 0
        cs.enforce(
            || format!("bit_{j}_boolean"),
            |lc| lc + bit.get_variable(),
            |lc| lc + bit.get_variable() - CS::one(),
            |lc| lc,
        );
    }

    let p2 = powers_of_two::<Scalar>(8);
    let bits_lc = bits
        .iter()
        .zip(p2.into_iter())
        .fold(LinearCombination::<Scalar>::zero(), |acc, (bit, coeff)| {
            acc + (coeff, bit.get_variable())
        });

    // sum(bit_i * 2^i) == byte
    cs.enforce(
        || "8-bit recomposition",
        |lc| lc + &bits_lc,
        |lc| lc + CS::one(),
        |lc| lc + byte.get_variable(),
    );

    Ok(())
}

fn scalar_256() -> Scalar {
    let mut r = Scalar::ONE;
    for _ in 0..8 {
        r = r + r;
    }
    r
}
