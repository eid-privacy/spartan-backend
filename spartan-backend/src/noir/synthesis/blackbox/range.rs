use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::{PrimeField, PrimeFieldBits};

// this is copied over from bellpepper_core gadgets/boolean.rs except for the "take" in the last
// assignment. This is meant as a way to avoid allocating one wire per bit when all we want to do
// is a range check (and hence bit_size bits is enough to enforce the range).
pub fn field_into_allocated_bits_le<Scalar, CS>(
    cs: &mut CS,
    value: Option<Scalar>,
    bit_size: usize,
    witness_index: u32,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
    Scalar: PrimeField,
    Scalar: PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    // Deconstruct in big-endian bit order
    let values = match value {
        Some(ref value) => {
            let field_char = Scalar::char_le_bits();
            let mut field_char = field_char.into_iter().rev();

            let mut tmp = Vec::with_capacity(Scalar::NUM_BITS as usize);

            let mut found_one = false;
            for b in value.to_le_bits().into_iter().rev() {
                // Skip leading bits
                found_one |= field_char.next().unwrap();
                if !found_one {
                    continue;
                }

                tmp.push(Some(b));
            }

            assert_eq!(tmp.len(), Scalar::NUM_BITS as usize);

            tmp
        }
        None => vec![None; Scalar::NUM_BITS as usize],
    };

    // Allocate in little-endian order
    let bits = values
        .into_iter()
        .rev()
        .take(bit_size)
        .map(|b| optional_boolean_to_ff(b))
        .enumerate()
        .map(|(i, b)| {
            AllocatedNum::alloc(
                cs.namespace(|| format!("bit {} of {}", i, witness_index)),
                || optional_ff_to_result(b),
            )
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
}

fn optional_boolean_to_ff<Scalar: PrimeField>(boolean: Option<bool>) -> Option<Scalar> {
    match boolean {
        Some(b) => Some(if b { Scalar::ONE } else { Scalar::ZERO }),
        None => None,
    }
}

fn optional_ff_to_result<Scalar: PrimeField>(
    maybe_e: Option<Scalar>,
) -> Result<Scalar, SynthesisError> {
    match maybe_e {
        Some(e) => Ok(e),
        None => Err(SynthesisError::AssignmentMissing),
    }
}

// TODO: make static/pre-computed somehow
pub fn powers_of_two<Scalar: PrimeField>(n: usize) -> Vec<Scalar> {
    let mut powers = Vec::<Scalar>::with_capacity(n);
    let mut current = Scalar::ONE;
    powers.push(current);

    for _p in 1..n {
        current = current + current;
        powers.push(current);
    }

    powers
}
