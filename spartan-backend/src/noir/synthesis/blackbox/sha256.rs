use acir::{FieldElement, circuit::opcodes::FunctionInput, native_types::Witness};
use bellpepper::gadgets::{sha256::sha256_compression_function, uint32::UInt32};
use bellpepper_core::{
    ConstraintSystem, LinearCombination, SynthesisError,
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
};
use ff::{Field, PrimeFieldBits};

use crate::{
    noir::synthesis::{
        allocation_support::{AllocatedWire, WitnessMap},
        blackbox::function_input::{allocate_or_get, get_witness_assignment},
    },
    types::Scalar,
};

pub fn handle_sha256_compression<CS: ConstraintSystem<Scalar>>(
    allocation_store: &WitnessMap<AllocatedWire<Scalar>>,
    cs: &mut CS,
    inputs: &[FunctionInput<FieldElement>; 16],
    hash_values: &[FunctionInput<FieldElement>; 8],
    outputs: &[Witness; 8],
) -> Result<(), SynthesisError> {
    let mut input_bits: Vec<Boolean> = Vec::with_capacity(512);
    for (i, fi) in inputs.iter().enumerate() {
        let allocated = allocate_or_get(
            allocation_store,
            &mut cs.namespace(|| format!("input word {i}")),
            fi,
        )?;
        let bits_be =
            decompose_u32_be(cs.namespace(|| format!("input word {i} bits")), &allocated)?;
        input_bits.extend(bits_be);
    }

    let mut current_hash: Vec<UInt32> = Vec::with_capacity(8);
    for (i, fi) in hash_values.iter().enumerate() {
        let allocated = allocate_or_get(
            allocation_store,
            &mut cs.namespace(|| format!("hash word {i}")),
            fi,
        )?;
        let bits_be = decompose_u32_be(cs.namespace(|| format!("hash word {i} bits")), &allocated)?;
        current_hash.push(UInt32::from_bits_be(&bits_be));
    }

    let compressed = sha256_compression_function(
        cs.namespace(|| "sha256 compression"),
        &input_bits,
        &current_hash,
    )?;

    for (i, word) in compressed.into_iter().enumerate() {
        let expected = get_witness_assignment(allocation_store, &outputs[i])?;
        let bits_le = word.into_bits();
        let mut lc = LinearCombination::<Scalar>::zero();
        let mut coeff = Scalar::ONE;
        for b in bits_le.iter() {
            lc = lc + &b.lc(CS::one(), coeff);
            coeff = coeff.double();
        }
        cs.enforce(
            || format!("output word {i} equality"),
            |z| z + &lc,
            |z| z + CS::one(),
            |z| z + expected.get_variable(),
        );
    }

    Ok(())
}

fn decompose_u32_be<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &AllocatedNum<Scalar>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let le_bits_opt: Option<Vec<bool>> = value
        .get_value()
        .map(|v| v.to_le_bits().into_iter().take(32).collect());

    let mut bits_le: Vec<AllocatedBit> = Vec::with_capacity(32);
    let mut lc = LinearCombination::<Scalar>::zero();
    let mut coeff = Scalar::ONE;
    for i in 0..32 {
        let bit_val = le_bits_opt.as_ref().map(|bs| bs[i]);
        let b = AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), bit_val)?;
        lc = lc + (coeff, b.get_variable());
        bits_le.push(b);
        coeff = coeff.double();
    }
    cs.enforce(
        || "bits compose to value",
        |z| z + &lc,
        |z| z + CS::one(),
        |z| z + value.get_variable(),
    );

    Ok(bits_le.into_iter().rev().map(Boolean::from).collect())
}
