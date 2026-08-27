use bellpepper_core::{ConstraintSystem, SynthesisError, boolean::AllocatedBit};
use ff::{PrimeField, PrimeFieldBits};

// this is copied over from bellpepper_core gadgets/boolean.rs except for the "take" in the last
// assignment. This is meant as a way to avoid allocating one wire per bit when all we want to do
// is a range check (and hence bit_size bits is enough to enforce the range).
pub fn field_into_allocated_bits_le<Scalar, CS>(
    cs: &mut CS,
    value: Option<Scalar>,
    bit_size: usize,
    witness_index: u32,
) -> Result<Vec<AllocatedBit>, SynthesisError>
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
        .enumerate()
        .map(|(i, b)| {
            AllocatedBit::alloc(
                cs.namespace(|| format!("bit {} of {}", i, witness_index)),
                b,
            )
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
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

mod test {
    use std::collections::{BTreeMap, BTreeSet, HashSet};

    use acir::{
        circuit::{
            Circuit, Opcode, Program, PublicInputs,
            opcodes::{BlackBoxFuncCall, FunctionInput},
        },
        native_types::Witness,
    };
    use bellpepper_core::{ConstraintSystem, num::AllocatedNum, test_cs::TestConstraintSystem};
    use noirc_abi::Abi;
    use noirc_artifacts::{debug::ProgramDebugInfo, program::ProgramArtifact};
    use vega_prover::traits::circuit::VegaCircuit;

    use crate::{
        Scalar,
        noir::{
            circuit_reader::types::input_wire::InputWire,
            synthesis::circuit_synthesizer::NoirCircuitSynthesizer,
        },
    };

    #[test]
    fn range_does_not_accept_256_with_a_non_boolean_bit() {
        let input = Witness(0);
        let circuit = Circuit {
            function_name: "malicious_range_witness".to_owned(),
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(input),
                num_bits: 8,
            })],
            private_parameters: BTreeSet::new(),
            public_parameters: PublicInputs(BTreeSet::from([input])),
            return_values: PublicInputs::default(),
            assert_messages: vec![],
        };
        let artifact = ProgramArtifact {
            noir_version: "malicious-acir".to_owned(),
            hash: 0,
            abi: Abi::default(),
            bytecode: Program {
                functions: vec![circuit],
                unconstrained_functions: vec![],
            },
            debug_symbols: ProgramDebugInfo::default(),
            file_map: BTreeMap::new(),
        };
        let synth = NoirCircuitSynthesizer::new(
            artifact,
            vec![InputWire::new(true, input, Some(Scalar::from(256u64)))],
            &HashSet::new(),
        );

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let shared: Vec<AllocatedNum<Scalar>> =
            synth.shared(&mut cs.namespace(|| "shared")).unwrap();
        let pre = synth
            .precommitted(&mut cs.namespace(|| "pre"), &shared)
            .unwrap();
        synth
            .synthesize(&mut cs.namespace(|| "online"), &shared, &pre, None)
            .unwrap();

        assert!(!cs.is_satisfied());

        let bit_path = cs
            .pretty_print_list()
            .into_iter()
            .find(|path| path.contains("bit 7 of 0"))
            .expect("range bit allocation exists")
            .trim_start_matches("AUX ")
            .to_owned();
        cs.set(&bit_path, Scalar::from(2u64));

        assert_eq!(cs.get(&bit_path), Scalar::from(2u64));
        assert!(
            !cs.is_satisfied(),
            "{}",
            cs.which_is_unsatisfied().unwrap_or_default()
        );
    }
}
