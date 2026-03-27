use std::collections::HashMap;
use acir::native_types::Witness;
use num_bigint::BigUint;
use crate::noir::circuit::CircuitParameters;
use crate::noir::circuit_reader::input_mapping::{read_inputs, CircuitInput, InputWireMapping, Visible};
use crate::noir::circuit_reader::read_noir_circuit;
use crate::utils::biguint_to_scalar;

struct CircuitSettings {
    circuit_file: String,
    prover_inputs_file: String,
    verifier_inputs_file: String,
}

impl CircuitSettings {
    const BASE_PATH: &'static str = "../circuits";

    pub fn new(name: &str) -> CircuitSettings {
        CircuitSettings {
            circuit_file: format!("{}/{}/target/{}.json", Self::BASE_PATH, name, name),
            prover_inputs_file: format!("{}/{}/prover_input.json", Self::BASE_PATH, name),
            verifier_inputs_file: format!("{}/{}/verifier_input.json", Self::BASE_PATH, name),
        }
    }
}

fn circuit_input_to_scalar(input: CircuitInput) -> Option<crate::Scalar> {
    match input {
        CircuitInput::Byte(b) => Some(biguint_to_scalar(&BigUint::from(b))),
        CircuitInput::Number(number) => Some(biguint_to_scalar(&BigUint::from(number))),
        CircuitInput::Missing => None,
    }
}

pub fn map_into_field_flat(
    inputs: &HashMap<String, InputWireMapping<CircuitInput>>,
) -> InputWireMapping<Option<crate::Scalar>> {

    inputs.values()
        .flat_map(|v|
            v.iter()
                .map(|(public, witness, value)| (*public, *witness, circuit_input_to_scalar(*value)))
                .collect::<Vec<(Visible, Witness, Option<crate::Scalar>)>>()
        )
        .collect()
}

pub fn instantiate_circuit(name: &str) ->  CircuitParameters {
    let circuit_settings = CircuitSettings::new(name);

    let program_artifact = read_noir_circuit(circuit_settings.circuit_file.as_str())
        .expect("Failed to read noir circuit");

    // map prover inputs
    let mapped_prover_input = read_inputs(
        &program_artifact,
        circuit_settings.prover_inputs_file.as_str()
    );
    log::debug!("Prover inputs: {:?}", mapped_prover_input);
    let field_prover_input = map_into_field_flat(&mapped_prover_input);
    // each wire has to be assigned for the prover
    assert!(field_prover_input.iter().all(|(_, _, value)| value.is_some()));

    // map verifier inputs
    let mapped_verifier_input = read_inputs(
        &program_artifact,
        circuit_settings.verifier_inputs_file.as_str()
    );
    log::debug!("Verifier inputs: {:?}", mapped_verifier_input);
    let field_verifier_input = map_into_field_flat(&mapped_verifier_input);

    CircuitParameters {
        name: String::from(name),
        program_artifact,
        prover_inputs: field_prover_input.clone(),
        verifier_inputs: field_verifier_input,
    }
}