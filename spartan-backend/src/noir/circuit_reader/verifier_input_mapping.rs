use crate::noir::circuit_reader::named_parameters_mapping::map_wires;
use crate::noir::circuit_reader::types::circuit_input::CircuitInput;
use crate::noir::circuit_reader::types::input_wire::InputWire;
use crate::noir::circuit_reader::types::wire::Wire;
use noirc_artifacts::program::ProgramArtifact;
use serde_json::{Error, Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::fs;

pub fn read_verifier_inputs(program: &ProgramArtifact, path: &str) -> Vec<InputWire<CircuitInput>> {
    let wires_mapping = map_wires(
        &program.abi.parameters,
        // assume a single function for now
        &program.bytecode.functions.first().unwrap(),
    );

    let config = read_verifier_config(path).unwrap();
    map_verifier_inputs(&config, &wires_mapping)
}

fn read_verifier_config(path: &str) -> Result<Map<String, Value>, Error> {
    let json_str = fs::read_to_string(path).map_err(Error::io)?;
    let v: Value = serde_json::from_str(&json_str)?;
    let obj = v.as_object().cloned().unwrap();
    Ok(obj)
}

pub fn map_verifier_inputs(
    input_map: &Map<String, Value>,
    wiring: &HashMap<String, Vec<Wire>>,
) -> Vec<InputWire<CircuitInput>> {
    assert_eq!(
        input_map.len(),
        wiring.len(),
        "Number of inputs mismatch with abi"
    );
    let input_keys: BTreeSet<&str> = input_map.keys().map(String::as_str).collect();
    let wiring_keys: BTreeSet<&str> = wiring.keys().map(String::as_str).collect();
    assert_eq!(input_keys, wiring_keys, "input keys and wiring keys differ");

    let mut new_mapping = HashMap::new();
    // each named input matches a number of input wires. This:
    // - Reads how many wires a parameter uses
    // - Read the value from the input file and split it in the correct number of wires
    // - Wraps that in a CircuitInput and matches it with the corresponding wire for later allocation
    for k in input_keys {
        let wire_mapping = wiring.get(k).unwrap();
        let arity = &wire_mapping.len();
        let split_input = match input_map.get(k).unwrap() {
            Value::String(s) => {
                let mut as_bytes = s.as_bytes().to_vec();
                as_bytes.resize(*arity, 0u8);
                as_bytes.iter().map(|v| CircuitInput::Byte(*v)).collect()
            }
            Value::Number(n) => {
                assert_eq!(1, *arity, "Unexpected arity for number input.");
                vec![CircuitInput::Number(n.as_u64().unwrap())]
            }
            Value::Array(arr) => {
                assert_eq!(arr.len(), *arity, "Array length mismatch for input '{k}'");
                arr.iter()
                    .map(|v| {
                        CircuitInput::Byte(
                            v.as_u64().expect("Array elements must be byte values") as u8
                        )
                    })
                    .collect()
            }
            Value::Null => vec![CircuitInput::Missing; *arity],
            _ => panic!("panik"),
        };

        // zip each input with their respective wire
        new_mapping.insert(
            k.to_string(),
            split_input
                .into_iter()
                .zip(wire_mapping)
                .map(|(byte, wire)| wire.assign(byte))
                .collect::<Vec<InputWire<CircuitInput>>>(),
        );
    }

    new_mapping.into_values().flatten().collect()
}
