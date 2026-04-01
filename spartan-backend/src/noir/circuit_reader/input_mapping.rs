use std::collections::{BTreeSet, HashMap};
use std::fs;
use acir::circuit::Circuit;
use acir::FieldElement;
use acir::native_types::Witness;
use noirc_abi::{AbiParameter, AbiVisibility};
use noirc_artifacts::program::ProgramArtifact;
use serde_json::{Error, Map, Value};

pub type Visible = bool;
pub type WireMapping = Vec<(Visible, Witness)>;
pub type InputWireMapping<V> = Vec<(Visible, Witness, V)>;

#[derive(Clone, Copy, Debug)]
pub enum CircuitInput {
    Byte(u8),
    Number(u64), // TODO: add other options
    Missing,
}

pub fn read_inputs(
    program: &ProgramArtifact,
    path: &str,
) -> HashMap<String, InputWireMapping<CircuitInput>> {
    let wires_mapping= map_wires(
        &program.abi.parameters,
        // assume a single function for now
        &program.bytecode.functions.first().unwrap(),
    );

    let config = read_config(path)
        .unwrap_or_else(|e| panic!("Failed to read input file '{}': {}", path, e));
    map_inputs(&config, &wires_mapping)
}

fn read_config(path: &str) -> Result<Map<String, Value>, Error> {
    let json_str = fs::read_to_string(path).map_err(Error::io)?;
    let v: Value = serde_json::from_str(&json_str)?;
    let obj = v.as_object().cloned().unwrap();
    Ok(obj)
}

pub fn map_inputs(
    input_map: &Map<String, Value>,
    wiring: &HashMap<String, WireMapping>,
) -> HashMap<String, InputWireMapping<CircuitInput>> {
    assert_eq!(input_map.len(), wiring.len(), "Number of inputs mismatch with abi");
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
            },
            Value::Number(n) => {
                assert_eq!(1, *arity, "Unexpected arity for number input.");
                vec![CircuitInput::Number(n.as_u64().unwrap())]
            },
            Value::Null => vec![CircuitInput::Missing; *arity],
            Value::Array(arr) => {
                arr.iter().map(|v| match v {
                    Value::Number(n) => CircuitInput::Number(n.as_u64().expect("array element must be a u64")),
                    _ => panic!("unsupported array element type in input map: {:?}", v),
                }).collect()
            },
            _ => panic!("panik"),
        };

        // zip each input with their respective wire
        new_mapping.insert(
            k.to_string(),
            split_input.into_iter()
                .zip(wire_mapping)
                .map(|(byte, (visible, witness))| (*visible, *witness, byte))
                .collect::<Vec<(Visible, Witness, CircuitInput)>>(),
        );
    }

    new_mapping
}

/// Read a `Prover.toml` and return inputs mapped to wires, just like `read_inputs` does for JSON.
pub fn read_inputs_from_prover_toml(
    program: &ProgramArtifact,
    toml_path: &str,
) -> HashMap<String, InputWireMapping<CircuitInput>> {
    let wires_mapping = map_wires(
        &program.abi.parameters,
        program.bytecode.functions.first().unwrap(),
    );
    let config = read_prover_toml(toml_path);
    map_inputs(&config, &wires_mapping)
}

/// Derive verifier inputs from a `Prover.toml`: keeps public param values, nulls private ones.
pub fn derive_verifier_inputs_from_prover_toml(
    program: &ProgramArtifact,
    toml_path: &str,
) -> HashMap<String, InputWireMapping<CircuitInput>> {
    let wires_mapping = map_wires(
        &program.abi.parameters,
        program.bytecode.functions.first().unwrap(),
    );
    let mut config = read_prover_toml(toml_path);
    for param in &program.abi.parameters {
        if param.visibility != AbiVisibility::Public {
            config.insert(param.name.clone(), Value::Null);
        }
    }
    map_inputs(&config, &wires_mapping)
}

fn read_prover_toml(path: &str) -> Map<String, Value> {
    let toml_str = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read Prover.toml '{}': {}", path, e));
    let table: toml::Table = toml_str
        .parse()
        .unwrap_or_else(|e| panic!("Failed to parse Prover.toml '{}': {}", path, e));
    table
        .into_iter()
        .map(|(k, v)| (k, toml_value_to_json(v)))
        .collect()
}

fn toml_value_to_json(value: toml::Value) -> Value {
    match value {
        toml::Value::Integer(n) => Value::Number(n.into()),
        toml::Value::String(s) => Value::String(s),
        toml::Value::Array(arr) => Value::Array(arr.into_iter().map(toml_value_to_json).collect()),
        toml::Value::Boolean(b) => Value::Bool(b),
        toml::Value::Float(f) => {
            Value::Number(serde_json::Number::from_f64(f).expect("non-finite float in Prover.toml"))
        }
        toml::Value::Table(t) => {
            Value::Object(t.into_iter().map(|(k, v)| (k, toml_value_to_json(v))).collect())
        }
        toml::Value::Datetime(dt) => Value::String(dt.to_string()),
    }
}

/// Assign ABI parameters to their respective witnesses in the bytecode
pub fn map_wires(
    abi_parameters: &Vec<AbiParameter>,
    function: &Circuit<FieldElement>,
) -> HashMap<String, WireMapping> {
    // we need to consume both these vectors to map chunks to parameters
    let mut public_wires = function.public_parameters.0.iter().copied();
    let mut private_wires = function.private_parameters.iter().copied();

    let mut wire_mapping = HashMap::new();

    for abi_parameter in abi_parameters.iter() {
        let public = abi_parameter.visibility == AbiVisibility::Public;
        let width = abi_parameter.typ.field_count() as usize;
        let wires = if public {
            public_wires.by_ref()
        } else {
            private_wires.by_ref()
        }
            .take(width)
            .map(|w| (public, w))
            .collect::<Vec<_>>();

        wire_mapping.insert(
            abi_parameter.name.clone(),
            wires,
        );
    }

    wire_mapping
}