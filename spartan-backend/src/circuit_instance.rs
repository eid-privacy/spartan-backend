use crate::noir::circuit::CircuitParameters;
use crate::noir::circuit_reader::input_mapping::{
    CircuitInput, InputWireMapping, Visible, read_inputs, read_inputs_from_prover_toml,
};
use crate::noir::circuit_reader::read_noir_circuit;
use crate::utils::{biguint_to_scalar, hex_to_ff};
use acir::native_types::{Witness, WitnessMap, WitnessStack};
use acir::{AcirField, FieldElement};
use noirc_artifacts::program::ProgramArtifact;
use num_bigint::BigUint;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

struct CircuitSettings {
    circuit_file: String,
    prover_inputs_file: String,
    verifier_inputs_file: String,
    prover_toml_file: String,
    witness_gz_file: String,
}

impl CircuitSettings {
    const BASE_PATH: &'static str = "../circuits";

    pub fn new(name: &str) -> CircuitSettings {
        CircuitSettings {
            circuit_file: format!("{}/{}/target/{}.json", Self::BASE_PATH, name, name),
            prover_inputs_file: format!("{}/{}/prover_input.json", Self::BASE_PATH, name),
            verifier_inputs_file: format!("{}/{}/verifier_input.json", Self::BASE_PATH, name),
            prover_toml_file: format!("{}/{}/Prover.toml", Self::BASE_PATH, name),
            witness_gz_file: format!("{}/{}/target/{}.gz", Self::BASE_PATH, name, name),
        }
    }

    pub fn from_directory(dir: &Path) -> CircuitSettings {
        let name = dir
            .file_name()
            .expect("directory path must have a final component")
            .to_str()
            .expect("directory name must be valid UTF-8");
        let dir_str = dir.to_str().expect("directory path must be valid UTF-8");
        CircuitSettings {
            circuit_file: format!("{}/target/{}.json", dir_str, name),
            prover_inputs_file: format!("{}/prover_input.json", dir_str),
            verifier_inputs_file: format!("{}/verifier_input.json", dir_str),
            prover_toml_file: format!("{}/Prover.toml", dir_str),
            witness_gz_file: format!("{}/target/{}.gz", dir_str, name),
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
    inputs
        .values()
        .flat_map(|v| {
            v.iter()
                .map(|(public, witness, value)| {
                    (*public, *witness, circuit_input_to_scalar(*value))
                })
                .collect::<Vec<(Visible, Witness, Option<crate::Scalar>)>>()
        })
        .collect()
}

/// Read a nargo-generated `.gz` witness file into a WitnessMap.
fn read_witness_gz(gz_path: &str) -> WitnessMap<FieldElement> {
    let bytes = std::fs::read(gz_path)
        .unwrap_or_else(|e| panic!("Failed to read witness file '{}': {}", gz_path, e));
    let mut stack = WitnessStack::<FieldElement>::deserialize(&bytes)
        .unwrap_or_else(|e| panic!("Failed to deserialize witness file '{}': {}", gz_path, e));
    stack
        .pop()
        .unwrap_or_else(|| panic!("Empty witness stack in '{}'", gz_path))
        .witness
}

/// Convert a nargo WitnessMap to the flat InputWireMapping used by the synthesizer.
/// Visibility is determined by the circuit's declared public parameters.
fn witness_map_to_prover_inputs(
    witness_map: WitnessMap<FieldElement>,
    program: &ProgramArtifact,
) -> InputWireMapping<Option<crate::Scalar>> {
    let public_indices: BTreeSet<u32> = program.bytecode.functions[0]
        .public_parameters
        .0
        .iter()
        .map(|w| w.witness_index())
        .collect();

    witness_map
        .into_iter()
        .map(|(witness, field_element)| {
            let visible = public_indices.contains(&witness.witness_index());
            let scalar: crate::Scalar = hex_to_ff(field_element.to_hex().as_str());
            (visible, witness, Some(scalar))
        })
        .collect()
}

/// Derive verifier inputs from a prover InputWireMapping: keep public values, null private ones.
fn derive_verifier_inputs(
    prover_inputs: &InputWireMapping<Option<crate::Scalar>>,
) -> InputWireMapping<Option<crate::Scalar>> {
    prover_inputs
        .iter()
        .map(|(visible, witness, value)| (*visible, *witness, if *visible { *value } else { None }))
        .collect()
}

pub fn instantiate_circuit_from_dir(dir: &Path) -> CircuitParameters {
    let circuit_settings = CircuitSettings::from_directory(dir);
    let name = dir
        .file_name()
        .expect("directory path must have a final component")
        .to_str()
        .expect("directory name must be valid UTF-8");
    instantiate_circuit_with_settings(name, circuit_settings)
}

pub fn instantiate_circuit(name: &str) -> CircuitParameters {
    let circuit_settings = CircuitSettings::new(name);
    instantiate_circuit_with_settings(name, circuit_settings)
}

fn instantiate_circuit_with_settings(
    name: &str,
    circuit_settings: CircuitSettings,
) -> CircuitParameters {
    let program_artifact = read_noir_circuit(circuit_settings.circuit_file.as_str())
        .expect("Failed to read noir circuit");

    // Prover inputs: prefer explicit JSON, then nargo witness file (includes intermediate
    // witnesses), then Prover.toml (only works for circuits without intermediate witnesses).
    let field_prover_input: InputWireMapping<Option<crate::Scalar>> = if Path::new(
        &circuit_settings.prover_inputs_file,
    )
    .exists()
    {
        map_into_field_flat(&read_inputs(
            &program_artifact,
            &circuit_settings.prover_inputs_file,
        ))
    } else if Path::new(&circuit_settings.witness_gz_file).exists() {
        log::warn!("prover_input.json not found, using nargo witness file");
        let witness_map = read_witness_gz(&circuit_settings.witness_gz_file);
        witness_map_to_prover_inputs(witness_map, &program_artifact)
    } else {
        log::warn!(
            "prover_input.json not found, falling back to Prover.toml (no intermediate witnesses)"
        );
        map_into_field_flat(&read_inputs_from_prover_toml(
            &program_artifact,
            &circuit_settings.prover_toml_file,
        ))
    };
    log::debug!("Prover inputs: {:?}", field_prover_input);

    // Each wire must be assigned for the prover.
    assert!(
        field_prover_input
            .iter()
            .all(|(_, _, value)| value.is_some()),
        "prover input has unassigned wires — intermediate witnesses may be missing"
    );

    // Verifier inputs: prefer explicit JSON, then derive from prover inputs (keeps the same
    // set of witnesses so prover and verifier R1CS shapes match).
    let field_verifier_input: InputWireMapping<Option<crate::Scalar>> =
        if Path::new(&circuit_settings.verifier_inputs_file).exists() {
            map_into_field_flat(&read_inputs(
                &program_artifact,
                &circuit_settings.verifier_inputs_file,
            ))
        } else {
            log::warn!("verifier_input.json not found, deriving from prover inputs");
            derive_verifier_inputs(&field_prover_input)
        };
    log::debug!("Verifier inputs: {:?}", field_verifier_input);

    CircuitParameters {
        name: String::from(name),
        program_artifact,
        prover_inputs: field_prover_input,
        verifier_inputs: field_verifier_input,
    }
}
