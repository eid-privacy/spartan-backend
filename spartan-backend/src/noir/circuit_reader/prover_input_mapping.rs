use std::{collections::HashMap, path::PathBuf};

use acir::{FieldElement, native_types::Witness};
use noir_artifact_cli::fs::witness::load_witness_from_file;
use noirc_artifacts::program::ProgramArtifact;

use crate::noir::circuit_reader::{
    named_parameters_mapping::map_wires,
    types::{circuit_input::CircuitInput, input_wire::InputWire, wire::Wire},
};

pub fn read_inputs(program: &ProgramArtifact, path: &str) -> Vec<InputWire<CircuitInput>> {
    // required to figure out if a wire is public or private input
    let wires_mapping = map_wires(
        &program.abi.parameters,
        // assume a single function for now
        &program.bytecode.functions.first().unwrap(),
    );

    let witness_values: HashMap<u32, (Witness, FieldElement)> = witness_assignments(path);
    map_inputs(&wires_mapping, &witness_values)
}

fn witness_assignments(path: &str) -> HashMap<u32, (Witness, FieldElement)> {
    let mut n = load_witness_from_file(&PathBuf::from(path))
        .expect(format!("Could not load circuit at path {}", path).as_str());
    let w = n.pop().unwrap();
    // TODO: support more than a main method
    assert_eq!(w.index, 0);

    w.witness
        .into_iter()
        .map(|(w, field_element)| (w.0, (w, field_element)))
        .collect()
}

pub fn map_inputs(
    wiring: &HashMap<String, Vec<Wire>>,
    witness_value_assignments: &HashMap<u32, (Witness, FieldElement)>,
) -> Vec<InputWire<CircuitInput>> {
    // each named input matches a number of input wires. This:
    // - Reads how many wires a parameter uses
    // - Read the value from the input file and split it in the correct number of wires
    // - Wraps that in a CircuitInput and matches it with the corresponding wire for later allocation
    let flat_wires: HashMap<u32, Wire> = wiring
        .iter()
        .flat_map(|(_, wire_mapping)| {
            wire_mapping
                .iter()
                .map(|w| (w.witness.witness_index(), *w))
                .collect::<Vec<(u32, Wire)>>()
        })
        .collect();

    let wires = witness_value_assignments
        .iter()
        .map(|(w_id, (w, f))| {
            let wire = match flat_wires.get(w_id) {
                Some(Wire { public, witness }) => Wire::new(*public, *witness),
                None => Wire {
                    public: false,
                    witness: *w,
                },
            };
            wire.assign(CircuitInput::FieldElement(*f))
        })
        .collect();

    wires
}
