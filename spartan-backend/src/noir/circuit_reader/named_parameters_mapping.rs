use crate::noir::circuit_reader::types::wire::Wire;
use acir::FieldElement;
use acir::circuit::Circuit;
use noirc_abi::{AbiParameter, AbiVisibility};
use std::collections::HashMap;

/// Assign ABI parameters to their respective witnesses in the bytecode
pub fn map_wires(
    abi_parameters: &Vec<AbiParameter>,
    function: &Circuit<FieldElement>,
) -> HashMap<String, Vec<Wire>> {
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
        .map(|w| Wire { public, witness: w })
        .collect::<Vec<_>>();

        wire_mapping.insert(abi_parameter.name.clone(), wires);
    }

    wire_mapping
}
