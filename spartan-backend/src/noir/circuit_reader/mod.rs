use std::fs;

use acir::{FieldElement, circuit::Opcode, native_types::Witness};
use noirc_artifacts::program::ProgramArtifact;
use serde_json::Error as JsonError;

pub mod named_parameters_mapping;
pub mod prover_input_mapping;
pub mod types;
pub mod verifier_input_mapping;

pub fn read_noir_circuit(file: &str) -> Result<ProgramArtifact, JsonError> {
    let json_str = fs::read_to_string(file).map_err(JsonError::io)?;

    serde_json::from_str(&json_str)
}

/// Scans a circuit's bytecode to list all references to witnesses
pub fn read_witnesses(program: &ProgramArtifact) -> Vec<Witness> {
    let mut seen_ids = std::collections::HashSet::<u32>::new();

    program
        .bytecode
        .functions
        .first()
        .unwrap()
        .opcodes
        .iter()
        .flat_map(map_opcode_witnesses)
        .filter(|witness| seen_ids.insert(witness.witness_index()))
        .collect()
}

fn map_opcode_witnesses(opcode: &Opcode<FieldElement>) -> Vec<Witness> {
    let expression_witnesses = |expr: &acir::native_types::Expression<FieldElement>| {
        let mut witnesses = Vec::new();
        witnesses.extend(expr.mul_terms.iter().flat_map(|(_, lhs, rhs)| [*lhs, *rhs]));
        witnesses.extend(expr.linear_combinations.iter().map(|(_, witness)| *witness));
        witnesses
    };

    match opcode {
        Opcode::AssertZero(expr) => expression_witnesses(expr),
        Opcode::BlackBoxFuncCall(call) => {
            let mut witnesses: Vec<Witness> = call.get_input_witnesses().into_iter().collect();
            witnesses.extend(call.get_outputs_vec());
            witnesses
        }
        Opcode::MemoryOp { block_id: _, op } => {
            vec![op.value, op.index]
        }
        Opcode::MemoryInit {
            block_id: _,
            init,
            block_type: _,
        } => init.clone(),
        Opcode::BrilligCall {
            id: _,
            inputs,
            outputs,
            predicate,
        } => {
            let mut witnesses = Vec::new();

            for input in inputs {
                match input {
                    acir::circuit::brillig::BrilligInputs::Single(expr) => {
                        witnesses.extend(expression_witnesses(expr));
                    }
                    acir::circuit::brillig::BrilligInputs::Array(exprs) => {
                        for expr in exprs {
                            witnesses.extend(expression_witnesses(expr));
                        }
                    }
                    acir::circuit::brillig::BrilligInputs::MemoryArray(_) => {}
                }
            }

            for output in outputs {
                match output {
                    acir::circuit::brillig::BrilligOutputs::Simple(witness) => {
                        witnesses.push(*witness);
                    }
                    acir::circuit::brillig::BrilligOutputs::Array(ws) => {
                        witnesses.extend(ws.iter().copied());
                    }
                }
            }

            witnesses.extend(expression_witnesses(predicate));
            witnesses
        }
        Opcode::Call {
            id: _,
            inputs,
            outputs,
            predicate,
        } => {
            let mut witnesses = inputs.clone();
            witnesses.extend(outputs.iter().copied());
            witnesses.extend(expression_witnesses(predicate));
            witnesses
        }
    }
}
