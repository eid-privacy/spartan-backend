use std::fs;
use noirc_artifacts::program::ProgramArtifact;
use serde_json::Error as JsonError;

pub fn read_noir_circuit(file: &str) -> Result<ProgramArtifact, JsonError> {
    let json_str = fs::read_to_string(file).expect("Unable to open circuit's json");

    serde_json::from_str(&json_str)
}