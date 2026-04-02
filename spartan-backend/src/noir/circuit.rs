use noirc_artifacts::program::ProgramArtifact;
use spartan2::provider::T256HyraxEngine;
use spartan2::traits::Engine;
use crate::noir::circuit_reader::types::input_wire::InputWire;

type E = T256HyraxEngine;
pub struct CircuitParameters {
    pub name: String,
    pub program_artifact: ProgramArtifact,
    pub verifier_inputs: Vec<InputWire<Option<<E as Engine>::Scalar>>>,
    pub prover_inputs: Vec<InputWire<Option<<E as Engine>::Scalar>>>,
}