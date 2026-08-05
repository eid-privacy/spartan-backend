use noirc_artifacts::program::ProgramArtifact;
use vega_prover::{provider::T256HyraxEngine, traits::Engine};

use crate::noir::circuit_reader::types::input_wire::InputWire;

type E = T256HyraxEngine;
pub struct CircuitParameters {
    pub name: String,
    pub program_artifact: ProgramArtifact,
    pub verifier_inputs: Vec<InputWire<Option<<E as Engine>::Scalar>>>,
    pub prover_inputs: Vec<InputWire<Option<<E as Engine>::Scalar>>>,
}
