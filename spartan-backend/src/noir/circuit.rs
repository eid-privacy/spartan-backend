use noirc_artifacts::program::ProgramArtifact;
use spartan2::provider::T256HyraxEngine;
use spartan2::traits::Engine;
use crate::noir::circuit_reader::input_mapping::InputWireMapping;

type E = T256HyraxEngine;
pub struct CircuitParameters {
    pub name: String,
    pub program_artifact: ProgramArtifact,
    pub verifier_inputs: InputWireMapping<Option<<E as Engine>::Scalar>>,
    pub prover_inputs: InputWireMapping<Option<<E as Engine>::Scalar>>,
}