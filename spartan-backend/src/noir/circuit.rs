use std::collections::HashMap;
use noirc_artifacts::program::ProgramArtifact;
use spartan2::provider::T256HyraxEngine;
use spartan2::traits::Engine;

type E = T256HyraxEngine;
pub struct CircuitParameters {
    pub program_artifact: ProgramArtifact,
    pub verifier_inputs: HashMap<String, Option<<E as Engine>::Scalar>>,
    pub prover_inputs: HashMap<String,Option<<E as Engine>::Scalar>>,
}