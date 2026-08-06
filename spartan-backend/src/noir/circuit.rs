use std::{collections::HashSet, path::PathBuf};

use noirc_artifacts::program::ProgramArtifact;
use vega_prover::{provider::T256HyraxEngine, traits::Engine};

use crate::noir::circuit_reader::types::input_wire::InputWire;

type E = T256HyraxEngine;
pub struct CircuitParameters {
    pub name: String,
    /// Directory the circuit was loaded from (holds `target/`, `online.json`, ...).
    pub dir: PathBuf,
    pub program_artifact: ProgramArtifact,
    pub verifier_inputs: Vec<InputWire<Option<<E as Engine>::Scalar>>>,
    pub prover_inputs: Vec<InputWire<Option<<E as Engine>::Scalar>>>,
    /// Witness indices of the ABI parameters declared "online" in the circuit's
    /// `online.json` manifest.
    /// Circuit parts that don't depend on online parameters can be precomputed.
    /// Empty set means the original monolithic behavior (everything in Vega's `rest` segment).
    pub online_seeds: HashSet<u32>,
}
