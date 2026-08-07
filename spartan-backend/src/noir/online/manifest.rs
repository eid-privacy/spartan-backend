//! Per-circuit manifest declaring which ABI parameters are "online" (change
//! between proofs). Everything not reachable from these seeds is treated as
//! invariant and committed once by Vega's `precommitted` segment.
//!
//! The manifest lives next to the circuit as `online.json`:
//! ```json
//! { "online_params": ["device_signature", "T_dev_x", "T_dev_y"] }
//! ```
//! An absent or empty manifest means *everything is online* — i.e. the original
//! monolithic behaviour (backward compatible).

use std::{collections::HashSet, fs, path::Path};

use noirc_artifacts::program::ProgramArtifact;
use serde::Deserialize;

use crate::noir::circuit_reader::named_parameters_mapping::map_wires;

/// The list of online ABI parameter names for a circuit.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OnlineManifest {
    /// ABI parameter names whose values change between proofs.
    #[serde(default)]
    pub online_params: Vec<String>,
}

impl OnlineManifest {
    /// Load `online.json` from a circuit directory. A missing file yields an
    /// empty manifest (everything online → original monolithic behaviour).
    pub fn load_from_dir(dir: &Path) -> Self {
        Self::load_from_file(&dir.join("online.json"))
    }

    /// Load a manifest from an explicit path. A missing file yields an empty
    /// manifest; a malformed file is logged and also treated as empty.
    pub fn load_from_file(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|e| {
                tracing::warn!(
                    "Failed to parse online manifest {}: {e}; treating as empty",
                    path.display()
                );
                OnlineManifest::default()
            }),
            Err(_) => OnlineManifest::default(),
        }
    }

    /// True when no online parameters are declared (monolithic behaviour).
    pub fn is_empty(&self) -> bool {
        self.online_params.is_empty()
    }

    /// Resolve the declared online ABI parameter names to the set of witness
    /// indices they occupy (the taint-closure seeds). Names absent from the ABI
    /// are logged and ignored.
    pub fn online_witnesses(&self, program: &ProgramArtifact) -> HashSet<u32> {
        let mapping = map_wires(
            &program.abi.parameters,
            program
                .bytecode
                .functions
                .first()
                .expect("program must have at least one function"),
        );

        let mut seeds = HashSet::new();
        for name in &self.online_params {
            match mapping.get(name) {
                Some(wires) => {
                    for wire in wires {
                        seeds.insert(wire.witness.witness_index());
                    }
                }
                None => tracing::warn!(
                    "Online manifest parameter '{}' not found in circuit ABI",
                    name
                ),
            }
        }
        seeds
    }
}
