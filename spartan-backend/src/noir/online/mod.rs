//! Lever A: precompute/online split for Noir circuits over Vega.
//!
//! Noir/ACIR emits a single monolithic circuit with no notion of which witness
//! is invariant across proofs vs. challenge-dependent. This module reconstructs
//! that boundary *outside* Noir:
//!
//! - [`manifest`] loads a per-circuit list of "online" ABI parameters (the ones
//!   that change between runs, e.g. `challenge_nonce` and the device-signature
//!   precompute for c0200).
//! - [`partition`] runs a value-independent taint closure over the ACIR opcodes
//!   to derive which opcodes/witnesses are invariant (Vega's `precommitted`
//!   segment) and which are online (Vega's `rest` segment), plus the cut set of
//!   invariant witnesses that must cross the boundary.
//!
//! The synthesizer ([`crate::noir::synthesis::circuit_synthesizer`]) consumes a
//! [`partition::Partition`] to allocate the invariant witness once
//! (`precommitted`) and only the online witness per proof (`synthesize`), so
//! Vega can reuse the prepared state (`prep_snark`) across proofs.

pub mod manifest;
pub mod partition;

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, path::Path};

    use super::{manifest::OnlineManifest, partition::Partition};
    use crate::noir::circuit_reader::read_noir_circuit;

    const C0200_JSON: &str = "../circuits/c0200_swiyu_jwt/target/c0200_swiyu_jwt.json";
    const C0200_DIR: &str = "../circuits/c0200_swiyu_jwt";

    /// The c0200 partition must isolate the invariant credential verification
    /// (precommitted) from the tiny per-challenge device check (rest).
    #[test]
    fn c0200_partition_splits_invariant_from_online() {
        if !Path::new(C0200_JSON).exists() {
            eprintln!("skipping: {C0200_JSON} not built");
            return;
        }
        let program = read_noir_circuit(C0200_JSON).expect("read c0200 artifact");
        let circuit = program.bytecode.functions.first().unwrap();

        let manifest = OnlineManifest::load_from_dir(Path::new(C0200_DIR));
        assert!(!manifest.is_empty(), "c0200 must ship an online manifest");
        let seeds = manifest.online_witnesses(&program);
        assert!(!seeds.is_empty(), "manifest must resolve to seed witnesses");

        // Public witnesses come from the circuit's declared public parameters.
        let public: HashSet<u32> = circuit
            .public_parameters
            .0
            .iter()
            .map(|w| w.witness_index())
            .collect();

        let partition = Partition::compute(circuit, &seeds, &public).expect("partition c0200");

        // The bulk of the circuit (SHA256, base64, JWT ECDSA) is invariant.
        assert!(
            !partition.invariant_witnesses.is_empty(),
            "precommitted segment must be non-empty"
        );
        assert!(
            partition.invariant_opcode_count() > 0,
            "there must be invariant opcodes"
        );
        // Only the device check changes per run, so the online segment is small.
        assert!(
            partition.rest_witnesses.len() < partition.invariant_witnesses.len() / 10,
            "online segment ({}) should be far smaller than invariant ({})",
            partition.rest_witnesses.len(),
            partition.invariant_witnesses.len()
        );
        // Every declared online seed that is actually referenced must be online.
        let rest: HashSet<u32> = partition.rest_witnesses.iter().copied().collect();
        let all: HashSet<u32> = partition
            .invariant_witnesses
            .iter()
            .chain(partition.rest_witnesses.iter())
            .copied()
            .collect();
        for s in &seeds {
            if all.contains(s) {
                assert!(rest.contains(s), "referenced seed {s} must be in rest");
            }
        }
    }

    /// An empty manifest must reproduce the monolithic all-online behaviour.
    #[test]
    fn empty_manifest_is_all_rest() {
        if !Path::new(C0200_JSON).exists() {
            eprintln!("skipping: {C0200_JSON} not built");
            return;
        }
        let program = read_noir_circuit(C0200_JSON).expect("read c0200 artifact");
        let circuit = program.bytecode.functions.first().unwrap();
        let public = HashSet::new();

        let partition = Partition::all_rest(circuit, &public);
        assert!(partition.invariant_witnesses.is_empty());
        assert!(partition.cut_set.is_empty());
        assert_eq!(partition.invariant_opcode_count(), 0);
        assert_eq!(partition.rest_opcode_count(), circuit.opcodes.len());
    }

    /// The partition is value-independent: recomputing it yields the same split.
    #[test]
    fn partition_is_deterministic() {
        if !Path::new(C0200_JSON).exists() {
            eprintln!("skipping: {C0200_JSON} not built");
            return;
        }
        let program = read_noir_circuit(C0200_JSON).expect("read c0200 artifact");
        let circuit = program.bytecode.functions.first().unwrap();
        let manifest = OnlineManifest::load_from_dir(Path::new(C0200_DIR));
        let seeds = manifest.online_witnesses(&program);
        let public: HashSet<u32> = circuit
            .public_parameters
            .0
            .iter()
            .map(|w| w.witness_index())
            .collect();

        let a = Partition::compute(circuit, &seeds, &public).unwrap();
        let b = Partition::compute(circuit, &seeds, &public).unwrap();
        assert_eq!(a.opcode_is_invariant, b.opcode_is_invariant);
        assert_eq!(a.cut_set, b.cut_set);
        assert_eq!(a.rest_witnesses, b.rest_witnesses);
        assert_eq!(a.invariant_witnesses, b.invariant_witnesses);
    }
}
