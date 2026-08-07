//! Amortize Vega's prepared state (`prep_snark`) across many proofs of the
//! *same* circuit that differ only in their online inputs:
//!
//! 1. [`OnlineProver::setup`] runs `setup` + `prep_prove` once, committing the
//!    invariant (precommitted) witness and caching its matrix-vector products.
//! 2. [`OnlineProver::prove_online`] runs `prove` on top of that state: only the
//!    small online (rest) segment is re-synthesized and re-committed.
//!
//! [`crate::precompute`] persists the state so the two phases can run in
//! separate processes (`--precompute` then `--prove`). Note that Vega's outer
//! sum-check still runs over all padded constraints on every proof, so only the
//! commitments are amortized.

use vega_prover::{errors::VegaError, traits::snark::R1CSSNARKTrait, vega_sc_zkp::VegaZkSNARK};

use crate::{
    E,
    noir::{circuit::CircuitParameters, synthesis::circuit_synthesizer::NoirCircuitSynthesizer},
};

/// The concrete zkSNARK type used by this backend.
pub type Snark = VegaZkSNARK<E>;
pub type ProverKey = <Snark as R1CSSNARKTrait<E>>::ProverKey;
pub type VerifierKey = <Snark as R1CSSNARKTrait<E>>::VerifierKey;
pub type PrepSnark = <Snark as R1CSSNARKTrait<E>>::PrepSNARK;

/// Holds the reusable proving artifacts for one credential circuit.
pub struct OnlineProver {
    pk: ProverKey,
    vk: VerifierKey,
    /// `Option` so we can move it out of `&mut self` into Vega's by-value
    /// `prove` without a (huge) clone; always `Some` outside `prove_online`.
    prep: Option<PrepSnark>,
}

impl OnlineProver {
    fn synthesizer(circuit: &CircuitParameters) -> NoirCircuitSynthesizer {
        NoirCircuitSynthesizer::new(
            circuit.program_artifact.clone(),
            circuit.prover_inputs.clone(),
            &circuit.online_seeds,
        )
    }

    /// Run `setup` + `prep_prove` once for the given circuit. Its invariant
    /// inputs are committed here and reused by every [`Self::prove_online`].
    pub fn setup(circuit: &CircuitParameters) -> Result<Self, VegaError> {
        let synth = Self::synthesizer(circuit);
        let (pk, vk) = Snark::setup(synth.clone())?;
        let prep = Snark::prep_prove(&pk, synth, false)?;
        Ok(Self {
            pk,
            vk,
            prep: Some(prep),
        })
    }

    /// Reconstruct an [`OnlineProver`] from persisted artifacts.
    pub fn from_parts(pk: ProverKey, vk: VerifierKey, prep: PrepSnark) -> Self {
        Self {
            pk,
            vk,
            prep: Some(prep),
        }
    }

    pub fn verifier_key(&self) -> &VerifierKey {
        &self.vk
    }

    pub fn prover_key(&self) -> &ProverKey {
        &self.pk
    }

    pub fn prep(&self) -> &PrepSnark {
        self.prep.as_ref().expect("prep is always present")
    }

    /// Produce a proof for a circuit whose invariant inputs equal those used in
    /// [`Self::setup`]; only the online (manifest-declared) inputs may differ.
    pub fn prove_online(&mut self, circuit: &CircuitParameters) -> Result<Snark, VegaError> {
        let synth = Self::synthesizer(circuit);
        let prep = self.prep.take().expect("prep is always present");
        let (proof, new_prep) = Snark::prove(&self.pk, synth, prep, false)?;
        self.prep = Some(new_prep);
        Ok(proof)
    }
}
