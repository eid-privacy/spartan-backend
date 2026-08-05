//! Amortize Vega's prepared state (`prep_snark`) across
//! many proofs of the *same* credential circuit that differ only in their
//! online inputs (e.g. `challenge_nonce` and the device-signature precompute).
//!
//! Lifecycle:
//! 1. [`OnlineProver::setup`] runs Vega's `setup` + `prep_prove` **once**. This
//!    commits the invariant (precommitted) witness — the expensive credential
//!    verification part — and caches its matrix-vector products.
//! 2. [`OnlineProver::prove_online`] runs Vega's `prove`, reusing the prepared
//!    state: it only re-synthesizes the small online (rest) segment and commits
//!    the *delta* of the changed columns. The rerandomized prep is threaded back
//!    for the next call.
//! 3. [`verify_online`] checks a proof against the reusable verifier key.
//!
//! ## Limitation
//! Vega's outer sum-check still runs over **all** padded constraints every
//! proof.amortizes the witness commitment MSM and the precommitted
//! matrix-vector products, **not** the sum-check.

use vega_prover::{errors::VegaError, traits::snark::R1CSSNARKTrait, vega_sc_zkp::VegaZkSNARK};

use crate::{
    E, Scalar,
    noir::{circuit::CircuitParameters, synthesis::circuit_synthesizer::NoirCircuitSynthesizer},
};

/// The concrete zkSNARK type used by this backend.
pub type Snark = VegaZkSNARK<E>;
/// Reusable prover key (serializable for persistence).
pub type ProverKey = <Snark as R1CSSNARKTrait<E>>::ProverKey;
/// Reusable verifier key (serializable for persistence).
pub type VerifierKey = <Snark as R1CSSNARKTrait<E>>::VerifierKey;
/// Reusable prepared proving state (serializable for persistence).
pub type PrepSnark = <Snark as R1CSSNARKTrait<E>>::PrepSNARK;

/// Holds the reusable proving artifacts for one credential circuit.
pub struct OnlineProver {
    pk: ProverKey,
    vk: VerifierKey,
    /// The prepared state, threaded through each `prove` call. `Option` so we
    /// can move it out of `&mut self` into Vega's by-value `prove` without a
    /// (huge) clone; it is always `Some` outside `prove_online`.
    prep: Option<PrepSnark>,
}

impl OnlineProver {
    /// Build the partition-aware synthesizer for a circuit + its prover inputs.
    fn synthesizer(circuit: &CircuitParameters) -> NoirCircuitSynthesizer {
        NoirCircuitSynthesizer::new(
            circuit.program_artifact.clone(),
            circuit.prover_inputs.clone(),
            &circuit.online_seeds,
        )
    }

    /// Run `setup` + `prep_prove` once for the given circuit. The circuit's
    /// invariant inputs are committed here and reused by every later
    /// [`Self::prove_online`] call.
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

    /// Reconstruct an [`OnlineProver`] from persisted artifacts (see
    /// [`crate::online_prover::persistence`]).
    pub fn from_parts(pk: ProverKey, vk: VerifierKey, prep: PrepSnark) -> Self {
        Self {
            pk,
            vk,
            prep: Some(prep),
        }
    }

    /// The reusable verifier key. Share this with verifiers; it is independent
    /// of the online inputs.
    pub fn verifier_key(&self) -> &VerifierKey {
        &self.vk
    }

    /// The reusable prover key.
    pub fn prover_key(&self) -> &ProverKey {
        &self.pk
    }

    /// The current prepared state (rerandomized after each proof).
    pub fn prep(&self) -> &PrepSnark {
        self.prep.as_ref().expect("prep is always present")
    }

    /// Produce a proof for a circuit that shares this prover's invariant inputs
    /// but carries fresh online inputs. Reuses (and rerandomizes) the prepared
    /// state; only the online segment is re-synthesized and the changed columns
    /// re-committed.
    ///
    /// The caller must pass a circuit whose invariant inputs equal those used in
    /// [`Self::setup`]; only the online (manifest-declared) inputs may differ.
    pub fn prove_online(&mut self, circuit: &CircuitParameters) -> Result<Snark, VegaError> {
        let synth = Self::synthesizer(circuit);
        let prep = self.prep.take().expect("prep is always present");
        let (proof, new_prep) = Snark::prove(&self.pk, synth, prep, false)?;
        self.prep = Some(new_prep);
        Ok(proof)
    }
}

/// Verify a proof against a reusable verifier key and check its public IO
/// matches `expected_public_values` (in ABI / witness-index order).
pub fn verify_online(
    vk: &VerifierKey,
    proof: &Snark,
    expected_public_values: &[Scalar],
) -> Result<Vec<Scalar>, VegaError> {
    let public_values = proof.verify(vk)?;
    if public_values != expected_public_values {
        return Err(VegaError::ProofVerifyError {
            reason: format!(
                "Public inputs mismatch: proof claims {:?}, verifier expects {:?}",
                public_values, expected_public_values
            ),
        });
    }
    Ok(public_values)
}

/// Compute the expected public values (ABI order) for a circuit from its
/// verifier inputs. Mirrors `NoirCircuitSynthesizer::public_values`.
pub fn expected_public_values(circuit: &CircuitParameters) -> Vec<Scalar> {
    use vega_prover::traits::circuit::VegaCircuit;
    let synth = NoirCircuitSynthesizer::new(
        circuit.program_artifact.clone(),
        circuit.verifier_inputs.clone(),
        &circuit.online_seeds,
    );
    synth
        .public_values()
        .expect("public_values must be available from verifier inputs")
}

pub mod persistence {
    //! Bincode (de)serialization of the reusable proving artifacts, enabling
    //! cold-start / cross-process reuse of the prepared state.

    use std::{io, path::Path};

    use super::{PrepSnark, ProverKey, VerifierKey};

    fn to_io_err<E: std::fmt::Display>(e: E) -> io::Error {
        io::Error::new(io::ErrorKind::Other, e.to_string())
    }

    /// Serialize a value with bincode 1.3 (the same serializer Vega uses).
    fn save<T: serde::Serialize>(value: &T, path: &Path) -> io::Result<()> {
        let bytes = bincode::serialize(value).map_err(to_io_err)?;
        std::fs::write(path, bytes)
    }

    /// Deserialize a value with bincode 1.3.
    fn load<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
        let bytes = std::fs::read(path)?;
        bincode::deserialize(&bytes).map_err(to_io_err)
    }

    /// Persist the prover key, verifier key and prepared state under `dir` using
    /// the fixed file names `pk.bin`, `vk.bin`, `prep.bin`.
    pub fn save_all(
        dir: &Path,
        pk: &ProverKey,
        vk: &VerifierKey,
        prep: &PrepSnark,
    ) -> io::Result<()> {
        std::fs::create_dir_all(dir)?;
        save(pk, &dir.join("pk.bin"))?;
        save(vk, &dir.join("vk.bin"))?;
        save(prep, &dir.join("prep.bin"))?;
        Ok(())
    }

    /// Load the prover key, verifier key and prepared state from `dir`.
    pub fn load_all(dir: &Path) -> io::Result<(ProverKey, VerifierKey, PrepSnark)> {
        let pk: ProverKey = load(&dir.join("pk.bin"))?;
        let vk: VerifierKey = load(&dir.join("vk.bin"))?;
        let prep: PrepSnark = load(&dir.join("prep.bin"))?;
        Ok((pk, vk, prep))
    }

    /// Load only the verifier key (all a verifier needs).
    pub fn load_vk(dir: &Path) -> io::Result<VerifierKey> {
        load(&dir.join("vk.bin"))
    }
}
