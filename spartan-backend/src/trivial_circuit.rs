use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use ff::{Field, PrimeField, PrimeFieldBits};
use vega_prover::{
    errors::VegaError,
    provider::T256HyraxEngine,
    traits::{Engine, circuit::VegaCircuit},
    vega_sc_zkp::VegaZkSNARK,
};

use crate::{nizk_prover::prove, nizk_verifier::verify};

// Test circuit
#[allow(unused)]
#[derive(Clone, Debug)]
pub struct TestCircuit<Scalar> {
    prover_witness: Option<Scalar>,
    public_input: Scalar,
}

impl<Scalar: PrimeField + PrimeFieldBits> TestCircuit<Scalar> {
    #[allow(unused)]
    pub(crate) fn new(prover_witness: Option<Scalar>, public_input: Scalar) -> Self {
        Self {
            prover_witness,
            public_input,
        }
    }

    /// Just a convenient one-liner for sanity checking
    #[allow(unused)]
    pub(crate) fn run_trivial_proof() {
        type E = T256HyraxEngine;
        let prover_circuit = TestCircuit::new(
            Some(<T256HyraxEngine as Engine>::Scalar::ONE),
            <T256HyraxEngine as Engine>::Scalar::ONE,
        );

        let verifier_circuit = TestCircuit::new(
            Some(<T256HyraxEngine as Engine>::Scalar::ZERO),
            <T256HyraxEngine as Engine>::Scalar::ONE,
        );

        let proof: Result<VegaZkSNARK<E>, VegaError> = prove(prover_circuit);
        match proof {
            Ok(proof) => {
                let expected_public_values = Vec::new();
                let verification_result = verify(verifier_circuit, proof, &expected_public_values);
                if let Err(e) = verification_result {
                    tracing::error!("Verification failed: {:?}", e);
                }
            }
            Err(e) => tracing::error!("Proof creation failed: {:?}", e),
        }
    }
}

impl<E: Engine> VegaCircuit<E> for TestCircuit<E::Scalar> {
    fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
        Ok(vec![self.public_input])
    }

    // not sure what is meant to go in here (sha256 example also has empty vec return value)
    fn shared<CS: ConstraintSystem<E::Scalar>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    // I understand that these are the private inputs, not sure why the example also does the
    // "enforce" here instead of in the synthesis (and why does synth not receive the public inputs ?!)
    fn precommitted<CS: ConstraintSystem<E::Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<E::Scalar>],
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
        if let Some(witness) = &self.prover_witness {
            Ok(vec![AllocatedNum::alloc(cs, || Ok(*witness))?])
        } else {
            Err(SynthesisError::AssignmentMissing)
        }
    }

    // Another one I don't understand and stole from the example
    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<E::Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<E::Scalar>],
        precommitted: &[AllocatedNum<E::Scalar>],
        _: Option<&[E::Scalar]>, // challenges from the verifier
    ) -> Result<(), SynthesisError> {
        let public_input =
            AllocatedNum::alloc(cs.namespace(|| "public input"), || Ok(self.public_input))?;
        let _ = public_input.inputize(cs.namespace(|| "inputize the public input"));

        // Enforce that witness = public_input
        cs.enforce(
            || "enforce witness equals public input".to_string(),
            |lc| lc + precommitted[0].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + public_input.get_variable(),
        );
        Ok(())
    }
}
