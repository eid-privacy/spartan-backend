use vega_prover::{
    errors::VegaError,
    traits::{Engine, circuit::VegaCircuit, snark::R1CSSNARKTrait},
    vega_sc_zkp::VegaZkSNARK,
};

#[derive(Clone, Debug)]
pub struct ExpectedPublicValue<S> {
    pub position: usize,
    pub witness_index: u32,
    pub configured_value: Option<S>,
}

pub fn verify<E: Engine, C: VegaCircuit<E>>(
    verifier_circuit: C,
    proof: VegaZkSNARK<E>,
    expected_public_values: &[ExpectedPublicValue<E::Scalar>],
) -> Result<Vec<E::Scalar>, VegaError>
where
    E::PCS: vega_prover::traits::pcs::FoldingEngineTrait<E>,
{
    let (_, vk) = {
        let _span = tracing::debug_span!("verifier_setup").entered();
        VegaZkSNARK::<E>::setup(verifier_circuit)?
    };

    let public_values = {
        let _span = tracing::debug_span!("verify").entered();
        proof.verify(&vk)
    }?;

    let mut filled_from_proof = 0usize;
    for expected in expected_public_values {
        let Some(actual) = public_values.get(expected.position) else {
            return Err(VegaError::ProofVerifyError {
                reason: format!(
                    "Public inputs mismatch: expected witness {} at position {}, but proof has only {} public values",
                    expected.witness_index,
                    expected.position,
                    public_values.len()
                ),
            });
        };

        if let Some(configured) = &expected.configured_value {
            if actual != configured {
                return Err(VegaError::ProofVerifyError {
                    reason: format!(
                        "Public input mismatch at witness {} (position {}): proof claims {:?}, verifier expects {:?}",
                        expected.witness_index, expected.position, actual, configured
                    ),
                });
            }
        } else {
            filled_from_proof += 1;
            tracing::info!(
                witness_index = expected.witness_index,
                position = expected.position,
                value = ?actual,
                "Verifier input missing in JSON, using proof public value"
            );
        }
    }
    if filled_from_proof > 0 {
        tracing::warn!(
            filled_from_proof,
            "Verifier JSON is incomplete: missing public values were taken from the proof"
        );
    }

    Ok(public_values)
}
