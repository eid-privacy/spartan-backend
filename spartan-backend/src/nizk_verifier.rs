use vega_prover::errors::VegaError;
use vega_prover::traits::Engine;
use vega_prover::traits::circuit::VegaCircuit;
use vega_prover::traits::snark::R1CSSNARKTrait;
use vega_prover::vega_sc_zkp::VegaZkSNARK;

pub fn verify<E: Engine, C: VegaCircuit<E>>(
    verifier_circuit: C,
    proof: VegaZkSNARK<E>,
) -> Result<Vec<E::Scalar>, VegaError>
where
    E::PCS: vega_prover::traits::pcs::FoldingEngineTrait<E>,
{
    let expected_public_values =
        verifier_circuit
            .public_values()
            .map_err(|e| VegaError::ProofVerifyError {
                reason: format!("Could not extract expected public values: {e}"),
            })?;

    let (_, vk) = {
        let _span = tracing::debug_span!("verifier_setup").entered();
        VegaZkSNARK::<E>::setup(verifier_circuit)?
    };

    let public_values = {
        let _span = tracing::debug_span!("verify").entered();
        proof.verify(&vk)
    }?;

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
