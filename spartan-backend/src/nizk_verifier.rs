use spartan2::errors::SpartanError;
use spartan2::spartan::SpartanSNARK;
use spartan2::traits::Engine;
use spartan2::traits::circuit::SpartanCircuit;
use spartan2::traits::snark::R1CSSNARKTrait;

pub fn verify<E: Engine, C: SpartanCircuit<E>>(
    verifier_circuit: C,
    proof: SpartanSNARK<E>,
) -> Result<Vec<E::Scalar>, SpartanError> {
    let expected_public_values =
        verifier_circuit
            .public_values()
            .map_err(|e| SpartanError::ProofVerifyError {
                reason: format!("Could not extract expected public values: {e}"),
            })?;

    let (_, vk) = {
        let _span = tracing::debug_span!("verifier_setup").entered();
        SpartanSNARK::<E>::setup(verifier_circuit)?
    };

    let public_values = {
        let _span = tracing::debug_span!("verify").entered();
        proof.verify(&vk)
    }?;

    if public_values != expected_public_values {
        return Err(SpartanError::ProofVerifyError {
            reason: format!(
                "Public inputs mismatch: proof claims {:?}, verifier expects {:?}",
                public_values, expected_public_values
            ),
        });
    }

    Ok(public_values)
}
