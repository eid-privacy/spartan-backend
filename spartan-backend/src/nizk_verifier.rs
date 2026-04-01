use spartan2::errors::SpartanError;
use spartan2::spartan::SpartanSNARK;
use spartan2::traits::Engine;
use spartan2::traits::circuit::SpartanCircuit;
use spartan2::traits::snark::R1CSSNARKTrait;
use tracing::debug_span;

pub fn verify<E: Engine, C: SpartanCircuit<E>>(
    verifier_circuit: C,
    proof: SpartanSNARK<E>,
) -> Result<Vec<E::Scalar>, SpartanError> {
    let (_, vk) = {
        let _span = debug_span!("verifier_setup").entered();
        SpartanSNARK::<E>::setup(verifier_circuit)?
    };

    let verification_result = {
        let _span = debug_span!("verify").entered();
        proof.verify(&vk)
    };

    verification_result
}
