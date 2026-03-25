use std::time::Instant;
use spartan2::errors::SpartanError;
use spartan2::spartan::SpartanSNARK;
use spartan2::traits::circuit::SpartanCircuit;
use spartan2::traits::Engine;
use spartan2::traits::snark::R1CSSNARKTrait;

pub fn verify<E: Engine, C: SpartanCircuit<E>>(
    verifier_circuit: C,
    proof: SpartanSNARK<E>
) -> Result<Vec<E::Scalar>, SpartanError> {
    let (_, vk) = SpartanSNARK::<E>::setup(verifier_circuit)?;

    let t0 = Instant::now();
    let verification_result = proof.verify(&vk);
    let verify_ms = t0.elapsed().as_millis();
    log::debug!("Verify: {:?}", verify_ms);
    verification_result
}