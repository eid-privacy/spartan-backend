use spartan2::errors::SpartanError;
use spartan2::spartan::SpartanSNARK;
use spartan2::traits::Engine;
use spartan2::traits::circuit::SpartanCircuit;
use spartan2::traits::snark::R1CSSNARKTrait;

pub fn prove<E: Engine, C: SpartanCircuit<E>>(
    prover_circuit: C,
) -> Result<SpartanSNARK<E>, SpartanError> {
    // SETUP
    let (pk, _vk) = {
        let _span = tracing::debug_span!("setup").entered();
        SpartanSNARK::<E>::setup(prover_circuit.clone())?
    };

    // PREPARE
    let prep_snark = {
        let _span = tracing::debug_span!("prep_prove").entered();
        SpartanSNARK::<E>::prep_prove(&pk, prover_circuit.clone(), false)?
    };

    // PROVE
    let (proof, _) = {
        let _span = tracing::debug_span!("prove").entered();
        SpartanSNARK::<E>::prove(&pk, prover_circuit, prep_snark, false)?
    };

    // proof
    //         .verify(&vk)
    //         .expect("Prover's sanity check verification failed");
    Ok(proof)
}
