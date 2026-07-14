use vega_prover::errors::VegaError;
use vega_prover::traits::Engine;
use vega_prover::traits::circuit::VegaCircuit;
use vega_prover::traits::snark::R1CSSNARKTrait;
use vega_prover::vega_sc_zkp::VegaZkSNARK;

pub fn prove<E: Engine, C: VegaCircuit<E>>(prover_circuit: C) -> Result<VegaZkSNARK<E>, VegaError>
where
    E::PCS: vega_prover::traits::pcs::FoldingEngineTrait<E>,
{
    // SETUP
    let (pk, _vk) = {
        let _span = tracing::debug_span!("setup").entered();
        VegaZkSNARK::<E>::setup(prover_circuit.clone())?
    };

    // PREPARE
    let prep_snark = {
        let _span = tracing::debug_span!("prep_prove").entered();
        VegaZkSNARK::<E>::prep_prove(&pk, prover_circuit.clone(), false)?
    };

    // PROVE
    let (proof, _) = {
        let _span = tracing::debug_span!("prove").entered();
        VegaZkSNARK::<E>::prove(&pk, prover_circuit, prep_snark, false)?
    };

    // proof
    //         .verify(&vk)
    //         .expect("Prover's sanity check verification failed");
    Ok(proof)
}
