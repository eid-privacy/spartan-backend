use std::time::Instant;
use spartan2::spartan::SpartanSNARK;
use spartan2::traits::circuit::SpartanCircuit;
use spartan2::traits::Engine;
use spartan2::traits::snark::R1CSSNARKTrait;

pub fn prove<E: Engine, C: SpartanCircuit<E>>(
    prover_circuit: C
) -> SpartanSNARK<E> {
    // SETUP
    let (pk, _) = {
        let _span = tracing::debug_span!("setup").entered();
        SpartanSNARK::<E>::setup(prover_circuit.clone()).expect("setup failed")
    };

    // PREPARE
    let prep_snark = {
        let _span = tracing::debug_span!("prep_prove").entered();
        SpartanSNARK::<E>::prep_prove(&pk, prover_circuit.clone(), false).expect("prep_prove failed")
    };

    // PROVE
    let proof = {
        let _span = tracing::debug_span!("prove").entered();
        SpartanSNARK::<E>::prove(&pk, prover_circuit, &prep_snark, false).expect("prove failed")
    };

    proof
}