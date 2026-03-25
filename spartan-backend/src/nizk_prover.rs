use std::time::Instant;
use spartan2::spartan::SpartanSNARK;
use spartan2::traits::circuit::SpartanCircuit;
use spartan2::traits::Engine;
use spartan2::traits::snark::R1CSSNARKTrait;

pub fn prove<E: Engine, C: SpartanCircuit<E>>(
    prover_circuit: C
) -> SpartanSNARK<E> {
    // SETUP
    let t0 = Instant::now();
    let (pk, _) = SpartanSNARK::<E>::setup(prover_circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    println!("Setup: {:?}", setup_ms);

    // PREPARE
    let t0 = Instant::now();
    let prep_snark =
        SpartanSNARK::<E>::prep_prove(&pk, prover_circuit.clone(), true).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    println!("Prep: {:?}", prep_ms);

    // PROVE
    let t0 = Instant::now();
    let proof =
        SpartanSNARK::<E>::prove(&pk, prover_circuit.clone(), &prep_snark, true).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();
    println!("Prove: {:?}", prove_ms);

    proof
}